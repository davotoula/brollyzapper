package lnd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// The two sentences the invoice stream logs before it waits to retry, and the
// two requestReBake logs before it asks the guard. Spelled out here rather
// than exported, so a change of wording has to be made twice — once where an
// operator reads it and once where it is asserted.
const (
	streamDropped     = "invoice stream dropped; reconnecting"
	streamWaiting     = "waiting for the guard's credential before opening the invoice stream"
	relinkNeeded      = "lnd rejected our macaroon; re-link needed"
	reBakeInCaseStale = "the node answered with an error; asking the guard to re-bake in case the credential is stale"
)

// logRecord is one JSON line, as an operator's grep sees it.
type logRecord struct {
	Level string `json:"level"`
	Msg   string `json:"msg"`
	State string `json:"state"`
	Code  string `json:"code"`
}

// syncBuffer is a bytes.Buffer a test may read while the stream goroutine is
// still writing to it. Reading a plain one mid-run is a data race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// first is the first record whose message is one of msgs.
func (b *syncBuffer) first(t *testing.T, msgs ...string) (logRecord, bool) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	for line := range strings.SplitSeq(b.buf.String(), "\n") {
		if line == "" {
			continue
		}
		var r logRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("a log line is not JSON: %q", line)
		}
		if slices.Contains(msgs, r.Msg) {
			return r, true
		}
	}
	return logRecord{}, false
}

// runStream runs the invoice stream until the test ends.
func runStream(t *testing.T, client *lnd.Client, handle lnd.InvoiceHandler) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- client.RunInvoiceStream(ctx, &memoryResume{}, handle) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("RunInvoiceStream = %v, want nil or context.Canceled", err)
		}
	})
}

// 20i.7. Every first start and every update logged a WARN "invoice stream
// dropped; reconnecting" with state=not_linked, four or five times, before the
// guard had baked anything — which is the expected condition, not a drop. A
// WARN that is normal on every start is one an operator learns to ignore.
//
// Decided by state and whether the stream had worked, never by the error text;
// logRetry says why, and the cached-connection row is the one that tells them
// apart.
func TestTheStreamRetryLineIsWordedByStateAndWhetherItWasUp(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     lnd.State
		wasUp     bool
		wantLevel string
		wantMsg   string
		setup     func(t *testing.T, node *lndtest.Node, dir string) lnd.InvoiceHandler
		// prime runs against the client before the stream starts, when set.
		prime func(t *testing.T, client *lnd.Client, dir string)
	}{{
		// The first start: the guard has not written the credential yet.
		name: "not linked, never up", state: lnd.StateNotLinked, wasUp: false,
		wantLevel: "INFO", wantMsg: streamWaiting,
		setup: func(*testing.T, *lndtest.Node, string) lnd.InvoiceHandler { return nil },
	}, {
		// The same condition with the connection already cached — by an earlier
		// call, as the admin pages make — so the absent credential arrives as a
		// stringified status rather than ErrNotLinked. The row that tells state
		// from error text: decided by the sentinel, the other rows still pass.
		name: "not linked, never up, connection cached", state: lnd.StateNotLinked, wasUp: false,
		wantLevel: "INFO", wantMsg: streamWaiting,
		setup: func(t *testing.T, node *lndtest.Node, dir string) lnd.InvoiceHandler {
			node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
			return nil
		},
		prime: func(t *testing.T, client *lnd.Client, dir string) {
			if _, err := client.GetInfo(t.Context()); err != nil {
				t.Fatalf("caching the connection: %v", err)
			}
			if err := os.Remove(filepath.Join(dir, lnd.ReceiveMacaroon)); err != nil {
				t.Fatal(err)
			}
		},
	}, {
		// A stream that delivered, and then lost its credential underneath it.
		// A drop of something that was up is a drop, whatever the state after.
		name: "not linked, was up", state: lnd.StateNotLinked, wasUp: true,
		wantLevel: "WARN", wantMsg: streamDropped,
		setup: func(t *testing.T, node *lndtest.Node, dir string) lnd.InvoiceHandler {
			node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
			node.SetLedger(lndtest.SettledInvoice("hash-1", 1, 1_000),
				lndtest.SettledInvoice("hash-2", 2, 1_000))
			node.SetBreakAfter(1)
			return func(context.Context, *lnrpc.Invoice) error {
				return os.Remove(filepath.Join(dir, lnd.ReceiveMacaroon))
			}
		},
	}, {
		// A node that does not answer: never up, and not waiting on the guard.
		name: "connecting, never up", state: lnd.StateConnecting, wasUp: false,
		wantLevel: "WARN", wantMsg: streamDropped,
		setup: func(t *testing.T, node *lndtest.Node, dir string) lnd.InvoiceHandler {
			node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
			node.SetRejectWith(status.Error(codes.Unavailable, "connection refused"))
			return nil
		},
	}, {
		// The drop the WARN exists for.
		name: "ready, was up", state: lnd.StateReady, wasUp: true,
		wantLevel: "WARN", wantMsg: streamDropped,
		setup: func(t *testing.T, node *lndtest.Node, dir string) lnd.InvoiceHandler {
			node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
			node.SetLedger(lndtest.SettledInvoice("hash-1", 1, 1_000),
				lndtest.SettledInvoice("hash-2", 2, 1_000))
			node.SetBreakAfter(1)
			return nil
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			node := lndtest.Start(t)
			dir := t.TempDir()
			handle := tc.setup(t, node, dir)
			if handle == nil {
				handle = func(context.Context, *lnrpc.Invoice) error { return nil }
			}
			var logged syncBuffer
			opts := testOptions(&lndtest.Broker{})
			opts.Log = logging.New(&logged, logging.NewLevelVar(slog.LevelDebug))
			client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), opts)
			defer client.Close()
			if tc.prime != nil {
				tc.prime(t, client, dir)
			}
			runStream(t, client, handle)

			var got logRecord
			lndtest.WaitFor(t, "the first retry line", func() bool {
				var ok bool
				got, ok = logged.first(t, streamDropped, streamWaiting)
				return ok
			})
			// The row has to be the case it names, or it proves nothing about it.
			if got.State != string(tc.state) {
				t.Fatalf("the retry was logged in state %q; this row is about %q", got.State, tc.state)
			}
			if got.Level != tc.wantLevel || got.Msg != tc.wantMsg {
				t.Errorf("state=%s wasUp=%v logged %s %q, want %s %q",
					tc.state, tc.wasUp, got.Level, got.Msg, tc.wantLevel, tc.wantMsg)
			}
		})
	}
}

// 20i.22. On the 0.1.21 box trip, LND booting through a core-app update was
// logged as WARN "lnd rejected our macaroon; re-link needed", with errors
// saying "waiting to start" and "wallet locked". The state code takes the
// narrow test on purpose and said "connecting"; the log took the broad one, and
// an operator who believed the log would re-link for nothing.
//
// The request to the guard is broad and stays broad. Only the sentence follows
// the narrow test.
func TestTheReBakeLineIsWordedByTheNarrowTest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cause  error
		relink bool
	}{
		{"unauthenticated", status.Error(codes.Unauthenticated, "verification failed: signature mismatch"), true},
		{"permission denied", status.Error(codes.PermissionDenied, "permission denied"), true},
		{"a node that is starting", status.Error(codes.Unknown, "waiting to start, RPC services not available"), false},
		{"a locked wallet", status.Error(codes.Unknown, "wallet locked, unlock it to enable full RPC access"), false},
		{"a macaroon the parser refused", status.Error(codes.Unknown, "cannot determine data format of binary-encoded macaroon"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := lndtest.Start(t)
			dir := t.TempDir()
			node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
			node.SetRejectWith(tc.cause)

			var logged syncBuffer
			broker := &lndtest.Broker{}
			opts := testOptions(broker)
			opts.Log = logging.New(&logged, logging.NewLevelVar(slog.LevelDebug))
			client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), opts)
			defer client.Close()
			runStream(t, client, func(context.Context, *lnrpc.Invoice) error { return nil })

			// The line is written before the request, so a request means the line exists.
			lndtest.WaitFor(t, "a re-bake request", func() bool { return broker.Bakes() > 0 })
			got, ok := logged.first(t, relinkNeeded, reBakeInCaseStale)
			if !ok {
				t.Fatal("the guard was asked to re-bake and nothing said so")
			}
			// Only a cause the state calls Relink may say re-link; anything else
			// names the code the node answered with.
			wantLevel, wantMsg, wantCode := "INFO", reBakeInCaseStale, status.Code(tc.cause).String()
			if tc.relink {
				wantLevel, wantMsg, wantCode = "WARN", relinkNeeded, ""
			}
			if got.Level != wantLevel || got.Msg != wantMsg || got.Code != wantCode {
				t.Errorf("%v logged %s %q code=%q, want %s %q code=%q",
					tc.cause, got.Level, got.Msg, got.Code, wantLevel, wantMsg, wantCode)
			}
		})
	}
}
