package lnd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
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

// The two sentences the invoice stream logs before it waits to retry. Spelled out here rather
// than exported, so a change of wording has to be made twice — once where an
// operator reads it and once where it is asserted.
const (
	streamDropped = "invoice stream dropped; reconnecting"
	streamWaiting = "waiting for the guard's credential before opening the invoice stream"
)

// logRecord is one JSON line, as an operator's grep sees it.
type logRecord struct {
	Level string `json:"level"`
	Msg   string `json:"msg"`
	State string `json:"state"`
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
		for _, m := range msgs {
			if r.Msg == m {
				return r, true
			}
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
// The discriminator is the state the record already carries, together with
// whether the stream had been working. NOT the error text: once the connection
// is cached, an absent credential arrives as a stringified Unauthenticated
// status rather than ErrNotLinked (recordState's comment), so a match on the
// sentinel works on the first start and silently stops on the second.
func TestTheStreamRetryLineIsWordedByStateAndWhetherItWasUp(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     lnd.State
		wasUp     bool
		wantLevel string
		wantMsg   string
		setup     func(t *testing.T, node *lndtest.Node, dir string) lnd.InvoiceHandler
	}{{
		// The first start: the guard has not written the credential yet.
		name: "not linked, never up", state: lnd.StateNotLinked, wasUp: false,
		wantLevel: "INFO", wantMsg: streamWaiting,
		setup: func(*testing.T, *lndtest.Node, string) lnd.InvoiceHandler { return nil },
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
