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
	"time"

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
func runStream(t *testing.T, client *lnd.Client, resume lnd.SettleIndexStore, handle lnd.InvoiceHandler) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- client.RunInvoiceStream(ctx, resume, handle) }()
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
		// resume is the settle-index store, memoryResume when unset.
		resume lnd.SettleIndexStore
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
		// Not linked, but the failure is this process's own: the resume point
		// could not be read, before the node or the credential was consulted.
		// The stored state still says not_linked, and "waiting for the guard"
		// would hide a database failure at INFO.
		name: "not linked, never up, resume point unreadable", state: lnd.StateNotLinked, wasUp: false,
		wantLevel: "WARN", wantMsg: streamDropped,
		setup:  func(*testing.T, *lndtest.Node, string) lnd.InvoiceHandler { return nil },
		resume: unreadableResume{},
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
			// A ceiling no single attempt can reach. testOptions pins it at 1ms,
			// and the stream counts an attempt that outlasts the ceiling as one
			// that worked — so a slow run flipped the never-up rows to WARN. Only
			// the first retry line is read, so nothing ever waits for it.
			opts := lnd.Options{Broker: &lndtest.Broker{}, MinBackoff: time.Millisecond, MaxBackoff: time.Minute}
			opts.Log = logging.New(&logged, logging.NewLevelVar(slog.LevelDebug))
			client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), opts)
			// A cleanup, not a defer: cleanups run last-in first-out, so the stream
			// is cancelled and joined before the connection under it is closed.
			t.Cleanup(func() { _ = client.Close() })
			if tc.prime != nil {
				tc.prime(t, client, dir)
			}
			resume := tc.resume
			if resume == nil {
				resume = &memoryResume{}
			}
			runStream(t, client, resume, handle)

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
// saying "waiting to start" and "wallet locked". The state took a narrower test
// than the log, and an operator who believed the log would re-link for nothing.
// The rule that fixed it stands: the sentence says re-link exactly when the
// state does.
//
// 2f0 changed what decides the state, so this table is by STAGE. LND answers a
// rotated macaroon ("root key with id N doesn't exist", measured 17 Sep 2026)
// with code Unknown, exactly as it answers a node that is starting or locked,
// so the narrow code test never said re-link on a real rotation. Now a rejection
// the code does not settle asks the node's State service, and only a stage that
// admits calls reads as re-link.
//
// The request to the guard is broad and stays broad; every row asks.
func TestTheReBakeLineIsWordedByTheRecordedState(t *testing.T) {
	for _, tc := range []struct {
		name string
		// stage is LND's name for the node's stage; SERVER_ACTIVE when empty, as
		// lndtest.Start leaves it. A name, not the enum: NON_EXISTING is its zero.
		stage lnd.WalletState
		// cause is what an admitted call fails with; a stage that does not admit
		// calls refuses with its own error first, as LND's interceptor order does.
		cause    error
		stateErr error
		relink   bool
		// asksStage is whether the node's State service was consulted: the codes
		// that settle it by themselves must not cost a call.
		asksStage bool
	}{
		// Settled by the code alone: our own client failing to read the macaroon
		// is Unauthenticated, and PermissionDenied is a verdict.
		{name: "unauthenticated", cause: status.Error(codes.Unauthenticated, "verification failed: signature mismatch"), relink: true},
		{name: "permission denied", cause: status.Error(codes.PermissionDenied, "permission denied"), relink: true},

		// A rotation, as LND answers it: the node is up and refuses the bytes.
		{name: "a rotation, as measured", cause: status.Error(codes.Unknown,
			"cannot retrieve macaroon: cannot get macaroon: root key with id 355822853575254257 doesn't exist"),
			relink: true, asksStage: true},
		{name: "another node's macaroon", cause: lndtest.RejectedLikeLND(), relink: true, asksStage: true},
		{name: "a rotation while the RPC server is active", stage: lnd.WalletRPCActive,
			cause: lndtest.RejectedLikeLND(), relink: true, asksStage: true},

		// The same code from a node that is not accepting calls says nothing
		// about the credential. The fake refuses with LND's state error by itself.
		{name: "a node waiting to start", stage: lnd.WalletWaitingToStart, asksStage: true},
		{name: "a node starting up", stage: lnd.WalletUnlocked, asksStage: true},
		{name: "a locked wallet", stage: lnd.WalletLocked, asksStage: true},
		{name: "a node with no wallet", stage: lnd.WalletNonExisting, asksStage: true},

		// A node whose stage cannot be read is not known to be up.
		{name: "a State service that will not answer", cause: lndtest.RejectedLikeLND(),
			stateErr: status.Error(codes.Unimplemented, "unknown service lnrpc.State"), asksStage: true},

		// d46.20's box case: LND's parser refusing a corrupt recv.macaroon on a
		// node that is up. It said "connecting" until 2f0, and it is exactly the
		// case where the operator had to click Re-link while the UI never said so.
		{name: "a macaroon the parser refused", cause: status.Error(codes.Unknown,
			"cannot determine data format of binary-encoded macaroon"), relink: true, asksStage: true},
		// LND's own macaroon check never answers Internal; its panic recovery
		// does, around every interceptor and handler. Re-link, as the guard counts
		// it: one rule for "the node is up and would not take the call". A code
		// other than Unknown, so the code attribute on the INFO rows is read from
		// the cause rather than assumed.
		{name: "an internal error", cause: status.Error(codes.Internal, "internal server error"), relink: true, asksStage: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := lndtest.Start(t)
			dir := t.TempDir()
			node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
			if tc.stage != "" {
				stage, known := lnrpc.WalletState_value[string(tc.stage)]
				if !known {
					t.Fatalf("%q is not a stage LND defines", tc.stage)
				}
				node.SetWalletState(lnrpc.WalletState(stage))
			}
			node.SetRejectWith(tc.cause)
			node.SetStateError(tc.stateErr)

			var logged syncBuffer
			broker := &lndtest.Broker{}
			opts := testOptions(broker)
			opts.Log = logging.New(&logged, logging.NewLevelVar(slog.LevelDebug))
			client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), opts)
			// A cleanup, not a defer: cleanups run last-in first-out, so the stream
			// is cancelled and joined before the connection under it is closed.
			t.Cleanup(func() { _ = client.Close() })
			runStream(t, client, &memoryResume{}, func(context.Context, *lnrpc.Invoice) error { return nil })

			// The line is written before the request, so a request means the line exists.
			lndtest.WaitFor(t, "a re-bake request", func() bool { return broker.Bakes() > 0 })
			got, ok := logged.first(t, relinkNeeded, reBakeInCaseStale)
			if !ok {
				t.Fatal("the guard was asked to re-bake and nothing said so")
			}
			// Only a failure the state calls Relink may say re-link; anything else
			// names the code the node answered with.
			wantState, wantLevel, wantMsg, wantCode := lnd.StateConnecting, "INFO", reBakeInCaseStale, "Unknown"
			if tc.cause != nil {
				wantCode = status.Code(tc.cause).String()
			}
			if tc.relink {
				wantState, wantLevel, wantMsg, wantCode = lnd.StateRelink, "WARN", relinkNeeded, ""
			}
			if got.Level != wantLevel || got.Msg != wantMsg || got.Code != wantCode {
				t.Errorf("logged %s %q code=%q, want %s %q code=%q",
					got.Level, got.Msg, got.Code, wantLevel, wantMsg, wantCode)
			}
			// The page and the log read one verdict. Every attempt meets the same
			// refusal, so the state cannot have moved on since the line was written.
			if got := client.State(); got != wantState {
				t.Errorf("State = %q, want %q — the log and the Node page disagree", got, wantState)
			}
			if calls, _ := node.StateCalls(); (calls > 0) != tc.asksStage {
				t.Errorf("the node's State service was asked %d times; want asked=%v", calls, tc.asksStage)
			}
		})
	}
}

// unreadableResume fails the way a locked or unreadable database would.
type unreadableResume struct{}

func (unreadableResume) LastSettleIndex(context.Context) (uint64, error) {
	return 0, errors.New("database is locked")
}
func (unreadableResume) SetLastSettleIndex(context.Context, uint64) error { return nil }
