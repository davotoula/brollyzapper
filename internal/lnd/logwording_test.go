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

// records is every line written so far, as an operator's grep sees it. A line
// that is not JSON fails the test rather than being skipped, so a count of zero
// cannot come from lines the parser dropped.
func (b *syncBuffer) records(t *testing.T) []logRecord {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []logRecord
	for line := range strings.SplitSeq(b.buf.String(), "\n") {
		if line == "" {
			continue
		}
		var r logRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("a log line is not JSON: %q", line)
		}
		out = append(out, r)
	}
	return out
}

// first is the first record whose message is one of msgs.
func (b *syncBuffer) first(t *testing.T, msgs ...string) (logRecord, bool) {
	t.Helper()
	for _, r := range b.records(t) {
		if slices.Contains(msgs, r.Msg) {
			return r, true
		}
	}
	return logRecord{}, false
}

// count is how many records carry msg.
func (b *syncBuffer) count(t *testing.T, msg string) int {
	t.Helper()
	n := 0
	for _, r := range b.records(t) {
		if r.Msg == msg {
			n++
		}
	}
	return n
}

// runLoggedStream runs the invoice stream against node at the tests' 1ms
// backoff, logging at Debug into the returned buffer.
func runLoggedStream(t *testing.T, node *lndtest.Node, resume lnd.SettleIndexStore) (*lnd.Client, *lndtest.Broker, *syncBuffer) {
	t.Helper()
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
	logged := &syncBuffer{}
	broker := &lndtest.Broker{}
	opts := testOptions(broker)
	opts.Log = logging.New(logged, logging.NewLevelVar(slog.LevelDebug))
	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), opts)
	// A cleanup, not a defer: cleanups run last-in first-out, so the stream is
	// cancelled and joined before the connection under it is closed.
	t.Cleanup(func() { _ = client.Close() })
	runStream(t, client, resume, func(context.Context, *lnrpc.Invoice) error { return nil })
	return client, broker, logged
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
		// settledByCode is a code that is a verdict whatever the node is doing,
		// so the node's State service must not be asked at all.
		settledByCode bool
	}{
		// Settled by the code alone: our own client failing to read the macaroon
		// is Unauthenticated, and PermissionDenied is a verdict.
		{name: "unauthenticated", cause: status.Error(codes.Unauthenticated, "verification failed: signature mismatch"), relink: true, settledByCode: true},
		{name: "permission denied", cause: status.Error(codes.PermissionDenied, "permission denied"), relink: true, settledByCode: true},

		// A rotation, as LND answers it: the node is up and refuses the bytes.
		{name: "a rotation, as measured", cause: status.Error(codes.Unknown,
			"cannot retrieve macaroon: cannot get macaroon: root key with id 355822853575254257 doesn't exist"),
			relink: true},
		{name: "another node's macaroon", cause: lndtest.RejectedLikeLND(), relink: true},
		{name: "a rotation while the RPC server is active", stage: lnd.WalletRPCActive,
			cause: lndtest.RejectedLikeLND(), relink: true},

		// The same code from a node that is not accepting calls says nothing
		// about the credential. The fake refuses with LND's state error by itself.
		{name: "a node waiting to start", stage: lnd.WalletWaitingToStart},
		{name: "a node starting up", stage: lnd.WalletUnlocked},
		{name: "a locked wallet", stage: lnd.WalletLocked},
		{name: "a node with no wallet", stage: lnd.WalletNonExisting},

		// A node whose stage cannot be read is not known to be up.
		{name: "a State service that will not answer", cause: lndtest.RejectedLikeLND(),
			stateErr: status.Error(codes.Unimplemented, "unknown service lnrpc.State")},

		// d46.20's box case: LND's parser refusing a corrupt recv.macaroon on a
		// node that is up. It said "connecting" until 2f0, and it is exactly the
		// case where the operator had to click Re-link while the UI never said so.
		{name: "a macaroon the parser refused", cause: status.Error(codes.Unknown,
			"cannot determine data format of binary-encoded macaroon"), relink: true},
		// LND's own macaroon check never answers Internal; its panic recovery
		// does, around every interceptor and handler. Re-link, as the guard counts
		// it: one rule for "the node is up and would not take the call". A code
		// other than Unknown, so the code attribute on the INFO rows is read from
		// the cause rather than assumed.
		{name: "an internal error", cause: status.Error(codes.Internal, "internal server error"), relink: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := lndtest.Start(t)
			if tc.stage != "" {
				node.SetWalletState(lnrpc.WalletState(lnrpc.WalletState_value[string(tc.stage)]))
			}
			node.SetRejectWith(tc.cause)
			node.SetStateError(tc.stateErr)
			client, broker, logged := runLoggedStream(t, node, &memoryResume{})

			// The line is written before the request, so a request means a line
			// exists. Every attempt meets the same refusal, so the row's verdict is
			// what the stream settles on, not what the first attempt said: a
			// stage-decided re-link takes a second refusal to confirm (relinkState).
			lndtest.WaitFor(t, "a re-bake request", func() bool { return broker.Bakes() > 0 })
			if tc.relink {
				lndtest.WaitFor(t, "the re-link line", func() bool { return logged.count(t, relinkNeeded) > 0 })
				got, _ := logged.first(t, relinkNeeded)
				if got.Level != "WARN" || got.Code != "" {
					t.Errorf("re-link was logged %s code=%q, want WARN with no code", got.Level, got.Code)
				}
				lndtest.WaitFor(t, "the re-link state", func() bool { return client.State() == lnd.StateRelink })
			} else {
				// No re-link, ever: enough attempts that a confirmation would have
				// landed, then the state and the sentence together. Counted by
				// stage calls, not macaroons — a node that is not accepting calls
				// never reaches the macaroon, in the fake as in LND.
				calls, _ := node.StateCalls()
				lndtest.WaitFor(t, "several refused attempts", func() bool {
					later, _ := node.StateCalls()
					return later > calls+10
				})
				if n := logged.count(t, relinkNeeded); n != 0 {
					t.Errorf("a node that is not accepting calls was logged as re-link %d times", n)
				}
				got, ok := logged.first(t, reBakeInCaseStale)
				if !ok {
					t.Fatal("the guard was asked to re-bake and nothing said so")
				}
				wantCode := "Unknown"
				if tc.cause != nil {
					wantCode = status.Code(tc.cause).String()
				}
				if got.Level != "INFO" || got.Code != wantCode {
					t.Errorf("logged %s code=%q, want INFO code=%q", got.Level, got.Code, wantCode)
				}
				if got := client.State(); got != lnd.StateConnecting {
					t.Errorf("State = %q, want %q — the log and the Node page disagree", got, lnd.StateConnecting)
				}
			}
			if calls, _ := node.StateCalls(); (calls == 0) != tc.settledByCode {
				t.Errorf("the node's State service was asked %d times; the code settles it alone: %v",
					calls, tc.settledByCode)
			}
		})
	}
}

// A real rotation, in the order the regtest stack meets it. LND restarts, and
// the stream's first refusal comes from a node that is still starting: that
// says connecting, asks the guard at INFO — which is what wakes the guard — and
// spends ReBakeInterval. Once the node is up it refuses the stale macaroon and
// the Node page says re-link. If the sentence rode only on a request, the log
// would say nothing above Debug for the rest of the minute, and the guard's
// re-bake usually lands inside it: page and log disagree for the whole episode,
// the 20i.22 bug by another route.
//
// Bounded: once per entry into re-link, not once per refused attempt.
func TestReLinkIsSaidWhenTheStateEntersItEvenBetweenReBakeRequests(t *testing.T) {
	node := lndtest.Start(t)
	node.SetWalletState(lnrpc.WalletState_WAITING_TO_START)
	client, broker, logged := runLoggedStream(t, node, &memoryResume{})

	lndtest.WaitFor(t, "the request made while the node was starting", func() bool { return broker.Bakes() > 0 })
	if got := logged.count(t, relinkNeeded); got != 0 {
		t.Fatalf("a starting node was logged as re-link %d times", got)
	}

	// The node comes up, and refuses the macaroon it no longer has a root key for.
	// Rejection first: the other order leaves a moment where the node is up and
	// accepts, and a stream that subscribes then waits on an empty ledger forever.
	node.SetRejectLikeLND(true)
	node.SetWalletState(lnrpc.WalletState_SERVER_ACTIVE)
	lndtest.WaitFor(t, "the re-link line", func() bool { return logged.count(t, relinkNeeded) > 0 })

	// Many more refusals in the same episode, at the tests' 1ms backoff.
	seen := len(node.SeenMacaroons())
	lndtest.WaitFor(t, "more refused attempts", func() bool { return len(node.SeenMacaroons()) > seen+20 })
	if got := logged.count(t, relinkNeeded); got != 1 {
		t.Errorf("re-link was said %d times over one episode, want once", got)
	}
	if got := broker.Bakes(); got != 1 {
		t.Errorf("the guard was asked %d times inside ReBakeInterval, want 1 — the sentence "+
			"is not a request", got)
	}
	if got := client.State(); got != lnd.StateRelink {
		t.Errorf("State = %q, want %q", got, lnd.StateRelink)
	}
}

// David's ruling, 17 Sep 2026, on 2f0's go-review: one refusal from a node
// reporting a stage that admits calls is not re-link. LND has no stopping stage,
// and it closes its macaroon service well before its gRPC server, so a reconnect
// during a Lightning update is refused with code Unknown ("macaroon store is
// locked") while GetState still says SERVER_ACTIVE. Every attempt after that
// fails with Unavailable and moves nothing, so a single-refusal rule would leave
// the page saying re-link for the whole restart — 20i.22 again, and what §6's
// d46.20 amendment warns a broad state would do.
//
// So: two consecutive refusals from an admitting stage, and the shutdown shape
// must produce none.
func TestReLinkNeedsASecondRefusalFromANodeThatIsStillUp(t *testing.T) {
	t.Run("a refusal and then the node goes away", func(t *testing.T) {
		node := lndtest.Start(t)
		// LND's shutdown, in order: the macaroon store is closed while the gRPC
		// server still answers, then the process goes. Scripted rather than set,
		// so nothing races the reconnect. The empty answer that follows is the
		// node back up, which is what makes the end of the episode observable.
		node.ScriptRejects(
			status.Error(codes.Unknown, "macaroon store is locked"),
			status.Error(codes.Unavailable, "connection refused"),
			status.Error(codes.Unavailable, "connection refused"),
		)
		// A settlement waiting for the accepted attempt: the stream reports ready
		// when it RECEIVES, so without one the end of the episode is unobservable.
		node.SetLedger(lndtest.SettledInvoice("hash-1", 1, 1_000))
		client, broker, logged := runLoggedStream(t, node, &memoryResume{})

		lndtest.WaitFor(t, "the node accepting again", func() bool { return client.State() == lnd.StateReady })
		if n := logged.count(t, relinkNeeded); n != 0 {
			t.Errorf("one refusal during a shutdown was logged as re-link %d times; the "+
				"operator would re-link for a Lightning update", n)
		}
		// The recovery is unchanged: the refusal still asked the guard.
		if got := broker.Bakes(); got != 1 {
			t.Errorf("the guard was asked %d times, want 1 — the re-bake is broad and stays broad", got)
		}
	})

	// The whole restart, which is the shape the ruling is really about: LND is
	// refused on the way down, is away for a while, and refuses once more on the
	// way up before its wallet is unlocked. Neither refusal has a partner, so
	// nothing here is re-link — which only holds if an outcome BETWEEN two
	// refusals ends the suspicion rather than banking it.
	t.Run("a refusal on the way down and another on the way up", func(t *testing.T) {
		node := lndtest.Start(t)
		node.ScriptRejects(
			status.Error(codes.Unknown, "macaroon store is locked"),
			status.Error(codes.Unavailable, "connection refused"),
			status.Error(codes.Unavailable, "connection refused"),
			status.Error(codes.Unknown, "macaroon store is locked"),
			status.Error(codes.Unavailable, "connection refused"),
		)
		node.SetLedger(lndtest.SettledInvoice("hash-1", 1, 1_000))
		client, _, logged := runLoggedStream(t, node, &memoryResume{})

		lndtest.WaitFor(t, "the node accepting again", func() bool { return client.State() == lnd.StateReady })
		if n := logged.count(t, relinkNeeded); n != 0 {
			t.Errorf("two refusals with the node away between them were logged as re-link %d "+
				"times; a suspicion must not survive the outcome after it", n)
		}
	})

	// A failure of OURS between two refusals is not an answer from the node, so
	// it cannot be what makes them consecutive. It also must not leave the
	// suspicion standing: the wait is shortened while one holds, and a resume
	// point that keeps failing would then spin at minBackoff (2f0 go-review).
	t.Run("a refusal, a failure of our own, and another refusal", func(t *testing.T) {
		node := lndtest.Start(t)
		node.ScriptRejects(lndtest.RejectedLikeLND(), lndtest.RejectedLikeLND())
		node.SetLedger(lndtest.SettledInvoice("hash-1", 1, 1_000))
		client, _, logged := runLoggedStream(t, node, &failOnceResume{failOn: 2})

		lndtest.WaitFor(t, "the node accepting again", func() bool { return client.State() == lnd.StateReady })
		if n := logged.count(t, relinkNeeded); n != 0 {
			t.Errorf("two refusals with an unreadable resume point between them were logged as "+
				"re-link %d times; the stream never asked the node in between", n)
		}
	})

	t.Run("two refusals in a row", func(t *testing.T) {
		node := lndtest.Start(t)
		// A rotation answers the confirming attempt exactly as it answered the
		// first; then the guard's re-bake lands, which ends the episode.
		node.ScriptRejects(lndtest.RejectedLikeLND(), lndtest.RejectedLikeLND())
		node.SetLedger(lndtest.SettledInvoice("hash-1", 1, 1_000))
		client, _, logged := runLoggedStream(t, node, &memoryResume{})

		lndtest.WaitFor(t, "the re-link line", func() bool { return logged.count(t, relinkNeeded) > 0 })
		lndtest.WaitFor(t, "the node accepting again", func() bool { return client.State() == lnd.StateReady })
		if n := logged.count(t, relinkNeeded); n != 1 {
			t.Errorf("two refusals said re-link %d times, want once", n)
		}
		// The first refusal said the other sentence, at INFO: it is the one that
		// cannot yet tell a rotation from a node on its way down.
		if got, ok := logged.first(t, relinkNeeded, reBakeInCaseStale); !ok || got.Msg != reBakeInCaseStale {
			t.Errorf("the first refusal logged %q; until it is confirmed it is not re-link", got.Msg)
		}
	})
}

// The confirming attempt does not wait out the grown backoff. A rotation is met
// by a stream whose backoff has already climbed — LND was down while it rotated
// — and at the ceiling the second observation would be a minute away, which is
// longer than the guard takes to re-bake: the operator would never be told at
// all, and regtest/rotation.sh could not assert the line.
//
// A POSITIVE BOUND, not a race: under the fix the confirmation waits minBackoff
// (20ms here) and under the old rule it waits the grown delay (640ms), and
// nothing lives between them.
func TestTheConfirmingAttemptDoesNotWaitOutTheGrownBackoff(t *testing.T) {
	node := lndtest.Start(t)
	// Five failures the classifier ignores, to climb the backoff: 20, 40, 80,
	// 160, 320ms. The refusal then lands with the next delay at 640ms.
	node.ScriptRejects(
		status.Error(codes.Unavailable, "connection refused"),
		status.Error(codes.Unavailable, "connection refused"),
		status.Error(codes.Unavailable, "connection refused"),
		status.Error(codes.Unavailable, "connection refused"),
		status.Error(codes.Unavailable, "connection refused"),
		lndtest.RejectedLikeLND(),
		lndtest.RejectedLikeLND(),
	)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
	logged := &syncBuffer{}
	opts := lnd.Options{Broker: &lndtest.Broker{}, MinBackoff: 20 * time.Millisecond, MaxBackoff: time.Minute}
	opts.Log = logging.New(logged, logging.NewLevelVar(slog.LevelDebug))
	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), opts)
	t.Cleanup(func() { _ = client.Close() })
	runStream(t, client, &memoryResume{}, func(context.Context, *lnrpc.Invoice) error { return nil })

	// The first stage question IS the first refusal: nothing else asks it.
	lndtest.WaitFor(t, "the first refusal", func() bool { calls, _ := node.StateCalls(); return calls > 0 })
	refused := time.Now()
	lndtest.WaitFor(t, "the re-link line", func() bool { return logged.count(t, relinkNeeded) > 0 })
	if waited := time.Since(refused); waited > 300*time.Millisecond {
		t.Errorf("the confirming attempt came %v after the first refusal; at that point the "+
			"backoff was 640ms, so it waited it out instead of confirming at minBackoff", waited)
	}
}

// LND checks the macaroon once, when the stream opens. A stream that has
// delivered was accepted, so a later failure on it is the handler's — LND's
// SubscribeInvoices answers an invoice it cannot convert, or one its aux data
// parser refuses, with a plain error, code Unknown, from a node that is up. Read
// by the stage, that was re-link on every reconnect, since the same invoice is
// replayed each time (2f0 go-review).
//
// The re-bake is still asked for: the request stays broad.
func TestAFailureAfterTheStreamDeliveredIsNotReadAsReLink(t *testing.T) {
	node := lndtest.Start(t)
	node.SetLedger(lndtest.SettledInvoice("hash-1", 1, 1_000), lndtest.SettledInvoice("hash-2", 2, 1_000))
	node.SetBreakAfter(1)
	node.SetBreakError(status.Error(codes.Unknown, "error parsing custom data: unknown record type"))
	// Pinned at zero, so every attempt delivers the first invoice and fails on
	// the second, the way a replayed bad invoice does.
	client, broker, logged := runLoggedStream(t, node, pinnedResume{})

	lndtest.WaitFor(t, "a re-bake request", func() bool { return broker.Bakes() > 0 })
	seen := len(node.SeenMacaroons())
	lndtest.WaitFor(t, "more failed attempts", func() bool { return len(node.SeenMacaroons()) > seen+20 })
	if got := logged.count(t, relinkNeeded); got != 0 {
		t.Errorf("a handler failure after delivery was logged as re-link %d times", got)
	}
	if calls, _ := node.StateCalls(); calls != 0 {
		t.Errorf("the node's stage was asked %d times about a stream it had already accepted", calls)
	}
	if got := client.State(); got == lnd.StateRelink {
		t.Errorf("State = %q after a handler failure on an accepted stream", got)
	}
}

// failOnceResume fails the way a locked database would, on one attempt only.
type failOnceResume struct {
	mu     sync.Mutex
	reads  int
	failOn int
}

func (r *failOnceResume) LastSettleIndex(context.Context) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reads++
	if r.reads == r.failOn {
		return 0, errors.New("database is locked")
	}
	return 0, nil
}

func (r *failOnceResume) SetLastSettleIndex(context.Context, uint64) error { return nil }

// unreadableResume fails the way a locked or unreadable database would.
type unreadableResume struct{}

func (unreadableResume) LastSettleIndex(context.Context) (uint64, error) {
	return 0, errors.New("database is locked")
}
func (unreadableResume) SetLastSettleIndex(context.Context, uint64) error { return nil }
