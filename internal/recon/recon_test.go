package recon_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/recon"
	"github.com/davotoula/brollyzapper/internal/wallet"
)

var now = time.Unix(1_700_000_000, 0).UTC()

type fakeNode struct {
	mu        sync.Mutex
	localMsat int64
	err       error
}

func (n *fakeNode) ChannelBalance(context.Context) (*lnrpc.ChannelBalanceResponse, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return nil, n.err
	}
	return &lnrpc.ChannelBalanceResponse{
		LocalBalance: &lnrpc.Amount{Msat: uint64(n.localMsat)},
	}, nil
}

func (n *fakeNode) set(msat int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.localMsat = msat
}

type fakeWallet struct {
	mu       sync.Mutex
	balance  int64
	deficit  wallet.Deficit
	frozen   bool
	recorded int
	cleared  int
}

func (w *fakeWallet) Balance(context.Context) (int64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.balance, nil
}

func (w *fakeWallet) RecordShortfall(_ context.Context, d wallet.Deficit) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.deficit, w.frozen, w.recorded = d, true, w.recorded+1
	return nil
}

func (w *fakeWallet) ClearShortfall(context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.frozen, w.cleared = false, w.cleared+1
	return nil
}

func (w *fakeWallet) Shortfall(context.Context) (wallet.Deficit, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.deficit, w.frozen, nil
}

func (w *fakeWallet) state() (wallet.Deficit, bool, int, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.deficit, w.frozen, w.recorded, w.cleared
}

type fakeAuditor struct {
	mu     sync.Mutex
	events []logging.Event
	last   string
}

func (a *fakeAuditor) Record(_ context.Context, _ slog.Level, msg string, event logging.Event, _ ...slog.Attr) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events, a.last = append(a.events, event), msg
	return nil
}

func (a *fakeAuditor) recorded() []logging.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]logging.Event(nil), a.events...)
}

func newReconciler(t *testing.T, nodeMsat, walletMsat int64) (*recon.Reconciler, *fakeNode, *fakeWallet, *fakeAuditor) {
	t.Helper()
	node := &fakeNode{localMsat: nodeMsat}
	purse := &fakeWallet{balance: walletMsat}
	auditor := &fakeAuditor{}
	r := recon.New(node, purse, auditor, recon.Options{
		Now: func() time.Time { return now },
		Log: logging.New(discard{}, logging.NewLevelVar(slog.LevelDebug)),
	})
	return r, node, purse, auditor
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func TestAHealthyNodeRecordsNoShortfall(t *testing.T) {
	r, _, purse, auditor := newReconciler(t, 1_000_000_000, 400_000_000)
	if err := r.Check(t.Context()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if _, frozen, recorded, _ := purse.state(); frozen || recorded != 0 {
		t.Errorf("a healthy node froze spending (frozen=%v recorded=%d)", frozen, recorded)
	}
	if len(auditor.recorded()) != 0 {
		t.Errorf("a healthy check raised %v", auditor.recorded())
	}
}

// §5: the check is deliberately COARSE. local_balance still counts channel
// reserves that can never be sent, so it catches the gross cases, not the last
// few thousand sats. An over-sensitive check freezes a working node, and an
// operator who sees a spurious freeze once will distrust the real one.
func TestASmallDiscrepancyDoesNotFreezeAWorkingNode(t *testing.T) {
	tolerance := recon.DefaultToleranceMsat
	// Exactly at the tolerance: still healthy.
	r, _, purse, _ := newReconciler(t, 1_000_000, 1_000_000+tolerance)
	if err := r.Check(t.Context()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if _, frozen, _, _ := purse.state(); frozen {
		t.Errorf("a discrepancy of exactly the %d msat tolerance froze spending", tolerance)
	}

	// One msat past it: a shortfall.
	r, _, purse, _ = newReconciler(t, 1_000_000, 1_000_000+tolerance+1)
	if err := r.Check(t.Context()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if _, frozen, _, _ := purse.state(); !frozen {
		t.Error("a discrepancy past the tolerance did not freeze spending")
	}
}

func TestAGrossShortfallFreezesSpendingAndRecordsWhy(t *testing.T) {
	r, _, purse, auditor := newReconciler(t, 500_000_000, 900_000_000)
	if err := r.Check(t.Context()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	deficit, frozen, recorded, _ := purse.state()
	if !frozen || recorded != 1 {
		t.Fatalf("frozen=%v recorded=%d, want a single recorded freeze", frozen, recorded)
	}
	if deficit.ShortfallMsat != 400_000_000 {
		t.Errorf("ShortfallMsat = %d, want 400000000", deficit.ShortfallMsat)
	}
	if deficit.WalletMsat != 900_000_000 || deficit.NodeMsat != 500_000_000 {
		t.Errorf("the deficit does not carry both sides: %+v", deficit)
	}
	if !deficit.At.Equal(now) {
		t.Errorf("At = %v, want the check's clock", deficit.At)
	}
	// §9 and criterion 4: a number with no candidate explanation sends the
	// operator to the wrong place.
	if strings.TrimSpace(deficit.Cause) == "" {
		t.Error("the deficit names no likely cause")
	}
	// §12 and criterion 9: through the Auditor, so it reaches the durable trail.
	if events := auditor.recorded(); len(events) != 1 || events[0] != logging.EventWalletShortfall {
		t.Errorf("audit events = %v, want one wallet.shortfall", events)
	}
}

// Criterion 4: the likely cause has to distinguish "the node lost funds" from
// "the operator allocated too much", because they send you to different places.
func TestTheCauseFollowsWhichSideMoved(t *testing.T) {
	t.Run("the node's balance fell", func(t *testing.T) {
		r, node, purse, _ := newReconciler(t, 1_000_000_000, 900_000_000)
		if err := r.Check(t.Context()); err != nil {
			t.Fatal(err)
		}
		node.set(100_000_000)
		if err := r.Check(t.Context()); err != nil {
			t.Fatal(err)
		}
		deficit, frozen, _, _ := purse.state()
		if !frozen {
			t.Fatal("the node losing most of its balance did not freeze spending")
		}
		lower := strings.ToLower(deficit.Cause)
		if !strings.Contains(lower, "node") {
			t.Errorf("cause = %q, want it to point at the node rather than the ceiling", deficit.Cause)
		}
	})

	t.Run("the ceiling was raised", func(t *testing.T) {
		r, _, purse, _ := newReconciler(t, 1_000_000_000, 900_000_000)
		if err := r.Check(t.Context()); err != nil {
			t.Fatal(err)
		}
		purse.mu.Lock()
		purse.balance = 5_000_000_000
		purse.mu.Unlock()
		if err := r.Check(t.Context()); err != nil {
			t.Fatal(err)
		}
		deficit, frozen, _, _ := purse.state()
		if !frozen {
			t.Fatal("raising the ceiling far above the node did not freeze spending")
		}
		lower := strings.ToLower(deficit.Cause)
		if !strings.Contains(lower, "alloc") {
			t.Errorf("cause = %q, want it to point at over-allocation", deficit.Cause)
		}
	})
}

// §5: once the shortfall clears, the freeze lifts — no operator action, no
// restart.
func TestTheFreezeLiftsOnItsOwnWhenTheShortfallClears(t *testing.T) {
	r, node, purse, auditor := newReconciler(t, 500_000_000, 900_000_000)
	if err := r.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, frozen, _, _ := purse.state(); !frozen {
		t.Fatal("the shortfall did not freeze spending")
	}

	node.set(2_000_000_000)
	if err := r.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, frozen, _, cleared := purse.state()
	if frozen {
		t.Error("the freeze survived the shortfall clearing")
	}
	if cleared != 1 {
		t.Errorf("ClearShortfall was called %d times, want 1", cleared)
	}
	events := auditor.recorded()
	if len(events) != 2 {
		t.Fatalf("audit events = %v, want one for the freeze and one for the recovery", events)
	}
	if !strings.Contains(strings.ToLower(auditor.last), "clear") &&
		!strings.Contains(strings.ToLower(auditor.last), "recover") {
		t.Errorf("the recovery event says %q; it should say the freeze lifted", auditor.last)
	}
}

// A freeze that re-records itself every five minutes floods the trail with the
// same fact.
func TestAContinuingShortfallIsRecordedOnce(t *testing.T) {
	r, _, purse, auditor := newReconciler(t, 500_000_000, 900_000_000)
	for range 4 {
		if err := r.Check(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, recorded, _ := purse.state(); recorded != 1 {
		t.Errorf("a continuing shortfall was recorded %d times, want 1", recorded)
	}
	if events := auditor.recorded(); len(events) != 1 {
		t.Errorf("a continuing shortfall raised %d audit events, want 1", len(events))
	}
}

// An unreachable node is not a shortfall. Freezing spending because LND is
// restarting would be an outage caused by the check itself.
func TestAnUnreachableNodeDoesNotFreezeSpending(t *testing.T) {
	r, node, purse, auditor := newReconciler(t, 1_000_000_000, 400_000_000)
	node.mu.Lock()
	node.err = errors.New("rpc error: code = Unavailable")
	node.mu.Unlock()

	err := r.Check(t.Context())
	if err == nil {
		t.Fatal("Check hid an unreachable node")
	}
	if _, frozen, recorded, _ := purse.state(); frozen || recorded != 0 {
		t.Error("an unreachable node froze spending")
	}
	if len(auditor.recorded()) != 0 {
		t.Error("an unreachable node raised a shortfall event")
	}
}

// The producer preflight has been waiting for. §11's Tier-2 reconciliation row
// reads this.
func TestShortfallIsThePreflightProducer(t *testing.T) {
	r, _, _, _ := newReconciler(t, 500_000_000, 900_000_000)
	if _, _, present := r.Shortfall(t.Context()); present {
		t.Error("a shortfall was reported before any check ran")
	}
	if err := r.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	amount, cause, present := r.Shortfall(t.Context())
	if !present || amount != 400_000_000 {
		t.Errorf("Shortfall = %d, %v; want 400000000, true", amount, present)
	}
	if strings.TrimSpace(cause) == "" {
		t.Error("the producer drops the cause, so the panel would show a number with no explanation")
	}
}

// The interval is injected so the test costs microseconds rather than minutes.
func TestRunChecksOnEveryTick(t *testing.T) {
	r, _, purse, _ := newReconciler(t, 500_000_000, 900_000_000)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tick := make(chan time.Time)
	checked := make(chan error, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx, tick, nil, func(err error) { checked <- err })
	}()

	tick <- now
	if err := <-checked; err != nil {
		t.Fatalf("the scheduled check failed: %v", err)
	}
	if _, frozen, _, _ := purse.state(); !frozen {
		t.Error("the scheduled check did not freeze spending")
	}
	cancel()
	<-done
}

// d46.21: a ceiling change makes recon's verdict stale immediately, and on the
// box that left the Security page showing a confident green tick for ~3.6
// minutes. The demand channel is the same affordance §9 already gives the
// domain probe.
//
// The tick channel here NEVER fires, so a check that happens can only be the
// demand's doing — there is no interval to wait out and none to accidentally
// pass the test.
func TestADemandChecksWithoutWaitingForTheInterval(t *testing.T) {
	r, _, purse, _ := newReconciler(t, 500_000_000, 900_000_000)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	never := make(chan time.Time)
	demand := make(chan struct{}, 1)
	checked := make(chan error, 4)
	go r.Run(ctx, never, demand, func(err error) { checked <- err })

	demand <- struct{}{}
	select {
	case err := <-checked:
		if err != nil {
			t.Fatalf("the demanded check failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a demanded reconciliation never ran; the verdict would stay stale until the tick")
	}
	if _, frozen, _, _ := purse.state(); !frozen {
		t.Error("the demanded check did not act on what it found")
	}
}

// A closed demand channel must end the loop, not spin it. Unreachable today —
// cmd never closes it and the api side is send-only — but the tick case already
// guards for this, and an unguarded sibling inside one select is the kind of
// asymmetry that becomes true later without anyone deciding it should.
func TestAClosedDemandChannelEndsTheLoopRatherThanSpinning(t *testing.T) {
	r, _, _, _ := newReconciler(t, 500_000_000, 900_000_000)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	demand := make(chan struct{})
	checks := make(chan error, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx, make(chan time.Time), demand, func(err error) { checks <- err })
	}()

	close(demand)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return on a closed demand channel; it is spinning Check " +
			"against the node and the wallet")
	}
	if len(checks) > 1 {
		t.Errorf("a closed demand channel drove %d checks", len(checks))
	}
}
