package wallet

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"
)

// u0u: a payment left unresolved by a previous run HOLDS spending.
//
// §6 says pending payments must be resolved before new ones are accepted. That
// used to be an ordering in cmd/brollyzapper — the resolver ran above the
// background loops — which the HTTP listener already outran and which d24.3
// could have routed around by starting NWC anywhere else. Here it is a state
// every outbound payment passes through, because Reserve is §3's one door.
func TestReserveIsHeldWhileAPreviousRunsPaymentIsUnresolved(t *testing.T) {
	db, _ := openStore(t)
	started := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	// A previous run's reservation: made an hour before this process started.
	previous := walletAt(db, started.Add(-time.Hour))
	allocate(t, previous, 1_000_000)
	stale, err := previous.Reserve(t.Context(), Reservation{AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: "stale", Ref: "previous run"})
	if err != nil {
		t.Fatalf("the previous run's reservation: %v", err)
	}

	// This process.
	w := walletAt(db, started)
	_, err = w.Reserve(t.Context(), Reservation{AmountMsat: 1_000, MaxFeeMsat: 10, PaymentHash: "fresh", Ref: "this run"})
	if !errors.Is(err, ErrPaymentsUnresolved) {
		t.Fatalf("Reserve = %v, want ErrPaymentsUnresolved — the ceiling is holding a "+
			"reservation whose fate is unknown (§6)", err)
	}
	// The message has to say what clears it: a freeze an operator cannot act on
	// and cannot wait out is an outage with no instructions.
	if !strings.Contains(err.Error(), "clears itself") {
		t.Errorf("error = %q, want it to say the hold lifts by itself once the node answers",
			err.Error())
	}
	// And it is NOT the reconciliation freeze. They are siblings, not one
	// wrapping the other, because their remedies differ: a shortfall may need an
	// operator's adjustment, this needs nobody. Reporting it as a shortfall
	// would put a deficit on §11's Tier-2 row and the Node page where there is
	// none.
	if errors.Is(err, ErrSpendingFrozen) {
		t.Error("an unresolved payment reported itself as a reconciliation shortfall")
	}

	// And it lifts the moment that row resolves — no restart, no operator
	// action, which is the same rule §5 sets for the reconciliation freeze.
	if err := w.Reverse(t.Context(), stale); err != nil {
		t.Fatalf("resolving the stale row: %v", err)
	}
	if _, err := w.Reserve(t.Context(), Reservation{AmountMsat: 1_000, MaxFeeMsat: 10, PaymentHash: "after", Ref: "this run"}); err != nil {
		t.Errorf("Reserve after the stale payment resolved: %v — the hold must lift by itself",
			err)
	}
}

// THE CRITERION: a payment THIS process is making does not freeze itself.
//
// A reservation is pending and unresolved for as long as LND takes to answer,
// which is the whole window a payment lives in. A freeze that counted it would
// mean the first payment holds the second, the second holds the third, and a
// single in-flight payment stops the wallet — every payment deadlocking against
// the one before it.
func TestAPaymentInFlightDoesNotFreezeTheNextOne(t *testing.T) {
	db, _ := openStore(t)
	started := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	w := walletAt(db, started)
	allocate(t, w, 1_000_000)

	// This process reserves and has not resolved it yet — exactly the state a
	// payment is in while LND is deciding.
	inFlight, err := w.Reserve(t.Context(), Reservation{AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: "in-flight", Ref: "now"})
	if err != nil {
		t.Fatalf("the first reservation: %v", err)
	}
	if pending, err := db.PendingPaymentsBefore(t.Context(), started.Add(time.Hour)); err != nil {
		t.Fatal(err)
	} else if len(pending) != 1 || pending[0].ID != int64(inFlight) {
		t.Fatalf("the in-flight row is not pending (%+v); this test is not exercising the "+
			"criterion", pending)
	}

	// A second payment must still be possible.
	if _, err := w.Reserve(t.Context(), Reservation{AmountMsat: 1_000, MaxFeeMsat: 10, PaymentHash: "second", Ref: "now"}); err != nil {
		t.Fatalf("Reserve while THIS process has a payment in flight: %v — the cutoff is what "+
			"stops a payment freezing against itself (u0u)", err)
	}
}

// --- helpers ---------------------------------------------------------------

// walletAt builds a wallet that believes it started at a given moment, which is
// what these tests vary: a "previous run" and "this run" over ONE store, which
// newWalletAt cannot express because it pairs a fresh store with one wallet.
func walletAt(db *store.Store, startedAt time.Time) *localSpender {
	return New(db, Options{
		Now:       func() time.Time { return startedAt },
		StartedAt: startedAt,
	})
}

// l3l: a payment THIS process dispatched whose send errored holds spending once
// it is older than UnresolvedAfter — without a restart.
//
// The class the start-based cutoff could not see. `SendPayment` errors, the row
// stays pending with its fate unknown, and a cutoff of "before this process
// started" excludes it — so it neither held spending nor was resolved until the
// NEXT start computed a later cutoff. §6 says pending payments are resolved
// before new ones are accepted, and this package's own comment claimed "the
// recon loop retries until the node answers"; neither was true of this row.
func TestAThisRunPaymentThatWentQuietEventuallyHoldsSpending(t *testing.T) {
	db, _ := openStore(t)
	started := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	clock := started

	w := New(db, Options{Now: func() time.Time { return clock }, StartedAt: started})
	allocate(t, w, 1_000_000)
	// Dispatched by THIS process; the send errored, so nothing closed it.
	if _, err := w.Reserve(t.Context(), Reservation{
		AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: "went-quiet", Ref: "this run",
	}); err != nil {
		t.Fatalf("the reservation: %v", err)
	}

	// Straight away it must NOT freeze — it may still be in flight, and freezing
	// here is the self-deadlock the cutoff exists to prevent.
	clock = started.Add(10 * time.Second)
	if _, err := w.Reserve(t.Context(), Reservation{
		AmountMsat: 1_000, MaxFeeMsat: 10, PaymentHash: "while-in-flight", Ref: "in flight",
	}); err != nil {
		t.Fatalf("Reserve ten seconds after dispatch: %v — a payment in flight must not freeze "+
			"against itself", err)
	}

	// Past UnresolvedAfter, with no restart, it does.
	clock = started.Add(UnresolvedAfter + time.Minute)
	_, err := w.Reserve(t.Context(), Reservation{
		AmountMsat: 1_000, MaxFeeMsat: 10, PaymentHash: "after", Ref: "later",
	})
	if !errors.Is(err, ErrPaymentsUnresolved) {
		t.Fatalf("Reserve = %v, want ErrPaymentsUnresolved — a payment this run dispatched and "+
			"never resolved must hold the ceiling, and it must not take a restart to notice",
			err)
	}

	// And the RESOLVER sees the same row, from the same cutoff: it is what
	// lifts the freeze, so a freeze it cannot see is a freeze nothing clears.
	pending, err := db.PendingPaymentsBefore(t.Context(), w.UnresolvedCutoff())
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) == 0 {
		t.Error("the freeze is holding a row the resolver's cutoff excludes; the two read one " +
			"definition precisely so this cannot happen")
	}
}

// The cutoff is the LATER of the two answers, and the startup case is why.
//
// A rolling cutoff alone would be WEAKER than what it replaced: at startup
// `now - UnresolvedAfter` is EARLIER than the process start, so a row a previous
// run left thirty seconds before it crashed would not freeze for another five
// minutes — a window in which the ceiling can be spent against a reservation
// that may already have settled.
func TestARowInheritedFromAPreviousRunFreezesImmediately(t *testing.T) {
	db, _ := openStore(t)
	crashed := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	previous := walletAt(db, crashed.Add(-time.Hour))
	allocate(t, previous, 1_000_000)
	if _, err := previous.Reserve(t.Context(), Reservation{
		AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: "inherited", Ref: "previous run",
	}); err != nil {
		t.Fatal(err)
	}

	// This process starts thirty seconds later — far less than UnresolvedAfter.
	started := crashed.Add(30 * time.Second)
	clock := started
	w := New(db, Options{Now: func() time.Time { return clock }, StartedAt: started})

	_, err := w.Reserve(t.Context(), Reservation{
		AmountMsat: 1_000, MaxFeeMsat: 10, PaymentHash: "fresh", Ref: "this run",
	})
	if !errors.Is(err, ErrPaymentsUnresolved) {
		t.Fatalf("Reserve = %v, want ErrPaymentsUnresolved — an inherited row must freeze at "+
			"once, not %v later", err, UnresolvedAfter)
	}
}
