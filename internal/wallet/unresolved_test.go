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
	// The message has to route the operator somewhere: a freeze with no
	// instructions is an outage. What it must NOT do is say WHICH hold this is
	// (`j9d`). Reserve knows only that one exists — HasUnresolvedPaymentsBefore
	// is one bit — and it used to guess for both: "this usually clears itself …
	// a payment the log names as dispatched … is the exception". The Security
	// row reads the named count and can say; this sends the reader there.
	if !strings.Contains(err.Error(), "Security page") {
		t.Errorf("error = %q, want it to send the operator to the row that knows which hold "+
			"this is", err.Error())
	}
	if strings.Contains(err.Error(), "usually") {
		t.Errorf("error = %q hedges about which hold it is, from a bit that cannot tell; the "+
			"Security row is what settles it", err.Error())
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

// `v7u`: the NAMED unresolved payments are a strict subset of the unresolved
// ones, over the same cutoff.
//
// The ladder tells a paired client which hold it is in — one the resolver may
// still clear, or one waiting for a human on the Wallet page — and it decides by
// comparing these two counts. Two things can go wrong and both are invisible
// from the message alone: a named count that ignored the cutoff would describe a
// row the freeze is not held for, and one that ignored the marker would send
// every operator to a page with an empty table.
func TestTheNamedUnresolvedPaymentsAreTheSubsetTheResolverGaveUpOn(t *testing.T) {
	db, _ := openStore(t)
	started := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	w := walletAt(db, started)
	allocate(t, w, 1_000_000)

	// Three pending payments from a previous run, one of which the resolver has
	// given up on.
	var ids []ReservationID
	for _, ref := range []string{"named", "still trying", "also still trying"} {
		id, err := w.Reserve(t.Context(), Reservation{
			AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: aPaymentHash(), Ref: ref,
		})
		if err != nil {
			t.Fatalf("reserving %q: %v", ref, err)
		}
		ids = append(ids, id)
	}

	// A LATER wallet, so the three rows are older than its cutoff and all three
	// are holding sending. Without this they are "this run's" and count for
	// neither total.
	later := walletAt(db, started.Add(time.Hour))

	if got, err := later.UnresolvedPayments(t.Context()); err != nil {
		t.Fatal(err)
	} else if got != 3 {
		t.Fatalf("UnresolvedPayments = %d, want 3; the fixture would prove nothing", got)
	}
	if got, err := later.NamedUnresolvedPayments(t.Context()); err != nil {
		t.Fatal(err)
	} else if got != 0 {
		t.Errorf("NamedUnresolvedPayments = %d before the resolver named anything, want 0 — "+
			"every operator would be sent to the Wallet page to look at an empty table", got)
	}

	if err := later.MarkUnresolvable(t.Context(), ids[0], "the node has no record of it"); err != nil {
		t.Fatal(err)
	}

	if got, err := later.NamedUnresolvedPayments(t.Context()); err != nil {
		t.Fatal(err)
	} else if got != 1 {
		t.Errorf("NamedUnresolvedPayments = %d after one row was named, want 1", got)
	}
	// The other two are untouched: naming is per row, and the hold they impose
	// is still the kind that may clear itself.
	if got, err := later.UnresolvedPayments(t.Context()); err != nil {
		t.Fatal(err)
	} else if got != 3 {
		t.Errorf("UnresolvedPayments = %d after naming one, want 3 — naming a row does not "+
			"resolve it", got)
	}

	// THE CUTOFF, which is the half a count written straight off
	// UnresolvablePayments would lose: the operator's table has no cutoff, this
	// count must have the freeze's. A wallet that has just started sees none of
	// these rows as holding sending, so none of them are named-and-holding either.
	if got, err := w.NamedUnresolvedPayments(t.Context()); err != nil {
		t.Fatal(err)
	} else if got != 0 {
		t.Errorf("NamedUnresolvedPayments = %d for rows newer than this run's cutoff, want 0 — "+
			"the refusal would describe a row that is not holding sending", got)
	}
}
