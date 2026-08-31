package store_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// d24.2: the payment hash goes onto the row WITH the reservation, in one
// transaction.
//
// The alternative — reserve, then write the hash — has a window in which a
// crash leaves a reserved row the resolver cannot resolve: it has
// nothing to ask the node about, and §6 forbids reversing a reservation whose
// fate is unknown. Such a row can never be confirmed and never be reversed.
func TestAReservationCarriesItsPaymentHashFromTheStart(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0)
	const hash = "aa" + "00000000000000000000000000000000000000000000000000000000000000"
	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		1_000_000, "float", at); err != nil {
		t.Fatal(err)
	}

	id, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 10_000, MaxFeeMsat: 1_000, PaymentHash: hash, Ref: "invoice"}, at)
	if err != nil {
		t.Fatalf("ReserveSpend: %v", err)
	}

	pending, err := s.PendingPaymentsBefore(t.Context(), at.Add(time.Second))
	if err != nil {
		t.Fatalf("PendingPayments: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("PendingPayments returned %d rows, want 1", len(pending))
	}
	if pending[0].ID != id || pending[0].PaymentHash != hash {
		t.Errorf("pending = %+v, want id %d and hash %s", pending[0], id, hash)
	}
}

// PendingPayments is what the resolver iterates, so it must contain exactly the
// rows that need resolving — and nothing else.
//
// A settled or reversed payment reappearing here would be re-resolved on every
// start; an inbound invoice appearing here would be tracked as a payment that
// was never made.
func TestPendingPaymentsHoldsOnlyUnresolvedOutboundPayments(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0)
	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		1_000_000, "float", at); err != nil {
		t.Fatal(err)
	}

	settled, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 1_000, MaxFeeMsat: 100, PaymentHash: hashOf(1), Ref: "settled"}, at)
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 1_000, MaxFeeMsat: 100, PaymentHash: hashOf(2), Ref: "reversed"}, at)
	if err != nil {
		t.Fatal(err)
	}
	stillPending, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 1_000, MaxFeeMsat: 100, PaymentHash: hashOf(3), Ref: "pending"}, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SettleSpend(t.Context(), settled, 50, secret.String{}, at); err != nil {
		t.Fatal(err)
	}
	if err := s.ReverseSpend(t.Context(), reversed, at); err != nil {
		t.Fatal(err)
	}

	pending, err := s.PendingPaymentsBefore(t.Context(), at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ID != stillPending {
		t.Fatalf("pending = %+v, want only the unresolved payment %d", pending, stillPending)
	}
}

// utt, and the behaviour the bead exists for: reserve -> fail -> reverse ->
// reserve the SAME hash, and the second reservation succeeds.
//
// Retrying an invoice whose first attempt failed is ordinary NWC client
// behaviour and LND permits it. Until migration 0008 this schema did not: d24.2
// began recording payment_hash on outbound rows at reserve time, and the
// table-wide UNIQUE then meant a reversed payment kept the hash for ever. The
// first failed payment to any invoice poisoned it permanently.
func TestAReversedPaymentCanBeRetriedAgainstTheSameInvoice(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0)
	const hash = "cafe" + "000000000000000000000000000000000000000000000000000000000000"
	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		1_000_000, "float", at); err != nil {
		t.Fatal(err)
	}

	first, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 20_000, MaxFeeMsat: 1_000, PaymentHash: hash, Ref: "attempt 1"}, at)
	if err != nil {
		t.Fatalf("the first reservation: %v", err)
	}
	if err := s.ReverseSpend(t.Context(), first, at); err != nil {
		t.Fatalf("reversing the first attempt: %v", err)
	}

	second, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 20_000, MaxFeeMsat: 1_000, PaymentHash: hash, Ref: "attempt 2"}, at)
	if err != nil {
		t.Fatalf("retrying an invoice whose first attempt was reversed: %v — a failed payment "+
			"consumes no budget (§5), and the operator has to be able to try again", err)
	}
	if second == first {
		t.Error("the retry reused the reversed row rather than making its own")
	}
	// And the retry is the only thing pending, so the resolver has exactly one
	// row to finish.
	pending, err := s.PendingPaymentsBefore(t.Context(), at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ID != second {
		t.Errorf("pending = %+v, want only the retry %d", pending, second)
	}
}

// The other half of the same change: §6's settlement idempotency still refuses.
//
// Scoping the constraint is only safe if the thing it was FOR still works. LND
// re-delivers a settlement after a reconnect, and the guarantee that a replay
// credits nothing extra comes from the uniqueness, not from the stream loop.
func TestASettlementStillCreditsOnlyOnceUnderTheScopedConstraint(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0)
	const hash = "feed" + "000000000000000000000000000000000000000000000000000000000000"

	if err := s.CreateInvoice(t.Context(), openInvoice(hash, 5_000, at.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	credited, err := s.CreditSettledInvoice(t.Context(), hash, "00", 5_000, at, true)
	if err != nil || !credited {
		t.Fatalf("the first settlement: credited=%v err=%v", credited, err)
	}
	after, err := s.BalanceMsat(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	// The redelivery.
	credited, err = s.CreditSettledInvoice(t.Context(), hash, "00", 5_000, at, true)
	if err != nil {
		t.Fatalf("the replayed settlement: %v", err)
	}
	if credited {
		t.Error("a replayed settlement reported a fresh credit")
	}
	again, err := s.BalanceMsat(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if again != after {
		t.Errorf("the balance moved from %d to %d on a replay; the partial index is what makes "+
			"the second insert a no-op (§6)", after, again)
	}
}

// The self-payment case, with its meaning changed by utt's ruling.
//
// It used to collide, and the collision was ruled acceptable because LND
// refuses self-payments anyway. Scoping the constraint to inbound removes the
// collision, so the row now INSERTS — and this asserts the new shape rather
// than being deleted, because "we can reserve against our own invoice's hash"
// is a thing a reader will want to know is deliberate.
//
// The payment still cannot succeed: LND refuses it, the send fails, and the
// reservation reverses like any other failure. That is a better answer than an
// opaque insert error, which is what the old behaviour gave a caller.
func TestReservingAgainstOurOwnInvoiceHashNowInsertsAndReversesNormally(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0)
	const hash = "beef" + "000000000000000000000000000000000000000000000000000000000000"

	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		1_000_000, "float", at); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateInvoice(t.Context(), openInvoice(hash, 5_000, at.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreditSettledInvoice(t.Context(), hash, "00", 5_000, at, true); err != nil {
		t.Fatal(err)
	}
	before, err := s.BalanceMsat(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	id, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 5_000, MaxFeeMsat: 500, PaymentHash: hash, Ref: "self-payment"}, at)
	if err != nil {
		t.Fatalf("reserving against our own invoice's hash: %v — the constraint is scoped to "+
			"inbound rows now, so this is an ordinary outbound row", err)
	}
	// And it reverses cleanly, which is the path a real self-payment takes once
	// LND refuses it.
	if err := s.ReverseSpend(t.Context(), id, at); err != nil {
		t.Fatalf("reversing it: %v", err)
	}
	after, err := s.BalanceMsat(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("balance moved from %d to %d across a reserve-and-reverse; a failed payment "+
			"consumes no budget (§5)", before, after)
	}
}

// hashOf makes a distinct 64-hex payment hash. txns.payment_hash is UNIQUE, so
// tests that reserve more than once need one each — and distinct for every n a
// test could reach, not just the small ones: an earlier version varied only the
// last digit and would have collided silently, deep inside ReserveSpend, at the
// eleventh call.
func hashOf(n int) string { return fmt.Sprintf("%064d", n) }

// The protection the table-wide constraint was giving ACCIDENTALLY, kept on
// purpose: two payments for one invoice may not be in flight at once.
//
// Without it the resolver asks the node about the same hash once per row, gets
// SUCCEEDED, and settles BOTH — the ledger debited twice for a single payment,
// permanently. Reconciliation does not catch that: the wallet ends up lower than
// the node, which is the safe direction and raises no shortfall.
//
// The retry case still works, and that pairing is the point: it is the STATE
// that makes the difference, so a resolved payment leaves the index.
func TestTwoPaymentsForOneInvoiceCannotBeInFlightAtOnce(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0)
	const hash = "1234" + "000000000000000000000000000000000000000000000000000000000000"
	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		1_000_000, "float", at); err != nil {
		t.Fatal(err)
	}

	first, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: hash, Ref: "attempt 1"}, at)
	if err != nil {
		t.Fatalf("the first reservation: %v", err)
	}
	if _, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: hash, Ref: "concurrent"}, at); err == nil {
		t.Fatal("a second payment for the same invoice was reserved while the first was still " +
			"in flight; the resolver would settle both and debit the ledger twice")
	}

	// Resolve the first, and the retry goes through — which is what separates
	// this from the table-wide constraint utt removed.
	if err := s.ReverseSpend(t.Context(), first, at); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: hash, Ref: "attempt 2"}, at); err != nil {
		t.Errorf("retrying after the first attempt resolved: %v", err)
	}
}
