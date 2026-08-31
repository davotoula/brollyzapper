package store_test

import (
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"
)

// t4t: the marker is written BEFORE the send, so its absence is the safe
// direction.
//
// The resolver's not-found arm is the one arm allowed to reverse a reservation
// (§6), and its reason was an inference from LND's payment record surviving —
// which on a deliberately shared node it may not. This is the app owning the
// fact instead.
func TestAReservationStartsUndispatchedAndCanBeMarked(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0).UTC()
	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		1_000_000, "float", at); err != nil {
		t.Fatal(err)
	}
	id, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: "hash-a", Ref: "ref"}, at)
	if err != nil {
		t.Fatal(err)
	}

	// A fresh reservation has NOT been dispatched. That is what makes the
	// resolver's reversal provably safe rather than inferred.
	pending := pendingByID(t, s, id)
	if pending.Dispatched {
		t.Fatal("a reservation was marked dispatched before anything was sent")
	}

	if err := s.MarkSpendDispatched(t.Context(), id, at.Add(time.Second)); err != nil {
		t.Fatalf("MarkSpendDispatched: %v", err)
	}
	if pending := pendingByID(t, s, id); !pending.Dispatched {
		t.Error("the marker did not survive; the resolver would reverse a payment we sent")
	}
}

// Marking twice is not an error: the resolver re-runs, and a retry of a step
// that already happened is agreement rather than a failure.
func TestMarkingDispatchedTwiceIsNotAnError(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0).UTC()
	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		1_000_000, "float", at); err != nil {
		t.Fatal(err)
	}
	id, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: "hash-b", Ref: "ref"}, at)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.MarkSpendDispatched(t.Context(), id, at); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSpendDispatched(t.Context(), id, at.Add(time.Hour)); err != nil {
		t.Errorf("a second mark failed: %v", err)
	}
	// The FIRST moment stands. It is when the payment left, and a later write
	// would move a fact about the past.
	if got := dispatchedAt(t, s, id); got != at.Unix() {
		t.Errorf("dispatched_at = %d, want the first mark at %d", got, at.Unix())
	}
}

func pendingByID(t *testing.T, s *store.Store, id int64) store.PendingPayment {
	t.Helper()
	rows, err := s.PendingPaymentsBefore(t.Context(), time.Unix(1_900_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID == id {
			return row
		}
	}
	t.Fatalf("reservation %d is not pending", id)
	return store.PendingPayment{}
}

func dispatchedAt(t *testing.T, s *store.Store, id int64) int64 {
	t.Helper()
	at, found, err := s.DispatchedAt(t.Context(), id)
	if err != nil || !found {
		t.Fatalf("DispatchedAt(%d): found=%v err=%v", id, found, err)
	}
	return at.Unix()
}
