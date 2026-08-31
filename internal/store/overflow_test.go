package store_test

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"
)

// The amount an outbound payment is for reaches this store from a REMOTE wallet
// app (§8's pay_invoice, d24.4), so its range is an attacker's choice.
//
// Found by the d24.4 review, and it is the worst kind of bug this app can have:
// `-(amountMsat + maxFeeMsat)` wraps for an amount near MaxInt64, so the debit
// becomes a large POSITIVE balance entry. appendBalanceEntry only refuses a
// NEGATIVE total, so it commits — and the wallet ceiling, which is the whole
// safety story of this app, goes up by ~9.2e18 msat. Every later "is there
// enough?" then passes, and the connection can drain the node's real channel
// balance with ordinary-looking payments until reconciliation notices.
//
// The ladder bounds the amount too. This is the layer that must refuse it
// whatever the ladder does, because it is the one that owns the ledger.
func TestAReservationCannotOverflowTheLedger(t *testing.T) {
	cases := []struct {
		name       string
		amountMsat int64
		maxFeeMsat int64
	}{
		{"the largest int64", math.MaxInt64, 10_000},
		{"an amount that wraps only once the fee is added", math.MaxInt64 - 5, 10},
		{"past the money supply", store.MaxMsat + 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := open(t)
			at := time.Unix(1_700_000_000, 0).UTC()
			if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
				1_000_000, "float", at); err != nil {
				t.Fatal(err)
			}

			_, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: tc.amountMsat, MaxFeeMsat: tc.maxFeeMsat, PaymentHash: "hash", Ref: "ref"}, at)

			// The SENTINEL, not merely "an error". Asserting err != nil passed
			// against the unfixed code: with a float already allocated, SQLite's
			// own SUM overflows and refuses the row for a reason that has nothing
			// to do with this bound — so the test was green before the fix and
			// after it, and proved neither. (Found by planting the fix away.)
			if !errors.Is(err, store.ErrAmountOutOfRange) {
				t.Errorf("the reservation failed with %v, want ErrAmountOutOfRange — an "+
					"amount this size must be refused for BEING out of range, not by "+
					"whatever arithmetic happens to notice downstream", err)
			}
			balance, berr := s.BalanceMsat(t.Context())
			if berr != nil {
				t.Fatal(berr)
			}
			if balance != 1_000_000 {
				t.Errorf("the balance is %d msat, want the 1,000,000 it started with — a "+
					"refused reservation must not move the ceiling, and an overflowing one "+
					"must not RAISE it", balance)
			}
		})
	}
}

// The same bound on the operator's own entries. An allocation is typed by a
// human, so this is not an attack surface — but the ledger's invariant is about
// the ledger, not about who is writing to it.
func TestAnAllocationCannotOverflowTheLedger(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0).UTC()

	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		math.MaxInt64, "float", at); !errors.Is(err, store.ErrAmountOutOfRange) {
		t.Errorf("an allocation of MaxInt64 msat failed with %v, want ErrAmountOutOfRange", err)
	}
	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		store.MaxMsat/2, "half the supply", at); err != nil {
		t.Fatalf("a large but sane allocation was refused: %v", err)
	}
	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		store.MaxMsat/2+2, "the other half, plus one", at); err == nil {
		t.Error("two allocations summing past the money supply were accepted; the bound is " +
			"on the LEDGER, not on one entry")
	}
}

// A second in-flight payment for one invoice is refused by name, not by a raw
// constraint error (test-spec E7, and §8 has to tell the client which it was).
func TestASecondPaymentForOneInvoiceIsNamedAsSuch(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0).UTC()
	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		1_000_000, "float", at); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: "same-hash", Ref: "first"}, at); err != nil {
		t.Fatal(err)
	}

	_, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: "same-hash", Ref: "second"}, at)

	if !errors.Is(err, store.ErrPaymentInFlight) {
		t.Errorf("the second reservation failed with %v, want ErrPaymentInFlight — the ladder "+
			"has to tell a client its invoice is already being paid, and give the budget back", err)
	}
}
