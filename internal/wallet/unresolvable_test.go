package wallet

import (
	"errors"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"
)

// 669 criterion 8, and it is the important one: a row the resolver has NOT
// named cannot be closed.
//
// §6 says only the operator can say whether such a payment settled — it does not
// say they may say it about a row the app is still working on. An operator
// racing the recon loop, asserting an outcome for a payment the node is about to
// answer for, is a worse failure than the stranded row this control exists to
// clear. So the gate is the resolver's marker, and nothing else.
func TestARowTheResolverStillOwnsCannotBeClosed(t *testing.T) {
	w, db, _ := newWalletAt(t)
	allocate(t, w, 1_000_000)
	id, err := w.Reserve(t.Context(), Reservation{
		AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: aPaymentHash(), Ref: "in flight",
	})
	if err != nil {
		t.Fatal(err)
	}
	balanceBefore, _ := w.Balance(t.Context())

	for _, settled := range []bool{true, false} {
		if err := w.AssertOutcome(t.Context(), id, settled); !errors.Is(err, store.ErrNotUnresolvable) {
			t.Errorf("AssertOutcome(settled=%v) = %v, want ErrNotUnresolvable — the resolver "+
				"has not given up on this row, and an operator must not be able to pre-empt it",
				settled, err)
		}
	}
	// And nothing moved. A refused assertion that had already written a balance
	// entry would be the worst of both.
	if got, _ := w.Balance(t.Context()); got != balanceBefore {
		t.Errorf("balance moved %d -> %d on a refused assertion", balanceBefore, got)
	}
	if rows, err := db.PendingPaymentsBefore(t.Context(), w.UnresolvedCutoff().Add(time.Hour)); err != nil {
		t.Fatal(err)
	} else if len(rows) != 1 {
		t.Errorf("%d rows are pending, want the 1 that was refused", len(rows))
	}
	// It is also not OFFERED: the page lists only named rows.
	if offered, err := w.Unresolvable(t.Context()); err != nil {
		t.Fatal(err)
	} else if len(offered) != 0 {
		t.Errorf("%d rows are offered to the operator, want none", len(offered))
	}
}

// Criterion 7: a NAMED row can be closed either way, the freeze lifts, and the
// ledger says the right thing in both directions.
func TestANamedRowCanBeClosedEitherWayAndTheFreezeLifts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		settled bool
		// wantSpent is what the whole episode costs the ceiling.
		wantSpent int64
		wantState string
	}{
		// It settled: the money is gone, and the reservation stands in full. The
		// operator cannot know the route's fee, so the reserve is what is booked
		// — inventing a smaller number would credit the ceiling with sats the
		// node may well have spent.
		{"asserted settled", true, 10_100, store.TxnSettled},
		// It failed: a failed payment consumes nothing, so the whole reservation
		// comes back.
		{"asserted failed", false, 0, store.TxnFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, db, _ := newWalletAt(t)
			allocate(t, w, 1_000_000)
			before, _ := w.Balance(t.Context())
			id, err := w.Reserve(t.Context(), Reservation{
				AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: aPaymentHash(), Ref: "stuck",
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := w.MarkUnresolvable(t.Context(), id, "the node has no record of it"); err != nil {
				t.Fatal(err)
			}

			// It is offered, with what the operator needs to check at the node.
			offered, err := w.Unresolvable(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if len(offered) != 1 {
				t.Fatalf("%d rows offered, want 1", len(offered))
			}
			if offered[0].PaymentHash == "" || offered[0].AmountMsat != 10_000 ||
				offered[0].Reason == "" {
				t.Errorf("the offered row does not carry what an operator needs to look it up: "+
					"%+v", offered[0])
			}

			if err := w.AssertOutcome(t.Context(), id, tc.settled); err != nil {
				t.Fatalf("AssertOutcome: %v", err)
			}

			if got, _ := w.Balance(t.Context()); got != before-tc.wantSpent {
				t.Errorf("balance %d, want %d", got, before-tc.wantSpent)
			}
			// THE FREEZE LIFTS, which is what the operator actually feels.
			later := walletAt(db, testTime.Add(time.Hour))
			if _, err := later.Reserve(t.Context(), Reservation{
				AmountMsat: 1_000, MaxFeeMsat: 10, PaymentHash: aPaymentHash(), Ref: "after",
			}); err != nil {
				t.Errorf("Reserve after the assertion: %v — the freeze outlived the row", err)
			}
			// And it is no longer offered: a row an operator has already decided
			// must not come back and invite a second, different decision.
			if again, _ := later.Unresolvable(t.Context()); len(again) != 0 {
				t.Errorf("%d rows are still offered after being closed", len(again))
			}
		})
	}
}
