package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/store"
)

// fakeBudgets is the resolver's connectionBudgets seam.
type fakeBudgets struct {
	adjustments map[int64]int64
	err         error
}

func (f *fakeBudgets) AdjustNWCBudget(_ context.Context, id, deltaMsat int64) error {
	if f.err != nil {
		return f.err
	}
	if f.adjustments == nil {
		f.adjustments = map[int64]int64{}
	}
	f.adjustments[id] += deltaMsat
	return nil
}

// A crash-recovered payment's connection budget is corrected from the RESERVE to
// what it actually spent (d24.15).
//
// Measured on the 0.1.9 box, and these are its numbers: a 21 sat payment
// reserved 10 000 msat of fee and the route cost 2 055, so the ladder's live
// path charges 23 055 and the recovery path charged 31 000. Every crash-
// recovered payment consumed ~38% more of the daily budget than it should,
// accumulating toward a QUOTA_EXCEEDED the operator did not earn.
//
// It could never cause an over-spend — the drift is conservative — which is why
// it took a field trip to find, and why it is exactly the drift the fee-reserve
// correction exists to prevent.
func TestARecoveredPaymentsBudgetIsCorrectedToTheActualFee(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq}
	node := &fakePayer{recorder: seq, result: lnd.PaymentResult{
		Status: lnrpc.Payment_SUCCEEDED, FeeMsat: 2_055,
	}}
	budgets := &fakeBudgets{}
	pending := &fakePending{rows: []store.PendingPayment{{
		ID: 16, PaymentHash: "abcd", Dispatched: true,
		AmountMsat: 21_000, FeeReservedMsat: 10_000, NWCConnectionID: 2,
	}}}

	if err := resolvePendingPayments(t.Context(), pending, purse, node, budgets,
		aCutoff, quietLog()); err != nil {
		t.Fatalf("resolvePendingPayments: %v", err)
	}

	// 2 055 actual against 10 000 reserved: 7 945 msat comes back.
	if got := budgets.adjustments[2]; got != -7_945 {
		t.Errorf("the connection budget moved by %d msat, want -7945 — the unused fee reserve. "+
			"Without it this connection is charged 31000 for a payment that spent 23055", got)
	}
}

// A crash-recovered payment that FAILED returns its budget IN FULL.
//
// Not what the field trip measured — it measured the settled case — and the
// larger of the two: §8 says a failed payment consumes no budget, the live path
// returns the whole reservation, and on the recovery path the connection kept
// all of it. A wallet app whose payment failed during a restart was charged for
// a payment that never happened.
func TestARecoveredPaymentThatFailedReturnsItsWholeBudget(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq}
	node := &fakePayer{recorder: seq, result: lnd.PaymentResult{Status: lnrpc.Payment_FAILED}}
	budgets := &fakeBudgets{}
	pending := &fakePending{rows: []store.PendingPayment{{
		ID: 17, PaymentHash: "abcd", Dispatched: true,
		AmountMsat: 21_000, FeeReservedMsat: 10_000, NWCConnectionID: 2,
	}}}

	if err := resolvePendingPayments(t.Context(), pending, purse, node, budgets,
		aCutoff, quietLog()); err != nil {
		t.Fatalf("resolvePendingPayments: %v", err)
	}

	if got := budgets.adjustments[2]; got != -31_000 {
		t.Errorf("the connection budget moved by %d msat, want -31000 — the whole reservation. "+
			"§8: a failed payment consumes no budget", got)
	}
}

// A SECOND resolver pass over a row another pass already closed corrects
// nothing.
//
// The correction adds a signed number to a running total, so it is not
// idempotent — and notPendingIsFine deliberately treats "already closed" as
// agreement, because the resolver is re-runnable by design (it runs at startup
// and on every recon tick). Without the closed/not-closed distinction the second
// pass would credit the connection 7 945 msat it never reserved.
func TestASecondResolverPassDoesNotCorrectTheBudgetTwice(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq, settleErr: store.ErrReservationNotPending}
	node := &fakePayer{recorder: seq, result: lnd.PaymentResult{
		Status: lnrpc.Payment_SUCCEEDED, FeeMsat: 2_055,
	}}
	budgets := &fakeBudgets{}
	pending := &fakePending{rows: []store.PendingPayment{{
		ID: 16, PaymentHash: "abcd", Dispatched: true,
		AmountMsat: 21_000, FeeReservedMsat: 10_000, NWCConnectionID: 2,
	}}}

	if err := resolvePendingPayments(t.Context(), pending, purse, node, budgets,
		aCutoff, quietLog()); err != nil {
		t.Fatalf("resolvePendingPayments: %v", err)
	}

	if got, ok := budgets.adjustments[2]; ok {
		t.Errorf("a row that was already closed moved the budget by %d msat; the correction is "+
			"not idempotent and the resolver re-runs on every recon tick", got)
	}
}

// A payment no connection asked for leaves every connection budget alone.
//
// Every row written before this wave has nwc_connection_id NULL, and so does any
// payment an operator made some other way. There is nothing to correct, and
// inventing a connection to correct would be worse than the drift.
func TestARecoveredPaymentWithNoConnectionCorrectsNothing(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq}
	node := &fakePayer{recorder: seq, result: lnd.PaymentResult{
		Status: lnrpc.Payment_SUCCEEDED, FeeMsat: 2_055,
	}}
	budgets := &fakeBudgets{}
	pending := &fakePending{rows: []store.PendingPayment{{
		ID: 3, PaymentHash: "abcd", Dispatched: true,
		AmountMsat: 21_000, FeeReservedMsat: 10_000,
	}}}

	if err := resolvePendingPayments(t.Context(), pending, purse, node, budgets,
		aCutoff, quietLog()); err != nil {
		t.Fatalf("resolvePendingPayments: %v", err)
	}
	if len(budgets.adjustments) != 0 {
		t.Errorf("a payment with no connection adjusted %v", budgets.adjustments)
	}
}

// A budget correction that FAILS does not un-resolve the payment.
//
// The ledger is right and the reservation is closed; this is a second number on
// a different table. Reporting it as a resolution failure would leave the freeze
// standing and hold every later payment over a budget counter. It is logged
// loudly instead, because the residue is what an operator would otherwise be
// left guessing about.
func TestAFailedBudgetCorrectionStillResolvesThePayment(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq}
	node := &fakePayer{recorder: seq, result: lnd.PaymentResult{
		Status: lnrpc.Payment_SUCCEEDED, FeeMsat: 2_055,
	}}
	budgets := &fakeBudgets{err: errors.New("the database is locked")}
	pending := &fakePending{rows: []store.PendingPayment{{
		ID: 16, PaymentHash: "abcd", Dispatched: true,
		AmountMsat: 21_000, FeeReservedMsat: 10_000, NWCConnectionID: 2,
	}}}
	log, logged := capturingLog()

	if err := resolvePendingPayments(t.Context(), pending, purse, node, budgets,
		aCutoff, log); err != nil {
		t.Fatalf("a budget counter took the payment resolution down with it: %v", err)
	}
	if !strings.Contains(logged.String(), `"level":"ERROR"`) {
		t.Error("the failed correction was not reported at ERROR; the residue is invisible")
	}
}
