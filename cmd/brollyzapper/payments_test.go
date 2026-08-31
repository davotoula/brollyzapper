package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/wallet"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// §5's order, which is the whole invariant: RESERVE first, then send — with
// t4t's dispatch marker between them, and its POSITION is the second invariant
// this sequence carries. A marker written after the send has a window in which
// the process dies with the payment made and no record of making it, which is
// the row the resolver would then wrongly reverse.
//
// The other order is a payment made against a ceiling nobody checked. Asserting
// on the recorded sequence rather than on the end state, because both orders
// reach the same end state when everything works — the difference only appears
// when the reserve would have refused.
func TestAPaymentReservesBeforeItSends(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq}
	node := &fakePayer{recorder: seq, result: lnd.PaymentResult{
		Status: lnrpc.Payment_SUCCEEDED, FeeMsat: 40}}

	if _, err := payInvoice(t.Context(), payment{
		bolt11: "lnbcrt1", amountMsat: 10_000, maxFeeMsat: 100, paymentHash: "ab",
	}, purse, node, quietLog()); err != nil {
		t.Fatalf("payInvoice: %v", err)
	}

	if want := []string{"reserve", "dispatch", "send", "settle"}; !slices.Equal(seq.seen(), want) {
		t.Errorf("order = %v, want %v — §5 invariant 2 is that nothing is sent before the "+
			"ceiling has been debited", seq.seen(), want)
	}
}

// wallet.MaxFee is THE number: what the reservation debits and what LND is
// given as fee_limit_msat. There is no second computation anywhere.
func TestTheReservedFeeIsTheFeeLimitSent(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq}
	node := &fakePayer{recorder: seq, result: lnd.PaymentResult{Status: lnrpc.Payment_SUCCEEDED}}

	const maxFee = int64(2_500)
	if _, err := payInvoice(t.Context(), payment{
		bolt11: "lnbcrt1", amountMsat: 10_000, maxFeeMsat: maxFee, paymentHash: "ab",
	}, purse, node, quietLog()); err != nil {
		t.Fatalf("payInvoice: %v", err)
	}
	if purse.reservedFee != maxFee {
		t.Errorf("reserved fee = %d, want %d", purse.reservedFee, maxFee)
	}
	if node.feeLimit != maxFee {
		t.Errorf("fee_limit_msat = %d, want the reserved %d", node.feeLimit, maxFee)
	}
}

// The route's ACTUAL fee settles the reservation, and the difference comes back.
// The arithmetic itself lives in the store; this asserts the right number
// reaches it.
func TestASuccessfulPaymentSettlesWithTheRoutesActualFee(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq}
	node := &fakePayer{recorder: seq, result: lnd.PaymentResult{
		Status: lnrpc.Payment_SUCCEEDED, FeeMsat: 37}}

	result, err := payInvoice(t.Context(), payment{
		bolt11: "lnbcrt1", amountMsat: 10_000, maxFeeMsat: 500, paymentHash: "ab",
	}, purse, node, quietLog())
	if err != nil {
		t.Fatalf("payInvoice: %v", err)
	}
	if !result.Succeeded() {
		t.Fatalf("result = %+v, want SUCCEEDED", result)
	}
	if purse.settledFee != 37 {
		t.Errorf("settled with fee %d, want the route's actual 37 — the reserve was 500 and the "+
			"difference is refunded by SettleSpend (§5)", purse.settledFee)
	}
}

// §5: a failed payment consumes no budget. It is REVERSED, not settled, and it
// is not an error — the caller is told what happened and the ceiling is whole.
func TestAFailedPaymentIsReversedAndIsNotAnError(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq}
	node := &fakePayer{recorder: seq, result: lnd.PaymentResult{
		Status:        lnrpc.Payment_FAILED,
		FailureReason: lnrpc.PaymentFailureReason_FAILURE_REASON_NO_ROUTE,
	}}

	result, err := payInvoice(t.Context(), payment{
		bolt11: "lnbcrt1", amountMsat: 10_000, maxFeeMsat: 500, paymentHash: "ab",
	}, purse, node, quietLog())
	if err != nil {
		t.Fatalf("a routing failure was reported as an error: %v", err)
	}
	if !result.Failed() {
		t.Fatalf("result = %+v, want FAILED", result)
	}
	if want := []string{"reserve", "dispatch", "send", "reverse"}; !slices.Equal(seq.seen(), want) {
		t.Errorf("order = %v, want %v — a failed payment consumes no budget (§5)",
			seq.seen(), want)
	}
}

// The dangerous case: the send itself errored, so the payment's fate is UNKNOWN.
//
// It must NOT be reversed. §6: reversing a reserved-but-unresolved payment
// double-spends the ceiling if it later settles. The reservation stays pending
// and the resolver — on the next start or the next recon tick — finishes it.
func TestASendThatErrorsLeavesTheReservationPending(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq}
	node := &fakePayer{recorder: seq, err: errors.New("the node stopped answering mid-payment")}

	_, err := payInvoice(t.Context(), payment{
		bolt11: "lnbcrt1", amountMsat: 10_000, maxFeeMsat: 500, paymentHash: "ab",
	}, purse, node, quietLog())
	if err == nil {
		t.Fatal("a send that errored was reported as success")
	}
	if want := []string{"reserve", "dispatch", "send"}; !slices.Equal(seq.seen(), want) {
		t.Errorf("order = %v, want %v — the payment may be in flight, and §6 forbids reversing "+
			"a reservation whose fate is unknown", seq.seen(), want)
	}
}

// A reservation the wallet REFUSES stops the payment dead.
//
// This is what "reserve before send" is actually for. The wallet refuses on
// insufficient balance and — the case that matters — while reconciliation has
// frozen spending (§5), and Reserve is where that freeze lives precisely so
// every outbound path inherits it. If the send went first, a frozen wallet
// would still pay.
func TestAPaymentTheWalletRefusesIsNeverSent(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq, reserveErr: errors.New("spending is frozen")}
	node := &fakePayer{recorder: seq, result: lnd.PaymentResult{Status: lnrpc.Payment_SUCCEEDED}}

	if _, err := payInvoice(t.Context(), payment{
		bolt11: "lnbcrt1", amountMsat: 10_000, maxFeeMsat: 100, paymentHash: "ab",
	}, purse, node, quietLog()); err == nil {
		t.Fatal("a payment the wallet refused to reserve for was reported as sent")
	}
	if got := seq.seen(); !slices.Equal(got, []string{"reserve"}) {
		t.Errorf("calls = %v, want only the refused reserve — nothing may reach the node "+
			"after the ceiling said no (§5)", got)
	}
}

// The resolver, arm by arm. This is the table from the brief, and each
// row is a decision about money.
func TestTheResolverResolvesEveryPendingPayment(t *testing.T) {
	for _, tc := range []struct {
		name     string
		track    lnd.PaymentResult
		trackErr error
		// wantErr states whether the pass reports the row as unresolved, rather
		// than re-deriving it from trackErr at the assertion.
		wantErr    bool
		want       []string
		dispatched bool
	}{{
		name:  "succeeded is settled with the actual fee",
		track: lnd.PaymentResult{Status: lnrpc.Payment_SUCCEEDED, FeeMsat: 21},
		want:  []string{"track", "settle"},
	}, {
		name:  "failed is reversed",
		track: lnd.PaymentResult{Status: lnrpc.Payment_FAILED},
		want:  []string{"track", "reverse"},
	}, {
		// The node has no record AND we never handed it over — our own marker
		// says so (t4t). Provably safe: this is the only failure that licenses
		// reversing at all, and now its reason is a fact rather than an
		// inference from LND's records surviving.
		name:     "not found and never dispatched is reversed",
		trackErr: lnd.ErrPaymentNotFound,
		want:     []string{"track", "reverse"},
	}, {
		// DISPATCHED, and the node has forgotten it. The case the Wave 21
		// ruling did not have: on a shared node another app can run
		// deletepayments, and a restore from an older backup has the same
		// effect. The payment may have settled, so §6 forbids reversing —
		// nothing moves, and it is named so an operator looks.
		name:       "not found but dispatched touches nothing",
		trackErr:   lnd.ErrPaymentNotFound,
		dispatched: true,
		wantErr:    true,
		want:       []string{"track"},
	}, {
		// Anything else leaves the fate unknown, and §6 forbids acting on that.
		name:     "an unreachable node changes nothing",
		trackErr: errors.New("connection refused"),
		wantErr:  true,
		want:     []string{"track"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			seq := &recorder{}
			purse := &fakeSpender{recorder: seq}
			node := &fakePayer{recorder: seq, result: tc.track, err: tc.trackErr}
			pending := &fakePending{rows: []store.PendingPayment{
				{ID: 7, PaymentHash: "abcd", Dispatched: tc.dispatched},
			}}

			err := resolvePendingPayments(t.Context(), pending, purse, node, nil, aCutoff, quietLog())
			if tc.wantErr && err == nil {
				t.Error("an unresolvable payment was reported as resolved")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("resolvePendingPayments: %v", err)
			}
			if !slices.Equal(seq.seen(), tc.want) {
				t.Errorf("calls = %v, want %v", seq.seen(), tc.want)
			}
			// The cutoff travels. A resolver that asked for everything would
			// grab a payment this process is still making (u0u).
			if !pending.asked.Equal(aCutoff) {
				t.Errorf("the store was asked for rows before %v, want the process start %v",
					pending.asked, aCutoff)
			}
			if tc.track.Succeeded() && purse.settledFee != 21 {
				t.Errorf("settled with fee %d, want the tracked 21", purse.settledFee)
			}
		})
	}
}

// The defect row: pending, and no hash to ask the node about.
//
// Impossible by construction after this wave — wallet.Reserve refuses one — so
// meeting it means something else is wrong. It is reported and LEFT PENDING.
// Never auto-reversed: §6's sentence is that a reserved-but-unresolved payment
// must never be silently reversed, because that double-spends the ceiling.
func TestAPendingPaymentWithNoHashIsReportedAndLeftAlone(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq}
	node := &fakePayer{recorder: seq}
	pending := &fakePending{rows: []store.PendingPayment{{ID: 9, PaymentHash: ""}}}
	log, logged := capturingLog()

	err := resolvePendingPayments(t.Context(), pending, purse, node, nil, aCutoff, log)
	if err == nil {
		t.Fatal("a row the resolver cannot resolve was reported as resolved")
	}
	if got := seq.seen(); len(got) != 0 {
		t.Errorf("something was called (%v); a row with no hash must be left exactly as it is "+
			"and the node has nothing to be asked", got)
	}
	if len(node.trackedHashes) != 0 {
		t.Errorf("the node was asked about %v; there is no hash to ask about", node.trackedHashes)
	}
	if !strings.Contains(logged.String(), `"level":"ERROR"`) {
		t.Error("no ERROR was logged; this is a defect an operator has to see, and recon is the " +
			"only other thing that will ever look at the row")
	}
}

// Idempotent and re-runnable: a row another instance already resolved is a
// no-op, not a failure. ErrReservationNotPending is the store SAYING so.
func TestResolvingAnAlreadySettledRowIsANoOp(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq, settleErr: store.ErrReservationNotPending}
	node := &fakePayer{recorder: seq, result: lnd.PaymentResult{Status: lnrpc.Payment_SUCCEEDED}}
	pending := &fakePending{rows: []store.PendingPayment{{ID: 3, PaymentHash: "ab"}}}

	if err := resolvePendingPayments(t.Context(), pending, purse, node, nil, aCutoff, quietLog()); err != nil {
		t.Fatalf("resolving a row that was already settled failed: %v — the store reporting "+
			"'not pending' is it agreeing with us, not refusing", err)
	}
}

// One bad row must not strand the rest. The resolver reports at the end.
func TestOneUnresolvableRowDoesNotStopTheOthers(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq}
	node := &fakePayer{recorder: seq, result: lnd.PaymentResult{
		Status: lnrpc.Payment_SUCCEEDED, FeeMsat: 1}}
	pending := &fakePending{rows: []store.PendingPayment{
		{ID: 1, PaymentHash: ""},     // the defect
		{ID: 2, PaymentHash: "beef"}, // resolvable
	}}

	if err := resolvePendingPayments(t.Context(), pending, purse, node, nil, aCutoff, quietLog()); err == nil {
		t.Fatal("the defect row was not reported")
	}
	if !slices.Equal(seq.seen(), []string{"track", "settle"}) {
		t.Errorf("calls = %v, want the second row tracked and settled", seq.seen())
	}
}

// --- fakes -----------------------------------------------------------------

// recorder is ONE sequence shared by the wallet and the node fakes.
//
// Two lists could not express the assertion that matters: "reserve came before
// send" is a statement about the order of calls to two DIFFERENT collaborators,
// and §5 invariant 2 is exactly that statement.
type recorder struct {
	mu    sync.Mutex
	order []string
}

func (r *recorder) record(what string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order = append(r.order, what)
}

func (r *recorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.order...)
}

type fakeSpender struct {
	*recorder
	reservedFee int64
	settledFee  int64
	reserveErr  error
	settleErr   error
	dispatchErr error
	// reserved is every reservation this fake was handed, so a test can assert
	// what the ledger row would carry (d24.15, d24.16).
	reserved []wallet.Reservation
	// settledPreimage is the proof handed to the settle, which must be the
	// node's and must never have been logged on the way (d24.16).
	settledPreimage secret.String
	// named is every row this resolver gave up on, and attempts is the
	// persistent-failure counter (`669`).
	named    []namedRow
	attempts int
}

func (f *fakeSpender) Reserve(_ context.Context, req wallet.Reservation) (wallet.ReservationID, error) {
	maxFeeMsat := req.MaxFeeMsat
	f.reserved = append(f.reserved, req)
	f.record("reserve")
	f.reservedFee = maxFeeMsat
	return 42, f.reserveErr
}

func (f *fakeSpender) Settle(_ context.Context, _ wallet.ReservationID, actualFeeMsat int64,
	preimage secret.String) error {
	f.settledPreimage = preimage
	f.record("settle")
	f.settledFee = actualFeeMsat
	return f.settleErr
}

func (f *fakeSpender) Reverse(context.Context, wallet.ReservationID) error {
	f.record("reverse")
	return nil
}

// MarkDispatched records the ORDER, because the order is the property (t4t): a
// marker written after the send leaves a window in which the process dies with
// the payment made and no record of making it.
func (f *fakeSpender) MarkDispatched(_ context.Context, _ wallet.ReservationID) error {
	f.record("dispatch")
	return f.dispatchErr
}

// ClearDispatched is the counterpart, and it is recorded in the SEQUENCE because
// that is the property: a send that never reached the node must take the marker
// back off, or the resolver refuses to touch the row for ever (t4t).
func (f *fakeSpender) ClearDispatched(_ context.Context, _ wallet.ReservationID) error {
	f.record("undispatch")
	return nil
}

// The `669` half. NOT recorded in the sequence: the sequence is about what the
// resolver does to the MONEY, and naming a row moves none — mixing them would
// make every existing call-order assertion fail for a reason unrelated to what
// it is testing.
func (f *fakeSpender) MarkUnresolvable(_ context.Context, id wallet.ReservationID, reason string) error {
	f.named = append(f.named, namedRow{id: id, reason: reason})
	return nil
}

func (f *fakeSpender) NoteResolveAttempt(context.Context, wallet.ReservationID) (int, error) {
	f.attempts++
	return f.attempts, nil
}

func (f *fakeSpender) ClearResolveAttempts(context.Context, wallet.ReservationID) error {
	f.attempts = 0
	return nil
}

// namedRow is one row the resolver gave up on, with its reason.
type namedRow struct {
	id     wallet.ReservationID
	reason string
}

type fakePayer struct {
	*recorder
	result        lnd.PaymentResult
	err           error
	feeLimit      int64
	trackedHashes []string
}

func (f *fakePayer) SendPayment(_ context.Context, _ string, feeLimitMsat int64) (lnd.PaymentResult, error) {
	f.record("send")
	f.feeLimit = feeLimitMsat
	return f.result, f.err
}

func (f *fakePayer) TrackPayment(_ context.Context, paymentHash []byte) (lnd.PaymentResult, error) {
	f.record("track")
	f.trackedHashes = append(f.trackedHashes, string(paymentHash))
	return f.result, f.err
}

// fakePending records the cutoff it was asked for, because "older than this
// process's start" is a criterion of u0u and a resolver that ignored it would
// grab a payment still being made. Asserted in the resolver table below.
type fakePending struct {
	rows  []store.PendingPayment
	asked time.Time
}

func (f *fakePending) PendingPaymentsBefore(_ context.Context, before time.Time) ([]store.PendingPayment, error) {
	f.asked = before
	return f.rows, nil
}

// aCutoff is a process-start moment for tests whose subject is not the cutoff.
var aCutoff = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func quietLog() *slog.Logger { return logging.New(io.Discard, logging.NewLevelVar(slog.LevelDebug)) }

// capturingLog is the REAL logger over a buffer — the house pattern, and not a
// bespoke handler. Going through logging.New matters beyond the line count: it
// is what makes a redaction regression visible to a log assertion, because the
// slog.LogValuer types only redact through the app's own handler.
func capturingLog() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return logging.New(&buf, logging.NewLevelVar(slog.LevelDebug)), &buf
}

// A send that never reached the node takes its marker back off.
//
// Found by review, and it is the difference between a reservation the next
// resolver pass tidies away and one frozen for ever. t4t writes the marker
// BEFORE the send so its absence is safe — but LND being down means the request
// never left, and a marker for a payment the node has never heard of puts the
// row in the resolver's do-not-touch arm permanently. The freeze that arm feeds
// (u0u) then refuses every later payment, with no in-app remedy.
func TestASendThatNeverReachedTheNodeClearsItsMarker(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq}
	node := &fakePayer{recorder: seq, err: fmt.Errorf("%w: no connection", lnd.ErrNotSent)}

	_, err := payInvoice(t.Context(), payment{bolt11: "lnbcrt1", amountMsat: 1_000,
		maxFeeMsat: 100, paymentHash: "abcd"}, purse, node, quietLog())

	if err == nil {
		t.Fatal("a send that never happened was reported as success")
	}
	want := []string{"reserve", "dispatch", "send", "undispatch"}
	if !slices.Equal(seq.seen(), want) {
		t.Errorf("calls = %v, want %v — the marker has to come back off, or this reservation "+
			"is frozen for ever", seq.seen(), want)
	}
}

// And a send whose fate is UNKNOWN keeps its marker: it may be in flight, and
// §6 forbids concluding anything from that.
func TestASendOfUnknownFateKeepsItsMarker(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq}
	node := &fakePayer{recorder: seq, err: errors.New("the stream broke mid-payment")}

	if _, err := payInvoice(t.Context(), payment{bolt11: "lnbcrt1", amountMsat: 1_000,
		maxFeeMsat: 100, paymentHash: "abcd"}, purse, node, quietLog()); err == nil {
		t.Fatal("a payment of unknown fate was reported as success")
	}

	if slices.Contains(seq.seen(), "undispatch") {
		t.Error("a payment that may be in flight had its marker cleared; the resolver would " +
			"then reverse a reservation whose payment might have settled")
	}
}

// hdu criterion 6 and 669: a PERSISTENT resolution failure is offered to the
// operator instead of being retried for ever.
//
// `hdu` fixed the one failure that could never succeed — a fee above the reserve
// now settles at the reserve with an adjustment — and the general defect behind
// it was that a persistent failure had no terminal disposition at all: the row
// stayed pending, every pass re-tracked it and re-failed, and the ceiling stayed
// frozen throughout. The counter is the general answer, and the name is where it
// leads.
func TestAPersistentResolutionFailureIsNamedForTheOperator(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq, settleErr: errors.New("the ledger would not book it")}
	node := &fakePayer{recorder: seq, result: lnd.PaymentResult{
		Status: lnrpc.Payment_SUCCEEDED, FeeMsat: 21,
	}}
	pending := &fakePending{rows: []store.PendingPayment{{ID: 7, PaymentHash: "abcd"}}}

	// Pass after pass, the way the recon loop runs them.
	for i := range store.MaxResolveAttempts {
		if err := resolvePendingPayments(t.Context(), pending, purse, node, nil, aCutoff, quietLog()); err == nil {
			t.Fatalf("pass %d reported the row as resolved", i)
		}
		if i < store.MaxResolveAttempts-1 && len(purse.named) != 0 {
			t.Fatalf("the row was named after %d of %d attempts; a transient failure must get "+
				"its retries", i+1, store.MaxResolveAttempts)
		}
	}

	if len(purse.named) != 1 {
		t.Fatalf("%d rows named after %d failed passes, want 1 — without a name the operator "+
			"cannot close it and the resolver will try again for ever",
			len(purse.named), store.MaxResolveAttempts)
	}
	if purse.named[0].reason == "" {
		t.Error("the row was named with no reason; the operator reads it to decide what to do")
	}
}

// A TRANSIENT failure does not accumulate toward a name.
//
// The counter is reset by a success, so a node that is down for four passes and
// answers on the fifth leaves the row exactly as it found it — a row the
// operator is invited to close is a row the app has given up on, and giving up
// on a working install would put a money decision in front of them for nothing.
func TestATransientFailureDoesNotWalkTowardsAName(t *testing.T) {
	seq := &recorder{}
	purse := &fakeSpender{recorder: seq}
	node := &fakePayer{recorder: seq, err: errors.New("connection refused")}
	pending := &fakePending{rows: []store.PendingPayment{{ID: 7, PaymentHash: "abcd"}}}

	for range store.MaxResolveAttempts - 1 {
		_ = resolvePendingPayments(t.Context(), pending, purse, node, nil, aCutoff, quietLog())
	}
	// The node comes back.
	node.err = nil
	node.result = lnd.PaymentResult{Status: lnrpc.Payment_SUCCEEDED, FeeMsat: 21}
	if err := resolvePendingPayments(t.Context(), pending, purse, node, nil, aCutoff, quietLog()); err != nil {
		t.Fatalf("the pass that should have succeeded: %v", err)
	}

	if len(purse.named) != 0 {
		t.Errorf("a row was named after a transient outage that cleared: %+v", purse.named)
	}
	if purse.attempts != 0 {
		t.Errorf("the failure counter is %d after a success, want 0 — an outage a month apart "+
			"must not add up to a name", purse.attempts)
	}
}

// The two arms the resolver can never resolve are named on the FIRST pass.
//
// No counter for these: a payment with no hash has nothing to ask about, and one
// the node has forgotten will not be remembered on the sixth try. Waiting five
// passes would hold the ceiling for five recon cycles over a fact already known.
func TestATerminallyUnresolvableRowIsNamedAtOnce(t *testing.T) {
	for _, tc := range []struct {
		name string
		row  store.PendingPayment
		err  error
	}{
		{"no payment hash", store.PendingPayment{ID: 7}, nil},
		{"dispatched and the node has forgotten it",
			store.PendingPayment{ID: 7, PaymentHash: "abcd", Dispatched: true},
			lnd.ErrPaymentNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seq := &recorder{}
			purse := &fakeSpender{recorder: seq}
			node := &fakePayer{recorder: seq, err: tc.err}
			pending := &fakePending{rows: []store.PendingPayment{tc.row}}

			_ = resolvePendingPayments(t.Context(), pending, purse, node, nil, aCutoff, quietLog())

			if len(purse.named) != 1 {
				t.Fatalf("%d rows named on the first pass, want 1 — this one can never be "+
					"resolved automatically, and the ceiling is frozen until somebody closes it",
					len(purse.named))
			}
		})
	}
}
