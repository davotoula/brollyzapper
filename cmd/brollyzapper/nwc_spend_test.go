package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/nwc"
	"github.com/davotoula/brollyzapper/internal/preflight"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/wallet"
)

// The seam between §8's ladder and the payment path, tested as a seam.
//
// Both sides are well covered on their own — internal/nwc against a fake Spend,
// and payInvoice against fake spender/payer — and the WIRE between them was
// invisible to both. That is the failure shape this repo keeps rediscovering
// (§13), and it is where ruling 4 lives: the translation from "settled but not
// booked" into "success" happens here and nowhere else.
func TestTheSpendSeamTranslatesEveryPaymentOutcome(t *testing.T) {
	settled := lnd.PaymentResult{
		Status: lnrpc.Payment_SUCCEEDED, FeeMsat: 77, Preimage: secret.New("c0ffee"),
	}
	failed := lnd.PaymentResult{
		Status: lnrpc.Payment_FAILED, FailureReason: lnrpc.PaymentFailureReason_FAILURE_REASON_NO_ROUTE,
	}

	cases := []struct {
		name          string
		result        lnd.PaymentResult
		settleErr     error
		sendErr       error
		reserveErr    error
		notDispatched bool
		want          nwc.PayResult
		wantErr       bool
		why           string
	}{{
		name:   "settled",
		result: settled,
		want: nwc.PayResult{
			Settled: true, FeeMsat: 77, Preimage: secret.New("c0ffee"),
		},
		why: "the preimage is the client's proof it paid, and travels typed",
	}, {
		name:   "failed",
		result: failed,
		want:   nwc.PayResult{Failed: true, FailureReason: "FAILURE_REASON_NO_ROUTE"},
		why:    "a definite failure is the only answer that licenses returning the budget",
	}, {
		name:      "settled but not booked",
		result:    settled,
		settleErr: errors.New("the database is gone"),
		want: nwc.PayResult{
			Settled: true, FeeMsat: 77, Preimage: secret.New("c0ffee"), Unbooked: true,
		},
		why: "ruling 4: the payment result is the truth about the money, and reporting " +
			"PAYMENT_FAILED for a payment that paid makes the client retry a paid invoice",
	}, {
		name:          "the wallet refused to reserve",
		result:        settled,
		reserveErr:    errors.New("wallet: spending is frozen by a reconciliation shortfall"),
		wantErr:       true,
		notDispatched: true,
		why: "nothing reached the node, so the ladder must give the budget back and say " +
			"so — not report a payment that may be in flight",
	}, {
		name:    "the send errored",
		result:  settled,
		sendErr: errors.New("the node stopped answering"),
		wantErr: true,
		why: "the fate is UNKNOWN — it may be in flight — and §6 forbids concluding " +
			"anything, so this must NOT arrive as a failure",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seq := &recorder{}
			purse := &fakeSpender{recorder: seq, settleErr: tc.settleErr, reserveErr: tc.reserveErr}
			node := &fakePayer{recorder: seq, result: tc.result, err: tc.sendErr}
			spend := nwcSpend{
				purse: seamPurse{fakeSpender: purse},
				node:  seamNode{fakePayer: node},
				log:   quietLog(),
			}

			got, err := spend.Pay(t.Context(), nwc.PayRequest{
				Bolt11: "lnbcrt1", AmountMsat: 1_000, MaxFeeMsat: 100, PaymentHash: "abcd",
			})

			if tc.wantErr {
				if err == nil {
					t.Fatalf("Pay returned no error; %s", tc.why)
				}
				if got.Failed {
					t.Errorf("a payment of unknown fate was reported as Failed; %s", tc.why)
				}
				if errors.Is(err, nwc.ErrNotDispatched) != tc.notDispatched {
					t.Errorf("ErrNotDispatched = %v, want %v — %s",
						!tc.notDispatched, tc.notDispatched, tc.why)
				}
				return
			}
			if err != nil {
				t.Fatalf("Pay: %v — %s", err, tc.why)
			}
			if got.Settled != tc.want.Settled || got.Failed != tc.want.Failed ||
				got.FeeMsat != tc.want.FeeMsat || got.Unbooked != tc.want.Unbooked ||
				got.FailureReason != tc.want.FailureReason {
				t.Errorf("Pay = %+v, want %+v — %s", got, tc.want, tc.why)
			}
			if got.Preimage.Reveal() != tc.want.Preimage.Reveal() {
				t.Errorf("the preimage did not travel; %s", tc.why)
			}
		})
	}
}

// seamNode is fakePayer widened to spendNode. Decoding is not what this seam
// test is about — the ladder does that before Pay is called — and it is covered
// where it lives, in internal/lnd.
type seamNode struct {
	*fakePayer
}

func (seamNode) Decode(context.Context, string) (lnd.Bolt11, error) {
	return lnd.Bolt11{}, errors.New("seamNode does not decode")
}

// seamPurse is fakeSpender widened to nwcPurse. The ladder's OTHER three
// questions are not what this seam test is about — they are answered by the
// wallet directly and are covered where they live.
type seamPurse struct {
	*fakeSpender
}

func (seamPurse) Balance(context.Context) (int64, error) { return 21_000_000, nil }

func (seamPurse) MarkDispatched(context.Context, wallet.ReservationID) error { return nil }

func (seamPurse) ClearDispatched(context.Context, wallet.ReservationID) error { return nil }

func (seamPurse) MaxFee(context.Context, int64) (int64, error) { return 100, nil }

func (seamPurse) Shortfall(context.Context) (wallet.Deficit, bool, error) {
	return wallet.Deficit{}, false, nil
}

func (seamPurse) UnresolvedPayments(context.Context) (int, error) { return 0, nil }

func (seamPurse) NamedUnresolvedPayments(context.Context) (int, error) { return 0, nil }

// The seam d24.6 is about: the ladder's step 2 and §11's Tier-2 report are the
// SAME policy, and this is where the two meet.
//
// Both sides were already covered — internal/nwc against a fake, preflight
// against its inputs — and the wire between them was invisible to both, which
// is how a report with four rows declaring Blocks: BlocksSending came to bound
// nothing at all.
func TestTheLadderRefusesExactlyWhatTierTwoBlocks(t *testing.T) {
	cases := []struct {
		name    string
		report  preflight.Report
		blocked bool
		failing []string
		why     string
	}{{
		name:   "everything passing",
		report: preflight.Report{Checks: []preflight.Check{{ID: preflight.CheckGuardReachable, State: preflight.Pass, Blocks: preflight.BlocksSending}}},
		why:    "a healthy node pays",
	}, {
		name: "a spend row failing",
		report: preflight.Report{Checks: []preflight.Check{
			{ID: preflight.CheckSpendIPMatches, State: preflight.Fail, Blocks: preflight.BlocksSending},
		}},
		blocked: true,
		failing: []string{preflight.CheckSpendIPMatches},
		why:     "the macaroon is locked to another container",
	}, {
		name: "something red that does not block sending",
		report: preflight.Report{Checks: []preflight.Check{
			{ID: preflight.CheckLightningAddress, State: preflight.Fail, Blocks: preflight.BlocksAddress},
		}},
		why: "an unreachable domain probe must not stop a payment — only BlocksSending does",
	}, {
		name: "a spend row not checked",
		report: preflight.Report{Checks: []preflight.Check{
			{ID: preflight.CheckSpendRootKey, State: preflight.NotChecked, Blocks: preflight.BlocksSending},
		}},
		why: "a question nobody could put is not a refusal (as0.11); guard.reachable is the row that blocks",
	}, {
		name: "two spend rows failing",
		report: preflight.Report{Checks: []preflight.Check{
			{ID: preflight.CheckSpendExpiry, State: preflight.Fail, Blocks: preflight.BlocksSending},
			{ID: preflight.CheckSpendRootKey, State: preflight.Fail, Blocks: preflight.BlocksSending},
		}},
		blocked: true,
		failing: []string{preflight.CheckSpendExpiry, preflight.CheckSpendRootKey},
		why:     "the log names every failing control, so the operator is not sent to one of two",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spend := nwcSpend{checks: func(context.Context) preflight.Report { return tc.report }}

			failing := spend.SendingBlocked(t.Context())

			if blocked := len(failing) > 0; blocked != tc.blocked {
				t.Fatalf("SendingBlocked = %v, want %v — %s", blocked, tc.blocked, tc.why)
			}
			if len(failing) != len(tc.failing) {
				t.Fatalf("failing = %v, want %v — %s", failing, tc.failing, tc.why)
			}
			for i := range failing {
				if failing[i] != tc.failing[i] {
					t.Errorf("failing = %v, want %v", failing, tc.failing)
					break
				}
			}
		})
	}
}

// A report that cannot be computed blocks sending.
//
// Not being able to tell whether sending is safe is not permission to send —
// and a nil closure is exactly what a future wiring mistake looks like.
func TestAMissingReportBlocksSending(t *testing.T) {
	if failing := (nwcSpend{}).SendingBlocked(t.Context()); len(failing) == 0 {
		t.Error("a ladder with no report wired to it paid; the safe direction is to refuse")
	}
}

// The freshness the ladder needs, and why it is not the freshness the UI needs.
//
// api.CachedBroker holds the guard's answer for 10 s so the Node and Security
// pages do not poll LND on every refresh. The ladder inherited that cache and
// with it a ten-second window in which a macaroon the node had ALREADY REVOKED
// still paid — reproduced on the regtest stack, which is where this was found.
//
// The fix is structural rather than sequenced: the ladder's report is built over
// the guard's socket directly, so there is no cache to be stale. This asserts
// the property that makes that true — every call reaches the status source.
func TestTheLadderReadsTheGuardEveryTime(t *testing.T) {
	asked := 0
	status := func(context.Context) (lnd.BrokerStatus, error) {
		asked++
		return lnd.BrokerStatus{}, nil
	}
	spend := nwcSpend{checks: func(ctx context.Context) preflight.Report {
		// Stands in for preflight.Run, which asks BrokerStatus itself.
		_, _ = status(ctx)
		return preflight.Report{}
	}}

	for range 3 {
		spend.SendingBlocked(t.Context())
	}

	if asked != 3 {
		t.Errorf("the guard was asked %d times for 3 payments; a cached answer is a window in "+
			"which a revoked credential still pays", asked)
	}
}

// `v7u` go-review: the adapter translates a payment the node never took on into
// §8's vocabulary, so the ladder can act on the fact fix A established.
//
// THE SEAM, and it is where the gap was. Fix A proves the fate is KNOWN inside
// payInvoice — it asks the node for a record and clears the dispatch marker on a
// provable absence — and this switch is the only thing that can carry that out
// to §8. Without this arm the error fell through to "the payment was dispatched
// and its outcome is not yet known", which keeps the connection's budget for a
// payment that never happened and tells the payer the opposite of the truth.
//
// internal/nwc cannot match lnd.ErrNotSent itself: §3 forbids it importing
// internal/lnd. This file is where both vocabularies are in scope, which is
// exactly why the translation has to be asserted here rather than at either end.
func TestTheAdapterTellsTheLadderTheNodeTookNothingOn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sendErr error
	}{{
		name: "the request never reached the node",
		// internal/lnd's own two: no connection, or no stream.
		sendErr: fmt.Errorf("%w: no connection", lnd.ErrNotSent),
	}, {
		name: "the node refused it without initiating anything",
		// `v7u`'s third way in, promoted by payInvoice after the node said it
		// has no record of the hash.
		sendErr: fmt.Errorf("%w: rpc error: code = Unknown desc = self-payments not allowed",
			lnd.ErrNotSent),
	}} {
		t.Run(tc.name, func(t *testing.T) {
			seq := &recorder{}
			purse := &fakeSpender{recorder: seq}
			node := &fakePayer{recorder: seq, err: tc.sendErr}
			spend := nwcSpend{
				purse: seamPurse{fakeSpender: purse},
				node:  seamNode{fakePayer: node},
				log:   quietLog(),
			}

			_, err := spend.Pay(t.Context(), nwc.PayRequest{
				Bolt11: "lnbcrt1", AmountMsat: 1_000, MaxFeeMsat: 100, PaymentHash: "abcd",
			})

			if err == nil {
				t.Fatal("a payment the node took nothing on was reported as a success")
			}
			if !errors.Is(err, nwc.ErrNotDispatched) {
				t.Errorf("err does not carry ErrNotDispatched: %v — the ladder keeps the "+
					"connection's budget for a payment that never happened (§8)", err)
			}
			if !errors.Is(err, nwc.ErrNothingSent) {
				t.Errorf("err does not carry ErrNothingSent: %v — the ladder answers the "+
					"generic \"spending is held\", which is false here", err)
			}
		})
	}
}
