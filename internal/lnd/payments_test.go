package lnd_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
)

// §6: `fee_limit_msat` is the reserved fee and the timeout is 60 seconds, and
// both are the caller's — nothing here recomputes either.
//
// The request the node RECEIVES is the assertion. A fee limit the client
// quietly adjusted would be invisible from the result, and the whole point of
// wallet.MaxFee being "THE number" is that the same figure is debited and sent.
func TestSendPaymentAsksForExactlyTheReservedFeeAndTheSpecTimeout(t *testing.T) {
	node := lndtest.Start(t)
	client := spendClient(t, node)

	const bolt11 = "lnbcrt1230n1pexample"
	const feeLimit = int64(4321)
	node.SetPaymentUpdates(bolt11, lndtest.Succeeded(99))

	if _, err := client.SendPayment(t.Context(), bolt11, feeLimit); err != nil {
		t.Fatalf("SendPayment: %v", err)
	}

	sent := node.SendPaymentRequests()
	if len(sent) != 1 {
		t.Fatalf("the node saw %d payment requests, want 1", len(sent))
	}
	if sent[0].PaymentRequest != bolt11 {
		t.Errorf("payment_request = %q, want the bolt11 it was given", sent[0].PaymentRequest)
	}
	if sent[0].FeeLimitMsat != feeLimit {
		t.Errorf("fee_limit_msat = %d, want the reserved %d — the wallet's MaxFee is the only "+
			"place that number is computed (§5, §6)", sent[0].FeeLimitMsat, feeLimit)
	}
	if want := int32(lnd.PaymentTimeout / time.Second); sent[0].TimeoutSeconds != want {
		t.Errorf("timeout_seconds = %d, want %d (§6)", sent[0].TimeoutSeconds, want)
	}
}

// The stream is consumed to a TERMINAL state, and the intermediate updates LND
// sends on the way are not answers.
//
// Returning on the first message would report IN_FLIGHT as the outcome, and the
// caller's next move on IN_FLIGHT is nothing at all — the reservation would sit
// pending until the next restart resolved it, for a payment that had in fact
// already succeeded.
func TestSendPaymentConsumesTheStreamToATerminalState(t *testing.T) {
	node := lndtest.Start(t)
	client := spendClient(t, node)

	const bolt11 = "lnbcrt1230n1pinflight"
	node.SetPaymentUpdates(bolt11, lndtest.InFlight(), lndtest.InFlight(), lndtest.Succeeded(77))

	result, err := client.SendPayment(t.Context(), bolt11, 1000)
	if err != nil {
		t.Fatalf("SendPayment: %v", err)
	}
	if !result.Succeeded() {
		t.Fatalf("result = %+v, want SUCCEEDED — the two IN_FLIGHT updates before it are not "+
			"outcomes", result)
	}
	if result.FeeMsat != 77 {
		t.Errorf("fee = %d, want the route's actual 77", result.FeeMsat)
	}
}

// A failed payment is a RESULT, not an error: it consumes no budget (§5) and
// the caller reverses the reservation. Reporting it as an error would send the
// caller down the same path as "the node is unreachable", where the correct
// move is the opposite one.
func TestAFailedPaymentIsAResultAndCarriesItsReason(t *testing.T) {
	node := lndtest.Start(t)
	client := spendClient(t, node)

	const bolt11 = "lnbcrt1230n1pnoroute"
	node.SetPaymentUpdates(bolt11, lndtest.InFlight(),
		lndtest.FailedBecause(lnrpc.PaymentFailureReason_FAILURE_REASON_NO_ROUTE))

	result, err := client.SendPayment(t.Context(), bolt11, 1000)
	if err != nil {
		t.Fatalf("a routing failure was reported as an error: %v", err)
	}
	if !result.Failed() {
		t.Fatalf("result = %+v, want FAILED", result)
	}
	if result.FailureReason != lnrpc.PaymentFailureReason_FAILURE_REASON_NO_ROUTE {
		t.Errorf("failure reason = %v, want NO_ROUTE — the caller shows it to the operator",
			result.FailureReason)
	}
}

// §6/o34.10: an ordinary payment failure must not touch the credential
// machinery. LND reports most of these as codes.Unknown, which is exactly why
// the whitelist inverted once before.
func TestAPaymentFailureNeverAsksTheGuardToReBake(t *testing.T) {
	node := lndtest.Start(t)
	broker := &lndtest.Broker{}
	client := lnd.New(node.Address(), spendCredentials(t, node),
		lnd.Options{Broker: broker, MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })

	// Every shape of failure the payment path can meet, including the two the
	// stream WOULD conclude a rejection from.
	node.SetRejectWith(errors.New("boom"))
	_, sendErr := client.SendPayment(t.Context(), "lnbcrt1", 1)
	_, trackErr := client.TrackPayment(t.Context(), []byte{1, 2, 3})
	if sendErr == nil || trackErr == nil {
		t.Fatal("the node was refusing everything and both calls succeeded")
	}

	if got := broker.Bakes(); got != 0 {
		t.Errorf("the payment path asked the guard to re-bake %d times; the invoice stream is "+
			"the sole call site, because a per-request RPC lets its caller drive the credential "+
			"broker one BakeMacaroon at a time (spec §6, o34.10)", got)
	}
}

// The resolver's four arms, at the level this package owns: what
// TrackPaymentV2 reports back.
func TestTrackPaymentReportsTheTerminalState(t *testing.T) {
	for _, tc := range []struct {
		name    string
		updates []*lnrpc.Payment
		want    lnrpc.Payment_PaymentStatus
	}{
		{"succeeded", []*lnrpc.Payment{lndtest.Succeeded(12)}, lnrpc.Payment_SUCCEEDED},
		{"failed", []*lnrpc.Payment{lndtest.FailedBecause(
			lnrpc.PaymentFailureReason_FAILURE_REASON_ERROR)}, lnrpc.Payment_FAILED},
		{
			// The resolver must not act on an intermediate update, and this is
			// where "keep tracking until terminal" is actually implemented:
			// the call does not return until the stream says something final.
			name:    "in flight, then terminal",
			updates: []*lnrpc.Payment{lndtest.InFlight(), lndtest.InFlight(), lndtest.Succeeded(5)},
			want:    lnrpc.Payment_SUCCEEDED,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := lndtest.Start(t)
			client := spendClient(t, node)
			hash := []byte{0xab, 0xcd}
			node.SetTrackedPayment(hash, tc.updates...)

			result, err := client.TrackPayment(t.Context(), hash)
			if err != nil {
				t.Fatalf("TrackPayment: %v", err)
			}
			if result.Status != tc.want {
				t.Errorf("status = %v, want %v", result.Status, tc.want)
			}
		})
	}
}

// "The node has no record of this payment" is its own answer, and the resolver
// treats it as evidence the payment was never dispatched.
//
// It must be distinguishable from every other failure, because the action it
// licenses — reversing a reservation — is the one action §6 forbids taking on a
// payment whose fate is unknown.
func TestTrackPaymentDistinguishesNotFoundFromEveryOtherFailure(t *testing.T) {
	node := lndtest.Start(t)
	client := spendClient(t, node)

	_, err := client.TrackPayment(t.Context(), []byte{9, 9, 9})
	if !errors.Is(err, lnd.ErrPaymentNotFound) {
		t.Fatalf("err = %v, want ErrPaymentNotFound for a hash the node never saw", err)
	}

	// And a node that is simply broken is NOT not-found. Getting this wrong
	// reverses a reservation for a payment that may well be in flight.
	node.SetRejectWith(errors.New("the node is having a bad day"))
	if _, err := client.TrackPayment(t.Context(), []byte{1}); errors.Is(err, lnd.ErrPaymentNotFound) {
		t.Error("an unreachable node was reported as 'payment not found', which would license " +
			"reversing a reservation whose fate is unknown (§6)")
	}
}

// §6, §3: the payment path presents the SPEND macaroon and the receive paths
// never do.
//
// Least privilege, and structural rather than a discipline: each Client holds
// exactly one CredentialSource, so there is no code path by which one could
// present the other's credential.
func TestThePaymentClientPresentsTheSpendMacaroonAndNothingElse(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, lndtest.Macaroon(t, "receive-only"))
	node.WriteCredentialVolume(t, dir, lnd.SpendMacaroon, lndtest.Macaroon(t, "spend"))

	spend := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.SpendMacaroon), lnd.Options{})
	t.Cleanup(func() { _ = spend.Close() })
	receive := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), lnd.Options{})
	t.Cleanup(func() { _ = receive.Close() })

	node.SetPaymentUpdates("lnbcrt1", lndtest.Succeeded(1))
	if _, err := spend.SendPayment(t.Context(), "lnbcrt1", 1); err != nil {
		t.Fatalf("SendPayment: %v", err)
	}
	if _, err := receive.GetInfo(t.Context()); err != nil {
		t.Fatalf("GetInfo: %v", err)
	}

	seen := node.SeenMacaroons()
	if len(seen) != 2 {
		t.Fatalf("the node saw %d macaroons, want 2", len(seen))
	}
	spendHex, receiveHex := hexOf(t, lnd.SpendMacaroon, dir), hexOf(t, lnd.ReceiveMacaroon, dir)
	if seen[0] != spendHex {
		t.Errorf("the payment presented %q, want the spend macaroon", short(seen[0]))
	}
	if seen[1] != receiveHex {
		t.Errorf("GetInfo presented %q, want the receive macaroon", short(seen[1]))
	}
	if spendHex == receiveHex {
		t.Fatal("the two credentials are identical, so this test cannot tell them apart")
	}
}

func short(hex string) string {
	if len(hex) > 24 {
		return hex[:24] + "…"
	}
	return hex
}

func hexOf(t *testing.T, name, dir string) string {
	t.Helper()
	raw, err := lnd.VolumeCredentials(dir, name).Macaroon()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

func spendCredentials(t *testing.T, node *lndtest.Node) lnd.CredentialSource {
	t.Helper()
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.SpendMacaroon, lndtest.Macaroon(t, "spend"))
	return lnd.VolumeCredentials(dir, lnd.SpendMacaroon)
}

// spendClient is the payment path's client: the spend macaroon, and NO broker.
//
// No broker is belt and braces beside the arch rule — a client that cannot ask
// for a re-bake cannot be made to by a later edit.
func spendClient(t *testing.T, node *lndtest.Node) *lnd.Client {
	t.Helper()
	c := lnd.New(node.Address(), spendCredentials(t, node),
		lnd.Options{MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// `v7u`: HasPayment answers from the node's FIRST word and does not wait for a
// terminal state.
//
// The discriminating fixture is one script read by both methods. A payment the
// node reports as IN_FLIGHT and never resolves is:
//
//   - an ERROR to TrackPayment, which reads to a terminal update and reaches the
//     end of the stream without one — correct, because its caller asked what
//     happened.
//   - (true, nil) to HasPayment, whose caller asked only whether a record
//     exists, and the first update already answers that.
//
// Asserting the pair rather than HasPayment alone is what makes this a test of
// the DIFFERENCE. HasPayment returning true here is uninteresting on its own;
// that TrackPayment cannot answer the same script is what shows the new method
// is not just the old one renamed — and on a real node that difference is the
// caller waiting out a payment in flight on the failure path of every payment.
func TestHasPaymentAnswersWithoutWaitingForATerminalState(t *testing.T) {
	node := lndtest.Start(t)
	client := spendClient(t, node)

	hash := []byte{0x0f, 0xf1}
	node.SetTrackedPayment(hash, lndtest.InFlight())

	has, err := client.HasPayment(t.Context(), hash)
	if err != nil {
		t.Fatalf("HasPayment: %v — the node reported a record, in flight", err)
	}
	if !has {
		t.Error("HasPayment says the node has no record of a payment it just reported as " +
			"IN_FLIGHT; clearing a dispatch marker on that answer reverses a reservation " +
			"whose payment may settle (§6)")
	}

	if _, err := client.TrackPayment(t.Context(), hash); err == nil {
		t.Error("TrackPayment answered a stream with no terminal update; the fixture no " +
			"longer distinguishes the two methods and this test proves nothing")
	}
}

// And the answer the whole mechanism turns on: a hash the node never initiated.
//
// ErrPaymentNotFound specifically, not merely an error — the caller clears a
// dispatch marker on this and on nothing else, so a widened match here is a
// reservation reversed for a payment that may be in flight.
func TestHasPaymentReportsNotFoundForAHashTheNodeNeverInitiated(t *testing.T) {
	node := lndtest.Start(t)
	client := spendClient(t, node)

	has, err := client.HasPayment(t.Context(), []byte{0xab, 0xcd})

	if has {
		t.Error("HasPayment claims a record for a hash the node has never heard of")
	}
	if !errors.Is(err, lnd.ErrPaymentNotFound) {
		t.Errorf("err = %v, want ErrPaymentNotFound — it is the ONLY answer that licenses "+
			"clearing a dispatch marker (`v7u`, `t4t`)", err)
	}
}

// A node that cannot be reached is "could not tell", never "no record".
//
// The direction that matters: false with a non-NotFound error leaves the caller
// in the conservative arm. If a transport failure came back as a provable
// absence, every payment made while the node was unreachable would have its
// marker cleared and be reversed — including the ones that settled.
func TestHasPaymentDoesNotTurnAnUnreachableNodeIntoAnAbsentRecord(t *testing.T) {
	// The node's real credentials, pointed at a port nothing listens on — the
	// package's existing way of spelling "unreachable" (certname_test.go). The
	// dial fails rather than the RPC, which is the honest shape: a node that is
	// down is not a node answering "no such payment".
	node := lndtest.Start(t)
	client := lnd.New("127.0.0.1:1", spendCredentials(t, node),
		lnd.Options{MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })

	has, err := client.HasPayment(t.Context(), []byte{0xab, 0xcd})

	if has {
		t.Error("HasPayment claims a record from a node that is not answering")
	}
	if err == nil {
		t.Fatal("HasPayment reported success against a stopped node")
	}
	if errors.Is(err, lnd.ErrPaymentNotFound) {
		t.Errorf("an unreachable node was reported as a provable absence: %v\n\nThat answer "+
			"clears the dispatch marker, and the resolver then reverses a reservation whose "+
			"payment may have settled (§6)", err)
	}
}

// IsCallerGaveUp, in the package that owns it.
//
// Raised by the `ecc:go-reviewer` pass as informational rather than a defect:
// the function was only exercised indirectly, through cmd/brollyzapper's
// TestOurOwnDeadlineIsNotTreatedAsTheNodeHavingNoRecord. That coverage is real
// and it is thorough, but it lives in another package and it reaches this
// function through payInvoice — so a change here that broke the classification
// would fail a test whose name is about dispatch markers, in a package whose
// subject is the payment path. Local, because the rule is local.
//
// BOTH DIRECTIONS, and the false half is the one that matters: this predicate
// SUPPRESSES the dispatch-time record check, so anything it wrongly calls "we
// gave up" is a payment whose marker is never cleared — back to `v7u`'s stranded
// row. Widening it is the failure, not narrowing it.
func TestIsCallerGaveUpRecognisesOurSideAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nothing went wrong", nil, false},
		{"the caller's context was cancelled", context.Canceled, true},
		{"the caller's deadline expired", context.DeadlineExceeded, true},
		{"a cancel wrapped by the payment path", fmt.Errorf("sending: %w", context.Canceled), true},
		{"grpc reported the call cancelled", status.Error(codes.Canceled, "context canceled"), true},
		{"grpc reported the deadline exceeded", status.Error(codes.DeadlineExceeded, "too slow"), true},
		// The node ANSWERING. Each of these must stay false, or the dispatch-time
		// check is skipped for exactly the refusals `v7u` exists to classify.
		{"the node refused a self-payment", status.Error(codes.Unknown, "self-payments not allowed"), false},
		{"the node has no record", status.Error(codes.NotFound, "payment isn't initiated"), false},
		{"the node is unavailable", status.Error(codes.Unavailable, "transport is closing"), false},
		{"a plain error from anywhere", errors.New("the stream broke"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := lnd.IsCallerGaveUp(tc.err); got != tc.want {
				t.Errorf("IsCallerGaveUp(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
