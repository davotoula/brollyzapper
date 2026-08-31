package lnd_test

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

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
