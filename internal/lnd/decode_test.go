package lnd_test

import (
	"errors"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
)

// §8's ladder needs the amount, the hash and the expiry BEFORE it reserves
// anything (test-spec E2/E3/E4), and it asks the node that is going to pay it.
//
// The node's decoder rather than a Go one, and that is the point: this project
// cannot import the LND module (ADR 0001, and an arch rule on go.mod), so a
// second parser would be a second opinion about what an invoice says — and the
// one that matters is held by the thing that pays.
func TestDecodeReadsWhatTheLadderNeeds(t *testing.T) {
	node := lndtest.Start(t)
	client := spendClient(t, node)
	node.SetDecoded("lnbcrt210n1good", &lnrpc.PayReq{
		PaymentHash: "abc123",
		NumMsat:     21_000,
		Description: "a coffee",
		Timestamp:   1_700_000_000,
		Expiry:      3600,
	})

	got, err := client.Decode(t.Context(), "lnbcrt210n1good")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.PaymentHash != "abc123" || got.AmountMsat != 21_000 || got.Description != "a coffee" {
		t.Errorf("Decode = %+v, want the node's answer", got)
	}
	if want := time.Unix(1_700_000_000+3600, 0).UTC(); !got.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v — the ladder refuses an expired invoice before it "+
			"reserves, so this has to be the invoice's own expiry", got.ExpiresAt, want)
	}
}

// A malformed invoice is an ERROR, not a zero value that reserves nothing and
// pays nobody (test-spec E2).
func TestDecodeRefusesAMalformedInvoice(t *testing.T) {
	node := lndtest.Start(t)
	client := spendClient(t, node)
	node.SetDecodeError("not-an-invoice", errors.New("invalid bech32 string"))

	if _, err := client.Decode(t.Context(), "not-an-invoice"); err == nil {
		t.Error("a malformed bolt11 decoded without error; the ladder would reserve against a " +
			"zero amount and send it to the node anyway")
	}
}

// A zero-amount invoice decodes to zero, and the LADDER decides what that means
// (E4). Reporting it as an error here would take that decision away from the
// only place that knows whether an `amount` parameter was supplied.
func TestDecodeReportsAZeroAmountInvoiceAsZero(t *testing.T) {
	node := lndtest.Start(t)
	client := spendClient(t, node)
	node.SetDecoded("lnbcrt1any", &lnrpc.PayReq{
		PaymentHash: "def456", NumMsat: 0, Timestamp: 1_700_000_000, Expiry: 600,
	})

	got, err := client.Decode(t.Context(), "lnbcrt1any")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.AmountMsat != 0 {
		t.Errorf("AmountMsat = %d, want 0", got.AmountMsat)
	}
}

// And the invoice's COMMITMENT comes across the seam (y09).
//
// description_hash is the one field on a decoded invoice that the payer did not
// choose and the paying app cannot forge: for a NIP-57 zap invoice it is sha256
// of the zap request the invoice was minted for, so it is what binds a paired
// client's claim about a payment to the payment itself. Carried here because
// internal/nwc has nothing else to check that claim against.
//
// Its own test because nothing else has one: internal/nwc's binding tests build
// a Bolt11 by hand and never reach this function, so deleting the assignment
// below changed no result anywhere until this existed — the untested seam, found
// by planting exactly that deletion.
func TestDecodeCarriesTheInvoicesCommitment(t *testing.T) {
	node := lndtest.Start(t)
	client := spendClient(t, node)
	const hash = "5c3f8b1d0a9e7c6b4d2f8a1e0c9b7d6a5f4e3c2b1a0908070605040302010fed"
	node.SetDecoded("lnbcrt210n1zap", &lnrpc.PayReq{
		PaymentHash:     "abc123",
		NumMsat:         21_000,
		DescriptionHash: hash,
		Timestamp:       1_700_000_000,
		Expiry:          3600,
	})

	got, err := client.Decode(t.Context(), "lnbcrt210n1zap")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.DescriptionHash != hash {
		t.Errorf("DescriptionHash = %q, want %q — without it a paired app can attach any "+
			"event it likes to any payment and the node has nothing to check it against",
			got.DescriptionHash, hash)
	}
}

// A plain invoice commits to nothing, and that has to stay distinguishable from
// a zap invoice rather than arriving as some placeholder.
func TestDecodeLeavesTheCommitmentEmptyWhenThereIsNone(t *testing.T) {
	node := lndtest.Start(t)
	client := spendClient(t, node)
	node.SetDecoded("lnbcrt210n1plain", &lnrpc.PayReq{
		PaymentHash: "abc123", NumMsat: 21_000, Description: "a coffee",
	})

	got, err := client.Decode(t.Context(), "lnbcrt210n1plain")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.DescriptionHash != "" {
		t.Errorf("DescriptionHash = %q on an invoice with none; \"commits to nothing\" is a "+
			"state internal/nwc acts on", got.DescriptionHash)
	}
}
