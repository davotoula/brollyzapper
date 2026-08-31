package main

import (
	"testing"

	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
)

// THE WIRE BETWEEN THE TWO PACKAGES THAT WERE BOTH TESTED (y09).
//
// nwcSpend.Decode copies lnd.Bolt11 into nwc.Bolt11 field by field, because §3
// keeps internal/nwc from importing internal/lnd. It dropped DescriptionHash,
// and nothing noticed: internal/lnd asserted that Decode carries the field,
// internal/nwc asserted the binding against a FAKE Decode that supplies it, and
// the six-line adapter between them had no test at all.
//
// The cost of that gap was the whole feature. Every zap paid through NWC was
// dropped with "the invoice commits to no description_hash" — the arm that
// exists to stop an unbound event being stored, refusing a bound one because the
// commitment never arrived. Green unit tests, green build, dead in the field.
//
// Found by regtest on the first run that could reach it, which is the argument
// for BrollyZap-1ar in one sentence.
//
// A REAL CLIENT AND A REAL DECODE, not a fake: the defect was a field-copy
// between two types, so a fake that returns the destination type would have
// reproduced nothing.
func TestTheDecodeSeamCarriesEverythingTheLadderAndTheBindingNeed(t *testing.T) {
	node := lndtest.Start(t)
	spend := nwcSpend{node: seamClient(t, node, t.TempDir())}

	const (
		bolt11 = "lnbcrt210n1seamprobe"
		hash   = "5c3f8b1d0a9e7c6b4d2f8a1e0c9b7d6a5f4e3c2b1a0908070605040302010fed"
	)
	node.SetDecoded(bolt11, &lnrpc.PayReq{
		PaymentHash:     "abc123",
		NumMsat:         21_000,
		Description:     "a coffee",
		DescriptionHash: hash,
		Timestamp:       1_700_000_000,
		Expiry:          3600,
	})

	got, err := spend.Decode(t.Context(), bolt11)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	// EVERY FIELD, not only the one that went missing. The next field added to
	// this struct will be added to lnd.Bolt11 and to nwc.Bolt11 by a compiler
	// that says nothing about the copy in between, which is exactly how this one
	// arrived.
	if got.DescriptionHash != hash {
		t.Errorf("DescriptionHash = %q, want %q — without it outgoingMetadata sees an invoice "+
			"that commits to nothing and drops every zap request a client sends",
			got.DescriptionHash, hash)
	}
	if got.PaymentHash != "abc123" {
		t.Errorf("PaymentHash = %q", got.PaymentHash)
	}
	if got.AmountMsat != 21_000 {
		t.Errorf("AmountMsat = %d", got.AmountMsat)
	}
	if got.Description != "a coffee" {
		t.Errorf("Description = %q", got.Description)
	}
	if got.ExpiresAt.IsZero() {
		t.Error("ExpiresAt is zero; the ladder refuses an expired invoice before it reserves")
	}
}
