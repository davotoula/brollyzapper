package store_test

import (
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"
)

// doy.2: an outgoing payment's metadata round-trips, and it does NOT make the
// row a zap.
//
// THIS IS THE SEAM THE WHOLE EPIC IS SHAPED AROUND. `IsZap` is derived from
// `zap_request` alone (invoices.go) and the admin page's receipt switch reads it:
// an outgoing row that answered true would fall through to "receipt abandoned" —
// the branch whose own comment calls it the case that reads as theft — on every
// zap the operator sent, on their own history page. The obvious implementation of
// this feature, reusing `zap_request` because it is right there and needs no
// migration, produces exactly that.
//
// So the write and the read are asserted TOGETHER, through the store, rather than
// unit-testing the column and the flag on their own: the defect lives in the wire
// between them and neither side can see it.
func TestAnOutgoingZapRequestRoundTripsWithoutMakingTheRowAZap(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_756_000_000, 0).UTC()
	const event = `{"kind":9734,"pubkey":"79be6","content":"thanks","tags":[["p","04c91"]]}`
	const metadata = `{"nostr":` + event + `,"recipient_data":{"identifier":"a@b.com"}}`
	const committed = "5c3f8b1d0a9e7c6b4d2f8a1e0c9b7d6a5f4e3c2b1a0908070605040302010fed"

	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		1_000_000, "float", at); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReserveSpend(t.Context(), store.SpendReservation{
		AmountMsat: 21_000, MaxFeeMsat: 210, PaymentHash: "hash-zap", Ref: "a zap",
		Metadata: metadata, DescriptionHash: committed,
	}, at); err != nil {
		t.Fatal(err)
	}

	txns, err := s.RecentTxns(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	var row store.Txn
	for _, candidate := range txns {
		if candidate.PaymentHash == "hash-zap" {
			row = candidate
		}
	}
	if row.PaymentHash == "" {
		t.Fatalf("the reservation is not in the history at all: %+v", txns)
	}

	if row.OutMetadata != metadata {
		t.Errorf("out_metadata read back as %q, want the client's bytes unchanged — the "+
			"event id is a hash over its own serialisation, so anything but verbatim is "+
			"unverifiable, and recipient_data is what a client labels the row with",
			row.OutMetadata)
	}
	if row.OutDescriptionHash != committed {
		t.Errorf("out_description_hash read back as %q, want the invoice's own commitment — "+
			"a hash recomputed from the blob it vouches for proves nothing",
			row.OutDescriptionHash)
	}
	if row.ZapRequest != "" {
		t.Errorf("zap_request = %q on an OUTGOING row; that column is documented as raw JSON "+
			"this node received and verified, and a paired client's claim is not that",
			row.ZapRequest)
	}
	if row.IsZap {
		t.Error("IsZap is true for an outgoing payment carrying a zap request. The admin " +
			"page's receipt switch reads this flag and its default arm is \"receipt " +
			"abandoned\" — so the operator's own history would report every zap they SENT " +
			"as one they failed to acknowledge. This is the trap migration 0015 exists to " +
			"avoid; if this line is failing, check whether the blob is being written to " +
			"zap_request or whether IsZap has been widened to include out_metadata.")
	}
}
