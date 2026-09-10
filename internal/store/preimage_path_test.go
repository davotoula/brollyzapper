package store_test

import (
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

// The receive path end to end, as a secret.String the whole way (twt,
// criterion 4).
//
// WHAT THIS ADDS OVER THE ROUND-TRIP TEST. That one proves the type can go into
// sqlite and come back. This proves the PATH does it: the value goes in through
// CreditSettledInvoice, lands in txns.preimage, and comes back out of both
// readers — SettledZapFor, which internal/zap builds the NIP-57 receipt from, and
// Txns, which internal/nwc answers lookup_invoice from. Before twt the value was
// a plain string at every one of those seams and was wrapped at the very end; the
// point of the bead is that nothing between them can hold it as a string, and the
// point of this test is that the change did not lose it on the way.
func TestAPreimageSurvivesTheReceivePathAsASecret(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	const hash = "path-hash"
	preimage := secret.New("aabbccddeeff00112233445566778899")

	invoice := openInvoice(hash, 21_000, time.Unix(1_700_003_600, 0).UTC())
	invoice.ZapRequest = `{"kind":9734,"tags":[["amount","21000"]]}`
	if err := s.CreateInvoice(ctx, invoice); err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}
	settledAt := time.Unix(1_700_000_000, 0).UTC()
	if _, err := s.CreditSettledInvoice(ctx, hash, preimage, 21_000, settledAt, true); err != nil {
		t.Fatalf("CreditSettledInvoice: %v", err)
	}

	zap, err := s.SettledZapFor(ctx, hash)
	if err != nil {
		t.Fatalf("SettledZapFor: %v", err)
	}
	if got := zap.Preimage.Reveal(); got != preimage.Reveal() {
		t.Errorf("SettledZapFor returned preimage %q, want %q — internal/zap builds NIP-57's "+
			"preimage tag from this, so an empty one is a receipt the sender cannot verify",
			got, preimage.Reveal())
	}

	// The other reader, which NIP-47's lookup_invoice answers from.
	txns, err := s.Txns(ctx, store.TxnFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Txns: %v", err)
	}
	var found bool
	for _, txn := range txns {
		if txn.PaymentHash != hash {
			continue
		}
		found = true
		if got := txn.Preimage.Reveal(); got != preimage.Reveal() {
			t.Errorf("Txns returned preimage %q, want %q", got, preimage.Reveal())
		}
	}
	if !found {
		t.Fatalf("no txn row for %s; the settlement did not land", hash)
	}

	// AND AN ABSENT PREIMAGE STAYS ABSENT, which is the half a Valuer could break
	// silently: nullString used to write NULL for "", and a Valuer returning ""
	// instead would make every unsettled row match `preimage IS NOT NULL`.
	const bare = "no-preimage"
	if err := s.CreateInvoice(ctx, openInvoice(bare, 1_000, time.Unix(1_700_003_600, 0).UTC())); err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}
	if _, err := s.CreditSettledInvoice(ctx, bare, secret.String{}, 1_000, settledAt, true); err != nil {
		t.Fatalf("CreditSettledInvoice with no preimage: %v", err)
	}
	txns, err = s.Txns(ctx, store.TxnFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Txns: %v", err)
	}
	for _, txn := range txns {
		if txn.PaymentHash == bare && !txn.Preimage.IsZero() {
			t.Errorf("an unsettled-proof row came back with preimage %q; the zero value must "+
				"stay NULL in the column", txn.Preimage.Reveal())
		}
	}
}
