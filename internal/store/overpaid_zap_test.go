package store_test

import (
	"testing"
	"time"
)

// 0vk.15: an OVERPAID zap keeps both numbers, and the receipt is built from the
// minted one.
//
// TWO AMOUNTS, TWO JOBS, and they were conflated. `minted` is what the sender
// asked for and what NIP-57 Appendix D rule 5 compares the zap request's
// `amount` tag against; `paid` is what LND received and belongs to the ledger.
// NIP-57 never relates the tag to the amount paid.
//
// LND accepts unbounded overpayment — `invoices/update.go` refuses only
// `amtPaid < Terms.Value` — so a 1000 msat invoice settled at 1001 credits the
// wallet, and then the receipt build failed against the paid amount and the
// sender got nothing. §7 names that direction as the dangerous one: "a zap that
// credits the wallet but never publishes a receipt is invisible to the sender
// and reads as theft."
func TestAnOverpaidZapKeepsTheMintedAmountAndThePaidAmount(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	const minted, paid = 21_000, 21_001

	invoice := openInvoice("overpaid", minted, time.Unix(1_700_003_600, 0).UTC())
	invoice.ZapRequest = `{"kind":9734,"tags":[["amount","21000"]]}`
	if err := s.CreateInvoice(ctx, invoice); err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}
	settledAt := time.Unix(1_700_000_000, 0).UTC()
	if _, err := s.CreditSettledInvoice(ctx, "overpaid", "preimage", paid, settledAt, true); err != nil {
		t.Fatalf("CreditSettledInvoice: %v", err)
	}

	zap, err := s.SettledZapFor(ctx, "overpaid")
	if err != nil {
		t.Fatalf("SettledZapFor: %v", err)
	}

	// The receipt is built against this one, and it must be what the sender
	// asked for.
	if zap.MintedMsat != minted {
		t.Errorf("MintedMsat = %d, want %d — this is what Appendix D rule 5 compares the "+
			"request's amount tag against, and an overpayment must not cost the sender a "+
			"receipt", zap.MintedMsat, minted)
	}
	// And the ledger keeps what actually arrived. Asserted in the SAME test,
	// because the bug is precisely the two being one number.
	if zap.PaidMsat != paid {
		t.Errorf("PaidMsat = %d, want %d — the wallet was credited for what LND received and "+
			"the ledger must say so", zap.PaidMsat, paid)
	}
	if zap.MintedMsat == zap.PaidMsat {
		t.Fatal("the fixture did not overpay; this test would prove nothing")
	}
}

// The ordinary case is unchanged: paid exactly, both numbers agree.
func TestAZapPaidExactlyReportsTheSameAmountTwice(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()

	invoice := openInvoice("exact", 21_000, time.Unix(1_700_003_600, 0).UTC())
	invoice.ZapRequest = `{"kind":9734}`
	if err := s.CreateInvoice(ctx, invoice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreditSettledInvoice(ctx, "exact", "preimage", 21_000,
		time.Unix(1_700_000_000, 0).UTC(), true); err != nil {
		t.Fatal(err)
	}

	zap, err := s.SettledZapFor(ctx, "exact")
	if err != nil {
		t.Fatal(err)
	}
	if zap.MintedMsat != 21_000 || zap.PaidMsat != 21_000 {
		t.Errorf("minted %d, paid %d, want 21000 for both", zap.MintedMsat, zap.PaidMsat)
	}
}
