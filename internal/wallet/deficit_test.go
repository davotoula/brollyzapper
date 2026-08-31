package wallet

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// §5: a shortfall freezes OUTBOUND payments. Receiving stays enabled — a wallet
// that stops accepting zaps because it is unsure how much it can spend has
// turned a recoverable accounting problem into lost income.
func TestAShortfallFreezesSpendingAndNothingElse(t *testing.T) {
	w, db := newWallet(t)
	ctx := t.Context()
	allocate(t, w, 1_000_000)
	mintInvoice(t, db, "hash-frozen", 21_000)

	// Before: spending works.
	id, err := w.Reserve(ctx, Reservation{AmountMsat: 10_000, MaxFeeMsat: 1_000, PaymentHash: aPaymentHash(), Ref: "before"})
	if err != nil {
		t.Fatalf("Reserve before the freeze: %v", err)
	}
	if err := w.Reverse(ctx, id); err != nil {
		t.Fatal(err)
	}

	deficit := Deficit{
		At: testTime, ShortfallMsat: 250_000, WalletMsat: 1_000_000, NodeMsat: 750_000,
		Cause: "another app on this node may have spent",
	}
	if err := w.RecordShortfall(ctx, deficit); err != nil {
		t.Fatalf("RecordShortfall: %v", err)
	}

	// Outbound is refused, and says why.
	_, err = w.Reserve(ctx, Reservation{AmountMsat: 10_000, MaxFeeMsat: 1_000, PaymentHash: aPaymentHash(), Ref: "during"})
	if !errors.Is(err, ErrSpendingFrozen) {
		t.Fatalf("Reserve during a shortfall = %v, want ErrSpendingFrozen", err)
	}
	if !strings.Contains(err.Error(), "250000") {
		t.Errorf("the refusal does not say how big the shortfall is: %v", err)
	}

	// Inbound is untouched: the zap still lands and still credits.
	credited, err := w.CreditInvoice(ctx, "hash-frozen", "preimage", 21_000, testTime)
	if err != nil || !credited {
		t.Fatalf("CreditInvoice during a shortfall = %v, %v; receiving must stay enabled", credited, err)
	}
	if balance, _ := w.Balance(ctx); balance != 1_000_000+21_000 {
		t.Errorf("balance = %d; the credit did not land", balance)
	}

	// The operator can still correct the ledger by hand — that is the sanctioned
	// route, and §5 says a correction is an explicit adjustment, never a
	// silent rewrite.
	if err := w.Adjust(ctx, -250_000, "correcting after a force close"); err != nil {
		t.Errorf("Adjust during a shortfall: %v", err)
	}
}

// §5: once the shortfall clears the freeze lifts, with no operator action and
// no restart. A freeze that needs a human to release it is an outage with extra
// steps.
func TestTheFreezeLiftsWhenTheShortfallClears(t *testing.T) {
	w, _ := newWallet(t)
	ctx := t.Context()
	allocate(t, w, 1_000_000)

	if err := w.RecordShortfall(ctx, Deficit{At: testTime, ShortfallMsat: 1, Cause: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Reserve(ctx, Reservation{AmountMsat: 1_000, MaxFeeMsat: 100, PaymentHash: aPaymentHash(), Ref: "frozen"}); !errors.Is(err, ErrSpendingFrozen) {
		t.Fatalf("Reserve = %v, want ErrSpendingFrozen", err)
	}

	if err := w.ClearShortfall(ctx); err != nil {
		t.Fatalf("ClearShortfall: %v", err)
	}
	if _, err := w.Reserve(ctx, Reservation{AmountMsat: 1_000, MaxFeeMsat: 100, PaymentHash: aPaymentHash(), Ref: "thawed"}); err != nil {
		t.Errorf("Reserve after the shortfall cleared = %v, want it to succeed", err)
	}
	if _, frozen, err := w.Shortfall(ctx); err != nil || frozen {
		t.Errorf("Shortfall reports frozen=%v after clearing (%v)", frozen, err)
	}
}

func TestDeficitRoundTripsThroughSettings(t *testing.T) {
	w, _ := newWallet(t)
	ctx := t.Context()
	if _, frozen, err := w.Shortfall(ctx); err != nil || frozen {
		t.Fatalf("a fresh wallet reports frozen=%v (%v)", frozen, err)
	}
	want := Deficit{
		At: time.Unix(1_700_000_123, 0).UTC(), ShortfallMsat: 42_000,
		WalletMsat: 100_000, NodeMsat: 58_000, Cause: "over-allocation",
	}
	if err := w.RecordShortfall(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, frozen, err := w.Shortfall(ctx)
	if err != nil || !frozen {
		t.Fatalf("Shortfall = frozen %v, %v", frozen, err)
	}
	if got.ShortfallMsat != want.ShortfallMsat || got.Cause != want.Cause || !got.At.Equal(want.At) {
		t.Errorf("Shortfall = %+v, want %+v", got, want)
	}
}

// A corrupted deficit row must not silently unfreeze: failing open on a
// security control is the wrong direction.
func TestAnUnreadableDeficitStateStaysFrozen(t *testing.T) {
	w, db := newWallet(t)
	ctx := t.Context()
	if err := db.SetSetting(ctx, SettingDeficitState, "{not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Reserve(ctx, Reservation{AmountMsat: 1_000, MaxFeeMsat: 100, PaymentHash: aPaymentHash(), Ref: "x"}); err == nil {
		t.Error("Reserve succeeded with an unreadable deficit state; it must fail closed")
	}
}
