package wallet

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"

	"github.com/davotoula/brollyzapper/internal/secret"
)

var testTime = time.Unix(1_700_000_000, 0).UTC()

func newWallet(t *testing.T) (*localSpender, *store.Store) {
	t.Helper()
	w, db, _ := newWalletAt(t)
	return w, db
}

// newWalletAt also hands back the data directory, for the one test that has to
// read the ledger rather than the balance: "no row was written" cannot be seen
// through a SUM, because a rejected call and a zero-amount row look the same
// from there.
func newWalletAt(t *testing.T) (*localSpender, *store.Store, string) {
	t.Helper()
	db, dir := openStore(t)
	w := New(db, Options{Now: func() time.Time { return testTime }})
	// LocalSpender must satisfy the seam §3 defines.
	var _ Spender = w
	return w, db, dir
}

// openStore opens a store and returns it with its directory. Separate from
// newWalletAt because the unresolved-payments tests build TWO wallets over one
// store, and a helper that pairs the two cannot express that.
func openStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	db, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, dir
}

func allocate(t *testing.T, w *localSpender, amountMsat int64) {
	t.Helper()
	if err := w.Allocate(t.Context(), amountMsat, "test allocation"); err != nil {
		t.Fatalf("Allocate(%d): %v", amountMsat, err)
	}
}

// Spec §5: allocation is a spending authorisation, not a Lightning operation.
func TestAllocationRaisesTheCeilingAndDeallocationLowersIt(t *testing.T) {
	w, _ := newWallet(t)
	ctx := t.Context()

	if balance, err := w.Balance(ctx); err != nil || balance != 0 {
		t.Fatalf("a fresh wallet has balance %d, %v; want 0, nil", balance, err)
	}
	allocate(t, w, 100_000)
	if balance, _ := w.Balance(ctx); balance != 100_000 {
		t.Errorf("balance after allocating = %d, want 100000", balance)
	}
	if err := w.Deallocate(ctx, 40_000, "changed my mind"); err != nil {
		t.Fatalf("Deallocate: %v", err)
	}
	if balance, _ := w.Balance(ctx); balance != 60_000 {
		t.Errorf("balance after deallocating = %d, want 60000", balance)
	}
}

func TestDeallocatingMoreThanTheBalanceIsRefused(t *testing.T) {
	w, _ := newWallet(t)
	allocate(t, w, 10_000)
	err := w.Deallocate(t.Context(), 10_001, "too much")
	if !errors.Is(err, store.ErrInsufficientBalance) {
		t.Errorf("Deallocate beyond the balance = %v, want ErrInsufficientBalance", err)
	}
	if balance, _ := w.Balance(t.Context()); balance != 10_000 {
		t.Errorf("balance = %d after a refused deallocation, want 10000 unchanged", balance)
	}
}

// Spec §5: max_fee is ONE number — what Reserve debits, what the §8 budget
// consumes, and what SendPaymentV2 gets as fee_limit_msat.
func TestMaxFeeIsTheFloorOrThePPMWhicheverIsLarger(t *testing.T) {
	w, _ := newWallet(t)
	ctx := t.Context()

	cases := []struct{ amountMsat, want int64 }{
		{0, 10_000},           // the floor
		{100_000, 10_000},     // 1% of 100k msat is 1000, below the floor
		{1_000_000, 10_000},   // 1% is exactly the floor
		{10_000_000, 100_000}, // 1% is above the floor
		{50_000_000, 500_000},
	}
	for _, c := range cases {
		got, err := w.MaxFee(ctx, c.amountMsat)
		if err != nil {
			t.Fatalf("MaxFee(%d): %v", c.amountMsat, err)
		}
		if got != c.want {
			t.Errorf("MaxFee(%d) = %d, want %d", c.amountMsat, got, c.want)
		}
	}
}

func TestMaxFeeFollowsTheSettings(t *testing.T) {
	w, db := newWallet(t)
	ctx := t.Context()
	if err := db.SetSetting(ctx, "max_fee_floor_msat", "500"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, "max_fee_ppm", "20000"); err != nil {
		t.Fatal(err)
	}
	got, err := w.MaxFee(ctx, 1_000_000)
	if err != nil {
		t.Fatalf("MaxFee: %v", err)
	}
	if got != 20_000 {
		t.Errorf("MaxFee = %d, want 20000 (2%% of 1000000)", got)
	}
}

// Spec §5: a settled payment nets to exactly -(amount + actual_fee), because
// only the unused part of the reserve comes back and there is no separate fee
// entry to double-count.
func TestASettledPaymentCostsAmountPlusTheActualFee(t *testing.T) {
	w, _ := newWallet(t)
	ctx := t.Context()
	allocate(t, w, 1_000_000)

	maxFee, err := w.MaxFee(ctx, 100_000)
	if err != nil {
		t.Fatalf("MaxFee: %v", err)
	}
	id, err := w.Reserve(ctx, Reservation{AmountMsat: 100_000, MaxFeeMsat: maxFee, PaymentHash: aPaymentHash(), Ref: "invoice-1"})
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if balance, _ := w.Balance(ctx); balance != 1_000_000-100_000-maxFee {
		t.Errorf("balance after reserving = %d, want %d", balance, 1_000_000-100_000-maxFee)
	}
	if err := w.Settle(ctx, id, 1_234, secret.String{}); err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if balance, _ := w.Balance(ctx); balance != 1_000_000-100_000-1_234 {
		t.Errorf("balance after settling = %d, want %d", balance, 1_000_000-100_000-1_234)
	}
}

// Spec §5: a failed payment consumes no budget at all.
func TestReserveThenReverseIsAnExactIdentity(t *testing.T) {
	w, _ := newWallet(t)
	ctx := t.Context()
	allocate(t, w, 250_000)
	before, _ := w.Balance(ctx)

	id, err := w.Reserve(ctx, Reservation{AmountMsat: 100_000, MaxFeeMsat: 5_000, PaymentHash: aPaymentHash(), Ref: "invoice-2"})
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := w.Reverse(ctx, id); err != nil {
		t.Fatalf("Reverse: %v", err)
	}
	after, _ := w.Balance(ctx)
	if after != before {
		t.Errorf("balance %d -> %d across reserve+reverse, want an exact identity", before, after)
	}
}

func TestAReservationIsClosedOnlyOnce(t *testing.T) {
	w, _ := newWallet(t)
	ctx := t.Context()
	allocate(t, w, 250_000)
	id, err := w.Reserve(ctx, Reservation{AmountMsat: 10_000, MaxFeeMsat: 1_000, PaymentHash: aPaymentHash(), Ref: "invoice-3"})
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := w.Settle(ctx, id, 100, secret.String{}); err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if err := w.Settle(ctx, id, 100, secret.String{}); !errors.Is(err, store.ErrReservationNotPending) {
		t.Errorf("second Settle = %v, want ErrReservationNotPending", err)
	}
	if err := w.Reverse(ctx, id); !errors.Is(err, store.ErrReservationNotPending) {
		t.Errorf("Reverse after Settle = %v, want ErrReservationNotPending", err)
	}
}

// Spec §5 invariants 1 and 2: the balance may never go negative, and two
// concurrent reservations cannot both pass the check — because the first one's
// debit is already committed when the second one looks.
func TestConcurrentReservationsCannotOverdraw(t *testing.T) {
	w, _ := newWallet(t)
	ctx := t.Context()
	// Room for exactly three reservations of 30_000 + 3_000.
	allocate(t, w, 99_000)

	const attempts = 12
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		accepted int
	)
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := w.Reserve(ctx, Reservation{AmountMsat: 30_000, MaxFeeMsat: 3_000, PaymentHash: aPaymentHash(), Ref: "race"}); err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			} else if !errors.Is(err, store.ErrInsufficientBalance) {
				t.Errorf("Reserve %d failed for the wrong reason: %v", i, err)
			}
		}()
	}
	wg.Wait()

	if accepted != 3 {
		t.Errorf("%d of %d concurrent reservations were accepted, want exactly 3", accepted, attempts)
	}
	balance, err := w.Balance(ctx)
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if balance < 0 {
		t.Errorf("balance = %d; it may never go negative (spec §5)", balance)
	}
	if balance != 0 {
		t.Errorf("balance = %d, want 0 after three reservations of 33000", balance)
	}
}

// o34.21: the settle time recorded is LND's, not the moment we got round to it.
//
// §7 says the receipt's created_at is "the invoice's settle time (not now)", and
// NIP-57 Appendix E says it SHOULD be the paid-at date. The stream handler
// receives lnrpc.Invoice.SettleDate; before this the wallet called its own clock
// instead, so on a warm stack the two agreed to the second and every test
// passed. Forced apart — settle while the server is stopped, restart, let the
// settle_index resume path deliver it — they differed by exactly the outage.
// Measured on regtest: 60 seconds. A server down six hours publishes receipts
// six hours late.
func TestTheSettleTimeRecordedIsTheNodesNotTheHandlersClock(t *testing.T) {
	w, db := newWallet(t)
	ctx := t.Context()
	mintInvoice(t, db, "hash-late", 21_000)

	// The node settled it an hour before this process even looked.
	settled := testTime.Add(-time.Hour)
	credited, err := w.CreditInvoice(ctx, "hash-late", "preimage", 21_000, settled)
	if err != nil || !credited {
		t.Fatalf("CreditInvoice = %v, %v; want true, nil", credited, err)
	}

	txns, err := db.RecentTxns(ctx, 10)
	if err != nil {
		t.Fatalf("reading the txns: %v", err)
	}
	if len(txns) != 1 {
		t.Fatalf("%d txns after one settlement, want 1", len(txns))
	}
	if got := txns[0].SettledAt.UTC(); !got.Equal(settled.UTC()) {
		t.Errorf("settled_at = %s, want the node's settle time %s. The handler's clock says "+
			"%s, and using it makes a receipt claim the zap happened when we noticed rather "+
			"than when it was paid", got, settled.UTC(), testTime.UTC())
	}
}

// The fallback, and why it is not silent.
//
// A settled invoice always carries a settle time, so a zero means the node said
// something unexpected. Stamping 1970 into a receipt would be worse than
// stamping now: it is a date every client would render, and it would look
// deliberate.
func TestAMissingSettleTimeFallsBackToTheClockRatherThanNineteenSeventy(t *testing.T) {
	w, db := newWallet(t)
	ctx := t.Context()
	mintInvoice(t, db, "hash-zero", 21_000)

	if _, err := w.CreditInvoice(ctx, "hash-zero", "preimage", 21_000, time.Time{}); err != nil {
		t.Fatalf("CreditInvoice: %v", err)
	}
	txns, err := db.RecentTxns(ctx, 10)
	if err != nil {
		t.Fatalf("reading the txns: %v", err)
	}
	if got := txns[0].SettledAt.UTC(); !got.Equal(testTime.UTC()) {
		t.Errorf("settled_at = %s for an invoice with no settle time, want the clock %s",
			got, testTime.UTC())
	}
}

// Spec §5: credit_received (default true) can be turned off if the operator
// wants incoming funds to stay unspendable until explicitly allocated.
func TestCreditReceivedControlsWhetherAZapRaisesTheCeiling(t *testing.T) {
	w, db := newWallet(t)
	ctx := t.Context()
	mintInvoice(t, db, "hash-on", 21_000)
	mintInvoice(t, db, "hash-off", 21_000)

	if on, err := w.CreditReceived(ctx); err != nil || !on {
		t.Fatalf("credit_received defaults to %v, %v; want true, nil", on, err)
	}
	credited, err := w.CreditInvoice(ctx, "hash-on", "preimage", 21_000, testTime)
	if err != nil || !credited {
		t.Fatalf("CreditInvoice = %v, %v; want true, nil", credited, err)
	}
	if balance, _ := w.Balance(ctx); balance != 21_000 {
		t.Errorf("balance = %d after a zap, want 21000", balance)
	}

	if err := w.SetCreditReceived(ctx, false); err != nil {
		t.Fatalf("SetCreditReceived: %v", err)
	}
	if _, err := w.CreditInvoice(ctx, "hash-off", "preimage", 21_000, testTime); err != nil {
		t.Fatalf("CreditInvoice with crediting off: %v", err)
	}
	if balance, _ := w.Balance(ctx); balance != 21_000 {
		t.Errorf("balance = %d; with credit_received off the zap must not raise the ceiling", balance)
	}
	// The zap is still recorded in full — only the balance entry is withheld.
	if count, err := db.TxnCount(ctx); err != nil || count != 2 {
		t.Errorf("TxnCount = %d, %v; want 2 — the zap is recorded either way", count, err)
	}
}

// Spec §13 asks for property-based tests over random operation sequences. The
// seed is fixed so a failure is reproducible.
func TestRandomOperationSequencesHoldTheInvariants(t *testing.T) {
	w, db := newWallet(t)
	ctx := t.Context()
	random := rand.New(rand.NewPCG(1, 2))

	var open []ReservationID
	for step := range 400 {
		switch random.IntN(5) {
		case 0:
			if err := w.Allocate(ctx, int64(random.IntN(50_000)+1), "prop"); err != nil {
				t.Fatalf("step %d Allocate: %v", step, err)
			}
		case 1:
			amount := int64(random.IntN(20_000) + 1)
			err := w.Deallocate(ctx, amount, "prop")
			if err != nil && !errors.Is(err, store.ErrInsufficientBalance) {
				t.Fatalf("step %d Deallocate: %v", step, err)
			}
		case 2:
			amount := int64(random.IntN(20_000) + 1)
			id, err := w.Reserve(ctx, Reservation{AmountMsat: amount, MaxFeeMsat: 1_000, PaymentHash: aPaymentHash(), Ref: "prop"})
			switch {
			case err == nil:
				open = append(open, id)
			case errors.Is(err, store.ErrInsufficientBalance):
			default:
				t.Fatalf("step %d Reserve: %v", step, err)
			}
		case 3:
			if len(open) == 0 {
				continue
			}
			id := open[len(open)-1]
			open = open[:len(open)-1]
			if err := w.Settle(ctx, id, int64(random.IntN(1_001)), secret.String{}); err != nil {
				t.Fatalf("step %d Settle: %v", step, err)
			}
		case 4:
			if len(open) == 0 {
				continue
			}
			id := open[0]
			open = open[1:]
			if err := w.Reverse(ctx, id); err != nil {
				t.Fatalf("step %d Reverse: %v", step, err)
			}
		}

		balance, err := w.Balance(ctx)
		if err != nil {
			t.Fatalf("step %d Balance: %v", step, err)
		}
		if balance < 0 {
			t.Fatalf("step %d left the balance at %d; it may never go negative", step, balance)
		}
		sum, err := db.BalanceMsat(ctx)
		if err != nil {
			t.Fatalf("step %d BalanceMsat: %v", step, err)
		}
		if balance != sum {
			t.Fatalf("step %d: Balance() = %d but SUM(balance_entries) = %d", step, balance, sum)
		}
	}
}

func mintInvoice(t *testing.T, db *store.Store, paymentHash string, amountMsat int64) {
	t.Helper()
	err := db.CreateInvoice(t.Context(), store.Invoice{
		PaymentHash: paymentHash, AmountMsat: amountMsat, DescriptionHash: "dh",
		Bolt11: "lnbcrt" + paymentHash, State: store.InvoiceOpen,
		CreatedAt: testTime, ExpiresAt: testTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}
}

// aPaymentHash is a distinct hash per call.
//
// txns.payment_hash is UNIQUE and these tests reserve more than once, so a
// shared literal would collide on the second reservation — and Reserve now
// REQUIRES one, because a pending payment_out without a hash is the
// unresolvable row §6 forbids reversing.
var paymentHashSeq atomic.Int64

func aPaymentHash() string { return fmt.Sprintf("%064x", paymentHashSeq.Add(1)) }
