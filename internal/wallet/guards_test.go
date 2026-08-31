package wallet

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// balanceEntryCount reads the ledger directly, which is the only way to see the
// thing these tests are about.
//
// The balance is a SUM, so it cannot distinguish "the call was refused" from
// "the call wrote a row worth nothing" — and §5's invariant is that
// balance_entries is APPEND-ONLY, which makes a spurious row permanent. Counting
// rows is the assertion; the balance is not.
//
// Opened read-only and separately from the store under test: this is a test
// looking at the ledger, not code reaching past wallet.Spender, and the arch
// rule that forbids the latter exempts internal/wallet for exactly this reason.
func balanceEntryCount(t *testing.T, dataDir string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, store.DBFileName)+"?mode=ro")
	if err != nil {
		t.Fatalf("opening the ledger: %v", err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM balance_entries").Scan(&n); err != nil {
		t.Fatalf("counting balance_entries: %v", err)
	}
	return n
}

// zu5.2 criterion 1. Every input guard on the money layer, and the assertion is
// not merely that each returns an error.
//
// §5 makes wallet.Spender the sole door to the balance and balance_entries
// append-only. These guards are that door's lock, and the coverage analysis
// (§3.4) found not one of them had a test: a guard with no test can be
// inverted, deleted, or written backwards without a single test going red. The
// concurrency invariant IS well covered — TestConcurrentReservationsCannotOverdraw
// is a real race test — but a wallet that cannot be overdrawn concurrently can
// still be handed a negative fee.
//
// Each row asserts BOTH halves: the call is refused, and the ledger is
// untouched. The second is the one that matters, because append-only means a
// row written by mistake can never be taken back.
func TestEveryInputGuardRefusesAndWritesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		// seed runs BEFORE the reading is taken, for the guards that need the
		// wallet in a particular state to be reachable at all. Anything it does
		// to the ledger is therefore part of the baseline rather than something
		// the refused call is blamed for — the first version of this table put
		// a Reserve inside call and read its debit as a guard failure.
		seed func(t *testing.T, w *localSpender) ReservationID
		call func(ctx context.Context, w *localSpender, id ReservationID) error
	}{{
		name: "reserve of zero",
		call: func(ctx context.Context, w *localSpender, _ ReservationID) error {
			_, err := w.Reserve(ctx, Reservation{AmountMsat: 0, MaxFeeMsat: 1_000, PaymentHash: aPaymentHash(), Ref: "ref"})
			return err
		},
	}, {
		name: "reserve of a negative amount",
		call: func(ctx context.Context, w *localSpender, _ ReservationID) error {
			_, err := w.Reserve(ctx, Reservation{AmountMsat: -1, MaxFeeMsat: 1_000, PaymentHash: aPaymentHash(), Ref: "ref"})
			return err
		},
	}, {
		// The guard the race test cannot reach: the amount is fine, the FEE is
		// not, and a negative fee reserve would credit the wallet on settle.
		name: "reserve with a negative max fee",
		call: func(ctx context.Context, w *localSpender, _ ReservationID) error {
			_, err := w.Reserve(ctx, Reservation{AmountMsat: 1_000, MaxFeeMsat: -1, PaymentHash: aPaymentHash(), Ref: "ref"})
			return err
		},
	}, {
		name: "settle with a negative fee",
		seed: func(t *testing.T, w *localSpender) ReservationID {
			allocate(t, w, 1_000_000)
			id, err := w.Reserve(t.Context(), Reservation{AmountMsat: 1_000, MaxFeeMsat: 100, PaymentHash: aPaymentHash(), Ref: "ref"})
			if err != nil {
				t.Fatalf("seeding a reservation to settle: %v", err)
			}
			return id
		},
		call: func(ctx context.Context, w *localSpender, id ReservationID) error {
			return w.Settle(ctx, id, -1, secret.String{})
		},
	}, {
		name: "allocate of zero",
		call: func(ctx context.Context, w *localSpender, _ ReservationID) error {
			return w.Allocate(ctx, 0, "note")
		},
	}, {
		name: "deallocate of zero",
		call: func(ctx context.Context, w *localSpender, _ ReservationID) error {
			return w.Deallocate(ctx, 0, "note")
		},
	}, {
		// "An adjustment of zero records nothing" — and a row recording nothing
		// is still a permanent row in an append-only ledger.
		name: "adjust of zero",
		call: func(ctx context.Context, w *localSpender, _ ReservationID) error {
			return w.Adjust(ctx, 0, "note")
		},
	}, {
		// The correction that cannot say why is the one nobody can audit later.
		name: "adjust with no note",
		call: func(ctx context.Context, w *localSpender, _ ReservationID) error {
			return w.Adjust(ctx, 1_000, "")
		},
	}, {
		// Driven through CreditInvoice rather than CreditReceived, because the
		// point is that an unreadable setting stops a WRITE. Reached before any
		// invoice lookup, so no invoice row is needed.
		name: "a credit_received setting that is not a boolean",
		seed: func(t *testing.T, w *localSpender) ReservationID {
			if err := w.store.SetSetting(t.Context(), SettingCreditReceived, "yes-please"); err != nil {
				t.Fatalf("seeding the setting: %v", err)
			}
			return 0
		},
		call: func(ctx context.Context, w *localSpender, _ ReservationID) error {
			_, err := w.CreditInvoice(ctx, "hash", "preimage", 21_000, testTime)
			return err
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			w, _, dir := newWalletAt(t)
			var seeded ReservationID
			if tc.seed != nil {
				seeded = tc.seed(t, w)
			}
			// A row first, so that "the count did not move" is a reading rather
			// than an absence. Without it a broken counter returning 0 forever
			// would satisfy every row in this table.
			allocate(t, w, 500_000)
			before := balanceEntryCount(t, dir)
			if before == 0 {
				t.Fatal("the ledger is empty before the call, so an unchanged count would prove nothing")
			}

			if err := tc.call(t.Context(), w, seeded); err == nil {
				t.Errorf("the call was accepted; this guard is what stops it")
			}
			if after := balanceEntryCount(t, dir); after != before {
				t.Errorf("balance_entries went %d -> %d; a refused call must write nothing, "+
					"and the ledger is append-only so it can never be taken back", before, after)
			}
		})
	}
}

// zu5.2 criterion 2, and coverage analysis §3.5. The invariant that stops a
// settlement spending more than was reserved.
//
// It sits in internal/store among the DB-error branches that surround it, which
// is how a real business rule comes to look like plumbing and goes untested.
// Reached here through wallet.Settle, so no §5 violation is needed to exercise
// it.
//
// AMENDED BY `hdu` (26 Aug 2026): the invariant is unchanged and the DISPOSITION
// is. An over-reserve fee used to be refused, permanently — the row stayed
// pending, every start re-tracked and re-failed it, and the ceiling stayed
// frozen for ever. The money had already left the node, so refusing to book it
// made the ledger less true. It now settles at the RESERVED fee, which is the
// invariant, and the excess becomes a visible `adjustment`.
func TestSettlingAboveTheReservedFeeBooksTheReserveAndAdjustsForTheExcess(t *testing.T) {
	const (
		amountMsat = 100_000
		reserveFee = 2_000
		excess     = 1
	)

	t.Run("over the reserve", func(t *testing.T) {
		w, db, _ := newWalletAt(t)
		allocate(t, w, 1_000_000)
		id, err := w.Reserve(t.Context(), Reservation{AmountMsat: amountMsat, MaxFeeMsat: reserveFee, PaymentHash: aPaymentHash(), Ref: "over"})
		if err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		balanceBefore, err := w.Balance(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		if err := w.Settle(t.Context(), id, reserveFee+excess, secret.String{}); err != nil {
			t.Fatalf("Settle: %v\n\nRefusing leaves the row pending for ever: every start "+
				"re-tracks it, re-settles it and re-fails, and the ceiling never lifts", err)
		}

		// THE INVARIANT: the payment books its RESERVED fee, never more.
		//
		// RecentTxns, which is the OPERATOR's history query — it filters no
		// kinds, so an adjustment appears there. store.Txns is NIP-47's
		// list_transactions and returns only invoice_in and payment_out, which
		// is right for a client and wrong for this assertion.
		txns, err := db.RecentTxns(t.Context(), 20)
		if err != nil {
			t.Fatal(err)
		}
		var payment, adjustment *store.Txn
		for i := range txns {
			switch txns[i].Kind {
			case store.KindPaymentOut:
				payment = &txns[i]
			case store.KindAdjustment:
				adjustment = &txns[i]
			}
		}
		if payment == nil {
			t.Fatal("the payment row is gone")
		}
		if payment.State != store.TxnSettled {
			t.Errorf("the payment is %q, want settled — an unterminated row holds the ceiling "+
				"for ever", payment.State)
		}
		if payment.FeeMsat != reserveFee {
			t.Errorf("the payment booked a fee of %d msat, want the RESERVED %d — settling at "+
				"the actual fee breaks §5's invariant that a spend never exceeds its "+
				"reservation, silently, in the one place balance may move",
				payment.FeeMsat, reserveFee)
		}

		// AND THE EXCESS IS VISIBLE. Absorbed into the settled amount it would
		// be a difference the ledger swallowed, which is the same defect one
		// step later.
		if adjustment == nil {
			t.Fatal("the fee excess produced no adjustment; the ledger absorbed a difference " +
				"nobody can account for")
		}
		if adjustment.AmountMsat != excess {
			t.Errorf("the adjustment is for %d msat, want %d", adjustment.AmountMsat, excess)
		}
		for _, want := range []string{"fee excess", "2000", "2001"} {
			if !strings.Contains(adjustment.Note, want) {
				t.Errorf("the adjustment's note does not mention %q: %q\n\nIt is what the "+
					"operator reads on their history, and a number with no explanation is one "+
					"nobody can audit", want, adjustment.Note)
			}
		}

		// THE LEDGER TOTAL IS RIGHT: the whole reservation was debited, nothing
		// was refunded, and the excess came off as well.
		want := balanceBefore - excess
		if got, _ := w.Balance(t.Context()); got != want {
			t.Errorf("balance %d, want %d — the node really did spend the excess, so the "+
				"ceiling really is lower by it", got, want)
		}
	})

	t.Run("exactly the reserve", func(t *testing.T) {
		w, _, _ := newWalletAt(t)
		allocate(t, w, 1_000_000)
		id, err := w.Reserve(t.Context(), Reservation{AmountMsat: amountMsat, MaxFeeMsat: reserveFee, PaymentHash: aPaymentHash(), Ref: "exact"})
		if err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		if err := w.Settle(t.Context(), id, reserveFee, secret.String{}); err != nil {
			t.Errorf("settling exactly the reserved fee was refused: %v — the rule is "+
				"'more than', and a filter that refuses the boundary too is an outage", err)
		}
	})
}

// hdu criterion 5: the row TERMINATES, so a later pass does not find it again.
//
// The defect was that it recurred: the settle failed, the row stayed pending,
// and every start re-tracked it, re-settled it and re-failed — for ever, with
// the ceiling frozen the whole time. A single-pass test cannot see that, so this
// simulates the restart the way a restart actually looks to this code: a NEW
// wallet over the same store, asking the same question again.
func TestAnOverspentFeeDoesNotComeBackOnTheNextStart(t *testing.T) {
	w, db, _ := newWalletAt(t)
	allocate(t, w, 1_000_000)
	id, err := w.Reserve(t.Context(), Reservation{
		AmountMsat: 100_000, MaxFeeMsat: 2_000, PaymentHash: aPaymentHash(), Ref: "over",
	})
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := w.Settle(t.Context(), id, 2_001, secret.String{}); err != nil {
		t.Fatalf("Settle: %v", err)
	}

	// A restart: a new wallet, started later, over the same ledger. Its cutoff
	// is at or after the row's creation, so anything still pending would be
	// picked up — which is the point.
	restarted := walletAt(db, testTime.Add(time.Hour))
	pending, err := db.PendingPaymentsBefore(t.Context(), restarted.UnresolvedCutoff())
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("%d payments are still pending after a settle that adjusted for an overspent "+
			"fee (%+v)\n\nThat is the loop: every start re-tracks it, re-settles it and "+
			"re-fails, and the ceiling never lifts", len(pending), pending)
	}
	// And the freeze is gone with it, which is what the operator actually feels.
	if _, err := restarted.Reserve(t.Context(), Reservation{
		AmountMsat: 1_000, MaxFeeMsat: 10, PaymentHash: aPaymentHash(), Ref: "after",
	}); err != nil {
		t.Errorf("Reserve after the adjusted settle: %v — the freeze outlived the row it was "+
			"holding for", err)
	}
}
