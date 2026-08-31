package api_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
	"github.com/davotoula/brollyzapper/internal/store"
)

// settleWith records a settled inbound payment, optionally as a zap with a
// comment, so the history has something to show.
func settleWith(t *testing.T, db *store.Store, hash string, amountMsat int64,
	zapRequest, comment string) {
	t.Helper()
	if err := db.CreateInvoice(t.Context(), store.Invoice{
		PaymentHash:     hash,
		AmountMsat:      amountMsat,
		DescriptionHash: "dh-" + hash,
		Bolt11:          "lnbcrt-" + hash,
		ZapRequest:      zapRequest,
		Comment:         comment,
		CreatedAt:       authTime,
		ExpiresAt:       authTime.Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}
	if _, err := db.CreditSettledInvoice(t.Context(), hash, "preimage-"+hash,
		amountMsat, authTime, true); err != nil {
		t.Fatalf("CreditSettledInvoice: %v", err)
	}
}

// §9 item 2 lists a transaction history on the Wallet page, and d46.9 shipped
// the page without one — so o34.12's comment and o34.3's zap_receipt_id were
// both stored and unreachable.
//
// It is rendered where §9 puts it: on the Wallet page, under the balance and
// the two forms.
func TestTheWalletPageShowsTheTransactionHistory(t *testing.T) {
	h := newHarness(t, func(_ *api.ServerOptions, db *store.Store) {
		settleWith(t, db, lnurltest.Hex64('a'), 21_000,
			string(lnurltest.SignedZapRequest(t, nil)), "thanks for the write-up 🙏")
	})
	page := h.get(t, "/", h.login(t)).Body.String()

	if !strings.Contains(page, "Transactions") {
		t.Fatal("the Wallet page has no transaction history")
	}
	// The amount, with msat precision preserved — §4: never floats for money,
	// and never a display that quietly drops the last three digits either.
	if !strings.Contains(page, "21.000") {
		t.Errorf("the history does not show the amount in sats with msat precision")
	}
	// The sender's own words, which o34.12 stored and nothing could reach.
	if !strings.Contains(page, "thanks for the write-up") {
		t.Errorf("the history does not show the LUD-12 comment")
	}
	// It must come AFTER the forms, where §9 puts it.
	if strings.Index(page, "Transactions") < strings.Index(page, "Lower the ceiling") {
		t.Error("the history is rendered above the allocate/deallocate forms; §9 item 2 " +
			"lists it after them")
	}
}

// The receipt indicator is the point of showing zaps at all: it makes
// zap.receipt.abandoned's audit row visible where an operator would look,
// rather than only in a trail they would have to know to read.
func TestTheHistoryDistinguishesTheThreeReceiptStates(t *testing.T) {
	zap := string(lnurltest.SignedZapRequest(t, nil))
	published, pending, abandoned := lnurltest.Hex64('1'),
		lnurltest.Hex64('2'), lnurltest.Hex64('3')

	h := newHarness(t, func(_ *api.ServerOptions, db *store.Store) {
		settleWith(t, db, published, 1_000, zap, "")
		if err := db.RecordZapReceipt(t.Context(), published, "eventid"+published); err != nil {
			t.Fatalf("RecordZapReceipt: %v", err)
		}
		settleWith(t, db, pending, 2_000, zap, "")
		if err := db.QueueZapReceipt(t.Context(), store.PendingReceipt{
			PaymentHash:   pending,
			GiveUpAt:      authTime.Add(time.Hour),
			NextAttemptAt: authTime,
		}); err != nil {
			t.Fatalf("QueueZapReceipt: %v", err)
		}
		// Settled, a zap, no receipt id, nothing queued: the retry window
		// closed with no relay accepting. §7's "reads as theft".
		settleWith(t, db, abandoned, 3_000, zap, "")
		// And an ordinary payment, which has no receipt state at all.
		settleWith(t, db, lnurltest.Hex64('4'), 4_000, "", "")
	})
	page := h.get(t, "/", h.login(t)).Body.String()

	for _, want := range []string{"receipt published", "receipt pending", "receipt abandoned"} {
		if !strings.Contains(page, want) {
			t.Errorf("the history never says %q", want)
		}
	}
	// The rendered text, not the CSS class — the class name contains the same
	// word and would count every row twice.
	if got := strings.Count(page, ">receipt "); got != 3 {
		t.Errorf("%d rows carry a receipt state, want 3 — an ordinary payment has none", got)
	}
	// §12's correlation rule: the event id is truncated, not reproduced whole
	// on a page an operator may screenshot.
	if strings.Contains(page, "eventid"+published) {
		t.Error("the full zap receipt event id is rendered; §12 truncates identifiers")
	}
}

// No paging in v1, so the page must not imply the list is everything.
func TestTheHistorySaysHowManyItIsNotShowing(t *testing.T) {
	h := newHarness(t, func(_ *api.ServerOptions, db *store.Store) {
		for i := range store.MaxHistoryRows + 5 {
			settleWith(t, db, fmt.Sprintf("%064x", i), int64(1_000+i), "", "")
		}
	})
	page := h.get(t, "/", h.login(t)).Body.String()

	want := "Showing 100 of 105"
	if !strings.Contains(page, want) {
		t.Errorf("the history does not say %q; with no paging, a list that looks "+
			"complete is a list that lies", want)
	}
}

// A history that cannot be read must not take the balance and the forms with
// it (§11, §19: degraded over dead).
func TestAnUnreadableHistoryStillRendersTheRestOfTheWalletPage(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.History = brokenHistory{}
	})
	rec := h.get(t, "/", h.login(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("the Wallet page = %d, want 200", rec.Code)
	}
	page := rec.Body.String()
	if !strings.Contains(page, "Balance:") || !strings.Contains(page, "Raise the ceiling") {
		t.Error("a failing history removed the balance or the forms from the page")
	}
	if !strings.Contains(page, "could not be read") {
		t.Error("a failing history said nothing at all")
	}
}

func hash64(i int) string {
	return strings.Repeat("f", 62) + string(rune('a'+i/26)) + string(rune('a'+i%26))
}

// brokenHistory fails every read.
type brokenHistory struct{}

func (brokenHistory) RecentTxns(context.Context, int) ([]store.Txn, error) {
	return nil, errNoHistory
}

func (brokenHistory) TxnCount(context.Context) (int64, error) { return 0, errNoHistory }

var errNoHistory = errors.New("the ledger is unreadable")

// The three receipt words are inferred from what is recorded, so a state that
// two different situations produce is a word that lies. "No receipt id and
// nothing queued" used to be true both of a genuinely abandoned receipt AND of
// a healthy zap in the seconds before its first publish attempt — so a good zap
// rendered as "abandoned", which is the one word an operator would act on.
//
// internal/zap now records the obligation at settlement, which makes "pending"
// the state a fresh zap is in and leaves "abandoned" genuinely terminal.
func TestAFreshlySettledZapReadsAsPendingNotAbandoned(t *testing.T) {
	hash := lnurltest.Hex64('7')
	h := newHarness(t, func(_ *api.ServerOptions, db *store.Store) {
		settleWith(t, db, hash, 5_000, string(lnurltest.SignedZapRequest(t, nil)), "")
		// Exactly what zap.Publisher.OnSettled records before it hands off.
		if err := db.QueueZapReceipt(t.Context(), store.PendingReceipt{
			PaymentHash:   hash,
			GiveUpAt:      authTime.Add(24 * time.Hour),
			NextAttemptAt: authTime.Add(30 * time.Second),
		}); err != nil {
			t.Fatalf("QueueZapReceipt: %v", err)
		}
	})
	page := h.get(t, "/", h.login(t)).Body.String()

	if strings.Contains(page, "receipt abandoned") {
		t.Error("a zap that settled moments ago reads as abandoned; that is the one " +
			"word an operator would act on, and it is not true yet")
	}
	if !strings.Contains(page, "receipt pending") {
		t.Error("a settled zap awaiting its first attempt does not read as pending")
	}
}
