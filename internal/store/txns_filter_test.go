package store_test

import (
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// d24.12 / test-spec D5: list_transactions' filters, against seeded rows.
//
// The bug this fixes was silent: the dispatch arm parsed `limit` and ignored
// from/until/offset/unpaid/type, so a client asking for unpaid outgoing got
// everything — MORE than it asked for, with nothing to tell it the filter was
// dropped. A wallet app showing "your unpaid invoices" would list settled zaps.
func TestTxnsHonoursEveryFilter(t *testing.T) {
	s, _ := open(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	seedHistory(t, s, base)

	cases := []struct {
		name   string
		filter store.TxnFilter
		want   []string // payment hashes, newest first
		why    string
	}{{
		name:   "everything settled, newest first",
		filter: store.TxnFilter{Limit: 10},
		want:   []string{"out-settled", "in-settled"},
		why:    "unpaid rows are excluded unless asked for",
	}, {
		name:   "incoming only",
		filter: store.TxnFilter{Limit: 10, Direction: store.Incoming},
		want:   []string{"in-settled"},
		why:    "type=incoming",
	}, {
		name:   "outgoing only",
		filter: store.TxnFilter{Limit: 10, Direction: store.Outgoing},
		want:   []string{"out-settled"},
		why:    "type=outgoing",
	}, {
		name:   "including unpaid",
		filter: store.TxnFilter{Limit: 10, Paid: store.IncludingUnpaid},
		want:   []string{"out-pending", "out-settled", "in-open", "in-settled"},
		why:    "unpaid=true adds everything that is not settled",
	}, {
		name:   "unpaid incoming only",
		filter: store.TxnFilter{Limit: 10, Paid: store.UnpaidOnly, Direction: store.Incoming},
		want:   []string{"in-open"},
		why:    "the combination the bug report named: unpaid + incoming",
	}, {
		name:   "unpaid outgoing only",
		filter: store.TxnFilter{Limit: 10, Paid: store.UnpaidOnly, Direction: store.Outgoing},
		want:   []string{"out-pending"},
		why:    "the other half of the pair the test spec names",
	}, {
		name:   "from excludes anything older",
		filter: store.TxnFilter{Limit: 10, From: base.Add(90 * time.Minute)},
		want:   []string{"out-settled"},
		why:    "from is inclusive on created_at",
	}, {
		name:   "until excludes anything newer",
		filter: store.TxnFilter{Limit: 10, Until: base.Add(30 * time.Minute)},
		want:   []string{"in-settled"},
		why:    "until is inclusive",
	}, {
		name:   "limit and offset paginate",
		filter: store.TxnFilter{Limit: 1, Offset: 1, Paid: store.IncludingUnpaid},
		want:   []string{"out-settled"},
		why:    "offset skips within the same ordering, or a paging client sees duplicates",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.Txns(t.Context(), tc.filter)
			if err != nil {
				t.Fatalf("Txns: %v", err)
			}
			var hashes []string
			for _, txn := range got {
				hashes = append(hashes, txn.PaymentHash)
			}
			if len(hashes) != len(tc.want) {
				t.Fatalf("Txns = %v, want %v — %s", hashes, tc.want, tc.why)
			}
			for i := range hashes {
				if hashes[i] != tc.want[i] {
					t.Errorf("Txns = %v, want %v — %s", hashes, tc.want, tc.why)
					break
				}
			}
		})
	}
}

// The operator's own ledger entries are NOT transactions a wallet app should
// see: an allocation is the operator moving their own float in, not money that
// arrived over Lightning. Reporting one as "incoming" would be a lie about a
// payment that never happened.
func TestTxnsExcludesTheOperatorsLedgerEntries(t *testing.T) {
	s, _ := open(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		500_000, "float", base); err != nil {
		t.Fatal(err)
	}
	seedHistory(t, s, base)

	got, err := s.Txns(t.Context(), store.TxnFilter{Limit: 50, Paid: store.IncludingUnpaid})
	if err != nil {
		t.Fatal(err)
	}
	for _, txn := range got {
		if txn.Kind == store.KindAllocation || txn.Kind == store.KindAdjustment {
			t.Errorf("Txns returned a %s row; the operator's ledger entries are not payments",
				txn.Kind)
		}
	}
}

// seedHistory writes four rows a filter can tell apart: settled and unpaid, in
// each direction, at four distinct times.
func seedHistory(t *testing.T, s *store.Store, base time.Time) {
	t.Helper()
	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		10_000_000, "float", base.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	// in-settled, oldest.
	mustCreateInvoice(t, s, "in-settled", 5_000, base)
	if _, err := s.CreditSettledInvoice(t.Context(), "in-settled", "preimage", 5_000,
		base.Add(time.Minute), false); err != nil {
		t.Fatal(err)
	}
	// in-open: an invoice nobody has paid, which has NO txns row at all — it|	// lives in `invoices` until it settles. This is the row d24.12 was|	// filed about.
	mustCreateInvoice(t, s, "in-open", 6_000, base.Add(time.Hour))

	// out-settled.
	id, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 7_000, MaxFeeMsat: 100, PaymentHash: "out-settled", Ref: "a payment"}, base.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SettleSpend(t.Context(), id, 10, secret.String{}, base.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// out-pending, newest.
	if _, err := s.ReserveSpend(t.Context(), store.SpendReservation{AmountMsat: 8_000, MaxFeeMsat: 100, PaymentHash: "out-pending", Ref: "in flight"}, base.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func mustCreateInvoice(t *testing.T, s *store.Store, hash string, amountMsat int64, at time.Time) {
	t.Helper()
	if err := s.CreateInvoice(t.Context(), store.Invoice{
		PaymentHash: hash, AmountMsat: amountMsat, Bolt11: "lnbcrt" + hash,
		CreatedAt: at, ExpiresAt: at.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
}

// d24.27 criterion 3: the history carries the zap request's CONTENT, not the
// fact that there was one.
//
// It goes through the QUERY on purpose. The unit test on the other side of this
// — nwc.TestAZapCarriesItsSenderAsMetadataNostr — builds a Txn by hand and cannot
// see the projection at all: with the old `zap_request IS NOT NULL` select
// planted back in, it passed. The sender's identity is read here or it is read
// nowhere.
func TestTheHistoryCarriesTheZapRequestItself(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	const zapRequest = `{"kind":9734,"pubkey":"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",` +
		`"created_at":1700000000,"content":"here is a coffee",` +
		`"tags":[["p","79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"]],"sig":"beef"}`
	at := time.Unix(1_700_000_000, 0).UTC()

	if err := s.CreateInvoice(ctx, store.Invoice{
		PaymentHash:     "zap-hash",
		AmountMsat:      21_000,
		DescriptionHash: "dhash",
		Bolt11:          "lnbc210n1thezap",
		ZapRequest:      zapRequest,
		CreatedAt:       at,
		ExpiresAt:       at.Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}
	if _, err := s.CreditSettledInvoice(ctx, "zap-hash", "preimage", 21_000, at, false); err != nil {
		t.Fatalf("CreditSettledInvoice: %v", err)
	}

	rows, err := s.Txns(ctx, store.TxnFilter{})
	if err != nil {
		t.Fatalf("Txns: %v", err)
	}
	var zap store.Txn
	for _, row := range rows {
		if row.PaymentHash == "zap-hash" {
			zap = row
		}
	}
	if zap.PaymentHash == "" {
		t.Fatalf("the settled zap is not in the history: %+v", rows)
	}
	if zap.ZapRequest != zapRequest {
		t.Errorf("the row carries %q, want %q — a client turns the request's pubkey into the "+
			"sender's name and face, and there is nothing it can do with a boolean",
			zap.ZapRequest, zapRequest)
	}
	if !zap.IsZap {
		t.Error("a row carrying a zap request does not report itself as a zap; the flag is " +
			"derived from the content now, and the two must not disagree")
	}
	if zap.Bolt11 != "lnbc210n1thezap" {
		t.Errorf("the row carries invoice %q, want the bolt11 it settled", zap.Bolt11)
	}

	// AN OPEN ZAP INVOICE — the other arm of the projection, and the one nothing
	// covered. `list_transactions` shows unpaid invoices from `openInvoiceColumns`,
	// a separate SELECT that has to stay column-for-column identical to the
	// settled one. Planting `''` into its zap_request position leaves every test
	// green otherwise, and since this wave derives IsZap from the content, the
	// same plant also makes every open zap stop being a zap.
	if err := s.CreateInvoice(ctx, store.Invoice{
		PaymentHash: "open-zap-hash", AmountMsat: 5_000, DescriptionHash: "dhash3",
		Bolt11: "lnbc50n1openzap", ZapRequest: zapRequest,
		CreatedAt: at, ExpiresAt: at.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	rows, err = s.Txns(ctx, store.TxnFilter{Paid: store.IncludingUnpaid})
	if err != nil {
		t.Fatal(err)
	}
	var open store.Txn
	for _, row := range rows {
		if row.PaymentHash == "open-zap-hash" {
			open = row
		}
	}
	if open.PaymentHash == "" {
		t.Fatalf("the open zap invoice is not in the history: %+v", rows)
	}
	if open.ZapRequest != zapRequest {
		t.Errorf("an UNSETTLED zap carries %q, want the zap request — a zap that has not been "+
			"paid yet still has a sender", open.ZapRequest)
	}
	if !open.IsZap {
		t.Error("an unsettled zap does not report itself as one")
	}

	// The other direction: an ordinary payment has no zap request and does not
	// claim one.
	if err := s.CreateInvoice(ctx, store.Invoice{
		PaymentHash: "plain-hash", AmountMsat: 1_000, DescriptionHash: "dhash2",
		Bolt11: "lnbc10n1plain", CreatedAt: at, ExpiresAt: at.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreditSettledInvoice(ctx, "plain-hash", "preimage2", 1_000, at, false); err != nil {
		t.Fatal(err)
	}
	rows, err = s.Txns(ctx, store.TxnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.PaymentHash == "plain-hash" && (row.IsZap || row.ZapRequest != "") {
			t.Errorf("a plain payment claims a zap request: %q", row.ZapRequest)
		}
	}
}
