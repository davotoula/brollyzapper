package api

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/wallet"
	"github.com/davotoula/brollyzapper/internal/web"
)

func (s *Server) wallet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data, _, _ := s.page(ctx, "Wallet")
	balance, err := s.Wallet.Balance(ctx)
	if err != nil {
		data.Error = "The ledger could not be read."
		s.Log.Error("reading the balance", "error", err.Error())
	}
	credit, _ := s.Wallet.CreditReceived(ctx)
	data.Wallet = web.WalletView{BalanceMsat: balance, CreditReceived: credit}
	s.fillUnresolvable(ctx, &data)
	s.fillHistory(ctx, &data)
	data.Flash = flashFrom(r)
	s.render(w, "wallet", data)
}

// assertPaymentOutcome is §6's "only its operator can say whether this payment
// settled", as a control (`669`).
//
// IT CAN MAKE THE LEDGER LIE IN EITHER DIRECTION — closing as settled when the
// payment failed loses money from the ledger's view; closing as failed when it
// settled credits money that is gone — so it is fenced. The gate is not here: it
// is re-read inside the transaction that closes the row (see
// store.AssertPaymentOutcome), because the recon loop runs on its own goroutine
// and could resolve the row between a check here and a write there. An operator
// racing the resolver is a worse failure than the stranded row this exists to
// clear.
func (s *Server) assertPaymentOutcome(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "that is not a payment", http.StatusBadRequest)
		return
	}
	// Settled or failed, and NOTHING ELSE. An amount would be a third thing the
	// operator could assert, and the app already has one of those: `adjust`,
	// which is separately audited and does not pretend to be a payment outcome.
	outcome := r.PostFormValue("outcome")
	settled := outcome == "settled"
	if !settled && outcome != "failed" {
		http.Error(w, "that is not an outcome", http.StatusBadRequest)
		return
	}
	if err := s.Wallet.AssertOutcome(r.Context(), wallet.ReservationID(id), settled); err != nil {
		s.Log.Warn("a payment outcome could not be asserted",
			"reservation", id, "outcome", outcome, "error", err.Error())
		http.Redirect(w, r, "/wallet?flash=refused", http.StatusSeeOther)
		return
	}
	// §12, and the WORDING is the requirement rather than the fact of a row:
	// a later reader has to be able to tell "the node told us this settled" from
	// "a human told us it did". They are different kinds of fact and only the
	// second can be wrong.
	s.auditRequest(r, slog.LevelWarn,
		"an operator ASSERTED the outcome of a payment the app could not resolve; this is a "+
			"human's statement about what happened, not something the node reported",
		logging.EventWalletAssert,
		slog.Int64("reservation", id), slog.String("asserted", outcome))
	// The freeze this row was holding may have just lifted, so recon's verdict
	// is stale the moment this returns (§11).
	nudge(s.ReconDemand)
	http.Redirect(w, r, "/wallet?flash=saved", http.StatusSeeOther)
}

// fillHistory adds §9 item 2's transaction history.
//
// A failure here degrades the section rather than the page: the balance and the
// two forms are what an operator came for, and a history that cannot be read is
// not a reason to withhold them (§11, §19 — degraded over dead).
func (s *Server) fillHistory(ctx context.Context, data *web.PageData) {
	if s.History == nil {
		return
	}
	txns, err := s.History.RecentTxns(ctx, store.MaxHistoryRows)
	if err != nil {
		s.Log.Error("reading the transaction history", "error", err.Error())
		// Scoped to the section. data.Error is shared, so writing it here would
		// also mask a ledger failure recorded a few lines earlier.
		data.Wallet.HistoryError = "The transaction history could not be read."
		return
	}
	total, err := s.History.TxnCount(ctx)
	if err != nil {
		s.Log.Error("counting transactions", "error", err.Error())
		total = int64(len(txns))
	}
	data.Wallet.Total = total
	data.Wallet.Txns = make([]web.TxnRow, 0, len(txns))
	for _, t := range txns {
		data.Wallet.Txns = append(data.Wallet.Txns, historyRow(t))
	}
}

// fillUnresolvable adds the rows an operator may close (`669`).
//
// EVERYTHING NEEDED TO CHECK IT AT THE NODE travels: the payment hash, the
// amount, and the moment it was dispatched. §6 says only the operator can say
// whether this settled — and one asked to assert that without being shown what
// to look up will guess, which is a wrong ledger rather than an unknown one.
func (s *Server) fillUnresolvable(ctx context.Context, data *web.PageData) {
	rows, err := s.Wallet.Unresolvable(ctx)
	if err != nil {
		s.Log.Error("reading unresolvable payments", "error", err.Error())
		data.Wallet.UnresolvableError = "The payments needing your decision could not be read."
		return
	}
	for _, row := range rows {
		out := web.UnresolvableRow{
			ID:          row.ID,
			PaymentHash: row.PaymentHash,
			AmountMsat:  row.AmountMsat + row.FeeReservedMsat,
			Reason:      row.Reason,
			When:        row.CreatedAt.Format("2006-01-02 15:04 UTC"),
		}
		if row.Dispatched {
			out.DispatchedAt = row.DispatchedAt.Format("2006-01-02 15:04 UTC")
		}
		data.Wallet.Unresolvable = append(data.Wallet.Unresolvable, out)
	}
}

// historyRow turns one stored transaction into the line the page shows.
func historyRow(t store.Txn) web.TxnRow {
	when := t.CreatedAt
	if !t.SettledAt.IsZero() {
		when = t.SettledAt
	}
	row := web.TxnRow{
		Kind:       t.Kind,
		State:      t.State,
		AmountMsat: t.AmountMsat,
		FeeMsat:    t.FeeMsat,
		Note:       t.Note,
		Comment:    t.Comment,
		When:       when,
	}
	if !t.IsZap {
		// THE OUTGOING LABEL, and it lives INSIDE this arm so that its exclusion
		// from the receipt switch below is structural (doy.5, review). An
		// outgoing row has no receipt to report on — the kind 9735 is published
		// by the payee's node, not ours — and the switch's default arm is
		// "receipt abandoned", the trap this whole epic exists to avoid. Placing
		// this above the arm worked only because out_metadata is never set on
		// a row that is IsZap, which is a guarantee made three files away; here,
		// reading this function is enough.
		//
		// NOTHING IS FETCHED. Both fields come out of the blob already on the
		// row; this function takes no context and so cannot make a request even
		// if a later edit wanted one.
		//
		// Comment is assigned rather than defaulted because on an outgoing row
		// it is empty: the store's comment column is LUD-12, which only an
		// incoming invoice carries. The two never both have something to say.
		if zap, ok := lnurl.ReadOutgoingMetadata(t.OutMetadata); ok {
			row.Payee = shortNpub(zap.Payee)
			row.Comment = zap.Comment
		}
		return row
	}
	switch {
	case t.ZapReceiptID != "":
		// §12's correlation rule: the id identifies the event without
		// reproducing it in full on a page an operator may screenshot.
		row.Receipt, row.ReceiptID = web.ReceiptPublished, logging.Short(t.ZapReceiptID)
	case t.ReceiptPending:
		row.Receipt = web.ReceiptPending
	default:
		// A zap with no receipt id and nothing queued: the retry window closed
		// without any relay accepting. §7 calls this the case that reads as
		// theft, and zap.receipt.abandoned records it in the audit trail — this
		// is the same fact where an operator would actually look for it.
		row.Receipt = web.ReceiptAbandoned
	}
	return row
}

// npubHead and npubTail are how much of a payee's npub the history table shows.
//
// Enough of each end that two different keys do not collide by eye, and short
// enough that the whole thing fits a cell beside an amount and a date. The middle
// is the part nobody reads.
//
// HERE RATHER THAN IN internal/nostr, where the first version put them (review):
// a truncation width is a fact about this table, not about nostr, and a
// protocol-primitives package should not carry one for a future caller with a
// different table to inherit.
const (
	npubHead = 12 // "npub1" plus seven characters of payload
	npubTail = 6
)

// shortNpub renders a payee for the history table, or nothing at all.
//
// NOTHING RATHER THAN THE INPUT for a value that is not a pubkey, and that is the
// security half rather than tidiness: the pubkey comes out of a blob a paired
// client sent us, so falling back to "whatever was in the column" would put a
// client-chosen string on the operator's page. A row shows a payee or it shows
// none.
//
// AND NOTHING IS FETCHED. Resolving a kind 0 profile to a display name would be a
// new outbound path from the server container, opened at page-render time,
// against relays chosen by whoever the operator paid. The page shows what this
// node already holds.
func shortNpub(pubkey string) string {
	npub, err := nostr.Npub(pubkey)
	if err != nil {
		return ""
	}
	if len(npub) <= npubHead+npubTail {
		// Unreachable today — a 32-byte pubkey always encodes to 63 characters —
		// and kept because the alternative to a wrong guess about someone else's
		// encoding is a slice out of range on the operator's wallet page. It
		// returns the whole npub rather than "", so a change in nip19's output
		// shows up as an ugly row instead of a blank one.
		return npub
	}
	return npub[:npubHead] + "…" + npub[len(npub)-npubTail:]
}

func (s *Server) allocate(w http.ResponseWriter, r *http.Request)   { s.moveCeiling(w, r, true) }
func (s *Server) deallocate(w http.ResponseWriter, r *http.Request) { s.moveCeiling(w, r, false) }

// moveCeiling raises or lowers the spending authorisation. §5: this moves no
// sats, which is why the page says so above the form.
func (s *Server) moveCeiling(w http.ResponseWriter, r *http.Request, up bool) {
	sats, err := strconv.ParseInt(r.PostFormValue("sats"), 10, 64)
	if err != nil || sats <= 0 {
		http.Error(w, "that is not an amount of sats", http.StatusBadRequest)
		return
	}
	note := r.PostFormValue("note")
	msat := sats * 1000
	event := logging.EventWalletDeallocate
	if up {
		event = logging.EventWalletAllocate
		err = s.Wallet.Allocate(r.Context(), msat, note)
	} else {
		err = s.Wallet.Deallocate(r.Context(), msat, note)
	}
	if err != nil {
		s.Log.Warn("the ceiling could not be moved", "error", err.Error())
		http.Redirect(w, r, "/?flash=refused", http.StatusSeeOther)
		return
	}
	// §12, d46.23: the ledger records the amount; this records who and from
	// where. "Who raised the spend ceiling, and when" is exactly the question
	// the Security page exists to answer without an SSH session.
	s.auditRequest(r, slog.LevelInfo, "the spending ceiling was moved", event,
		slog.Int64("amount_msat", msat))
	// The ceiling just moved, so recon's verdict is stale the moment this
	// returns. Asking now is what keeps the Security page's tick honest rather
	// than green for up to five minutes (§11, d46.21).
	nudge(s.ReconDemand)
	http.Redirect(w, r, "/?flash=saved", http.StatusSeeOther)
}
