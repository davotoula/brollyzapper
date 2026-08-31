package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// Invoice is the pre-settlement record of an inbound invoice (spec §4). It is
// the only place an unpaid invoice exists; once it settles, a txns row of kind
// invoice_in carries it.
type Invoice struct {
	PaymentHash     string
	AmountMsat      int64
	DescriptionHash string
	Bolt11          string
	ZapRequest      string // raw JSON, byte-identical to what the sender SIGNED
	ZapRelays       string // JSON array from the zap request's relays tag
	// Comment is LUD-12's, in the sender's own words. Bounded in CHARACTERS by
	// lnurl.CommentAllowed, which is the unit the endpoint advertises — the
	// same number in the same units, which o34.12 criterion 2 asserts.
	//
	// It is deliberately NOT part of the metadata string and must never be
	// folded into it: description_hash is computed over the metadata, and a
	// comment mixed in would change the hash the wallet already committed to.
	Comment   string
	State     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateInvoice records a freshly minted invoice.
func (s *Store) CreateInvoice(ctx context.Context, inv Invoice) error {
	state := inv.State
	if state == "" {
		state = InvoiceOpen
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO invoices
		   (payment_hash, amount_msat, description_hash, bolt11, zap_request, zap_relays,
		    comment, state, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		inv.PaymentHash, inv.AmountMsat, inv.DescriptionHash, inv.Bolt11,
		nullString(inv.ZapRequest), nullString(inv.ZapRelays), nullString(inv.Comment),
		state, inv.CreatedAt.Unix(), inv.ExpiresAt.Unix())
	if err != nil {
		return fmt.Errorf("creating invoice: %w", err)
	}
	return nil
}

// Invoice reads one invoice by payment hash.
func (s *Store) Invoice(ctx context.Context, paymentHash string) (Invoice, bool, error) {
	var (
		inv                   Invoice
		zapRequest, zapRelays sql.NullString
		createdAt, expiresAt  int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT payment_hash, amount_msat, description_hash, bolt11, zap_request, zap_relays,
		        COALESCE(comment, ''), state, created_at, expires_at
		 FROM invoices WHERE payment_hash = ?`, paymentHash).
		Scan(&inv.PaymentHash, &inv.AmountMsat, &inv.DescriptionHash, &inv.Bolt11,
			&zapRequest, &zapRelays, &inv.Comment, &inv.State, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Invoice{}, false, nil
	}
	if err != nil {
		return Invoice{}, false, fmt.Errorf("reading invoice: %w", err)
	}
	inv.ZapRequest = zapRequest.String
	inv.ZapRelays = zapRelays.String
	inv.CreatedAt = unixTime(createdAt)
	inv.ExpiresAt = unixTime(expiresAt)
	return inv, true, nil
}

// CreditSettledInvoice records the settlement of an inbound invoice: it marks
// the invoice settled, creates the txns(invoice_in) row, and — when
// creditBalance is set — credits the wallet, all in one transaction (spec §4).
//
// creditBalance carries §5's credit_received setting. When it is false the zap
// is still recorded in full; only the balance entry is withheld, so incoming
// funds stay unspendable until the operator allocates them. internal/wallet is
// the only caller and the only reader of that setting.
//
// Named for the money rather than the invoice on purpose: wallet.Spender.Settle
// settles an OUTBOUND reservation, and two things called Settle one layer apart
// is how a payment gets booked as a receipt.
//
// It reports whether this call was the one that credited. A settlement LND
// redelivers after a restart conflicts on the partial index over
// txns.payment_hash and becomes a no-op,
// which is the difference between recovering from a restart and paying the
// wallet twice for one zap.
func (s *Store) CreditSettledInvoice(ctx context.Context, paymentHash, preimage string, amountPaidMsat int64, settledAt time.Time, creditBalance bool) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("settling invoice: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the tx is committed

	var (
		bolt11     string
		zapRequest sql.NullString
		comment    sql.NullString
	)
	err = tx.QueryRowContext(ctx,
		"SELECT bolt11, zap_request, comment FROM invoices WHERE payment_hash = ?", paymentHash).
		Scan(&bolt11, &zapRequest, &comment)
	if errors.Is(err, sql.ErrNoRows) {
		// The one place this sentinel is produced. See its doc: the invoice
		// stream SKIPS on it, which is safe only because it means exactly
		// "no invoices row for this payment hash".
		return false, fmt.Errorf("settling %s: %w", paymentHash, ErrUnknownInvoice)
	}
	if err != nil {
		return false, fmt.Errorf("settling %s: %w", paymentHash, err)
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO txns
		   (kind, state, amount_msat, payment_hash, bolt11, preimage, zap_request, comment,
		    created_at, settled_at)
		 VALUES ('invoice_in', 'settled', ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(payment_hash) WHERE kind = 'invoice_in' DO NOTHING`,
		amountPaidMsat, paymentHash, bolt11, nullString(preimage), zapRequest, comment,
		settledAt.Unix(), settledAt.Unix())
	if err != nil {
		return false, fmt.Errorf("recording settlement of %s: %w", paymentHash, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("recording settlement of %s: %w", paymentHash, err)
	}
	if affected == 0 {
		// Already settled. Commit so the read transaction closes cleanly.
		return false, tx.Commit()
	}

	txnID, err := res.LastInsertId()
	if err != nil {
		return false, fmt.Errorf("recording settlement of %s: %w", paymentHash, err)
	}
	if creditBalance {
		if err := appendBalanceEntry(ctx, tx, txnID, amountPaidMsat, ReasonCredit, settledAt); err != nil {
			return false, fmt.Errorf("crediting %s: %w", paymentHash, err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		"UPDATE invoices SET state = ? WHERE payment_hash = ?", InvoiceSettled, paymentHash); err != nil {
		return false, fmt.Errorf("marking %s settled: %w", paymentHash, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("committing settlement of %s: %w", paymentHash, err)
	}
	return true, nil
}

// TxnCount is the number of recorded transactions.
func (s *Store) TxnCount(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM txns").Scan(&n); err != nil {
		return 0, fmt.Errorf("counting txns: %w", err)
	}
	return n, nil
}

// openInvoiceCountSQL counts invoices that are open AND not yet past due.
//
// Both halves matter. The sweep runs once a minute, so between ticks the table
// holds open rows that have already expired; counting on state alone would make
// the §7 cap up to a minute stickier than the 600-second invoice expiry it is
// meant to self-clear on. The literal 'open' is inlined for the same reason it
// is in expirySweepSQL — sqlite can only use the partial index when it can
// prove the query implies state = 'open', which it cannot do about a parameter
// it has not seen. It is this package's own constant, never a caller's value.
const openInvoiceCountSQL = `SELECT COUNT(*) FROM invoices ` +
	`WHERE state = 'open' AND expires_at > ?`

// CountOpenInvoices is §7's open-invoice cap, measured.
//
// The cap is the public callback's real resource bound: per-sender buckets and
// the global backstop limit REQUESTS, but what an attacker actually consumes by
// minting is a row in LND's invoice database, and that is what this counts. It
// self-clears — an unpaid LNURL invoice expires in 600 seconds — so a flood costs
// the node ten minutes of a full ceiling rather than permanent damage. NWC-minted
// invoices share the cap and expire in an hour; with the pairing's own budget in
// front of them, they cannot flood it.
func (s *Store) CountOpenInvoices(ctx context.Context, now time.Time) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx, openInvoiceCountSQL, now.Unix()).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting open invoices: %w", err)
	}
	return n, nil
}

// expirySweepSQL is the minute sweep, in one place.
//
// The two states are inlined rather than bound. sqlite can only use the partial
// index idx_invoices_open_expiry when it can prove the query implies
// "state = 'open'", and it cannot prove that about a parameter it has not seen
// yet — so with bound values the index would exist, cost writes, and never be
// used. Both values are this package's own constants, never anything a caller
// supplies. The test that asserts the query plan explains THIS string, so the
// two cannot drift apart.
const expirySweepSQL = `UPDATE invoices SET state = 'expired' ` +
	`WHERE state = 'open' AND expires_at <= ?`

// ExpireInvoices moves past-due open invoices to expired and reports how many
// moved. Settled invoices are never touched, however old.
func (s *Store) ExpireInvoices(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, expirySweepSQL, now.Unix())
	if err != nil {
		return 0, fmt.Errorf("expiring invoices: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("expiring invoices: %w", err)
	}
	return n, nil
}

// SweepObserver is told the outcome of each sweep, so the caller can log it
// without this package importing a logger.
type SweepObserver func(expired int64, err error)

// RunExpirySweep expires past-due invoices on every tick until ctx is done
// (spec §4: "a sweep every minute"). The tick channel and the clock are both
// injected so the behaviour is testable without waiting a minute.
func (s *Store) RunExpirySweep(ctx context.Context, tick <-chan time.Time, now func() time.Time, observe SweepObserver) error {
	if now == nil {
		now = time.Now
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-tick:
			if !ok {
				return nil
			}
			expired, err := s.ExpireInvoices(ctx, now())
			if observe != nil {
				observe(expired, err)
			}
		}
	}
}

func unixTime(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

// nullInt64Ptr writes NULL for an absent optional integer. NULL is meaningful in
// nwc_connections — an absent budget is unlimited, an absent cap is no cap — so
// a zero would be a different rule, not a smaller one.
func nullInt64Ptr(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

// nullUnix writes NULL for the zero time rather than 1970.
func nullUnix(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}

func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// --- pending zap receipts (o34.3 criterion 9) -------------------------------

// SettledZap is everything a kind 9735 receipt is built from, and nothing else.
//
// It spans two tables because the pieces do: the invoice holds the zap request
// and the relays the sender named, and the settled txn holds the preimage and
// the settle time. A receipt needs all four, so one query returns them rather
// than a caller joining them by hand and getting the settle time from the wrong
// place.
type SettledZap struct {
	PaymentHash string
	// MintedMsat is what the invoice was minted FOR — the callback's `amount`
	// parameter — and PaidMsat is what LND actually received.
	//
	// TWO NUMBERS, because they are two facts and each kept doing the other's
	// job (`0vk.15`). NIP-57 Appendix D rule 5 compares the zap request's
	// `amount` tag against the amount the invoice was minted for; it never
	// relates the tag to the amount paid. LND accepts unbounded OVERPAYMENT — it
	// refuses only `amtPaid < Terms.Value` — so a 1000 msat invoice settled at
	// 1001 credits the wallet and then failed to produce a receipt, because the
	// receipt was being checked against the paid amount.
	//
	// §7 says why that direction is the dangerous one: "a zap that credits the
	// wallet but never publishes a receipt is invisible to the sender and reads
	// as theft." The wallet is credited either way; the receipt is the only
	// thing the sender can see.
	MintedMsat int64
	PaidMsat   int64
	Bolt11     string
	// Preimage is proof this invoice was paid, and §11 lists preimages among
	// the things that must never reach a log. The receipt publishes it
	// deliberately, as NIP-57's preimage tag, which is a reveal at one named
	// call site rather than an accident anywhere a struct is formatted.
	Preimage   secret.String
	ZapRequest string
	ZapRelays  string
	// SettledAt is when the invoice was PAID. It becomes the receipt's
	// created_at, and it is why this is read rather than passed: a retry a day
	// later must still stamp the receipt with the moment the zap happened.
	SettledAt time.Time
}

// LogValue keeps the preimage's neighbours from carrying it into a log by
// association (§12). The hash identifies the zap; the preimage is the proof and
// is revealed at exactly one call site, in the receipt.
func (z SettledZap) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("payment_hash", shortID(z.PaymentHash)),
		// BOTH, because a log line that showed one would be the conflation
		// this type exists to end: an overpaid zap is the case worth seeing,
		// and it is invisible unless the two numbers appear side by side.
		slog.Int64("minted_msat", z.MintedMsat),
		slog.Int64("paid_msat", z.PaidMsat),
		slog.Time("settled_at", z.SettledAt),
	)
}

// SettledZapFor returns what the receipt for a settled zap invoice is built
// from. Not found means either no such settlement or an ordinary payment with
// no zap request, which are the same thing to a caller: nothing to publish.
func (s *Store) SettledZapFor(ctx context.Context, paymentHash string) (SettledZap, error) {
	// BOTH amounts. i.amount_msat was always one column away on a join this
	// query already made, and selecting only the ledger's number is what made an
	// overpaid zap unreceiptable (`0vk.15`). See SettledZap for which is which.
	const q = `SELECT t.payment_hash, i.amount_msat, t.amount_msat, COALESCE(t.bolt11, ''),
	    COALESCE(t.preimage, ''), COALESCE(i.zap_request, ''), t.settled_at
	  FROM txns t JOIN invoices i ON i.payment_hash = t.payment_hash
	  WHERE t.payment_hash = ? AND t.kind = ? AND i.zap_request IS NOT NULL`
	var z SettledZap
	var settledAt sql.NullInt64
	var preimage string
	err := s.db.QueryRowContext(ctx, q, paymentHash, KindInvoiceIn).
		Scan(&z.PaymentHash, &z.MintedMsat, &z.PaidMsat, &z.Bolt11, &preimage,
			&z.ZapRequest, &settledAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SettledZap{}, ErrNotFound
	}
	if err != nil {
		return SettledZap{}, fmt.Errorf("reading the settled zap %s: %w", paymentHash, err)
	}
	if !settledAt.Valid {
		return SettledZap{}, fmt.Errorf("the zap %s has no settle time", paymentHash)
	}
	z.SettledAt = time.Unix(settledAt.Int64, 0).UTC()
	z.Preimage = secret.New(preimage)
	return z, nil
}

// PendingReceipt is a receipt that has not reached a relay yet.
type PendingReceipt struct {
	PaymentHash   string
	Attempts      int
	GiveUpAt      time.Time
	NextAttemptAt time.Time
	LastError     string
}

// QueueZapReceipt records that a receipt still needs publishing, or updates the
// schedule of one already queued.
//
// Upsert rather than insert: the same payment hash arrives again on every
// failed retry, and a duplicate-key error there would turn a relay outage into
// a log full of database errors.
func (s *Store) QueueZapReceipt(ctx context.Context, r PendingReceipt) error {
	const q = `INSERT INTO pending_zap_receipts
	    (payment_hash, attempts, give_up_at, next_attempt_at, last_error)
	  VALUES (?, ?, ?, ?, ?)
	  ON CONFLICT(payment_hash) DO UPDATE SET
	    attempts        = excluded.attempts,
	    next_attempt_at = excluded.next_attempt_at,
	    last_error      = excluded.last_error`
	if _, err := s.db.ExecContext(ctx, q, r.PaymentHash, r.Attempts,
		r.GiveUpAt.Unix(), r.NextAttemptAt.Unix(), nullString(r.LastError)); err != nil {
		return fmt.Errorf("queueing a zap receipt for %s: %w", r.PaymentHash, err)
	}
	return nil
}

// dueZapReceiptsSQL is the retry loop's one question, in one place so the test
// that asserts its query plan explains THIS string and the two cannot drift.
//
// next_attempt_at and last_error are deliberately not selected: the caller
// overwrites both before anything reads them, and a column scanned into a field
// nobody consults reads as state that matters.
const dueZapReceiptsSQL = `SELECT payment_hash, attempts, give_up_at
  FROM pending_zap_receipts WHERE next_attempt_at <= ?
  ORDER BY next_attempt_at LIMIT ?`

// DueZapReceipts returns queued receipts whose next attempt has arrived,
// oldest first, at most limit of them.
//
// Bounded on purpose: a box that has been offline for a day comes back with
// every receipt due at once, and publishing them in one burst would open a
// websocket per relay per receipt simultaneously. The loop takes a batch each
// tick instead.
func (s *Store) DueZapReceipts(ctx context.Context, now time.Time, limit int) ([]PendingReceipt, error) {
	rows, err := s.db.QueryContext(ctx, dueZapReceiptsSQL, now.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("reading due zap receipts: %w", err)
	}
	defer rows.Close()
	var out []PendingReceipt
	for rows.Next() {
		var r PendingReceipt
		var giveUp int64
		if err := rows.Scan(&r.PaymentHash, &r.Attempts, &giveUp); err != nil {
			return nil, fmt.Errorf("scanning a due zap receipt: %w", err)
		}
		r.GiveUpAt = time.Unix(giveUp, 0).UTC()
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading due zap receipts: %w", err)
	}
	return out, nil
}

// DropZapReceipt removes a queued receipt, whether it was published or given up
// on. The outcome is recorded elsewhere — txns.zap_receipt_id on success, an
// audit event on give-up — so this row's only job is scheduling.
func (s *Store) DropZapReceipt(ctx context.Context, paymentHash string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM pending_zap_receipts WHERE payment_hash = ?`, paymentHash); err != nil {
		return fmt.Errorf("dropping the queued zap receipt for %s: %w", paymentHash, err)
	}
	return nil
}

// RecordZapReceipt writes the published event id against the settled txn
// (criterion 8). It is the durable answer to "did the sender ever get told".
func (s *Store) RecordZapReceipt(ctx context.Context, paymentHash, eventID string) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE txns SET zap_receipt_id = ? WHERE payment_hash = ? AND kind = ?`,
		eventID, paymentHash, KindInvoiceIn); err != nil {
		return fmt.Errorf("recording the zap receipt for %s: %w", paymentHash, err)
	}
	return nil
}

// ZapReceiptID returns the recorded event id for a settled invoice.
func (s *Store) ZapReceiptID(ctx context.Context, paymentHash string) (string, error) {
	var id sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT zap_receipt_id FROM txns WHERE payment_hash = ? AND kind = ?`,
		paymentHash, KindInvoiceIn).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("reading the zap receipt id for %s: %w", paymentHash, err)
	}
	return id.String, nil
}

// --- the Wallet page's transaction history (§9 item 2, 5do) -----------------

// Txn is one row of the transaction history.
//
// Facts only. Whether a zap's receipt counts as "pending" or "abandoned" is a
// rendering decision and is made in the view, not here — the store's job is to
// say what is recorded, and the same three fields answer it either way.
type Txn struct {
	Kind        string
	State       string
	AmountMsat  int64
	FeeMsat     int64
	Note        string
	Comment     string
	PaymentHash string
	// IsZap is whether this settlement carried a zap request. A zap with no
	// receipt id is a different thing from an ordinary payment with none.
	IsZap bool
	// ZapRequest is the kind 9734 event this settlement carried, raw JSON
	// exactly as received, empty when there was none (d24.27).
	//
	// THE CONTENT rather than the fact, and the difference is a sender's name and
	// face in a wallet app's history: NIP-47's `metadata.nostr` IS this event, and
	// a client reads its pubkey and its `p` tag and resolves them against relays
	// it already holds. The query used to select `zap_request IS NOT NULL`, which
	// is the sender's identity read as a boolean and thrown away.
	//
	// Not a new disclosure: the kind 9735 receipt published PUBLICLY carries this
	// same blob verbatim in its description tag, because NIP-57 requires a client
	// to recompute description_hash from it.
	ZapRequest string
	// OutMetadata is the NWC-06 `metadata` object a paired client sent with the
	// payment it asked for, raw JSON exactly as received, empty when it sent
	// none. It is what gives an OUTGOING zap a payee instead of a blank line: a
	// NIP-57 invoice commits to a description_hash and carries no memo, so its
	// `nostr` member is the only place the payee's identity exists.
	//
	// THE WHOLE OBJECT, not just that member. NWC-06 also defines
	// `recipient_data.identifier` — the payee's lightning address — and
	// `comment`, and a client's own row renderer falls back to the address when a
	// profile has not resolved. Storing only the event handed every row back
	// nameless.
	//
	// STILL A CLIENT'S ASSERTION IN KIND, and bound only in part: nothing reaches
	// this column unless its `nostr` member hashes to the paid invoice's
	// description_hash (y09), but that hash covers the EVENT and not its
	// siblings. `recipient_data` is an unverified claim travelling beside a
	// verified one — fine to hand back to the client that sent it, and not
	// something this node may present as a payee. Why a signature alone was not
	// enough is written once, at the place that enforces it —
	// nwc.Service.outgoingMetadata.
	//
	// A SEPARATE COLUMN FROM ZapRequest, and the separation is load-bearing
	// twice over. IsZap below is derived from ZapRequest alone, and an outgoing
	// row in that column renders as "receipt abandoned" on the admin page — the
	// branch whose own comment calls it the case that reads as theft. And the
	// two are not the same KIND of fact: ZapRequest is raw JSON this node
	// received and verified, this is a paired client's assertion.
	//
	// THE IDENTITY IS THE `p` TAG, not the event's pubkey. On an incoming row the
	// useful party is the sender, who signed it; on an outgoing one the signer is
	// the payer — us, or a throwaway key for an anonymous zap — and the payee is
	// the `p` tag.
	OutMetadata string
	// OutDescriptionHash is what the paid invoice committed to, lowercase hex,
	// empty when the row has none.
	//
	// Stored rather than recomputed, because a hash derived from the blob it is
	// meant to vouch for agrees with it by construction and proves nothing. This
	// came off the invoice, so a client can hash our `metadata.nostr` against it
	// and check the attribution rather than trusting this node for it.
	OutDescriptionHash string
	// Bolt11 is the invoice this row is for, empty when the row has none.
	Bolt11         string
	ZapReceiptID   string
	ReceiptPending bool
	// Description is the invoice's own memo. On an OUTGOING row it is the memo
	// of the invoice this app paid, written at reserve time (d24.16) — before
	// which the operator's history was a list of unlabelled debits while every
	// incoming row carried its zap comment.
	Description string
	// Preimage is the proof this payment settled, and it is secret.String so
	// that putting a Txn through slog cannot leak it (§12 lists preimages with
	// the macaroons). Empty on anything that has not settled, and on every
	// outgoing row written before d24.16 — LND still holds those, this ledger
	// never will.
	Preimage secret.String
	// NWCConnectionID is the pairing that asked for this payment, 0 when none
	// did. It is what lets a caller answer "is this row THIS client's?" — see
	// nwc.txnResult, which reveals a preimage only for a connection's own rows.
	NWCConnectionID int64
	CreatedAt       time.Time
	SettledAt       time.Time
}

// LogValue keeps the preimage out of a log line even when a whole Txn is handed
// to slog (§12).
//
// internal/arch enforced this the moment the type gained a secret, which is the
// rule working: the first version of d24.16 added the field and nothing else,
// and the build failed rather than a preimage reaching a log in three months'
// time.
//
// It reports the FACT rather than the value. "Did this row keep its proof" is a
// real operator question — d24.16 exists because the answer used to be no — and
// the proof itself belongs to the client that made the payment.
func (t Txn) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("kind", t.Kind),
		slog.String("state", t.State),
		slog.Int64("amount_msat", t.AmountMsat),
		slog.Int64("fee_msat", t.FeeMsat),
		slog.String("payment_hash", shortID(t.PaymentHash)),
		slog.Bool("has_preimage", !t.Preimage.IsZero()),
	)
}

// MaxHistoryRows is how many rows a history read returns, and the CAP on what a
// caller may ask for.
//
// No paging in the ADMIN UI: §9 lists a transaction history and does not say how
// it is paged, and inventing pagination there is a §9 decision rather than an
// implementation detail. The page says "showing 100 of N" so the operator can
// see there is more, which is the honest version of not having built it. NIP-47
// pages properly (d24.12: `limit` and `offset`), because the protocol defines
// how — and this number is what bounds a client's `limit` whatever it asks for.
const MaxHistoryRows = 100

// txnColumns is the projection both history readers share, so the admin page and
// NIP-47 cannot come to disagree about what a transaction is.
const txnColumns = `SELECT t.kind, t.state, t.amount_msat, COALESCE(t.fee_msat, 0),
    COALESCE(t.note, ''), COALESCE(t.comment, ''), COALESCE(t.payment_hash, ''),
    COALESCE(t.zap_request, ''), COALESCE(t.out_metadata, ''),
    COALESCE(t.out_description_hash, ''),
    COALESCE(t.bolt11, ''), COALESCE(t.zap_receipt_id, ''),
    EXISTS(SELECT 1 FROM pending_zap_receipts p WHERE p.payment_hash = t.payment_hash),
    COALESCE(t.description, ''), COALESCE(t.preimage, ''),
    COALESCE(t.nwc_connection_id, 0),
    t.created_at, t.settled_at
  FROM txns t`

// openInvoiceColumns shapes an UNPAID invoice as a transaction, in txnColumns'
// exact order and types so the two can be unioned.
//
// Zero fee and NULL settled_at, because neither exists yet — an unpaid invoice
// is a promise, not a payment.
const openInvoiceColumns = `SELECT 'invoice_in', i.state, i.amount_msat, 0,
    '', COALESCE(i.comment, ''), i.payment_hash,
    COALESCE(i.zap_request, ''), '', '', i.bolt11, '',
    EXISTS(SELECT 1 FROM pending_zap_receipts p WHERE p.payment_hash = i.payment_hash),
    '', '', 0,
    i.created_at, NULL
  FROM invoices i`

// recentTxnsSQL is the admin page's history query, in one place so the
// query-plan assertion explains THIS string and the two cannot drift (§13).
//
// Ordered by created_at DESC, which idx_txns_created already serves — no new
// index, and the plan test proves sqlite chooses it rather than sorting the
// whole table to answer a LIMIT.
const recentTxnsSQL = txnColumns + ` ORDER BY t.created_at DESC LIMIT ?`

// TxnFilter is NIP-47's list_transactions parameters, as this store understands
// them (d24.12, test-spec D5).
//
// Every field is optional and the zero value means "no opinion", which is what
// makes the filters composable rather than one query per combination.
type TxnFilter struct {
	// From and Until bound created_at, both INCLUSIVE. Zero means unbounded.
	From  time.Time
	Until time.Time
	// Limit is capped at MaxHistoryRows by Txns itself, whatever a client asks
	// for: `limit` arrives from a paired wallet app.
	Limit  int
	Offset int
	// Direction restricts which way the money went.
	Direction Direction
	// Paid restricts by settlement state.
	Paid PaidFilter
}

// Direction is which way a transaction moved money.
//
// An enum rather than a []string of kinds, so "an allocation is not a payment"
// is unrepresentable rather than validated: the operator's own ledger entries
// are not transactions a wallet app should see, and a caller that could name a
// kind could name that one.
type Direction int

// The directions list_transactions understands (NIP-47's `type`).
const (
	// EitherDirection is both, which is NIP-47's default.
	EitherDirection Direction = iota
	Incoming
	Outgoing
)

// PaidFilter is NIP-47's `unpaid` family, as three states rather than two
// booleans.
//
// Two flags could express a fourth state — "only unpaid, excluding unpaid" —
// which means nothing, and the code that guarded against it was a branch nobody
// could reach on purpose.
type PaidFilter int

const (
	// SettledOnly is the default: money that actually moved.
	SettledOnly PaidFilter = iota
	// IncludingUnpaid adds rows that are not settled — NIP-47's `unpaid: true`.
	IncludingUnpaid
	// UnpaidOnly is NIP-47's unpaid_incoming/unpaid_outgoing: the open ones and
	// nothing else.
	UnpaidOnly
)

// kinds is the txn kinds this direction covers.
func (d Direction) kinds() []string {
	switch d {
	case Incoming:
		return []string{KindInvoiceIn}
	case Outgoing:
		return []string{KindPaymentOut}
	default:
		return []string{KindInvoiceIn, KindPaymentOut}
	}
}

// includes reports whether this direction covers one kind.
func (d Direction) includes(kind string) bool { return slices.Contains(d.kinds(), kind) }

// paymentKinds is what list_transactions may ever return.
var paymentKinds = []string{KindInvoiceIn, KindPaymentOut}

// Txns reads the history through a filter, newest first.
//
// TWO SOURCES, unioned, and the reason is the data model rather than the query.
// A settled incoming payment is a txns row; an UNPAID one is not — an invoice
// only becomes a txn when it settles. So "unpaid incoming", which is the exact
// combination d24.12 was filed about, cannot be answered from txns at all. It
// lives in `invoices`, and a filter that pretended otherwise would return an
// empty list for a client whose invoices are simply still open.
//
// The invoices arm is added only when unpaid rows are asked for. It carries no
// fee and no settle time, because an unpaid invoice has neither.
func (s *Store) Txns(ctx context.Context, filter TxnFilter) ([]Txn, error) {
	var (
		query string
		args  []any
	)
	// The txns arm answers everything that HAS settled, plus outbound rows that
	// are pending or failed — an outbound payment gets its row at reservation.
	if filter.Paid != UnpaidOnly || filter.Direction.includes(KindPaymentOut) {
		query, args = settledTxnsArm(filter)
	}
	if filter.Paid != SettledOnly && filter.Direction.includes(KindInvoiceIn) {
		q, a := openInvoicesArm(filter)
		if query != "" {
			query += "\nUNION ALL\n"
		}
		query += q
		args = append(args, a...)
	}
	if query == "" {
		return []Txn{}, nil
	}

	limit := filter.Limit
	if limit <= 0 || limit > MaxHistoryRows {
		limit = MaxHistoryRows
	}
	args = append(args, limit, max(filter.Offset, 0))

	rows, err := s.db.QueryContext(ctx,
		query+` ORDER BY created_at DESC, payment_hash DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("reading the transaction history: %w", err)
	}
	defer rows.Close()
	return scanTxns(rows, limit)
}

// settledTxnsArm selects from txns, which is where money that MOVED is recorded.
func settledTxnsArm(filter TxnFilter) (string, []any) {
	kinds := filter.Direction.kinds()
	where := ` WHERE t.kind IN (` + placeholders(len(kinds)) + `)`
	args := make([]any, 0, len(kinds)+4)
	for _, kind := range kinds {
		args = append(args, kind)
	}
	switch filter.Paid {
	case UnpaidOnly:
		where += ` AND t.state != ?`
		args = append(args, TxnSettled)
	case SettledOnly:
		where += ` AND t.state = ?`
		args = append(args, TxnSettled)
	}
	bounds, boundArgs := createdAtBounds("t", filter)
	return txnColumns + where + bounds, append(args, boundArgs...)
}

// openInvoicesArm selects invoices nobody has paid yet, shaped as transactions.
func openInvoicesArm(filter TxnFilter) (string, []any) {
	bounds, args := createdAtBounds("i", filter)
	return openInvoiceColumns + ` WHERE i.state != ?` + bounds,
		append([]any{InvoiceSettled}, args...)
}

// createdAtBounds is the time window, for whichever table is being read.
//
// One function because the two arms compare DIFFERENT columns of different
// tables against the same two numbers: written twice, an inclusive bound that
// became exclusive on one side would be invisible.
func createdAtBounds(alias string, filter TxnFilter) (string, []any) {
	var (
		clause string
		args   []any
	)
	if !filter.From.IsZero() {
		clause += ` AND ` + alias + `.created_at >= ?`
		args = append(args, filter.From.Unix())
	}
	if !filter.Until.IsZero() {
		clause += ` AND ` + alias + `.created_at <= ?`
		args = append(args, filter.Until.Unix())
	}
	return clause, args
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?, ", n-1) + "?"
}

// RecentTxns returns the most recent transactions, newest first.
func (s *Store) RecentTxns(ctx context.Context, limit int) ([]Txn, error) {
	rows, err := s.db.QueryContext(ctx, recentTxnsSQL, limit)
	if err != nil {
		return nil, fmt.Errorf("reading the transaction history: %w", err)
	}
	defer rows.Close()
	return scanTxns(rows, limit)
}

func scanTxns(rows *sql.Rows, limit int) ([]Txn, error) {
	out := make([]Txn, 0, limit)
	for rows.Next() {
		var t Txn
		var created int64
		var settled sql.NullInt64
		var preimage string
		if err := rows.Scan(&t.Kind, &t.State, &t.AmountMsat, &t.FeeMsat, &t.Note,
			&t.Comment, &t.PaymentHash, &t.ZapRequest, &t.OutMetadata,
			&t.OutDescriptionHash, &t.Bolt11, &t.ZapReceiptID,
			&t.ReceiptPending,
			&t.Description, &preimage, &t.NWCConnectionID,
			&created, &settled); err != nil {
			return nil, fmt.Errorf("scanning a transaction: %w", err)
		}
		// Wrapped at the scan, so the plain string exists for the length of this
		// statement and nowhere else (§12).
		// DERIVED rather than selected, so the two cannot disagree: a row has a
		// zap request or it does not, and there is one place that decides.
		//
		// OutMetadata IS DELIBERATELY NOT PART OF THIS. IsZap gates the admin
		// page's receipt switch, whose default arm is "receipt abandoned" — an
		// outgoing row has no receipt to publish and never will, so counting it
		// here would report every zap the operator SENT as one they failed to
		// acknowledge (doy.2). That is the whole reason out_metadata is its
		// own column.
		t.IsZap = t.ZapRequest != ""
		t.Preimage = secret.New(preimage)
		t.CreatedAt = time.Unix(created, 0).UTC()
		if settled.Valid {
			t.SettledAt = time.Unix(settled.Int64, 0).UTC()
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading the transaction history: %w", err)
	}
	return out, nil
}
