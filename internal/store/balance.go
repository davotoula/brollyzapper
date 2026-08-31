package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// Reasons for a balance entry (spec §5). Nothing else may appear in the column.
const (
	ReasonAllocate      = "allocate"
	ReasonDeallocate    = "deallocate"
	ReasonCredit        = "credit"
	ReasonReserve       = "reserve"
	ReasonRefundReserve = "refund_reserve"
	ReasonReverse       = "reverse"
	ReasonAdjust        = "adjust"
)

// Transaction kinds (spec §4).
const (
	KindAllocation   = "allocation"
	KindDeallocation = "deallocation"
	KindInvoiceIn    = "invoice_in"
	KindPaymentOut   = "payment_out"
	KindAdjustment   = "adjustment"
)

// Transaction states (spec §4).
const (
	TxnPending = "pending"
	TxnSettled = "settled"
	TxnFailed  = "failed"
	TxnExpired = "expired"
)

// ErrInsufficientBalance means the operation would have taken the balance
// below zero. §5 invariant 1: that may never happen, and the check is inside
// the transaction that appends the entry, so two concurrent reservations
// cannot both pass it.
var ErrInsufficientBalance = errors.New("store: insufficient balance")

// ErrReservationNotPending means the reservation was already settled or
// reversed. Reserving, settling and reversing are each recorded once.
var ErrReservationNotPending = errors.New("store: reservation is not pending")

// appendBalanceEntry appends one signed entry and asserts the balance is still
// non-negative, inside the caller's transaction.
//
// This is the single chokepoint for §5's first invariant. Doing the check in
// the caller — read balance, decide, then write — is the race that lets two
// concurrent payments both pass.
func appendBalanceEntry(ctx context.Context, tx *sql.Tx, txnID, amountMsat int64, reason string, at time.Time) error {
	// The choke point every entry passes, so the bound holds however the caller
	// arrived — and the running total is checked too, since a ledger can be
	// walked past the supply one sane-looking entry at a time.
	if err := inRange(amountMsat); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO balance_entries (txn_id, amount_msat, reason, created_at) VALUES (?, ?, ?, ?)`,
		txnID, amountMsat, reason, at.Unix()); err != nil {
		return fmt.Errorf("appending a %s entry: %w", reason, err)
	}
	var balance sql.NullInt64
	if err := tx.QueryRowContext(ctx, "SELECT SUM(amount_msat) FROM balance_entries").Scan(&balance); err != nil {
		return fmt.Errorf("checking the balance after a %s entry: %w", reason, err)
	}
	if balance.Int64 < 0 {
		return fmt.Errorf("%s of %d msat would leave %d msat: %w",
			reason, amountMsat, balance.Int64, ErrInsufficientBalance)
	}
	if balance.Int64 > MaxMsat {
		return fmt.Errorf("%s of %d msat would leave %d msat: %w",
			reason, amountMsat, balance.Int64, ErrAmountOutOfRange)
	}
	return nil
}

// BalanceMsat is the wallet balance: the sum of every balance entry (spec §4).
// Only internal/wallet may call this — §3 puts the balance behind the Spender
// seam, and TestOnlyTheWalletReachesTheBalance fails the build if anything else
// does.
func (s *Store) BalanceMsat(ctx context.Context) (int64, error) {
	var balance sql.NullInt64
	if err := s.db.QueryRowContext(ctx, "SELECT SUM(amount_msat) FROM balance_entries").Scan(&balance); err != nil {
		return 0, fmt.Errorf("reading balance: %w", err)
	}
	return balance.Int64, nil
}

// AdjustBalance appends an allocation, deallocation or adjustment: the three
// ways the operator moves the ceiling by hand.
//
// Every one of them is a new txn with a note. §5 invariant 3: balance_entries
// is append-only, so a correction is another entry, never an edit.
func (s *Store) AdjustBalance(ctx context.Context, kind, reason string, amountMsat int64, note string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("adjusting the balance: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the tx is committed

	magnitude := amountMsat
	if magnitude < 0 {
		magnitude = -magnitude
	}
	txnID, err := insertTxn(ctx, tx, txnRow{
		kind: kind, state: TxnSettled, amountMsat: magnitude,
		note: note, createdAt: at, settledAt: &at,
	})
	if err != nil {
		return err
	}
	if err := appendBalanceEntry(ctx, tx, txnID, amountMsat, reason, at); err != nil {
		return err
	}
	return tx.Commit()
}

// MaxMsat is the largest amount this ledger will hold or move: 21 million BTC
// in msat, which is all the bitcoin there will ever be.
//
// A bound rather than a taste, and it is about ARITHMETIC rather than about
// wealth. Amounts reach this package from a remote wallet app (§8's pay_invoice)
// and `-(amount + fee)` wraps near MaxInt64 — a debit that becomes a large
// positive credit, raising the ceiling that is the whole safety story of this
// app. Refusing anything past the money supply leaves every sum in this file
// with room to spare: MaxMsat plus its worst-case fee reserve is still four
// times smaller than MaxInt64.
const MaxMsat int64 = 21_000_000 * 100_000_000 * 1_000

// ErrPaymentInFlight means a payment for that invoice is already reserved and
// unresolved — idx_txns_pending_out_hash refused a second one.
//
// TYPED because the caller's answer depends on it: §8's ladder must tell a
// client "that invoice is already being paid" and give its budget back, which is
// a different sentence from "the wallet refused" and a very different one from
// "the payment may be in flight". The unique index remains the enforcement; this
// only names what it said.
var ErrPaymentInFlight = errors.New("store: a payment for that invoice is already in flight")

// ErrAmountOutOfRange means an amount is past what this ledger will hold.
var ErrAmountOutOfRange = errors.New("store: the amount is out of range")

// inRange refuses an amount no ledger entry may carry.
func inRange(amountMsat int64) error {
	if amountMsat < -MaxMsat || amountMsat > MaxMsat {
		return fmt.Errorf("%w: %d msat is past the %d msat this ledger holds",
			ErrAmountOutOfRange, amountMsat, MaxMsat)
	}
	return nil
}

// SpendReservation is one outbound payment, as it is known BEFORE anything is
// sent.
//
// A struct rather than six positional arguments, and it earned that on the way
// through: d24.15 and d24.16 both needed one more fact on the row, and a
// (int64, int64, string, string, string, int64, time.Time) call is a place where
// two strings swap silently and the ledger records the wrong thing.
type SpendReservation struct {
	AmountMsat  int64
	MaxFeeMsat  int64
	PaymentHash string
	// Ref is what the operator sees on the transaction.
	Ref string
	// Description is the invoice's own memo, from the bolt11 the payer decoded.
	//
	// Written HERE rather than on settle, which is a deliberate reading of
	// d24.16's ruling: it is known now, and a payment that fails or is left
	// pending deserves its label as much as one that settles. The field trip
	// found outgoing rows blank while incoming rows carried the zap comment.
	Description string
	// Metadata is the NWC-06 `metadata` object the paired client sent with this
	// payment, raw JSON as received, empty when it sent none. DescriptionHash is
	// what the paid invoice committed to, which is what a client checks that
	// metadata against.
	//
	// Written at reserve time for the same reason Description is: both are known
	// now, and a payment that fails or is left pending deserves its label as much
	// as one that settles. They land in `out_metadata` and `out_description_hash`,
	// NOT in `zap_request` — see migration 0015 for why that separation is not
	// cosmetic.
	Metadata        string
	DescriptionHash string
	// NWCConnectionID is the pairing that asked for this payment, 0 when the
	// payment did not come from one.
	//
	// The column has existed since migration 0001 and NOTHING EVER WROTE IT,
	// which is the structural reason the resolver could not correct a recovered
	// payment's connection budget (d24.15): it lives in cmd, knows nothing about
	// NWC, and had only a ref string to go on. Written at reserve time because
	// this is the one moment the ladder has the connection in hand.
	NWCConnectionID int64
}

// ReserveSpend debits amount plus the fee reserve and records a pending
// payment. §5 invariant 2: this happens before the LND call, always.
func (s *Store) ReserveSpend(ctx context.Context, req SpendReservation, at time.Time) (int64, error) {
	amountMsat, maxFeeMsat := req.AmountMsat, req.MaxFeeMsat
	paymentHash, ref := req.PaymentHash, req.Ref
	// BEFORE the transaction, because the sum below is what wraps: an amount
	// near MaxInt64 turns a debit into a credit and raises the ceiling.
	if err := inRange(amountMsat); err != nil {
		return 0, err
	}
	if err := inRange(maxFeeMsat); err != nil {
		return 0, err
	}
	if err := inRange(amountMsat + maxFeeMsat); err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("reserving: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the tx is committed

	// The hash goes in with the reservation, in the SAME transaction (d24.2).
	// It is known from the bolt11 before anything is sent, and the startup
	// resolver has nothing else to ask the node about — a crash between the
	// reserve and a separate hash-write would leave exactly the row the resolver
	// must never meet: reserved, unresolvable, and forbidden to reverse (§6).
	txnID, err := insertTxn(ctx, tx, txnRow{
		kind: KindPaymentOut, state: TxnPending, amountMsat: amountMsat,
		feeReservedMsat: maxFeeMsat, paymentHash: paymentHash, note: ref, createdAt: at,
		description: req.Description, outMetadata: req.Metadata,
		outDescriptionHash: req.DescriptionHash, nwcConnectionID: req.NWCConnectionID,
	})
	if err != nil {
		// The partial index idx_txns_pending_out_hash is what guarantees one
		// in-flight payment per invoice (utt). The driver names the COLUMN
		// rather than the index, and that is specific enough here: this function
		// inserts payment_out rows and nothing else, so a uniqueness violation
		// on txns.payment_hash from inside it can only be that index. The
		// alternative — a pre-check — would be a second opinion about a
		// constraint the database already holds.
		if strings.Contains(err.Error(), "UNIQUE constraint failed: txns.payment_hash") {
			return 0, fmt.Errorf("%w: %s", ErrPaymentInFlight, paymentHash)
		}
		return 0, err
	}
	// One entry for amount + max_fee. §5 is explicit that there is no separate
	// fee entry: the reserve carries it, and only the unused remainder comes
	// back, so a settled payment nets to exactly -(amount + actual_fee).
	if err := appendBalanceEntry(ctx, tx, txnID, -(amountMsat + maxFeeMsat), ReasonReserve, at); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("committing the reservation: %w", err)
	}
	return txnID, nil
}

// PendingPayment is an outbound payment the app reserved for and never
// resolved. It is what the resolver works through (§6, d24.2).
type PendingPayment struct {
	ID int64
	// PaymentHash is what TrackPaymentV2 is asked about. It is recorded with the
	// reservation, so it is present for every row this app created — a row
	// WITHOUT one is a defect, and the resolver reports it rather than guessing.
	PaymentHash string
	// DispatchedAt is WHEN it was handed over, zero when it was not.
	//
	// The moment rather than the fact, because the one arm that reads it is the
	// one whose log line an operator takes to their node: "dispatched at 14:02
	// and the node has no record of it" is the sentence; a boolean cannot say
	// it.
	DispatchedAt time.Time
	// Dispatched reports whether this payment was handed to the node (t4t).
	//
	// It is what turns the resolver's not-found reversal from an INFERENCE into
	// a fact. The marker is written immediately before SendPaymentV2, so false
	// can only mean "we had not sent it yet" — and a node with no record of a
	// payment we never sent is provably safe to reverse. True with the node
	// having no record is the opposite: a payment that may have settled and a
	// record that has been deleted, which §6 says must not be resolved by
	// guessing.
	Dispatched bool
	// AmountMsat and FeeReservedMsat are what the reservation TOOK, and they are
	// here so the resolver can put the right amount back on the connection's
	// budget (d24.15).
	//
	// The wallet's own ledger does not need them — closeReservation reads the
	// row inside its own transaction — but the NWC budget is a second number on
	// a different table, charged `amount + reserve` by the ladder and corrected
	// to `amount + actual fee` only on the live path. A crash-recovered payment
	// kept the whole reserve: measured on the box at 31000 msat where 46110 was
	// right, ~38% of a daily budget consumed by a payment that did not spend it.
	AmountMsat      int64
	FeeReservedMsat int64
	// NWCConnectionID is the pairing that asked for this payment, 0 when none
	// did — every row written before this wave, and every payment an operator
	// made some other way.
	NWCConnectionID int64
}

// PendingPaymentsBefore is every reserved-but-unresolved outbound payment
// created before a cutoff, oldest first.
//
// Oldest first by created_at, which is what "oldest" means — id was a proxy for
// it, and ordering by the real thing also lets idx_txns_pending_out serve the
// sort instead of the table. The resolver processes them in order so that a
// crash during resolution makes progress rather than restarting at whichever row
// the database happened to return; id breaks ties.
//
// THE CUTOFF IS THE POINT, not a convenience (u0u). Callers pass this process's
// start, and every one of them needs the same filter for the same reason: a
// payment the CURRENT process is in the middle of making is reserved and
// unresolved by definition, for as long as it takes LND to answer. A periodic
// resolution pass without the cutoff would track a payment still being made,
// and the freeze that reads this would refuse the very reservation the payment
// it is refusing had just created — every payment deadlocking against itself.
//
// One query with one filter, rather than a filtered and an unfiltered variant:
// two would be two chances for a caller to pick the wrong one.
//
// STRICTLY before, and created_at is Unix SECONDS, so equality is ambiguous: a
// row written in the same second the process started could belong to either
// run. Excluding it is the safe direction. Including it risks tracking a
// payment this process is still making — the self-deadlock the cutoff exists to
// prevent — while excluding it leaves at worst a row from a previous run that
// no pass resolves, which stays visibly `pending` for reconciliation and the
// operator to see. The window is the one second a crash and a container restart
// would have to fit inside.
func (s *Store) PendingPaymentsBefore(ctx context.Context, before time.Time) ([]PendingPayment, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, COALESCE(payment_hash, ''), COALESCE(dispatched_at, 0),
		        amount_msat, fee_reserved_msat, COALESCE(nwc_connection_id, 0)
		   FROM txns `+unresolvedPaymentsWhere+` ORDER BY created_at, id`,
		KindPaymentOut, TxnPending, before.Unix())
	if err != nil {
		return nil, fmt.Errorf("reading pending payments: %w", err)
	}
	defer rows.Close()
	var out []PendingPayment
	for rows.Next() {
		var p PendingPayment
		var dispatched int64
		if err := rows.Scan(&p.ID, &p.PaymentHash, &dispatched,
			&p.AmountMsat, &p.FeeReservedMsat, &p.NWCConnectionID); err != nil {
			return nil, fmt.Errorf("reading pending payments: %w", err)
		}
		if dispatched != 0 {
			p.DispatchedAt, p.Dispatched = time.Unix(dispatched, 0).UTC(), true
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading pending payments: %w", err)
	}
	return out, nil
}

// MarkSpendDispatched records that a payment was handed to the node (t4t).
//
// Named for the …Spend family so the arch rule that keeps the ceiling's
// protections behind internal/wallet can NAME it: the rule matches on the
// method text, and a method called MarkDispatched on both this type and the
// wallet's could not be pinned without also matching the legitimate call. The
// wallet's stays MarkDispatched, which is what its callers see.
//
// Called IMMEDIATELY BEFORE SendPaymentV2, and the order is the whole point: a
// marker written afterwards leaves a window in which the process dies with the
// payment made and no record of making it — precisely the state this column
// exists to rule out. Written first, its absence can only mean "not sent yet".
//
// The FIRST moment stands: `WHERE dispatched_at IS NULL` makes a second call a
// no-op rather than a rewrite. Nothing calls it twice today — payInvoice calls
// it once per reservation — and the guard is here because "when did this payment
// leave" is a fact about the past, and a retry that moved it would be answering
// a question about a different moment.
func (s *Store) MarkSpendDispatched(ctx context.Context, txnID int64, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE txns SET dispatched_at = ?
		  WHERE id = ? AND kind = ? AND state = ? AND dispatched_at IS NULL`,
		at.Unix(), txnID, KindPaymentOut, TxnPending)
	if err != nil {
		return fmt.Errorf("marking payment %d dispatched: %w", txnID, err)
	}
	// Rows affected is checked, and that is not ceremony: the caller's guarantee
	// is "a failure here refuses to send", and without this the only failure it
	// could detect is a SQL error — a wrong id would return nil and the payment
	// would go out unmarked, which is the row this column exists to rule out.
	//
	// Zero is not always wrong, though: a second call for a row already marked
	// changes nothing and is agreement. So zero rows is an error only when the
	// row is not already marked.
	if affected, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("marking payment %d dispatched: %w", txnID, err)
	} else if affected == 0 {
		if _, marked, err := s.DispatchedAt(ctx, txnID); err != nil {
			return err
		} else if !marked {
			return fmt.Errorf("marking payment %d dispatched: no pending outbound payment "+
				"with that id", txnID)
		}
	}
	return nil
}

// ClearSpendDispatched takes the marker back off a payment that never left.
//
// The counterpart to writing it first (t4t), and the reason both exist. The
// marker is written BEFORE SendPaymentV2 so its absence is the safe direction —
// but a send that fails before the request reaches the node leaves a marker for
// a payment LND has never heard of, and the resolver's dispatched arm refuses to
// touch such a row for ever. That is a reservation frozen permanently, and the
// freeze it feeds (u0u) refuses every later payment with it.
//
// Only lnd.ErrNotSent licenses this — the two failures where the stream never
// carried the request. Every other send failure leaves the fate unknown, and an
// unknown fate keeps its marker.
func (s *Store) ClearSpendDispatched(ctx context.Context, txnID int64) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE txns SET dispatched_at = NULL WHERE id = ? AND kind = ? AND state = ?`,
		txnID, KindPaymentOut, TxnPending); err != nil {
		return fmt.Errorf("clearing payment %d's dispatch marker: %w", txnID, err)
	}
	return nil
}

// DispatchedAt reports when a payment was handed to the node, if it was.
//
// The resolver's diagnosis needs the MOMENT, not the fact: "this row was
// dispatched at 14:02 and the node has no record of it" is the sentence an
// operator takes to their node's logs, and a boolean cannot say it. Also what
// MarkSpendDispatched consults to tell "already marked" from "no such row".
func (s *Store) DispatchedAt(ctx context.Context, txnID int64) (time.Time, bool, error) {
	var at sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT dispatched_at FROM txns WHERE id = ?`, txnID).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("reading payment %d's dispatch time: %w", txnID, err)
	}
	if !at.Valid {
		return time.Time{}, false, nil
	}
	return time.Unix(at.Int64, 0).UTC(), true, nil
}

// MaxResolveAttempts is how many consecutive failed resolution passes a pending
// payment gets before it is named for the operator (`669`).
//
// THE GENERAL ANSWER to a persistent failure, not one error's. `hdu` fixed the
// fee overspend that could never succeed; what made it expensive was that a
// persistent Settle failure had no terminal disposition at all, so it recurred
// on every start for ever with the ceiling frozen throughout. Any persistent
// failure now walks this counter.
//
// Five, and the number is about the recon loop rather than about the error: a
// node that is briefly down clears itself well inside five passes, and one that
// is not is not going to on the sixth. A success resets it, so a transient
// failure never accumulates toward a name.
const MaxResolveAttempts = 5

// NoteResolveAttempt records that a resolution pass failed for this row, and
// reports how many have now failed in a row.
func (s *Store) NoteResolveAttempt(ctx context.Context, txnID int64) (int, error) {
	var attempts int
	if err := s.db.QueryRowContext(ctx,
		`UPDATE txns SET resolve_attempts = resolve_attempts + 1
		  WHERE id = ? AND kind = ? AND state = ?
		  RETURNING resolve_attempts`,
		txnID, KindPaymentOut, TxnPending).Scan(&attempts); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Already closed by another pass. Not an error: the row reached a
			// terminal state, which is the outcome this counter exists to reach.
			return 0, nil
		}
		return 0, fmt.Errorf("recording a resolution attempt for txn %d: %w", txnID, err)
	}
	return attempts, nil
}

// ClearResolveAttempts forgets a row's failed passes, so a transient failure
// never accumulates toward a name.
func (s *Store) ClearResolveAttempts(ctx context.Context, txnID int64) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE txns SET resolve_attempts = 0 WHERE id = ? AND resolve_attempts != 0`,
		txnID); err != nil {
		return fmt.Errorf("clearing resolution attempts for txn %d: %w", txnID, err)
	}
	return nil
}

// MarkPaymentUnresolvable names a pending payment the resolver has given up on,
// which is what unlocks the operator's control over it (`669`).
//
// Only ever set by the RESOLVER. §6 says only the operator can say whether such
// a payment settled, and the control that lets them say it can make the ledger
// lie in either direction — so it is fenced to rows the thing that tried has
// already stopped trying on. An operator racing the recon loop is a worse
// failure than the stranded row.
//
// Idempotent, and it does not overwrite: the FIRST reason is the one that
// explains the row, and a later pass restating it would replace an accurate
// diagnosis with whatever failed most recently.
func (s *Store) MarkPaymentUnresolvable(ctx context.Context, txnID int64, reason string) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE txns SET unresolvable_reason = ?
		  WHERE id = ? AND kind = ? AND state = ? AND unresolvable_reason IS NULL`,
		reason, txnID, KindPaymentOut, TxnPending); err != nil {
		return fmt.Errorf("naming txn %d unresolvable: %w", txnID, err)
	}
	return nil
}

// UnresolvablePayments is every pending payment the resolver has named, oldest
// first — the rows the operator may close, and no others.
func (s *Store) UnresolvablePayments(ctx context.Context) ([]UnresolvablePayment, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, COALESCE(payment_hash, ''), amount_msat, fee_reserved_msat,
		        COALESCE(dispatched_at, 0), created_at, COALESCE(unresolvable_reason, '')
		   FROM txns
		  WHERE kind = ? AND state = ? AND unresolvable_reason IS NOT NULL
		  ORDER BY created_at, id`,
		KindPaymentOut, TxnPending)
	if err != nil {
		return nil, fmt.Errorf("reading unresolvable payments: %w", err)
	}
	defer rows.Close()
	var out []UnresolvablePayment
	for rows.Next() {
		var p UnresolvablePayment
		var dispatched, created int64
		if err := rows.Scan(&p.ID, &p.PaymentHash, &p.AmountMsat, &p.FeeReservedMsat,
			&dispatched, &created, &p.Reason); err != nil {
			return nil, fmt.Errorf("reading unresolvable payments: %w", err)
		}
		p.CreatedAt = time.Unix(created, 0).UTC()
		if dispatched != 0 {
			p.DispatchedAt, p.Dispatched = time.Unix(dispatched, 0).UTC(), true
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UnresolvablePayment is one such row, with everything the operator needs to
// check it AT THE NODE before asserting anything.
//
// §6 says only they can say whether this settled. One asked to assert that
// without being shown what to look up will guess, and a guess here is a wrong
// ledger — so the hash, the amount and the moment it was dispatched all travel.
type UnresolvablePayment struct {
	ID              int64
	PaymentHash     string
	AmountMsat      int64
	FeeReservedMsat int64
	CreatedAt       time.Time
	DispatchedAt    time.Time
	Dispatched      bool
	Reason          string
}

// ErrNotUnresolvable means the operator tried to close a row the resolver has
// not given up on.
var ErrNotUnresolvable = errors.New("store: that payment has not been named unresolvable")

// AssertPaymentOutcome is the operator saying what became of a payment the app
// could not find out about (`669`).
//
// THE GATE IS INSIDE THE TRANSACTION, and that is the point rather than
// tidiness: the resolver runs on the recon loop and could clear a row between a
// handler's check and its write. Re-reading the marker under the same
// transaction that closes the row is what makes "only rows the resolver has
// given up on" true rather than likely.
//
// SETTLED books the RESERVED fee. The operator is asserting that the payment
// went through, not what the route cost — they have no way to know — and the
// reservation is what was taken from the ceiling. Booking anything else would be
// inventing a number.
func (s *Store) AssertPaymentOutcome(ctx context.Context, txnID int64, settled bool, at time.Time) error {
	return s.closeReservation(ctx, txnID, at, func(ctx context.Context, tx *sql.Tx, r reservation) error {
		var named sql.NullString
		if err := tx.QueryRowContext(ctx,
			`SELECT unresolvable_reason FROM txns WHERE id = ?`, txnID).Scan(&named); err != nil {
			return fmt.Errorf("reading txn %d: %w", txnID, err)
		}
		if !named.Valid {
			return ErrNotUnresolvable
		}
		if !settled {
			if _, err := tx.ExecContext(ctx,
				"UPDATE txns SET state = ? WHERE id = ?", TxnFailed, txnID); err != nil {
				return fmt.Errorf("failing txn %d: %w", txnID, err)
			}
			return appendBalanceEntry(ctx, tx, txnID,
				r.amountMsat+r.reservedFeeMsat, ReasonReverse, at)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE txns SET state = ?, fee_msat = ?, settled_at = ? WHERE id = ?`,
			TxnSettled, r.reservedFeeMsat, at.Unix(), txnID); err != nil {
			return fmt.Errorf("settling txn %d: %w", txnID, err)
		}
		// Nothing to refund: the whole reservation stands, which is the
		// conservative direction for a payment nobody could confirm.
		return nil
	})
}

// unresolvedPaymentsWhere is THE predicate, written once.
//
// Two readers ask this question — the resolver, which works the rows, and the
// freeze, which only counts them — and they must agree about which rows count.
// Drift between two inline copies would be silent and would mean either
// spending held on a row nothing resolves, or a row resolved that the freeze
// never saw. Same reason openInvoiceCountSQL sits beside the expiry sweep.
const unresolvedPaymentsWhere = `WHERE kind = ? AND state = ? AND created_at < ?`

// HasUnresolvedPaymentsBefore is PendingPaymentsBefore reduced to the one bit
// the freeze needs.
//
// Separate because it is asked on EVERY Reserve and the answer is almost always
// no: EXISTS stops at the first match and returns a scalar, where the row query
// would build a slice. Both share unresolvedPaymentsWhere, which is the part
// that has to agree — see there.
func (s *Store) HasUnresolvedPaymentsBefore(ctx context.Context, before time.Time) (bool, error) {
	var held bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM txns `+unresolvedPaymentsWhere+`)`,
		KindPaymentOut, TxnPending, before.Unix()).Scan(&held); err != nil {
		return false, fmt.Errorf("checking for unresolved payments: %w", err)
	}
	return held, nil
}

// CountUnresolvedPaymentsBefore is the same question as a NUMBER, for §11's
// Tier-2 row.
//
// The third reader of unresolvedPaymentsWhere, and it is here rather than
// len(PendingPaymentsBefore(...)) for the reason stated above: COUNT returns a
// scalar where the row query builds a slice of rows nobody looks at. Sharing the
// predicate is what keeps the freeze, the resolver and the dashboard agreeing
// about which rows count.
func (s *Store) CountUnresolvedPaymentsBefore(ctx context.Context, before time.Time) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM txns `+unresolvedPaymentsWhere,
		KindPaymentOut, TxnPending, before.Unix()).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting unresolved payments: %w", err)
	}
	return n, nil
}

// SettleSpend closes a reservation that paid, refunding the part of the fee
// reserve the route did not use and recording the PREIMAGE.
//
// The preimage is the row's proof that this payment settled, and d24.16 is what
// it costs to leave it out: the field trip found txns.preimage NULL for two real
// payments the node held proof of, and every payment made before that fix has no
// proof-of-payment in this app's ledger, permanently. LND keeps its own copy;
// this app's history does not, and cannot be backfilled honestly.
//
// secret.String all the way in, so the one place it becomes a plain string is
// this INSERT's argument list. §12 lists preimages with the macaroons, and a
// plain string parameter would put it in every %v between here and the driver.
// It reports the fee EXCESS it had to adjust for, so the one caller that has an
// auditor can raise §12's row. Returned rather than audited here because this
// package writes no security events — the Auditor is the server's, and the store
// is what it writes into.
func (s *Store) SettleSpend(ctx context.Context, txnID, actualFeeMsat int64,
	preimage secret.String, at time.Time) (int64, error) {
	var excess int64
	err := s.closeReservation(ctx, txnID, at, func(ctx context.Context, tx *sql.Tx, r reservation) error {
		// AN OVERSPENT FEE SETTLES AT THE RESERVED ONE, AND THE EXCESS BECOMES AN
		// ADJUSTMENT (`hdu`, 26 Aug 2026).
		//
		// This used to return an error, and the error was permanent: the row
		// stayed pending, every start re-tracked it, re-settled it and re-failed,
		// and the resolver's claim that every pending payment reaches a terminal
		// state acquired a counterexample that could never clear. It also held
		// the ceiling for ever, since the freeze counts exactly that row.
		//
		// THE MONEY HAS ALREADY LEFT THE NODE. Refusing to book it does not
		// un-spend it; it makes the ledger less true, not more. So the payment
		// is booked.
		//
		// AT THE RESERVED FEE, not the actual one, and that is the whole
		// distinction. Settling at the actual fee would break §5's invariant
		// that a spend never exceeds its reservation — silently, inside the one
		// place the balance may move. Reserved plus a separate `adjustment`
		// keeps the invariant AND makes the discrepancy a row an operator can
		// see, which is what KindAdjustment is the vocabulary for. Absorbed into
		// the settled amount it would be invisible, and a ledger that quietly
		// absorbs differences is one nobody can audit.
		//
		// It should not happen: `fee_limit_msat` is a cap LND respects. Meeting
		// it means something is wrong, and the adjustment is how the operator
		// finds out rather than how the app hides it.
		bookedFeeMsat, excessMsat := actualFeeMsat, int64(0)
		if actualFeeMsat > r.reservedFeeMsat {
			bookedFeeMsat, excessMsat = r.reservedFeeMsat, actualFeeMsat-r.reservedFeeMsat
		}
		excess = excessMsat
		if _, err := tx.ExecContext(ctx,
			`UPDATE txns SET state = ?, fee_msat = ?, settled_at = ?,
			                 preimage = COALESCE(?, preimage)
			  WHERE id = ?`,
			TxnSettled, bookedFeeMsat, at.Unix(), nullString(preimage.Reveal()),
			txnID); err != nil {
			return fmt.Errorf("settling txn %d: %w", txnID, err)
		}
		if refund := r.reservedFeeMsat - bookedFeeMsat; refund != 0 {
			if err := appendBalanceEntry(ctx, tx, txnID, refund, ReasonRefundReserve, at); err != nil {
				return err
			}
		}
		if excessMsat == 0 {
			return nil
		}
		// The note names the row and BOTH fees. It is what the operator reads on
		// their transaction history, and an adjustment with no explanation is a
		// number nobody can account for — which is the same defect as absorbing
		// it, one step later.
		note := fmt.Sprintf("fee excess on payment %d: the route cost %d msat and %d msat was "+
			"reserved", txnID, actualFeeMsat, r.reservedFeeMsat)
		adjustmentID, err := insertTxn(ctx, tx, txnRow{
			kind: KindAdjustment, state: TxnSettled, amountMsat: excessMsat,
			note: note, createdAt: at, settledAt: &at,
		})
		if err != nil {
			return err
		}
		// NEGATIVE: the ceiling really is lower by this much, because the node
		// really did spend it.
		return appendBalanceEntry(ctx, tx, adjustmentID, -excessMsat, ReasonAdjust, at)
	})
	if err != nil {
		// Nothing was committed, so nothing was adjusted.
		return 0, err
	}
	return excess, nil
}

// ReverseSpend closes a reservation that failed, returning the whole
// reservation to the balance. A failed payment consumes nothing.
func (s *Store) ReverseSpend(ctx context.Context, txnID int64, at time.Time) error {
	return s.closeReservation(ctx, txnID, at, func(ctx context.Context, tx *sql.Tx, r reservation) error {
		if _, err := tx.ExecContext(ctx,
			"UPDATE txns SET state = ? WHERE id = ?", TxnFailed, txnID); err != nil {
			return fmt.Errorf("failing txn %d: %w", txnID, err)
		}
		return appendBalanceEntry(ctx, tx, txnID, r.amountMsat+r.reservedFeeMsat, ReasonReverse, at)
	})
}

// reservation is the pending payment_out row both closers need.
type reservation struct {
	amountMsat      int64
	reservedFeeMsat int64
}

// closeReservation runs close over a pending payment_out, in one transaction.
func (s *Store) closeReservation(ctx context.Context, txnID int64, at time.Time,
	close func(ctx context.Context, tx *sql.Tx, r reservation) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("closing reservation %d: %w", txnID, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the tx is committed

	var (
		state string
		r     reservation
	)
	err = tx.QueryRowContext(ctx,
		"SELECT state, amount_msat, fee_reserved_msat FROM txns WHERE id = ? AND kind = ?",
		txnID, KindPaymentOut).Scan(&state, &r.amountMsat, &r.reservedFeeMsat)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("reservation %d: %w", txnID, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("reading reservation %d: %w", txnID, err)
	}
	if state != TxnPending {
		return fmt.Errorf("reservation %d is %s: %w", txnID, state, ErrReservationNotPending)
	}
	if err := close(ctx, tx, r); err != nil {
		return err
	}
	return tx.Commit()
}

// txnRow is the subset of txns these operations write.
type txnRow struct {
	kind               string
	state              string
	amountMsat         int64
	feeReservedMsat    int64
	paymentHash        string
	note               string
	description        string
	outMetadata        string
	outDescriptionHash string
	nwcConnectionID    int64
	createdAt          time.Time
	settledAt          *time.Time
}

func insertTxn(ctx context.Context, tx *sql.Tx, row txnRow) (int64, error) {
	var settledAt any
	if row.settledAt != nil {
		settledAt = row.settledAt.Unix()
	}
	var connectionID any
	if row.nwcConnectionID != 0 {
		// NULL rather than 0 for a payment no connection asked for: the column
		// is a REFERENCES nwc_connections(id), and 0 is not a connection.
		connectionID = row.nwcConnectionID
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO txns (kind, state, amount_msat, fee_reserved_msat, payment_hash, note,
		                   description, out_metadata, out_description_hash,
		                   nwc_connection_id, created_at, settled_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.kind, row.state, row.amountMsat, row.feeReservedMsat, nullString(row.paymentHash),
		nullString(row.note), nullString(row.description), nullString(row.outMetadata),
		nullString(row.outDescriptionHash),
		connectionID, row.createdAt.Unix(), settledAt)
	if err != nil {
		return 0, fmt.Errorf("recording a %s txn: %w", row.kind, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("recording a %s txn: %w", row.kind, err)
	}
	return id, nil
}
