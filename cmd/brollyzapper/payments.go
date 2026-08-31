package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/nwc"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/wallet"
)

// The payment path's two collaborators, declared HERE because this is the
// consumer — the same shape as crediter above, and §3's rule.

// spender is the wallet's outbound slice. Only these three, so nothing in this
// file can raise a ceiling or read a balance it has no business reading.
type spender interface {
	Reserve(ctx context.Context, req wallet.Reservation) (wallet.ReservationID, error)
	Settle(ctx context.Context, id wallet.ReservationID, actualFeeMsat int64, preimage secret.String) error
	Reverse(ctx context.Context, id wallet.ReservationID) error
	// MarkDispatched records that the payment is about to be handed to the node
	// (t4t). On this seam and not the store's, because it is part of the same
	// sequence Reserve begins: a caller holding one holds the other.
	MarkDispatched(ctx context.Context, id wallet.ReservationID) error
	// ClearDispatched takes the marker back off a payment that never reached the
	// node, which lnd.ErrNotSent is the only licence for.
	ClearDispatched(ctx context.Context, id wallet.ReservationID) error
	// MarkUnresolvable names a row this resolver has stopped trying to resolve
	// (`669`). It is what unlocks the operator's control over that row, and the
	// RESOLVER is the only thing that sets it — see wallet.AssertOutcome.
	MarkUnresolvable(ctx context.Context, id wallet.ReservationID, reason string) error
	// NoteResolveAttempt and ClearResolveAttempts walk the counter that turns a
	// PERSISTENT failure into a named row instead of an endless retry.
	NoteResolveAttempt(ctx context.Context, id wallet.ReservationID) (int, error)
	ClearResolveAttempts(ctx context.Context, id wallet.ReservationID) error
}

// payer is the node's payment slice: send one, and ask about one already sent.
//
// Deliberately NOT widened with Decode when d24.4 needed it: payInvoice does not
// decode — the ladder does, before it calls this at all — and a seam that named
// a method its only consumer never uses would make every fake implement it to
// prove nothing. nwcSpend declares the wider slice it actually holds.
type payer interface {
	SendPayment(ctx context.Context, bolt11 string, feeLimitMsat int64) (lnd.PaymentResult, error)
	TrackPayment(ctx context.Context, paymentHash []byte) (lnd.PaymentResult, error)
}

// pendingPayments is the store's slice: the rows the resolver works through.
type pendingPayments interface {
	PendingPaymentsBefore(ctx context.Context, before time.Time) ([]store.PendingPayment, error)
}

// connectionBudgets is the NWC slice the resolver needs, and ONE method is the
// point (d24.15).
//
// Consumer-declared here, the way lnd.CredentialBroker and logging.AuditSink
// are, so this file can correct a connection budget without importing the
// ladder — cmd knowing what a NIP-47 permission group is would be the dependency
// running backwards (§3). What it can do is add a signed number to one
// connection's spend counter, which is precisely the correction and nothing
// else: it cannot read a secret, grant a permission, or revoke a pairing.
//
// NIL IS VALID. The resolver runs on installs that have never paired anything,
// and a wiring that demanded a budget corrector would make every test that
// exercises payment recovery carry a fake for nothing.
type connectionBudgets interface {
	AdjustNWCBudget(ctx context.Context, id, deltaMsat int64) error
}

// ErrBooking means the PAYMENT resolved but recording it did not.
//
// Typed while there is exactly one caller, because the obvious thing for d24.3
// to write is `if err != nil { return a NIP-47 error }` — which would tell the
// client a settled payment failed, for a payment that has already left the
// node. The result value beside it is the truth about the money; this error is
// the truth about the ledger, and they are not the same sentence.
var ErrBooking = errors.New("payments: the payment resolved but recording it failed")

// ErrNotDispatched means the reservation was refused, so nothing reached the
// node and the payment's fate is KNOWN.
//
// The counterpart to ErrBooking, and it exists for the same reason: an error
// from this function is not one fact. "The wallet said no" and "the node stopped
// answering mid-payment" call for opposite responses — return the budget and
// tell the client, or keep everything and let the resolver decide.
var ErrNotDispatched = errors.New("payments: the payment was refused before dispatch")

// resolveTimeout bounds the whole startup resolution pass.
//
// The resolver runs INLINE before the background loops, so anything it waits on
// is the app not starting. gRPC is fail-fast by default and a refused
// connection returns at once — but a node whose address blackholes packets does
// not refuse, it hangs, and on that path an unbounded wait would be a server
// that never comes up because of a payment from last week. §11 says a missing
// dependency is a degraded state, never a stall.
//
// Generous, because the alternative to finishing is leaving money unresolved: a
// minute is far longer than a healthy node needs for a handful of rows, and far
// shorter than an operator's patience with a dashboard that will not load.
const resolveTimeout = time.Minute

// payment is one outbound payment, already decoded.
//
// Decoding the bolt11 is the caller's job (d24.3's, in practice): by the time
// anything here runs, the amount and the hash are known, and maxFeeMsat has
// come from wallet.MaxFee — which is the ONLY place that number is computed,
// and there is an arch rule saying so.
type payment struct {
	bolt11      string
	amountMsat  int64
	maxFeeMsat  int64
	paymentHash string
	// ref is what the operator sees on the transaction.
	ref string
	// description is the invoice's own memo, and connectionID is the NWC pairing
	// that asked for this payment. Both are written onto the reservation row: the
	// first so the operator's history is not a list of unlabelled debits
	// (d24.16), the second so the resolver can find whose budget to correct
	// after a crash (d24.15).
	description  string
	connectionID int64
	// metadata is the NWC-06 object the paired client sent with this payment and
	// descriptionHash is what the paid invoice committed to. Carried through
	// untouched — this layer is plumbing, and the bounding, the shape check and
	// the binding happen where the request arrives.
	metadata        string
	descriptionHash string
}

// payInvoice reserves, sends, and closes the reservation on the answer.
//
//	MaxFee -> Reserve -> SendPaymentV2 -> terminal -> Settle | Reverse
//
// RESERVE FIRST, always (§5 invariant 2). The reservation is what makes the
// ceiling mean anything; sending first would be paying against a limit nobody
// checked, and Reserve is also where the reconciliation freeze lives, so the
// order is what makes the freeze impossible to route around.
//
// The three endings are deliberately different, and the third is the one that
// matters:
//
//   - SUCCEEDED — Settle with the route's ACTUAL fee. The unused part of the
//     reserve comes back; that arithmetic is SettleSpend's and is fed this
//     number and nothing else.
//   - FAILED — Reverse. A failed payment consumes no budget (§5), and it is not
//     an error: the caller is told, and the ceiling is whole again.
//   - the send itself ERRORED — do NOTHING. The payment's fate is unknown; it
//     may be in flight at the node right now. §6 forbids reversing a
//     reserved-but-unresolved payment, because if it later settles the ceiling
//     has been spent twice. The reservation stays pending and the startup
//     resolver finishes it with the only thing that actually knows: the node.
func payInvoice(ctx context.Context, p payment, purse spender, node payer,
	log *slog.Logger) (lnd.PaymentResult, error) {
	id, err := purse.Reserve(ctx, wallet.Reservation{
		AmountMsat: p.amountMsat, MaxFeeMsat: p.maxFeeMsat, PaymentHash: p.paymentHash,
		Ref: p.ref, Description: p.description, Metadata: p.metadata,
		DescriptionHash: p.descriptionHash, NWCConnectionID: p.connectionID,
	})
	if err != nil {
		// NOTHING was dispatched, and the caller has to be able to tell: §8's
		// ladder answers a refused reservation differently from a send whose
		// outcome is unknown, and gives the connection's budget back for one and
		// not the other. Collapsing the two was a real bug (d24.4 review) — a
		// frozen node told a retrying wallet app its payments might be in
		// flight, and kept the budget for each.
		return lnd.PaymentResult{}, fmt.Errorf("%w: %w", ErrNotDispatched, err)
	}

	// THE MARKER, before the send (t4t). Its absence is what makes the
	// resolver's not-found reversal provably safe rather than an inference from
	// LND's payment record surviving — and on a deliberately shared node that
	// record may not. Written first, we can only fail to have written it for a
	// payment we had not yet handed over.
	//
	// A failure here REFUSES TO SEND. That is the conservative direction and the
	// only one available: sending anyway would produce exactly the row this
	// exists to prevent — dispatched, unmarked, and reversible by a resolver
	// that would be wrong. The reservation stays pending, which the freeze
	// already holds spending on, and the next pass resolves it against a node
	// that has never heard of it.
	if err := purse.MarkDispatched(ctx, id); err != nil {
		log.Error("could not record that a payment is about to be dispatched; NOT sending it, "+
			"because an unmarked payment the node has forgotten is one this app would "+
			"wrongly reverse", "reservation", int64(id), "error", err.Error())
		return lnd.PaymentResult{}, fmt.Errorf("payments: marking reservation %d dispatched: %w",
			int64(id), err)
	}

	result, err := node.SendPayment(ctx, p.bolt11, p.maxFeeMsat)
	switch {
	case errors.Is(err, lnd.ErrNotSent):
		// NOTHING reached the node — no connection, or no stream — so the marker
		// written a moment ago is a lie, and a lie in that direction is
		// permanent: the resolver's dispatched arm refuses to touch such a row,
		// and the freeze it feeds then refuses every later payment for ever.
		// Found by review; before t4t this case self-healed.
		//
		// The reservation still stays pending and is still not reversed here —
		// §6's rule is unchanged. What changes is that the next resolver pass
		// meets an UNMARKED row, asks the node, and takes the provably-safe arm.
		if clearErr := purse.ClearDispatched(ctx, id); clearErr != nil {
			log.Error("a payment never reached the node and its dispatch marker could not be "+
				"cleared; the reservation will need an operator",
				"reservation", int64(id), "error", clearErr.Error())
		}
		log.Warn("a payment never reached the node; the reservation stays pending and the "+
			"resolver will reverse it", "reservation", int64(id),
			"payment_hash", p.paymentHash, "error", err.Error())
		return lnd.PaymentResult{}, err
	case err != nil:
		// Left pending, on purpose. See the doc above.
		log.Warn("a payment was dispatched and its outcome is unknown; the reservation stays "+
			"pending and will be resolved against the node",
			"reservation", int64(id), "payment_hash", p.paymentHash, "error", err.Error())
		return lnd.PaymentResult{}, err
	}

	// The bool is the resolver's business, not this path's: a live payment owns
	// its own reservation, and the ladder corrects its own connection budget.
	_, err = closeReservation(ctx, id, result, purse)
	return result, err
}

// closeReservation applies a terminal payment result to the wallet, reporting
// whether THIS call is the one that closed it.
//
// Shared by the live path and the resolver, deliberately: they are the same
// decision made at different times, and two copies would be two places for
// "FAILED means Reverse" to drift. Booking a failed payment as settled is a
// one-word difference and the difference is money.
//
// The bool exists because the resolver now corrects a connection's NWC budget
// after closing (d24.15), and that correction is NOT idempotent: it adds a
// signed number to a running total. notPendingIsFine deliberately treats "some
// other pass already closed this" as agreement, so without the bool a second
// resolver pass over the same row would apply the same correction twice and the
// budget would drift in the other direction. The live path ignores it — it
// corrects its own budget from the ladder, where the reservation is its own.
func closeReservation(ctx context.Context, id wallet.ReservationID,
	result lnd.PaymentResult, purse spender) (bool, error) {
	switch {
	case result.Succeeded():
		return closed(booking(notPendingIsFine(purse.Settle(ctx, id, result.FeeMsat, result.Preimage))))
	case result.Failed():
		return closed(booking(notPendingIsFine(purse.Reverse(ctx, id))))
	default:
		// Neither, which consume() does not produce: it returns only on a
		// terminal update or an error. Reaching here means that contract broke,
		// and the safe answer is to touch nothing.
		return false, fmt.Errorf("payments: reservation %d has a non-terminal result %v",
			int64(id), result.Status)
	}
}

// closed turns notPendingIsFine's two "no error" cases back into two answers.
//
// A nil error from it means one of two things — this call closed the
// reservation, or it was already closed — and only the first licenses a budget
// correction. errAlreadyClosed is the marker notPendingIsFine leaves.
func closed(err error) (bool, error) {
	if errors.Is(err, errAlreadyClosed) {
		return false, nil
	}
	return err == nil, err
}

// errAlreadyClosed marks a reservation another pass had already closed. It never
// escapes this file: closed() turns it into `false, nil`.
var errAlreadyClosed = errors.New("payments: that reservation was already closed")

// booking marks an error as a bookkeeping failure rather than a payment one.
func booking(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrBooking, err)
}

// notPendingIsFine treats "that reservation is not pending" as agreement.
//
// The resolver is idempotent and re-runnable, and a row another pass already
// closed is the store telling us so — not a failure. Any other error is real.
func notPendingIsFine(err error) error {
	if errors.Is(err, store.ErrReservationNotPending) {
		return errAlreadyClosed
	}
	return err
}

// resolvePendingPayments finishes every reservation a previous run left open.
//
// This is the half that makes d24.2 crash-safety rather than "call an RPC". A
// process that dies between SendPaymentV2 and the settle leaves a reserved row
// and no idea what became of it — and the node is the only thing that knows.
//
// ITS PLACEMENT IS NO LONGER LOAD-BEARING (u0u). It ran at startup because §6
// says pending payments must be resolved before new ones are accepted, and an
// ordering was standing in for that rule — badly, since the HTTP listener
// starts above it and the ordering only ever covered the background loops. The
// rule now lives in wallet.Reserve as a freeze, which no caller can get in
// front of.
//
// It stays here because it is cheap and it resolves the common case before any
// traffic: on a clean start it is one local query and the node is never
// touched. What changed is what its FAILURE means. It used to drop the
// invariant silently; now it leaves the freeze standing, and the recon loop
// retries until the node answers.
//
// `before` is THIS process's start, and the same moment the wallet's freeze
// reads. It excludes payments this process is still making, which are reserved
// and unresolved by definition — store.PendingPaymentsBefore has why that is a
// criterion and not a tidy-up.
//
// The arms, and each is a decision about money:
//
//   - SUCCEEDED   Settle with the actual fee.
//   - FAILED      Reverse.
//   - not found, never dispatched   Reverse, with a line naming why. Our own
//     marker says we never handed it over (t4t), so this is a resolved reversal
//     rather than the silent one §6 forbids — and a fact rather than the
//     inference it used to be.
//   - not found, DISPATCHED   Nothing moves, at ERROR. We sent it and the node
//     has forgotten it, which on a shared box means deleted payment records or
//     an older backup. The payment may have settled; §6 forbids guessing.
//   - no hash     A defect. Reported at ERROR and LEFT PENDING — never
//     auto-reversed, because a reservation whose payment might have settled
//     would double-spend the ceiling. Impossible by construction after this
//     wave (wallet.Reserve refuses one), so meeting it means something else is
//     wrong and an operator has to look.
//   - anything else   The fate is unknown. Nothing moves.
//
// IN_FLIGHT is not an arm because it cannot reach here: TrackPayment consumes
// the stream to a terminal state, which is where "keep tracking until terminal"
// is actually implemented.
//
// One unresolvable row does not strand the others: every row is attempted and
// the failures are reported together. A single bad row blocking startup would
// take the whole app down over one transaction.
func resolvePendingPayments(ctx context.Context, rows pendingPayments, purse spender,
	node payer, budgets connectionBudgets, before time.Time, log *slog.Logger) error {
	pending, err := rows.PendingPaymentsBefore(ctx, before)
	if err != nil {
		return fmt.Errorf("payments: reading pending payments: %w", err)
	}
	if len(pending) == 0 {
		// The normal start, and it costs one local query: nothing reaches the
		// node, so a node that is down does not slow the boot at all.
		return nil
	}
	log.Info("resolving payments left unresolved by a previous run", "count", len(pending))

	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()

	var unresolved []error
	for _, row := range pending {
		if err := resolveOne(ctx, row, purse, node, budgets, log); err != nil {
			unresolved = append(unresolved, err)
		}
	}
	return errors.Join(unresolved...)
}

func resolveOne(ctx context.Context, row store.PendingPayment, purse spender,
	node payer, budgets connectionBudgets, log *slog.Logger) error {
	id := wallet.ReservationID(row.ID)
	if row.PaymentHash == "" {
		// Left exactly as it is. See the arms above: this is the one row the
		// resolver must not act on, and recon is what surfaces it afterwards.
		log.Error("a pending payment has no payment hash, so nothing can be asked about it; "+
			"leaving it pending for reconciliation. This is impossible by construction and "+
			"means something else is wrong", "reservation", row.ID)
		// TERMINAL for this resolver: with no hash there is nothing to ask, and
		// no later pass will have more. Named for the operator rather than
		// retried for ever (`669`).
		name(ctx, id, purse, "this payment has no payment hash, so the node cannot be asked "+
			"about it at all", log)
		return fmt.Errorf("payments: reservation %d is pending with no payment hash", row.ID)
	}
	hash, err := hex.DecodeString(row.PaymentHash)
	if err != nil {
		log.Error("a pending payment's hash is not hex; leaving it pending for reconciliation",
			"reservation", row.ID, "error", err.Error())
		name(ctx, id, purse, "this payment's hash cannot be read, so the node cannot be asked "+
			"about it", log)
		return fmt.Errorf("payments: reservation %d has an unreadable payment hash: %w", row.ID, err)
	}

	result, err := node.TrackPayment(ctx, hash)
	switch {
	case errors.Is(err, lnd.ErrPaymentNotFound) && !row.Dispatched:
		// The node has no record AND we never handed it over. Provably safe to
		// reverse: this is not an inference from LND's records surviving, it is
		// our own marker, written before every send (t4t).
		//
		// Named in the log because a reversal the operator cannot account for is
		// exactly what §6 guards against — this one has a reason, and now the
		// reason is a fact rather than a deduction.
		log.Warn("the node has no record of this payment and it was never dispatched; "+
			"reversing the reservation", "reservation", row.ID, "payment_hash", row.PaymentHash)
		return notPendingIsFine(purse.Reverse(ctx, id))
	case errors.Is(err, lnd.ErrPaymentNotFound):
		// Dispatched, and the node has forgotten it. THE ONE STATE AN OPERATOR
		// MUST LOOK AT — and the case the Wave 21 ruling did not have in front
		// of it.
		//
		// We handed this payment over; the node's record of it is gone. On
		// Umbrel that is a shared node another app can run deletepayments on, or
		// a restore from an older backup. The payment may have settled. §6
		// forbids reversing an unresolved reservation precisely here, because if
		// it settled the ceiling would be spent twice — so nothing moves.
		//
		// No new surface is needed: u0u's freeze already holds spending while an
		// unresolved row exists and 1xp already renders it. What this adds is the
		// NAME, so an operator is not left waiting out a state that will never
		// clear itself.
		log.Error("a payment this app DISPATCHED has no record at the node; leaving it "+
			"pending and touching nothing. This does not clear itself: the node's payment "+
			"record has been deleted or restored from an older backup, and only its operator "+
			"can say whether this payment settled",
			"reservation", row.ID, "payment_hash", row.PaymentHash,
			// The MOMENT, not just the fact. It is what an operator takes to
			// their node's own logs, and it is the question they ask next.
			"dispatched_at", row.DispatchedAt.Format(time.RFC3339))
		// TERMINAL: we handed it over and the node's record is gone. No later
		// pass can learn more, and §6 forbids guessing — so the only remaining
		// path to a terminal state is the operator's (`669`).
		name(ctx, id, purse, "this payment was handed to the node and the node has no record "+
			"of it; only you can say whether it settled", log)
		return fmt.Errorf("payments: reservation %d was dispatched but the node has no record "+
			"of it", row.ID)
	case err != nil:
		log.Warn("could not resolve a pending payment; leaving it pending",
			"reservation", row.ID, "error", err.Error())
		countAttempt(ctx, id, purse, "the node could not be asked about this payment, and "+
			"repeated attempts have failed", log)
		return fmt.Errorf("payments: resolving reservation %d: %w", row.ID, err)
	}

	log.Info("resolved a payment left open by a previous run",
		"reservation", row.ID, "status", result.Status.String(), "fee_msat", result.FeeMsat)
	wasClosed, err := closeReservation(ctx, id, result, purse)
	if err != nil {
		// The node ANSWERED and the ledger would not book it. `hdu` removed the
		// one such error that could never succeed — a fee above the reserve now
		// settles at the reserve with an adjustment — and this is the general
		// case behind it: a persistent failure here used to recur on every start
		// for ever, with the ceiling frozen throughout.
		countAttempt(ctx, id, purse, "the node answered about this payment and the ledger "+
			"could not book the result", log)
		return err
	}
	// A success forgets the failed passes, so a transient error never
	// accumulates toward a name.
	if err := purse.ClearResolveAttempts(ctx, id); err != nil {
		log.Warn("could not clear a payment's resolution attempts",
			"reservation", row.ID, "error", err.Error())
	}
	if wasClosed {
		correctConnectionBudget(ctx, row, result, budgets, log)
	}
	return nil
}

// countAttempt walks the persistent-failure counter, and names the row when it
// runs out (`669`).
//
// The general answer to "a pending row whose resolution keeps failing". A
// transient failure — a node that is down — clears itself well inside the bound
// and is reset by the first success; one that does not is not going to on the
// next pass, and the row needs a path to a terminal state that is not another
// retry.
func countAttempt(ctx context.Context, id wallet.ReservationID, purse spender,
	reason string, log *slog.Logger) {
	attempts, err := purse.NoteResolveAttempt(ctx, id)
	if err != nil {
		log.Warn("could not record a resolution attempt", "reservation", int64(id),
			"error", err.Error())
		return
	}
	if attempts < store.MaxResolveAttempts {
		return
	}
	log.Error("a pending payment has failed to resolve too many times; naming it for the "+
		"operator, who is the only one who can close it now",
		"reservation", int64(id), "attempts", attempts)
	name(ctx, id, purse, reason, log)
}

// name records the resolver's reason for giving up, which is what unlocks the
// operator's control over the row — and nothing else does.
func name(ctx context.Context, id wallet.ReservationID, purse spender,
	reason string, log *slog.Logger) {
	if err := purse.MarkUnresolvable(ctx, id, reason); err != nil {
		log.Error("could not name an unresolvable payment for the operator; it stays pending "+
			"and they cannot close it", "reservation", int64(id), "error", err.Error())
	}
}

// correctConnectionBudget puts back what a recovered payment did not spend
// (d24.15).
//
// THE ARITHMETIC IS THE LIVE PATH'S, moved to the one place that could not run
// it. §8's ladder charges `amount + fee reserve` before it pays and corrects to
// `amount + ACTUAL fee` when the node answers; a payment whose process died in
// between never reached that correction, so the connection kept the whole
// reserve. Measured on the box: 31 000 msat charged where 46 110 was right, and
// it accumulates toward a QUOTA_EXCEEDED the operator did not earn.
//
// The failed arm is NOT what the field trip measured, and it is the larger of
// the two: a crash-recovered payment that FAILED had its wallet reservation
// reversed in full and its connection budget not returned at all. §8 says a
// failed payment consumes no budget, and on this path it consumed all of it.
//
// Best effort, and deliberately after the ledger. The reservation is closed and
// the money is right; this is a second number on a different table, and failing
// to fix it must never leave the ledger half-resolved. It is logged loudly
// instead, because the residue is exactly what an operator would otherwise be
// left guessing about.
func correctConnectionBudget(ctx context.Context, row store.PendingPayment,
	result lnd.PaymentResult, budgets connectionBudgets, log *slog.Logger) {
	if row.NWCConnectionID == 0 || budgets == nil {
		// No connection asked for this payment — an operator's own, or a row
		// written before this wave, when nothing filled the column in.
		return
	}
	// THE LADDER'S OWN ARITHMETIC, called rather than copied. nwc.BudgetCorrection
	// is the single definition of what a terminal payment does to a connection's
	// counter; the switch here is only about which terminal state this is, since
	// "neither settled nor failed" corrects nothing at all.
	var correction int64
	switch {
	case result.Succeeded():
		correction = nwc.BudgetCorrection(true, row.AmountMsat, row.FeeReservedMsat, result.FeeMsat)
	case result.Failed():
		correction = nwc.BudgetCorrection(false, row.AmountMsat, row.FeeReservedMsat, 0)
	}
	if correction == 0 {
		return
	}
	if err := budgets.AdjustNWCBudget(ctx, row.NWCConnectionID, correction); err != nil {
		log.Error("a recovered payment's connection budget could not be corrected; this "+
			"connection will appear to have spent more than it did until its window rolls",
			"reservation", row.ID, "connection", row.NWCConnectionID,
			"correction_msat", correction, "error", err.Error())
		return
	}
	log.Info("corrected a recovered payment's connection budget from the reserve to what it "+
		"actually spent", "reservation", row.ID, "connection", row.NWCConnectionID,
		"correction_msat", correction)
}
