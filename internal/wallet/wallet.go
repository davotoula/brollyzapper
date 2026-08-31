package wallet

import (
	"context"
	"errors"
	"fmt"
	"github.com/davotoula/brollyzapper/internal/logging"
	"log/slog"
	"strconv"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// ReservationID identifies one authorised outbound payment.
type ReservationID int64

// Spender authorises and records outbound spends against the wallet ceiling
// (spec §3). Nothing outside this interface may consult or mutate the balance,
// and TestOnlyTheWalletReachesTheBalance fails the build if anything tries.
type Spender interface {
	Reserve(ctx context.Context, req Reservation) (ReservationID, error)
	Settle(ctx context.Context, id ReservationID, actualFeeMsat int64, preimage secret.String) error
	Reverse(ctx context.Context, id ReservationID) error
	Balance(ctx context.Context) (int64, error)
}

// Settings keys and their defaults (spec §5).
const (
	SettingMaxFeeFloorMsat = "max_fee_floor_msat"
	SettingMaxFeePPM       = "max_fee_ppm"
	SettingCreditReceived  = "credit_received"

	DefaultMaxFeeFloorMsat int64 = 10_000 // 10 sat
	DefaultMaxFeePPM       int64 = 10_000 // 1%
)

// Reservation is one outbound payment as it is known before anything is sent.
//
// A struct because the call grew past what positional arguments carry safely:
// d24.15 added the connection and d24.16 the description, and
// `Reserve(ctx, 21000, 10000, hash, ref, desc, 2)` is a call where two strings
// swap without the compiler noticing and the ledger records the wrong thing. It
// mirrors store.SpendReservation field for field, deliberately — this seam
// exists so consumers do not import the store, not so the two can drift.
type Reservation struct {
	AmountMsat  int64
	MaxFeeMsat  int64
	PaymentHash string
	// Ref is what the operator sees on the transaction.
	Ref string
	// Description is the invoice's own memo (d24.16).
	Description string
	// Metadata is the NWC-06 `metadata` object the paired client sent with this
	// payment, and DescriptionHash is what the paid invoice committed to.
	// Carried, not inspected: this package does not read either, it records what
	// it was handed.
	Metadata        string
	DescriptionHash string
	// NWCConnectionID is the pairing that asked for this payment, 0 when none
	// did (d24.15).
	NWCConnectionID int64
}

// Options configure a LocalSpender. The zero value is usable.
type Options struct {
	// Now is injected so tests can stamp entries deterministically.
	Now func() time.Time
	// StartedAt is when THIS process began, and it is the cutoff the unresolved
	// payments freeze reads (u0u).
	//
	// Injected rather than taken from the clock here so a test can move it, and
	// because cmd/brollyzapper computes it once and hands the same moment to
	// the wallet and to the payment resolver — two statements of one fact is
	// exactly what would let the freeze and the resolver disagree about which
	// payments belong to this run. Zero means "now", which is what a wallet
	// built at startup wants anyway.
	StartedAt time.Time
	// Auditor raises §12's row when the app adjusts the ceiling itself. Nil is
	// valid — see localSpender.auditor.
	Auditor Auditor
	// Log is where a failure to write that row is reported. Nil takes the
	// process default.
	Log *slog.Logger
}

// localSpender is §3's localSpender: the soft, in-process ceiling.
//
// It gives the operator a sensible day-to-day limit and good errors, and it is
// what a compromised server can bypass. The guard's hard cap (§6) is the
// independent layer underneath, in another container, owned by an environment
// variable this process cannot change.
//
// Deliberately unexported. It carries more than the Spender seam — allocation,
// crediting, the fee number — and a consumer that can name the concrete type
// gets outbound spend authority along with whatever it actually wanted. Callers
// declare the interface they need, the way internal/lnd declares
// CredentialBroker and internal/logging declares AuditSink.
type localSpender struct {
	store *store.Store
	now   func() time.Time
	// startedAt is the cutoff for the unresolved-payments freeze. See Options.
	startedAt time.Time
	// auditor raises §12's row for an adjustment the app made to itself. NIL IS
	// VALID: a wallet without one still books the adjustment — the ledger is the
	// money and this is the explanation.
	auditor Auditor
	log     *slog.Logger
}

// Auditor is §12's trail, as this package needs it. Declared here, by the
// consumer, per §3.
type Auditor interface {
	Record(ctx context.Context, level slog.Level, msg string, event logging.Event,
		attrs ...slog.Attr) error
}

// New builds the wallet over the store that holds the ledger.
func New(db *store.Store, opts Options) *localSpender { //nolint:revive // see the type comment
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	startedAt := opts.StartedAt
	if startedAt.IsZero() {
		startedAt = now()
	}
	log := opts.Log
	if log == nil {
		log = logging.Default()
	}
	return &localSpender{store: db, now: now, startedAt: startedAt,
		auditor: opts.Auditor, log: log}
}

var _ Spender = (*localSpender)(nil)

// UnresolvedAfter is how long a payment may be pending before it counts as
// unresolved (`l3l`).
//
// EXPIRY CONDITION, and it is LND's number rather than ours: `lnd.PaymentTimeout`
// is 60 seconds, so a payment still legitimately in flight cannot be older than
// that plus the round trip. Five minutes is that with room for a slow node and a
// retried stream. What moves this is LND's timeout changing — not convenience,
// and not a test wanting to wait less.
const UnresolvedAfter = 5 * time.Minute

// UnresolvedCutoff is the moment the unresolved-payments freeze measures
// against, and it is the LATER of two answers.
//
// Exposed so the resolver reads the SAME value the freeze does. They must agree
// about which payments belong to a previous run — a resolver with a later
// cutoff would resolve a payment still being made, and one with an earlier
// cutoff would leave rows the freeze is holding spending for. One value, owned
// by the thing that enforces it, beats two copies threaded from the wiring.
//
// WHY TWO ANSWERS AND NOT ONE (`l3l`). It used to be this process's start alone,
// which left a class uncovered: a payment THIS process dispatched whose send
// errored is pending and unresolved too, and a start-based cutoff excludes it —
// so it neither held spending nor was resolved until the next start computed a
// later cutoff. A rolling "older than UnresolvedAfter" covers that class, and on
// its own it would LOSE the other: at startup, `now - UnresolvedAfter` is
// EARLIER than the process start, so a row a previous run left thirty seconds
// before it crashed would not freeze for another five minutes — a window in
// which the ceiling can be spent against a reservation that may already have
// settled.
//
// The later of the two takes both. At startup it is the process start, so an
// inherited row freezes immediately; once the process has been up longer than
// UnresolvedAfter it is the rolling one, so this run's own stuck rows are caught
// without waiting for a restart. A payment genuinely in flight is younger than
// both and is excluded by both — which is the self-deadlock criterion, unchanged.
func (w *localSpender) UnresolvedCutoff() time.Time {
	if rolling := w.now().Add(-UnresolvedAfter); rolling.After(w.startedAt) {
		return rolling
	}
	return w.startedAt
}

// UnresolvedPayments is how many payments a previous run left in flight, for
// §11's Tier-2 row (1xp).
//
// On the WALLET rather than read from the store directly, because an arch rule
// keeps the store's spend methods inside this package — and for the reason that
// rule exists: the freeze is a wallet state, and a second reader deciding for
// itself which rows count is how the dashboard and the freeze come to disagree.
// Same cutoff, same query, one answer.
func (w *localSpender) UnresolvedPayments(ctx context.Context) (int, error) {
	return w.store.CountUnresolvedPaymentsBefore(ctx, w.UnresolvedCutoff())
}

// Balance is the sum of every balance entry (spec §5).
func (w *localSpender) Balance(ctx context.Context) (int64, error) {
	return w.store.BalanceMsat(ctx)
}

// Reserve debits amount plus the fee reserve and records a pending payment.
//
// This happens before the LND call, always (§5 invariant 2). The debit is
// committed by the time this returns, which is why two concurrent payments
// cannot both pass the ceiling.
func (w *localSpender) Reserve(ctx context.Context, req Reservation) (ReservationID, error) {
	amountMsat, maxFeeMsat, paymentHash := req.AmountMsat, req.MaxFeeMsat, req.PaymentHash
	if err := requirePositive("reserve", amountMsat); err != nil {
		return 0, err
	}
	if maxFeeMsat < 0 {
		return 0, fmt.Errorf("wallet: cannot reserve a negative fee of %d msat", maxFeeMsat)
	}
	// The hash is REQUIRED, which is what makes "a pending payment_out with no
	// hash is impossible" a property of the code rather than a hope (d24.2).
	//
	// It is the only thing the resolver can ask the node about after a
	// crash, and a row without one is unresolvable: §6 forbids reversing a
	// reserved-but-unresolved payment, because doing so double-spends the
	// ceiling if it later settles. So such a row can never be reversed and never
	// be confirmed — it is a defect, and the place to stop it is here, before it
	// exists. Every outbound payment has a bolt11, and every bolt11 has a hash.
	if paymentHash == "" {
		return 0, errors.New("wallet: refusing to reserve without a payment hash; the startup " +
			"resolver would have nothing to ask the node, and §6 forbids reversing an " +
			"unresolved reservation")
	}
	// §5: reconciliation freezes outbound payments, and Reserve is where every
	// outbound payment passes (§3's Spender seam). Checking here rather than in
	// each caller is what makes the freeze impossible to route around.
	if deficit, frozen, err := w.Shortfall(ctx); err != nil {
		return 0, err
	} else if frozen {
		return 0, fmt.Errorf("%w: the wallet authorises %d msat more than the node can send (%s)",
			ErrSpendingFrozen, deficit.ShortfallMsat, deficit.Cause)
	}
	// The SECOND freeze reason, and it is here for the same reason as the first
	// (u0u). §6 says pending payments must be resolved before new ones are
	// accepted; that used to be an ORDERING in cmd/brollyzapper — the resolver
	// ran above the background loops — which the HTTP listener already outran,
	// and which d24.3 could have routed around by starting NWC anywhere else. A
	// state the wallet reads is a thing no caller can get in front of.
	//
	// Older than UnresolvedCutoff, which is the later of this process's start
	// and UnresolvedAfter ago: a payment being made right now is reserved and
	// unresolved by definition, and counting it would make every payment freeze
	// against itself. See store.PendingPaymentsBefore and UnresolvedCutoff.
	//
	// It clears itself. The recon loop re-runs resolution on every tick and on
	// demand, so a node that was down at boot lifts this within one cycle of
	// coming back — no operator action, no restart (§5's rule for the other
	// freeze, and the same one here).
	//
	// BOTH CLASSES ARE COVERED SINCE `l3l`. A payment THIS process dispatched
	// whose send errored used to be excluded by a start-based cutoff, so it
	// neither held spending nor was resolved until the next start. The rolling
	// half of the cutoff catches it within UnresolvedAfter, on the recon loop,
	// with no restart — which is what makes §6's "resolved before new ones are
	// accepted" and this package's "the recon loop retries until the node
	// answers" true of every pending row rather than most of them.
	if held, err := w.store.HasUnresolvedPaymentsBefore(ctx, w.UnresolvedCutoff()); err != nil {
		return 0, err
	} else if held {
		return 0, fmt.Errorf("%w; they are being resolved against the node, and this usually "+
			"clears itself once it answers — a payment the log names as dispatched with no "+
			"record at the node is the exception, and does not", ErrPaymentsUnresolved)
	}
	id, err := w.store.ReserveSpend(ctx, store.SpendReservation{
		AmountMsat: amountMsat, MaxFeeMsat: maxFeeMsat, PaymentHash: paymentHash,
		Ref: req.Ref, Description: req.Description, Metadata: req.Metadata,
		DescriptionHash: req.DescriptionHash, NWCConnectionID: req.NWCConnectionID,
	}, w.now())
	if err != nil {
		return 0, err
	}
	return ReservationID(id), nil
}

// MarkDispatched records that a reservation's payment is about to be handed to
// the node (t4t).
//
// On the WALLET rather than reached from the store directly, for the reason the
// arch rule exists: this package is the only one that touches a reservation's
// row, and a second writer would be a second idea of when a payment counts as
// sent. It writes no balance entry and moves no money — it records a fact about
// the payment the reservation is for.
func (w *localSpender) MarkDispatched(ctx context.Context, id ReservationID) error {
	return w.store.MarkSpendDispatched(ctx, int64(id), w.now())
}

// ClearDispatched takes the marker back off a payment that never left (t4t).
//
// Licensed by lnd.ErrNotSent alone — the two failures where the stream never
// carried the request. It is the difference between a reservation the next
// resolver pass tidies away and one frozen for ever, which is what the marker
// costs if it is allowed to outlive a send that did not happen.
func (w *localSpender) ClearDispatched(ctx context.Context, id ReservationID) error {
	return w.store.ClearSpendDispatched(ctx, int64(id))
}

// Settle closes a reservation that paid, refunding the part of the fee reserve
// the route did not use.
//
// Named Settle because §3's interface is; the inbound counterpart is
// store.CreditSettledInvoice, deliberately named for the money rather than the
// invoice so the two cannot be confused (d46.6).
func (w *localSpender) Settle(ctx context.Context, id ReservationID, actualFeeMsat int64,
	preimage secret.String) error {
	if actualFeeMsat < 0 {
		return fmt.Errorf("wallet: cannot settle with a negative fee of %d msat", actualFeeMsat)
	}
	// The preimage rides through as secret.String and is never logged here or
	// anywhere on this path (d24.16, §12). An EMPTY one is allowed and leaves
	// the column as it was: a resolver settling a payment the node reported
	// without one must still close the reservation, and a settle that refused
	// would leave the ceiling debited for ever over a missing proof.
	excessMsat, err := w.store.SettleSpend(ctx, int64(id), actualFeeMsat, preimage, w.now())
	if err != nil || excessMsat == 0 {
		return err
	}
	// §12 for the adjustment the app made to ITSELF (`hdu`). The ledger already
	// has the amount; this says the app did it, and why, which is the half an
	// operator cannot reconstruct from a number on a history page.
	//
	// HERE rather than at the caller, because this is the one door both the live
	// payment path and the startup resolver pass through — two audit sites would
	// be two chances for one of them to stop writing. Best effort: the ledger is
	// already correct and committed, and failing the settle over a log row would
	// leave the reservation open, which is the defect this whole change exists
	// to end.
	if w.auditor != nil {
		if err := w.auditor.Record(ctx, slog.LevelWarn,
			"a payment's route cost more than was reserved; it settled at the reserved fee and "+
				"the excess was adjusted off the ceiling",
			logging.EventWalletAdjust,
			slog.Int64("reservation", int64(id)),
			slog.Int64("excess_msat", excessMsat),
			slog.Int64("actual_fee_msat", actualFeeMsat)); err != nil {
			w.log.Error("could not write the audit trail for a fee adjustment",
				"reservation", int64(id), "error", err.Error())
		}
	}
	return nil
}

// Unresolvable is every pending payment the resolver has given up on (`669`).
//
// On the WALLET rather than read from the store directly, for the reason the
// arch rule about the store's spend methods exists: which rows an operator may
// close is a wallet decision, and a second reader deciding for itself is how the
// page and the handler come to disagree about it.
func (w *localSpender) Unresolvable(ctx context.Context) ([]store.UnresolvablePayment, error) {
	return w.store.UnresolvablePayments(ctx)
}

// AssertOutcome is the operator saying what became of a payment this app could
// not find out about (`669`).
//
// §6: "only its operator can say whether this payment settled." This is the one
// control that lets them, and it can make the ledger lie in either direction —
// so it is fenced to rows the RESOLVER has already named, and the gate is
// re-checked inside the transaction that closes the row. See
// store.AssertPaymentOutcome.
//
// It is NOT Settle or Reverse with a different name. Those are the app booking
// what the NODE told it; this is the app booking what a PERSON told it, and §12's
// trail has to let a later reader tell those apart — which is why the caller
// audits it as an assertion.
func (w *localSpender) AssertOutcome(ctx context.Context, id ReservationID, settled bool) error {
	return w.store.AssertPaymentOutcome(ctx, int64(id), settled, w.now())
}

// MarkUnresolvable names a pending payment the resolver has stopped trying to
// resolve, which is what unlocks AssertOutcome for it.
func (w *localSpender) MarkUnresolvable(ctx context.Context, id ReservationID, reason string) error {
	return w.store.MarkPaymentUnresolvable(ctx, int64(id), reason)
}

// NoteResolveAttempt records a failed resolution pass and reports how many have
// failed in a row; ClearResolveAttempts forgets them after a success.
func (w *localSpender) NoteResolveAttempt(ctx context.Context, id ReservationID) (int, error) {
	return w.store.NoteResolveAttempt(ctx, int64(id))
}

func (w *localSpender) ClearResolveAttempts(ctx context.Context, id ReservationID) error {
	return w.store.ClearResolveAttempts(ctx, int64(id))
}

// Reverse closes a reservation that failed, returning it in full. A failed
// payment consumes no budget.
func (w *localSpender) Reverse(ctx context.Context, id ReservationID) error {
	return w.store.ReverseSpend(ctx, int64(id), w.now())
}

// Allocate raises the ceiling. Nothing moves on Lightning: allocation is a
// spending authorisation, not a transfer (§5), and the admin UI must say so.
func (w *localSpender) Allocate(ctx context.Context, amountMsat int64, note string) error {
	if err := requirePositive("allocate", amountMsat); err != nil {
		return err
	}
	return w.store.AdjustBalance(ctx, store.KindAllocation, store.ReasonAllocate, amountMsat, note, w.now())
}

// Deallocate lowers the ceiling. It cannot take the balance below zero.
func (w *localSpender) Deallocate(ctx context.Context, amountMsat int64, note string) error {
	if err := requirePositive("deallocate", amountMsat); err != nil {
		return err
	}
	return w.store.AdjustBalance(ctx, store.KindDeallocation, store.ReasonDeallocate, -amountMsat, note, w.now())
}

// Adjust records a correction as a new signed entry with a note. §5 invariant
// 3: balance_entries is append-only, so a correction is never an edit.
func (w *localSpender) Adjust(ctx context.Context, deltaMsat int64, note string) error {
	if deltaMsat == 0 {
		return fmt.Errorf("wallet: an adjustment of zero records nothing")
	}
	if note == "" {
		return fmt.Errorf("wallet: an adjustment needs a note saying why")
	}
	return w.store.AdjustBalance(ctx, store.KindAdjustment, store.ReasonAdjust, deltaMsat, note, w.now())
}

// CreditInvoice records a settled inbound invoice and, unless the operator has
// turned crediting off, raises the ceiling by what arrived (spec §5).
//
// It reports whether this call was the one that credited: a settlement LND
// re-delivers after a restart is a no-op, not a second credit.
//
// settledAt is the NODE's settle time, taken from the invoice the stream
// delivered — not this process's clock (o34.21). §7 makes the zap receipt's
// created_at that time, and the two are only the same while the server happens
// to be running at the moment of settlement. When it is not — a restart, and the
// settle_index resume path delivering afterwards — the handler's clock is late
// by exactly the outage, and the receipt then says the zap happened when we
// noticed rather than when it was paid. Measured on regtest: 60 seconds.
//
// A zero settledAt falls back to the clock. A settled invoice always carries a
// settle time, so a zero means the node said something unexpected; stamping
// 1970 into a public event would look deliberate to every client that rendered
// it.
func (w *localSpender) CreditInvoice(ctx context.Context, paymentHash, preimage string, amountPaidMsat int64, settledAt time.Time) (bool, error) {
	credit, err := w.CreditReceived(ctx)
	if err != nil {
		return false, err
	}
	if settledAt.IsZero() {
		settledAt = w.now()
	}
	return w.store.CreditSettledInvoice(ctx, paymentHash, preimage, amountPaidMsat, settledAt, credit)
}

// CreditReceived reports whether incoming payments raise the ceiling. Default
// true: the wallet you zap out of is the wallet zaps land in (§5).
func (w *localSpender) CreditReceived(ctx context.Context) (bool, error) {
	raw, ok, err := w.store.Setting(ctx, SettingCreditReceived)
	if err != nil {
		return false, err
	}
	if !ok {
		return true, nil
	}
	credit, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("wallet: %s is %q, which is not a boolean: %w", SettingCreditReceived, raw, err)
	}
	return credit, nil
}

// SetCreditReceived turns crediting of incoming payments on or off.
func (w *localSpender) SetCreditReceived(ctx context.Context, credit bool) error {
	return w.store.SetSetting(ctx, SettingCreditReceived, strconv.FormatBool(credit))
}

// requirePositive rejects the amounts that would record nothing or record
// backwards, with a wallet-level message rather than an inscrutable constraint
// failure from sqlite.
func requirePositive(verb string, amountMsat int64) error {
	if amountMsat <= 0 {
		return fmt.Errorf("wallet: cannot %s %d msat", verb, amountMsat)
	}
	return nil
}
