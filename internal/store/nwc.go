package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// The NWC tables have existed since migration 0001; §8 describes what goes in
// them. This file is the first code to use them.

// NWCConnection is one wallet-app pairing (§8).
//
// The two secrets are secret.String end to end: §11 lists a connection's
// service_privkey and client_secret on the never-log list, and §12 requires the
// types themselves to refuse to serialise. They are stored in plaintext for the
// same reason §4 gives about the nostr identity — the service must sign with
// one and re-display the other — and the type is what stops that becoming a log
// line.
type NWCConnection struct {
	ID   int64
	Name string
	// ServicePrivkey is this connection's OWN key. NIP-47's privacy guidance:
	// a shared service key links all of the operator's apps together on the
	// relay, so every connection gets its own.
	ServicePrivkey secret.String
	ServicePubkey  string
	ClientPubkey   string
	// ClientSecret is kept so the operator can re-display the pairing URI.
	ClientSecret secret.String
	// Relays are the pairing's OWN relays, in the order its URI named them
	// (d24.18). A list rather than one, because a pairing pinned to a single
	// relay is down for as long as that relay is — measured rather than
	// supposed: the 0.1.10 trip watched one refuse 8 of 20 upgrades while two
	// others took every one.
	//
	// NEVER default_relays and never a setting. §8's argument is that the
	// unencrypted kind 13194 info event must not be announced next to the
	// operator's own zap receipts; what keeps that true is that these come from
	// the connection row and from nowhere else.
	Relays []string
	// Permissions are §8's permission GROUPS, not raw method names.
	Permissions []string

	// BudgetMsat is NIL for unlimited, which is §4's own reading of the NULL
	// column — and "unlimited" still means bounded by the wallet ceiling, which
	// is a different check at a different layer (§8 step 7). A pointer rather
	// than a zero-means-unlimited int64, because zero is a budget an operator
	// might genuinely set and it means the opposite.
	BudgetMsat *int64
	// BudgetPeriod is never | daily | weekly | monthly (§4).
	BudgetPeriod string
	// BudgetUsedMsat is amount + max_fee per reservation, corrected to actuals
	// on settle and returned in full on failure (§8).
	BudgetUsedMsat int64
	// BudgetRenewsAt is when the window rolls. Zero when it never does.
	BudgetRenewsAt time.Time
	// MaxPaymentMsat caps a SINGLE payment, and is separate from the budget on
	// purpose: a monthly budget with no per-payment cap lets one request spend
	// the month (§8 step 4). Nil means no cap.
	MaxPaymentMsat *int64

	CreatedAt  time.Time
	LastUsedAt time.Time
	Revoked    bool

	// LastRefusalCode and LastRefusalAt are the last NIP-47 error this pairing
	// was answered with, and when (d24.21, ruling B). Empty and zero mean it has
	// never been refused — which the Connections page has to be able to tell
	// apart from a refusal at the epoch, and is why the column is nullable.
	//
	// State, not a log: see migration 0011 for why there is one of these rather
	// than a per-connection history, and why it is not an audit row.
	//
	// The MESSAGE is carried as well as the code because one code has six
	// meanings — RESTRICTED is "sending is off" far more often than it is "this
	// pairing may not", and only the message says which.
	LastRefusalCode    string
	LastRefusalMessage string
	LastRefusalAt      time.Time
	// PanicCount is how many of this pairing's requests have crashed the handler
	// since it was last resumed, and PausedReason/PausedAt are set when the app
	// stopped serving it for that reason (`xmc` Fix C).
	//
	// PAUSED IS NOT REVOKED. Revoked means the operator ended the pairing;
	// paused means the app defended itself from a client whose requests it could
	// not survive, and the operator can undo it from the Connections page
	// without re-pairing a phone. See migration 0014.
	PanicCount   int
	PausedReason string
	PausedAt     time.Time
}

// Paused reports whether the app has stopped serving this pairing.
func (c NWCConnection) Paused() bool { return c.PausedReason != "" }

// The limits a connection granted the pay group gets when the operator names
// none (plk).
//
// DELIBERATELY the guard's own numbers — config.DefaultMaxSpendMsat and
// config.DefaultMaxPaymentMsat — so the system carries ONE set: a stock
// connection may spend up to what the guard would allow it anyway, and raising
// or lowering is an operator's deliberate act. Duplicated as literals rather
// than imported because internal/store must not depend on internal/config; the
// test below pins them to each other, which is what keeps the two honest.
//
// EXPIRY CONDITION: revisit when the guard's caps become operator-configurable
// (§10). The point of matching is that a stock connection cannot exceed the
// guard, and a configurable guard cap breaks that silently unless these move
// with it.
//
// Why defaults at all: both columns are nullable and nil means unlimited, so a
// connection created with `pay` and nothing else could spend the entire wallet
// ceiling in one request. §2's posture is that a stock anything is bounded, and
// the ceiling is the backstop rather than the only limit. nil stays expressible
// — see LimitPolicy — it must simply never be the default.
const (
	DefaultConnectionBudgetMsat     int64 = 100_000_000 // 100k sat, daily
	DefaultConnectionMaxPaymentMsat int64 = 25_000_000  // 25k sat per payment
)

// CanPay reports whether this connection holds §8's pay group.
//
// On the type because three callers asked it — the store's own default-limits
// pass, the connections page, and that page's audit line — and three copies of
// slices.Contains(perms, PermissionPay) is three places for "which group means
// spending" to drift.
func (c NWCConnection) CanPay() bool { return slices.Contains(c.Permissions, PermissionPay) }

// The budget periods §4 names.
const (
	BudgetNever   = "never"
	BudgetDaily   = "daily"
	BudgetWeekly  = "weekly"
	BudgetMonthly = "monthly"
)

// LogValue is §12's worked example, which names this type by name.
//
// The two secrets are secret.String, so slog.Any on a connection would already
// redact them — this is the second half of that rule rather than a substitute
// for it: §12 asks for identifiers TRUNCATED rather than dropped, and without
// this a debugging `slog.Any("conn", conn)` emits both pubkeys and the relay in
// full. A connection's service pubkey is how an observer links the operator's
// apps to each other; it does not belong in a log line at full length.
func (c NWCConnection) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int64("id", c.ID),
		slog.String("name", c.Name),
		slog.String("client_pubkey", shortID(c.ClientPubkey)),
		slog.String("service_pubkey", shortID(c.ServicePubkey)),
	) // service_privkey, client_secret and relay are structurally absent
}

// shortID is §12's `short`: enough of an identifier to follow one connection
// through a log, not enough to be the identifier.
func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "…"
}

// ActiveNWCConnections is every connection the service should serve.
//
// Revoked ones are excluded here rather than filtered by the caller: a revoked
// connection that still answered would be a revocation that did nothing, and
// leaving that to a caller's `if` is how it comes back.
//
// PAUSED ones are excluded for the same reason and are a different fact (`xmc`
// Fix C): the app stopped serving this pairing because its requests kept
// crashing the handler, and a paused connection that still answered would be a
// quarantine that did nothing. The operator's page reads AllNWCConnections, so
// they still see it — paused, with the reason, and with a way back.
func (s *Store) ActiveNWCConnections(ctx context.Context) ([]NWCConnection, error) {
	rows, err := s.db.QueryContext(ctx, nwcConnectionColumns+
		` FROM nwc_connections WHERE revoked = 0 AND paused_reason = '' ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("reading NWC connections: %w", err)
	}
	defer rows.Close()
	var out []NWCConnection
	for rows.Next() {
		conn, err := scanNWCConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, conn)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading NWC connections: %w", err)
	}
	return out, nil
}

// NWCConnection reads one connection by id.
func (s *Store) NWCConnection(ctx context.Context, id int64) (NWCConnection, bool, error) {
	rows, err := s.db.QueryContext(ctx, nwcConnectionColumns+` FROM nwc_connections WHERE id = ?`, id)
	if err != nil {
		return NWCConnection{}, false, fmt.Errorf("reading NWC connection %d: %w", id, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return NWCConnection{}, false, rows.Err()
	}
	conn, err := scanNWCConnection(rows)
	if err != nil {
		return NWCConnection{}, false, err
	}
	return conn, true, rows.Err()
}

// withDefaultLimits bounds a new connection that may pay (plk).
//
// Applied HERE rather than in the UI, and that is the point: the page is one
// caller, the regtest stack is another, and d24.9's field trip will be a third.
// A default that lives in a form is a default that the next caller does not get.
//
// Only for connections that can actually spend. A budget on a connection without
// the pay group is a number an operator has to reason about for no reason.
func withDefaultLimits(conn NWCConnection, limits LimitPolicy) NWCConnection {
	if limits == NoLimits || !conn.CanPay() {
		return conn
	}
	if conn.BudgetMsat == nil {
		budget := DefaultConnectionBudgetMsat
		conn.BudgetMsat = &budget
		if conn.BudgetPeriod == "" {
			conn.BudgetPeriod = BudgetDaily
		}
	}
	if conn.BudgetPeriod != "" && conn.BudgetPeriod != BudgetNever && conn.BudgetRenewsAt.IsZero() {
		// A period with no renewal point counts up once and then refuses for
		// ever until something rolls it (d24.4 review). The roll can establish
		// one now, but starting the window at creation is the honest reading of
		// "daily from when you made it".
		conn.BudgetRenewsAt = nextWindow(conn.CreatedAt, conn.BudgetPeriod)
	}
	if conn.MaxPaymentMsat == nil {
		cap := DefaultConnectionMaxPaymentMsat
		conn.MaxPaymentMsat = &cap
	}
	return conn
}

// nextWindow is when a budget period first rolls.
func nextWindow(from time.Time, period string) time.Time {
	switch period {
	case BudgetDaily:
		return from.AddDate(0, 0, 1)
	case BudgetWeekly:
		return from.AddDate(0, 0, 7)
	case BudgetMonthly:
		return from.AddDate(0, 1, 0)
	default:
		return time.Time{}
	}
}

// SetNWCConnectionLimits rewrites what a connection is allowed to do.
//
// Permissions and limits together, because they are one decision an operator
// makes on one screen (§9's connections page, d24.5) — and because a budget
// raised in a separate call from the group that can use it is a window in which
// the two disagree.
//
// It deliberately does NOT touch budget_used_msat. What a connection has already
// spent is a fact about the past; an operator lowering a budget is changing what
// happens next, not forgiving what happened.
//
// It writes to a LIVE connection only — `revoked = 0`. Editing the limits of a
// revoked pairing would be an operator changing what a connection that no longer
// exists is allowed to do, and the bool would then say "yes, changed" about
// nothing an operator can see.
//
// That guard is a SECOND LINE OF DEFENCE, not the mechanism, and saying so is
// better than implying otherwise: UpdateNWCConnectionLimits reads the row and
// refuses a revoked one before reaching here, which is what the handler's test
// covers. What this catches is the race the read cannot — a revoke landing
// between the read and this UPDATE — and it costs a clause.
func (s *Store) SetNWCConnectionLimits(ctx context.Context, id int64, permissions []string,
	budgetMsat *int64, period string, renewsAt time.Time, maxPaymentMsat *int64) (bool, error) {
	encoded, err := encodePermissions(permissions)
	if err != nil {
		return false, err
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE nwc_connections
		    SET permissions = ?, budget_msat = ?, budget_period = ?, budget_renews_at = ?,
		        max_payment_msat = ?
		  WHERE id = ? AND revoked = 0`,
		encoded, nullInt64Ptr(budgetMsat), nullString(period), nullUnix(renewsAt),
		nullInt64Ptr(maxPaymentMsat), id)
	if err != nil {
		return false, fmt.Errorf("updating NWC connection %d's limits: %w", id, err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("updating NWC connection %d's limits: %w", id, err)
	}
	return changed > 0, nil
}

// UpdateNWCConnectionLimits is §9's update control (d24.17): it applies plk's
// defaults and keeps the existing budget WINDOW, then writes.
//
// Two things this does that a raw SetNWCConnectionLimits cannot, and both are
// the reason it exists here rather than in the handler:
//
//   - plk's rules still apply on an EDIT. A connection granted `pay` in an
//     update, with the limit fields left blank, is bounded exactly as one
//     created that way is — the defaults live in the store precisely so the next
//     caller gets them.
//   - THE WINDOW DOES NOT RESET. A budget that is changed keeps its existing
//     budget_renews_at, so an operator lowering a limit does not accidentally
//     hand the connection a fresh period's worth of spending — which would make
//     the cheapest safety action briefly INCREASE what a worried operator's app
//     can spend. A window is only computed when there was none.
//
// It returns the connection AS STORED, which is not the same as what the caller
// posted: withDefaultLimits may have filled blank limits in. The audit row must
// state the stored values or §12's trail answers "what did this app's limit
// change to?" with the operator's blanks — recording 0, which everything else
// here reads as "no limit" (found by review).
func (s *Store) UpdateNWCConnectionLimits(ctx context.Context, id int64, permissions []string,
	budgetMsat, maxPaymentMsat *int64, limits LimitPolicy, now time.Time) (NWCConnection, bool, error) {
	current, found, err := s.NWCConnection(ctx, id)
	if err != nil {
		return NWCConnection{}, false, err
	}
	if !found || current.Revoked {
		return NWCConnection{}, false, nil
	}
	updated := withDefaultLimits(NWCConnection{
		Permissions: permissions, BudgetMsat: budgetMsat, MaxPaymentMsat: maxPaymentMsat,
	}, limits)

	period, renewsAt := "", time.Time{}
	if updated.BudgetMsat != nil {
		period = current.BudgetPeriod
		if period == "" {
			period = BudgetDaily
		}
		renewsAt = current.BudgetRenewsAt
		if renewsAt.IsZero() {
			renewsAt = nextWindow(now, period)
		}
	}
	changed, err := s.SetNWCConnectionLimits(ctx, id, updated.Permissions,
		updated.BudgetMsat, period, renewsAt, updated.MaxPaymentMsat)
	if err != nil || !changed {
		return NWCConnection{}, changed, err
	}
	updated.ID, updated.BudgetPeriod, updated.BudgetRenewsAt = id, period, renewsAt
	return updated, true, nil
}

// NoteNWCPanic records that one of this pairing's requests crashed the handler,
// and reports how many have since it was last resumed (`xmc` Fix C).
//
// The count is what Fix C's threshold reads, and it is persistent for the reason
// migration 0014 gives: a per-process counter would be re-armed by the very
// restarts a crash loop produces.
func (s *Store) NoteNWCPanic(ctx context.Context, id int64) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx,
		`UPDATE nwc_connections SET panic_count = panic_count + 1
		  WHERE id = ? AND revoked = 0
		  RETURNING panic_count`, id).Scan(&count); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Revoked while the request was in flight. Nothing to count, and
			// nothing to pause.
			return 0, nil
		}
		return 0, fmt.Errorf("recording a panic for NWC connection %d: %w", id, err)
	}
	return count, nil
}

// PauseNWCConnection stops the app serving a pairing, with the reason the
// operator will read (`xmc` Fix C).
//
// NOT `revoked`, which is the operator's own kill switch. Idempotent and
// first-reason-wins, like MarkPaymentUnresolvable: a later pass restating it
// would replace the diagnosis that explains the row.
func (s *Store) PauseNWCConnection(ctx context.Context, id int64, reason string, at time.Time) error {
	// The reason IS the flag — paused_reason != '' is what every reader tests —
	// so an empty one would write a pause that reads as "never paused" and
	// return nil. One caller passes a constant today; the type is what stops the
	// second one being silent.
	if strings.TrimSpace(reason) == "" {
		return errors.New("store: pausing a connection needs a reason; it is what the page " +
			"shows and what marks the row as paused")
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE nwc_connections SET paused_reason = ?, paused_at = ?
		  WHERE id = ? AND revoked = 0 AND paused_reason = ''`,
		reason, at.Unix(), id); err != nil {
		return fmt.Errorf("pausing NWC connection %d: %w", id, err)
	}
	return nil
}

// ResumeNWCConnection is the operator saying the client is fixed: the pairing is
// served again and its panic count starts over.
//
// The count is cleared HERE and nowhere else. That is what makes it "since the
// last resume" rather than "for ever", and it is the moment a person asserts
// something changed — see migration 0014 for why it is not cleared per
// successful request.
// It reports whether anything CHANGED, like RevokeNWCConnection: a resume of a
// pairing that was never paused is not an event, and auditing one would put a
// row in §12's trail for something that did not happen.
func (s *Store) ResumeNWCConnection(ctx context.Context, id int64) (bool, error) {
	result, err := s.db.ExecContext(ctx,
		`UPDATE nwc_connections SET paused_reason = '', paused_at = NULL, panic_count = 0
		  WHERE id = ? AND revoked = 0 AND paused_reason != ''`, id)
	if err != nil {
		return false, fmt.Errorf("resuming NWC connection %d: %w", id, err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("resuming NWC connection %d: %w", id, err)
	}
	return changed > 0, nil
}

// AllNWCConnections is every connection including revoked ones, for the page
// that lists them.
//
// Revoked rows are INCLUDED here and excluded by ActiveNWCConnections, and the
// difference is who is asking: the service must not serve a revoked connection,
// while an operator looking at the page needs to see that the one they revoked
// is gone rather than wondering whether the click worked.
func (s *Store) AllNWCConnections(ctx context.Context) ([]NWCConnection, error) {
	rows, err := s.db.QueryContext(ctx, nwcConnectionColumns+
		` FROM nwc_connections ORDER BY revoked, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("reading NWC connections: %w", err)
	}
	defer rows.Close()
	var out []NWCConnection
	for rows.Next() {
		conn, err := scanNWCConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, conn)
	}
	return out, rows.Err()
}

// CountPayingNWCConnections is how many live pairings may spend.
//
// The Sending page says what disabling will do, and "three connections will stop
// being able to pay" is the sentence that needs this number.
func (s *Store) CountPayingNWCConnections(ctx context.Context) (int, error) {
	// ActiveNWCConnections rather than AllNWCConnections filtered by hand: the
	// service reloads from the active set, so counting from the same set is what
	// makes this number the one the operator is actually about to affect.
	rows, err := s.ActiveNWCConnections(ctx)
	if err != nil {
		return 0, err
	}
	var n int
	for _, row := range rows {
		if row.CanPay() {
			n++
		}
	}
	return n, nil
}

// RevokeNWCConnection stops a connection being served, permanently.
//
// A flag rather than a DELETE, and §12 is why: the audit trail records that a
// connection was revoked, and a row that vanished would leave that event
// pointing at nothing. The pairing URI it issued also stops working, which is
// the operator's actual intent — a revoked connection's client can still reach
// the relay and will simply never be answered.
//
// The bool reports whether a row actually changed. An UPDATE that matched
// nothing is not an error in SQL and it is not one here either — but it is not a
// revocation, and the caller must not say it was: the audit trail is §12's
// durable answer to "what happened to this connection", and a row claiming the
// revocation of an id that never existed is a false entry in it. Found by
// review, which also found the wave's own regtest leaning on the old behaviour.
func (s *Store) RevokeNWCConnection(ctx context.Context, id int64) (bool, error) {
	result, err := s.db.ExecContext(ctx,
		`UPDATE nwc_connections SET revoked = 1 WHERE id = ? AND revoked = 0`, id)
	if err != nil {
		return false, fmt.Errorf("revoking NWC connection %d: %w", id, err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("revoking NWC connection %d: %w", id, err)
	}
	return changed > 0, nil
}

// ReserveNWCBudget rolls an expired window and takes amountMsat, atomically,
// reporting whether it fitted (§8 steps 5 and 6).
//
// ONE STATEMENT, and that is the whole point (test-spec E6). §8 reads as two
// rules — reset an expired window, then refuse if the amount does not fit — and
// implementing them as a read followed by an update leaves a gap in which two
// requests both see room that only one of them has. SQLite serialises writers,
// so a guarded UPDATE decides both questions under the write lock; the loser
// changes nothing and is told so by its row count.
//
// The roll is inside the guard as well as inside the SET, which is why the CASE
// appears twice: a request arriving after the window expired must be measured
// against a counter of zero, not against the previous window's spend. Writing it
// once and referring to the alias is not available here — SQLite does not let an
// UPDATE's WHERE clause see the columns it is setting.
//
// amountMsat is amount + max_fee. §8 reserves the fee too, because a payment
// whose route costs the full reserve must not be able to exceed the budget the
// operator set.
func (s *Store) ReserveNWCBudget(ctx context.Context, id, amountMsat int64,
	now, nextRenewal time.Time) (BudgetOutcome, error) {
	// Three questions in one expression, and each is load-bearing.
	//
	// `? = 1` is whether this budget rolls AT ALL: a period of `never` is a
	// LIFETIME budget, and a counter that reset would make it no budget.
	//
	// `budget_renews_at IS NULL` is a window that was never established.
	// CreateNWCConnection writes NULL for a zero renewal point, so without this
	// a connection with a period and no point counts up once and then refuses
	// for ever — and SetNWCConnectionLimits deliberately does not touch
	// budget_used_msat, so no UI could clear it (d24.4 review).
	//
	// `<= ?` is the ordinary case: the window has passed.
	rolls := 0
	if !nextRenewal.IsZero() {
		rolls = 1
	}
	const rolled = `CASE WHEN ? = 1 AND (budget_renews_at IS NULL OR budget_renews_at <= ?)
	                     THEN 0 ELSE budget_used_msat END`
	res, err := s.db.ExecContext(ctx,
		`UPDATE nwc_connections
		    SET budget_used_msat = `+rolled+` + ?,
		        budget_renews_at = CASE WHEN ? = 1 AND (budget_renews_at IS NULL OR budget_renews_at <= ?)
		                                THEN ? ELSE budget_renews_at END
		  WHERE id = ?
		    -- A SECOND LINE OF DEFENCE since uhg, not the mechanism. The
		    -- service reloads on demand and closes a revoked connection's
		    -- subscription, so a revoked connection is not being served at all.
		    -- This stays because it costs nothing and covers the window between
		    -- the revoke and the reload — and because a guard that only ever
		    -- agrees is the cheapest kind to keep.
		    AND revoked = 0
		    AND (budget_msat IS NULL OR `+rolled+` + ? <= budget_msat)`,
		rolls, now.Unix(), amountMsat,
		rolls, now.Unix(), nullUnix(nextRenewal),
		id,
		rolls, now.Unix(), amountMsat)
	if err != nil {
		return BudgetRefused, fmt.Errorf("reserving %d msat of NWC connection %d's budget: %w",
			amountMsat, id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return BudgetRefused, fmt.Errorf("reserving NWC budget: %w", err)
	}
	if affected == 1 {
		return BudgetTaken, nil
	}
	// Nothing changed, and the caller has to know WHICH nothing: the guard
	// covers the budget and `revoked = 0` together, so an over-budget payment
	// and a revoked connection are the same row count and very different
	// sentences. Read after the fact rather than checked before it — the guard
	// is what enforces, and this only reports.
	conn, found, err := s.NWCConnection(ctx, id)
	switch {
	case err != nil:
		return BudgetRefused, err
	case !found || conn.Revoked:
		return BudgetConnectionGone, nil
	default:
		return BudgetRefused, nil
	}
}

// BudgetOutcome is why a budget reservation did or did not happen.
type BudgetOutcome int

const (
	// BudgetRefused means the payment would exceed the budget for this window.
	BudgetRefused BudgetOutcome = iota
	// BudgetTaken means the amount was reserved.
	BudgetTaken
	// BudgetConnectionGone means the connection is revoked or no longer exists.
	//
	// Its own outcome because the client is owed a different answer, and because
	// this is the ONE capability that takes effect without a restart: the
	// permissions the ladder reads are a startup copy (uhg), but the guarded
	// UPDATE reads `revoked` from the row every time.
	BudgetConnectionGone
)

// AdjustNWCBudget moves what a connection has spent by a SIGNED delta.
//
// Both directions, because §8's correction goes both ways: a failed payment
// returns everything it took (§8: a failed payment consumes no budget), a settle
// returns the part of the fee reserve the route did not use — and a route that
// cost MORE than the reserve has to be charged for. That last case is rare
// enough to be easy to leave out, and leaving it out under-counts a connection's
// spending, which is the direction that matters.
//
// CLAMPED AT ZERO, and not as defensive habit: a return can outlive its window.
// Reserve, the window rolls to zero, then the payment fails and gives back what
// it took — subtracting from zero would leave a NEGATIVE used figure, which is a
// connection carrying MORE than its budget for the rest of the window. A refund
// must never become spending authority.
//
// Deliberately NOT guarded by the budget: this is a correction to spending that
// already happened, and refusing it because the corrected figure exceeds the
// budget would leave the ledger describing a payment that was not made.
func (s *Store) AdjustNWCBudget(ctx context.Context, id, deltaMsat int64) error {
	if deltaMsat == 0 {
		return nil
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE nwc_connections
		    SET budget_used_msat = MAX(0, budget_used_msat + ?)
		  WHERE id = ?`, deltaMsat, id); err != nil {
		return fmt.Errorf("adjusting NWC connection %d's budget by %d msat: %w",
			id, deltaMsat, err)
	}
	return nil
}

// LimitPolicy says what a caller means by leaving a limit blank (plk).
//
// nil has to mean two different things at creation time — "the operator did not
// say", which gets the defaults, and "the operator removed this limit", which is
// a legitimate choice and must survive — and neither the row nor the columns can
// carry that difference, because what is STORED is the nil either way.
//
// An argument rather than a field on NWCConnection, which is what the first
// version used: a field that scanNWCConnection never sets reads false on every
// row that comes back out of the database, so a round-tripped connection quietly
// disagrees with the one that was written. Review caught it. This way the
// question is asked exactly where it can be answered — at the call — and cannot
// be asked anywhere it cannot.
type LimitPolicy int

const (
	// DefaultLimits fills blank limits on a paying connection with plk's
	// defaults. The zero value, so a caller that has not thought about it gets
	// the bounded answer.
	DefaultLimits LimitPolicy = iota
	// NoLimits leaves blank limits blank — the operator's explicit act.
	NoLimits
)

// CreateNWCConnection stores a new pairing and returns it with its id.
//
// The admin UI is d24.5; this is the store method that page will use, and the
// one tests and the regtest arc seed through in the meantime.
func (s *Store) CreateNWCConnection(ctx context.Context, conn NWCConnection,
	limits LimitPolicy) (NWCConnection, error) {
	conn = withDefaultLimits(conn, limits)
	permissions, err := encodePermissions(conn.Permissions)
	if err != nil {
		return NWCConnection{}, err
	}
	relays, err := encodeRelays(conn.Relays)
	if err != nil {
		return NWCConnection{}, err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO nwc_connections
		   (name, service_privkey, service_pubkey, client_pubkey, client_secret, relays,
		    permissions, budget_msat, budget_period, budget_renews_at, max_payment_msat,
		    created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		conn.Name, conn.ServicePrivkey.Reveal(), conn.ServicePubkey, conn.ClientPubkey,
		conn.ClientSecret.Reveal(), relays, permissions,
		nullInt64Ptr(conn.BudgetMsat), nullString(conn.BudgetPeriod),
		nullUnix(conn.BudgetRenewsAt), nullInt64Ptr(conn.MaxPaymentMsat),
		conn.CreatedAt.Unix())
	if err != nil {
		return NWCConnection{}, fmt.Errorf("creating the NWC connection %q: %w", conn.Name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return NWCConnection{}, fmt.Errorf("creating the NWC connection %q: %w", conn.Name, err)
	}
	conn.ID = id
	return conn, nil
}

// RecordNWCRefusal remembers the last thing this pairing was refused (d24.21).
//
// An UPDATE that matches nothing is not an error: this runs on a connection's
// worker goroutine, after the answer has already gone out, and a row revoked and
// deleted underneath it is a race the operator must not be shown. The refusal
// itself is already logged; what would be lost is a field on a row that no
// longer exists.
func (s *Store) RecordNWCRefusal(ctx context.Context, id int64, code, message string,
	at time.Time) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE nwc_connections
		    SET last_refusal_code = ?, last_refusal_message = ?, last_refusal_at = ?
		  WHERE id = ?`,
		code, message, at.Unix(), id); err != nil {
		return fmt.Errorf("recording a refusal for NWC connection %d: %w", id, err)
	}
	return nil
}

// TouchNWCConnection records that a connection was used, so the operator can see
// which pairings are live and which are forgotten apps.
func (s *Store) TouchNWCConnection(ctx context.Context, id int64, at time.Time) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE nwc_connections SET last_used_at = ? WHERE id = ?`, at.Unix(), id); err != nil {
		return fmt.Errorf("touching NWC connection %d: %w", id, err)
	}
	return nil
}

// NWCHandledResponse returns the response a request id was already answered
// with (§8's durable replay protection).
//
// The second return is whether it was found. A known id must return its CACHED
// response and execute nothing — the point being that a relay re-delivering a
// request the process handled seconds before it died must not run it twice.
func (s *Store) NWCHandledResponse(ctx context.Context, eventID string) (string, bool, error) {
	var response string
	err := s.db.QueryRowContext(ctx,
		`SELECT response_json FROM nwc_handled_requests WHERE event_id = ?`,
		eventID).Scan(&response)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reading the handled-request cache: %w", err)
	}
	return response, true, nil
}

// ClaimNWCRequest claims a request id BEFORE it is executed, and reports whether
// this caller won it (§8).
//
// Wave 23 looked the id up, executed, and wrote the row afterwards. That is safe
// against a redelivery which ARRIVES LATER and unsafe against one that overlaps:
// two deliveries both find nothing, both execute, and the second write is
// discarded by the ON CONFLICT. For make_invoice that is two invoices; for
// d24.4's pay_invoice it is two payments, which is precisely what the durable
// cache exists to prevent.
//
// So the lookup and the claim are one statement. The INSERT is the lock: SQLite
// decides the winner, the loser is handed whatever the winner stored, and
// nothing executes twice. A claim that FAILS is fatal to the request — a spend
// whose idempotency record did not land is a spend a redelivery makes again.
//
// The placeholder matters. A loser that arrives mid-flight is answered with it,
// so it says "already being processed" rather than nothing — and if the process
// dies between the claim and the completion, the row holds that answer for the
// retention window. That is the conservative direction: a payment is left to the
// resolver rather than made twice, and a lost make_invoice costs the client one
// new request.
//
// The stored response is PLAINTEXT and is re-encrypted on replay: the scheme is
// the client's choice per request (§8), so caching the ciphertext would answer a
// NIP-44 replay with a NIP-04 payload.
func (s *Store) ClaimNWCRequest(ctx context.Context, eventID string, connectionID int64,
	method, placeholderJSON string, at time.Time) (bool, string, time.Time, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO nwc_handled_requests (event_id, connection_id, method, response_json, handled_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(event_id) DO NOTHING`,
		eventID, connectionID, method, placeholderJSON, at.Unix())
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("claiming the NWC request %s: %w", eventID, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("claiming the NWC request %s: %w", eventID, err)
	}
	if affected == 1 {
		return true, "", at, nil
	}
	// Someone else holds it. What they stored is the answer this delivery gets —
	// their final response if they have finished, their placeholder if they have
	// not, and either way NOT a second execution.
	//
	// WHEN it was stored comes back too, and d24.18 is why: a request now arrives
	// on every relay a pairing names, so a losing delivery is usually a sibling
	// socket's copy from milliseconds ago rather than a client asking again. The
	// caller needs to tell those apart, and this timestamp is the only thing that
	// can. It is the CLAIM's time while the answer is in flight and the
	// COMPLETION's time afterwards — see CompleteNWCRequest, which moves it.
	existing, handledAt, err := s.nwcHandled(ctx, eventID)
	return false, existing, handledAt, err
}

// nwcHandled reads a cache row's response and when it was last written.
func (s *Store) nwcHandled(ctx context.Context, eventID string) (string, time.Time, error) {
	var (
		response  string
		handledAt int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT response_json, handled_at FROM nwc_handled_requests WHERE event_id = ?`,
		eventID).Scan(&response, &handledAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, nil
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("reading the NWC response for %s: %w", eventID, err)
	}
	return response, time.Unix(handledAt, 0).UTC(), nil
}

// CompleteNWCRequest replaces a claim's placeholder with the real response.
//
// Separate from the claim because the answer does not exist yet when the claim
// is made — that is the entire point of claiming first.
func (s *Store) CompleteNWCRequest(ctx context.Context, eventID, responseJSON string,
	at time.Time) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE nwc_handled_requests SET response_json = ?, handled_at = ? WHERE event_id = ?`,
		responseJSON, at.Unix(), eventID); err != nil {
		return fmt.Errorf("completing the NWC request %s: %w", eventID, err)
	}
	return nil
}

// PruneNWCHandled deletes cache rows handled before a cutoff. §8: 24 hours,
// pruned hourly.
func (s *Store) PruneNWCHandled(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM nwc_handled_requests WHERE handled_at < ?`, before.Unix())
	if err != nil {
		return 0, fmt.Errorf("pruning the handled-request cache: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("pruning the handled-request cache: %w", err)
	}
	return n, nil
}

const nwcConnectionColumns = `SELECT id, name, service_privkey, service_pubkey, client_pubkey,
	 client_secret, relays, permissions, budget_msat, COALESCE(budget_period, ''),
	 budget_used_msat, COALESCE(budget_renews_at, 0), max_payment_msat,
	 created_at, COALESCE(last_used_at, 0), revoked,
	 last_refusal_code, last_refusal_message, COALESCE(last_refusal_at, 0),
	 panic_count, paused_reason, COALESCE(paused_at, 0)`

// scanNWCConnection reads one row into the type §11 wants the secrets held in.
//
// Takes *sql.Rows rather than an interface both it and QueryRow satisfy: there
// is one caller. d24.5 adds the by-id lookup the admin UI needs, and widening
// this to `interface{ Scan(...any) error }` is a one-line change when a second
// caller actually exists.
func scanNWCConnection(row *sql.Rows) (NWCConnection, error) {
	var (
		conn                        NWCConnection
		privkey, clientSecret       string
		permissions, relays         string
		budgetMsat, maxPayment      sql.NullInt64
		budgetPeriod                string
		budgetUsed, budgetRenews    int64
		createdAt, lastUsedAt       int64
		revoked                     int
		refusalCode, refusalMessage string
		refusedAt                   int64
		panicCount                  int
		pausedReason                string
		pausedAt                    int64
	)
	if err := row.Scan(&conn.ID, &conn.Name, &privkey, &conn.ServicePubkey, &conn.ClientPubkey,
		&clientSecret, &relays, &permissions, &budgetMsat, &budgetPeriod, &budgetUsed,
		&budgetRenews, &maxPayment, &createdAt, &lastUsedAt, &revoked,
		&refusalCode, &refusalMessage, &refusedAt,
		&panicCount, &pausedReason, &pausedAt); err != nil {
		return NWCConnection{}, fmt.Errorf("reading an NWC connection: %w", err)
	}
	conn.PanicCount, conn.PausedReason = panicCount, pausedReason
	if pausedAt != 0 {
		conn.PausedAt = time.Unix(pausedAt, 0).UTC()
	}
	conn.LastRefusalCode, conn.LastRefusalMessage = refusalCode, refusalMessage
	if refusedAt != 0 {
		conn.LastRefusalAt = time.Unix(refusedAt, 0).UTC()
	}
	if budgetMsat.Valid {
		conn.BudgetMsat = &budgetMsat.Int64
	}
	if maxPayment.Valid {
		conn.MaxPaymentMsat = &maxPayment.Int64
	}
	conn.BudgetPeriod = budgetPeriod
	conn.BudgetUsedMsat = budgetUsed
	if budgetRenews != 0 {
		conn.BudgetRenewsAt = time.Unix(budgetRenews, 0).UTC()
	}
	conn.ServicePrivkey = secret.New(privkey)
	conn.ClientSecret = secret.New(clientSecret)
	pairing, err := decodeRelays(relays)
	if err != nil {
		return NWCConnection{}, err
	}
	conn.Relays = pairing
	conn.CreatedAt = time.Unix(createdAt, 0).UTC()
	if lastUsedAt != 0 {
		conn.LastUsedAt = time.Unix(lastUsedAt, 0).UTC()
	}
	conn.Revoked = revoked != 0
	groups, err := decodePermissions(permissions)
	if err != nil {
		return NWCConnection{}, err
	}
	conn.Permissions = groups
	return conn, nil
}

// Permission groups (§8). Groups rather than raw method names, because
// LNbits' grouping is markedly better UX than asking an operator to tick
// `multi_pay_invoice` — and because a group survives a method being added to it.
const (
	PermissionPay     = "pay"
	PermissionInvoice = "invoice"
	PermissionLookup  = "lookup"
	PermissionHistory = "history"
	PermissionBalance = "balance"
	PermissionInfo    = "info"
)

// DefaultPermissions is what a new connection gets: everything except `pay`.
//
// §8 notes the deviation from LNbits, which defaults `pay` ON. BrollyZapper
// defaults it OFF, consistent with §2 — a new connection cannot spend until that
// is granted deliberately.
func DefaultPermissions() []string {
	return []string{PermissionInvoice, PermissionLookup, PermissionHistory,
		PermissionBalance, PermissionInfo}
}

func encodePermissions(groups []string) (string, error) {
	if groups == nil {
		groups = []string{}
	}
	raw, err := json.Marshal(groups)
	if err != nil {
		return "", fmt.Errorf("encoding permission groups: %w", err)
	}
	return string(raw), nil
}

// encodeRelays and decodeRelays carry the pairing's relay list to and from
// sqlite, in the shape permissions already use: a JSON array in one TEXT column.
//
// A separate pair rather than a generic helper shared with permissions, because
// the error messages have to name which list failed. Two callers of one helper
// is how "decoding permission groups" comes to be the error an operator sees
// about a relay.
func encodeRelays(relays []string) (string, error) {
	if relays == nil {
		relays = []string{}
	}
	raw, err := json.Marshal(relays)
	if err != nil {
		return "", fmt.Errorf("encoding the connection's relays: %w", err)
	}
	return string(raw), nil
}

func decodeRelays(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var relays []string
	if err := json.Unmarshal([]byte(raw), &relays); err != nil {
		return nil, fmt.Errorf("decoding the connection's relays %q: %w", raw, err)
	}
	return relays, nil
}

func decodePermissions(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var groups []string
	if err := json.Unmarshal([]byte(raw), &groups); err != nil {
		return nil, fmt.Errorf("decoding permission groups %q: %w", raw, err)
	}
	return groups, nil
}
