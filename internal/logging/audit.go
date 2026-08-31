package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"
)

// Event is a security-relevant occurrence. §12: security is a dimension, not a
// level — every one of these is logged at whatever severity actually fits and
// carries an audit= attribute so an operator can filter on it.
type Event string

// The §12 vocabulary, in full. Nothing outside this list may be written to the
// trail; a typo becomes a failure rather than a row nobody ever finds.
const (
	EventAuthOK           Event = "auth.ok"
	EventAuthFail         Event = "auth.fail"
	EventMacaroonBake     Event = "macaroon.bake"
	EventMacaroonRevoke   Event = "macaroon.revoke"
	EventMacaroonRotate   Event = "macaroon.rotate"
	EventConnectionCreate Event = "connection.create"
	EventConnectionRevoke Event = "connection.revoke"
	// EventNWCPanic is a request whose handler panicked and was contained
	// (`xmc`). The request is DROPPED, and the row is what stops that being
	// silent: the panic happens before §8's replay claim, so a contained request
	// leaves no cache entry, no response and no other trace of having existed.
	EventNWCPanic Event = "nwc.panic"
	// EventConnectionPause is the APP pausing a pairing whose requests kept
	// crashing the handler (`xmc` Fix C), and EventConnectionResume is the
	// operator undoing it. Their own entries rather than a connection.revoke
	// with a different message: revoke is the operator ENDING a pairing, pause
	// is the app defending itself from a client, and a trail that cannot tell
	// those apart cannot answer "who stopped this and can it come back".
	EventConnectionPause  Event = "connection.pause"
	EventConnectionResume Event = "connection.resume"
	EventSendingToggle    Event = "sending.toggle"
	EventSettingChange    Event = "setting.change"
	EventDomainProbe      Event = "domain.probe"
	EventGuardReject      Event = "guard.reject"
	EventGuardRegister    Event = "guard.register"
	// Added in P1 (d46.10). §11 requires the data-directory repair to be logged
	// "at WARN with audit=" and gives the Tier-1 refusal no event at all, so
	// the vocabulary gained the two it was missing.
	EventPreflightRepair Event = "preflight.repair"
	EventPreflightRefuse Event = "preflight.refuse"
	// Added in P1 (d46.7). §5 freezes spending on a reconciliation shortfall
	// and §11 lists it in Tier 2, but §12's vocabulary had nothing for it —
	// and a freeze that leaves no durable trace cannot answer "why did this
	// stop paying?" after the logs have rotated. One event covers both edges;
	// the detail says whether it opened or cleared.
	EventWalletShortfall Event = "wallet.shortfall"
	// Added in P1 (d46.23). A ceiling move writes txns and balance_entries, so
	// the ledger has the AMOUNT — but not who moved it or from where, and
	// attribution is the half the Security page exists to answer without SSH.
	EventWalletAllocate   Event = "wallet.allocate"
	EventWalletDeallocate Event = "wallet.deallocate"
	// Added by `hdu` (26 Aug 2026). An adjustment the APP made to itself, not
	// one the operator asked for: a payment whose route cost more than was
	// reserved settles at the reserve and the excess comes off as a separate
	// entry. The ledger has the amount; this says the app did it and why, which
	// is the half an operator cannot reconstruct from a number on a history
	// page. It should never fire — `fee_limit_msat` is a cap LND respects — so
	// one of these is a thing to go and look at.
	EventWalletAdjust Event = "wallet.adjust"
	// Added by `669` (26 Aug 2026). An operator ASSERTING what became of a
	// payment the app could not resolve — the node had no record of it, or the
	// ledger could not book the answer.
	//
	// ITS OWN EVENT, and not `wallet.adjust` or a settlement, because §12's trail
	// has to let a later reader tell "the node told us this settled" from "a
	// human told us it did". They are different kinds of fact and only the second
	// can be wrong; a reader auditing a discrepancy needs to know which one they
	// are looking at.
	EventWalletAssert Event = "wallet.assert"
	// Added in P2 (o34.3). §7: "a zap that credits the wallet but never
	// publishes a receipt is invisible to the sender and reads as theft." When
	// the 24-hour retry window closes with no relay having accepted, that is
	// exactly what has happened — and it is the one fact this app produces that
	// somebody may come asking about weeks later. A log line alone would let
	// rotation erase the answer to "you took my sats and I never got a
	// receipt", which is the case §12 keeps a durable trail for.
	EventZapReceiptAbandoned Event = "zap.receipt.abandoned"

	// EventRelayRefuse is a relay refused at DIAL time because the address it
	// resolved to is one no stranger may make this node connect to (§7, bcf).
	//
	// The distinction from the pre-check is the whole reason this is an audit
	// event rather than a log line. A relay refused BEFORE the dial is ordinary
	// hostile input — someone put a LAN address in a zap request — and stays in
	// the publish summary at INFO. Reaching the dial check means the pre-check
	// resolved that host to a PUBLIC address and the socket then got a private
	// one: a DNS rebinding attempt in progress, an attack under way rather than
	// a bad relay list. §12's trail exists so log rotation cannot erase the
	// answer to what happened, and "someone attacked the relay allow-list on
	// Tuesday" is exactly such an answer.
	EventRelayRefuse Event = "relay.refuse"

	// EventConnectionRefuse is a paired client refused at a CAPABILITY
	// BOUNDARY — it asked for something it does not have (§8, d24.14).
	//
	// The 0.1.9 field trip is what asked for it. Across the whole trip, at
	// debug level, a real payment produced zero log lines, eleven NWC requests
	// produced zero, and a RESTRICTED refusal produced zero AND left no row
	// here. The trail recorded every action the OPERATOR took and nothing a
	// CONNECTION did, so someone probing a revoked pairing left no trace at all.
	//
	// Bounded to capability refusals, and the line is deliberate: RESTRICTED and
	// UNAUTHORIZED mean "you may not do this", which is a security fact.
	// QUOTA_EXCEEDED and INSUFFICIENT_BALANCE mean "not right now", which is an
	// honest client meeting its own budget — routine, logged at INFO, and
	// auditing it would drown the boundary refusals in exactly the noise that
	// makes a trail unreadable.
	EventConnectionRefuse Event = "connection.refuse"

	// EventConnectionUpdate is the operator changing a live pairing's limits or
	// permission groups (§9 item 4, d24.17).
	//
	// The same class as connection.create and sending.toggle, and it arrived
	// late for the same reason the control did: §9 said "list, create, revoke"
	// and never said update, so nothing in the vocabulary covered a change to
	// what a paired app may spend. Lowering a budget is an operator's cheapest
	// safety action; a trail that records the pairing's creation and its
	// revocation but not the moment its authority changed cannot answer "when
	// did this app's limit change, and to what?".
	EventConnectionUpdate Event = "connection.update"

	// EventGuardAuthorise is the operator's ceremony over a guard control
	// (`06v`): a one-time authorisation issued, redeemed, discarded, or a
	// control changed with or without one.
	//
	// SEPARATE FROM sending.toggle, which is the SERVER recording what an
	// operator asked it for, and separate from guard.reject, which is a refusal.
	// This is the guard recording what it actually did to its own stored intent
	// — the durable answer to "who raised the spending limit, and when", asked
	// after the fact by someone who cannot trust the server's own account of it.
	//
	// The `outcome` attribute carries which of those it is; `change` carries the
	// guard's own sentence about the change, the same one the operator read. THE
	// CODE IS NEVER AN ATTRIBUTE — see guard.Authorisation.
	EventGuardAuthorise Event = "guard.authorise"
)

// Events is the whole vocabulary, for validation and for the admin UI's filter.
var Events = []Event{
	EventAuthOK, EventAuthFail,
	EventMacaroonBake, EventMacaroonRevoke, EventMacaroonRotate,
	EventConnectionCreate, EventConnectionRevoke,
	EventNWCPanic, EventConnectionPause, EventConnectionResume,
	EventSendingToggle, EventSettingChange, EventDomainProbe,
	EventGuardReject, EventGuardRegister,
	EventPreflightRepair, EventPreflightRefuse,
	EventWalletShortfall,
	EventWalletAllocate, EventWalletDeallocate, EventWalletAdjust, EventWalletAssert,
	EventZapReceiptAbandoned,
	EventRelayRefuse,
	EventConnectionRefuse, EventConnectionUpdate,
	EventGuardAuthorise,
}

// Valid reports whether e is in the §12 vocabulary.
func (e Event) Valid() bool { return slices.Contains(Events, e) }

// Audit is the attribute that makes an event findable regardless of level.
func Audit(e Event) slog.Attr { return slog.String("audit", string(e)) }

// Severities for the durable trail (spec §12).
const (
	SeverityInfo  = "info"
	SeverityWarn  = "warn"
	SeverityError = "error"
)

// severityFor maps a log level onto the trail's three severities.
func severityFor(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return SeverityError
	case level >= slog.LevelWarn:
		return SeverityWarn
	default:
		return SeverityInfo
	}
}

// AuditEvent is one row of the durable trail (spec §4, §12).
type AuditEvent struct {
	ID       int64
	Event    Event
	Severity string
	Detail   string // JSON, redacted by the same LogValue rules as the log line
	Remote   string // source IP for auth events, else empty
	// SourceID is set only on a relayed event and is what makes redelivery
	// idempotent. Empty for everything raised in this process.
	SourceID  string
	CreatedAt time.Time
}

// RelayedEvent is a security event raised by a component that has no database
// of its own, on its way to the one that has.
//
// The guard is the case that exists (§12, §16, d46.18). It is the sole holder
// of admin.macaroon and is deliberately given no mount for the server's data
// directory — an arch rule enforces it — so its events lived only in its
// stdout, where log rotation erases them. That is the exact failure §12's
// durable trail exists to prevent, and the socket is what resolves the two
// rules: the guard reports, and the SERVER writes the row.
type RelayedEvent struct {
	// ID is opaque here, unique per event, and stable across the originator's
	// restarts. The originator cannot learn whether a report was stored, so it
	// keeps reporting; this is what makes redelivery produce one row rather
	// than one per poll.
	ID    string            `json:"id"`
	At    time.Time         `json:"at"`
	Level slog.Level        `json:"level"`
	Event Event             `json:"event"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Attributes renders the event's attributes in a deterministic order.
//
// Both sides use it: the originator for its log line and the server for the
// stored row. That makes it structurally true, rather than coincidentally true,
// that the line and the row say the same thing in the same order.
func (e RelayedEvent) Attributes() []slog.Attr {
	attrs := make([]slog.Attr, 0, len(e.Attrs))
	for _, k := range slices.Sorted(maps.Keys(e.Attrs)) {
		attrs = append(attrs, slog.String(k, e.Attrs[k]))
	}
	return attrs
}

// AuditSink persists audit events. *store.Store implements it; the interface
// lives here so this package depends on no database.
type AuditSink interface {
	AppendAuditEvent(ctx context.Context, ev AuditEvent) error
	// AppendUniqueAuditEvent appends ev unless a row with the same SourceID is
	// already stored, reporting whether it wrote one.
	AppendUniqueAuditEvent(ctx context.Context, ev AuditEvent) (stored bool, err error)
}

// Auditor writes a security event to the log and to the durable trail. §12:
// alongside the log line, never instead of it — log rotation must not be able
// to erase the answer to "when did sending get enabled, and by whom?".
type Auditor struct {
	log  *slog.Logger
	sink AuditSink
	now  func() time.Time
}

// NewAuditor pairs a logger with the trail.
func NewAuditor(log *slog.Logger, sink AuditSink) *Auditor {
	return &Auditor{log: log, sink: sink, now: time.Now}
}

// Record logs the event and appends it to the trail. The log line is always
// written, even if the trail write fails — losing the row must not also lose
// the line.
func (a *Auditor) Record(ctx context.Context, level slog.Level, msg string, event Event, attrs ...slog.Attr) error {
	if !event.Valid() {
		return fmt.Errorf("logging: %q is not one of the §12 audit events", event)
	}
	a.log.LogAttrs(ctx, level, msg, append([]slog.Attr{Audit(event)}, attrs...)...)

	detail, err := detailJSON(attrs)
	if err != nil {
		return fmt.Errorf("logging: rendering audit detail for %q: %w", event, err)
	}
	return a.sink.AppendAuditEvent(ctx, AuditEvent{
		Event:     event,
		Severity:  severityFor(level),
		Detail:    detail,
		Remote:    remoteOf(attrs),
		CreatedAt: a.now(),
	})
}

// Relay records an event that happened somewhere else.
//
// It writes the durable row and nothing else. The originator already emitted
// the log line at the moment the event happened — §12's other half — and a
// second line here would carry the delivery time rather than the event's, which
// is worse than no line at all when the question is "when did this happen?".
//
// It reports whether a row was written, so a caller polling a source that
// re-reports can tell a first delivery from a redelivery.
func (a *Auditor) Relay(ctx context.Context, ev RelayedEvent) (bool, error) {
	if !ev.Event.Valid() {
		return false, fmt.Errorf("logging: %q is not one of the §12 audit events", ev.Event)
	}
	if ev.ID == "" {
		return false, fmt.Errorf("logging: a relayed %q carries no source id; without one every "+
			"redelivery would append another row", ev.Event)
	}
	attrs := ev.Attributes()
	detail, err := detailJSON(attrs)
	if err != nil {
		return false, fmt.Errorf("logging: rendering audit detail for %q: %w", ev.Event, err)
	}
	return a.sink.AppendUniqueAuditEvent(ctx, AuditEvent{
		Event:     ev.Event,
		Severity:  severityFor(ev.Level),
		Detail:    detail,
		Remote:    remoteOf(attrs),
		SourceID:  ev.ID,
		CreatedAt: ev.At,
	})
}

// remoteOf lifts the source address out of the attributes, because the trail
// has a column for it.
func remoteOf(attrs []slog.Attr) string {
	for _, a := range attrs {
		if a.Key == "remote" {
			return a.Value.Resolve().String()
		}
	}
	return ""
}

// detailJSON renders the attributes for the trail's detail column. Every value
// is resolved first, so a slog.LogValuer redacts itself exactly as it would in
// a log line.
func detailJSON(attrs []slog.Attr) (string, error) {
	if len(attrs) == 0 {
		return "", nil
	}
	b, err := json.Marshal(attrsToMap(attrs))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func attrsToMap(attrs []slog.Attr) map[string]any {
	out := make(map[string]any, len(attrs))
	for _, a := range attrs {
		v := a.Value.Resolve()
		if v.Kind() == slog.KindGroup {
			out[a.Key] = attrsToMap(v.Group())
			continue
		}
		out[a.Key] = v.Any()
	}
	return out
}
