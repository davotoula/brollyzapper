package guard

import (
	"context"
	"log/slog"
	"slices"

	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/secret"
)

// audit raises one guard security event: the log line here, and a durable copy
// in the guard's OWN state file for the server to collect over the socket.
//
// §12 and §16 pull against each other here — the trail must survive log
// rotation, and the guard must write to nothing the server owns — and the
// socket is what resolves them. Before d46.18 only the log line existed, so
// audit_events held no macaroon.bake on a box where the guard had plainly
// logged one, and the durable half of §12 was missing for every event the
// guard raises.
//
// A failure to record is logged and swallowed: losing the row must not also
// lose the operation that raised it.
func (g *Guard) audit(ctx context.Context, level slog.Level, msg string,
	event logging.Event, attrs map[string]string) {
	ev := logging.RelayedEvent{At: g.rotation.clock(), Level: level, Event: event, Attrs: attrs}
	// The same check logging.Auditor.Record makes. The guard cannot use the
	// Auditor — §16 gives it no mount for the server's database — so without
	// this the §12 vocabulary would be enforced only by the server rejecting
	// the event later, one process away from the typo that caused it.
	if !event.Valid() {
		g.log.Error("refusing to raise a security event outside the §12 vocabulary",
			"event", string(event), "message", msg)
		return
	}
	g.log.LogAttrs(ctx, level, msg, append([]slog.Attr{logging.Audit(event)}, ev.Attributes()...)...)

	if err := g.state.update(func(s *State) {
		// A random id per event, rather than a per-guard origin and a counter.
		// Nothing parses it — the server only ever compares it for equality —
		// so uniqueness across a wiped DATA_DIR holds by construction instead
		// of by argument, and there is no sequencing state to keep.
		ev.ID = secret.RandomToken(16)
		s.RecentAudit = append(s.RecentAudit, ev)
		if extra := len(s.RecentAudit) - maxRetainedAuditEvents; extra > 0 {
			s.RecentAudit = slices.Delete(s.RecentAudit, 0, extra)
		}
	}); err != nil {
		g.log.Error("could not record a security event for the server to collect",
			"event", string(event), "error", err.Error())
	}
}

// recentAuditEvents is what every response carries back.
func (g *Guard) recentAuditEvents() []logging.RelayedEvent {
	state, err := g.state.load()
	if err != nil {
		g.log.Warn("could not read the security events to report", "error", err.Error())
		return nil
	}
	return state.RecentAudit
}
