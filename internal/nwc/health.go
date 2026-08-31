package nwc

import "time"

// FailureReminderInterval is how often a connection that cannot reach its relay
// says so AGAIN, while that is still true (d24.21).
//
// Both halves are the requirement, and the 0.1.10 field trip named them: "a
// relay that is unreachable IS the app being down for every paired wallet. It
// deserves a periodic WARN while the condition persists, not one line at the
// moment it first happens." One line at the moment it happens is what the trip
// got — 10:54:48, then silence through hours of an app nobody could use.
//
// Bounded, because the opposite failure is as bad and easier to reach: one line
// per dial at ReconnectBackoff is twelve a minute per pairing, seventeen thousand
// a day, and a log at that density is one an operator stops reading. Five minutes
// puts the condition in front of them a few times an hour, which is the rate at
// which they can act on it.
//
// EXPIRY CONDITION: this is a bound on REPORTING and ReconnectBackoff is the
// bound on retrying. Its justification — roughly one line per sixty dials — moves
// with that constant, so if the backoff stops being flat and short, say what this
// number became instead.
const FailureReminderInterval = 5 * time.Minute

// HealthState is what the service currently knows about one pairing's relay
// session (d24.21).
//
// PER CONNECTION, not per relay, and that is a decision rather than an
// accident: two connections may name the same relay and one of them can still be
// unusable for reasons of its own. d24.18 — several relays per connection — is
// the thing that would change this shape, and it is undecided; if it lands, this
// becomes a state per connection PER RELAY and the page has to say which relay
// it is talking about.
type HealthState string

const (
	// HealthServing means the subscription is up. It is not a promise that the
	// relay is delivering — nothing here can know that — only that this end has
	// a socket and is listening on it.
	HealthServing HealthState = "serving"
	// HealthRetrying means the relay refused or dropped us and the connection is
	// dialling again. Requests sent to this pairing are reaching nobody.
	HealthRetrying HealthState = "retrying"
	// HealthUnusable means the ROW cannot be served — see prepare. No relay
	// coming back fixes it, so this one is not retrying and saying "retrying"
	// would promise a recovery that cannot arrive.
	HealthUnusable HealthState = "unusable"
)

// ConnectionHealth is one pairing's state as the Connections page shows it.
//
// A pairing with two of three relays up is neither "serving" nor "retrying", and
// the honest answer is that it is BOTH — per relay. So the connection-level
// value carries only what is true of the pairing as a whole (its row cannot be
// served at all), and everything else is per relay, in the order the pairing's
// URI named them.
//
// WHY "ANY RELAY UP" IS THE PAIRING WORKING, which is the judgement criterion 4
// of d24.18's brief asks for: a client publishes its request to a relay it chose
// from that same list, so one relay being up means SOME client can reach us and
// none being up means none can. Calling a two-of-three pairing "degraded" would
// be truer of our sockets and less true of the operator's question, which is
// whether their phone works. The page shows the count, so a pairing that is one
// bad relay from silence still says so.
type ConnectionHealth struct {
	// State is HealthUnusable when the ROW cannot be served at all, and empty
	// otherwise — a pairing whose row is fine is described by its relays.
	State HealthState
	// Since is when an unusable row became unusable. Zero otherwise.
	Since time.Time
	// Relays is one entry per relay the pairing names, in its URI's order.
	Relays []RelayHealth
}

// Working reports whether ANY of this pairing's relays currently holds a
// subscription. See the type's doc for why that is the operator's question.
func (c ConnectionHealth) Working() bool {
	for _, relay := range c.Relays {
		if relay.State == HealthServing {
			return true
		}
	}
	return false
}

// RelayHealth is one relay session of one pairing.
type RelayHealth struct {
	Relay string
	State HealthState
	// Since is when this state began. "It is failing" without a time cannot be
	// told from "it has always been like this", which is the position the
	// operator was in for thirteen minutes on the 0.1.10 trip.
	Since time.Time
	// FailedDials is how many attempts have failed since Since. Zero while
	// serving.
	FailedDials int
	// Reconnects is how many times this relay has come BACK since the service
	// started, and it is what makes a flapping relay visible.
	//
	// A relay that accepts a subscription and drops it seconds later leaves the
	// state reading "working" at every moment the operator happens to look, with
	// FailedDials at zero — "an app that looked idle and healthy", which is the
	// sentence this whole bead exists to make impossible. The count is the one
	// thing that survives the flapping, so it is what the page shows.
	Reconnects int
}

// health is the registry's own copy of one pairing, carrying two things per relay
// that the page must not see: when that relay's trouble was last LOGGED, and
// whether the current or most recent episode produced a line at all.
//
// Both are carried ACROSS a recovery, and that is the whole reason they exist. A
// relay that accepts and drops every backoff is ONE condition; without the carry
// each cycle looks like a fresh episode, reports itself, and produces the
// twelve-lines-a-minute the bound was written to prevent.
type health struct {
	unusable  bool
	since     time.Time
	reported  time.Time
	announced bool
	// order is the order relays were first SEEN in, which is not the pairing's
	// own — reload starts one session per relay at once, so it is arrival order
	// and it varies from boot to boot. Health takes the row's list as the
	// authority and falls back to this only for a relay the row no longer names.
	order  []string
	relays map[string]*relayState
}

type relayState struct {
	RelayHealth
	reported  time.Time
	announced bool
}

// Health is what the service currently knows about every pairing it has tried.
//
// A COPY, because the caller is an HTTP handler on another goroutine and the map
// is written by the connection goroutines.
//
// IN MEMORY, and a connection the service has not reached yet is ABSENT rather
// than assumed healthy. That is the honest answer after a restart: this describes
// live sockets, and a durable "serving" read back from before a restart would
// claim ones that do not exist yet. The page says "not known yet", which is true
// for the second or two before the first reload lands. The durable half of this
// bead is the last refusal — a fact about the past, which survives a restart
// properly, on the connection's row.
func (s *Service) Health() map[int64]ConnectionHealth {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	out := make(map[int64]ConnectionHealth, len(s.health))
	for id, h := range s.health {
		view := ConnectionHealth{Since: h.since}
		if h.unusable {
			view.State = HealthUnusable
		}
		for _, relay := range h.order {
			if state := h.relays[relay]; state != nil {
				view.Relays = append(view.Relays, state.RelayHealth)
			}
		}
		out[id] = view
	}
	return out
}

// Order puts a pairing's relay states into the order the pairing itself names
// them, which is what the page renders.
//
// NOT the order they were first seen in. reload starts one session per relay at
// once, so arrival order is whichever dial finished first and it varies from boot
// to boot — measured at six distinct orders across sixty reloads of a three-relay
// pairing. This wave says repeatedly that the FIRST relay is the one a
// single-relay client uses, so a page listing the sessions in a random order
// would contradict the sentence next to it (found by review, which caught the doc
// comment claiming an order the code did not produce).
//
// A relay in the state but no longer in the row keeps its place at the end rather
// than vanishing: it cannot happen today — the list is not editable — and
// dropping it silently is the wrong half of that to guess at.
func (c ConnectionHealth) Order(pairing []string) ConnectionHealth {
	if len(c.Relays) == 0 {
		return c
	}
	byRelay := make(map[string]RelayHealth, len(c.Relays))
	for _, state := range c.Relays {
		byRelay[state.Relay] = state
	}
	ordered := make([]RelayHealth, 0, len(c.Relays))
	for _, relay := range pairing {
		if state, known := byRelay[relay]; known {
			ordered = append(ordered, state)
			delete(byRelay, relay)
		}
	}
	for _, state := range c.Relays {
		if _, left := byRelay[state.Relay]; left {
			ordered = append(ordered, state)
		}
	}
	c.Relays = ordered
	return c
}

// entry returns this pairing's record, creating it on first use. Callers hold
// healthMu.
func (s *Service) entry(id int64) *health {
	h := s.health[id]
	if h == nil {
		h = &health{relays: map[string]*relayState{}}
		s.health[id] = h
	}
	return h
}

// relayEntry returns one relay's record, creating it — and remembering the order
// relays were first seen in, which is the pairing's own.
func (h *health) relayEntry(relay string) *relayState {
	state := h.relays[relay]
	if state == nil {
		state = &relayState{RelayHealth: RelayHealth{Relay: relay}}
		h.relays[relay] = state
		h.order = append(h.order, relay)
	}
	return state
}

// markServing records that one relay's subscription is up, and reports what it
// was doing before plus whether the recovery is worth a log line.
//
// A recovery is worth one exactly when the BREAK was: an episode nobody was told
// about does not need an all-clear, and telling them anyway is how a flapping
// relay produces two lines per cycle instead of none.
func (s *Service) markServing(id int64, relay string) (previous RelayHealth, report bool) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	state := s.entry(id).relayEntry(relay)
	before := state.RelayHealth
	recovered := before.State != "" && before.State != HealthServing
	state.RelayHealth = RelayHealth{Relay: relay, State: HealthServing, Since: s.now(),
		Reconnects: before.Reconnects}
	if recovered {
		state.Reconnects++
	}
	return before, recovered && state.announced
}

// markRetrying records a failed dial on one relay and reports whether this one is
// worth a log line.
//
// The first trouble of a relay's life always reports: that is the transition, and
// it is what tells an operator when their pairing stopped working. After that —
// INCLUDING a new episode after a brief recovery — the line repeats at
// FailureReminderInterval. A new episode respecting the same clock is what makes
// the bound hold for a relay that accepts and drops every backoff, which the
// obvious version does not: it would treat each cycle as news.
func (s *Service) markRetrying(id int64, relay string) (current RelayHealth, report bool) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	now := s.now()
	state := s.entry(id).relayEntry(relay)
	if state.State != HealthRetrying {
		state.RelayHealth = RelayHealth{Relay: relay, State: HealthRetrying, Since: now,
			FailedDials: 1, Reconnects: state.Reconnects}
		state.announced = state.reported.IsZero() || now.Sub(state.reported) >= s.reminder
		if state.announced {
			state.reported = now
		}
		return state.RelayHealth, state.announced
	}
	state.FailedDials++
	report = now.Sub(state.reported) >= s.reminder
	if report {
		state.reported, state.announced = now, true
	}
	return state.RelayHealth, report
}

// markUnusable records that this connection's ROW cannot be served, and reports
// whether to say so again.
//
// SINCE IS NOT MOVED when the row was already unusable, and the reason is that
// reload runs on every operator action: creating an unrelated pairing, saving a
// limit, or toggling sending all nudge the demand channel. A row that has been
// broken since boot must not read as broken since the last time somebody saved a
// setting — "since when" is the whole reason the field exists. The WARN is
// bounded on the same clock for the same reason.
func (s *Service) markUnusable(id int64) (report bool) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	now := s.now()
	h := s.entry(id)
	if h.unusable {
		if now.Sub(h.reported) < s.reminder {
			return false
		}
		h.reported = now
		return true
	}
	// A row that becomes unusable has no relay sessions to report: nothing is
	// dialling, and a leftover "retrying" beside "this can never work" would be
	// two answers to one question.
	//
	// There is nothing to clear, and that is worth stating rather than
	// defending against. markUnusable is reached only from prepare's failure
	// branch, which reload takes only for a row NOT already in `live` — and a row
	// leaves `live` only by leaving the active set, which deletes its health
	// outright. A row cannot become unusable while it is being served: its relays
	// are not editable, so nothing about it can change under a running session.
	// The line that emptied the map here has been removed; if a path is ever
	// added that can break a live row, this is where its state has to be cleared
	// (found by review, which spent twenty minutes proving the line unreachable).
	h.unusable, h.since, h.reported, h.announced = true, now, now, true
	return true
}

// forgetHealth drops a connection the service no longer serves.
//
// Called once every relay SESSION of that pairing has exited, which is the only
// moment no dial can still be in flight. reload cannot do it: a revoke can land
// while a session is blocked inside Subscribe, and the error it gets on the way
// out would re-insert the entry a moment after reload deleted it — found by
// review, reproduced with a blocked dial.
func (s *Service) forgetHealth(id int64) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	delete(s.health, id)
}

// retainHealth drops every pairing that is no longer in the active set.
//
// The sweep exists for the rows no session ever owned: a row prepare rejected is
// deliberately not put in `live`, so nothing else would ever forget it, and
// `nwc_connections.id` is a plain rowid that sqlite may reuse after a delete —
// which would hand a fresh pairing the previous occupant's "cannot be used at
// all".
func (s *Service) retainHealth(active map[int64]bool) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	for id := range s.health {
		if !active[id] {
			delete(s.health, id)
		}
	}
}
