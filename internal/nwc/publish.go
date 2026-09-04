package nwc

import (
	"context"
	"strings"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/nostr"
)

// ClientResponseBudget is how long a paired client waits for its answer before
// it stops listening (d24.25).
//
// SIXTY SECONDS, and it is a HARD WALL rather than a soft one. Amethyst — the
// client the field trips pair with — sets `NWC_RESPONSE_TIMEOUT_SECONDS = 60`
// and, when the timer fires, UNSUBSCRIBES before telling the user the payment
// failed. So a response published at 61 seconds is not late; it is unreceivable,
// and the attempt that produced it spent a socket on an answer nobody is
// listening for. Its desktop client is stricter still for two of the three
// methods (30 s for balance and invoice, 60 s for pay).
//
// EXPIRY CONDITION, and it is unusually sharp: this is a THIRD PARTY'S number,
// read from their source rather than measured, and it has already moved once —
// an earlier reading of a different file in the same project concluded there was
// no timeout at all. Re-read it before relying on this, and if a second client
// with a shorter budget becomes the one that matters, this is the constant that
// moves.
const ClientResponseBudget = 60 * time.Second

// ResponseAttemptTimeout bounds ONE publish of a response.
//
// Five seconds, against the thirty the zap-receipt path uses (§7 publishes
// best-effort to six relays and tolerates most refusing, where waiting is free).
// Here it is the opposite: one thirty-second attempt spends the client's whole
// budget by itself and every retry after it publishes into a subscription that
// is already gone. A relay that is going to accept an event does it in
// milliseconds; five seconds only fails to help a relay that is pathologically
// slow, and by then the client has stopped listening anyway.
//
// EXPIRY CONDITION: this and ClientResponseBudget are one policy. Three attempts
// must fit inside the budget with the margin to spare, so if the budget shrinks
// this shrinks with it.
//
// ITS RELATION TO internal/nostr's connectBudget CHANGED WITH d1o (4 Sep 2026),
// from a correctness coupling to a latency one. It did not go away, and an
// earlier version of this note claimed it had.
//
// Both are five seconds. The pool used to dial every relay before sending to
// any of them, so a pairing holding one dead relay spent this entire attempt
// dialling it and the live relay's send then ran against a context that had
// just expired: every attempt FAILED and every retry paid it again. The pool
// now sends per relay, so an already-open relay is published to without waiting
// on any other relay's dial, and that failure is gone.
//
// WHAT REMAINS, and it is why this is not "safe to tune in isolation": the
// dial context still DERIVES from the attempt context, so the effective dial
// bound is min(connectBudget, this). A pairing with a dead relay still COSTS
// the whole of it — the attempt no longer fails, it just takes that long — and
// shrinking this constant shortens every dial on the NWC path with it.
// The reasoning is in internal/nostr/pool.go, on sendAndDial and connectBudget.
const ResponseAttemptTimeout = 5 * time.Second

// ResponseDeliveryMargin is how much of the client's budget must remain for a
// RETRY to be worth making.
//
// A response still has to cross a relay and reach a phone. A retry published with
// a tenth of a second left is not delivery, it is a socket spent on an answer
// that arrives after the client has unsubscribed — and on the operator's side it
// looks exactly like a successful publish, which is worse than nothing.
//
// The FIRST attempt does not wait on this, and the asymmetry is deliberate: that
// attempt IS the answer, and a request fifty-eight seconds old still deserves
// one throw at it. What the margin decides is whether there is room for another.
//
// EXPIRY CONDITION: it is a guess at a relay hop plus a client's own processing,
// and it is the number to revisit if a trip ever measures that round trip. Two
// seconds is deliberately generous against a local relay and mean against a
// congested one.
const ResponseDeliveryMargin = 2 * time.Second

// ResponseRetryDelays is the wait BEFORE each retry, so the attempts land at
// 0 s, +1 s and +3 s.
//
// Flat and short, for ReconnectBackoff's reason: the failure being waited out is
// a relay having a bad second — the 0.1.10 trip measured one refusing 8 of 20
// websocket upgrades — and not a stranger's server to be polite to. Exponential
// backoff optimises for the wrong thing when the whole budget is a minute.
//
// EXPIRY CONDITION: three attempts inside 0–3 s is chosen so the last one starts
// while most of the client's minute is still unspent. A budget that shrinks, or a
// per-attempt timeout that grows, changes this.
var ResponseRetryDelays = []time.Duration{time.Second, 2 * time.Second}

// publishResponse delivers one response to the connection's relay, retrying
// while the client can still hear it (d24.25).
//
// THE SAME RELAY, always. Ruling A: a retry names no new host and leaks nothing
// the subscription already holding that relay open has not leaked. A fallback to
// a different relay is a different decision with a different security argument,
// and it is d24.18's.
//
// Bounded three ways, and the deadline is the one that is easy to forget: the
// attempt count, the per-attempt timeout, and the client's own budget measured
// from ITS timestamp rather than from ours. A request that has been in flight for
// fifty-eight seconds gets one attempt, because there is no room for a second.
func (s *Service) publishResponse(ctx context.Context, conn *connection, response gonostr.Event,
	requestedAt time.Time) {
	// From the CLIENT'S timestamp, not from now: the clock the client is
	// watching started when it published, and everything since — the relay hop,
	// the ladder, a payment that ran to LND's own timeout — has already spent
	// part of it. §8's freshness window bounds this to a minute either side, so a
	// skewed clock cannot buy more than that.
	budgetEnds := requestedAt.Add(ClientResponseBudget)
	// EVERY relay the pairing names, on every attempt (d24.18). NIP-47 lets a
	// client choose any of them to listen on, and we do not know which it chose —
	// so a response sent to a subset is a response the client may never hear.
	// Accepted by any ONE of them is delivery.
	relays := nostr.PairingRelays(conn.row().Relays)

	for attempt := 0; ; attempt++ {
		// THE FIRST ATTEMPT IS ALWAYS MADE. The budget bounds RETRIES, and that
		// asymmetry is a correction rather than a nicety: §8 answers a request
		// outside the freshness window with "request expired" so the client stops
		// waiting, and a request is outside that window precisely when it is
		// older than 60 seconds — the same 60 seconds as the client budget. So
		// the deadline had ALREADY passed for every stale request, and the one
		// answer §8 requires most was the one answer never published. A
		// clock-skewed client got total silence, which is the "app that looks
		// idle" shape this whole line of beads exists to remove (found by review).
		//
		// One event published to a client that has genuinely stopped listening
		// costs a relay write. Saying nothing to one that has not costs it its
		// only explanation.
		if attempt > 0 && !s.now().Add(ResponseDeliveryMargin).Before(budgetEnds) {
			s.log.Warn("gave up retrying an NWC response; the client has stopped listening",
				"connection", conn.row().ID, "relays", strings.Join(relays.URLs(), " "),
				"attempts", attempt)
			return
		}
		if nostr.Accepted(s.publishOnce(ctx, response, relays)) > 0 {
			// A relay that took it does not need it again — and one answering
			// "duplicate" HAS it, which a retry would report as a failure.
			return
		}
		if attempt >= len(s.responseRetries) {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-conn.done:
			return
		case <-time.After(s.responseRetries[attempt]):
		}
	}

	// WHAT SAVES THIS, and what does not. The response is already in
	// nwc_handled_requests, so a client that re-sends the same request id gets
	// the cached answer without re-executing it (§8's replay protection). That
	// is a floor rather than an answer: Amethyst does NOT re-send after its
	// give-up timer fires — it unsubscribes and tells the user the payment
	// failed — so for the client the field trips use, this line is the last
	// thing that happens.
	s.log.Warn("no relay accepted an NWC response", "connection", conn.row().ID,
		"relays", strings.Join(relays.URLs(), " "), "attempts", len(s.responseRetries)+1)
}

// publishOnce is one attempt, bounded by its own timeout.
//
// The bound is put on the CONTEXT rather than taken from the pool, and that is
// what keeps the two paths apart: the pool's own publishTimeout is thirty
// seconds and is right for the zap-receipt path it is shared with. A context
// deadline can only narrow it, so this path gets five seconds without the
// receipt path getting five seconds too — which is the "two statements of one
// fact" shape a shared, smaller constant would have.
func (s *Service) publishOnce(ctx context.Context, response gonostr.Event,
	relays nostr.ConnectionRelays) []nostr.PublishResult {
	ctx, cancel := context.WithTimeout(ctx, s.attemptTimeout)
	defer cancel()
	return s.relays.PublishToConnection(ctx, response, relays)
}
