package guard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/davotoula/brollyzapper/internal/logging"
)

// Control names one operator-settable guard control (`06v`).
//
// A CLOSED SET, and the closedness is the point: the server says which of three
// controls to change and cannot name a fourth. It is the same argument §6 makes
// about the socket API's narrowness, one level down — a free-form key would make
// this a general "write into the guard's state" primitive wearing a safe name.
type Control string

const (
	ControlSending    Control = "sending"
	ControlSpendCap   Control = "spend_cap"
	ControlPaymentCap Control = "payment_cap"
)

// Controls is the whole set. A fourth is a design change, not an implementation
// detail — see the test that pins this list.
var Controls = []Control{ControlSending, ControlSpendCap, ControlPaymentCap}

// Change is one control and the value it is being moved to.
//
// It carries a VALUE, not a direction. Which direction that value represents is
// computed here, against the guard's own stored state — see State.loosens — and
// never taken from the caller: the direction is exactly the thing a compromised
// server would lie about.
type Change struct {
	Control Control `json:"control"`
	// On is the new position of ControlSending. Ignored for the caps.
	On bool `json:"on,omitempty"`
	// Msat is the new value of either cap. Ignored for ControlSending.
	Msat int64 `json:"msat,omitempty"`
}

// valid reports whether this change is one the guard implements at all.
//
// A cap below zero is refused rather than clamped: a negative limit is a
// nonsense an operator did not mean, and silently reading it as something else
// is how a security control comes to hold a value nobody chose.
func (c Change) valid() error {
	switch c.Control {
	case ControlSending:
		return nil
	case ControlSpendCap, ControlPaymentCap:
		if c.Msat < 0 {
			return fmt.Errorf("guard: %s cannot be negative", c.Control)
		}
		return nil
	default:
		return fmt.Errorf("guard: %q is not a control this guard has", c.Control)
	}
}

// describe is the sentence the OPERATOR reads in the authorisation file.
//
// It is written here, in the guard, and that is the security property rather
// than a style choice: the operator's only trustworthy account of what is about
// to change is one the server did not compose. If this ever takes a string from
// the caller, operation-binding is gone and the ceremony degrades to "type a
// code the app asked you for".
func (c Change) describe() string { return c.sentence("RAISE") }

// sentence renders the change for a person, with verb naming the cap direction.
//
// ONE WORDING, TWO CONTRACTS. describe() and auditSentence differ only in that
// verb, and writing the sentences out twice would leave the operator's most
// safety-critical line in two copies that a reworded one could silently break —
// which is what a per-control agreement test can only notice after the fact.
// Sharing the words here makes the agreement structural instead.
//
// verb is a LITERAL from the two callers below and never anything off the wire:
// see describe()'s note on operation-binding, which this does not weaken.
func (c Change) sentence(verb string) string {
	switch c.Control {
	case ControlSending:
		// Sending carries its own new position, so the verb does not apply.
		if c.On {
			return "TURN SENDING ON — let this app make your node pay invoices."
		}
		return "turn sending off."
	case ControlSpendCap:
		return verb + " THE SPENDING LIMIT to " + msatSentence(c.Msat) +
			" in any 24 hours."
	case ControlPaymentCap:
		return verb + " THE PER-PAYMENT LIMIT to " + msatSentence(c.Msat) + "."
	}
	return "make a change this version does not recognise. Do not allow it."
}

// auditSentence is describe()'s counterpart for the durable trail, and it takes
// the direction because the trail records BOTH.
//
// describe() has one contract — the sentence the operator reads in the
// authorisation FILE — and that file is only ever written for a loosening, so
// its "RAISE" is true by construction. Reusing it for the trail is what produced
// a durable row reading "RAISE THE SPENDING LIMIT to 50,000 sats" beside outcome
// "tightening": a row contradicting itself about a security control's direction
// (BrollyZap-66t).
//
// The direction is not derived here because it cannot be: whether a cap moves up
// or down depends on the STORED value, which a Change does not carry — see the
// note on Change itself, which says so as a design property. The outcome carries
// it instead.
func (c Change) auditSentence(tightening bool) string {
	if tightening {
		return c.sentence("LOWER")
	}
	return c.sentence("RAISE")
}

// msatSentence renders msat for a person, in whole sats where it divides.
//
// §9 says amounts display as whole sats and the msat remainder only when it is
// non-zero. A cap is set in msat and will almost always be a round number of
// sats; printing "100000.000" in the one sentence the operator must read
// carefully is noise where it can least afford it.
func msatSentence(msat int64) string {
	if msat == 0 {
		return "0 sats (which refuses every payment)"
	}
	if msat%1000 == 0 {
		return strconv.FormatInt(msat/1000, 10) + " sats"
	}
	return strconv.FormatInt(msat, 10) + " msat"
}

// loosens reports whether applying c to this state moves in the direction a
// compromised server would want (`06v`, Ruling 1).
//
// THE MONOTONIC SPLIT, SAID ONCE. Tightening — turning sending off, lowering
// either cap — is a plain operator action with no ceremony, because a
// compromised server gains nothing by restricting itself and ceremony on that
// direction costs the operator and buys nothing. Loosening needs the unforgeable
// channel.
//
// THIS DECISION LIVES IN THE GUARD AND NOWHERE ELSE, and an arch rule holds it
// here. If the server decided which changes were loosenings, a compromised
// server would call every one of its own a tightening, and the whole ceremony
// would be advisory.
//
// GRIEFING IS ACCEPTED, deliberately: a compromised server can lower a cap to
// zero or turn sending off, and the operator must perform the ceremony to
// restore it. That is an availability attack by the thing that IS the
// availability, and it is not worth defending against.
//
// AN UNKNOWN CONTROL LOOSENS. Fail closed: a value this version cannot classify
// is one it cannot promise is safe.
func (st State) loosens(c Change) bool {
	switch c.Control {
	case ControlSending:
		return c.On && !st.SendingLatch
	case ControlSpendCap:
		return c.Msat > st.MaxSpendMsat
	case ControlPaymentCap:
		return c.Msat > st.MaxPaymentMsat
	}
	return true
}

// alreadyHas reports whether this change would move nothing.
//
// An unknown control is NOT "already had": it falls through to valid(), which
// refuses it. Answering true here would turn a control this version does not
// implement into a silent success — the operator told the change happened, and
// nothing having happened.
func (st State) alreadyHas(c Change) bool {
	switch c.Control {
	case ControlSending:
		return st.SendingLatch == c.On
	case ControlSpendCap:
		return st.MaxSpendMsat == c.Msat
	case ControlPaymentCap:
		return st.MaxPaymentMsat == c.Msat
	}
	return false
}

// apply writes the change into the state. It decides nothing; the caller has
// already established that this change is permitted.
func (st *State) apply(c Change) {
	switch c.Control {
	case ControlSending:
		st.SendingLatch = c.On
	case ControlSpendCap:
		st.MaxSpendMsat = c.Msat
	case ControlPaymentCap:
		st.MaxPaymentMsat = c.Msat
	}
}

// errAuthorisationRequired is returned when a loosening arrives with no valid
// code.
//
// UNEXPORTED, and it is the same reasoning errSpendRefused carries: this error
// crosses the socket, where `dispatch` flattens it to a string and
// SocketClient.call rebuilds it with errors.New — so nothing on the server side
// can ever errors.Is it, by construction. An exported name would read as a
// contract, and the next handler wanting to tell "needs a code" from "wrong
// code" would write a match that compiles, never fires, and fails silently.
// What survives is the TEXT, which is why the text says what to do. Found by
// review.
var errAuthorisationRequired = errors.New("guard: this change needs an authorisation code")

// RequestAuthorisation issues a one-time grant for a loosening and writes it
// where only the operator can read it.
//
// A NEW REQUEST SUPERSEDES AN OUTSTANDING ONE, including one for a different
// change. Two live codes would mean two sentences on disk describing two pending
// operations, and an operator typing the code they can see for the change they
// did not read — which is the phishing this design exists to prevent, assembled
// out of two honest halves.
//
// IT RETURNS NOTHING BUT AN ERROR, and in particular it does not return the code:
// the server must not learn it, and a return value is the easiest possible way
// to leak it into a log line. It does not return the EXPIRY either — that
// reaches the server through Status.AuthorisationExpiresAt, which is the wire's
// own account of the pending grant, and a second channel for it would be a
// second thing to keep in step. Found by review.
func (g *Guard) RequestAuthorisation(ctx context.Context, change Change) error {
	if err := change.valid(); err != nil {
		return err
	}
	state, err := g.state.load()
	if err != nil {
		return err
	}
	if !state.loosens(change) {
		// Refused rather than issued. A grant for a change that needs none would
		// teach the operator that the ceremony is a formality they perform for
		// everything, which is exactly how a phished one stops reading the
		// sentence.
		return fmt.Errorf("guard: %s does not need an authorisation; it is not a loosening",
			change.Control)
	}
	now := g.rotation.clock()
	code, err := newCode()
	if err != nil {
		return err
	}
	grant := &Authorisation{Change: change, Code: code, ExpiresAt: now.Add(authorisationTTL)}
	// The FILE first, then the state. A file with no grant behind it is a code
	// that does not work, which the operator retries; a grant with no file is a
	// code nobody can read, which is a dead end they cannot diagnose.
	if err := g.writeAuthorisationFile(grant, now); err != nil {
		return err
	}
	if err := g.state.update(func(st *State) { st.Authorisation = grant }); err != nil {
		return err
	}
	// Audited: an authorisation request is the app asking for more authority
	// than it has, which is worth a durable row whether or not it is redeemed.
	// The CODE IS NOT IN IT — see Authorisation.
	g.auditAuthorisation(ctx, slog.LevelWarn, "an authorisation was requested for a loosening",
		change, outcomeIssued)
	return nil
}

// outcome is what happened to an operator control AND which way it moved.
//
// THE TWO TRAVEL TOGETHER because the trail's sentence renders the direction.
// The first version of this fix carried the word alone and recovered the
// direction with `outcome == "tightening"` — which reads as safe and is not: the
// outcome vocabulary is OPEN. Seven words reach auditAuthorisation today,
// including free-form text composed by discardAuthorisation, so every word but
// one defaulted to RAISE. The next outcome added on a non-loosening path would
// have reproduced BrollyZap-66t exactly, one word later, with no compile error
// and no failing test — and RAISE is the wrong way for that default to fall,
// because the loosening claim is the one that should have to be opted into.
//
// A new outcome cannot now be written without stating its direction.
type outcome struct {
	word string
	// tightening is the direction, and it is a property of the OUTCOME rather
	// than of the Change: a Change carries a value, never a direction (see its
	// own note), and for a tightening the direction simply is the outcome.
	tightening bool
}

var (
	outcomeIssued     = outcome{word: "issued"}
	outcomeAuthorised = outcome{word: "authorised"}
	outcomeTightening = outcome{word: "tightening", tightening: true}
	outcomeWrongCode  = outcome{word: "wrong code"}
)

// discarded is the one outcome whose word is composed rather than chosen, and it
// is always a loosening: a grant only ever exists for one, because
// RequestAuthorisation refuses to issue for anything else.
func discarded(why string) outcome { return outcome{word: why} }

// ApplyChange is the one site that changes an operator control.
//
// The order is the design:
//
//  1. Validate the change at all. An unknown control never reaches the state.
//  2. Ask whether it LOOSENS, against the guard's own stored state.
//  3. A tightening applies immediately, with no code. Free, by Ruling 1.
//  4. A loosening is checked against the outstanding grant — the same change,
//     unexpired, unspent, and the right code — and the grant is consumed
//     whichever way that goes.
//
// The invariant §6 requires of the caps holds HERE rather than only at config
// load: a per-payment cap above the window cap is unenforceable, and the check
// has to be where the change is applied because that is where the pair can be
// made inconsistent one control at a time.
func (g *Guard) ApplyChange(ctx context.Context, change Change, code string) error {
	if err := change.valid(); err != nil {
		return err
	}
	// Serialised against baking for the same reason bake takes it: this composes
	// a load with a later update, and the change it applies is one BakeSpend
	// reads.
	g.bakeMu.Lock()
	defer g.bakeMu.Unlock()

	state, err := g.state.load()
	if err != nil {
		return err
	}
	// A change that is ALREADY IN EFFECT is a no-op, and stops here.
	//
	// It is not merely wasted work. Without this, the Sending page's retry path —
	// an operator clicking Enable on an install whose latch is already on,
	// because an earlier bake failed — rewrites the state file and puts a
	// `guard.authorise` row reading "tightening" in the durable trail for
	// something that did not happen. That row is indistinguishable from a real
	// one, it spends the ceremony's audit budget, and the budget exists to keep
	// room for events an operator actually needs. Found by review.
	if state.alreadyHas(change) {
		return nil
	}
	if err := g.checkCapPair(state, change); err != nil {
		return err
	}
	if !state.loosens(change) {
		return g.commitChange(ctx, change, outcomeTightening)
	}
	if err := g.redeem(ctx, state, change, code); err != nil {
		return err
	}
	return g.commitChange(ctx, change, outcomeAuthorised)
}

// checkCapPair keeps §6's outer bound true across a one-control change.
//
// config.LoadGuard makes the same check over the environment; this is the same
// invariant over the STORED values, and it has to be enforced here because the
// operator changes one cap at a time. Lowering the window cap below the payment
// cap would leave a per-payment limit that can never be reached — a number on
// the page that means nothing, which is worse than a refusal that says why.
//
// THE REMEDY NAMES THE CONTROL THE OPERATOR IS NOT EDITING (8vj). It used to say
// "change the 24-hour limit first" in both directions, which is right only when
// the operator is RAISING the per-payment cap. An operator lowering the window
// was told to change the control they had just typed into.
//
// That is not a wording nit, and the box priced it on 2026-09-02: an operator
// holding a 250-sat per-payment cap tried to set a 100-sat 24-hour ceiling, was
// refused with the backwards remedy, tried 10,000, and settled at 1,000 — ten
// times looser than they wanted, on the control whose whole purpose is bounding
// loss. §6 makes tightening the free direction precisely so the safe move is the
// cheap one; a message that obstructs tightening charges for it.
//
// It does NOT say which way costs a ceremony, though the two differ: lowering
// the per-payment limit is a tightening and takes one click, while raising the
// 24-hour limit is a loosening and needs the unforgeable channel. Left out
// because this string is read by someone who has just been refused mid-task,
// whose next act is the remedy rather than a choice between two of them — and
// the page carries the ceremony's own explanation where there is room for it.
func (g *Guard) checkCapPair(state State, change Change) error {
	window, payment := state.MaxSpendMsat, state.MaxPaymentMsat
	// Chosen HERE, in the switch that already knows which control the operator is
	// editing, rather than in a second conditional beside the message that could
	// drift from it. It also means a third cap control cannot reach the refusal
	// without choosing its remedy in the same breath, and the default below is
	// what keeps this string from ever being empty.
	var remedy string
	switch change.Control {
	case ControlSpendCap:
		window = change.Msat
		remedy = "lower the per-payment limit first"
	case ControlPaymentCap:
		payment = change.Msat
		remedy = "raise the 24-hour limit first"
	default:
		return nil
	}
	if payment > window {
		// IN SATS, because this string is read by an operator on a page §9 says
		// renders whole sats. It reaches them through the flash copy, and a
		// number in msat there is three orders of magnitude away from the one in
		// the box they just typed into. Found by review.
		return fmt.Errorf("guard: a per-payment limit of %s is above the 24-hour limit of %s, "+
			"so it could never be reached; %s",
			msatSentence(payment), msatSentence(window), remedy)
	}
	return nil
}

// redeem consumes the outstanding grant against this change.
//
// THE GRANT IS CONSUMED WHATEVER HAPPENS on a wrong code past the attempt bound,
// and on any expiry. A grant that survived failed attempts would be a standing
// target for the one attacker with unlimited local tries.
//
// It is checked against the WHOLE change, value included, not against the
// control: a grant issued for "raise the 24-hour limit to 50k sats" must not be
// redeemable for five million. That is what operation-binding means, and
// checking only the control would leave the operator's sentence true and the
// applied change something else entirely.
func (g *Guard) redeem(ctx context.Context, state State, change Change, code string) error {
	grant := state.Authorisation
	if grant == nil {
		return errAuthorisationRequired
	}
	now := g.rotation.clock()
	if grant.expired(now) {
		g.discardAuthorisation(ctx, change, "expired")
		return fmt.Errorf("guard: that authorisation expired; ask for a new one")
	}
	if grant.Change != change {
		// NOT counted as an attempt, and consumed outright. A code offered for a
		// change other than the one the operator was shown is not a typo — it is
		// the server spending an answer on a question it was not asked, which is
		// the attack this file exists to stop.
		g.discardAuthorisation(ctx, change, "offered against a different change")
		return fmt.Errorf("guard: the outstanding authorisation is for a different change; " +
			"ask for a new one")
	}
	if !grant.matches(code) {
		grant.Attempts++
		if grant.Attempts >= maxAuthorisationAttempts {
			g.discardAuthorisation(ctx, change, "too many wrong codes")
			return fmt.Errorf("guard: that code is wrong, and this authorisation is now spent; " +
				"ask for a new one")
		}
		if err := g.state.update(func(st *State) { st.Authorisation = grant }); err != nil {
			return err
		}
		g.auditAuthorisation(ctx, slog.LevelWarn, "a wrong authorisation code was offered",
			change, outcomeWrongCode)
		return fmt.Errorf("guard: that code is wrong; %d attempt(s) left",
			maxAuthorisationAttempts-grant.Attempts)
	}
	// Consumed on use, before the change is applied. A crash between the two
	// costs the operator one ceremony; the other order would leave a spent code
	// usable a second time.
	return g.consumeAuthorisation()
}

// discardAuthorisation ends a grant that will not be honoured, and says why.
func (g *Guard) discardAuthorisation(ctx context.Context, change Change, why string) {
	if err := g.consumeAuthorisation(); err != nil {
		g.log.Warn("could not clear a spent authorisation", "error", err.Error())
	}
	g.auditAuthorisation(ctx, slog.LevelWarn, "an authorisation was discarded", change, discarded(why))
}

func (g *Guard) consumeAuthorisation() error {
	if err := g.state.update(func(st *State) { st.Authorisation = nil }); err != nil {
		return err
	}
	g.clearAuthorisationFile()
	return nil
}

// auditAuthorisationBound is how much of the guard's 32-slot ring one burst of
// ceremony events may take (t0b).
//
// IT IS ITS OWN BUDGET, not the refusals one, for the same reason `xmc` gave the
// panics budget its own: these are driven by a different actor, and a flood of
// one must not spend the allowance that would have recorded the first of the
// other. A compromised server making a hundred authorisation requests must not
// evict the `guard.reject` row for the bake it then attempted.
//
// EIGHT, matching auditRejectBound, and for the identical reason — the ring is
// 32 slots and nothing drains it. EXPIRY CONDITION: the same one. If
// maxRetainedAuditEvents grows, both bounds grow with it; the ratio is the fact,
// not either number.
const auditAuthorisationBound = 8

// auditAuthorisation raises one ceremony event. It exists so that no call site
// has to remember which attributes the trail expects — and so that none of them
// can reach for the code.
//
// BOUNDED, because every one of these is server-drivable at will: a compromised
// server can ask for an authorisation, offer a wrong code, or lower a cap by one
// msat, as fast as the socket allows. Unbounded, that is thirty-two socket calls
// to flush the ring and take `macaroon.bake` with it — the row an operator most
// needs after exactly the incident that produced the flood.
//
// An operator's own ceremony can therefore be logged-only in a window a server
// has already spent. That is the same trade auditReject makes, and the bound
// announces itself once so "bounded" is distinguishable from "nothing happened".
func (g *Guard) auditAuthorisation(ctx context.Context, level slog.Level, msg string,
	change Change, result outcome) {
	record, sayBounded := g.authoriseBudget.Allow()
	if sayBounded {
		g.audit(ctx, slog.LevelWarn, "more operator-control events this hour than the audit "+
			"bound allows; the rest are in the log only", logging.EventGuardAuthorise,
			map[string]string{
				"bound":  strconv.Itoa(auditAuthorisationBound),
				"remedy": "read the guard's log for the ones not recorded here",
			})
	}
	// The trail's sentence, not the file's: this path is reached for a lowering
	// as well as a raise (BrollyZap-66t).
	sentence := change.auditSentence(result.tightening)
	if !record {
		g.log.LogAttrs(ctx, level, msg, slog.String("control", string(change.Control)),
			slog.String("change", sentence), slog.String("outcome", result.word))
		return
	}
	g.audit(ctx, level, msg, logging.EventGuardAuthorise, map[string]string{
		"control": string(change.Control),
		"change":  sentence,
		"outcome": result.word,
	})
}

// commitChange writes the change and records it in the durable trail.
func (g *Guard) commitChange(ctx context.Context, change Change, how outcome) error {
	if err := g.state.update(func(st *State) { st.apply(change) }); err != nil {
		return err
	}
	g.auditAuthorisation(ctx, slog.LevelWarn, "an operator control was changed", change, how)
	return nil
}

// sendingPermitted is the whole gate on minting spend authority, and it is a
// conjunction of two different things (`06v`, Ruling 4).
//
//   - allowSending is the DEPLOYMENT ceiling — GUARD_ALLOW_SENDING, now true by
//     default. It is a hard "never" for a deployment that wants one, and nothing
//     inside the app can lift it.
//   - the LATCH is the operator's own gate, off on a fresh install, and it is
//     what preserves §6's receive-only default now that the env var does not.
//
// Both, because they answer different questions and neither subsumes the other.
func (g *Guard) sendingPermitted(state State) bool {
	return g.allowSending && state.SendingLatch
}
