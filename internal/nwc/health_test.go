package nwc

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"
)

// d24.21: the service knows, and can say, which pairings are currently serving.
//
// A durable, visible STATE rather than more log lines. The 0.1.10 trip is what
// this is for: from 12:19 to 12:32 the app was unusable — balance spinning, a zap
// timing out — and the operator could only establish that by reading
// nwc_handled_requests out of SQLite and noticing the timestamps had stopped. An
// event that fires once at boot cannot answer "is it broken NOW", which is the
// only question being asked.
func TestTheServiceSaysWhichConnectionsAreServing(t *testing.T) {
	h := newHarness(t)
	h.service.backoff = time.Millisecond
	const downRelay = "wss://relay.down"
	down := h.addConnection("a pairing whose relay is down", downRelay, nil)
	broken := h.addConnection("a pairing whose row is broken", "wss://relay.broken",
		func(row *store.NWCConnection) { row.ServicePubkey = anIdentity(t).PublicKey() })
	h.relays.refuse(downRelay, 1_000_000)

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	defer func() {
		cancel()
		for _, conn := range live {
			conn.close()
		}
		h.service.serving.Wait()
	}()
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatalf("reload: %v", err)
	}

	// The first dial is the session goroutine's now, not reload's, so the state
	// this test reads exists a moment after reload returns rather than when it
	// does.
	h.subscribed(t, testRelay)
	waitFor(t, "the failing relay to report itself", func() bool {
		return len(h.service.Health()[down.ID].Relays) == 1
	})
	health := h.service.Health()
	if !health[h.conn.row().ID].Working() {
		t.Errorf("the reachable connection reads as not working: %+v", health[h.conn.row().ID])
	}
	if health[down.ID].Working() {
		t.Errorf("the connection whose relay refused reads as working: %+v", health[down.ID])
	}
	if got := relayHealthOf(t, health[down.ID], downRelay).State; got != HealthRetrying {
		t.Errorf("the relay that refused is %q, want %q — the operator's question is whether "+
			"this pairing works, and \"it is trying\" is the answer", got, HealthRetrying)
	}
	if got := health[broken.ID].State; got != HealthUnusable {
		t.Errorf("the connection whose row is broken is %q, want %q — it is not retrying and "+
			"never will, and saying \"retrying\" would promise a recovery that cannot come",
			got, HealthUnusable)
	}
	if len(health[broken.ID].Relays) != 0 {
		t.Errorf("a row that can never be served still lists relay sessions (%+v); nothing is "+
			"dialling, and \"retrying\" beside \"this can never work\" is two answers to one "+
			"question", health[broken.ID].Relays)
	}
	// SINCE WHEN, not just what: "it is failing" without a time cannot be told
	// from "it has always been like this", which is the state the trip was in.
	if relayHealthOf(t, health[down.ID], downRelay).Since.IsZero() {
		t.Error("the failing relay does not say since when")
	}

	// AND IT DOES NOT MOVE while the condition persists. Asserting only that it
	// is set passes against a "keep it fresh" edit that rewrites Since on every
	// failed dial — after which the page reads "the relay has been refusing
	// since <a moment ago>" for ever, which is the one fact the 0.1.10 story is
	// about (found by review, by planting exactly that).
	failingSince := relayHealthOf(t, health[down.ID], downRelay).Since
	dials := relayHealthOf(t, health[down.ID], downRelay).FailedDials
	waitFor(t, "several more dials to fail", func() bool {
		return relayHealthOf(t, h.service.Health()[down.ID], downRelay).FailedDials > dials+2
	})
	if got := relayHealthOf(t, h.service.Health()[down.ID], downRelay).Since; !got.Equal(failingSince) {
		t.Errorf("after more failed dials the state says it has been failing since %v, was "+
			"%v — the dials are what accumulate, not the moment it broke", got, failingSince)
	}

	// And it recovers on its own. The state is what the operator watches, so it
	// has to come back without anyone touching the page.
	h.relays.refuse(downRelay, 0)
	// WAITS ON THE LAST STEP, which is the log line and not the state: the state
	// flips inside markServing and the line is written after it returns, so a
	// wait on the state wins on this machine and loses on a loaded one. The first
	// version of this assertion did exactly that and failed here immediately —
	// which is the cheapest possible version of that lesson.
	//
	// The line says HOW LONG it was down, which is the only reason markServing
	// hands back the previous state at all.
	waitFor(t, "the recovery to be reported with how long the pairing was unreachable",
		func() bool { return strings.Contains(h.logs.String(), "unreachable_for") })
	if !h.service.Health()[down.ID].Working() {
		t.Errorf("the recovered connection reads as not working: %+v", h.service.Health()[down.ID])
	}
}

// The state is IN MEMORY, and after a restart it is honestly ABSENT rather than
// stale.
//
// The choice, stated because criterion 2 of the brief asks for one: this
// describes a live websocket, and a durable "serving" read back after a restart
// would claim a socket that does not exist yet. "Serving since boot" that
// silently resets is a lie an operator acts on; "not known yet", for the second
// or two before the first reload lands, is not. The DURABLE half of this bead is
// the last refusal, which is a fact about the past and survives properly.
func TestHealthIsAbsentUntilTheServiceHasTried(t *testing.T) {
	h := newHarness(t)
	if got := h.service.Health(); len(got) != 0 {
		t.Errorf("a service that has not run yet already reports %d connections as having a "+
			"state; after a restart that would be a claim about a socket nobody has opened", len(got))
	}
	if _, known := h.service.Health()[h.conn.row().ID]; known {
		t.Error("an untried connection has a state")
	}
}

// A healthy install adds NOTHING at INFO.
//
// d24.14's ruling 5 is the precedent: the trip watched Amethyst poll get_info
// and get_balance eleven times in two idle minutes, and §12 requires INFO to
// stand alone for diagnosis. A "still fine" heartbeat would make this bead's own
// remedy — a line that means something is wrong — unfindable.
func TestAHealthyConnectionAddsNoInfoNoise(t *testing.T) {
	h := newHarness(t)
	h.service.backoff = time.Millisecond
	h.service.reminder = 10 * time.Millisecond
	// The REAL clock, so the reminder periods slept through below can actually
	// come due. Against the harness's frozen one nothing gated on s.now() could
	// fire, and "silence is a claim about time" would not have been true — a
	// heartbeat on the reminder clock would have been invisible to this test
	// (found by review).
	h.service.now = time.Now

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	defer func() {
		cancel()
		for _, conn := range live {
			conn.close()
		}
		h.service.serving.Wait()
	}()
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatalf("reload: %v", err)
	}
	h.subscribed(t, testRelay)
	h.relays.deliverTo(testRelay, h.request(t, h.client, MethodGetBalance, nil))
	waitFor(t, "the request to be answered", func() bool { return len(h.relays.published()) == 1 })
	// Many reminder periods, so silence is a claim about time.
	time.Sleep(20 * h.service.reminder)

	if got := countLoggedAt(t, h.logs.String(), "INFO", ""); got != 0 {
		t.Errorf("a healthy connection produced %d INFO lines in a period where nothing "+
			"happened:\n%s", got, h.logs.String())
	}
}

// A connection that cannot reach its relay says so AGAIN while that is still
// true — and a bounded number of times.
//
// Both halves are the requirement. The trip's words: "a relay that is
// unreachable IS the app being down for every paired wallet. It deserves a
// periodic WARN while the condition persists, not one line at the moment it
// first happens." And the other direction is why it is bounded: one line per
// dial at ReconnectBackoff is twelve a minute per pairing — seventeen thousand a
// day — which is a log an operator stops reading, so the reminder would defeat
// itself.
func TestAPersistingRelayFailureIsRepeatedButBounded(t *testing.T) {
	h := newHarness(t)
	h.service.backoff = 5 * time.Millisecond
	h.service.reminder = 150 * time.Millisecond
	// THE REAL CLOCK, uniquely in this file. The harness freezes time, and the
	// thing under test is precisely how much of it has passed since the last
	// line — against a frozen clock the reminder can never come due, so the test
	// would assert that a bound works by never reaching it.
	h.service.now = time.Now
	h.relays.refuse(testRelay, 1_000_000)

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	defer func() {
		cancel()
		for _, conn := range live {
			conn.close()
		}
		h.service.serving.Wait()
	}()
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatalf("reload: %v", err)
	}

	start := time.Now()
	time.Sleep(600 * time.Millisecond)
	// Measured, not assumed: a sleep that returns late leaves the dial loop
	// running for the extra time, and a bound computed from the requested
	// duration would report that as hammering.
	span := time.Since(start)
	lines := countLoggedAt(t, h.logs.String(), "WARN", "cannot reach")

	// It repeats: one line at the moment it first happened is the shape this
	// bead exists to replace.
	if lines < 2 {
		t.Errorf("%d WARN lines in %s at a %s reminder; a condition that persists has to keep "+
			"saying so\n%s", lines, span, h.service.reminder, h.logs.String())
	}
	// And it is bounded by the REMINDER, not by the retry: the failure message
	// names how many dials went by, and a line for each of them is the noise
	// this bound exists to prevent.
	if want := int(span/h.service.reminder) + 2; lines > want {
		t.Errorf("%d WARN lines in %s, want at most %d — one line per dial (%d of them) is a "+
			"log nobody reads", lines, span, want, int(span/h.service.backoff))
	}
}

// Ruling B: a limit refusal is recorded ON THE CONNECTION, durably, and is still
// NOT an audit row.
//
// d24.14's ruling 3 stands and is not reopened here. What changed is its
// unstated premise: it assumed the CLIENT tells the user, and d24.22 measured
// that false — Amethyst renders RESTRICTED and swallows QUOTA_EXCEEDED. So the
// operator is the only possible explainer, and their only record was one INFO
// line in a rotating log.
func TestALimitRefusalIsRecordedOnTheConnectionAndStillNotAudited(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.setBudget(1_000)
	h.decodesTo("lnbc210n1overbudget", 21_000, "over budget")

	resp := h.handle(t, MethodPayInvoice, json.RawMessage(`{"invoice":"lnbc210n1overbudget"}`))
	if resp.Error == nil || resp.Error.Code != CodeQuotaExceeded {
		t.Fatalf("want QUOTA_EXCEEDED, got %+v", resp)
	}

	row, found, err := h.db.NWCConnection(t.Context(), h.conn.row().ID)
	if err != nil || !found {
		t.Fatalf("NWCConnection: found=%v err=%v", found, err)
	}
	if row.LastRefusalCode != CodeQuotaExceeded {
		t.Errorf("the connection records %q as its last refusal, want %s — without it the "+
			"operator's answer to \"my zap did not work\" is to read a table over SSH",
			row.LastRefusalCode, CodeQuotaExceeded)
	}
	if !row.LastRefusalAt.Equal(h.clock.at) {
		t.Errorf("the refusal is dated %v, want %v", row.LastRefusalAt, h.clock.at)
	}
	if rows := h.audit.events(); len(rows) != 0 {
		t.Errorf("a budget refusal wrote %d audit rows; ruling 3 stands — the trail is about "+
			"capability boundaries, and an honest client meeting its own limit would bury them",
			len(rows))
	}
}

// And the DEBUG class is not recorded, which is where the line is drawn.
//
// A method this build does not implement is a client's programming, not
// something an operator can act on — and a field that recorded it would answer
// "what stopped this app" with a fact about a button nobody pressed. The set
// that IS recorded is exactly the set reportOutcome already treats as worth an
// operator's attention.
func TestAnUnimplementedMethodIsNotRecordedAsTheLastRefusal(t *testing.T) {
	h := newHarness(t)
	resp := h.handle(t, Method("nonsense_method"), nil)
	if resp.Error == nil || resp.Error.Code != CodeNotImplemented {
		t.Fatalf("want NOT_IMPLEMENTED, got %+v", resp)
	}

	row, _, err := h.db.NWCConnection(t.Context(), h.conn.row().ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.LastRefusalCode != "" {
		t.Errorf("an unimplemented method was recorded as the last refusal (%q)",
			row.LastRefusalCode)
	}
}

// A relay that ACCEPTS and immediately drops is bounded too, and the state makes
// it visible.
//
// The failure mode the first version of this had, found by review: every
// reconnect ended the episode, so every drop looked like fresh news and produced
// a WARN and an INFO — twelve of each per minute per pairing at the production
// backoff, which is the density FailureReminderInterval exists to prevent. Worse
// than the noise, the page read "Working, 0 failed dials" at every moment the
// operator happened to look, which is the "idle and healthy while unreachable"
// sentence this whole bead was filed on.
func TestAFlappingRelayIsBoundedAndVisible(t *testing.T) {
	h := newHarness(t)
	h.service.backoff = 5 * time.Millisecond
	h.service.reminder = 150 * time.Millisecond
	h.service.now = time.Now // elapsed time is the subject; see the test above
	h.relays.flap(true)

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	defer func() {
		cancel()
		for _, conn := range live {
			conn.close()
		}
		h.service.serving.Wait()
	}()
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatalf("reload: %v", err)
	}

	start := time.Now()
	time.Sleep(600 * time.Millisecond)
	span := time.Since(start)
	logs := h.logs.String()
	warns := countLoggedAt(t, logs, "WARN", "subscription ended")
	infos := countLoggedAt(t, logs, "INFO", "")

	if want := int(span/h.service.reminder) + 2; warns > want {
		t.Errorf("a flapping relay produced %d WARN lines in %s, want at most %d — every "+
			"reconnect must not restart the reminder clock", warns, span, want)
	}
	if want := int(span/h.service.reminder) + 2; infos > want {
		t.Errorf("a flapping relay produced %d INFO lines in %s, want at most %d — an "+
			"all-clear for a break nobody was told about is the other half of the noise",
			infos, span, want)
	}
	// And it is not silent: a condition that persists keeps saying so.
	if warns == 0 {
		t.Errorf("a flapping relay said nothing at all:\n%s", logs)
	}

	// The page's half. "Working" is true at this instant and stays true; the
	// reconnect count is the only thing that survives the flapping.
	state := relayHealthOf(t, h.service.Health()[h.conn.row().ID], testRelay)
	if state.Reconnects < 2 {
		t.Errorf("after %s of flapping the state shows %d reconnects; an operator looking at "+
			"this page sees a pairing that is working, and this count is what tells them "+
			"otherwise", span, state.Reconnects)
	}
}

// An unusable row keeps its "since", and says so once — not once per reload.
//
// reload runs on every operator action: creating an unrelated pairing, saving a
// limit, toggling sending. A row broken since boot must not read as broken since
// the last time somebody saved a setting, and must not warn about it each time
// (found by review).
func TestAnUnusableRowKeepsItsSinceAcrossReloads(t *testing.T) {
	h := newHarness(t)
	var nanos atomic.Int64
	nanos.Store(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC).UnixNano())
	h.service.now = func() time.Time { return time.Unix(0, nanos.Load()).UTC() }
	broken := h.addConnection("broken", "wss://relay.broken",
		func(row *store.NWCConnection) { row.ServicePubkey = anIdentity(t).PublicKey() })

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	defer func() {
		cancel()
		for _, conn := range live {
			conn.close()
		}
		h.service.serving.Wait()
	}()
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}
	first := h.service.Health()[broken.ID].Since

	// A minute later the operator saves something unrelated, twice.
	nanos.Store(first.Add(time.Minute).UnixNano())
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}
	nanos.Store(first.Add(2 * time.Minute).UnixNano())
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}

	if got := h.service.Health()[broken.ID].Since; !got.Equal(first) {
		t.Errorf("the unusable row now reads as broken since %v, want %v — nothing about it "+
			"changed, and only the operator's unrelated saves moved this", got, first)
	}
	if got := countLoggedAt(t, h.logs.String(), "WARN", "cannot be served"); got != 1 {
		t.Errorf("an unchanged broken row was reported %d times across three reloads inside "+
			"one reminder period, want 1", got)
	}

	// And past the reminder it does say so again: a row nobody can use is a
	// condition that persists, and the same rule applies to it as to a relay.
	nanos.Store(first.Add(FailureReminderInterval + time.Minute).UnixNano())
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}
	if got := countLoggedAt(t, h.logs.String(), "WARN", "cannot be served"); got != 2 {
		t.Errorf("%d reports after the reminder period elapsed, want 2 — a broken row that "+
			"goes quiet for ever is the shape this bead replaced", got)
	}
	if got := h.service.Health()[broken.ID].Since; !got.Equal(first) {
		t.Errorf("the reminder moved \"since\" to %v; the line repeating is not the "+
			"condition restarting", got)
	}
}

// A revoked pairing's state does not come back after its dial finishes.
//
// The race review reproduced: reload revokes and closes while the connection is
// blocked inside Subscribe; the error that dial returns then goes through the
// failure path, which used to re-insert the entry a moment after reload had
// deleted it — permanently, since nothing would ever remove it again.
func TestARevokedConnectionsStateDoesNotComeBack(t *testing.T) {
	h := newHarness(t)
	h.service.backoff = time.Millisecond
	h.relays.refuse(testRelay, 1_000_000)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	defer h.relays.release()
	live := map[int64]*connection{}
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the retry to start", func() bool { return h.relays.subscribesTo(testRelay) >= 1 })
	h.relays.block()
	waitFor(t, "a dial to be in flight", func() bool { return h.relays.subscribesTo(testRelay) >= 2 })

	// Revoked WHILE that dial is outstanding.
	if _, err := h.db.RevokeNWCConnection(t.Context(), h.conn.row().ID); err != nil {
		t.Fatal(err)
	}
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}
	h.relays.release()
	h.service.serving.Wait()
	// The pairing's state is dropped by the goroutine that waits on its
	// sessions, so this waits for THAT rather than for the sessions — the
	// second-to-last step and the last one.
	h.service.forgetting.Wait()

	if state, known := h.service.Health()[h.conn.row().ID]; known {
		t.Errorf("a revoked pairing still has a state (%q since %v); nothing will ever remove "+
			"it, and a reused row id would inherit it", state.State, state.Since)
	}
}

// A row that could never be served loses its state when it goes away.
//
// Its own test because it is the one case the owning goroutine cannot cover:
// prepare rejected it, so it was never put in `live` and no goroutine ever
// existed to forget it. `nwc_connections.id` is a plain rowid that sqlite may
// reuse after a delete, which would hand a fresh pairing the previous
// occupant's "cannot be used at all".
func TestAnUnusableRowLosesItsStateWhenItIsRevoked(t *testing.T) {
	h := newHarness(t)
	broken := h.addConnection("broken", "wss://relay.broken",
		func(row *store.NWCConnection) { row.ServicePubkey = anIdentity(t).PublicKey() })

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	defer func() {
		cancel()
		for _, conn := range live {
			conn.close()
		}
		h.service.serving.Wait()
	}()
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}
	if _, known := h.service.Health()[broken.ID]; !known {
		t.Fatal("the broken row has no state at all, so this test would prove nothing")
	}

	if _, err := h.db.RevokeNWCConnection(t.Context(), broken.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}

	if state, known := h.service.Health()[broken.ID]; known {
		t.Errorf("a revoked row that was never served still has a state (%q); nothing owns it, "+
			"so nothing will ever remove it", state.State)
	}
}

// A pairing revoked while it is waiting out the backoff after a DROP makes no
// further dial.
//
// The drop path's own wait, which is the one that had drifted: resubscribe and
// serveAfterAFailedOpen both watched the connection, and this one watched only
// the service's context, so a revocation slept the full period and then dialled
// once more before attach refused it. Asserted separately because the failed-open
// test cannot reach this wait at all — it goes through resubscribe's own loop
// (found by review; the first plant of the fix printed `ok`, which is what
// showed the gap).
func TestARevokeDuringThePostDropBackoffStopsTheDial(t *testing.T) {
	h := newHarness(t)
	// Long enough that the revoke lands inside the wait, and short enough that
	// the assertion below does not dominate the package's runtime.
	h.service.backoff = 300 * time.Millisecond

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	defer func() {
		cancel()
		for _, conn := range live {
			conn.close()
		}
		h.service.serving.Wait()
	}()
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the connection to be subscribed", func() bool {
		return h.relays.subscriptionsTo(testRelay) == 1
	})

	// The relay drops it, so the connection enters the post-drop wait.
	h.relays.drop()
	waitFor(t, "the drop to be noticed", func() bool {
		return strings.Contains(h.logs.String(), "subscription ended")
	})

	// Revoked while it waits.
	if _, err := h.db.RevokeNWCConnection(t.Context(), h.conn.row().ID); err != nil {
		t.Fatal(err)
	}
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}

	dials := h.relays.subscribesTo(testRelay)
	time.Sleep(2 * h.service.backoff)
	if got := h.relays.subscribesTo(testRelay); got != dials {
		t.Errorf("a revoked pairing dialled %d more times after the backoff it was revoked "+
			"during; it stops being served on our decision, not when the timer fires",
			got-dials)
	}
}

// relayHealthOf is one relay's entry of a pairing's health, or a failure naming what
// was there instead. A nil-safe lookup would let a test about a relay session
// pass against a pairing that has no sessions at all.
func relayHealthOf(t *testing.T, health ConnectionHealth, relay string) RelayHealth {
	t.Helper()
	for _, state := range health.Relays {
		if state.Relay == relay {
			return state
		}
	}
	t.Fatalf("the pairing has no session for %s; it has %+v", relay, health.Relays)
	return RelayHealth{}
}

// 0vk.14, the layering half: what is STORED is byte-identical to what the client
// was told.
//
// This is why the quantity was removed at the composition site rather than on
// the way out to the client. Wave 28 made the refusal durable in
// `nwc_connections.last_refusal_message`, so a redaction applied at the publish
// boundary would have left the UNREDACTED number on disk while the client saw
// the redacted one — the fix exactly inverted, and the operator's own page
// showing something the client was spared.
//
// One composition, both consumers. If a later change redacts in one place, this
// fails.
func TestTheStoredRefusalIsWhatTheClientWasTold(t *testing.T) {
	const held = "sending is held on this node right now; its owner can see why on the Security page"
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.spend.held = held
	h.setBudget(1_000_000)
	h.decodesTo("lnbc210n1held", 21_000, "held")

	resp := h.handle(t, MethodPayInvoice, json.RawMessage(`{"invoice":"lnbc210n1held"}`))
	if resp.Error == nil || resp.Error.Code != CodeRestricted {
		t.Fatalf("want RESTRICTED, got %+v", resp)
	}

	row, found, err := h.db.NWCConnection(t.Context(), h.conn.row().ID)
	if err != nil || !found {
		t.Fatalf("NWCConnection: found=%v err=%v", found, err)
	}
	if row.LastRefusalMessage != resp.Error.Message {
		t.Errorf("the operator's copy and the client's differ:\n  stored: %q\n  sent:   %q\n\n"+
			"They are composed once precisely so a redaction cannot be applied to one and not "+
			"the other", row.LastRefusalMessage, resp.Error.Message)
	}
	// And neither carries a quantity. The composition site is tested separately;
	// this asserts the property survives the whole path.
	if regexp.MustCompile(`[0-9]`).MatchString(row.LastRefusalMessage) {
		t.Errorf("the stored refusal carries a number: %q", row.LastRefusalMessage)
	}
}
