package nwc

import (
	"strings"
	"testing"
	"time"
)

// d24.25: a response that one publish fails to deliver is tried again.
//
// The 0.1.9 and 0.1.10 trips both logged "no relay accepted an NWC response",
// which is exactly a spinner on the phone: the request was handled, the money
// may have moved, and the answer never arrived. One attempt and a WARN was the
// whole of the delivery policy.
func TestAResponseRefusedOnceIsRetriedAndDelivered(t *testing.T) {
	h := newHarness(t)
	h.service.responseRetries = []time.Duration{time.Millisecond, time.Millisecond}
	h.relays.refusePublishesFor(1)

	h.handle(t, MethodGetBalance, nil)

	if got := len(h.relays.published()); got != 2 {
		t.Errorf("%d publish attempts for one response, want 2 — the first was refused and "+
			"nothing else will ever deliver this answer", got)
	}
	if !loggedAt(t, h.logs.String(), "WARN", "no relay accepted") {
		return // delivered, which is the point
	}
	t.Errorf("the response was delivered on the retry and still logged a failure:\n%s",
		h.logs.String())
}

// Three attempts, and no more.
func TestAResponseIsAttemptedThreeTimesAndThenGivenUpOn(t *testing.T) {
	h := newHarness(t)
	h.service.responseRetries = []time.Duration{time.Millisecond, time.Millisecond}
	h.relays.refusePublishesFor(100)

	h.handle(t, MethodGetBalance, nil)

	if got := len(h.relays.published()); got != 3 {
		t.Errorf("%d publish attempts, want 3", got)
	}
	// The give-up is not silent. §12: an operator asking why their phone spun
	// must not need debug mode.
	if !loggedAt(t, h.logs.String(), "WARN", "no relay accepted") {
		t.Errorf("the service gave up on a response without saying so:\n%s", h.logs.String())
	}
}

// The SPACING is the real one, and this test uses it rather than an injected
// value.
//
// A retry policy tested only through a knob set to a millisecond asserts that
// the loop runs, not that it waits — the same trap a backoff test in this
// package fell into by capping the backoff at 1 ms. Only the first gap is waited
// for, so the test costs one second rather than three.
func TestTheRetrySpacingIsTheRealOne(t *testing.T) {
	h := newHarness(t)
	h.relays.refusePublishesFor(100)

	// THE NUMBER, not just the constant. Comparing the measured gap against
	// ResponseRetryDelays[0] asserts that the loop reads its own constant, which
	// it would do at fifty milliseconds too — the value is the policy, so the
	// value is what is pinned (found by review).
	const wantFirstGap = time.Second
	if ResponseRetryDelays[0] != wantFirstGap {
		t.Fatalf("the first retry delay is %s, want %s — three attempts at 0 s, +1 s and +3 s "+
			"is the policy, chosen against a sixty second client budget",
			ResponseRetryDelays[0], wantFirstGap)
	}

	done := make(chan struct{})
	go func() { defer close(done); h.handle(t, MethodGetBalance, nil) }()
	// A DEADLINE OF ITS OWN, because waitFor's three seconds has to contain a
	// real one-second delay and leaves two for a loaded runner — which is a false
	// FAIL waiting to happen under -race -count=20.
	deadline := time.Now().Add(20 * time.Second)
	for len(h.relays.published()) < 2 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if len(h.relays.published()) < 2 {
		t.Fatal("the response was never retried")
	}

	times := h.relays.publishTimes()
	if gap := times[1].Sub(times[0]); gap < wantFirstGap {
		t.Errorf("the second attempt came %s after the first, want at least %s — a retry that "+
			"does not wait is a relay being hammered", gap, wantFirstGap)
	}
	<-done
}

// Each attempt is bounded by its own timeout, and it is FIVE seconds rather than
// the thirty the receipt path uses.
//
// The number is the one that matters most in the whole policy: a 30 s attempt
// spends the client's entire budget by itself, and every retry after it
// publishes to a subscription that is already gone. Asserted by reading the
// deadline the attempt was given — waiting for it to expire would cost five
// seconds per run and prove no more.
func TestEachPublishAttemptIsBoundedByTheResponseTimeout(t *testing.T) {
	h := newHarness(t)
	before := time.Now()

	h.handle(t, MethodGetBalance, nil)

	deadline, ok := h.relays.publishDeadline(0)
	if !ok {
		t.Fatal("the publish attempt carried no deadline at all; it is bounded only by the " +
			"pool's 30 s, which is the whole of the client's budget")
	}
	// Generous on the upper side: `before` is taken outside the handle, so
	// anything that delays getting to the publish — a loaded runner, -race — adds
	// to the measured budget and would otherwise be a false failure. The lower
	// bound is the one that matters, and nothing can inflate it.
	budget := deadline.Sub(before)
	if budget < ResponseAttemptTimeout-time.Second || budget > ResponseAttemptTimeout+10*time.Second {
		t.Errorf("the attempt was given %s, want about %s", budget.Round(time.Millisecond),
			ResponseAttemptTimeout)
	}
}

// A relay that takes the event and never answers is given up on rather than
// waited for.
//
// The timeout is injected here and asserted at its real value in the test above:
// this one is about the behaviour when it expires, and running it against five
// real seconds would add a hundred to the gate's `-count=20` pass.
func TestAHungRelayDoesNotHoldTheWorker(t *testing.T) {
	h := newHarness(t)
	h.service.attemptTimeout = 20 * time.Millisecond
	h.service.responseRetries = []time.Duration{time.Millisecond, time.Millisecond}
	h.relays.holdPublishes()

	done := make(chan struct{})
	go func() { defer close(done); h.handle(t, MethodGetBalance, nil) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the response publish is still waiting on a relay that never answered; the " +
			"worker it holds is one of four this connection has")
	}
	if got := len(h.relays.published()); got != 3 {
		t.Errorf("%d attempts against a hung relay, want 3 — each one bounded by its own "+
			"timeout", got)
	}
}

// A DEADLINE, not just a count: a request the client has almost given up on gets
// ONE attempt, not three.
//
// This is the criterion that fails if someone implements the count and forgets
// the clock. Amethyst's budget is a hard 60 s from ITS publish, and when the
// timer fires it unsubscribes — so a response published at 61 s is not late, it
// is unreceivable, and the attempts that produced it spent a socket for nothing.
func TestARequestThatIsAlmostOutOfTimeGetsOneAttempt(t *testing.T) {
	h := newHarness(t)
	h.service.responseRetries = []time.Duration{time.Millisecond, time.Millisecond}
	h.relays.refusePublishesFor(100)

	// The client sent this 58 seconds ago: inside §8's freshness window, and
	// with less than the delivery margin of its own budget left.
	event := h.requestAt(t, h.client, MethodGetBalance, nil, h.clock.at.Add(-58*time.Second))
	h.service.handle(t.Context(), h.conn, event)

	if got := len(h.relays.published()); got != 1 {
		t.Errorf("%d attempts for a request that is 58 seconds old, want 1 — the client's "+
			"60 second timer has all but fired, and it unsubscribes when it does", got)
	}
}

// A relay that ACCEPTED is not asked twice — asserted where ONE of a pairing's
// relays takes it and the others do not.
//
// The single-relay case is already covered by the first test in this file, which
// this one used to duplicate byte for byte (found by review). What it adds is the
// case the list makes ordinary: nostr.Accepted counts successes across the whole
// set, so one relay taking the event is delivery, and a retry against the two
// that refused would republish to the one that already has it.
func TestAResponseOneRelayAcceptedIsNotPublishedAgain(t *testing.T) {
	h := newHarness(t, "wss://relay.takes-it", "wss://relay.refuses")
	h.service.responseRetries = []time.Duration{time.Millisecond, time.Millisecond}
	h.relays.refuseRelayPublishes("wss://relay.refuses")

	h.handle(t, MethodGetBalance, nil)

	if got := len(h.relays.published()); got != 1 {
		t.Errorf("%d publish attempts, want 1 — one relay accepted, which is delivery, and the "+
			"other one refusing is what a list is for", got)
	}
	if loggedAt(t, h.logs.String(), "WARN", "no relay accepted") {
		t.Errorf("a delivered response was reported as a failure:\n%s", h.logs.String())
	}
}

// Ruling A: the retry names the connection's OWN relay and no other.
//
// Worth its own test even though it looks obvious, because d24.18 is about to
// make multi-relay publishing normal in the neighbouring code — and the one
// thing that must never become normal is a fallback to the operator's relays.
func TestTheRetryNeverNamesAnotherRelay(t *testing.T) {
	h := newHarness(t)
	h.service.responseRetries = []time.Duration{time.Millisecond, time.Millisecond}
	h.relays.refusePublishesFor(100)

	h.handle(t, MethodGetBalance, nil)

	for i, target := range h.relays.publishedTo() {
		if target != testRelay {
			t.Errorf("attempt %d went to %q; this connection's relay is %q, and a response "+
				"sent anywhere else is a pairing announced somewhere it never agreed to be",
				i, target, testRelay)
		}
	}
}

// A request that arrived too late still gets its answer published.
//
// §8 answers a request outside the freshness window with "request expired" so the
// client stops waiting — and a request is outside that window precisely when it
// is more than RequestWindow old, which is the same sixty seconds as the client
// budget. So the delivery deadline had ALREADY passed for every stale request,
// and the one answer §8 asks for most was the one never published: a client whose
// clock runs slow against ours sent something perfectly fresh, was judged stale,
// and heard nothing at all.
//
// Found by review. The rule now is that the budget bounds RETRIES; the first
// attempt is the answer and is always made.
func TestAStaleRequestsRefusalIsStillPublished(t *testing.T) {
	h := newHarness(t)

	// Older than §8's freshness window, which is what makes it stale.
	event := h.requestAt(t, h.client, MethodGetBalance, nil,
		h.clock.at.Add(-RequestWindow-time.Second))
	resp, answered := h.service.handle(t.Context(), h.conn, event)

	if !answered || resp.Error == nil {
		t.Fatalf("a stale request was answered %+v (answered=%v), want an error", resp, answered)
	}
	if got := len(h.relays.published()); got != 1 {
		t.Errorf("%d responses published for a stale request, want 1 — the client is told to "+
			"stop waiting, or it does not", got)
	}
	if got := h.open(t, h.relays.published()[0]); !strings.Contains(got, "expired") {
		t.Errorf("the published answer is %q, want the expiry §8 requires", got)
	}
}
