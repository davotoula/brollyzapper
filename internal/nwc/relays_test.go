package nwc

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"
)

// threeRelays is a pairing's list, and the ORDER is part of every test that uses
// it: NIP-47 says the URI's relay parameter "may be more than one", and a client
// that implements only the first pairs on exactly the one at the front.
var threeRelays = []string{"wss://relay.first", "wss://relay.second", "wss://relay.third"}

// d24.18 criterion 2: the response reaches the client while ONE relay is refusing
// it — including when the refusing one is the FIRST.
//
// Order must not be load-bearing for delivery. It is load-bearing for pairing —
// a single-relay client uses the front of the list — and confusing those two is
// how a list comes to work only when the failure happens to be at the back.
func TestAResponseIsDeliveredWhileOneRelayRefuses(t *testing.T) {
	for _, dead := range threeRelays {
		t.Run("dead "+dead, func(t *testing.T) {
			h := newHarness(t)
			h.mutate(func(row *store.NWCConnection) { row.Relays = threeRelays })
			h.relays.refuseRelayPublishes(dead)

			h.handle(t, MethodGetBalance, nil)

			// Published to all three; refused by one; delivered because the
			// other two took it, and no retry was needed.
			if got := len(h.relays.published()); got != 1 {
				t.Errorf("%d publish attempts, want 1 — two relays accepted, so there was "+
					"nothing to retry", got)
			}
			targets := h.relays.publishedTo()
			if len(targets) != len(threeRelays) {
				t.Fatalf("the response was published to %v, want all of %v", targets, threeRelays)
			}
			if !strings.Contains(h.logs.String(), "an NWC request was answered") {
				t.Errorf("the request was not answered while %s was refusing:\n%s", dead,
					h.logs.String())
			}
			if loggedAt(t, h.logs.String(), "WARN", "no relay accepted") {
				t.Errorf("one relay refusing was reported as a delivery failure; the other two "+
					"took it, which is what the list is for:\n%s", h.logs.String())
			}
		})
	}
}

// And a pairing whose relays are ALL refusing is still a failure, said out loud.
//
// The other half of the pair above: a list that swallowed a total outage would be
// worse than one relay, because the operator would have no line to find.
func TestAResponseNoRelayTakesIsStillReported(t *testing.T) {
	h := newHarness(t)
	h.service.responseRetries = []time.Duration{time.Millisecond, time.Millisecond}
	h.mutate(func(row *store.NWCConnection) { row.Relays = threeRelays })
	h.relays.refusePublishesFor(100)

	h.handle(t, MethodGetBalance, nil)

	if !loggedAt(t, h.logs.String(), "WARN", "no relay accepted") {
		t.Errorf("every relay refused and nothing said so:\n%s", h.logs.String())
	}
}

// d24.18 criterion 3, and it is the sharp one: the same request now arrives on
// three sockets, and must be EXECUTED once.
//
// §8's replay cache elects one handler per request id in a single INSERT, so the
// machinery predates the list — what is new is that the race it was written for
// (a relay redelivering after a restart) is now the ordinary case, three times
// per request. The three answers must also agree: the cache stores PLAINTEXT and
// re-encrypts per delivery, so a client reading any socket gets the same answer
// rather than three different ones.
func TestOneRequestOnEveryRelayIsExecutedOnce(t *testing.T) {
	h := newHarness(t, threeRelays...)

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	defer func() {
		cancel()
		for _, conn := range live {
			conn.close()
		}
		h.service.serving.Wait()
		h.service.forgetting.Wait()
	}()
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatalf("reload: %v", err)
	}
	h.subscribed(t, threeRelays...)

	// THE WINNER IS HELD while the other two deliveries arrive, and without that
	// this test detected its own headline regression about one run in six: a fast
	// method finishes before the losers reach the claim, so they replay a real
	// answer and the placeholder path — the thing the sibling window exists for —
	// is never taken. Measured by review at 10 failures in 60 with the guard
	// inverted; the other 50 passed for the wrong reason.
	//
	// Holding the wallet makes the winner genuinely still working when the losers
	// claim, which is what a pay_invoice looks like and what the field will do.
	release := make(chan struct{})
	h.wallet.hold(release)

	// ONE event, delivered on all three sockets at once — which is exactly what
	// a relay fleet that all saw the client's request does.
	event := h.request(t, h.client, MethodGetBalance, nil)
	before := h.wallet.balanceCalls()
	for _, relay := range threeRelays {
		h.relays.deliverTo(relay, event)
	}
	// Both losers have been through the claim by now: they either published or
	// deliberately did not, and either way they are done.
	waitFor(t, "the two duplicate deliveries to be handled", func() bool {
		return countLoggedAt(t, h.logs.String(), "DEBUG",
			"arrived on more than one of this pairing's relays") == 2
	})
	close(release)

	// AT LEAST ONE, not exactly one, and the number is genuinely timing-dependent:
	// a delivery that loses the claim while the winner is still working says
	// nothing (SiblingDeliveryWindow), while one that loses after the winner has
	// finished replays the completed answer. Both are correct and both are
	// consistent, which is why the assertions below are about the CONTENT of the
	// answers rather than how many there are.
	//
	// The first version waited for exactly one and flaked two runs in eight under
	// -race: the count passes through 1 on its way to 3, and a poll every
	// millisecond can miss it. An equality on a value that is still moving is an
	// assertion about scheduling.
	waitFor(t, "the request to be answered", func() bool { return len(h.relays.published()) > 0 })
	// A moment for any further answers, so what is asserted is the settled state
	// rather than the first thing seen.
	time.Sleep(50 * time.Millisecond)

	if executed := h.wallet.balanceCalls() - before; executed != 1 {
		t.Errorf("the request was EXECUTED %d times, want 1 — the replay cache elects one "+
			"handler per request id, and three sockets is now the ordinary case rather than "+
			"the crash window it was written for", executed)
	}

	// CONSISTENT ANSWERS, which is the half of the criterion the claim race can
	// break. Every response published for this request says the same thing, and
	// none of them is the in-flight placeholder.
	//
	// This is the criterion earning its place. Before SiblingDeliveryWindow, a
	// delivery that lost the race while the winner was still working published
	// the cached PLACEHOLDER — so two of the pairing's relays carried "this
	// request is already being processed" alongside the real answer on the third,
	// and a client that takes the first response it sees would have shown a
	// failure for a request that succeeded. A fast method hides that (the winner
	// finishes first, so the losers replay a real answer); a payment would not.
	answers := h.relays.published()
	if len(answers) == 0 {
		t.Fatal("the request was never answered")
	}
	first := h.open(t, answers[0])
	for i, answer := range answers {
		plaintext := h.open(t, answer)
		if plaintext != first {
			t.Errorf("answer %d is %q and the first is %q — a client reading a different "+
				"socket would get a different answer to one question", i+1, plaintext, first)
		}
		if strings.Contains(plaintext, inProgressMessage) {
			t.Errorf("answer %d is the in-flight placeholder (%q), racing the real answer on "+
				"the pairing's other relays", i+1, plaintext)
		}
	}
	if !strings.Contains(first, "balance") {
		t.Errorf("the published answer is %q, want the real one", first)
	}
	// That each answer reaches every relay is asserted by
	// TestTheResponseGoesToTheConnectionsOwnRelays and by the one-relay-refusing
	// test above; counting targets here would count the info event's publishes
	// too, and an assertion that has to explain away half its input is one that
	// will be read as noise the first time it fails.
}

// A client that asks AGAIN, later, is told its request is still running.
//
// The other side of SiblingDeliveryWindow, and the half a frozen clock cannot
// see: with s.now() never advancing, every duplicate is a sibling and the
// placeholder path is unreachable — inverting the comparison left the whole suite
// green (found by review). The placeholder exists so a client is told its payment
// is in flight rather than being invited to start a second one under a new
// request id, which is money, so it is worth an assertion that can fail.
func TestAClientAskingAgainLaterIsToldTheRequestIsRunning(t *testing.T) {
	h := newHarness(t)
	var nanos atomic.Int64
	nanos.Store(h.clock.at.UnixNano())
	h.service.now = func() time.Time { return time.Unix(0, nanos.Load()).UTC() }

	// The winner is still working when the duplicate arrives.
	release := make(chan struct{})
	h.wallet.hold(release)
	event := h.request(t, h.client, MethodGetBalance, nil)
	done := make(chan struct{})
	go func() { defer close(done); h.service.handle(t.Context(), h.conn, event) }()
	waitFor(t, "the first delivery to be working", func() bool { return h.wallet.balanceCalls() == 1 })

	// A SIBLING, milliseconds later: silence.
	h.service.handle(t.Context(), h.conn, event)
	if got := len(h.relays.published()); got != 0 {
		t.Errorf("a duplicate arriving at once published %d answers; it is another relay's copy "+
			"of a request already being handled", got)
	}

	// The same client asking again, well past the window: it is told.
	nanos.Store(h.clock.at.Add(SiblingDeliveryWindow + time.Second).UnixNano())
	h.service.handle(t.Context(), h.conn, event)
	if got := len(h.relays.published()); got != 1 {
		t.Fatalf("a client asking again after %s published %d answers, want 1 — silence looks "+
			"identical to a service that is down, and for a payment it invites a second one "+
			"under a new request id", SiblingDeliveryWindow, got)
	}
	if answer := h.open(t, h.relays.published()[0]); !strings.Contains(answer, inProgressMessage) {
		t.Errorf("the answer to a re-send is %q, want the in-flight placeholder", answer)
	}

	close(release)
	<-done
}

// A pairing keeps working while ONE of its relays is unreachable, and the page
// can tell which.
//
// The state is per relay since d24.18 because a pairing with two of three up is
// neither serving nor retrying — see ConnectionHealth. "Working" is the
// operator's question and it is answered by any relay being up; which one is
// down is the diagnosis underneath it.
func TestAPairingWorksWhileOneOfItsRelaysDoesNot(t *testing.T) {
	h := newHarness(t, threeRelays...)
	h.service.backoff = time.Millisecond
	// The FIRST one, which is the relay a single-relay client would have used.
	h.relays.refuse(threeRelays[0], 1_000_000)

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	defer func() {
		cancel()
		for _, conn := range live {
			conn.close()
		}
		h.service.serving.Wait()
		h.service.forgetting.Wait()
	}()
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatalf("reload: %v", err)
	}
	h.subscribed(t, threeRelays[1], threeRelays[2])
	waitFor(t, "the dead relay to report itself", func() bool {
		return len(h.service.Health()[h.conn.row().ID].Relays) == len(threeRelays)
	})

	health := h.service.Health()[h.conn.row().ID]
	if !health.Working() {
		t.Errorf("a pairing with two of three relays up reads as not working: %+v", health)
	}
	if got := relayHealthOf(t, health, threeRelays[0]).State; got != HealthRetrying {
		t.Errorf("the unreachable relay is %q, want %q", got, HealthRetrying)
	}
	for _, up := range threeRelays[1:] {
		if got := relayHealthOf(t, health, up).State; got != HealthServing {
			t.Errorf("%s is %q, want %q", up, got, HealthServing)
		}
	}

	// And it still ANSWERS, on a relay that is up.
	h.relays.deliverTo(threeRelays[1], h.request(t, h.client, MethodGetBalance, nil))
	waitFor(t, "the request to be answered on a relay that is up", func() bool {
		return len(h.relays.published()) == 1
	})
}

// A pairing announces itself ONCE when it comes up, however many relays it has.
//
// Two findings met here. The announce is guarded so a replaceable event is not
// published once per relay — but the guard read the count through a SECOND call
// after attaching, and reload starts every session at once: two sessions
// attaching before either looked would both see the final count and NEITHER
// would announce, so a brand-new pairing would publish no info event at all. The
// count now comes back from attach, under the lock the insert already holds.
func TestAPairingAnnouncesItselfExactlyOnceOnEveryRelay(t *testing.T) {
	h := newHarness(t, threeRelays...)

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	defer func() {
		cancel()
		for _, conn := range live {
			conn.close()
		}
		h.service.serving.Wait()
		h.service.forgetting.Wait()
	}()
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatalf("reload: %v", err)
	}
	h.subscribed(t, threeRelays...)
	// A moment for any further announcements that must not come.
	time.Sleep(50 * time.Millisecond)

	events := h.relays.infoEvents()
	if len(events) != 1 {
		t.Errorf("%d info events for one pairing coming up, want 1 — a wallet app builds its "+
			"buttons from this, and it is replaceable, so three copies on three relays is "+
			"nine publishes of one fact", len(events))
	}
	if len(events) == 0 {
		t.Fatal("a new pairing published NO info event; a wallet app would show a wallet that " +
			"supports nothing")
	}
	// And it reached every relay, because the client may read any of them.
	for _, relay := range threeRelays {
		var found bool
		for _, target := range h.relays.publishedTo() {
			if target == relay {
				found = true
			}
		}
		if !found {
			t.Errorf("the info event never reached %s; a client listening there sees a wallet "+
				"that supports nothing", relay)
		}
	}
}

// A relay that drops and comes back is re-announced TO ITSELF, not to the whole
// pairing.
//
// Re-announcing covers that relay having lost the event while we were away,
// which is a fact about that relay. Publishing to the set would put a fresh copy
// on the ones that never lost it — and a pairing whose sessions all drop and
// recover together, which is what a Pi losing its network looks like, would
// produce N×N publishes of a replaceable event.
func TestAReconnectReannouncesOnlyToTheRelayThatCameBack(t *testing.T) {
	h := newHarness(t, threeRelays...)
	h.service.backoff = time.Millisecond

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	defer func() {
		cancel()
		for _, conn := range live {
			conn.close()
		}
		h.service.serving.Wait()
		h.service.forgetting.Wait()
	}()
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatalf("reload: %v", err)
	}
	h.subscribed(t, threeRelays...)
	waitFor(t, "the opening announcement", func() bool { return len(h.relays.infoEvents()) == 1 })
	before := len(h.relays.publishedTo())

	// ONE relay drops.
	h.relays.dropRelay(threeRelays[1])
	waitFor(t, "the dropped relay to come back", func() bool {
		return h.relays.subscriptionsTo(threeRelays[1]) == 2
	})
	waitFor(t, "the re-announcement", func() bool { return len(h.relays.infoEvents()) == 2 })
	time.Sleep(20 * time.Millisecond)

	// ONE new target, and it is the relay that came back.
	targets := h.relays.publishedTo()[before:]
	if len(targets) != 1 || targets[0] != threeRelays[1] {
		t.Errorf("the re-announcement went to %v, want exactly [%s] — the other two never lost "+
			"the event", targets, threeRelays[1])
	}
}

// A row naming the same relay twice is refused rather than half-served.
//
// The sessions key on the relay URL, so a duplicate means the second attach
// overwrites the first subscription — which is then never closed, since close()
// iterates the map and the map holds only the survivor — while the first session
// to exit detaches that survivor and leaves the other reading a nil channel for
// ever. Found by review.
func TestARowNamingOneRelayTwiceIsRefused(t *testing.T) {
	h := newHarness(t)
	h.addConnection("a pairing that repeats itself", "wss://relay.twice",
		func(row *store.NWCConnection) {
			row.Relays = []string{"wss://relay.twice", "wss://relay.twice"}
		})

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	defer func() {
		cancel()
		for _, conn := range live {
			conn.close()
		}
		h.service.serving.Wait()
		h.service.forgetting.Wait()
	}()
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatalf("reload: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if got := h.relays.subscribesTo("wss://relay.twice"); got != 0 {
		t.Errorf("a row naming one relay twice opened %d subscriptions; one of them would be "+
			"leaked and the other left reading nothing", got)
	}
	if !loggedAt(t, h.logs.String(), "WARN", "cannot be served") {
		t.Errorf("a row naming one relay twice was not reported:\n%s", h.logs.String())
	}
}

// A shutdown with a worker in flight on one relay and requests queued on another
// is race-free.
//
// The shape d24.18 introduced and review reproduced: `conn.working` belongs to
// the CONNECTION, and with a session per relay a `defer conn.working.Wait()` in
// serve is one session waiting on a group another session is still adding to.
// That is documented WaitGroup misuse — "calls with a positive delta that occur
// when the counter is zero must happen before a Wait" — and it panics the process
// when the Add lands as the counter reaches zero. The workers are waited on once
// now, by the goroutine that already knows every session has gone.
//
// It needs -race and this exact arrangement to show: every fake answers instantly
// otherwise, so `working` is almost always zero and the window never opens. A
// shutdown during a pay_invoice with its siblings queued behind it is the
// ordinary multi-relay state, not a corner.
func TestAShutdownWithWorkInFlightOnAnotherRelayIsRaceFree(t *testing.T) {
	relays := []string{"wss://relay.busy", "wss://relay.queued"}
	h := newHarness(t, relays...)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	live := map[int64]*connection{}
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatalf("reload: %v", err)
	}
	h.subscribed(t, relays...)

	// One worker held on the first relay: this is the payment that must not be
	// abandoned mid-ladder.
	release := make(chan struct{})
	h.wallet.hold(release)
	h.relays.deliverTo(relays[0], h.request(t, h.client, MethodGetBalance, nil))
	waitFor(t, "the held worker to start", func() bool { return h.wallet.balanceCalls() == 1 })

	// And more work queued on the second relay's session, each a DIFFERENT
	// request so none is absorbed by the replay cache.
	for range 4 {
		h.relays.deliverTo(relays[1], h.request(t, h.client, MethodGetInfo, nil))
	}

	// The connection closes while all of that is outstanding, and the held worker
	// is released into the teardown.
	for _, conn := range live {
		conn.close()
	}
	close(release)

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.service.serving.Wait()
		h.service.forgetting.Wait()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the teardown did not finish; a session is waiting on work that another " +
			"session is still starting")
	}
}
