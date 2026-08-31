package nwc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

// d24.24: a connection whose relay refuses at boot must be RETRIED, without the
// operator touching anything and without a restart.
//
// The 0.1.10 field trip is what this reproduces. relay.damus.io refused 8 of 20
// websocket upgrades from inside the app's container, it was the shipped
// pre-filled default, and reload() answered a refused upgrade with one WARN and
// a `continue` — so the connection never entered the live map, no goroutine was
// started for it, and serve()'s retry was unreachable. Thirteen minutes of an
// app that looked idle and healthy while every paired wallet was talking to
// nobody.
func TestAConnectionWhoseRelayRefusedAtBootIsRetriedAndRecovers(t *testing.T) {
	h := newHarness(t)
	h.service.backoff = time.Millisecond
	// Refused three times, then the relay takes it — which is the shape the trip
	// measured, not a relay that is simply down.
	h.relays.refuse(testRelay, 3)

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	// CANCEL FIRST, then close, then wait. The retry goroutines end on the
	// context or on the connection; waiting on them before either has happened
	// is a test that hangs rather than fails.
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

	// subscriptionsTo, not subscribesTo: the refused dials are counted too, and
	// delivering to a subscription that does not exist yet is a test waiting on
	// the second-to-last step of the thing it is asserting.
	waitFor(t, "the connection to reach the relay after it recovered", func() bool {
		return h.relays.subscriptionsTo(testRelay) >= 1
	})

	// The operator's own symptom, inverted: a request sent after the relay came
	// back is ANSWERED. Asserting the subscribe alone would pass against a retry
	// that reconnected and then served nobody.
	h.relays.deliverTo(testRelay, h.request(t, h.client, MethodGetBalance, nil))
	waitFor(t, "a request sent after the relay recovered to be answered", func() bool {
		return len(h.relays.published()) == 1
	})
}

// And the other half of the distinction: a row no relay will ever fix is NOT
// retried.
//
// Three ways for that to be true, and all three fail before a socket is opened —
// which is why the retry has to be reached from the SUBSCRIBE failing and not
// from open() failing. A retry that did not separate them would ask the relay
// about a corrupt row every ReconnectBackoff for ever, and could not even build
// a connection to retry with: the identity that newConnection needs is the thing
// that failed to parse.
func TestAStructurallyBrokenConnectionIsNotRetried(t *testing.T) {
	cases := []struct {
		name   string
		relay  string
		break_ func(row *store.NWCConnection)
	}{
		{
			name:   "no relay at all",
			relay:  "",
			break_: func(row *store.NWCConnection) { row.Relays = nil },
		},
		{
			name:   "a service key that does not parse",
			relay:  "wss://relay.unparseable",
			break_: func(row *store.NWCConnection) { row.ServicePrivkey = secret.New("not a private key") },
		},
		{
			name:   "a stored pubkey that is not this key's",
			relay:  "wss://relay.mismatch",
			break_: func(row *store.NWCConnection) { row.ServicePubkey = anIdentity(t).PublicKey() },
		},
		{
			// More relays than a pairing may hold: sockets are the scarce thing
			// on a Pi, and the cap is a property of the ROW rather than of the
			// form that usually writes it (d24.18, condition 9).
			name:  "more relays than may be served",
			relay: "wss://relay.over-cap",
			break_: func(row *store.NWCConnection) {
				row.Relays = []string{"wss://relay.one", "wss://relay.two",
					"wss://relay.three", "wss://relay.over-cap"}
			},
		},
		{
			// Not reachable through the create form, which gates on the same
			// predicate — but a row written by an older build or by hand is, and
			// the pool rejects a malformed URL BEFORE it dials, so this would
			// otherwise be retried for ever against an address no relay can be
			// at (found by review).
			name:   "a relay address that is not one",
			relay:  "not a relay address",
			break_: func(row *store.NWCConnection) { row.Relays = []string{"not a relay address"} },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			const backoff = 20 * time.Millisecond
			h.service.backoff = backoff
			h.addConnection("broken", tc.relay, tc.break_)

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

			// Several backoff periods, so "not retried" is a claim about time
			// rather than about how fast this assertion ran.
			time.Sleep(10 * backoff)

			if got := h.relays.subscribesTo(tc.relay); got != 0 {
				t.Errorf("a row with %s was asked of its relay %d times; no relay can fix it, "+
					"so every one of those is a hot loop against a corrupt row", tc.name, got)
			}
			if got := countLoggedAt(t, h.logs.String(), "WARN", "cannot be served"); got != 1 {
				t.Errorf("a row with %s was reported %d times, want exactly 1 — the operator "+
					"needs to be told once, not every backoff\n%s", tc.name, got, h.logs.String())
			}
		})
	}
}

// One unusable connection does not stop the others.
//
// This property exists today because reload() `continue`s past a failed open,
// and it is exactly the kind of thing a restructure costs quietly — so it is
// asserted rather than assumed. The unreachable connection here never recovers,
// which is the harder case: it is still retrying while the assertion runs.
func TestOneUnreachableRelayDoesNotStopTheOtherConnections(t *testing.T) {
	h := newHarness(t)
	h.service.backoff = 5 * time.Millisecond
	const downRelay = "wss://relay.down"
	h.addConnection("a pairing whose relay is down", downRelay, nil)
	h.relays.refuse(downRelay, 1_000_000)

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	// CANCEL FIRST, then close, then wait. The retry goroutines end on the
	// context or on the connection; waiting on them before either has happened
	// is a test that hangs rather than fails.
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

	waitFor(t, "the reachable connection to be subscribed", func() bool {
		return h.relays.subscriptionsTo(testRelay) == 1
	})
	h.relays.deliverTo(testRelay, h.request(t, h.client, MethodGetBalance, nil))
	waitFor(t, "the reachable connection to answer while the other one is still retrying",
		func() bool { return len(h.relays.published()) == 1 })

	// The first retry is one backoff away, so this waits rather than asserting
	// immediately: without it the test would pass on a connection that had been
	// abandoned, which is the very thing it exists to rule out.
	waitFor(t, "the unreachable connection to be genuinely still retrying, so that this test "+
		"proves the other pairing survived it", func() bool {
		return h.relays.subscribesTo(downRelay) >= 2
	})
}

// Shutdown is clean while a connection is mid-retry.
//
// Through Run rather than reload, because Run's teardown is the thing being
// asserted: the retry goroutine has to be waited on by s.serving, and a
// goroutine started outside it would leave the process holding a socket nobody
// closes — and would pass every other test here.
func TestShutdownIsCleanWhileAConnectionIsRetrying(t *testing.T) {
	h := newHarness(t)
	h.service.backoff = 5 * time.Millisecond
	h.relays.refuse(testRelay, 1_000_000)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.service.Run(ctx, nil, nil) }()

	waitFor(t, "the retry loop to be running", func() bool { return h.relays.subscribesTo(testRelay) >= 2 })
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v on shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run's teardown did not return while a connection was mid-retry; the retry " +
			"goroutine is not being waited on by s.serving, or it does not watch ctx")
	}
}

// The retry waits. A loop that reached the relay as fast as it could would
// satisfy every test above.
//
// The backoff here is 50 ms and not 1 ms on purpose: at 1 ms a busy loop and a
// correct one are indistinguishable inside the noise, which is how a backoff
// test comes to assert nothing. At 50 ms over 250 ms a correct loop makes about
// five attempts and a busy one makes thousands.
func TestTheRetryAfterAFailedOpenWaitsOutTheBackoff(t *testing.T) {
	h := newHarness(t)
	const backoff = 50 * time.Millisecond
	h.service.backoff = backoff
	h.relays.refuse(testRelay, 1_000_000)

	ctx, cancel := context.WithCancel(t.Context())
	live := map[int64]*connection{}
	// CANCEL FIRST, then close, then wait. The retry goroutines end on the
	// context or on the connection; waiting on them before either has happened
	// is a test that hangs rather than fails.
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

	waitFor(t, "the retry to start", func() bool { return h.relays.subscribesTo(testRelay) >= 2 })
	before := h.relays.subscribesTo(testRelay)
	start := time.Now()
	time.Sleep(250 * time.Millisecond)
	// The span is MEASURED, not assumed. A sleep that returns late on a loaded
	// runner leaves the dial loop running for the extra time, and a bound
	// computed from the requested duration would call that hammering (found by
	// review).
	span := time.Since(start)
	got := h.relays.subscribesTo(testRelay) - before

	// Only an upper bound. "It retried at all" is what the first test in this
	// file asserts.
	if want := int(span/backoff) + 2; got > want {
		t.Errorf("%d retries in %s at a %s backoff, want at most %d — the relay is being "+
			"hammered rather than waited out", got, span, backoff, want)
	}
}

// countLoggedAt is loggedAt's counting sibling: "reported once" is a different
// claim from "reported", and a retry that logs every backoff satisfies the
// second one.
func countLoggedAt(t *testing.T, logs, level, substr string) int {
	t.Helper()
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		msg, _ := entry["msg"].(string)
		if entry["level"] == level && strings.Contains(msg, substr) {
			n++
		}
	}
	return n
}

// Revoking a connection whose relay is down stops it dialling — now, not at the
// next restart.
//
// Found while building the retry above, and it is the same rule consume already
// follows: a connection stops being served on OUR decision. resubscribe watched
// only the service's context, so a revoked pairing went on asking a dead relay
// every backoff for as long as the process lived. It answered nobody — attach
// refuses a closed connection — but a failed open reaches that loop far more
// often than a dropped socket ever did, so the leak is now the ordinary case
// rather than a rare one.
func TestRevokingAConnectionStopsItsRetry(t *testing.T) {
	h := newHarness(t)
	const backoff = 10 * time.Millisecond
	h.service.backoff = backoff
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
	waitFor(t, "the retry to start", func() bool { return h.relays.subscribesTo(testRelay) >= 2 })

	if _, err := h.db.RevokeNWCConnection(t.Context(), h.conn.row().ID); err != nil {
		t.Fatal(err)
	}
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatalf("reload: %v", err)
	}

	// The service is still running: ctx is live and nothing was cancelled. What
	// has to end is this connection's goroutine.
	stopped := make(chan struct{})
	go func() { h.service.serving.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("a revoked connection is still retrying; its dialling ends only when the " +
			"process does")
	}

	// And it stopped ASKING, which is the observable half — a goroutine that
	// returned is not evidence on its own that nothing else took over.
	before := h.relays.subscribesTo(testRelay)
	time.Sleep(5 * backoff)
	if got := h.relays.subscribesTo(testRelay); got != before {
		t.Errorf("a revoked connection asked its relay %d more times", got-before)
	}
}

// Shutdown WAITS for a connection whose dial is in flight.
//
// Its own test because the obvious one cannot catch what it claims to.
// TestShutdownIsCleanWhileAConnectionIsRetrying asserts that Run returns, and a
// retry goroutine started OUTSIDE s.serving lets it return sooner rather than
// later — so that test passes against the orphan it is supposed to rule out.
// What distinguishes them is a dial that has not come back yet: waited on, Run
// cannot return until it does.
func TestShutdownWaitsForAConnectionWhoseDialIsInFlight(t *testing.T) {
	h := newHarness(t)
	h.service.backoff = 50 * time.Millisecond
	h.relays.refuse(testRelay, 1_000_000)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	defer h.relays.release()
	done := make(chan error, 1)
	go func() { done <- h.service.Run(ctx, nil, nil) }()

	// The FIRST dial is reload's, and blocking that would hang Run before there
	// is anything to assert. The block goes on after it, and the retry one
	// backoff later is the one held.
	waitFor(t, "the failed open", func() bool { return h.relays.subscribesTo(testRelay) >= 1 })
	h.relays.block()
	// COUNTED AFTER the block is installed, so the dial this waits for is one the
	// block is guaranteed to hold. Waiting for ">= 2" instead would pass on a
	// dial that had already completed if this goroutine were descheduled past a
	// backoff — a flake that only appears on a LOADED runner, which is the
	// direction that matters (found by review).
	held := h.relays.subscribesTo(testRelay)
	waitFor(t, "a retry dial to be in flight", func() bool {
		return h.relays.subscribesTo(testRelay) > held
	})

	cancel()
	select {
	case <-done:
		t.Fatal("Run returned while a retry was still dialling the relay; the retry goroutine " +
			"is not in s.serving, so the process can exit with a socket in flight")
	case <-time.After(200 * time.Millisecond):
		// Still waiting, which is the property. A slow machine only makes this
		// wait longer, so it cannot fail for being loaded.
	}

	h.relays.release()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v on shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the dial it was waiting for came back")
	}
}
