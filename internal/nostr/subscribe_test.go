package nostr_test

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/nostr"
)

// §8: a subscription holds one relay open and delivers events nobody asked for.
func TestASubscriptionReceivesEventsFromItsRelay(t *testing.T) {
	relays := newFleet(t, 1)
	pool := lifetimePool(t, func() []string { return nil })

	sub, err := pool.Subscribe(t.Context(), relays.urls()[0], gonostr.Filter{Kinds: []int{23194}})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	lndtest.WaitFor(t, "the relay to see the subscription", func() bool {
		live, _ := relays.counts()
		return live == 1
	})
	if got := pool.Connected(); !slices.Contains(got, sub.Relay()) {
		t.Errorf("the pool holds %v, want the subscribed relay %s", got, sub.Relay())
	}
}

// 9xg, and the test that could not be written before this wave.
//
// A zap receipt publish must leave an NWC subscription's socket ALONE. The
// subscription's relay is not in default_relays — it comes from a connection
// row — so a teardown written as "close anything not configured" takes it down,
// and the operator's wallet app silently stops receiving until something
// reconnects it.
//
// The bead records that its first version was VACUOUS and was deleted: with no
// way to hold a relay open independently of a publish, the test could only
// assert that a publish left its own relays alone, which every teardown rule
// does. Pool.Subscribe is what makes the two rules distinguishable.
//
// The plant is on the bead: revert Publish's teardown to the negative form and
// this goes red.
func TestAZapPublishLeavesAnNWCSubscriptionConnected(t *testing.T) {
	configured := newFleet(t, 1)
	nwcRelay := newFleet(t, 1)
	pool := lifetimePool(t, configured.urls)

	sub, err := pool.Subscribe(t.Context(), nwcRelay.urls()[0], gonostr.Filter{Kinds: []int{23194}})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()
	lndtest.WaitFor(t, "the NWC relay to accept the subscription", func() bool {
		live, _ := nwcRelay.counts()
		return live == 1
	})

	// A zap receipt goes out to the operator's own relays, which do NOT include
	// the connection's.
	results := pool.Publish(t.Context(), signedNote(t))
	if nostr.Accepted(results) < 1 {
		t.Fatalf("the configured relay did not take the receipt: %+v", results)
	}

	// The subscription is still up. Asserted from the RELAY's side as well as
	// the pool's: the pool forgetting a relay and the socket actually closing
	// are two different facts, and it is the socket the wallet app is on.
	if live, _ := nwcRelay.counts(); live != 1 {
		t.Errorf("the NWC relay has %d live connections after a zap publish, want 1 — a "+
			"connection outliving a publish is the whole point of 9xg", live)
	}
	if got := pool.Connected(); !slices.Contains(got, sub.Relay()) {
		t.Errorf("the pool dropped the subscribed relay during a publish: %v", got)
	}
}

// The subscription's relay is exempt from the dial-time address check, because
// the operator typed it into a connection (§8, vz1.4).
//
// The fleet is on 127.0.0.1, which is exactly what that check refuses a stranger
// — so a subscription that was NOT exempt could not connect at all here, and
// this test would fail by timing out rather than by asserting.
func TestASubscribedRelayIsTreatedAsOperatorConfigured(t *testing.T) {
	relays := newFleet(t, 1)
	// No configured relays and a resolver that refuses everything: the ONLY
	// thing that can make this dial succeed is the subscription's own exemption.
	pool := nostr.NewPool(t.Context(), func() []string { return nil },
		nostr.Options{Resolve: answers{err: errNoDNS}})
	defer pool.Close()

	sub, err := pool.Subscribe(t.Context(), relays.urls()[0], gonostr.Filter{Kinds: []int{23194}})
	if err != nil {
		t.Fatalf("Subscribe: %v — a connection's relay is operator-configured, so the dial-time "+
			"check must exempt it", err)
	}
	defer sub.Close()
	lndtest.WaitFor(t, "the relay to accept the subscription", func() bool {
		live, _ := relays.counts()
		return live == 1
	})
}

// And the exemption is NOT a publish target. Folding connection relays into
// p.relays() would have been the easy way to exempt them, and it would start
// publishing zap receipts to whatever relay a wallet app happened to pair on —
// which is a privacy leak, not a routing detail.
func TestASubscribedRelayNeverBecomesAPublishTarget(t *testing.T) {
	configured := newFleet(t, 1)
	nwcRelay := newFleet(t, 1)
	pool := lifetimePool(t, configured.urls)

	sub, err := pool.Subscribe(t.Context(), nwcRelay.urls()[0], gonostr.Filter{Kinds: []int{23194}})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()

	results := pool.Publish(t.Context(), signedNote(t))
	for _, r := range results {
		if r.Relay == sub.Relay() {
			t.Errorf("a zap receipt was published to the NWC connection's relay (%s); it is "+
				"exempt from the dial check, not a place the operator's receipts go", r.Relay)
		}
	}
	if _, arrived := nwcRelay.counts(); arrived != 0 {
		t.Errorf("the NWC relay received %d events; it is subscribed to, not published to", arrived)
	}
}

// And the leak has TWO directions. The test above covers zap receipts reaching
// an NWC relay; this is the other one, and it is the one that was there.
//
// §8 step 6 says publish the response to the SAME relay. Handing the connection
// relay to Publish as an extra target does something else: Publish sends to the
// operator's configured list plus the extras. That would put every NWC response
// — and, worse, the UNENCRYPTED kind 13194 info event, which carries a
// connection's service pubkey and its method list — on the operator's public
// zap-receipt relays, from one IP, alongside their receipts. The per-connection
// service keypair exists so an observer cannot link the operator's apps to each
// other; co-publishing them on a shared relay defeats it without reusing a
// single key.
func TestAnNWCPublishReachesOnlyTheConnectionsRelays(t *testing.T) {
	configured := newFleet(t, 1)
	nwcRelay := newFleet(t, 1)
	pool := lifetimePool(t, configured.urls)

	sub, err := pool.Subscribe(t.Context(), nwcRelay.urls()[0], gonostr.Filter{Kinds: []int{23194}})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()

	results := pool.PublishToConnection(t.Context(), signedNote(t),
		nostr.PairingRelays([]string{sub.Relay()}))

	if len(results) != 1 || results[0].Relay != sub.Relay() {
		t.Errorf("PublishToConnection reported %+v; §8 step 6 is the pairing's own relays, "+
			"and this pairing names one", results)
	}
	if _, arrived := nwcRelay.counts(); arrived != 1 {
		t.Errorf("the connection's relay received %d events, want 1", arrived)
	}
	if _, leaked := configured.counts(); leaked != 0 {
		t.Errorf("%d NWC events reached the operator's configured relays; an info event there "+
			"announces a connection's service pubkey next to that operator's zap receipts",
			leaked)
	}
}

// Closing a subscription forgets its exemption, so a relay is not exempt for
// ever because something once subscribed to it.
func TestClosingASubscriptionForgetsItsExemption(t *testing.T) {
	relays := newFleet(t, 1)
	pool := lifetimePool(t, func() []string { return nil })

	sub, err := pool.Subscribe(t.Context(), relays.urls()[0], gonostr.Filter{Kinds: []int{23194}})
	if err != nil {
		t.Fatal(err)
	}
	sub.Close()

	// The events channel closes, which is how a consumer's range loop ends.
	select {
	case _, open := <-sub.Events:
		if open {
			t.Error("the events channel is still delivering after Close")
		}
	case <-time.After(3 * time.Second):
		t.Error("the events channel never closed, so a consumer would block for ever")
	}
}

// Two apps paired on ONE relay is the ordinary case, not a corner: an operator
// with a phone client and a desktop client points both at the relay they run.
// The exemption is therefore COUNTED rather than a set — with a set, the first
// subscription to close would drop the exemption out from under the second, and
// nothing would notice until that one's socket had to be re-dialled and was
// refused for an address the operator chose themselves.
//
// Asserted through the dial hook rather than through a second Subscribe, and
// that is the whole point of the test: Subscribe REGISTERS the relay before it
// dials, so a fresh Subscribe would re-add the exemption it is supposed to be
// checking and pass under either implementation. The hook is what the dial
// consults, so it is what has to be asked.
func TestClosingOneOfTwoSubscriptionsLeavesTheOthersExemption(t *testing.T) {
	relays := newFleet(t, 1)
	url := relays.urls()[0]
	// No configured relays: the subscriptions are the only source of exemption.
	pool := nostr.NewPool(t.Context(), func() []string { return nil }, nostr.Options{})
	defer pool.Close()

	first, err := pool.Subscribe(t.Context(), url, gonostr.Filter{Kinds: []int{23194}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.Subscribe(t.Context(), url, gonostr.Filter{Kinds: []int{23194}})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	// Both live: the relay is on loopback, which the policy refuses to anyone
	// who did not configure it. This is the positive control — without it, a
	// test that only ever saw "allowed" could be asserting nothing.
	if err := nostr.CheckDialAddress(pool, url, "127.0.0.1:7777"); err != nil {
		t.Fatalf("a subscribed relay was refused its own address: %v", err)
	}

	first.Close()

	if err := nostr.CheckDialAddress(pool, url, "127.0.0.1:7777"); err != nil {
		t.Errorf("closing one subscription revoked the exemption another one is still "+
			"relying on: %v", err)
	}

	// And the count reaches zero: the last one out really does revoke it, or the
	// exemption would outlive every connection that justified it.
	second.Close()
	if err := nostr.CheckDialAddress(pool, url, "127.0.0.1:7777"); err == nil {
		t.Error("the exemption survived the last subscription's Close; a relay nobody is " +
			"subscribed to is a stranger's again")
	}
}

var errNoDNS = errors.New("no DNS in this test")

// The lifecycle cases relay_lifecycle_test.go promised this wave.
//
// The fork's o34.19 commit fixed three races on Relay.Connection and
// ConnectionError, and two of them need a SUBSCRIPTION to reach: Relay.Subscribe
// reading Connection while the writer goroutine nils it, and ConnectionError
// written by the reader while the writer reads it. Until Pool.Subscribe existed
// nothing in this tree subscribed, so those fixes were carried on the fork's own
// tests alone. These are the consumer-side cases.
//
// Run under -race, and the gate runs this package with -count=5 for that reason.
func TestASubscriptionTornDownConcurrentlyIsRaceFree(t *testing.T) {
	relays := newFleet(t, 1)
	pool := lifetimePool(t, func() []string { return nil })

	for range 20 {
		sub, err := pool.Subscribe(t.Context(), relays.urls()[0],
			gonostr.Filter{Kinds: []int{23194}})
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		// Close racing a consumer draining the channel: the shape a service
		// shutting down while a request is arriving actually has.
		go func() { defer wg.Done(); sub.Close() }()
		go func() {
			defer wg.Done()
			for range sub.Events { //nolint:revive // draining is the point
			}
		}()
		wg.Wait()
	}
}

// Teardown racing a concurrent PUBLISH, which is the pair that matters: the
// publish's deferred closeTransient walks the pool's relay map while the
// subscription is removing itself from the exemption set.
func TestASubscriptionTeardownRacingAPublishIsRaceFree(t *testing.T) {
	configured := newFleet(t, 1)
	nwcRelay := newFleet(t, 1)
	pool := lifetimePool(t, configured.urls)

	for range 10 {
		sub, err := pool.Subscribe(t.Context(), nwcRelay.urls()[0],
			gonostr.Filter{Kinds: []int{23194}})
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); pool.Publish(t.Context(), signedNote(t)) }()
		go func() { defer wg.Done(); sub.Close() }()
		wg.Wait()
	}
}
