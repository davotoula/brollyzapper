package nostr

import (
	"context"
	"fmt"
	"strings"

	gonostr "github.com/nbd-wtf/go-nostr"
)

// Subscription is one long-lived filter subscription on one relay (§8).
//
// It is what NWC needs and zap publishing never did: a socket held open for the
// life of a connection, on a relay chosen per connection rather than from
// default_relays, receiving events nobody asked for a moment ago.
type Subscription struct {
	// Events closes when the subscription ends, which is how a consumer's range
	// loop terminates without a second signal to watch.
	Events <-chan *gonostr.Event

	relayURL string
	pool     *Pool
	sub      *gonostr.Subscription
	cancel   context.CancelFunc
}

// Relay is the normalised URL this subscription is attached to.
func (s *Subscription) Relay() string { return s.relayURL }

// Close ends the subscription and forgets the relay's exemption.
//
// It does NOT close the socket. The pool owns relay lifetimes — Publish's
// teardown, Pool.Close, and Pool.dial discarding a duplicate or a dead entry are
// where a relay is closed — and a subscription that closed its own would race a
// publish that is using the same relay, which is precisely the shape the fork's
// o34.19 commit exists to make survivable rather than to rely on.
// Nil-tolerant in each of its three parts. A Subscription built by anything
// other than Subscribe — a consumer's test double is the case that exists — has
// no relay, no context and no pool, and a Close that panicked on one would make
// the teardown path the hardest thing about this type to exercise.
func (s *Subscription) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.sub != nil {
		s.sub.Unsub()
	}
	if s.pool != nil {
		s.pool.forgetSubscribed(s.relayURL)
	}
}

// Subscribe opens a long-lived subscription on relayURL.
//
// THE RELAY IS TREATED AS OPERATOR-CONFIGURED, and that is a decision worth
// stating (§8, vz1.4). The dial-time address check exempts relays the operator
// configured — because an operator may legitimately point at a relay on their
// own LAN — and refuses a private address for a relay a STRANGER named. An NWC
// connection's relay comes from a connection row rather than default_relays, but
// the operator is the one who created that connection and typed that URL, so it
// belongs on the configured side.
//
// Registered in a set of its own rather than by widening p.relays(), and the
// difference matters: p.relays() is also the publish target list, so folding
// connection relays into it would start publishing zap receipts to whatever
// relay a wallet app happened to pair on. Exempt from the dial check, never a
// target.
//
// This is also the dial the exemptRelays nil-snapshot path was built for: a
// subscription dials outside any publish, so there is no snapshot to honour and
// the operator's list is read fresh.
//
// IT DIALS THROUGH Pool.dial, not through the library's EnsureRelay, and du9.1
// is why. Two ways of writing one map is a torn store: EnsureRelay writes with a
// plain Store under a fifty-bucket hash lock, Pool.dial writes with an atomic
// Compute, and neither serialises against the other — so a subscribe and a
// publish dialling one URL at once left two live sockets and one map entry, and
// the unmapped socket could never be closed, because every teardown here walks
// the map. One door, one kind of write, no torn outcome.
//
// THE DIAL IS NOW BOUNDED BY THE CALLER'S CONTEXT, at connectBudget rather than
// the library's hardcoded fifteen seconds off the pool's, and for a long-lived
// subscription that is a deliberate choice rather than a side effect. Five
// seconds is right because the retry is what makes a subscription resilient, not
// the first dial: internal/nwc's resubscribe loop retries in place for ever at a
// FLAT ReconnectBackoff, so a shorter dial only brings the next attempt forward
// — there is no exponential penalty for failing sooner — and the WARN it emits
// is bounded separately by FailureReminderInterval, so the tighter cycle does
// not turn into a louder log.
//
// EXPIRY CONDITION: that argument rests on the backoff being flat. If it becomes
// exponential, a five-second dial starts costing a doubling it did not before,
// and this should take a budget of its own rather than connectBudget.
//
// AND dial's DUPLICATE-CLOSING IS SAFE HERE, which was the second thing du9.1
// had to settle before routing a subscription through it. It closes the relay
// that lost the Compute; nothing can have subscribed on that relay, because dial
// returns the WINNER and the winner is the only handle this function ever sees —
// the Subscribe below runs on the line after the dial returns.
//
// The other half of that question is the relay it closes when it does NOT lose:
// a map entry whose socket has dropped, which it replaces. That entry may be one
// a live Subscription is nominally attached to, and closing it is right rather
// than merely tolerable — the subscription on a dropped socket is already over,
// internal/nwc's loop is already re-subscribing, and the close is what releases
// the dead relay's ping and read goroutines. A CONNECTED entry is never closed:
// Compute keeps it and discards the newcomer instead.
func (p *Pool) Subscribe(ctx context.Context, relayURL string,
	filter gonostr.Filter) (*Subscription, error) {
	normalised := gonostr.NormalizeURL(strings.TrimSpace(relayURL))
	if normalised == "" || !gonostr.IsValidRelayURL(normalised) {
		return nil, fmt.Errorf("nostr: %q is not a usable relay URL", relayURL)
	}
	// BEFORE the dial, because the dial is what consults it — through
	// checkDialAddress, which Pool.dial passes to the relay by hand, so this
	// ordering is what keeps a subscription to the operator's own LAN relay
	// dialable at all.
	p.rememberSubscribed(normalised)

	// NOT WRAPPED. dial's own error already names this relay and says whether
	// the connect budget expired; a second "nostr: connecting to X:" in front of
	// it is the message twice.
	relay, err := p.dial(ctx, normalised)
	if err != nil {
		p.forgetSubscribed(normalised)
		return nil, err
	}
	// Its own cancellable context, so Close ends the subscription without
	// touching the caller's.
	subCtx, cancel := context.WithCancel(ctx)
	sub, err := relay.Subscribe(subCtx, gonostr.Filters{filter})
	if err != nil {
		cancel()
		p.forgetSubscribed(normalised)
		return nil, fmt.Errorf("nostr: subscribing on %s: %w", normalised, err)
	}
	return &Subscription{
		Events:   sub.Events,
		relayURL: normalised,
		pool:     p,
		sub:      sub,
		cancel:   cancel,
	}, nil
}

func (p *Pool) rememberSubscribed(url string) {
	p.subscribedMu.Lock()
	defer p.subscribedMu.Unlock()
	if p.subscribed == nil {
		p.subscribed = make(map[string]int)
	}
	p.subscribed[url]++
}

func (p *Pool) forgetSubscribed(url string) {
	p.subscribedMu.Lock()
	defer p.subscribedMu.Unlock()
	if p.subscribed[url] <= 1 {
		delete(p.subscribed, url)
		return
	}
	p.subscribed[url]--
}

// subscribedRelays is the set of relays a live subscription is attached to.
func (p *Pool) subscribedRelays() []string {
	p.subscribedMu.Lock()
	defer p.subscribedMu.Unlock()
	urls := make([]string, 0, len(p.subscribed))
	for url := range p.subscribed {
		urls = append(urls, url)
	}
	return urls
}
