package nwc

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/store"
)

// Run serves every active connection until ctx ends (§8).
//
// One subscription per connection, on that connection's OWN relay — the URL from
// its pairing URI, not default_relays. Each also gets its own service keypair,
// which is NIP-47's privacy guidance: a shared key links all of the operator's
// apps together on the relay, so an observer could see that the wallet app and
// the podcast app belong to the same person.
//
// The prune tick is a parameter for the same reason the reconciler's is: the
// schedule belongs to the caller and a test costs microseconds.
func (s *Service) Run(ctx context.Context, prune <-chan time.Time, demand <-chan struct{}) error {
	live := map[int64]*connection{}
	if err := s.reload(ctx, live); err != nil {
		return err
	}
	defer func() {
		for _, conn := range live {
			conn.close()
		}
		s.serving.Wait()
		// And the per-connection goroutine that drops a pairing's health once
		// its sessions have gone: it outlives them by construction, and a Run
		// that returned while one was still running would be a write to the
		// health map after the service was done with it.
		s.forgetting.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-demand:
			// The operator changed something on the Connections or Sending page
			// (uhg) — or the service itself paused a pairing whose requests kept
			// crashing the handler (`xmc` Fix C), which nudges this same
			// channel. Reload rather than restart: a restart would drop every
			// in-flight request and every open subscription to answer a question
			// about one row.
			if err := s.reload(ctx, live); err != nil {
				s.log.Error("could not reload NWC connections", "error", err.Error())
			}
		case _, ok := <-prune:
			if !ok {
				return nil
			}
			if n, err := s.store.PruneNWCHandled(ctx, s.now().Add(-HandledRetention)); err != nil {
				s.log.Warn("could not prune the NWC replay cache", "error", err.Error())
			} else if n > 0 {
				s.log.Debug("pruned the NWC replay cache", "rows", n)
			}
		}
	}
}

// reload brings the served connections into line with the database (uhg).
//
// Three things happen here and each is a §8 requirement: a new connection gets a
// subscription and an info event, a revoked one is closed, and an existing one's
// row is REFRESHED — which is what makes an edited budget, a removed permission
// or a lowered cap take effect without a restart. Before this the ladder read a
// copy taken at startup, so tightening a limit changed nothing until the process
// was restarted; revocation happened to work only because ReserveNWCBudget's
// guard reads `revoked` from the row every time.
//
// What it must NOT do, and does not: it touches neither nwc_since nor the replay
// cache, so the resume point keeps its discipline and a redelivered request is
// still answered from the row that already holds it. An existing connection's
// SUBSCRIPTION is left alone — the socket, its in-flight requests and its
// position all survive, because nothing about them changed.
func (s *Service) reload(ctx context.Context, live map[int64]*connection) error {
	rows, err := s.store.ActiveNWCConnections(ctx)
	if err != nil {
		return fmt.Errorf("nwc: reading connections: %w", err)
	}
	since, err := s.since(ctx)
	if err != nil {
		return err
	}

	seen := make(map[int64]bool, len(rows))
	for _, row := range rows {
		seen[row.ID] = true
		if conn, running := live[row.ID]; running {
			// Compared against what this connection LAST ANNOUNCED, not against
			// what advertised() would have said a moment ago.
			//
			// The difference is a real bug review found here: advertised() reads
			// the sending setting live, and both readings happen after the
			// Sending page has already written it — so enabling sending changed
			// nothing between the two calls and the info event was never
			// republished. §8 requires the republish whenever capabilities
			// change, and gaining pay_invoice is the change that makes a pay
			// button appear in a wallet app. What was last ANNOUNCED is the one
			// thing that cannot move under the comparison.
			conn.update(row)
			// Order-sensitive, deliberately: both lists are built in one order
			// by one function, so sorting could only hide a change of order that
			// is itself a change.
			if now := s.advertised(ctx, conn); !slices.Equal(conn.announced(), now) {
				// A CAPABILITY change is a fact about the pairing rather than
				// about one relay, so this one goes to all of them.
				s.announce(ctx, conn, nostr.PairingRelays(conn.row().Relays))
			}
			continue
		}
		conn, err := s.prepare(row)
		if err != nil {
			// PERMANENT, and that is why this one is dropped rather than
			// retried: no relay coming back fixes a row with no relay in it, a
			// service key that does not parse, or a stored pubkey that is not
			// that key's. Reported once, here — a retry would ask a relay about
			// an unfixable row every backoff for ever.
			//
			// One unusable connection must not stop the others: a relay that is
			// down is a state, and the operator's other pairings still work
			// (§11).
			if s.markUnusable(row.ID) {
				s.log.Warn("an NWC connection cannot be served and no relay can fix it",
					"connection", row.ID, "relays", strings.Join(row.Relays, " "),
					"error", err.Error())
			}
			continue
		}
		live[row.ID] = conn

		// ONE GOROUTINE PER RELAY (d24.18), each owning that relay's session:
		// its subscription, its retry loop and its half of the pairing's health.
		// A pairing is reachable while ANY of them is, which is the whole point
		// of the list — so a relay that refuses is a session that retries, not a
		// connection that stops.
		//
		// The subscribe attempt happens inside the goroutine rather than here,
		// because with several relays "did it work" is no longer one answer:
		// reload would otherwise wait on the slowest dial in every pairing
		// before returning to the operator who nudged it.
		relays := conn.relays()
		s.serving.Add(len(relays))
		// BEFORE any session goroutine starts, and before the forgetter below
		// can Wait on it. Adding inside serveRelay is a race the health test
		// caught: the forgetter reached Wait first, saw a zero counter, and
		// dropped the pairing's state while a dial was still in flight — after
		// which that dial's error put the entry back for ever.
		conn.sessions.Add(len(relays))
		s.forgetting.Add(1)
		for _, relay := range relays {
			go func() {
				defer s.serving.Done()
				s.serveRelay(ctx, conn, relay, since)
			}()
		}
		// The pairing's state is forgotten once EVERY relay session has gone,
		// which is the only moment no dial can still be in flight to re-insert
		// it. See forgetHealth.
		go func() {
			defer s.forgetting.Done()
			conn.sessions.Wait()
			// EVERY session has gone, so nothing can add another worker — which
			// is what makes this the one safe place to wait for the ones still
			// running. A shutdown still does not abandon a payment mid-ladder:
			// Run's teardown waits on s.forgetting, which waits here.
			conn.working.Wait()
			s.forgetHealth(row.ID)
		}()
	}

	for id, conn := range live {
		if seen[id] {
			continue
		}
		// Revoked, deleted, or PAUSED by Fix C. Closed here rather than left to
		// notice on its own: a connection that kept answering after any of
		// those is the decision having done nothing, which is a security
		// property and not a tidiness one.
		s.log.Info("an NWC connection is no longer served; closing its subscription",
			"connection", id)
		conn.close()
		delete(live, id)
	}
	// Every row that is gone loses its state, which the loop above cannot do on
	// its own: a row prepare rejected was never in `live`.
	s.retainHealth(seen)
	return nil
}

// prepare builds one connection from its row, or says why that row can NEVER be
// served.
//
// The split from subscribe is d24.24's whole design question. Opening a
// connection fails for two classes of reason and only one of them is worth
// retrying: everything HERE is permanent, and everything in subscribe is the
// relay having a bad minute. A caller that could not tell them apart would
// either abandon a pairing whose relay blipped — the bug this was filed as — or
// ask a relay about a corrupt row every backoff for ever.
//
// It could not be otherwise even if the distinction were only a preference: two
// of these three failures mean there is no identity, and newConnection needs
// one. There is nothing to retry WITH.
func (s *Service) prepare(row store.NWCConnection) (*connection, error) {
	if len(row.Relays) == 0 {
		return nil, fmt.Errorf("the connection has no relay; its pairing URI names at least " +
			"one (§8), and NIP-47 allows more than one (d24.18)")
	}
	if len(row.Relays) > nostr.MaxPairingRelays {
		// A row is not allowed to make this process hold more sockets than the
		// cap, whoever wrote it. The form refuses it too; this is the half that
		// covers a row written by anything else.
		return nil, fmt.Errorf("the connection names %d relays; at most %d may be served",
			len(row.Relays), nostr.MaxPairingRelays)
	}
	seen := make(map[string]bool, len(row.Relays))
	for _, relay := range row.Relays {
		if seen[relay] {
			// A DUPLICATE IS A BROKEN ROW, not a harmless repetition, and the
			// damage is quiet: the sessions key on the relay URL, so the second
			// attach overwrites the first subscription — which is then never
			// closed, because close() iterates the map and the map holds only
			// the survivor — while the first session to exit detaches the
			// survivor and leaves the other reading a nil channel for ever.
			// Refused for the same reason a bad address is: silently serving
			// something other than what the row says is how "it works for me"
			// and "it never works" become both true (found by review).
			return nil, fmt.Errorf("the connection names %q more than once", relay)
		}
		seen[relay] = true
		if !nostr.IsRelayURL(relay) {
			// The SAME predicate the create form gates on, here as well as
			// there, because this is the half that decides whether to retry: the
			// pool rejects a malformed URL before it dials, so without this a row
			// written by anything but the form — an older build, a hand-edited
			// database — would be retried every backoff for ever against an
			// address no relay can be at (found by review).
			//
			// ONE BAD ADDRESS FAILS THE WHOLE ROW rather than being skipped. A
			// pairing served on two of the three relays its URI named is a
			// pairing whose client may be listening on the third, and silently
			// serving a subset is the shape that makes "it works for me" and "it
			// never works" both true.
			return nil, fmt.Errorf("%q is not a usable relay address", relay)
		}
	}
	identity, err := nostr.Parse(row.ServicePrivkey)
	if err != nil {
		return nil, fmt.Errorf("reading the connection's service key: %w", err)
	}
	if identity.PublicKey() != row.ServicePubkey {
		// The stored pubkey and the key that would sign disagree, so requests
		// are addressed to a key we do not hold. Refused rather than served
		// under the key we DO hold, which would answer nobody.
		return nil, fmt.Errorf("the stored service pubkey does not match its private key")
	}
	return newConnection(row, identity), nil
}

// serveRelay owns ONE relay session of one pairing, for as long as it lasts
// (d24.18).
//
// The unit changed from the connection to the relay session, and the state
// machine did not: dial, serve, re-dial on a drop, give up only when the service
// or the connection ends. What is new is that a pairing has several of these and
// is reachable while ANY of them is up — so the failure the 0.1.10 trip measured,
// one relay refusing 8 of 20 upgrades, now costs a pairing nothing as long as its
// other relays answer.
//
// The first dial happens HERE rather than in reload, because with a list there is
// no single answer to "did it open": reload would otherwise block the operator
// who nudged it on the slowest relay in the slowest pairing.
func (s *Service) serveRelay(ctx context.Context, conn *connection, relay string, since time.Time) {
	// The counter was raised by reload before this goroutine existed; see there.
	defer conn.sessions.Done()
	// This session's relay is dropped from the map on the way out, so a closed
	// subscription cannot make serving() overcount.
	defer conn.detach(relay)

	if err := s.subscribe(ctx, conn, relay, since); err != nil {
		// TRANSIENT — the relay is down, or refusing the upgrade. Served ANYWAY:
		// the session goes straight into its retry loop and starts working by
		// itself when the relay answers.
		//
		// Until d24.24 a failed open was dropped, which left the pairing dead
		// until the operator touched an unrelated row or the app restarted —
		// serve()'s supervision only ever covered a subscription that had been
		// established and then ended. The 0.1.10 field trip cost thirteen minutes
		// to exactly that.
		s.reportUnreachable(conn.row().ID, relay, err)
		if !s.waitAndResubscribe(ctx, conn, relay) {
			return
		}
	}
	s.serve(ctx, conn, relay)
}

// subscribe opens one relay's subscription for a prepared connection, and
// announces the pairing on it.
//
// The filter is this connection's OWN service pubkey, not a union of all of
// them: each connection has its own key precisely so an observer cannot link
// them, and one subscription asking for several would undo that on the relay.
//
// Its only failure is the relay's, which is why the caller may retry it: see
// prepare for the half that must not be retried.
func (s *Service) subscribe(ctx context.Context, conn *connection, relay string,
	since time.Time) error {
	row := conn.row()
	sub, err := s.relays.Subscribe(ctx, relay, filterFrom(row.ServicePubkey, since))
	if err != nil {
		return err
	}
	attached, serving := conn.attach(relay, sub)
	if !attached {
		// Closed already, which only a shutdown racing a reload can do. attach
		// has closed the subscription, and there is nobody to announce to.
		return nil
	}
	s.markServing(row.ID, relay)

	// Announced after the subscription is up, so a client that reacts to the
	// info event by sending a request finds someone listening. To the WHOLE set
	// rather than to this relay alone: the client may be reading any of them and
	// has never seen an info event for this pairing.
	//
	// ONCE, by whichever relay comes up first, and the count comes back from
	// attach so the decision cannot be a check-then-act. Read through a second
	// call, two sessions attaching before either looked would both see the final
	// count and NEITHER would announce — a brand-new pairing publishing no info
	// event at all (found by review).
	if serving == 1 {
		s.announce(ctx, conn, nostr.PairingRelays(conn.row().Relays))
	}
	return nil
}

// filter is what a RE-subscribe asks for: the same shape as the first one, but
// from the resume point as it stands now rather than as it stood at startup.
// Requests that arrived while the socket was down are exactly what it has to
// pick up, and the durable cache absorbs anything already handled.
func (s *Service) filter(ctx context.Context, conn *connection) gonostr.Filter {
	since, err := s.since(ctx)
	if err != nil {
		// Not fatal: the freshness window bounds what an over-wide filter can
		// deliver, and refusing to reconnect over an unreadable setting would
		// turn a database hiccup into a dead wallet.
		s.log.Warn("could not read the NWC resume point; re-subscribing from the beginning",
			"error", err.Error())
	}
	return filterFrom(conn.row().ServicePubkey, since)
}

func filterFrom(servicePubkey string, since time.Time) gonostr.Filter {
	filter := gonostr.Filter{
		Kinds: []int{KindRequest},
		Tags:  gonostr.TagMap{"p": []string{servicePubkey}},
	}
	if !since.IsZero() {
		ts := gonostr.Timestamp(since.Unix())
		filter.Since = &ts
	}
	return filter
}

// announce publishes a connection's info event (§8), to every relay the pairing
// names.
//
// TO ALL OF THEM, and this is where NIP-47's own wording lands: the relay
// parameter "may be more than one", and a client is entitled to read the info
// event on whichever it chose. Announcing on only the first would advertise the
// pairing's capabilities to a client listening on the second and leave it with a
// wallet that appears to support nothing.
//
// Accepted by NONE of them is what is worth a line — one relay refusing is the
// ordinary case a list exists to absorb.
func (s *Service) announce(ctx context.Context, conn *connection, relays nostr.ConnectionRelays) {
	event, err := s.infoEvent(ctx, conn)
	if err != nil {
		s.log.Error("could not build an NWC info event", "connection", conn.row().ID,
			"error", err.Error())
		return
	}
	if results := s.relays.PublishToConnection(ctx, event, relays); nostr.Accepted(results) == 0 {
		s.log.Warn("no relay accepted an NWC info event", "connection", conn.row().ID,
			"relays", strings.Join(relays.URLs(), " "))
	}
	// Recorded whether or not a relay took it: what matters to the comparison is
	// what this service last SAID, and a republish that nobody accepted is one
	// the next reload should not repeat for the same unchanged capabilities.
	conn.setAnnounced(s.advertised(ctx, conn))
}

// serve consumes one relay session's requests, and RE-SUBSCRIBES when that relay
// drops it.
//
// Without this the service was one relay hiccup away from being permanently
// broken, silently: go-nostr's Relay.Subscribe — unlike SimplePool.SubscribeMany
// — does not reconnect, so a dropped socket closes sub.Events, the range loop
// returns, and that session is dead until the process restarts. Run would sit in
// its prune loop unaware, and the only symptom is a wallet app that stopped
// working. On a Pi behind a home connection that is days, not months.
//
// The resume point is what makes it safe: the new subscription asks from
// nwc_since, so requests that arrived while the socket was down are delivered,
// and the durable cache absorbs any that were already handled — including the
// ones another relay in the same pairing already answered.
// The in-flight WORKERS are waited on by the connection's forgetter goroutine and
// NOT here, which is a d24.18 correction rather than a preference: conn.working
// belongs to the connection, and with a session per relay a `defer
// conn.working.Wait()` here is one session waiting on a group another session is
// still adding to. That is documented WaitGroup misuse — "calls with a positive
// delta that occur when the counter is zero must happen before a Wait" — and it
// panics the process when the Add lands in the window where the counter has just
// reached zero. Reproduced under -race by review, with one worker held and events
// queued on a sibling relay while the connection closed.
func (s *Service) serve(ctx context.Context, conn *connection, relay string) {
	for {
		if !s.consume(ctx, conn, relay) {
			return
		}
		s.reportDropped(conn, relay)
		if !s.waitAndResubscribe(ctx, conn, relay) {
			return
		}
	}
}

// waitAndResubscribe waits out the backoff and re-establishes one relay's
// subscription, reporting whether the caller should keep serving it.
//
// One wait for both entry points — a subscription that ended and one that never
// opened — because they had drifted: this one watched only the service context,
// so a pairing REVOKED during the backoff slept the full period and then made one
// more dial before attach refused it. Watching conn.done as well is the same rule
// consume follows (found by review).
func (s *Service) waitAndResubscribe(ctx context.Context, conn *connection, relay string) bool {
	select {
	case <-ctx.Done():
		return false
	case <-conn.done:
		return false
	case <-time.After(s.backoff):
	}
	return s.resubscribe(ctx, conn, relay)
}

// reportDropped says that a live subscription ended, bounded by the same clock
// as reportUnreachable.
//
// A distinct sentence from "cannot reach its relay", because losing a socket we
// had is a different fact from never getting one — but on ONE clock, because they
// are the same condition to an operator. Unbounded, this is the line a flapping
// relay produces twelve times a minute: every reconnect ends the episode, so
// every drop would look like news (found by review).
func (s *Service) reportDropped(conn *connection, relay string) {
	if _, report := s.markRetrying(conn.row().ID, relay); !report {
		return
	}
	s.log.Warn("an NWC subscription ended; reconnecting", "connection", conn.row().ID,
		"relay", relay, "in", s.backoff.String())
}

// consume reads one subscription until it ends, and reports whether the caller
// should try to re-establish it.
//
// A select rather than a range, so shutdown does not depend on the RELAY
// closing the channel. It normally does — Subscription.Close unsubscribes and
// go-nostr closes Events — but "normally" is doing real work in that sentence:
// a relay that stops answering without closing the socket would otherwise hold
// this goroutine, and Run's teardown waits on it.
func (s *Service) consume(ctx context.Context, conn *connection, relay string) bool {
	events := conn.events(relay)
	for {
		select {
		case <-ctx.Done():
			return false
		case <-conn.done:
			// This connection was closed — revoked, or the service is shutting
			// down. Either way it stops being served HERE, not whenever the
			// relay library closes its channel.
			return false
		case event, open := <-events:
			if !open {
				// The relay dropped us. Not an error and not a shutdown: the
				// caller waits and re-subscribes.
				return true
			}
			if event == nil {
				continue
			}
			s.dispatchOne(ctx, conn, event)
		}
	}
}

// dispatchOne hands one request to a worker, bounded by InFlightPerConnection.
//
// CONCURRENT, and the reason is a real interaction between two constants that
// were chosen independently (d24.4 review). A pay_invoice can run to LND's
// 60-second PaymentTimeout, and §8's freshness window is also 60 seconds — so a
// serial reader means every request delivered behind a slow payment is read
// after the window has passed and answered "request expired". Concretely: the
// operator taps pay, then taps refresh-balance, and the balance request is
// refused because their own payment was still going.
//
// Safe to run concurrently because the pieces that had to be atomic already
// are: the replay claim elects one handler per request id in a single INSERT,
// and the budget is one guarded UPDATE. What was serial was only the reading.
//
// BOUNDED, because a paired app chooses how many requests arrive: without a cap
// this would be one goroutine per event, which is the shape a rate limit is
// supposed to bound (l3j). When the slots are full the reader waits, which is
// exactly the old behaviour and no worse.
func (s *Service) dispatchOne(ctx context.Context, conn *connection, event *gonostr.Event) {
	select {
	case conn.slots <- struct{}{}:
	case <-conn.done:
		// Revoked, or shutting down, while every worker was busy. Without this
		// the reader waits for a slot and then dispatches the event it is
		// holding — answering one more request for a connection the operator
		// has just revoked (found by review).
		return
	case <-ctx.Done():
		return
	}
	conn.working.Add(1)
	go func() {
		// THE ORDER IS LIFO, and it is chosen (`xmc`). working.Done() is
		// registered first so it runs LAST — a shutdown waits on it, and it must
		// not report the worker finished while containPanic is still writing.
		// The slot is registered last so it is released FIRST, before the panic
		// path's audit row, its panic count and possibly a pause and a second
		// row: up to four durable writes, which the connection's next request
		// should not queue behind.
		defer conn.working.Done()
		// THE ONLY recover() in this tree, and internal/arch pins it here
		// (`xmc`, B2). It runs AFTER handleOne's own deferred advance, because
		// defers unwind outward: the cursor has already moved past this event by
		// the time the panic arrives here, so a poison request costs one request
		// instead of the app.
		//
		// Not a general safety net. A panic anywhere else in this process is
		// still a panic, and should be: this one exists because a single
		// authorized client's malformed request must not be able to take LNURL,
		// zap receipts and the admin UI down with it, which is what a shared
		// process means and what `xmc` did.
		defer s.containPanic(ctx, conn, event)
		defer func() { <-conn.slots }()
		s.handleOne(ctx, conn, event)
	}()
}

// resubscribe re-opens one connection's subscription, and reports whether the
// caller should keep serving it.
//
// Retries in place rather than returning, because "the relay is still down" is
// the ordinary case and giving up on it is what the loop above exists to stop.
// It ends only when the service is shutting down or the connection is closed.
func (s *Service) resubscribe(ctx context.Context, conn *connection, relay string) bool {
	for {
		sub, err := s.relays.Subscribe(ctx, relay, s.filter(ctx, conn))
		if err == nil {
			if attached, _ := conn.attach(relay, sub); !attached {
				return false
			}
			// HOW LONG it was down, not merely that it came back — an operator
			// reading this after the fact is asking how much of their day the
			// pairing was unreachable for, and the state knows.
			//
			// At INFO only when the BREAK was reported. An all-clear for a break
			// nobody was told about is the other half of the flapping relay's
			// two lines per cycle; the state still shows it on the page, and the
			// reconnect count is what makes the flapping visible there.
			previous, report := s.markServing(conn.row().ID, relay)
			attrs := []any{"connection", conn.row().ID, "relay", relay,
				"unreachable_for", s.now().Sub(previous.Since).Round(time.Second).String(),
				"failed_dials", previous.FailedDials}
			if report {
				s.log.Info("an NWC subscription was re-established", attrs...)
			} else {
				s.log.Debug("an NWC subscription was re-established", attrs...)
			}
			// TO THIS RELAY ALONE. Re-announcing covers the relay having lost
			// the event while we were away, which is a fact about THIS relay —
			// publishing to the whole set would put a fresh copy on the two that
			// never lost it, and a pairing whose three sessions drop and recover
			// together (a Pi losing its network, the ordinary way this happens)
			// would produce nine publishes of a replaceable event. Found by
			// review, against the rule the initial announce states.
			s.announce(ctx, conn, nostr.PairingRelays([]string{relay}))
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		s.reportUnreachable(conn.row().ID, relay, err)
		select {
		case <-ctx.Done():
			return false
		case <-conn.done:
			// REVOKED while its relay was down, and this case is why d24.24
			// noticed it: the loop watched only the service's context, so a
			// pairing the operator revoked went on dialling a dead relay every
			// backoff until the process stopped. It answered nobody — attach
			// refuses a closed connection — but "the revocation takes effect at
			// the next restart" is not what consume's rule says, and a failed
			// open now reaches this loop far more often than a dropped socket
			// did.
			return false
		case <-time.After(s.backoff):
		}
	}
}

// reportUnreachable records a failed dial and says so — at most once per
// FailureReminderInterval while the condition persists (d24.21).
//
// One message and one place, used by the failed OPEN and by every failed
// re-dial, because an operator grepping for "this pairing is not working" should
// find one sentence rather than two spellings of it.
//
// BOTH halves are the requirement. The 0.1.10 trip got one line at 10:54:48 and
// then silence through hours of an unusable app: "a relay that is unreachable IS
// the app being down for every paired wallet. It deserves a periodic WARN while
// the condition persists, not one line at the moment it first happens." And the
// bound is why it is not simply one line per dial — see FailureReminderInterval.
func (s *Service) reportUnreachable(id int64, relay string, err error) {
	current, report := s.markRetrying(id, relay)
	if !report {
		return
	}
	s.log.Warn("an NWC connection cannot reach its relay", "connection", id, "relay", relay,
		"error", err.Error(), "since", current.Since.Format(time.RFC3339),
		"failed_dials", current.FailedDials, "retrying_in", s.backoff.String())
}

// handleOne processes one event and advances the resume point.
//
// nwc_since ADVANCES AS REQUESTS ARE HANDLED, and only ever forwards. §8 forbids
// a naive `startup − 1h`, and the reason a monotonic advance is the right
// discipline is the same one: the resume point exists so a restart resumes where
// it stopped, and a point that could move BACKWARDS would re-deliver requests
// the durable cache then has to absorb — which works, but turns the cache from a
// crash-window guarantee into a routine dependency.
//
// Advanced AFTER handling rather than before, so a crash mid-handle leaves the
// request re-deliverable. The cache is what makes that safe.
//
// ONLY FOR REQUESTS INSIDE THE FRESHNESS WINDOW, and this is not a detail: the
// regtest stack found it. created_at is the CLIENT's claim, and a request dated
// into the future is refused for being out of window — but advancing to its
// timestamp anyway moves the subscription filter into the future too, and the
// relay then delivers nothing at all until real time catches up. One request
// dated a year ahead would silence the service for a year, from anyone who can
// reach the relay.
//
// Belt and braces: the advance is also clamped to now, so even a request that
// passed the window cannot push the resume point past the present.
func (s *Service) handleOne(ctx context.Context, conn *connection, event *gonostr.Event) {
	if _, answered := s.handle(ctx, conn, event); answered {
		if err := s.store.TouchNWCConnection(ctx, conn.row().ID, s.now()); err != nil {
			s.log.Debug("could not record connection use", "error", err.Error())
		}
	}
	now, at := s.now(), event.CreatedAt.Time()
	if !inWindow(now, at) {
		return
	}
	if at.After(now) {
		at = now
	}
	s.advanceSince(ctx, at)
}

// inWindow is §8 step 3's freshness test, in one place.
//
// Both directions: §8 says "more than 60 s FROM now", which is a distance and
// not an age — a clock-skewed client sends requests from the future, and a
// future-dated one is exactly as unusable as an old one.
func inWindow(now, createdAt time.Time) bool {
	drift := now.Sub(createdAt)
	return drift <= RequestWindow && drift >= -RequestWindow
}

func (s *Service) advanceSince(ctx context.Context, at time.Time) {
	current, err := s.since(ctx)
	if err != nil || !at.After(current) {
		return
	}
	if err := s.store.SetSetting(ctx, SettingSince, strconv.FormatInt(at.Unix(), 10)); err != nil {
		s.log.Warn("could not advance the NWC resume point", "error", err.Error())
	}
}

// since reads the persisted resume point.
//
// Zero when unset, which subscribes from the beginning of the relay's memory —
// correct on a first run, because there is nothing to replay, and bounded
// anyway by the freshness window: anything the relay hands back from before
// RequestWindow is refused.
func (s *Service) since(ctx context.Context) (time.Time, error) {
	raw, ok, err := s.store.Setting(ctx, SettingSince)
	if err != nil {
		return time.Time{}, fmt.Errorf("nwc: reading %s: %w", SettingSince, err)
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return time.Time{}, nil
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		// Unreadable is not evidence of anything, and guessing would either
		// replay a window or skip one. Start from zero and let the freshness
		// window do the bounding.
		s.log.Warn("the NWC resume point is unreadable; starting from the beginning",
			"value", raw)
		return time.Time{}, nil
	}
	return time.Unix(seconds, 0).UTC(), nil
}

// infoEvent is the kind 13194 announcement (§8).
//
// Published when a connection is opened, whenever it is re-established, and —
// since uhg — whenever a reload finds this connection's advertised methods
// differ from what was last announced. That is §8's "on every capability
// change": a permission edit, a revocation, and enabling sending all arrive
// through reload(), and none of them waits for a restart any more.
//
// What it carries is decided by advertised(), not by this function: pay_invoice
// appears only for a connection holding the pay group while sending is enabled,
// so an operator who has not turned sending on sees a receive-only wallet rather
// than a pay button that answers RESTRICTED.
func (s *Service) infoEvent(ctx context.Context, conn *connection) (gonostr.Event, error) {
	schemes := make([]string, 0, len(nostr.SupportedEncryption))
	for _, e := range nostr.SupportedEncryption {
		schemes = append(schemes, string(e))
	}
	event := gonostr.Event{
		Kind:      KindInfo,
		CreatedAt: gonostr.Timestamp(s.now().Unix()),
		Content:   strings.Join(s.advertised(ctx, conn), " "),
		Tags: gonostr.Tags{
			{"encryption", strings.Join(schemes, " ")},
			// Space-separated in ONE tag value, which is the spec's own form
			// ("eg. 02 03 04"). Amethyst parses both that and one value per
			// element — NwcInfoEvent.spaceSeparatedTag splits on spaces after
			// flattening — so the spec's form is the one to emit (read, not run).
			{"extensions", extensions(conn)},
		},
	}
	if err := conn.identity.Sign(&event); err != nil {
		return gonostr.Event{}, fmt.Errorf("nwc: signing the info event: %w", err)
	}
	return event, nil
}

// containPanic stops a panicking request from taking the process down, and
// WRITES THE DROP DOWN before it does (`xmc`, Ruling C).
//
// THE RECORD IS THE POINT, not the recovery. §8's replay claim happens well
// after decryption, so a request that panics before it is never claimed, never
// cached and never answered — recover without a record and the request is
// silently gone. That trades an outage for a silent drop, which is the worse of
// the two for this codebase.
//
// THROUGH THE AUDITOR, because "a request crashed the handler" is exactly the
// answer that has to survive log rotation. It is remote-INFLUENCED rather than
// remote-triggerable — an authorized, paired client is the only thing that can
// reach here — and it is bounded like every other such writer (`t0b`), on its
// own budget rather than the refusal one.
//
// WHAT IT DOES NOT CARRY: the request body. It is a paired client's encrypted
// content, and the event id plus the connection is what diagnoses this. The
// stack goes to the log, where a stack belongs, and not into a durable row.
func (s *Service) containPanic(ctx context.Context, conn *connection, event *gonostr.Event) {
	r := recover()
	if r == nil {
		return
	}
	connectionID := conn.row().ID
	s.log.Error("a panic while handling an NWC request was contained; the request is dropped "+
		"and the connection keeps serving", "connection", connectionID, "event", event.ID,
		"panic", fmt.Sprint(r), "stack", string(debug.Stack()))
	s.auditBounded(ctx, s.panics, slog.LevelError,
		"an NWC request panicked and was dropped; it was never claimed, so nothing else "+
			"records that it arrived",
		logging.EventNWCPanic,
		[]any{"connection", connectionID, "event", logging.Short(event.ID)},
		slog.Int64("connection", connectionID),
		slog.String("event", logging.Short(event.ID)))
	// LAST, and unconditional: a service built without an Auditor still has to
	// stop serving a client it cannot survive. Fix C is not a reporting feature.
	s.quarantine(ctx, connectionID)
}

// quarantine counts this pairing's panics and stops serving it past the
// threshold (`xmc` Fix C).
//
// PER CONNECTION, and that is the whole design rather than a detail: one
// client's broken build must not disable the operator's other pairings. The
// count lives on the row, so it is scoped by construction and cannot be a global
// counter that happens to be keyed correctly today.
//
// It runs on the SAME bounded context as the audit row above, for the same
// reason: the request that triggered it is over.
func (s *Service) quarantine(ctx context.Context, connectionID int64) {
	// Detached and bounded, for auditBounded's reason: the request this is about
	// is over, and the decision must not be lost to the cancellation of the
	// thing that caused it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	count, err := s.store.NoteNWCPanic(ctx, connectionID)
	if err != nil {
		s.log.Error("could not count a contained NWC panic; this pairing is one panic further "+
			"from being paused than the count says", "connection", connectionID,
			"error", err.Error())
		return
	}
	if count < MaxPanicsPerConnection {
		s.log.Warn("an NWC pairing's request crashed the handler", "connection", connectionID,
			"panics", count, "pauses_at", MaxPanicsPerConnection)
		return
	}
	// The operator's words, and they are the deliverable: this is what the
	// Connections page shows, and it has to say what happened, what was done,
	// and what makes it safe to undo.
	const reason = "this app kept sending requests this pairing could not survive, so it has " +
		"been paused. Update the app that owns it, then re-enable this connection."
	if err := s.store.PauseNWCConnection(ctx, connectionID, reason, s.now()); err != nil {
		s.log.Error("could not pause an NWC pairing whose requests keep crashing the handler",
			"connection", connectionID, "error", err.Error())
		return
	}
	s.log.Error("an NWC pairing has been paused after repeated panics; it will not be served "+
		"until the operator re-enables it", "connection", connectionID, "panics", count)
	s.auditBounded(ctx, s.panics, slog.LevelWarn,
		"an NWC pairing was paused by the app after its requests repeatedly crashed the "+
			"handler; the operator can re-enable it from the Connections page",
		logging.EventConnectionPause,
		[]any{"connection", connectionID, "panics", count},
		slog.Int64("connection", connectionID),
		slog.Int("panics", count))
	// Ask Run to re-read the table. It owns the live map, so that is the one
	// place the connection can be closed AND forgotten — see Service.demand.
	// Non-blocking: a reload already pending does this one's job, and a service
	// wired without a channel simply waits for the next reload.
	select {
	case s.demand <- struct{}{}:
	default:
	}
}
