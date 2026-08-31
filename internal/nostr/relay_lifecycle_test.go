package nostr_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/nostr"
)

// publicDNS is the resolver these fleets need, spelled once.
//
// They are httptest servers on 127.0.0.1, and the pool now refuses a
// STRANGER-named relay whose addresses are not public — correctly; that is z9k,
// and internal/nostr/dialable_test.go is where it is asserted. These tests are
// about the lifetime of a socket, not about who may open one, so they hand the
// pool a resolver that says "public" and let the dial go where the URL actually
// points. That the checked address and the dialled address can differ is the
// residual dialableHost names in its own doc.
//
// vz1.4 closed that residual, so the pre-check is no longer the only gate: the
// DIAL is checked too, on its own resolution, and loopback is what it refuses.
// The seam these tests were leaning on is gone, so they declare one —
// anyAddress, below — rather than getting it from a hole in the product.
var publicDNS = answers{addrs: []string{"93.184.216.34"}}

// lifetimePool is a pool for the tests below, whose subject is the LIFETIME of a
// stranger's socket rather than whether it may exist. It stands the dial-time
// address policy down; nostr.StandDownDialPolicy explains why that is needed and
// why the seam lives in export_test.go.
func lifetimePool(t *testing.T, relays func() []string) *nostr.Pool {
	t.Helper()
	pool := nostr.NewPool(t.Context(), relays, nostr.Options{Resolve: publicDNS})
	nostr.StandDownDialPolicy(pool)
	return pool
}

// fleet is a set of in-process nostr relays that count their own live
// connections.
//
// Real websockets, not a fake pool. The claim under test is "the connection is
// closed when the publish finishes", and a fake that never opens one would let
// every assertion below pass while the sockets piled up exactly as before —
// which is the shape of the bug this bead exists to fix.
type fleet struct {
	mu sync.Mutex
	// live is the number of connections currently open across every relay.
	live int
	// arrived is the number of events the fleet has been handed.
	arrived int
	// hold, once set, makes every relay wait for it to be closed before
	// answering OK — which is what lets a publish be caught mid-flight, with
	// its sockets open and nothing yet torn down.
	hold    chan struct{}
	servers []*httptest.Server
}

func newFleet(t *testing.T, n int) *fleet {
	t.Helper()
	// Real relays, torn down under -race — see TestTearingDownAConnectedRelayIsRaceFree.
	f := &fleet{}
	for range n {
		server := httptest.NewServer(http.HandlerFunc(f.serve))
		t.Cleanup(server.Close)
		f.servers = append(f.servers, server)
	}
	return f
}

// urls returns the fleet's relay addresses as ws:// URLs.
func (f *fleet) urls() []string {
	var out []string
	for _, s := range f.servers {
		out = append(out, "ws://"+strings.TrimPrefix(s.URL, "http://"))
	}
	return out
}

func (f *fleet) serve(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	f.enter()
	defer f.leave()
	defer conn.CloseNow() //nolint:errcheck // the test relay is going away regardless

	ctx := r.Context()
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var msg []json.RawMessage
		if err := json.Unmarshal(data, &msg); err != nil || len(msg) < 2 {
			continue
		}
		var kind string
		if err := json.Unmarshal(msg[0], &kind); err != nil || kind != "EVENT" {
			continue
		}
		var event gonostr.Event
		if err := json.Unmarshal(msg[1], &event); err != nil {
			continue
		}
		if hold := f.received(); hold != nil {
			select {
			case <-hold:
			case <-ctx.Done():
				return
			}
		}
		if err := conn.Write(ctx, websocket.MessageText,
			[]byte(fmt.Sprintf(`["OK",%q,true,""]`, event.ID))); err != nil {
			return
		}
	}
}

func (f *fleet) enter() { f.mu.Lock(); f.live++; f.mu.Unlock() }
func (f *fleet) leave() { f.mu.Lock(); f.live--; f.mu.Unlock() }

// holdUntil makes every relay in the fleet wait for release before answering.
func (f *fleet) holdUntil(release chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hold = release
}

// received books an event in and reports what, if anything, the relay must wait
// for before answering it.
func (f *fleet) received() chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.arrived++
	return f.hold
}

func (f *fleet) counts() (live, arrived int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.live, f.arrived
}

// settle waits for the fleet to stop changing and reports what it stopped at.
//
// The reading it exists to take is a NEGATIVE — that no ninth socket appears —
// and one sample cannot tell "there is no ninth" from "the ninth has not been
// dialled yet". Stillness can: these relays are in-process, so a fleet that has
// not moved for a tenth of a second is not about to.
//
// It never fails the test on its own, because its caller is holding a publish
// open and must get to the release.
func (f *fleet) settle(t *testing.T) (live, arrived int) {
	t.Helper()
	const (
		poll  = 2 * time.Millisecond
		still = 50   // consecutive unchanged polls
		limit = 3000 // ~6s, long enough that only a hang reaches it
	)
	var last [2]int
	var unchanged int
	for range limit {
		var now [2]int
		now[0], now[1] = f.counts()
		if now != last || now[0] == 0 {
			unchanged = 0
		} else {
			unchanged++
		}
		if unchanged == still {
			return now[0], now[1]
		}
		last = now
		time.Sleep(poll)
	}
	t.Errorf("the relay fleet never went still: %d live, %d events", last[0], last[1])
	return last[0], last[1]
}

func signedNote(t *testing.T) gonostr.Event {
	t.Helper()
	id, err := nostr.Generate()
	if err != nil {
		t.Fatal(err)
	}
	event := &gonostr.Event{Kind: 1, CreatedAt: gonostr.Timestamp(1_700_000_000)}
	if err := id.Sign(event); err != nil {
		t.Fatal(err)
	}
	return *event
}

// 0ak criteria 1 and 2. Every distinct relay URL a stranger has ever named used
// to leave a live websocket plus its ping and read goroutines running for the
// life of the process — on a Pi, memory and descriptors accumulating at a rate
// strangers choose.
//
// The pool now holds persistent connections only to the operator's set, and the
// count is what is asserted: a claim about closing sockets that did not count
// sockets would be a claim about the code, not about the sockets.
func TestSenderNamedRelaysAreClosedWhenThePublishFinishes(t *testing.T) {
	configured := newFleet(t, 2)
	strangers := newFleet(t, 5)

	pool := lifetimePool(t, configured.urls)
	defer pool.Close()

	results := pool.Publish(t.Context(), signedNote(t), strangers.urls()...)
	if got := nostr.Accepted(results); got != 7 {
		t.Fatalf("%d of 7 relays accepted the event; the fleet is not answering", got)
	}

	// The operator's relays stay. The strangers' do not.
	lndtest.WaitFor(t, "the sender-named connections to close", func() bool {
		live, _ := strangers.counts()
		return live == 0
	})
	if live, _ := configured.counts(); live != 2 {
		t.Errorf("%d configured connections are live, want 2 — the pool must keep the "+
			"operator's own relays", live)
	}
	if got := pool.Connected(); len(got) != 2 {
		t.Errorf("the pool holds %d relays (%v), want only the 2 configured ones",
			len(got), got)
	}
}

// Criterion 4. The bound must not depend on how many goroutines happen to
// publish: Pool.Publish serialises, so a second publisher added later cannot
// silently double the sockets a stranger can have open at once.
//
// Measured from inside the publishes, not inferred from the design — one
// publish is HELD at the relays while the count is taken, so the sockets being
// counted are sockets that are genuinely open at that instant.
//
// The holding is the whole design, and it is a bug fix (23 Aug 2026). This used
// to sample the fleet as each event arrived and assert on the high-water mark,
// and it failed twice in CI at 9 on commits that changed no Go code. A relay
// decrements its own count when its handler goroutine notices the client has
// gone, which happens some scheduler-decided time AFTER the publish closed the
// socket and released the lock — so the ninth was a socket this node had
// already closed. Planting a 5ms delay in fleet.leave reproduced it at 16 with
// the pool behaving perfectly, which is the proof that the number was never
// about the pool. Held publishes have closed nothing yet, so the count is exact.
func TestSenderNamedConnectionsStayUnderTheCapUnderConcurrentPublishes(t *testing.T) {
	configured := newFleet(t, 1)
	// ONE fleet, so one counter — split into two DISJOINT halves, because that
	// is the only shape that can double the bound. Four publishers naming the
	// same relays share sockets: go-nostr's pool keys connections by URL and
	// reuses them, so that test passes whether or not publishes are
	// serialised, which is to say it proves nothing. Two strangers naming
	// different relays is the case where an unserialised pool opens 2×.
	strangers := newFleet(t, nostr.MaxTransientRelays*2)
	all := strangers.urls()
	first, second := all[:nostr.MaxTransientRelays], all[nostr.MaxTransientRelays:]

	release := make(chan struct{})
	strangers.holdUntil(release)

	pool := lifetimePool(t, configured.urls)
	defer pool.Close()

	var wg sync.WaitGroup
	for _, set := range [][]string{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pool.Publish(context.Background(), signedNote(t), set...)
		}()
	}

	// One publisher's relays are now answering and holding; the other is
	// waiting for the lock and has dialled nothing. Wait for stillness rather
	// than for a number — an unserialised pool dials its second eight while the
	// first eight are held here, so it goes still at 16, not at 8.
	live, arrived := strangers.settle(t)
	close(release)
	wg.Wait()

	if live != nostr.MaxTransientRelays || arrived != nostr.MaxTransientRelays {
		t.Errorf("%d sender-named sockets open and %d events delivered while one publish "+
			"was held, want %d of each — a second publisher must not widen the number of "+
			"sockets a stranger can make this node hold",
			live, arrived, nostr.MaxTransientRelays)
	}
	lndtest.WaitFor(t, "every sender-named connection to close", func() bool {
		live, _ := strangers.counts()
		return live == 0
	})
}

// The named guard for the go.mod replace (bead bym).
//
// go-nostr v0.52.3's Relay.close() cancelled the connection context and then read
// a field its own writer goroutine nils on that cancellation, so every teardown
// of a CONNECTED relay was a data race — and losing it between the nil check and
// the Close() call was a nil-pointer dereference inside the library, in a process
// that handles payments. Pool.Close() had done it at every shutdown since Wave 8;
// Wave 12 moved it onto the settlement path.
//
// This test exists so the guard is a test with a name rather than a side effect
// of the two socket-counting tests above, which could reasonably be rewritten
// against a fake pool one day and would take the guard with them silently. To see
// it work, point the replace in go.mod back at upstream v0.52.3: it races again.
//
// It does NOT cover the whole class — Subscribe and ConnectionError still race
// upstream of the fix, unreachable until §8 subscribes (BrollyZap-o34.19). This
// is the natural home for those cases when they land.
func TestTearingDownAConnectedRelayIsRaceFree(t *testing.T) {
	// Repeated, because the window is between two adjacent statements: one
	// teardown that happens to win is not evidence.
	for range 20 {
		relays := newFleet(t, 1)
		pool := lifetimePool(t, relays.urls)
		// Publish first: closing a relay that was never CONNECTED takes the
		// early return and proves nothing.
		if got := nostr.Accepted(pool.Publish(t.Context(), signedNote(t))); got != 1 {
			t.Fatalf("%d of 1 relays accepted the event; the relay is not connected, so "+
				"this test would prove nothing", got)
		}
		pool.Close()
	}
}

// The zap-receipt path still gets its THIRTY seconds (d24.25).
//
// The NWC response path now bounds each of its own attempts at five, and the
// obvious way to build that would have been to make publishTimeout smaller —
// which would have narrowed this path too, silently, to a number chosen for a
// different problem. §7 publishes a receipt best-effort to six relays and
// tolerates most of them refusing; a relay that takes six seconds to answer OK
// is a relay whose acceptance is still worth having, because nobody is waiting.
//
// Asserted by holding the relay's OK past the NWC budget and then releasing it:
// the publish must SUCCEED. It costs a few seconds of the gate, which is the
// price of the assertion being about behaviour rather than about a constant's
// value — and the failure it is here to catch (a shared constant quietly
// re-narrowed) is exactly the kind that an artifact check would let through
// after a refactor moved the number somewhere else.
func TestTheReceiptPathIsNotNarrowedToTheNWCResponseBudget(t *testing.T) {
	fleet := newFleet(t, 1)
	pool := lifetimePool(t, fleet.urls)

	release := make(chan struct{})
	fleet.holdUntil(release)
	done := make(chan []nostr.PublishResult, 1)
	go func() { done <- pool.Publish(t.Context(), signedNote(t)) }()

	// Longer than the NWC path's five seconds, and far short of thirty.
	const heldFor = 7 * time.Second
	select {
	case results := <-done:
		t.Fatalf("the receipt publish returned after less than %s: %+v — the NWC response "+
			"path's budget has been applied to the path it was deliberately kept off",
			heldFor, results)
	case <-time.After(heldFor):
	}
	close(release)

	select {
	case results := <-done:
		if nostr.Accepted(results) != 1 {
			t.Errorf("the relay answered after %s and the publish had already given up: %+v",
				heldFor, results)
		}
	case <-time.After(20 * time.Second):
		t.Error("the receipt publish never returned after the relay answered")
	}
}
