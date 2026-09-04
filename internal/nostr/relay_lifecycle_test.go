package nostr_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
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

// blackHole is a TCP listener that accepts connections and never answers the
// websocket upgrade.
//
// A raw net.Listener and deliberately NOT an httptest.Server with a blocking
// handler: httptest.Server.Close waits for its handlers to return, so a server
// whose handler is parked for ever hangs the test's own cleanup rather than the
// code under test.
//
// It HOLDS what it accepts. A listener that accepted and closed would hand the
// dialler an immediate EOF, which fails fast — the opposite of the case this
// exists to be. Holding is what makes the connect phase hang, which is the
// failure the field measured.
//
// The fleet's `hold` is the OTHER case and the two are not interchangeable: that
// one connects and withholds the OK, which §7 says must still be waited for.
// This one withholds the handshake.
type blackHole struct {
	url string

	mu    sync.Mutex
	live  int
	conns []net.Conn
}

func newBlackHole(t *testing.T) *blackHole {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &blackHole{url: "ws://" + listener.Addr().String()}
	accepting := make(chan struct{})
	go func() {
		defer close(accepting)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			h.live++
			h.conns = append(h.conns, conn)
			h.mu.Unlock()
			// Read and discard, so the count falls when the CLIENT closes —
			// which is the assertion this type is here to support. Nothing is
			// ever written back, so the upgrade never completes.
			go func() {
				_, _ = io.Copy(io.Discard, conn)
				h.mu.Lock()
				h.live--
				h.mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-accepting
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, conn := range h.conns {
			_ = conn.Close()
		}
	})
	return h
}

func (h *blackHole) counts() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.live
}

// du9 criterion 1. A publish waits for relays that answer, never for relays that
// are down (§7).
//
// The bug this replaces was a flat 15.0 s per zap receipt on any install with
// one unreachable relay in its list, measured on the box five times out of five
// with relays=6 accepted=4 — go-nostr's EnsureRelay dials under a hardcoded
// fifteen seconds hung off the pool's context, and PublishMany closes its result
// channel only once every per-relay goroutine has returned.
//
// The budget is read from the CONSTANT. Asserting against five seconds would
// pass on the day somebody raised it to thirty, which is the change this test
// exists to catch.
//
// The two live relays are a positive control: a run in which everything failed
// would be fast for the wrong reason.
func TestAPublishIsNotHeldUpByARelayThatNeverConnects(t *testing.T) {
	// Each of these pays the full connect budget on a black hole of its own;
	// in series that is the package's slowest twenty seconds, twice under -race.
	t.Parallel()
	configured := newFleet(t, 2)
	hole := newBlackHole(t)

	pool := lifetimePool(t, configured.urls)
	defer pool.Close()

	start := time.Now()
	results := pool.Publish(t.Context(), signedNote(t), hole.url)
	elapsed := time.Since(start)

	// Two seconds of slack over the budget, for the two live relays' own
	// handshake and OK on a loaded CI box.
	if limit := nostr.ConnectBudget + 2*time.Second; elapsed > limit {
		t.Errorf("the publish took %s, want under %s — a relay that is down must cost the "+
			"connect budget (%s) and not the library's hardcoded fifteen seconds",
			elapsed.Round(time.Millisecond), limit, nostr.ConnectBudget)
	}
	if got := nostr.Accepted(results); got != 2 {
		t.Errorf("%d of the 2 live relays accepted the event: %+v — a fast publish that "+
			"delivered nothing is not the fix", got, results)
	}
	// Per relay, never a failed batch: o34.3's retry reads these, and a
	// black-holed relay is one failed result rather than a failed publish.
	switch got := resultFor(results, hole.url); {
	case got == nil:
		t.Errorf("the black hole got no result at all: %+v; it was named, so it must be "+
			"reported", results)
	case got.OK():
		t.Errorf("the black hole reported success: %+v", results)
	case !strings.Contains(got.Err.Error(), nostr.ConnectBudget.String()):
		t.Errorf("the failure does not name the budget: %v", got.Err)
	}
}

// du9, and the case relay_lifecycle_test did not have: a relay that never
// completes its handshake must leave nothing behind either.
//
// The closed sockets of 0ak were of relays that CONNECTED. A relay abandoned
// mid-handshake is a different object — go-nostr's NewRelay starts no goroutines
// until Connect returns, so what has to be true is that the half-open TCP
// connection is closed and that nothing was stored in the pool under its URL.
//
// BOTH ARMS, because only the second one is load-bearing and the first one alone
// looks like it is. A sender-named relay is covered whatever Pool.dial does: the
// deferred closeTransient closes anything this publish added that is not the
// operator's, so storing a relay that never connected would be swept up and the
// assertion would pass. The operator's OWN relay is not swept, and storing a
// never-connected one there is the bad case with teeth: IsConnected() is
// "not closed" rather than "has a socket", so a stored never-connected relay
// reads as live for ever — Pool.connect would stop dialling it and EnsureRelay
// would hand the dead object to PublishMany, on the operator's own relay, on
// every publish from then on.
//
// It PASSES before du9 as well, in fifteen seconds rather than five: it is a
// guard on the new dialling path, not a regression test for the bug.
func TestARelayThatNeverCompletesItsHandshakeLeavesNothingBehind(t *testing.T) {
	// Each of these pays the full connect budget on a black hole of its own;
	// in series that is the package's slowest twenty seconds, twice under -race.
	t.Parallel()
	for _, tc := range []struct {
		name        string
		senderNamed bool
	}{
		{name: "named by a sender", senderNamed: true},
		{name: "the operator's own", senderNamed: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			live := newFleet(t, 1)
			hole := newBlackHole(t)

			relays := live.urls
			var extra []string
			if tc.senderNamed {
				extra = []string{hole.url}
			} else {
				relays = func() []string { return append(live.urls(), hole.url) }
			}
			pool := lifetimePool(t, relays)
			defer pool.Close()

			results := pool.Publish(t.Context(), signedNote(t), extra...)
			if got := nostr.Accepted(results); got != 1 {
				t.Fatalf("%d of 1 live relays accepted the event: %+v", got, results)
			}
			if got := resultFor(results, hole.url); got == nil || got.OK() {
				t.Errorf("the black hole is not reported as failed: %+v", results)
			}
			lndtest.WaitFor(t, "the abandoned connection to the black hole to close", func() bool {
				return hole.counts() == 0
			})
			if got := pool.Connected(); len(got) != 1 {
				t.Errorf("the pool holds %d relays (%v), want only the 1 live one — a relay "+
					"that never connected must not be stored, whoever named it", len(got), got)
			}
		})
	}
}

// syncBuffer is a log sink two goroutines may reach.
//
// slog serialises a single record, not the buffer behind several handlers, and
// the publish path logs from the dialler's goroutine as well as its own. A bare
// bytes.Buffer here is a data race that -race would find on some runs and not
// others.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// loggedPool builds a pool whose DEBUG output is captured.
func loggedPool(t *testing.T, relays func() []string) (*nostr.Pool, *syncBuffer) {
	t.Helper()
	out := &syncBuffer{}
	pool := nostr.NewPool(t.Context(), relays, nostr.Options{
		Resolve: publicDNS,
		Log:     logging.New(out, logging.NewLevelVar(slog.LevelDebug)),
	})
	nostr.StandDownDialPolicy(pool)
	return pool, out
}

// costRecord is one relay's per-relay record as logged: its outcome and cost.
type costRecord struct {
	Outcome string
	MS      int64
}

// relayCosts is the per-relay records of one captured log, keyed by relay.
type relayCosts map[string]costRecord

// relayKey is how the map is keyed: go-nostr's NormalizeURL gives a bare host a
// trailing slash, and the tests write URLs without one, so both forms meet here.
func relayKey(url string) string { return strings.TrimSuffix(url, "/") }

// costFor is the record for a relay, looked up by the URL as the test wrote it.
func (c relayCosts) costFor(url string) costRecord { return c[relayKey(url)] }

// costRecords picks the per-relay records out of a captured log.
func costRecords(t *testing.T, logged string) relayCosts {
	t.Helper()
	out := relayCosts{}
	for _, record := range logLines(t, logged) {
		msg, _ := record["msg"].(string)
		if !strings.HasPrefix(msg, "relay outcome") {
			continue
		}
		relay, _ := record["relay"].(string)
		key := relayKey(relay)
		if _, seen := out[key]; seen {
			t.Errorf("two records for %s; one per relay, or the line cannot be read as "+
				"a relay's cost", relay)
		}
		outcome, _ := record["outcome"].(string)
		ms, _ := record["ms"].(float64)
		out[key] = costRecord{Outcome: outcome, MS: int64(ms)}
	}
	return out
}

// du9 criterion 2 / §7 part 3: the measurement lands with the fix.
//
// Without it nobody can show the fix worked, and the bug it fixed hid for weeks
// precisely because nothing stated the interval. The claim is not "a DEBUG call
// exists" but "the relay that cost the time can be named from a box", so the
// assertions are on the numbers: the black hole must show the budget and the
// live relay must not.
//
// The quiet half is as much of the rule as the loud one. A record per relay on
// every healthy publish is noise an operator filters out, after which the lines
// are absent on the day they are wanted.
func TestASlowOrPartialPublishNamesWhatEachRelayCost(t *testing.T) {
	// Each of these pays the full connect budget on a black hole of its own;
	// in series that is the package's slowest twenty seconds, twice under -race.
	t.Parallel()
	t.Run("slow and partial", func(t *testing.T) {
		live := newFleet(t, 1)
		hole := newBlackHole(t)
		pool, logged := loggedPool(t, live.urls)
		defer pool.Close()

		results := pool.Publish(t.Context(), signedNote(t), hole.url)
		if nostr.Accepted(results) != 1 {
			t.Fatalf("the live relay did not accept: %+v", results)
		}

		records := costRecords(t, logged.String())
		if len(records) != 2 {
			t.Fatalf("%d per-relay records, want 2 — one for each relay in the publish\n%s",
				len(records), logged.String())
		}

		// The relay that cost the time, named, with the cost on it. The label
		// was not_connected until du9.3 split it: a relay that ate the budget
		// and one that failed fast were the same word, which is the distinction
		// TestARelayThatHangsAndOneThatRefusesTheUpgradeAreRecordedDifferently
		// now owns. The claim here is unchanged — only the vocabulary moved.
		down := records.costFor(hole.url)
		if down.Outcome != "over_budget" {
			t.Errorf("the black hole's outcome is %q, want %q — a relay that ate the whole "+
				"connect budget and one that merely failed to connect are different faults "+
				"on a box", down.Outcome, "over_budget")
		}
		// Within a tenth of the budget: the assertion is that the duration is
		// the real one and not a zero that happens to be logged.
		if floor := (nostr.ConnectBudget - nostr.ConnectBudget/10).Milliseconds(); down.MS < floor {
			t.Errorf("the black hole is recorded at %dms, want at least %dms — it held the "+
				"publish for the whole budget", down.MS, floor)
		}

		// And the relay that did NOT cost the time must not read as if it had,
		// which is what makes the pair of numbers an answer rather than a
		// timestamp. Its own dial and OK, with the connect barrier subtracted.
		up := records.costFor(live.urls()[0])
		if up.Outcome != "accepted" {
			t.Errorf("the live relay's outcome is %q, want %q", up.Outcome, "accepted")
		}
		if ceiling := nostr.ConnectBudget / 2; up.MS >= ceiling.Milliseconds() {
			t.Errorf("the live relay is recorded at %dms, want well under %s — it answered "+
				"at once, and a record that blames it too names nobody", up.MS, ceiling)
		}
	})

	t.Run("a healthy publish says nothing", func(t *testing.T) {
		live := newFleet(t, 2)
		pool, logged := loggedPool(t, live.urls)
		defer pool.Close()

		if got := nostr.Accepted(pool.Publish(t.Context(), signedNote(t))); got != 2 {
			t.Fatalf("%d of 2 relays accepted the event", got)
		}
		if records := costRecords(t, logged.String()); len(records) != 0 {
			t.Errorf("%d per-relay records on a fast, complete publish, want none\n%s",
				len(records), logged.String())
		}
	})
}

// shedding is a relay that completes TCP and TLS and then rejects the websocket
// upgrade, which is how a front proxy sheds load — relay.damus.io's 503s on the
// relay probe are exactly this.
//
// An ordinary httptest.Server is right here and wrong for the black hole, which
// is the distinction worth keeping straight: this handler RETURNS, so Close has
// nothing to wait for, while a handler parked for ever would hang the test's own
// cleanup. See newBlackHole, which is a raw listener for that reason.
func newShedding(t *testing.T, status int) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return "ws://" + strings.TrimPrefix(server.URL, "http://")
}

// du9.3: a relay that HANGS and a relay that REFUSES FAST must not read the same.
//
// They did. On the 0.1.19-rc1 trip — the first per-relay records ever read off a
// box — relay.nostr.band (TCP never completes) and relay.damus.io (503 at the
// upgrade) were both recorded not_connected, one at 5000 ms and the other at
// 241 ms. The durations told them apart and the labels did not, which is a
// diagnosis left as arithmetic for whoever reads the journal: "is 241 ms fast?"
// requires already knowing what the budget is.
//
// The two are opposite operational facts. One ate the whole budget and IS why
// the publish was slow; the other cost nothing and is merely unavailable.
func TestARelayThatHangsAndOneThatRefusesTheUpgradeAreRecordedDifferently(t *testing.T) {
	// Each of these pays the full connect budget on a black hole of its own;
	// in series that is the package's slowest twenty seconds, twice under -race.
	t.Parallel()
	live := newFleet(t, 1)
	hangs := newBlackHole(t)
	refuses := newShedding(t, http.StatusServiceUnavailable)

	pool, logged := loggedPool(t, live.urls)
	defer pool.Close()

	results := pool.Publish(t.Context(), signedNote(t), hangs.url, refuses)
	if nostr.Accepted(results) != 1 {
		t.Fatalf("the live relay did not accept, so this proves nothing about the other "+
			"two: %+v", results)
	}

	records := costRecords(t, logged.String())
	if len(records) != 3 {
		t.Fatalf("%d per-relay records, want 3\n%s", len(records), logged.String())
	}

	hung := records.costFor(hangs.url)
	shed := records.costFor(refuses)

	// The claim, stated as the two labels differing rather than as two separate
	// equality checks: an implementation that labelled both the same would
	// satisfy either check alone if the expected value were the one it chose.
	if hung.Outcome == shed.Outcome {
		t.Errorf("both are recorded %q — a relay that ate the %s budget and one that "+
			"refused the upgrade in milliseconds are the same line",
			hung.Outcome, nostr.ConnectBudget)
	}
	if hung.Outcome != "over_budget" {
		t.Errorf("the relay that hung is recorded %q, want %q", hung.Outcome, "over_budget")
	}
	if shed.Outcome != "not_connected" {
		t.Errorf("the relay that refused the upgrade is recorded %q, want %q — it never "+
			"connected, and it did not cost the budget either", shed.Outcome, "not_connected")
	}

	// And the durations still agree with the labels, so the two halves of the
	// record cannot drift apart.
	if floor := (nostr.ConnectBudget - nostr.ConnectBudget/10).Milliseconds(); hung.MS < floor {
		t.Errorf("the relay that hung is recorded at %dms, want at least %dms", hung.MS, floor)
	}
	if ceiling := (nostr.ConnectBudget / 2).Milliseconds(); shed.MS >= ceiling {
		t.Errorf("the relay that refused is recorded at %dms, want well under %dms — it "+
			"answered at once", shed.MS, ceiling)
	}
}

// assertPromptly is how the three d1o tests state their claim: the relay had the
// event long before the dead one's dial could possibly have finished.
//
// A POSITIVE TIME BOUND, and the first version of these tests did not have one —
// it asserted instead that Publish had not returned yet, with a non-blocking
// receive taken the moment the relay's arrival count moved. That is a RACE
// AGAINST THE BUG rather than a measurement of it. Under the barrier being
// fixed, the dial finishes and the send to the open relay follows within
// milliseconds, so "the event arrived" and "Publish returned" land together and
// which one the poll sees is a coin flip: measured against the pre-fix code, one
// of those tests passed 3 times in 10 and another 4 times in 10 — passing
// against exactly the bug it exists to catch. It looked reliable only because
// the whole-tree plant runs it alongside everything else, and the load hid it.
//
// Half the connect budget is the bound. Under the fix the arrival is immediate;
// under the barrier it cannot happen before the budget elapses. Nothing lives in
// between, which is what makes the margin wide instead of tight.
func assertPromptly(t *testing.T, started time.Time, what string) {
	t.Helper()
	elapsed, limit := time.Since(started), nostr.ConnectBudget/2
	if elapsed > limit {
		t.Errorf("%s after %s, want under %s — it waited for the dead relay's dial",
			what, elapsed.Round(time.Millisecond), limit)
	}
}

// d1o, the NWC half and the one that matters: §8 gives one response attempt
// exactly the connect budget, so a dead relay in a pairing's list can spend all
// of it dialling and leave nothing for the live one.
//
// ResponseAttemptTimeout is 5 s (internal/nwc/publish.go) and connectBudget is
// 5 s, and the dial context DERIVES from the attempt's. Before this fix the
// connect phase was a barrier: every dial had to finish before anything was
// sent, so a pairing holding one dead relay dialled it for the whole attempt and
// then published to its live, already-subscribed relay against a context that
// had just expired.
//
// It is a REGRESSION introduced by du9. Before that, the library's own fan-out
// sent to the live relay immediately while the dead one was still dialling.
//
// The live relay is SUBSCRIBED, which is what makes it already-open and is the
// real shape: an NWC pairing holds its relays open for the life of the pairing.
func TestAnNWCResponseReachesTheLiveRelayWhileADeadOneIsStillDialling(t *testing.T) {
	// Another black hole, another full connect budget; in series these three
	// would add fifteen seconds to the package, more under -race. The timing
	// claim below survives it: what it asserts is that the publish has not
	// returned in the seconds the dead relay still has left to dial.
	t.Parallel()
	live := newFleet(t, 1)
	hole := newBlackHole(t)

	pool := lifetimePool(t, func() []string { return nil })
	defer pool.Close()

	sub, err := pool.Subscribe(t.Context(), live.urls()[0], gonostr.Filter{Kinds: []int{23194}})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()
	lndtest.WaitFor(t, "the pairing's relay to accept the subscription", func() bool {
		open, _ := live.counts()
		return open == 1
	})

	// The attempt budget, exactly as §8 sets it and exactly equal to the connect
	// budget. This is the arrangement the bug needs, not a contrived one.
	ctx, cancel := context.WithTimeout(t.Context(), nostr.ConnectBudget)
	defer cancel()

	started := time.Now()
	done := make(chan []nostr.PublishResult, 1)
	go func() {
		done <- pool.PublishToConnection(ctx, signedNote(t),
			nostr.PairingRelays([]string{live.urls()[0], hole.url}))
	}()

	// The claim, measured from the RELAY's side: the response is handed to the
	// live relay while the dead one is still being dialled, not after it.
	lndtest.WaitFor(t, "the live relay to be handed the response", func() bool {
		_, arrived := live.counts()
		return arrived == 1
	})
	assertPromptly(t, started, "the live relay was handed the response")

	select {
	case results := <-done:
		// And the result says so. Against an expired context the send fails,
		// the attempt is recorded as failed and retried, and every retry pays
		// the same five seconds again.
		if got := resultFor(results, live.urls()[0]); got == nil || !got.OK() {
			t.Errorf("the live, already-subscribed relay did not take the response: %+v — "+
				"the dial for the dead relay spent the whole attempt budget", results)
		}
		if got := resultFor(results, hole.url); got == nil || got.OK() {
			t.Errorf("the dead relay is not reported as failed: %+v", results)
		}
	case <-time.After(nostr.ConnectBudget + 5*time.Second):
		t.Fatal("PublishToConnection never returned")
	}
}

// d1o, the receipt half: latency only, but the same barrier.
//
// §7 says nobody is waiting on a receipt and publishTimeout is 30 s, so the
// event still goes out — every healthy relay just gets it up to a whole connect
// budget later than it could have, whenever one dead relay is in the list. That
// is the ordinary case on an install with a stale relay list.
//
// The configured relay is opened by a first publish, so the second one finds it
// already connected — which is the state the pool is in for every publish after
// the first.
func TestAnAlreadyOpenRelayIsSentToWhileAnotherIsStillDialling(t *testing.T) {
	// Another black hole, another full connect budget; in series these three
	// would add fifteen seconds to the package, more under -race. The timing
	// claim below survives it: what it asserts is that the publish has not
	// returned in the seconds the dead relay still has left to dial.
	t.Parallel()
	configured := newFleet(t, 1)
	hole := newBlackHole(t)

	pool := lifetimePool(t, configured.urls)
	defer pool.Close()

	if got := nostr.Accepted(pool.Publish(t.Context(), signedNote(t))); got != 1 {
		t.Fatalf("%d of 1 relays accepted the first event; the fleet is not answering", got)
	}

	started := time.Now()
	done := make(chan []nostr.PublishResult, 1)
	go func() { done <- pool.Publish(t.Context(), signedNote(t), hole.url) }()

	lndtest.WaitFor(t, "the open relay to be handed the second event", func() bool {
		_, arrived := configured.counts()
		return arrived == 2
	})
	assertPromptly(t, started, "the open relay was handed the event")

	select {
	case results := <-done:
		if got := nostr.Accepted(results); got != 1 {
			t.Errorf("%d relays accepted: %+v", got, results)
		}
	case <-time.After(nostr.ConnectBudget + 5*time.Second):
		t.Fatal("the publish never returned")
	}
}

// d1o, and the case that decides the SHAPE of the fix rather than whether to
// fix it.
//
// The bead proposed two phases: send to the already-open relays at once,
// concurrently with dialling the rest. That leaves the same barrier inside the
// dialled group — nothing is open on the first publish after a restart, so a
// live relay would still wait for a dead one, and for an NWC pairing that is
// precisely the moment a subscription has dropped and the response matters most.
//
// So: no relay waits for another, open or not. This is the FIRST publish on a
// fresh pool, which is what makes the live relay unopened.
func TestARelayThatIsNotOpenYetIsAlsoNotHeldUpByADeadOne(t *testing.T) {
	// Another black hole, another full connect budget; in series these three
	// would add fifteen seconds to the package, more under -race. The timing
	// claim below survives it: what it asserts is that the publish has not
	// returned in the seconds the dead relay still has left to dial.
	t.Parallel()
	configured := newFleet(t, 1)
	hole := newBlackHole(t)

	pool := lifetimePool(t, configured.urls)
	defer pool.Close()
	if got := pool.Connected(); len(got) != 0 {
		t.Fatalf("the pool already holds %v; this test needs the live relay UNOPENED, or it "+
			"is the already-open case again", got)
	}

	started := time.Now()
	done := make(chan []nostr.PublishResult, 1)
	go func() { done <- pool.Publish(t.Context(), signedNote(t), hole.url) }()

	lndtest.WaitFor(t, "the live relay to be handed the event", func() bool {
		_, arrived := configured.counts()
		return arrived == 1
	})
	assertPromptly(t, started, "the live relay was handed the event")

	select {
	case results := <-done:
		if got := nostr.Accepted(results); got != 1 {
			t.Errorf("%d relays accepted: %+v", got, results)
		}
	case <-time.After(nostr.ConnectBudget + 5*time.Second):
		t.Fatal("the publish never returned")
	}
}
