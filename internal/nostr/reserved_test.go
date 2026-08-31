package nostr

// An INTERNAL test, deliberately. The property zu5.1 asks for is "one case per
// entry in reservedPrefixes", and the only way to assert that the cases and the
// table stay in step is to be able to count the table.

import (
	"bytes"
	"context"
	"fmt"
	"github.com/davotoula/brollyzapper/internal/logging"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
)

// reservedCases is one representative address per entry in reservedPrefixes,
// written out LITERALLY and never derived from the table.
//
// That is the whole design. A test that ranges over reservedPrefixes and picks
// an address out of each entry cannot fail when an entry is deleted, because the
// case is deleted with it — it would be asserting that the table matches itself.
// These rows are independent, so removing a prefix leaves one row with nothing
// to catch it, and that row alone fails.
var reservedCases = []struct {
	what string
	addr string
}{
	// CGNAT by name, because it is the one that was actually missed: the first
	// Wave 12 version of this table left it out, which allowed every Tailscale
	// address on a box that is routinely on a tailnet. It is not RFC1918, so
	// IsPrivate does not catch it, and nothing else in dialableAddr does either.
	{"CGNAT, and therefore every Tailscale address", "100.64.0.1"},
	{"IETF protocol assignments", "192.0.0.8"},
	// Inside the SECOND half of the /15: a case in 198.18.x would still pass if
	// someone narrowed the prefix to a /16.
	{"benchmarking", "198.19.255.1"},
	{"TEST-NET-1", "192.0.2.5"},
	{"TEST-NET-2", "198.51.100.5"},
	{"TEST-NET-3", "203.0.113.5"},
	{"NAT64, which wraps a v4 address in a v6 one", "64:ff9b::c000:221"},
	{"6to4, which wraps 192.168.77.1 in a v6 address", "2002:c0a8:101::1"},
}

// answersWith is a resolver that gives every host the same single address.
type answersWith netip.Addr

func (a answersWith) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.Addr(a)}, nil
}

// zu5.1 criteria 1 and 2. reservedPrefixes' CONTENTS are the security property,
// and until this existed no test read a single entry: dropping a line from the
// slice left the whole suite green. The table has been wrong twice — see its own
// comment — and both times a human re-reading the code is what found it. These
// are ranges IsGlobalUnicast still calls global, so nothing else in dialableAddr
// covers them.
//
// Asserted through the RESOLVING path, which is where the table now does its
// work, and which is the only path that reaches it for the two v6 entries: a v6
// literal is refused by dialableName long before any address is looked at
// (see TestAnIPv6LiteralIsRefusedForItsShapeNotItsRange), so a row phrased as
// Dialable("64:ff9b::…") would pass with the prefix deleted. Vacuous in exactly
// the way this bead exists to prevent.
func TestEveryReservedRangeIsRefused(t *testing.T) {
	if len(reservedCases) != len(reservedPrefixes) {
		t.Errorf("%d test cases for %d reserved prefixes — every entry needs its own "+
			"representative address, or the next one added is untested",
			len(reservedCases), len(reservedPrefixes))
	}
	for _, tc := range reservedCases {
		addr := netip.MustParseAddr(tc.addr)
		pool := NewPool(t.Context(), nil, Options{Resolve: answersWith(addr)})
		defer pool.Close()
		if pool.dialableHost(context.Background(), "relay.example") {
			t.Errorf("a name resolving to %s (%s) may be dialled; a stranger can point "+
				"this node at it", tc.addr, tc.what)
		}
	}
	// The v4 rows again, this time as literals, because that is the form
	// internal/lnurl refuses at parse time and it goes through Dialable rather
	// than through the pool.
	for _, tc := range reservedCases {
		if addr := netip.MustParseAddr(tc.addr); addr.Is4() && Dialable(tc.addr) {
			t.Errorf("the literal %s (%s) may be dialled", tc.addr, tc.what)
		}
	}
}

// The other direction, so the test can fail both ways. A filter that refused
// everything would satisfy the table above and take the product down with it —
// an SSRF filter that blocks ordinary relays is not a filter, it is an outage.
func TestOrdinaryPublicAddressesAreDialable(t *testing.T) {
	for _, addr := range []string{
		"93.184.216.34",        // example.com
		"8.8.8.8",              // a well-known resolver
		"1.1.1.1",              // another, and adjacent to no reserved range
		"2606:4700:4700::1111", // v6 global unicast, reachable only by resolution
	} {
		parsed := netip.MustParseAddr(addr)
		pool := NewPool(t.Context(), nil, Options{Resolve: answersWith(parsed)})
		defer pool.Close()
		if !pool.dialableHost(context.Background(), "relay.example") {
			t.Errorf("a name resolving to %s was refused; the allow-list is blocking "+
				"ordinary relays", addr)
		}
		if parsed.Is4() && !Dialable(addr) {
			t.Errorf("the literal %s was refused", addr)
		}
	}
}

// Known behaviour, written down because the table test above has to work around
// it: EVERY dotless host is refused, and an IPv6 literal has no dots. So
// wss://[2606:4700:4700::1111] is refused for its SHAPE, before its range is
// ever considered — the same rule that stops ws://router and ws://umbrel.
//
// That is stricter than it needs to be for a public v6 relay, and it is the
// safe direction to be wrong in, so it stands. It is recorded here so nobody
// reads a passing v6 row in the table test as evidence that the prefix worked.
func TestAnIPv6LiteralIsRefusedForItsShapeNotItsRange(t *testing.T) {
	const public = "2606:4700:4700::1111" // in no reserved prefix at all
	if Dialable(public) {
		t.Errorf("Dialable(%q) = true; this test records the opposite as known "+
			"behaviour — if the shape rule has changed, the v6 rows in "+
			"TestEveryReservedRangeIsRefused need re-checking for vacuity", public)
	}
	if !dialableAddr(netip.MustParseAddr(public)) {
		t.Errorf("%s is in a reserved range after all; the premise of this test is wrong",
			public)
	}
}

// Criterion 4: publishing is per-relay, and the union of the configured set and
// the ones the caller names — for a receipt, the zap request's relays tag (§7).
//
// Against the unexported targets, because Pool.Targets is gone. It was exported,
// it had no production caller, and it returned the union BEFORE the allow-list
// ran — the one API in this package shaped exactly like the bypass
// chooseTargets' own doc says cannot exist. An exported route around a security
// check is not made safe by nobody having taken it yet.
func TestTargetsAreTheUnionAndAreDeduplicated(t *testing.T) {
	configured := []string{"wss://one.example", "wss://two.example"}
	got := targets(configured, "wss://two.example/", "wss://three.example", "", "nonsense")
	if want := 3; len(got) != want {
		t.Fatalf("targets = %v, want %d distinct relays", got, want)
	}
	seen := map[string]bool{}
	for _, url := range got {
		if seen[url] {
			t.Errorf("targets repeated %q; that is two connections and two answers", url)
		}
		seen[url] = true
	}
}

// The dial hook's second mode: no publish in flight.
//
// That is §8's NWC connections, which dial on their own. Nothing in a shipped
// binary reaches it yet, so it is reached here directly — the alternative was to
// leave it untested until §8, and its first version FAILED CLOSED on exactly
// this path, refusing the operator's own relay because an absent snapshot was
// read as an empty one.
//
// In package nostr, because the hook is unexported and the point is to call it
// with no Publish around it. See export_test.go.
func TestTheDialHookFallsBackToAFreshReadWhenNoPublishIsInFlight(t *testing.T) {
	const onTheLAN = "ws://relay.example:7777"

	pool := NewPool(t.Context(), func() []string { return []string{onTheLAN} }, Options{})
	defer pool.Close()

	// Sanity: no publish has run, so there is no snapshot to honour.
	if pool.exempt.Load() != nil {
		t.Fatal("a snapshot exists; this test is not exercising the fallback")
	}

	// The operator's own relay, on a private address, dialled outside a publish.
	// This is the case the fallback exists for.
	if err := CheckDialAddress(pool, onTheLAN, "192.168.77.50:7777"); err != nil {
		t.Errorf("the operator's own configured relay was refused with no publish in "+
			"flight: %v; an NWC connection to a LAN relay is exactly what §8 does", err)
	}

	// And the fallback must not become a blanket exemption: a relay the operator
	// did NOT configure is still refused on the same address.
	if err := CheckDialAddress(pool, "ws://stranger.example:7777", "192.168.77.50:7777"); err == nil {
		t.Error("a stranger's relay was allowed onto a private address with no publish in " +
			"flight; the fallback exempts the operator's list, not everything")
	}
}

// bcf: a dial-time refusal is an AUDIT event, not a log line.
//
// The pre-check refusal is ordinary hostile input — someone put a LAN address
// in a zap request — and stays at INFO in the publish summary. Reaching HERE
// means the pre-check resolved that host to a public address and the socket got
// a private one, which is a rebinding attempt in progress. §12's trail exists so
// rotation cannot erase the answer to what happened.
//
// In package nostr, because the hook is unexported. See export_test.go.
func TestADialTimeRefusalReachesTheAuditTrail(t *testing.T) {
	sink := &recordingAuditor{}
	pool := NewPool(t.Context(), func() []string { return nil }, Options{Audit: sink})
	defer pool.Close()

	err := CheckDialAddress(pool, "ws://stranger.example:7777", "192.168.77.50:7777")

	if err == nil {
		t.Fatal("the refusal did not happen, so there is nothing to audit")
	}
	if len(sink.events) != 1 {
		t.Fatalf("%d audit events were recorded, want 1", len(sink.events))
	}
	got := sink.events[0]
	if got.event != logging.EventRelayRefuse {
		t.Errorf("event = %q, want %q", got.event, logging.EventRelayRefuse)
	}
	// The pair is the evidence: the relay as NAMED, and what it resolved to.
	// Either alone is unremarkable.
	if got.attrs["relay"] != "ws://stranger.example:7777" {
		t.Errorf("relay = %q, want the URL as named", got.attrs["relay"])
	}
	if got.attrs["resolved"] != "192.168.77.50" {
		t.Errorf("resolved = %q, want the address the dial got", got.attrs["resolved"])
	}
}

// One event, one record. The audit call REPLACES the hand-rolled WARN rather
// than joining it.
//
// The Auditor's contract is the log line and the durable row together
// (CLAUDE.md), so a pool that also wrote its own line would report one refusal
// twice — and an operator counting rebinding attempts in the log would count
// double. Nothing else catches this: the arch rule fires on a hand-built audit=
// attribute, and a plain second WARN carries none.
func TestARefusalIsRecordedOnceWhenAPoolHasASink(t *testing.T) {
	var buf bytes.Buffer
	sink := &recordingAuditor{}
	pool := NewPool(t.Context(), func() []string { return nil }, Options{
		Log:   logging.New(&buf, logging.NewLevelVar(slog.LevelDebug)),
		Audit: sink,
	})
	defer pool.Close()

	if err := CheckDialAddress(pool, "ws://stranger.example:7777", "192.168.77.50:7777"); err == nil {
		t.Fatal("the refusal did not happen")
	}

	if len(sink.events) != 1 {
		t.Fatalf("%d audit events, want 1", len(sink.events))
	}
	// The real Auditor writes the line; this pool must not write a second. The
	// fake records without logging, so anything in the buffer came from here.
	if strings.Contains(buf.String(), "relay refused at dial time") {
		t.Errorf("the pool logged the refusal as well as auditing it, so one event is "+
			"recorded twice: %s", buf.String())
	}
}

// And a pool built WITHOUT a sink still refuses and still says so.
//
// Required rather than tolerated: the relay fleet builds dozens of pools, and a
// constructor demanding a sink would make every one of them carry a fake for
// nothing.
func TestAPoolWithNoAuditSinkStillRefusesAndLogs(t *testing.T) {
	var buf bytes.Buffer
	pool := NewPool(t.Context(), func() []string { return nil },
		Options{Log: logging.New(&buf, logging.NewLevelVar(slog.LevelDebug))})
	defer pool.Close()

	if err := CheckDialAddress(pool, "ws://stranger.example:7777", "192.168.77.50:7777"); err == nil {
		t.Fatal("a pool without an audit sink stopped refusing")
	}
	// A LINE, and deliberately not an audit= attribute: the Auditor's contract
	// is the line and the durable row together, so claiming the attribute
	// without a trail to write to would be claiming a row that does not exist.
	// internal/arch enforces that, and caught the first version of this.
	got := buf.String()
	if !strings.Contains(got, "relay refused at dial time") {
		t.Errorf("the refusal was silent: %s", got)
	}
	if strings.Contains(got, `"audit"`) {
		t.Errorf("a pool with no sink claimed an audit event: %s", got)
	}
}

// recordingAuditor is logging.Auditor's one method, remembered.
type recordingAuditor struct {
	events []recordedEvent
}

type recordedEvent struct {
	event logging.Event
	attrs map[string]string
}

func (r *recordingAuditor) Record(_ context.Context, _ slog.Level, _ string,
	event logging.Event, attrs ...slog.Attr) error {
	flat := map[string]string{}
	for _, a := range attrs {
		flat[a.Key] = a.Value.String()
	}
	r.events = append(r.events, recordedEvent{event: event, attrs: flat})
	return nil
}

// The trail is a fixed ring, and this is the one event a stranger can drive.
//
// §12 trims audit_events to 10,000 rows, oldest first. An attacker who can flip
// a hostname from public to private between the pre-check and the dial could
// otherwise evict macaroon.bake, guard.reject and wallet.shortfall — defeating
// the durability this event was added for. The refusals past the bound still
// happen and still log; they simply stop spending the trail on repetition.
func TestAFloodOfRefusalsCannotEvictTheRestOfTheTrail(t *testing.T) {
	sink := &recordingAuditor{}
	pool := NewPool(t.Context(), func() []string { return nil }, Options{Audit: sink})
	defer pool.Close()

	const attempts = MaxAuditedRefusalsPerHour * 5
	for i := range attempts {
		relay := fmt.Sprintf("ws://stranger%d.example:7777", i)
		if err := CheckDialAddress(pool, relay, "192.168.77.50:7777"); err == nil {
			t.Fatalf("refusal %d did not happen", i)
		}
	}

	if len(sink.events) != MaxAuditedRefusalsPerHour {
		t.Errorf("%d of %d refusals were audited, want the bound of %d — a stranger must not "+
			"be able to choose what stays in §12's trail",
			len(sink.events), attempts, MaxAuditedRefusalsPerHour)
	}
}
