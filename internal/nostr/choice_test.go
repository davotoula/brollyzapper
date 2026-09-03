package nostr_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
)

// realisticDNS answers names from a map and hands every literal straight back,
// which is what net.DefaultResolver does.
//
// The literal half is the part that matters. A resolver that answered "public"
// for 192.168.77.1 would let this test pass with the allow-list switched off:
// the LAN address would be accepted and the counts below would be measuring
// nothing.
type realisticDNS map[string]string

func (d realisticDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	answer, ok := d[host]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", host)
	}
	return []netip.Addr{netip.MustParseAddr(answer)}, nil
}

// zmn criteria 2, 3 and 4, in the shape the 0.1.5 box trip produced: ten relays
// named, one of them a LAN address, and a cap of eight.
//
// That trip is the whole reason this line exists. The filter dropped the LAN
// address, the cap cut another, and NOTHING was logged — invoices.zap_relays
// was the only evidence anywhere on the box that either had happened, and an
// operator asking "why did my zap receipt go nowhere" had no line to find.
func TestOnePublishLogsWhichRelaysItUsedAndWhichItDropped(t *testing.T) {
	const onTheLAN = "wss://192.168.77.1:4444"

	dns := realisticDNS{}
	named := []string{onTheLAN}
	for i := range 9 {
		host := fmt.Sprintf("relay%d.example", i)
		dns[host] = "93.184.216.34"
		named = append(named, "wss://"+host)
	}

	var out bytes.Buffer
	configured := newFleet(t, 1)
	pool := nostr.NewPool(t.Context(), configured.urls, nostr.Options{
		Resolve: dns,
		Log:     logging.New(&out, logging.NewLevelVar(slog.LevelInfo)),
	})
	defer pool.Close()

	pool.Publish(t.Context(), signedNote(t), named...)

	line := logLine(t, out.String(), "relays chosen for this publish")

	// The cap is on CANDIDATES, so the first eight of the ten are examined: the
	// LAN literal, refused on content, and seven names that resolve public. The
	// last two are dropped on room. The two reasons must not arrive as one
	// number — "we tried and it said no" and "we did not try" send an operator
	// to different places.
	for _, want := range []struct {
		key string
		val float64
	}{{"named", 10}, {"kept", 7}, {"dropped", 3}} {
		if got, ok := line[want.key].(float64); !ok || got != want.val {
			t.Errorf("%s = %v, want %v\n%s", want.key, line[want.key], want.val, out.String())
		}
	}
	if refused := stringList(t, line, "refused"); len(refused) != 1 || refused[0] != onTheLAN {
		t.Errorf("refused = %v, want exactly [%s]", refused, onTheLAN)
	}
	if overCap := stringList(t, line, "over_cap"); len(overCap) != 2 {
		t.Errorf("over_cap = %v, want the two relays dropped for room", overCap)
	}

	// Criterion 3. A relay URL is not a secret, and a redacted one is useless —
	// an operator cannot match "wss://relay3.exa…" against their own list.
	relays := stringList(t, line, "relays")
	if len(relays) != 1+7 {
		t.Errorf("relays = %v, want the configured relay plus the 7 that survived", relays)
	}
	for _, relay := range relays {
		if strings.Contains(relay, "…") {
			t.Errorf("the line redacts a relay URL (%q); hostnames are not secrets", relay)
		}
	}
	if !strings.Contains(out.String(), "relay0.example") {
		t.Errorf("no relay appears in full:\n%s", out.String())
	}
	if strings.Contains(out.String(), `"audit"`) {
		t.Error("the line carries an audit= attribute; a stranger naming a LAN address is " +
			"expected input on a public endpoint, not a security event (§12)")
	}
}

// logLines parses every JSON record in a captured log, in order. The one place
// a test decides what a log line is; logLine and costRecords both read through it.
func logLines(t *testing.T, logged string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(logged), "\n") {
		if raw == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			t.Fatalf("log line is not JSON: %s", raw)
		}
		out = append(out, record)
	}
	return out
}

// logLine finds the one JSON record carrying this message, and fails unless
// there is exactly one — "ONE line per accepted zap request" is half the
// criterion, and a per-relay line would be the noise it was written against.
func logLine(t *testing.T, logged, msg string) map[string]any {
	t.Helper()
	var found []map[string]any
	for _, record := range logLines(t, logged) {
		if record["msg"] == msg {
			found = append(found, record)
		}
	}
	if len(found) != 1 {
		t.Fatalf("found %d %q lines, want exactly 1:\n%s", len(found), msg, logged)
	}
	return found[0]
}

func stringList(t *testing.T, line map[string]any, key string) []string {
	t.Helper()
	// An empty list is logged as JSON null, which is a legitimate answer and
	// not a malformed one.
	raw, ok := line[key]
	if !ok || raw == nil {
		return nil
	}
	items, ok := raw.([]any)
	if !ok {
		t.Fatalf("%s = %#v, want a list of relay URLs", key, raw)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, fmt.Sprint(item))
	}
	return out
}

// du9.4: the line must tell "the sender named nothing" from "the sender named
// relays we already have".
//
// It could not. The counting loop skipped a relay that was also the operator's
// BEFORE counting it, so a request naming exactly the relays already configured
// logged named=0 kept=0 dropped=0 — the same line a request naming no relays at
// all produces. The relay probe hit exactly that (two publishes, Amethyst's two
// relays pasted into the operator's list) and the line could not explain itself,
// while earlier zaps from the same client had logged named=2 kept=2.
//
// THE TABLE IS THE TEST. A single case would pass against a counter that always
// reported what that case wanted; the three rows move named, already_ours and
// kept independently of each other, and the last row is the one the old code got
// right — so a change that fixed the first two by breaking it cannot hide.
func TestTheChosenRelaysLineSaysWhichNamedRelaysWeAlreadyHad(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		ours, fresh                   int
		wantNamed, wantOurs, wantKept int
	}{{
		name: "the sender names exactly the relays we already have",
		ours: 2, fresh: 0,
		wantNamed: 2, wantOurs: 2, wantKept: 0,
	}, {
		name: "the sender names one of ours and one new",
		ours: 1, fresh: 1,
		wantNamed: 2, wantOurs: 1, wantKept: 1,
	}, {
		// The case the old code already got right, kept as the control.
		name: "the sender names only relays we did not have",
		ours: 0, fresh: 2,
		wantNamed: 2, wantOurs: 0, wantKept: 2,
	}, {
		// And the reading that used to be ambiguous with the first row.
		name: "the sender names nothing",
		ours: 0, fresh: 0,
		wantNamed: 0, wantOurs: 0, wantKept: 0,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			configured := newFleet(t, 2)
			strangers := newFleet(t, 2)
			named := append(configured.urls()[:tc.ours], strangers.urls()[:tc.fresh]...)

			pool, logged := loggedPool(t, configured.urls)
			defer pool.Close()

			results := pool.Publish(t.Context(), signedNote(t), named...)
			if got := nostr.Accepted(results); got != 2+tc.fresh {
				t.Fatalf("%d relays accepted, want %d — the fleets are not answering, so "+
					"the counters below would be measuring nothing: %+v",
					got, 2+tc.fresh, results)
			}

			line := logLine(t, logged.String(), "relays chosen for this publish")
			for _, want := range []struct {
				key string
				val int
			}{{"named", tc.wantNamed}, {"already_ours", tc.wantOurs}, {"kept", tc.wantKept}} {
				if got, ok := line[want.key].(float64); !ok || int(got) != want.val {
					t.Errorf("%s = %v, want %d\n%s", want.key, line[want.key], want.val,
						logged.String())
				}
			}
			// The arithmetic closes, which is what makes the line readable
			// rather than four numbers that happen to be near each other: every
			// relay the sender named is accounted for exactly once.
			sum := 0
			for _, key := range []string{"kept", "dropped", "already_ours"} {
				got, ok := line[key].(float64)
				if !ok {
					t.Fatalf("%s is missing from the line\n%s", key, logged.String())
				}
				sum += int(got)
			}
			if named, _ := line["named"].(float64); sum != int(named) {
				t.Errorf("kept + dropped + already_ours = %d, but named = %v\n%s",
					sum, line["named"], logged.String())
			}
		})
	}
}
