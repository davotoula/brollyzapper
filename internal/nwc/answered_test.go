package nwc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// answeredLines is every "an NWC request was answered" record in a captured log.
func answeredLines(t *testing.T, logs string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		if entry["msg"] == "an NWC request was answered" {
			out = append(out, entry)
		}
	}
	return out
}

// k2z criterion 8: ONE greppable line per answered request says how long the
// server took, how long the publish took, how many relays were tried and how many
// took it.
//
// One line and not two joined on the event id, which is the bead's reason for
// existing: the 28 Aug Amethyst report could say when the service ANSWERED and
// nothing about the publish that followed, and an operator reading a box's journal
// greps one record.
func TestTheAnsweredLineCarriesHandleAndPublishTiming(t *testing.T) {
	h := newHarness(t, "wss://one.example", "wss://two.example")

	h.handle(t, MethodGetBalance, nil)

	lines := answeredLines(t, h.logs.String())
	if len(lines) != 1 {
		t.Fatalf("%d answered lines for one request, want 1:\n%s", len(lines), h.logs.String())
	}
	line := lines[0]
	if line["level"] != "DEBUG" {
		t.Errorf("the answered line is at %v, want DEBUG — ruling 5, the idle polls", line["level"])
	}
	// Every attribute it had, and the five.
	for _, key := range []string{"connection", "method", "handle_ms", "publish_ms", "relays", "accepted"} {
		if _, ok := line[key]; !ok {
			t.Errorf("the answered line has no %s: %v", key, line)
		}
	}
	if line["method"] != string(MethodGetBalance) {
		t.Errorf("method = %v", line["method"])
	}
	handleMS, _ := line["handle_ms"].(float64)
	publishMS, _ := line["publish_ms"].(float64)
	relays, _ := line["relays"].(float64)
	accepted, _ := line["accepted"].(float64)
	if handleMS < 0 || publishMS < 0 {
		t.Errorf("handle_ms=%v publish_ms=%v, want both non-negative", handleMS, publishMS)
	}
	if relays != 2 || accepted != 2 {
		t.Errorf("relays=%v accepted=%v, want 2 and 2", relays, accepted)
	}
}

// k2z criterion 9: one relay refusing makes accepted one less than relays, on
// that same line.
func TestTheAnsweredLineCountsARelayThatRefused(t *testing.T) {
	h := newHarness(t, "wss://one.example", "wss://relay.refuses")
	h.relays.refuseRelayPublishes("wss://relay.refuses")

	h.handle(t, MethodGetBalance, nil)

	lines := answeredLines(t, h.logs.String())
	if len(lines) != 1 {
		t.Fatalf("%d answered lines, want 1:\n%s", len(lines), h.logs.String())
	}
	relays, _ := lines[0]["relays"].(float64)
	accepted, _ := lines[0]["accepted"].(float64)
	if relays != 2 || accepted != 1 {
		t.Errorf("relays=%v accepted=%v, want 2 and 1", relays, accepted)
	}
}

// The publish's duration is the WHOLE delivery, retries and their waits
// included — the time between "we produced a response" and "a relay has it",
// which is the interval the stall report could not localise.
func TestPublishMSCoversTheRetries(t *testing.T) {
	h := newHarness(t)
	h.service.responseRetries = []time.Duration{50 * time.Millisecond, time.Millisecond}
	h.relays.refusePublishesFor(1)

	h.handle(t, MethodGetBalance, nil)

	lines := answeredLines(t, h.logs.String())
	if len(lines) != 1 {
		t.Fatalf("%d answered lines, want 1:\n%s", len(lines), h.logs.String())
	}
	if publishMS, _ := lines[0]["publish_ms"].(float64); publishMS < 50 {
		t.Errorf("publish_ms=%v across a refused attempt and a 50 ms wait, want at least 50", publishMS)
	}
	if accepted, _ := lines[0]["accepted"].(float64); accepted != 1 {
		t.Errorf("accepted=%v, want 1 — the attempt that delivered it", accepted)
	}
}

// k2z criterion 10: the retry path's WARN survives, unchanged.
func TestTheGiveUpWarningSurvivesTheAnsweredLine(t *testing.T) {
	h := newHarness(t)
	h.service.responseRetries = []time.Duration{time.Millisecond, time.Millisecond}
	h.relays.refusePublishesFor(100)

	h.handle(t, MethodGetBalance, nil)

	if !loggedAt(t, h.logs.String(), "WARN", "no relay accepted an NWC response") {
		t.Errorf("the give-up WARN is gone:\n%s", h.logs.String())
	}
	lines := answeredLines(t, h.logs.String())
	if len(lines) != 1 {
		t.Fatalf("%d answered lines, want 1:\n%s", len(lines), h.logs.String())
	}
	if accepted, _ := lines[0]["accepted"].(float64); accepted != 0 {
		t.Errorf("accepted=%v on a response no relay took, want 0", accepted)
	}
}
