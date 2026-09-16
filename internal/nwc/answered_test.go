package nwc

import (
	"encoding/json"
	"errors"
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

// xej: the LEVEL of the answered line, per method. Ruling 3's reasoning — "an
// operator asking why did my phone stop paying must not need debug mode" —
// applied to the line that explains a stall: INFO for the money-moving method,
// DEBUG for the reads, so Amethyst's idle balance polls stay out of an
// operator's log.
//
// The level is the whole bead, so this asserts it and not merely the presence
// of a line.
func TestTheAnsweredLineIsInfoForAPaymentAndDebugForARead(t *testing.T) {
	cases := []struct {
		method Method
		setUp  func(h *harness)
		params json.RawMessage
		level  string
	}{
		{
			method: MethodPayInvoice,
			setUp: func(h *harness) {
				h.grantPay()
				h.sendEnabled(true)
				h.decodesTo("lnbcrt1xej", 50_000, "a payment")
			},
			params: payParams("lnbcrt1xej", 0),
			level:  "INFO",
		},
		{
			// The one Amethyst polls, and the reason the split exists.
			method: MethodGetBalance,
			setUp:  func(*harness) {},
			level:  "DEBUG",
		},
	}
	for _, tc := range cases {
		t.Run(string(tc.method), func(t *testing.T) {
			h := newHarness(t)
			tc.setUp(h)

			if resp := h.handle(t, tc.method, tc.params); resp.Error != nil {
				t.Fatalf("%s was refused, so the fixture is wrong: %+v", tc.method, resp.Error)
			}

			lines := answeredLines(t, h.logs.String())
			if len(lines) != 1 {
				t.Fatalf("%d answered lines for one %s, want 1:\n%s",
					len(lines), tc.method, h.logs.String())
			}
			if lines[0]["level"] != tc.level {
				t.Errorf("the %s answered line is at %v, want %s",
					tc.method, lines[0]["level"], tc.level)
			}
		})
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

// go-review of k2z: a response that could not be sealed was never published, so
// nothing may say it was answered — the line is written after the publish, and
// "relays=0" on it would read as a pairing with no relays rather than a
// response that went nowhere. The ERROR line says what happened.
func TestAResponseThatCouldNotBeSealedIsNotLoggedAsAnswered(t *testing.T) {
	h := newHarness(t)
	h.counting.mu.Lock()
	h.counting.encryptErr = errors.New("the conversation key could not be derived")
	h.counting.mu.Unlock()
	// Built after the request is sealed by the CLIENT's identity, so only the
	// service's reply fails.
	h.handle(t, MethodGetBalance, nil)

	if lines := answeredLines(t, h.logs.String()); len(lines) != 0 {
		t.Errorf("%d answered lines for a response nothing published:\n%s", len(lines), h.logs.String())
	}
	if !loggedAt(t, h.logs.String(), "ERROR", "could not encrypt an NWC response") {
		t.Errorf("the failure itself was not logged:\n%s", h.logs.String())
	}
	if got := len(h.relays.published()); got != 0 {
		t.Fatalf("the fixture is wrong: %d publishes", got)
	}
}
