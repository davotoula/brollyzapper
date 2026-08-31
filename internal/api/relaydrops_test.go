package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/store"
)

// zmn criterion 2, the second half: what the RELAYS TAG lost at the parse.
//
// The pool's INFO line reports what IT dropped, but by then the list has been
// filtered and capped here, so the pool's `named` is what survived this parse
// rather than what the sender wrote. Without this line the sender's own number
// appears nowhere at all, and "why did my zap receipt reach fewer relays than I
// named" has no answer on the box.
//
// DEBUG rather than INFO because a callback is free and a stranger can drive it
// at the backstop rate — an INFO line here would be a stranger choosing how fast
// this node writes to its own log. §12 makes LOG_LEVEL changeable without a
// restart, so an operator diagnosing turns it on.
func TestTheParseLogsWhatTheRelaysTagLostAndWhy(t *testing.T) {
	var logged bytes.Buffer
	h := newLNURLHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.Log = logging.New(&logged, logging.NewLevelVar(slog.LevelDebug))
	})

	// One of each reason, in an order that exercises the cap's early break: the
	// eighth survivor is named before the last two, so those two are never
	// examined and must still be accounted for.
	named := []string{
		"wss://192.168.77.1:4444", // literal_private — the LAN
		"http://relay.example",    // bad_scheme — not a websocket URL at all
		"wss://good0.example",     // kept 1
		"wss://good0.example",     // duplicate
	}
	for i := 1; i <= 9; i++ { // kept 2..8, then two past the cap
		named = append(named, fmt.Sprintf("wss://good%d.example", i))
	}

	raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
		e.Tags = append(lnurltest.WithoutTag(e.Tags, "relays"),
			append(gonostr.Tag{"relays"}, named...))
	})
	rec := h.get(t, "/lnurlp/bob/callback?amount=21000&nostr="+url.QueryEscape(string(raw)), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback = %d %q", rec.Code, rec.Body)
	}

	line := debugLine(t, &logged, "zap request relays filtered at the parse")
	for _, want := range []struct {
		key string
		val float64
	}{
		{"named", 13},
		{"kept", 8},
		{"literal_private", 1},
		{"bad_scheme", 1},
		{"duplicate", 1},
		{"over_cap", 2}, // never examined — the filter stops at the cap
	} {
		if got, ok := line[want.key].(float64); !ok || got != want.val {
			t.Errorf("%s = %v, want %v\n%s", want.key, line[want.key], want.val, logged.String())
		}
	}
	// The accounting closes. A line whose numbers do not add up leaves a reader
	// wondering which bucket the missing relay fell into, which is the state
	// this exists to end.
	sum := 0.0
	for _, key := range []string{"kept", "literal_private", "bad_scheme", "duplicate", "over_cap"} {
		sum += line[key].(float64)
	}
	if sum != line["named"].(float64) {
		t.Errorf("kept + the reasons = %v, but named = %v", sum, line["named"])
	}
	if got := line["level"]; got != "DEBUG" {
		t.Errorf("level = %v, want DEBUG — a stranger drives this path for free", got)
	}
}

// A plain LNURL payment names no relays, so there is nothing to account for and
// the line must not appear at all. Without this, "logged for every request"
// would pass the test above and put a line of zeroes on the busiest free path
// this node has.
func TestAPlainPaymentLogsNoRelayLine(t *testing.T) {
	var logged bytes.Buffer
	h := newLNURLHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.Log = logging.New(&logged, logging.NewLevelVar(slog.LevelDebug))
	})

	if rec := h.get(t, "/lnurlp/bob/callback?amount=21000", nil); rec.Code != http.StatusOK {
		t.Fatalf("callback = %d %q", rec.Code, rec.Body)
	}
	if strings.Contains(logged.String(), "relays filtered at the parse") {
		t.Errorf("a payment carrying no zap request logged a relay line:\n%s", logged.String())
	}
}

// debugLine finds the one record with this message, and fails unless there is
// exactly one — a line per relay would be the noise this was written against.
func debugLine(t *testing.T, out *bytes.Buffer, msg string) map[string]any {
	t.Helper()
	var found []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if raw == "" || !strings.Contains(raw, msg) {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			t.Fatalf("log line is not JSON: %s", raw)
		}
		if record["msg"] == msg {
			found = append(found, record)
		}
	}
	if len(found) != 1 {
		t.Fatalf("found %d %q lines, want exactly 1:\n%s", len(found), msg, out.String())
	}
	return found[0]
}
