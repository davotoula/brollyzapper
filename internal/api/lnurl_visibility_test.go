package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/store"
)

// q22, part 1: the receive path stops being invisible.
//
// THE INVESTIGATION THIS EXISTS FOR turns on one question — how far does a
// wallet get? — and the path has three stages: the address document is fetched,
// the callback mints or refuses, the invoice is paid. Stages A and B both left
// NO trace, so "that wallet never reached us" and "that wallet read our document
// and refused it" looked identical in the log, and they point at completely
// different places.

// Criterion 1: a successful document fetch is visible, with the address name.
func TestASuccessfulAddressDocumentFetchIsLogged(t *testing.T) {
	logs, h := loggingLNURLHarness(t)

	if rec := h.get(t, "/.well-known/lnurlp/bob", nil); rec.Code != http.StatusOK {
		t.Fatalf("the document = %d, want 200", rec.Code)
	}

	line := logLine(t, logs, "served the lightning address document")
	if line["name"] != "bob" {
		t.Errorf("the line names %v, want bob — without it a multi-address install cannot "+
			"tell which address was asked for", line["name"])
	}
	if line["level"] != "DEBUG" {
		t.Errorf("the line is at %v, want DEBUG — §7 leaves this endpoint behind NO rate "+
			"limiter, so an INFO line here is a log-flood vector by construction", line["level"])
	}
}

// Criterion 2: a refusal on the SHOWABLE path logs the reason the caller was
// given, and that reason already names the Appendix D rule.
//
// This is the branch the whole bead is about: it told the STRANGER why and told
// the operator nothing.
func TestAShowableRefusalLogsTheReasonTheCallerWasGiven(t *testing.T) {
	logs, h := loggingLNURLHarness(t)

	// A real Appendix D rejection: a zap request that is not a kind 9734.
	rec := h.get(t, "/lnurlp/bob/callback?amount=21000&nostr="+
		`%7B%22kind%22%3A1%2C%22content%22%3A%22hi%22%7D`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("the callback = %d, want 200 — LNURL puts errors in a 200 body", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ERROR") {
		t.Fatalf("the callback did not refuse: %s", rec.Body)
	}

	line := logLine(t, logs, "refused an LNURL request")
	reason, _ := line["reason"].(string)
	if reason == "" {
		t.Fatal("the line carries no reason; a line saying \"a callback was refused\" with no " +
			"reason repeats the defect one level up")
	}
	// The SAME sentence the wallet was given. Two texts would be two answers to
	// one question, and the operator's would be the one nobody checked.
	if !strings.Contains(rec.Body.String(), reason) {
		t.Errorf("the operator was told %q and the caller something else:\n%s", reason, rec.Body)
	}
	// And it names the rule, which is what a wallet author needs.
	if !strings.Contains(reason, "9734") {
		t.Errorf("the reason %q does not name the rule that failed", reason)
	}
	if line["level"] != "DEBUG" {
		t.Errorf("the line is at %v, want DEBUG", line["level"])
	}
}

// Criterion 3: the NOT-showable path still logs as it did, at WARN.
//
// THE PLANT THIS GUARDS IS A RESTRUCTURE. `answer`'s two branches became three
// arms of one decision, and the old one is easy to absorb — the first version of
// this change put a `break` in it, which in a switch skips the write below and
// sent the caller an empty body. Both halves are asserted here.
func TestAnInternalFailureStillLogsAtWarnAndStillAnswers(t *testing.T) {
	logs, h := loggingLNURLHarness(t)
	h.node.SetReject(true)

	rec := h.get(t, "/lnurlp/bob/callback?amount=21000", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("the callback = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ERROR") {
		t.Fatalf("an internal failure produced no LNURL error body: %q", rec.Body.String())
	}
	line := logLine(t, logs, "the LNURL callback failed")
	if line["level"] != "WARN" {
		t.Errorf("the line is at %v, want WARN — this one is OUR failure and it was already "+
			"loud", line["level"])
	}
	// And the caller still learns nothing about the node.
	if strings.Contains(rec.Body.String(), "rejected") {
		t.Errorf("the callback quoted our node's error to a stranger: %s", rec.Body)
	}
}

// Criterion 5: NOTHING logs the zap request bytes.
//
// It is a stranger's signed event, up to MaxZapRequestBytes, and the reason plus
// the sender key is what diagnoses this. Asserted as an ABSENCE, over every line
// the request produced.
func TestTheZapRequestBytesNeverReachTheLog(t *testing.T) {
	logs, h := loggingLNURLHarness(t)
	const marker = "a-sentinel-nobody-would-log-by-accident"
	request := `{"kind":1,"content":"` + marker + `"}`

	h.get(t, "/lnurlp/bob/callback?amount=21000&nostr="+urlEscape(request), nil)

	if strings.Contains(logs.String(), marker) {
		t.Errorf("a stranger's zap request reached the log:\n%s", logs.String())
	}
	// And the refusal WAS logged, so this is an absence in a line that exists
	// rather than an absence of lines.
	if !strings.Contains(logs.String(), "refused an LNURL request") {
		t.Error("no refusal was logged at all; this test would prove nothing")
	}
}

// The self-probe names itself, so the operator's own fetches are separable from
// strangers' — which matters because devops reads this log looking for one
// specific fetch and the probe runs every few minutes.
//
// A CLAIM AND NOT A VERDICT: anything can send this string, which is why it is
// logged under `user_agent` rather than turned into a boolean the server cannot
// establish.
func TestTheAddressDocumentLogCarriesTheCallersClaimedIdentity(t *testing.T) {
	logs, h := loggingLNURLHarness(t)

	r := httptest.NewRequest(http.MethodGet, "/.well-known/lnurlp/bob", nil)
	r.Header.Set("User-Agent", api.ProbeUserAgent)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)

	line := logLine(t, logs, "served the lightning address document")
	if line["user_agent"] != api.ProbeUserAgent {
		t.Errorf("the line says user_agent %v, want %q — the probe fetches this endpoint over "+
			"the public internet every few minutes, and its traffic is otherwise "+
			"indistinguishable from a stranger's", line["user_agent"], api.ProbeUserAgent)
	}
}

// Criterion 6: a healthy install adds no INFO noise. All of this is DEBUG.
func TestTheNewVisibilityIsInvisibleAtInfo(t *testing.T) {
	var buf bytes.Buffer
	h := newLNURLHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.Log = logging.New(&buf, logging.NewLevelVar(slog.LevelInfo))
	})

	h.get(t, "/.well-known/lnurlp/bob", nil)

	if strings.Contains(buf.String(), "served the lightning address document") {
		t.Errorf("a document fetch logged at INFO; this endpoint has no rate limiter at all "+
			"and every fetch would land in an operator's log:\n%s", buf.String())
	}
}

// --- helpers ---------------------------------------------------------------

// loggingLNURLHarness is the LNURL harness with its log in a buffer a test can
// read, at DEBUG.
func loggingLNURLHarness(t *testing.T) (*bytes.Buffer, *lnurlHarness) {
	t.Helper()
	var buf bytes.Buffer
	h := newLNURLHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Log = logging.New(&buf, logging.NewLevelVar(slog.LevelDebug))
	})
	return &buf, h
}

// logLine finds the one line carrying msg, or fails naming what was there.
func logLine(t *testing.T, logs *bytes.Buffer, msg string) map[string]any {
	t.Helper()
	for _, raw := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var line map[string]any
		if json.Unmarshal([]byte(raw), &line) != nil {
			continue
		}
		if got, _ := line["msg"].(string); got == msg {
			return line
		}
	}
	t.Fatalf("no log line said %q; the log held:\n%s", msg, logs.String())
	return nil
}

func urlEscape(s string) string { return url.QueryEscape(s) }

// Criterion 4: each of the THREE rate-limit paths logs, distinguishably.
//
// ONE TEST PER PATH, deliberately. A single test for the trio cannot tell you
// which one is unreachable — and the three have three different remedies, so an
// undifferentiated line would leave the operator knowing only that something
// refused something.

func TestTheGlobalBackstopSaysSoInTheLog(t *testing.T) {
	var buf bytes.Buffer
	h := newLNURLHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Log = logging.New(&buf, logging.NewLevelVar(slog.LevelDebug))
		if err := db.SetSetting(t.Context(), api.SettingPublicRateLimitMinute, "1"); err != nil {
			t.Fatal(err)
		}
	})

	for range 3 {
		h.get(t, "/lnurlp/bob/callback?amount=21000", nil)
	}

	line := rateLimitLine(t, &buf, "backstop")
	if line["reason"] == "" {
		t.Error("the backstop refusal carries no reason")
	}
	if line["level"] != "DEBUG" {
		t.Errorf("the line is at %v, want DEBUG — this path is reachable by anyone", line["level"])
	}
}

func TestThePerSenderLimitSaysSoInTheLogWithTheSender(t *testing.T) {
	var buf bytes.Buffer
	h := newLNURLHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.Log = logging.New(&buf, logging.NewLevelVar(slog.LevelDebug))
	})
	noisy := gonostr.GeneratePrivateKey()

	for range api.PerSenderPerMinute + 1 {
		h.get(t, zapCallback(t, noisy, 21_000), nil)
	}

	line := rateLimitLine(t, &buf, "per_sender")
	// THE SENDER KEY, which is the whole point of this layer: it is what tells
	// an operator whether one wallet is flooding them or the crowd is.
	sender, _ := line["sender"].(string)
	if sender == "" {
		t.Error("the per-sender refusal does not say which sender; that is the one fact this " +
			"layer knows and the backstop does not")
	}
	pub, err := gonostr.GetPublicKey(noisy)
	if err != nil {
		t.Fatal(err)
	}
	if sender != logging.Short(pub) {
		t.Errorf("the line names sender %q, want %q — truncated per §12", sender, logging.Short(pub))
	}
}

func TestTheOpenInvoiceCapSaysSoInTheLog(t *testing.T) {
	var buf bytes.Buffer
	h := newLNURLHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.Log = logging.New(&buf, logging.NewLevelVar(slog.LevelDebug))
		opts.Invoices = fullOfInvoices{}
	})

	h.get(t, "/lnurlp/bob/callback?amount=21000", nil)

	line := rateLimitLine(t, &buf, "open_invoices")
	if !strings.Contains(line["reason"].(string), "unpaid invoices") {
		t.Errorf("the reason %q does not say what filled up", line["reason"])
	}
}

// fullOfInvoices reports the cap as already reached.
type fullOfInvoices struct{}

func (fullOfInvoices) CountOpenInvoices(context.Context, time.Time) (int64, error) {
	return int64(api.OpenInvoiceCap), nil
}

// rateLimitLine finds the rate-limit line for one named limit, or fails saying
// which limits DID fire — so a wrong-path failure reads as a wrong path rather
// than as an absent line.
func rateLimitLine(t *testing.T, logs *bytes.Buffer, limit string) map[string]any {
	t.Helper()
	var seen []string
	for _, raw := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var line map[string]any
		if json.Unmarshal([]byte(raw), &line) != nil {
			continue
		}
		if msg, _ := line["msg"].(string); msg != "rate-limited an LNURL callback" {
			continue
		}
		got, _ := line["limit"].(string)
		if got == limit {
			return line
		}
		seen = append(seen, got)
	}
	t.Fatalf("no line reported the %q limit; the limits that fired were %v\n%s",
		limit, seen, logs.String())
	return nil
}
