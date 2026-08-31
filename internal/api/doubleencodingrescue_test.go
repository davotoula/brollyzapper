package api_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
)

// The api half of BrollyZap-w0i's workaround, in a file named for it.
//
// It lived in relaydrops_test.go, next to the log line it was modelled on. That
// is the wrong home for a TEMPORARY thing: whoever removes the workaround greps
// for its name, and these two tests still compile and pass with the production
// code gone — they would fail on the next run, which is the right outcome only
// if someone finds them. A file named after the feature is what makes the
// removal a directory listing rather than a search.

// The rescue announces itself, because that line is the removal condition.
//
// The fallback tolerates input that is malformed by specification. That is
// defensible only while a real client needs it, and leniency with no signal for
// its own removal becomes permanent by default — so the line is not decoration,
// it is the thing an operator watches to know the workaround can go. It carries
// the client tag because that names whose encoder is wrong, which is the
// question the upstream report has to answer.
//
// AT INFO, asserted deliberately. LOG_LEVEL defaults to info, so a DEBUG line
// would be one a default deployment never emits — and a removal signal nobody
// can observe is not a signal. If this assertion is ever relaxed back to DEBUG,
// the workaround loses the only thing that would retire it.
func TestARescuedDoubleEncodedZapRequestSaysSoAndNamesTheClient(t *testing.T) {
	logged, h := loggingLNURLHarness(t)

	raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
		e.Tags = append(e.Tags, gonostr.Tag{"client", "primal-web"})
	})
	doubled := string(lnurltest.DoubleEncoded(raw))
	rec := h.get(t, "/lnurlp/bob/callback?amount=21000&nostr="+url.QueryEscape(doubled), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback = %d %q; the double-encoded request was not rescued", rec.Code, rec.Body)
	}

	line := logLine(t, logged, api.RescueNoticeForTest)
	if got, _ := line["client"].(string); got != "primal-web" {
		t.Errorf("the rescue line names client %q, want \"primal-web\"; without it the "+
			"upstream report cannot say whose encoder is wrong", got)
	}
	if got, _ := line["level"].(string); got != "INFO" {
		t.Errorf("the rescue line is %s, want INFO; LOG_LEVEL defaults to info, so a quieter "+
			"level is a removal signal a default deployment never emits", got)
	}
}

// ONCE PER PROCESS, which is what buys INFO on a path a stranger drives.
//
// A callback is free and anonymous, so an unbounded INFO line here would let a
// stranger choose how fast this node writes to its own log. sync.Once makes the
// volume one line per lifetime instead, and a restart re-arms it — so each
// release re-tests whether anything still needs the workaround.
func TestTheRescueNoticeIsLoggedOncePerProcessNotPerRequest(t *testing.T) {
	logged, h := loggingLNURLHarness(t)

	raw := lnurltest.SignedZapRequest(t, nil)
	doubled := string(lnurltest.DoubleEncoded(raw))
	for range 3 {
		rec := h.get(t, "/lnurlp/bob/callback?amount=21000&nostr="+url.QueryEscape(doubled), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("callback = %d %q", rec.Code, rec.Body)
		}
	}

	if got := strings.Count(logged.String(), "second percent-decode"); got != 1 {
		t.Errorf("three rescued requests logged %d notices, want exactly 1; at INFO on an "+
			"anonymous path that is a stranger choosing this node's log volume", got)
	}
}

// And it is SILENT for a correctly encoded request — which is what makes its
// absence mean "nothing needs this any more" rather than "nobody looked".
func TestACorrectlyEncodedZapRequestLogsNoRescue(t *testing.T) {
	logged, h := loggingLNURLHarness(t)

	raw := lnurltest.SignedZapRequest(t, nil)
	rec := h.get(t, "/lnurlp/bob/callback?amount=21000&nostr="+url.QueryEscape(string(raw)), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback = %d %q", rec.Code, rec.Body)
	}
	if strings.Contains(logged.String(), "second percent-decode") {
		t.Error("a correctly encoded request logged a rescue; the line would then never " +
			"fall silent and could never signal that the workaround can be removed")
	}
}
