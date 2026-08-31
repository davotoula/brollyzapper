package api_test

import (
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/preflight"
)

// tna.2 criterion 5: guard rejections surface as a BANNER, with the window they
// cover stated beside the number (§12).
//
// §12 calls a burst of guard rejections the highest-signal event in the system —
// either a bug in the wallet ceiling or a compromise in progress — which is why
// it renders above the checks rather than as one row among twenty. The window is
// on the page because the number is a RATE: "3 rejections" means nothing until
// the reader knows over what.
func TestAGuardRejectionBurstRendersAsABannerWithItsWindow(t *testing.T) {
	h := newHarness(t)
	h.report.Rejections = &preflight.RejectionBurst{Count: 3, Within: 24 * time.Hour}
	cookie := h.login(t)

	body := h.body(t, "/security", cookie)

	for _, want := range []string{"refused 3 operation(s)", "24 hours", "compromise in progress"} {
		if !strings.Contains(body, want) {
			t.Errorf("the security page does not state %q; §12's loudest signal has to say how "+
				"many and over what:\n%s", want, body)
		}
	}
}

// No rejections, no banner. A standing warning on a healthy install is a warning
// an operator learns to scroll past.
func TestNoRejectionsMeansNoBanner(t *testing.T) {
	h := newHarness(t)
	h.report.Rejections = &preflight.RejectionBurst{Count: 0, Within: 24 * time.Hour}
	cookie := h.login(t)

	if body := h.body(t, "/security", cookie); strings.Contains(body, "compromise in progress") {
		t.Errorf("a quiet install shows the burst banner:\n%s", body)
	}
}

// The spend window renders as a MEASUREMENT, and says so.
//
// Ruling A: it is not a Check because it has no failure state. The page has to
// carry that distinction too, or an operator reading a number among a column of
// ticks and crosses will look for the level at which it turns red.
func TestTheSecurityPageStatesTheSpendWindowAsAMeasurement(t *testing.T) {
	h := newHarness(t)
	h.report.Spend = &preflight.SpendWindow{
		UsedMsat: 12_000_000, LimitMsat: 100_000_000, Period: 24 * time.Hour,
	}
	cookie := h.login(t)

	body := h.body(t, "/security", cookie)

	for _, want := range []string{"100000.000 sats", "12000.000 sats", "24 hours", "not a check"} {
		if !strings.Contains(body, want) {
			t.Errorf("the security page does not state %q:\n%s", want, body)
		}
	}
}

// And absent means absent: a receive-only install states no cap at all.
func TestTheSecurityPageStatesNoSpendWindowWhenSendingIsOff(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	if body := h.body(t, "/security", cookie); strings.Contains(body, "will not let this app spend") {
		t.Errorf("a receive-only install states a spend cap:\n%s", body)
	}
}
