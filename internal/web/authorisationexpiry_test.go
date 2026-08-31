package web_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/web"
)

// The ceremony page must say how long the code has left, not only when it dies
// (BrollyZap-5z4).
//
// The expiry read "17:32 UTC" while the operator's own clock said 19:2x, so
// working out how long was left meant knowing your offset from UTC and doing
// arithmetic — in the middle of a ten-minute window, on a phone, on the one
// surface where the operator is under time pressure. The authorisation FILE
// already said both; the two halves of one ceremony described the same deadline
// in two registers, and the harder one was on the screen being looked at.
//
// BOTH, not a replacement. A relative figure rendered server-side goes stale the
// moment the page is served, so the absolute instant stays as the arbiter and
// the relative one is phrased against page load.
func TestTheCeremonyPageSaysHowLongTheCodeHasLeft(t *testing.T) {
	body := renderSendingCeremony(t, web.AuthorisationView{
		Pending:             true,
		Control:             "sending",
		Change:              "TURN SENDING ON — let this app make your node pay invoices.",
		ExpiresAt:           time.Date(2026, 8, 28, 17, 32, 0, 0, time.UTC),
		MinutesLeftAtRender: 10,
		Location:            "Files -> Apps -> brollyzapper -> data -> guard",
	})

	if !strings.Contains(body, "2026-08-28 17:32 UTC") {
		t.Error("the absolute expiry is gone; it is the arbiter, and a relative figure alone " +
			"goes stale on a page left open")
	}
	if !strings.Contains(body, "10 minutes") {
		t.Errorf("the page does not say how long the code has left, so reading it needs the "+
			"operator's offset from UTC and some arithmetic:\n%s", body)
	}
}

// One minute is "1 minute", not "1 minutes". The producer rounds UP so that a
// code with seconds left says one rather than zero, which makes the singular a
// case that actually occurs rather than a pedantry.
func TestASingleMinuteIsNotPluralised(t *testing.T) {
	body := renderSendingCeremony(t, web.AuthorisationView{
		Pending: true, Control: "sending", MinutesLeftAtRender: 1,
		ExpiresAt: time.Date(2026, 8, 28, 17, 32, 0, 0, time.UTC),
	})

	if strings.Contains(body, "1 minutes") || !strings.Contains(body, "1 minute") {
		t.Errorf("a single minute does not render as \"1 minute\":\n%s", body)
	}
}

// Once the deadline has passed there is no relative figure at all, and the
// absolute instant speaks for itself.
//
// minutesUntil reserves zero for "gone" — under a minute rounds up to one — so
// zero here is the EXPIRED case, not the nearly-expired one. Suppressing the
// clause matters because "about 0 minutes from when this page loaded" reads as
// a countdown that has stopped rather than as a deadline that has passed.
func TestAnExpiredCodeShowsNoRelativeFigure(t *testing.T) {
	body := renderSendingCeremony(t, web.AuthorisationView{
		Pending: true, Control: "sending", MinutesLeftAtRender: 0,
		ExpiresAt: time.Date(2026, 8, 28, 17, 32, 0, 0, time.UTC),
	})

	if strings.Contains(body, "0 minutes") {
		t.Error("an expired code renders \"0 minutes\", which reads as a stopped countdown")
	}
	if !strings.Contains(body, "2026-08-28 17:32 UTC") {
		t.Error("the absolute instant is gone too, so the page now says nothing about the " +
			"deadline at all")
	}
}

// renderSendingCeremony renders the Sending page's ceremony block.
//
// GuardReachable and AllowedByDeployment are both required or the block is
// absent entirely, and every assertion above would then pass or fail on an empty
// page rather than on what it meant to check.
func renderSendingCeremony(t *testing.T, view web.AuthorisationView) string {
	t.Helper()
	data := web.PageData{Title: "Sending"}
	data.Sending.GuardReachable = true
	data.Sending.AllowedByDeployment = true
	data.Sending.Authorisation = view

	var buf bytes.Buffer
	if err := newRenderer(t).Render(&buf, "sending", data); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return buf.String()
}
