package api_test

import (
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd"
)

// The Sending page computes how long the pending code has left (BrollyZap-5z4).
//
// internal/web renders the figure; this is the half that produces it, and
// without it the field is a decoration nothing sets. The harness clock is
// already fixed at authTime, so the assertion is on the arithmetic rather than
// on how long the test took.
func TestTheSendingPageSaysHowLongTheAuthorisationHasLeft(t *testing.T) {
	body := sendingPageWith(t, lnd.BrokerStatus{
		LNDReachable: true, SendingAllowedByDeployment: true,
		AuthorisationPending:   true,
		AuthorisationControl:   "sending",
		AuthorisationChange:    "TURN SENDING ON — let this app make your node pay invoices.",
		AuthorisationExpiresAt: authTime.Add(7 * time.Minute),
		AuthorisationLocation:  "Files -> Apps -> brollyzapper -> data -> guard",
	})

	if !strings.Contains(body, "7 minutes") {
		t.Errorf("the page does not say the code has 7 minutes left, so reading it needs the "+
			"operator's offset from UTC and some arithmetic:\n%s", body)
	}
	if !strings.Contains(body, authTime.Add(7*time.Minute).Format("2006-01-02 15:04 UTC")) {
		t.Error("the absolute expiry is gone; it is the arbiter once the page has aged")
	}
}

// Seconds left must round UP to a minute: "0 minutes" reads as dead on a code
// that still works, and an operator who believes it stops typing.
func TestACodeWithSecondsLeftIsReportedAsAMinute(t *testing.T) {
	body := sendingPageWith(t, lnd.BrokerStatus{
		LNDReachable: true, SendingAllowedByDeployment: true,
		AuthorisationPending:   true,
		AuthorisationControl:   "sending",
		AuthorisationExpiresAt: authTime.Add(20 * time.Second),
	})

	if strings.Contains(body, "0 minutes") {
		t.Error("twenty seconds left renders as \"0 minutes\"")
	}
	if !strings.Contains(body, "1 minute") {
		t.Errorf("twenty seconds left does not round up to a minute:\n%s", body)
	}
}
