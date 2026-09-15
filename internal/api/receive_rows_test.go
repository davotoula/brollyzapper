package api_test

import (
	"html"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/preflight"
)

// `0vk.11` criterion 5, rendered: the Security page carries the receive
// credential's four rows, each with its threat, from the real report.
//
// And the banner half: an install the guard has not linked yet has four receive
// rows with nothing to read, for one reason. The banner says it once — four
// copies of one sentence read as four problems.
func TestTheSecurityPageRendersTheReceiveCredentialRows(t *testing.T) {
	h := newHarness(t, livePreflight(lnd.StateNotLinked, func(in *preflight.Inputs) {
		in.ReceiveMacaroon = func() ([]byte, bool) { return nil, false }
	}))
	cookie := h.login(t)

	security := html.UnescapeString(h.get(t, "/security", cookie).Body.String())
	for _, title := range []string{
		"The receive macaroon carries its caveats",
		"The receive macaroon is locked to this container",
		"The receive macaroon has not expired",
		"The node still honours the receive root key",
	} {
		verdict, detail := securityRow(t, security, title)
		if verdict == "pass" {
			t.Errorf("%q passes with no receive macaroon to read: %q", title, detail)
		}
	}
	if !strings.Contains(security, "Receive macaroon exfiltrated") {
		t.Error("the receive rows do not name the §11 threat they map to")
	}

	wallet := html.UnescapeString(h.get(t, "/", cookie).Body.String())
	if n := strings.Count(wallet, "there is no receive macaroon yet"); n != 1 {
		t.Errorf("the degraded banner says the receive macaroon is missing %d times, want once", n)
	}
}
