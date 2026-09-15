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
// rows with nothing to read, for one reason. Since as0.11 they are NOT CHECKED,
// which the banner does not list at all — the reason is node.linked's failure,
// and that is said once.
func TestTheSecurityPageRendersTheReceiveCredentialRows(t *testing.T) {
	h := newHarness(t, livePreflight(lnd.StateNotLinked, func(in *preflight.Inputs) {
		in.ReceiveMacaroon = func() ([]byte, bool) { return nil, false }
	}))
	cookie := h.login(t)

	raw := h.get(t, "/security", cookie).Body.String()
	security := html.UnescapeString(raw)
	for _, title := range []string{
		"The receive macaroon carries its caveats",
		"The receive macaroon is locked to this container",
		"The receive macaroon has not expired",
		"The node still honours the receive root key",
	} {
		verdict, detail := securityRow(t, raw, title)
		if verdict != "not checked" {
			t.Errorf("%q reads %q with no receive macaroon to read, want not checked: %q", title, verdict, detail)
		}
	}
	if !strings.Contains(security, "Receive macaroon exfiltrated") {
		t.Error("the receive rows do not name the §11 threat they map to")
	}

	wallet := html.UnescapeString(h.get(t, "/", cookie).Body.String())
	if n := strings.Count(wallet, "There is no receive macaroon yet"); n != 0 {
		t.Errorf("the degraded banner lists the not-checked receive rows %d times; not yet known is "+
			"not a failure, and the Security page is where it is said", n)
	}
	if n := strings.Count(wallet, "No credentials for your Lightning node yet"); n != 1 {
		t.Errorf("the degraded banner names the unlinked node %d times, want once — it is the row "+
			"that knows why the receive rows could not be read", n)
	}
}
