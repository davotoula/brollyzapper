package api_test

import (
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/lnd"
)

// `20i.3` criterion 4. The Node page said "relink" and offered a Re-link button
// for a refusal re-linking cannot fix, so an operator whose address is wrong
// presses it for ever. The kind now reaches the page and the page says the one
// thing that is true.
func TestTheNodePageExplainsAnAddressMismatchAndOffersNoReLink(t *testing.T) {
	h := newHarness(t)
	h.broker.Answer = lnd.BrokerStatus{
		ReceiveMacaroonPresent: true,
		RefusalKind:            lnd.RefusalAddressMismatch,
		CredentialAddress:      "10.61.7.20",
	}
	page := h.get(t, "/node", h.login(t)).Body.String()

	for _, want := range []string{
		"refusing the credential for the address it sees",
		"10.61.7.20",                      // what the credential is locked to
		"Re-linking will not change this", // why the button is gone
		"restart the guard",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the Node page does not carry %q:\n%s", want, page)
		}
	}
	// THE BUTTON IS THE POINT. Copy explaining that re-linking cannot help,
	// beside a button offering to re-link, is worse than either alone.
	if strings.Contains(page, `action="/node/relink"`) {
		t.Errorf("the Node page still offers Re-link while the node is refusing the "+
			"credential for its address; the button cannot change what address the node "+
			"sees, so pressing it is a loop:\n%s", page)
	}
}

// The other direction, and the one criterion 5 turns into a golden: with no
// kind the page is exactly what it was. A hint that renders when nothing is
// wrong is a worse defect than the one it was written for.
func TestTheNodePageIsUnchangedWithNoRefusal(t *testing.T) {
	h := newHarness(t)
	h.broker.Answer = lnd.BrokerStatus{ReceiveMacaroonPresent: true}
	page := h.get(t, "/node", h.login(t)).Body.String()

	if strings.Contains(page, "refusing the credential for the address it sees") {
		t.Errorf("the Node page explains an address mismatch that is not happening:\n%s", page)
	}
	if !strings.Contains(page, `action="/node/relink"`) {
		t.Errorf("the Node page no longer offers Re-link on a healthy install; that button is "+
			"the recovery for a ROTATED macaroon, which is a real and different case:\n%s", page)
	}
}

// An unknown token — a guard newer than this server — renders as no kind at
// all. This is the page half of lnd.KnownRefusalKind: the gate is upstream, and
// this is what proves the page never sees past it.
func TestANodePageGivenAnUnknownRefusalRendersAsUsual(t *testing.T) {
	h := newHarness(t)
	h.broker.Answer = lnd.BrokerStatus{
		ReceiveMacaroonPresent: true,
		// Not a token this build knows. It cannot arrive through the socket —
		// KnownRefusalKind drops it there — so this stands in for a caller that
		// bypassed the gate, and asserts the page does not act on one either.
		RefusalKind: lnd.RefusalKind("something_a_newer_guard_says"),
	}
	page := h.get(t, "/node", h.login(t)).Body.String()

	if strings.Contains(page, "refusing the credential for the address it sees") {
		t.Errorf("an unrecognised refusal token rendered the address-mismatch copy:\n%s", page)
	}
	if !strings.Contains(page, `action="/node/relink"`) {
		t.Errorf("an unrecognised refusal token removed the Re-link button:\n%s", page)
	}
}
