package api_test

import (
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/store"
)

// SPELLED ONCE, because two of the three assertions below are NEGATIVE. A
// heading changed in the template would leave "the page does not contain the
// old heading" true and those tests green while asserting nothing — silence
// meaning "did not run" rather than "passed".
const (
	mismatchHeading = "refusing the credential for the address it sees"
	relinkForm      = `action="/node/relink"`
)

// `20i.3` criterion 4. The Node page said "relink" and offered a Re-link button
// for a refusal re-linking cannot fix, so an operator whose address is wrong
// presses it for ever.
//
// BOTH HALVES OF THE CONDITION are set here, and that is the fix this test
// exists to hold: the guard's kind alone means only "a re-bake would change
// nothing", which is equally true of a healthy install whose operator clicked
// twice. The node must actually be rejecting the credential as well.
func TestTheNodePageExplainsAnAddressMismatchAndOffersNoReLink(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.NodeState = func() lnd.State { return lnd.StateRelink }
	})
	h.broker.Answer = lnd.BrokerStatus{
		ReceiveMacaroonPresent: true,
		RefusalKind:            guard.KindAddressMismatch,
		CredentialAddress:      "10.61.7.20",
	}
	page := h.get(t, "/node", h.login(t)).Body.String()

	for _, want := range []string{
		mismatchHeading,
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
	if strings.Contains(page, relinkForm) {
		t.Errorf("the Node page still offers Re-link while the node is refusing the "+
			"credential for its address; the button cannot change what address the node "+
			"sees, so pressing it is a loop:\n%s", page)
	}
}

// THE DEFECT THIS BEAD SHIPPED AND THE REVIEW CAUGHT. wouldRepeatItself refuses
// whenever the credential meets the policy, is younger than MinBakeInterval and
// its root key is still listed — all true on a healthy install after a second
// Re-link click. Measured: the guard really does report the kind here. Without
// the node-state half, a working deployment was told its address was wrong and
// had its only recovery button removed until the next renewal, days later.
func TestAHealthyInstallIsNotAccusedAfterTwoReLinkClicks(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		// The node is answering: nothing is rejecting anything.
		opts.NodeState = func() lnd.State { return lnd.StateReady }
	})
	h.broker.Answer = lnd.BrokerStatus{
		ReceiveMacaroonPresent: true,
		// The guard refused a second bake inside MinBakeInterval, which is what
		// clicking Re-link twice does.
		RefusalKind:       guard.KindAddressMismatch,
		CredentialAddress: "10.61.7.20",
	}
	page := h.get(t, "/node", h.login(t)).Body.String()

	if strings.Contains(page, mismatchHeading) {
		t.Errorf("a HEALTHY install is being told its address is wrong because the operator "+
			"pressed Re-link twice; the guard's refusal means only that a re-bake would "+
			"change nothing:\n%s", page)
	}
	if !strings.Contains(page, relinkForm) {
		t.Errorf("a healthy install lost its Re-link button to a refusal that means nothing "+
			"is wrong:\n%s", page)
	}
}

// The other direction, and the one criterion 5 turns into a golden: with no
// refusal the page is exactly what it was. A hint that renders when nothing is
// wrong is a worse defect than the one it was written for.
func TestTheNodePageIsUnchangedWithNoRefusal(t *testing.T) {
	h := newHarness(t)
	h.broker.Answer = lnd.BrokerStatus{ReceiveMacaroonPresent: true}
	page := h.get(t, "/node", h.login(t)).Body.String()

	if strings.Contains(page, mismatchHeading) {
		t.Errorf("the Node page explains an address mismatch that is not happening:\n%s", page)
	}
	if !strings.Contains(page, relinkForm) {
		t.Errorf("the Node page no longer offers Re-link on a healthy install; that button is "+
			"the recovery for a ROTATED macaroon, which is a real and different case:\n%s", page)
	}
}
