package guard_test

import (
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
)

// `20i.3` criterion 3. The guard already refuses a bake that would change
// nothing, and the reason already reaches the Security page as an audit row —
// what was missing is a token the Node page can act on, because that page was
// saying "relink" and offering a button for a problem re-linking cannot fix.
//
// BOTH DIRECTIONS IN ONE TEST, deliberately: a kind that is set and never
// cleared would leave the page accusing the operator's network for ever, and a
// test that only asserted the set half would pass against exactly that.
// OVER THE SOCKET, not against the guard in-process, and the reason is the one
// TestTheGateReachesTheServerOverTheSocket records: the page tests set this
// field on a broker fake, so a Status that stopped filling it would leave every
// one of them green. This is the wire between the two sides (§13), and it
// exercises lnd.KnownRefusalKind on the way through as well.
func TestTheRefusalKindIsSetOnRefusalAndClearedByASuccessfulBake(t *testing.T) {
	node := lndtest.Start(t)
	clock := &testClock{now: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)}
	g, _ := newGuardWithOptions(t, node, guard.Options{Now: clock.Now})
	client := serveGuard(t, g)

	status, err := client.Status(t.Context())
	if err != nil {
		t.Fatalf("Status over the socket: %v", err)
	}
	if status.RefusalKind != "" {
		t.Fatalf("RefusalKind = %q before anything was refused, want empty; the page would "+
			"explain a failure that has not happened", status.RefusalKind)
	}

	// A first bake succeeds; a second moments later is the refusal under test.
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	err = g.BakeSpend(t.Context())
	if err == nil {
		t.Fatal("the second bake was accepted; this test needs the refusal it is about")
	}
	if !strings.Contains(err.Error(), "already meets the policy") {
		t.Fatalf("the refusal is not the one this test is about: %v", err)
	}

	status, err = client.Status(t.Context())
	if err != nil {
		t.Fatalf("Status over the socket: %v", err)
	}
	if status.RefusalKind != guard.KindAddressMismatch {
		t.Errorf("RefusalKind = %q after the address-mismatch refusal, want %q",
			status.RefusalKind, guard.KindAddressMismatch)
	}
	// The address travels with it, as a VALUE — the page needs it to say which
	// address the node is disagreeing with, and that is a fact rather than a
	// sentence about one.
	if status.CredentialAddress == "" {
		t.Error("CredentialAddress is empty, so the page cannot name what the credential is " +
			"locked to — the one fact the operator has to compare against their node")
	}

	// And past MinBakeInterval the bake proceeds, which must clear it. Without
	// this the operator fixes the address, the guard recovers, and the page goes
	// on telling them it did not.
	clock.advance(guard.MinBakeInterval + time.Minute)
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("a bake past MinBakeInterval was refused: %v", err)
	}
	status, err = client.Status(t.Context())
	if err != nil {
		t.Fatalf("Status over the socket: %v", err)
	}
	if status.RefusalKind != "" {
		t.Errorf("RefusalKind = %q after a successful bake, want empty — the page would keep "+
			"explaining a refusal that has been repaired", status.RefusalKind)
	}
}
