package lnd_test

import (
	"testing"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
)

// HasGuardCaveat matches the NAME, not merely the `lnd-custom` prefix.
//
// THE NEGATIVE CASE IS THE POINT, and nothing exercised it. LND's custom-caveat
// mechanism is shared: any app on the node can bake `lnd-custom <its own name>`.
// A check that accepted any custom caveat would read another app's macaroon as
// guard-capped everywhere it matters — §11's spend.cap row green,
// credentialNeedsBaking declining to re-bake, VerifyBaked passing — on a
// credential this guard's middleware will never be asked about.
func TestHasGuardCaveatMatchesTheNameAndNotJustThePrefix(t *testing.T) {
	for _, tc := range []struct {
		name    string
		caveats []string
		want    bool
	}{
		{"ours", []string{lnd.GuardCaveat("nonce")}, true},
		{"ours with no nonce", []string{lnd.CaveatLNDCustom + " " + lnd.GuardCaveatName}, true},
		{"another app's custom caveat", []string{lnd.CaveatLNDCustom + " litd 1"}, false},
		{"a name that merely starts the same", []string{lnd.CaveatLNDCustom + " brollyguardian 1"}, false},
		{"an ordinary caveat", []string{lnd.CaveatIPAddr + " 10.21.0.17"}, false},
		{"none at all", nil, false},
		{"ours among others", []string{
			lnd.CaveatIPAddr + " 10.21.0.17",
			lnd.CaveatLNDCustom + " litd 1",
			lnd.GuardCaveat("nonce"),
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := lnd.HasGuardCaveat(lndtest.Macaroon(t, tc.caveats...)); got != tc.want {
				t.Errorf("HasGuardCaveat(%v) = %v, want %v", tc.caveats, got, tc.want)
			}
		})
	}
	// And bytes that are not a macaroon answer NO rather than panicking: this is
	// read from a file the guard did not necessarily write.
	if lnd.HasGuardCaveat([]byte("not a macaroon")) {
		t.Error("bytes that are not a macaroon read as carrying the guard caveat")
	}
}
