package lnd_test

import (
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
)

func TestCaveatsReadsWhatWasBakedIn(t *testing.T) {
	raw := lndtest.Macaroon(t, "ipaddr 10.21.21.5", "time-before 2026-09-01T00:00:00Z")
	got, err := lnd.Caveats(raw)
	if err != nil {
		t.Fatalf("Caveats: %v", err)
	}
	if len(got) != 2 || got[0] != "ipaddr 10.21.21.5" {
		t.Errorf("Caveats = %v, want the two that were added", got)
	}
}

func TestCaveatsRejectsSomethingThatIsNotAMacaroon(t *testing.T) {
	if _, err := lnd.Caveats([]byte("not a macaroon")); err == nil {
		t.Error("Caveats accepted arbitrary bytes")
	}
}

// §11: after every bake, assert the caveats are genuinely present rather than
// trusting that the bake applied them. Without this a silently-unconstrained
// credential ships while every indicator reads green.
func TestRequireCaveatsCatchesAStrippedMacaroon(t *testing.T) {
	want := []string{"ipaddr", "time-before"}

	full := lndtest.Macaroon(t, "ipaddr 10.21.21.5", "time-before 2026-09-01T00:00:00Z")
	if err := lnd.RequireCaveats(full, want); err != nil {
		t.Errorf("RequireCaveats on a correctly baked macaroon: %v", err)
	}

	// The failure that matters: a macaroon that looks fine and constrains
	// nothing.
	stripped := lndtest.Macaroon(t)
	err := lnd.RequireCaveats(stripped, want)
	if err == nil {
		t.Fatal("RequireCaveats accepted a macaroon with every caveat stripped")
	}
	for _, condition := range want {
		if !strings.Contains(err.Error(), condition) {
			t.Errorf("error %q does not name the missing %s caveat", err, condition)
		}
	}

	// Half-stripped is still a failure.
	half := lndtest.Macaroon(t, "ipaddr 10.21.21.5")
	if err := lnd.RequireCaveats(half, want); err == nil {
		t.Error("RequireCaveats accepted a macaroon missing time-before")
	}
}

func TestCaveatIPAddrIsReadBack(t *testing.T) {
	raw := lndtest.Macaroon(t, "ipaddr 10.21.21.5", "time-before 2026-09-01T00:00:00Z")
	got, ok := lnd.CaveatValue(raw, "ipaddr")
	if !ok || got != "10.21.21.5" {
		t.Errorf("CaveatValue(ipaddr) = %q, %v; want 10.21.21.5, true", got, ok)
	}
	if _, ok := lnd.CaveatValue(raw, "iprange"); ok {
		t.Error("CaveatValue found an iprange caveat that was never added")
	}
}

// §11's Tier 2: an expired spend macaroon blocks sending and leaves receiving
// alone, so the expiry has to be readable.
func TestExpiryIsReadFromTheTimeBeforeCaveat(t *testing.T) {
	when := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	raw := lndtest.Macaroon(t, "ipaddr 10.21.21.5", "time-before "+when.Format(time.RFC3339))

	got, ok := lnd.Expiry(raw)
	if !ok {
		t.Fatal("Expiry found no time-before caveat")
	}
	if !got.Equal(when) {
		t.Errorf("Expiry = %v, want %v", got, when)
	}
	if _, ok := lnd.Expiry(lndtest.Macaroon(t)); ok {
		t.Error("Expiry reported a time on a macaroon with no time-before caveat")
	}
}

// RequireHardening checks the caveat NAMES; this checks the arguments, which is
// where the likely mistake is. A credential locked to the wrong address, or
// carrying a time LND cannot parse, satisfies every name-level check and is
// then refused by the node — and §11's whole point is that such a credential
// must not reach disk looking green.
//
// It is a backstop against a bug in caveat construction, so no call site can
// trigger it: it is tested directly or not at all.
func TestRequireCaveatValuesChecksWhatTheCaveatsActuallySay(t *testing.T) {
	expiry := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	good := lndtest.Macaroon(t, "ipaddr 10.21.21.14",
		"time-before "+expiry.Format(time.RFC3339))

	if err := lnd.RequireCaveatValues(good, "10.21.21.14", expiry); err != nil {
		t.Fatalf("a correctly built credential was refused: %v", err)
	}

	for _, tc := range []struct {
		name    string
		raw     []byte
		wantIP  string
		expiry  time.Time
		mustSay string
	}{
		{
			name: "locked to the wrong address", raw: good,
			wantIP: "10.21.21.99", expiry: expiry, mustSay: "10.21.21.99",
		},
		{
			name:   "an expiry that is not the one asked for",
			raw:    good,
			wantIP: "10.21.21.14", expiry: expiry.Add(time.Hour), mustSay: "expires at",
		},
		{
			name:   "a time-before the node cannot parse",
			raw:    lndtest.Macaroon(t, "ipaddr 10.21.21.14", "time-before next tuesday"),
			wantIP: "10.21.21.14", expiry: expiry, mustSay: "RFC3339",
		},
		{
			name:   "no IP caveat at all",
			raw:    lndtest.Macaroon(t, "time-before "+expiry.Format(time.RFC3339)),
			wantIP: "10.21.21.14", expiry: expiry, mustSay: "no readable IP caveat",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := lnd.RequireCaveatValues(tc.raw, tc.wantIP, tc.expiry)
			if err == nil {
				t.Fatal("accepted a credential whose caveats do not say what was asked for")
			}
			if !strings.Contains(err.Error(), tc.mustSay) {
				t.Errorf("error = %v, want it to mention %q", err, tc.mustSay)
			}
		})
	}

	// An iprange lock is read the same way.
	ranged := lndtest.Macaroon(t, "iprange 10.21.0.0/16",
		"time-before "+expiry.Format(time.RFC3339))
	if err := lnd.RequireCaveatValues(ranged, "10.21.0.0/16", expiry); err != nil {
		t.Errorf("an iprange-locked credential was refused: %v", err)
	}
}
