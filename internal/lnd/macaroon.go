package lnd

import (
	"fmt"
	"slices"
	"strings"
	"time"

	macaroonpkg "gopkg.in/macaroon.v2"
)

// Caveat conditions LND understands, from lnd/macaroons/constraints.go. The
// spend macaroon carries the first two (§6); the third is the fallback when a
// static IP is unavailable.
const (
	CaveatTimeBefore = "time-before"
	CaveatIPAddr     = "ipaddr"
	CaveatIPRange    = "iprange"
)

// CaveatIPConditions are the two ways a credential can be locked to a source
// address. Which one a bake uses depends on whether a static address is known;
// a consumer that cannot see the guard's configuration checks for either.
var CaveatIPConditions = []string{CaveatIPAddr, CaveatIPRange}

// CaveatLNDCustom is the condition prefix LND reserves for caveats it does not
// interpret itself, from lnd/macaroons/custom_caveat.go. A caveat reads
// `lnd-custom <name> <condition>`, and LND routes a request carrying it to the
// middleware registered under <name> — passing <condition> through untouched.
//
// It FAILS CLOSED: a macaroon with a custom caveat whose middleware is not
// registered is rejected outright (§14, verified in LND's rpcperms
// interceptor). That is the property P4 is built on — if the guard dies, the
// spend macaroon is dead rather than unrestricted.
const CaveatLNDCustom = "lnd-custom"

// GuardCaveatName is the middleware name the guard registers under, and the
// <name> half of its custom caveat. One constant, because a registration that
// does not match the caveat means every spend RPC is rejected and nothing else
// goes wrong — the quietest possible way to break sending.
const GuardCaveatName = "brollyguard"

// GuardCaveat builds the spend macaroon's custom caveat with a per-bake nonce
// (§6: `lnd-custom brollyguard <nonce>`).
//
// The nonce carries no meaning to LND, which passes it through, and the guard
// does not gate on it — see Guard.credentialCaveats for why matching it would
// refuse payments in flight across a renewal.
func GuardCaveat(nonce string) string {
	return CaveatLNDCustom + " " + GuardCaveatName + " " + nonce
}

// HasGuardCaveat reports whether a serialised macaroon carries the guard's
// custom caveat at all.
//
// The NAME only, not the nonce: this is the question §11's Tier 2 row asks — is
// this credential one the middleware will see? — and a credential baked before
// P4 answers no whatever its nonce would have been.
func HasGuardCaveat(raw []byte) bool {
	present, err := Caveats(raw)
	if err != nil {
		return false
	}
	for _, caveat := range present {
		condition, rest, found := strings.Cut(caveat, " ")
		if !found || condition != CaveatLNDCustom {
			continue
		}
		name, _, _ := strings.Cut(rest, " ")
		if name == GuardCaveatName {
			return true
		}
	}
	return false
}

// AddCaveats returns the macaroon with the given first-party caveats added.
//
// LND's BakeMacaroon takes permissions and nothing else, so every constraint is
// added here, client-side, with the same library that reads them back (§6).
// The result is a NEW macaroon: caveats are part of the signature chain, so
// adding one after the credential has been written would invalidate it.
func AddCaveats(raw []byte, caveats []string) ([]byte, error) {
	var m macaroonpkg.Macaroon
	if err := m.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("lnd: not a macaroon: %w", err)
	}
	for _, caveat := range caveats {
		if strings.TrimSpace(caveat) == "" {
			continue
		}
		if err := m.AddFirstPartyCaveat([]byte(caveat)); err != nil {
			return nil, fmt.Errorf("lnd: adding the %q caveat: %w", caveat, err)
		}
	}
	constrained, err := m.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("lnd: re-encoding the constrained macaroon: %w", err)
	}
	return constrained, nil
}

// RequireHardening asserts a credential carries §6's policy: an IP lock of
// either kind, and an expiry.
//
// It is deliberately about the POLICY rather than about the exact conditions a
// particular bake asked for. RequireCaveats catches "we asked and it did not
// happen"; this catches "we stopped asking" — a bake that quietly requested no
// caveats would satisfy RequireCaveats against its own empty list, and every
// indicator would read green while the credential constrained nothing.
func RequireHardening(raw []byte) error {
	present, err := Caveats(raw)
	if err != nil {
		return err
	}
	// Every failure at once, not the first: a credential missing both is the
	// common case on an upgrade, and naming one of them sends the reader
	// looking for a smaller problem than the one they have.
	var missing []string
	if !hasCondition(present, CaveatIPAddr) && !hasCondition(present, CaveatIPRange) {
		missing = append(missing, fmt.Sprintf("neither an %s nor an %s caveat, so a stolen copy "+
			"would work from anywhere", CaveatIPAddr, CaveatIPRange))
	}
	if !hasCondition(present, CaveatTimeBefore) {
		missing = append(missing, fmt.Sprintf("no %s caveat, so a stolen copy would never stop "+
			"working", CaveatTimeBefore))
	}
	if len(missing) > 0 {
		return fmt.Errorf("lnd: the macaroon carries %s", strings.Join(missing, "; and "))
	}
	return nil
}

// RequireCaveatValues asserts the caveats say what this build meant them to say.
//
// RequireHardening checks the condition NAMES; this checks the arguments, which
// is where the likely mistake is. A credential locked to the wrong address, or
// carrying a time-before LND cannot parse, satisfies every name-level check and
// is refused by the node — and the whole point of §11's post-bake verification
// is that a credential which constrains nothing must not reach disk looking
// green.
func RequireCaveatValues(raw []byte, wantIP string, wantExpiry time.Time) error {
	locked, ok := CaveatValue(raw, CaveatIPAddr)
	if !ok {
		locked, ok = CaveatValue(raw, CaveatIPRange)
	}
	if !ok {
		return fmt.Errorf("lnd: the macaroon carries no readable IP caveat")
	}
	if wantIP != "" && locked != wantIP {
		return fmt.Errorf("lnd: the macaroon is locked to %q, not the %q it was baked for",
			locked, wantIP)
	}
	when, ok := Expiry(raw)
	if !ok {
		return fmt.Errorf("lnd: the macaroon's %s caveat cannot be parsed as an RFC3339 time, "+
			"so the node will not accept it", CaveatTimeBefore)
	}
	if !when.Equal(wantExpiry.UTC().Truncate(time.Second)) {
		return fmt.Errorf("lnd: the macaroon expires at %s, not the %s it was baked for",
			when.Format(time.RFC3339), wantExpiry.UTC().Format(time.RFC3339))
	}
	return nil
}

// Caveats returns the first-party caveats// Caveats returns the first-party caveats a serialised macaroon carries.
//
// ADR 0001 means lnd's own macaroons package is unavailable, so this reads the
// bytes with gopkg.in/macaroon.v2 — which is what §6 says to use for adding
// caveats client-side, and therefore the same library that put them there.
func Caveats(raw []byte) ([]string, error) {
	var m macaroonpkg.Macaroon
	if err := m.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("lnd: not a macaroon: %w", err)
	}
	caveats := make([]string, 0, len(m.Caveats()))
	for _, caveat := range m.Caveats() {
		// A third-party caveat has a location; LND uses only first-party ones,
		// and a third-party caveat here would be something we did not bake.
		if len(caveat.VerificationId) != 0 {
			continue
		}
		caveats = append(caveats, string(caveat.Id))
	}
	return caveats, nil
}

// RequireCaveats asserts the macaroon genuinely carries every named condition.
//
// §11 calls this the check that matters most, and the reason is the failure
// mode it prevents: without it, a silent change in LND or in our own baking
// code ships a credential we BELIEVE is IP-locked and time-limited, while every
// indicator on the security page reads green. Nothing looks wrong.
func RequireCaveats(raw []byte, conditions []string) error {
	present, err := Caveats(raw)
	if err != nil {
		return err
	}
	var missing []string
	for _, condition := range conditions {
		if !hasCondition(present, condition) {
			missing = append(missing, condition)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("lnd: the baked macaroon is missing the %s caveat(s); it constrains "+
			"less than it appears to", strings.Join(missing, ", "))
	}
	return nil
}

// CaveatValue returns the argument of the first caveat with the given
// condition — "10.21.21.5" for "ipaddr 10.21.21.5".
func CaveatValue(raw []byte, condition string) (string, bool) {
	present, err := Caveats(raw)
	if err != nil {
		return "", false
	}
	for _, caveat := range present {
		name, value, found := strings.Cut(caveat, " ")
		if found && name == condition {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

// Expiry reads the time-before caveat. §11's Tier 2: an expired spend macaroon
// blocks sending and leaves receiving alone, so this has to be readable without
// asking the node.
func Expiry(raw []byte) (time.Time, bool) {
	value, ok := CaveatValue(raw, CaveatTimeBefore)
	if !ok {
		return time.Time{}, false
	}
	when, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, false
	}
	return when, true
}

func hasCondition(caveats []string, condition string) bool {
	return slices.ContainsFunc(caveats, func(caveat string) bool {
		name, _, _ := strings.Cut(caveat, " ")
		return name == condition
	})
}
