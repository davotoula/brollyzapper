package nostr

import "net/netip"

// StandDownDialPolicy replaces the dial-time address policy with one that
// accepts everything, for tests whose subject is the LIFETIME of a stranger's
// socket rather than whether it may exist.
//
// Under the real policy they could not open one at all: the only address a test
// can serve from is 127.0.0.1, which is exactly what the policy refuses a
// stranger. This is the seam those tests used to get from the TOCTOU itself —
// telling the pre-check "public" and letting the dial go to loopback — which
// vz1.4 closed.
//
// In export_test.go, so it exists only in this package's test binary. The
// earlier version of this was an exported Options field, which put a knob in
// the shipped API whose entire documented contract was "nothing may set this",
// held by an arch rule matching the text "Dialable:" — and therefore blind to
// the assignment form the package itself uses three lines from the field. The
// compiler is the better rule.
//
// Never in a test of the policy itself: dialable_test.go's rebinding test takes
// the real one deliberately, and that is what proves the shipped behaviour.
func StandDownDialPolicy(p *Pool) {
	p.dialable = func(netip.Addr) bool { return true }
}

// CheckDialAddress reaches the dial hook directly, so the no-publish-in-flight
// mode can be tested. Nothing dials outside a publish until §8, so there is no
// other way to reach it — and leaving it unreached is what let its first version
// fail closed for the one case it exists to allow.
func CheckDialAddress(p *Pool, relayURL, resolved string) error {
	return p.checkDialAddress("tcp4", relayURL, resolved)
}

// ConnectBudget is du9's connect-phase bound, exported for the regression test.
//
// The test asserts against the CONSTANT and not against five seconds: the number
// is delegated and will move, and a test carrying its own copy of it would pass
// on the day the budget was raised to thirty.
const ConnectBudget = connectBudget
