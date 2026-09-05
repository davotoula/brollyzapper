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

// ErrNoAnswer is nok's sentinel, exported for the regression test.
//
// Unexported in the package proper: nothing outside internal/nostr distinguishes
// it yet — internal/zap only asks whether anything was Accepted — and an
// exported sentinel is a promise to keep it stable.
var ErrNoAnswer = errNoAnswer

// SendOutcome is the pure classifier behind publishOne, exported so its table
// can be asserted directly.
//
// Two of its four rows have no other test and are awkward to reach through a
// real relay: `refused` needs a relay that answers OK(false), and the
// documented false negative — a socket dropping just after a genuine OK — is a
// race nothing can hold open. As a pure function they are four lines.
func SendOutcome(err error, connected bool) (string, error) { return sendOutcome(err, connected) }

// MappedRelayIsConnected reports whether the pool's map holds a LIVE relay for
// url, which is the half of du9.1's claim that a socket count cannot make.
//
// "Exactly one live relay" and "the live one is the one in the map" are
// different statements, and the bug this exists to catch satisfies the first
// while breaking the second: two sockets open, one of them mapped, the other
// reachable by nothing. Connected() cannot answer it — it reports what is in the
// map whether or not the socket under it is still up.
func MappedRelayIsConnected(p *Pool, url string) bool {
	return liveRelay(p.pool.Relays.Load(url))
}
