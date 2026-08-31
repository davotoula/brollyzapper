package nostr

import (
	"context"
	"net/netip"
	"strings"
	"time"
)

// Dialable reports whether this node may open a connection to host on a
// STRANGER's say-so.
//
// A zap request's relays tag is an anonymous caller choosing which outbound
// connections this node opens. The node sits on a home LAN, next to the
// router's admin interface, the Umbrel dashboard and every other app on the
// box — so the tag is an SSRF vector wearing a protocol's clothes, and "it only
// opens a websocket" is not much comfort when the target is 169.254.169.254.
//
// This is the LITERAL half: what the host string says on its own, with no DNS.
// The resolving half is [Pool.dialableHost], which is the only caller that can
// close the gap a name leaves open.
//
// It lives here rather than in internal/lnurl because this package owns the
// dialling, and because there must be exactly one copy of the table below. It
// has already been wrong twice — see reservedPrefixes — and a second copy is
// how a third miss would happen quietly.
func Dialable(host string) bool {
	if !dialableName(host) {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// A hostname, and this function does not resolve: a DNS lookup must not
		// happen on the parse path, where a stranger would be choosing what an
		// unauthenticated request makes this node look up. The pool resolves it
		// instead, once, at the point of dialling.
		return true
	}
	return dialableAddr(addr)
}

// dialableName is what the host string rules out on its own, before any address
// is known.
//
// A single-label name resolves through the search domain — ws://router,
// ws://umbrel — and .local is mDNS on the same LAN. Both are the case this
// filter exists for, and neither is an address, so no allow-list can catch
// them.
func dialableName(host string) bool {
	lower := strings.ToLower(host)
	return host != "" && strings.Contains(lower, ".") &&
		!strings.HasSuffix(lower, ".local") && !strings.HasSuffix(lower, ".localhost") &&
		lower != "localhost"
}

// dialableAddr is the allow-list itself, applied to one address.
//
// An ALLOW-list of what may be dialled, not a deny-list of what may not. A
// deny-list of address classes is always one class short — that is precisely
// how the Wave 8 version failed, and the first Wave 12 version was missing
// 100.64.0.0/10, which is CGNAT and therefore every Tailscale address, on boxes
// that are routinely on a tailnet.
func dialableAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() {
		return false
	}
	for _, reserved := range reservedPrefixes {
		if reserved.Contains(addr) {
			return false
		}
	}
	return true
}

// reservedPrefixes are special-purpose ranges that IsGlobalUnicast still calls
// global. Each is a place a stranger must not be able to point this node at.
//
// The CONTENTS are the security property, which is why zu5.1 gives every entry
// its own test case: dropping a line here is a silent widening of what an
// anonymous caller can reach, and the two times this list was wrong it was a
// human re-reading it that noticed, not the suite.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT — and every Tailscale address
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64
	netip.MustParsePrefix("2002::/16"),       // 6to4
}

// Resolver is how the pool learns what a stranger-named hostname points at.
//
// Declared here rather than taking *net.Resolver so a test can answer without
// DNS: the interesting cases are a name that answers with a LAN address and a
// name that answers with both a public and a LAN address, and neither can be
// arranged against the real resolver.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// resolveTimeout bounds one lookup. A stranger picks the name, so a resolver
// that never answers is a stranger holding a publish open; §7 says publication
// must never block a settlement.
const resolveTimeout = 3 * time.Second

// dialableHost is Dialable plus the resolution a name needs, and it is the
// check that makes the filter more than advisory.
//
// Every resolved address must pass. A host answering with both a public and a
// LAN address is an attack, not an edge case — taking "any public address is
// good enough" would mean a single extra A record defeats the whole list.
//
// A host that does not resolve is DROPPED, not dialled: a name nothing answers
// for is not a relay, and treating a failed lookup as permission would hand a
// stranger the filter's off switch (make the lookup fail, get dialled anyway).
//
// TOCTOU / DNS REBINDING — closed, and it used to be an accepted residual here.
//
// The addresses checked here are not the addresses dialled: go-nostr resolves
// the name again when it connects, and a record that changes between the two —
// or a name that answers differently each time — walks through the gap. This
// comment used to say so and stop there, because the library exposed no dial
// hook.
//
// It does now: the fork carries WithDialAddressCheck, and Pool.checkDialAddress
// applies dialableAddr to the address actually on the socket (vz1.4).
//
// The two are NOT the same check, and neither one subsumes the other.
//
// This one is BROADER, and one clause of that is load-bearing rather than
// merely tidy: it requires EVERY address the name answers with to pass. The
// dial check cannot, because it hangs off net.Dialer.Control, which runs per
// candidate address while the dialer simply moves on to the next one after a
// refusal — so a host answering with one public address and one private one is
// caught here and nowhere else. It also refuses a name that does not resolve at
// all, and a relay it drops is named with its reason in the publish's own log
// line rather than only in one relay's error.
//
// The dial check is NARROWER but AUTHORITATIVE: it is the only one of the two
// whose verdict gates the actual socket. Delete this function and single-address
// attacks are still blocked; delete the dial check and rebinding is wide open
// again. So "backstop" describes its job — stopping a second answer being
// believed after the first was checked — and not its importance.
//
// It could apply dialableName too, and does not: it has the relay's URL, so the
// name is right there. It is redundant by then. dialableName exists to refuse a
// shape before paying for a lookup; once an address is in hand, dialableAddr
// decides everything dialableName would have.
func (p *Pool) dialableHost(ctx context.Context, host string) bool {
	if !dialableName(host) {
		return false
	}
	// THERE IS NO BRANCH HERE FOR A LITERAL, and if you are looking for one,
	// this is the reason. Everything goes through the resolver, literals
	// included: LookupNetIP hands a literal straight back without touching the
	// network, so an address the operator's sender typed and an address a name
	// led to arrive at the allow-list the same way. The allow-list is therefore
	// applied to addresses, and only to addresses, at one point — which is what
	// makes "there is exactly one copy of the table" a statement about the code
	// rather than a hope. A special case for literals here would be a second
	// place for it to drift.
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	addrs, err := p.resolve.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, addr := range addrs {
		if !dialableAddr(addr) {
			return false
		}
	}
	return true
}
