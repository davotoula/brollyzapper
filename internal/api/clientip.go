package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// forwardedFor is the only forwarding header this codebase reads.
//
// X-Real-IP is deliberately absent and must stay absent: measured on the
// reference box (2026-08-21), Umbrel's app_proxy neither sets nor strips it, so
// it arrives verbatim from the client. Several rate-limiter helpers check it
// before X-Forwarded-For; behind app_proxy that is a free bypass.
const forwardedFor = "X-Forwarded-For"

// ClientIP derives the address to attribute a request to (spec §7).
//
// The TCP peer is never the client when it is itself a proxy: on Umbrel the
// callback sits behind app_proxy, and on the public side behind a tunnel.
// Keying on the peer would put every caller in one bucket; trusting the header
// unconditionally would let any caller spoof past a limit. So: if the peer is
// trusted, walk X-Forwarded-For right to left and take the first address that
// is not itself trusted. Otherwise the peer is the client.
//
// app_proxy replaces the header rather than appending to it, which makes the
// walk a single step on Umbrel — but §19 requires the app to run off Umbrel
// behind arbitrary proxies where appending is normal, so the general rule
// stands and Umbrel is the degenerate case.
func ClientIP(r *http.Request, trusted func(netip.Addr) bool) netip.Addr {
	peer := parseAddr(r.RemoteAddr)
	if !peer.IsValid() || trusted == nil || !trusted(peer) {
		return peer
	}

	hops := strings.Split(r.Header.Get(forwardedFor), ",")
	var leftmost netip.Addr
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			// A malformed hop is skipped rather than fatal: the header is
			// attacker-influenced and must never be able to cause an error path.
			continue
		}
		addr = addr.Unmap()
		if !trusted(addr) {
			return addr
		}
		leftmost = addr
	}
	// Every hop was a proxy we trust. The leftmost of them is the closest thing
	// to a client this request carries; with no usable hop at all, the peer is.
	if leftmost.IsValid() {
		return leftmost
	}
	return peer
}

// parseAddr pulls the address out of a host:port, tolerating a bare host.
func parseAddr(hostPort string) netip.Addr {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	// Values arrive v4-mapped (::ffff:a.b.c.d) through app_proxy; unmapping is
	// what stops ::ffff:1.2.3.4 and 1.2.3.4 becoming two different buckets.
	return addr.Unmap()
}
