package nostr_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/nostr"
)

// answers is a resolver that says the same thing about every host.
//
// Every host, because the only host these tests can put in a URL and still have
// a real dial reach a real server is 127.0.0.1 — the configured relay and the
// stranger's relay are the same host and differ only by port. The exemption is
// keyed on the whole relay URL, so that is a distinction it can make and a
// host-keyed one could not: the operator's relay connects and the stranger's is
// refused, both on 127.0.0.1.
type answers struct {
	addrs []string
	err   error
}

func (a answers) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	if a.err != nil {
		return nil, a.err
	}
	out := make([]netip.Addr, 0, len(a.addrs))
	for _, raw := range a.addrs {
		out = append(out, netip.MustParseAddr(raw))
	}
	return out, nil
}

// z9k criterion 5. The filter's subject is the ADDRESS a stranger's name leads
// to, not the name.
//
// Before this, wss://evil.example with an A record of 192.168.77.1 walked
// straight through: internal/lnurl checked the literal, found a name, and
// treated it as public. One DNS record defeated the whole allow-list, and the
// code said so in a comment — which is honest, and is not enforcement.
//
// A dropped relay is distinguishable from an unreachable one without reading
// any log: Publish reports one result PER TARGET, so a relay that was filtered
// out has no result at all, while one that was kept and refused has a result
// carrying its error. The assertions below turn on exactly that.
func TestAStrangerNamedHostIsCheckedByWhatItResolvesTo(t *testing.T) {
	for _, tc := range []struct {
		name    string
		resolve answers
		dialled bool
	}{{
		name:    "a name pointing at the LAN",
		resolve: answers{addrs: []string{"192.168.77.1"}},
	}, {
		// The case that decides whether the check is worth having: taking "one
		// public address is good enough" would mean an extra A record is all it
		// costs to get the LAN one dialled too.
		name:    "a name pointing at both a public address and the LAN",
		resolve: answers{addrs: []string{"93.184.216.34", "192.168.77.1"}},
	}, {
		name:    "a name pointing at CGNAT, which is every Tailscale address",
		resolve: answers{addrs: []string{"100.100.100.100"}},
	}, {
		name:    "a name nothing answers for",
		resolve: answers{err: errors.New("NXDOMAIN")},
	}, {
		// Distinct from an error: a resolver that succeeds with an empty answer
		// must not read as "no address failed the check, so dial it".
		name:    "a name that answers with no addresses at all",
		resolve: answers{},
	}, {
		name:    "a name pointing only at public addresses",
		resolve: answers{addrs: []string{"93.184.216.34", "1.1.1.1"}},
		dialled: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			configured := newFleet(t, 1)
			stranger := newFleet(t, 1)
			// The subject here is the FILTER, so the dial-time policy is stood
			// down: a kept relay must be shown really getting the event, and
			// every relay these tests can serve is on loopback. The dial-time
			// policy has its own test below, which takes the shipped default.
			pool := nostr.NewPool(t.Context(), configured.urls,
				nostr.Options{Resolve: tc.resolve})
			nostr.StandDownDialPolicy(pool)
			defer pool.Close()

			named := stranger.urls()[0]
			results := pool.Publish(t.Context(), signedNote(t), named)

			// The operator's own relay is always dialled, so a run in which
			// everything was refused cannot pass by accident.
			if got := nostr.Accepted(results); got < 1 {
				t.Fatalf("the configured relay did not accept the event: %+v", results)
			}
			if got, want := resultFor(results, named) != nil, tc.dialled; got != want {
				t.Errorf("Publish reported a result for the stranger's relay = %v, want %v; "+
					"a filtered target gets no result, a kept one does\n%+v", got, want, results)
			}
			if tc.dialled {
				lndtest.WaitFor(t, "the stranger's relay to be handed the event", func() bool {
					_, arrived := stranger.counts()
					return arrived == 1
				})
				return
			}
			if live, arrived := stranger.counts(); live != 0 || arrived != 0 {
				t.Errorf("the stranger's relay saw %d connections and %d events; it must not "+
					"have been dialled at all", live, arrived)
			}
		})
	}
}

// z9k criterion 6. The operator may point at a relay on their own LAN — the
// regtest stack does exactly that, by compose service name — so the check is
// for STRANGER-named relays and nothing else.
//
// The pair is the test. The same single-label URL is configured in one half and
// named by a stranger in the other, and it is kept in the first and dropped in
// the second; asserting only the first would pass against a pool that filters
// nothing. Neither can connect, which is the point: being NAMED in the results
// is what proves it got as far as a dial attempt.
//
// If a configured relay ever stops being dialled — regtest's relay2.zap.test is
// the one that would notice first — this exemption is what is wrong, not the
// test that caught it.
func TestConfiguredRelaysAreExemptFromTheResolutionCheck(t *testing.T) {
	const onTheLAN = "ws://relay" // a compose service name; single-label, unresolvable

	refuses := answers{err: errors.New("no DNS in this test")}

	t.Run("configured", func(t *testing.T) {
		pool := nostr.NewPool(t.Context(), func() []string { return []string{onTheLAN} },
			nostr.Options{Resolve: refuses})
		defer pool.Close()

		results := pool.Publish(t.Context(), signedNote(t))
		if resultFor(results, "ws://relay") == nil {
			t.Errorf("the operator's own single-label relay was filtered out: %+v", results)
		}
	})

	t.Run("named by a stranger", func(t *testing.T) {
		configured := newFleet(t, 1)
		pool := nostr.NewPool(t.Context(), configured.urls, nostr.Options{Resolve: refuses})
		defer pool.Close()

		results := pool.Publish(t.Context(), signedNote(t), onTheLAN)
		if resultFor(results, "ws://relay") != nil {
			t.Errorf("a stranger got the node to dial a single-label host: %+v", results)
		}
	})
}

// resultFor finds one relay's answer, tolerating the trailing-slash
// normalisation go-nostr applies to a URL on its way through the pool.
func resultFor(results []nostr.PublishResult, relay string) *nostr.PublishResult {
	want := strings.TrimSuffix(relay, "/")
	for i, r := range results {
		if strings.TrimSuffix(r.Relay, "/") == want {
			return &results[i]
		}
	}
	return nil
}

// vz1.4: the TOCTOU, closed — and this test could not be written before the
// dial-time hook existed.
//
// The shape is DNS rebinding, exactly. chooseTargets resolves a stranger's host
// and gets a public address, so the relay survives the filter; the library then
// resolves again when it dials and gets a private one. Nothing between those two
// resolutions is ours, and until the hook there was no moment at which the
// second answer could be seen — dialableHost's doc named that as an accepted
// residual.
//
// Both relays are on 127.0.0.1 and differ only by port, which is the point. The
// exemption is keyed on the relay URL, so the operator's own relay connects
// from that same private address while the stranger's is refused — one run,
// both arms, and a host-keyed exemption could not pass it. It also means the
// configured relay is a live positive control: if the hook refused everything,
// the accept below would fail rather than this test passing for the wrong
// reason.
func TestARelayThatRebindsToAPrivateAddressIsRefusedAtDial(t *testing.T) {
	configured := newFleet(t, 1)
	stranger := newFleet(t, 1)

	// The pre-check's answer: public, so the stranger's relay passes
	// chooseTargets. The DIAL will resolve the same URL to 127.0.0.1.
	pool := nostr.NewPool(t.Context(), configured.urls,
		nostr.Options{Resolve: answers{addrs: []string{"93.184.216.34"}}})
	defer pool.Close()

	named := stranger.urls()[0]
	results := pool.Publish(t.Context(), signedNote(t), named)

	// The operator's own relay, on the very address the stranger's was refused
	// for, was dialled and took the event.
	if got := nostr.Accepted(results); got < 1 {
		t.Fatalf("the configured relay did not accept the event, so the dial check is "+
			"refusing the operator's own relays too: %+v", results)
	}

	// The stranger's got past the filter — otherwise this would be testing
	// chooseTargets again rather than the dial.
	got := resultFor(results, named)
	if got == nil {
		t.Fatal("the relay was filtered out before the dial; this test is meant to reach " +
			"the dial-time check, so it is proving nothing about it")
	}
	if got.OK() {
		t.Error("the publish succeeded; the address dialled was private and the pre-check " +
			"had been told it was public — that is the rebinding the hook exists to stop")
	}
	// And nothing was actually delivered.
	if live, arrived := stranger.counts(); live != 0 || arrived != 0 {
		t.Errorf("the relay saw %d connections and %d events; the dial must have been "+
			"refused before the socket was connected", live, arrived)
	}
}
