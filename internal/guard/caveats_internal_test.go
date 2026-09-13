package guard

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd"
)

// WHICH IP LOCK WINS when both addresses are configured (20i.14).
//
// deploy/docker-compose.yml and DEPLOYING.md both tell the operator that
// NETWORK_CIDR is not read while SERVER_IP is set. That is true only because of
// the ORDER of two cases in credentialCaveats' switch, and before this test
// nothing held the order: TestBakeSpendRefusesWhenThereIsNoAddressToLockTo
// asserts "never neither" and assertHardened allows either caveat, so swapping
// the cases left every guard test green and both documents false.
//
// The both-set row is the one carrying the claim. The single-address rows are
// here so that a "fix" which always emits one kind cannot pass, and the
// neither row so the table covers every combination the switch can see.
//
// Internal, because credentialCaveats is unexported and the property is about
// that function rather than about a bake: a bake needs a running node, and the
// order is decided before the node is asked anything.
func TestCredentialCaveatsPrefersServerIPOverNetworkCIDR(t *testing.T) {
	serverIP := netip.MustParseAddr("10.61.7.10")
	networkCIDR := netip.MustParsePrefix("10.61.7.0/24")

	rows := []struct {
		name        string
		serverIP    netip.Addr
		networkCIDR netip.Prefix
		want        string // the one IP caveat expected; "" means the bake is refused
	}{
		{"both set: SERVER_IP wins, NETWORK_CIDR is not read", serverIP, networkCIDR,
			lnd.CaveatIPAddr + " " + serverIP.String()},
		{"only SERVER_IP", serverIP, netip.Prefix{},
			lnd.CaveatIPAddr + " " + serverIP.String()},
		{"only NETWORK_CIDR", netip.Addr{}, networkCIDR,
			lnd.CaveatIPRange + " " + networkCIDR.String()},
		{"neither: refused", netip.Addr{}, netip.Prefix{}, ""},
	}
	// Both credentials, because both call the one function and a future second
	// list is exactly the drift d46.26 collapsed.
	for _, c := range []credential{receiveCredential, spendCredential} {
		for _, row := range rows {
			t.Run(c.kind+"/"+row.name, func(t *testing.T) {
				g := &Guard{serverIP: row.serverIP, networkCIDR: row.networkCIDR}
				caveats, err := g.credentialCaveats(c, time.Now().Add(CredentialLifetime))

				if row.want == "" {
					if err == nil {
						t.Fatalf("baked with no address to lock to: %q", caveats)
					}
					if got := g.ipCaveatValue(); got != "" {
						t.Errorf("ipCaveatValue() = %q with no address configured, want empty", got)
					}
					return
				}
				if err != nil {
					t.Fatalf("credentialCaveats: %v", err)
				}
				var ipLocks []string
				for _, caveat := range caveats {
					condition, _, _ := strings.Cut(caveat, " ")
					if slices.Contains(lnd.CaveatIPConditions, condition) {
						ipLocks = append(ipLocks, caveat)
					}
				}
				if len(ipLocks) != 1 || ipLocks[0] != row.want {
					t.Errorf("IP caveats = %q, want exactly [%q]", ipLocks, row.want)
				}
				// The refusal message names this value, so it must agree with the
				// caveat the bake actually carries.
				_, wantValue, _ := strings.Cut(row.want, " ")
				if got := g.ipCaveatValue(); got != wantValue {
					t.Errorf("ipCaveatValue() = %q, want %q — the value the caveat carries", got, wantValue)
				}
			})
		}
	}
}
