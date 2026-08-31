package guard

import (
	"context"
	"errors"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/secret"
)

// CredentialLifetime is how long a baked credential is valid before the guard
// replaces it (§6). Seven days for both macaroons: a stolen copy stops working
// within a week without anyone noticing it was stolen, and the scheduled
// re-bake keeps a healthy install ahead of it.
const CredentialLifetime = 7 * 24 * time.Hour

// RenewBefore is how early the scheduled re-bake replaces a credential.
//
// A third of the lifetime, so a guard that is down for a day or restarts a few
// times still renews well before expiry — and so an operator who notices the
// Node page has never seen an expired credential.
const RenewBefore = CredentialLifetime / 3

// credentialCaveats is the hardening EVERY credential the guard bakes carries.
//
// ONE function, deliberately: before d46.26 the spend macaroon carried an IP
// lock and an expiry while the receive macaroon carried nothing, on the
// reasoning that five methods which cannot move a satoshi need no constraining.
// That reasoning was wrong — a stolen recv.macaroon streams every invoice on
// the node, for every app, over LND's Tor-published gRPC — and two lists were
// what let the two credentials drift apart in the first place. They differ in
// permissions and in nothing else.
//
// The IP lock is `ipaddr` against the server's static address where there is
// one, and `iprange` against the app network otherwise. Both are checked by LND
// against the SOURCE address of the gRPC connection, and the credential is used
// by the SERVER container — which is why compose pins that container's address
// and passes it here.
func (g *Guard) credentialCaveats(c credential, expiry time.Time) ([]string, error) {
	caveats := []string{lnd.CaveatTimeBefore + " " + expiry.UTC().Format(time.RFC3339)}
	// P4's custom caveat, on the SPEND credential only (§6, §14, tna.1). It is
	// a field on the credential rather than a second list here — see
	// credential.guardCaveat for why, and note that this function still applies
	// one policy to both: the flag says which of them the policy includes it
	// for, not what their policies are.
	//
	// A FRESH NONCE per bake. LND passes it through untouched and the guard does
	// not gate on it: matching it would refuse a payment in flight across a
	// renewal, because the server holds an open gRPC connection carrying the
	// credential the guard has just replaced. Its job is to make two credentials
	// distinguishable in the node's logs and in an intercepted request.
	if c.guardCaveat {
		caveats = append(caveats, lnd.GuardCaveat(secret.RandomToken(8)))
	}
	switch {
	case g.serverIP.IsValid():
		caveats = append(caveats, lnd.CaveatIPAddr+" "+g.serverIP.String())
	case g.networkCIDR.IsValid():
		caveats = append(caveats, lnd.CaveatIPRange+" "+g.networkCIDR.String())
	default:
		// Refusing beats baking a credential that constrains nothing. SERVER_IP
		// is a required setting, so this cannot fire on a configured install —
		// it fires for an embedder who skipped it, at the moment they would
		// otherwise have got an unconstrained credential and no warning.
		return nil, errors.New("guard: no SERVER_IP and no NETWORK_CIDR, so a baked credential " +
			"could not be locked to any source address (§6)")
	}
	return caveats, nil
}

// MinBakeInterval is the shortest gap between two bakes that would produce the
// same credential. It bounds the damage of a caveat the node will not accept:
// see Guard.wouldRepeatItself.
const MinBakeInterval = 30 * time.Minute

// RenewInterval is how often the guard checks whether a credential is due for
// replacement. Frequent relative to RenewBefore, so a guard that was down over
// the renewal window catches up within the hour rather than at the next expiry.
const RenewInterval = time.Hour

// RunRenewal replaces credentials before they expire, until ctx ends.
//
// The tick channel is a parameter so the schedule is the caller's and a test
// costs microseconds — the same shape as the reconciler and the domain probe.
// It does NOT check on entry: cmd/brollyguard calls EnsureReceiveMacaroon at
// startup, and a second immediate pass would only double the attempt count on
// the failing path.
//
// A failure is logged and retried on the next tick. An expiring credential is a
// state the Node page shows (Status carries ReceiveExpiry); it is never a reason
// to exit, and the guard's one sanctioned exit stays the rotation path (§11).
//
// BOTH credentials, and the spend one only while sending is enabled — d24.8's
// one spend-specific rule, enforced inside EnsureSpendMacaroon so that every
// path into renewal inherits it rather than each caller remembering. A loop
// that re-baked a revoked spend credential would turn "Disable sending" into
// "Disable sending for up to an hour".
//
// The two are independent: a receive renewal that fails must not stop the spend
// one being attempted, because they fail for different reasons and a shared
// early return would hide the second behind the first.
func (g *Guard) RunRenewal(ctx context.Context, tick <-chan time.Time) {
	renew := func() {
		if err := g.EnsureReceiveMacaroon(ctx); err != nil {
			g.log.Warn("could not renew the receive macaroon; will try again",
				"error", err.Error())
		}
		if err := g.EnsureSpendMacaroon(ctx); err != nil {
			g.log.Warn("could not renew the spend macaroon; will try again",
				"error", err.Error())
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-tick:
			if !ok {
				return
			}
			renew()
		}
	}
}
