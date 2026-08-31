// Package guard is the credential broker: the only holder of admin.macaroon,
// with no network listener of any kind. It bakes the macaroons the server uses,
// writes them into the shared credential volume, and answers a small fixed set
// of questions over a unix socket (spec §3, §6).
//
// It also holds the OPERATOR's own settings — the sending latch and the two
// spend caps — because `06v` established that the environment is not a channel
// an operator can reach on umbrelOS, and the server is the container this whole
// design defends against. See operator.go and authorisation.go.
package guard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// Options configure a Guard. The zero value is usable.
type Options struct {
	Log *slog.Logger
	// Now and Sleep are injected so rotation detection is testable without
	// waiting thirty seconds or ten.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
	// RotationWindow and RotationThreshold override the §6 defaults.
	RotationWindow    time.Duration
	RotationThreshold int
	// ProbeInterval overrides how often the guard samples LND once it has been
	// rejected once. Zero takes ProbeInterval.
	ProbeInterval time.Duration
	// MaxWindowAttempts overrides the spend window's record bound. Zero takes
	// MaxWindowAttempts, which is five thousand — a test that filled that many
	// records would rewrite a growing JSON file five thousand times, and the
	// behaviour AT the bound is the same whatever the bound is.
	MaxWindowAttempts int
}

// Guard brokers credentials between LND and the server.
type Guard struct {
	node           *lnd.Client
	credentialsDir string
	certSourcePath string
	// serverIP and networkCIDR are what the IP caveat locks a credential to.
	// They describe the SERVER container, which is the one that uses what the
	// guard bakes — the guard itself connects with an unencumbered
	// admin.macaroon and never has a caveat pointed at it (§6).
	serverIP    netip.Addr
	networkCIDR netip.Prefix
	// dataDir is the guard's own volume — guard-state.json and the operator's
	// authorisation file. The server has no mount for it, which is the property
	// both of those rest on (§6, §16, `06v`).
	dataDir string
	// allowSending is the DEPLOYMENT ceiling on minting spend authority
	// (tna.4, reshaped by `06v` Ruling 4): may sending ever be enabled here at
	// all. True by default now; the operator's own gate is the stored latch.
	allowSending bool
	// authorisationLocation is where the deployment says the operator will find
	// the authorisation file, in the deployment's own words. Relayed to the
	// server so the page can name a route that exists without the generic app
	// assuming a deployment-specific path (§19).
	authorisationLocation string
	// middlewareUp is whether LND has confirmed the registration. §11 blocks
	// sending while it is false, and it is atomic because the middleware
	// goroutine sets it while the socket's goroutines read it in Status.
	middlewareUp atomic.Bool
	// runNonce namespaces spend-window records to this process, so a restart
	// cannot decrement a record it did not make (Ruling 2).
	runNonce string
	// maxWindowAttempts is the record bound; see MaxWindowAttempts.
	maxWindowAttempts int
	// rejectBudget bounds how much of the guard's 32-slot ring one burst of
	// refusals may take. See auditReject.
	rejectBudget *logging.RefusalBudget
	// authoriseBudget bounds the ceremony's events separately from refusals, so
	// a flood of one cannot spend the allowance that would have recorded the
	// first of the other. See auditAuthorisation.
	authoriseBudget *logging.RefusalBudget
	state           *stateStore
	rotation        *RotationDetector
	log             *slog.Logger
	sleep           func(ctx context.Context, d time.Duration) error

	rotated chan struct{}

	probeInterval time.Duration

	// bakeMu serialises baking. There are two callers now — the socket's
	// per-connection goroutine and the renewal loop — and BakeReceive composes
	// state.load() with a later state.update(), which is exactly what
	// stateStore's own doc comment says a caller must never do. Two interleaved
	// bakes would leave the credential on disk under a root key the state file
	// does not name: a key that can never be revoked.
	bakeMu sync.Mutex
}

// New builds a guard from the guard binary's configuration. It performs no
// network I/O.
func New(cfg *config.Guard, opts Options) (*Guard, error) {
	// The seed is what an install upgrading from ≤0.1.12 gets for the operator
	// controls the first time this store is read (`06v`, Migration). The caps
	// come from the environment, which is now their INITIAL value rather than a
	// ceiling; the latch is derived from evidence that sending was already on.
	state, err := openStateStore(cfg.DataDir, operatorSeed{
		maxSpendMsat:        cfg.MaxSpendMsat,
		maxPaymentMsat:      cfg.MaxPaymentMsat,
		spendCredentialPath: filepath.Join(cfg.CredentialsDir, lnd.SpendMacaroon),
	})
	if err != nil {
		return nil, err
	}
	log := opts.Log
	if log == nil {
		log = logging.Default()
	}
	sleep := opts.Sleep
	if sleep == nil {
		sleep = lnd.SleepContext
	}
	probeInterval := opts.ProbeInterval
	if probeInterval <= 0 {
		probeInterval = ProbeInterval
	}
	windowAttempts := opts.MaxWindowAttempts
	if windowAttempts <= 0 {
		windowAttempts = MaxWindowAttempts
	}
	// The guard dials LND with its own two bind-mounted files, through the same
	// client the server uses — one TLS path, one per-RPC credential mechanism.
	node := lnd.New(cfg.LNDAddress,
		lnd.FileCredentials(cfg.LNDCertFile, cfg.LNDAdminMacaroonFile),
		lnd.Options{Log: log})

	return &Guard{
		node:                  node,
		credentialsDir:        cfg.CredentialsDir,
		certSourcePath:        cfg.LNDCertFile,
		serverIP:              cfg.ServerIP,
		networkCIDR:           cfg.NetworkCIDR,
		dataDir:               cfg.DataDir,
		allowSending:          cfg.AllowSending,
		authorisationLocation: cfg.AuthorisationLocation,
		runNonce:              newRunNonce(),

		maxWindowAttempts: windowAttempts,
		rejectBudget:      logging.NewRefusalBudget(auditRejectBound, opts.Now),
		authoriseBudget:   logging.NewRefusalBudget(auditAuthorisationBound, opts.Now),
		state:             state,
		rotation:          NewRotationDetector(opts.Now, opts.RotationWindow, opts.RotationThreshold),
		log:               log,
		sleep:             sleep,
		rotated:           make(chan struct{}),
		probeInterval:     probeInterval,
	}, nil
}

// Close releases the connection to LND.
func (g *Guard) Close() error { return g.node.Close() }

// CopyCertificate re-copies LND's certificate into the credential volume. The
// guard does this on every start: it is how a regenerated certificate reaches
// the server, which holds no mount from the lightning app at all (§6).
func (g *Guard) CopyCertificate() error {
	certificate, err := os.ReadFile(g.certSourcePath)
	if err != nil {
		return fmt.Errorf("guard: reading %s: %w", g.certSourcePath, err)
	}
	return WriteCredential(g.credentialPath(lnd.CertFile), certificate, 0o600)
}

func (g *Guard) credentialPath(name string) string {
	return filepath.Join(g.credentialsDir, name)
}

// credential is one of the two the guard bakes. The two differ in these four
// values and in NOTHING else — which is the claim §6 makes in prose, expressed
// here as the only thing that varies.
//
// It is a struct rather than four parameters because the bake's ORDER carries
// the invariants: pending key recorded before the node is asked, verify before
// write, write before state, revoke last. Those are the rules a future
// amendment is most likely to touch, and when they lived in two copies an
// amendment reached one credential. That is exactly how the receive macaroon
// shipped unconstrained for the whole of P1 (d46.26).
type credential struct {
	kind        string   // "receive" or "spend"; appears in messages and audit
	file        string   // the name in the credential volume
	permissions []string // URI-scoped, compiled in, never from the socket

	// record writes a completed bake into the guard's state.
	record func(st *State, rootKeyID uint64, now time.Time)
	// rootKeyOf reads the key the last credential of this kind was baked under.
	rootKeyOf func(State) uint64
	// bakedAtOf reads when it was last baked, for the repeat-bake guard.
	bakedAtOf func(State) time.Time
	// guardCaveat is P4's `lnd-custom brollyguard` caveat (§6, §14, tna.1).
	//
	// The ONE thing the two credentials' caveat lists differ by, and it is a
	// field here rather than a second list for the reason credentialCaveats
	// gives: two lists are what let the receive macaroon ship unconstrained for
	// the whole of P1. The receive credential must NOT carry it — a custom
	// caveat fails closed, so receiving would stop dead whenever the guard
	// restarted, and zap receiving is what the app is for.
	guardCaveat bool
}

var receiveCredential = credential{
	kind:        "receive",
	file:        lnd.ReceiveMacaroon,
	permissions: ReceivePermissions,
	record: func(st *State, rootKeyID uint64, now time.Time) {
		st.ReceiveRootKeyID = rootKeyID
		st.ReceiveBakedAt = now
	},
	rootKeyOf: func(st State) uint64 { return st.ReceiveRootKeyID },
	bakedAtOf: func(st State) time.Time { return st.ReceiveBakedAt },
}

var spendCredential = credential{
	kind:        "spend",
	file:        lnd.SpendMacaroon,
	permissions: SpendPermissions,
	record: func(st *State, rootKeyID uint64, now time.Time) {
		st.SpendRootKeyID = rootKeyID
		st.SpendBakedAt = now
	},
	rootKeyOf:   func(st State) uint64 { return st.SpendRootKeyID },
	bakedAtOf:   func(st State) time.Time { return st.SpendBakedAt },
	guardCaveat: true,
}

// BakeReceive bakes the receive-only macaroon, constrains it, writes it into
// the credential volume, and revokes the key the previous one was baked under.
//
// The permission list is ReceivePermissions and cannot be influenced from
// outside this package — that is the whole point of the socket API's shape.
func (g *Guard) BakeReceive(ctx context.Context) error {
	return g.bake(ctx, receiveCredential, "asked for")
}

// bake does the work for either credential, carrying WHY it is baking so the
// reason reaches the durable trail rather than only a log line the guard's
// stdout will rotate away (§12, d46.18).
func (g *Guard) bake(ctx context.Context, c credential, reason string) error {
	// Serialises baking, and excludes RevokeSpend as well. Two reasons, and the
	// second is the sharper one: this composes state.load() with a later
	// state.update(), which is exactly what stateStore's own doc comment says a
	// caller must never do; and a revoke interleaved with a bake could delete
	// the key of the credential the bake has just written, leaving a live file
	// nothing honours.
	g.bakeMu.Lock()
	defer g.bakeMu.Unlock()
	now := g.rotation.clock()
	previous, err := g.state.load()
	if err != nil {
		return err
	}

	// A bake that would produce the credential already on disk is refused.
	//
	// Without this the loop is unbounded: an ipaddr the node does not agree with
	// makes every RPC fail, something asks for a re-bake, and the guard bakes
	// the SAME wrong caveat from the same static config every time. Each attempt
	// creates a root key on the node and writes macaroon.bake and
	// macaroon.revoke rows — against a 10,000-row trail, which erases the
	// evidence needed to diagnose it. Re-baking cannot fix a caveat that is
	// wrong in configuration, so it must not keep trying.
	if err := g.wouldRepeatItself(ctx, c, previous, now); err != nil {
		// Through the auditor, so it reaches audit_events and the Security page
		// (§12, d46.18) rather than only the guard's stdout, which log rotation
		// erases. This is the one message that names the actual cause when the
		// node will not accept a credential the guard believes is correct, and
		// the operator otherwise sees "most likely rotated", which is wrong.
		g.audit(ctx, slog.LevelWarn, "not re-baking the "+c.kind+" macaroon",
			logging.EventPreflightRefuse, map[string]string{"reason": err.Error()})
		return err
	}

	// Its own root key, so revoking this credential does not take every other
	// app's — or the other credential's — with it (§6, d46.26). Distinct between
	// the two BY CONSTRUCTION: newRootKeyID reads the node's ListMacaroonIDs,
	// which already lists the other one, so the collision retry treats it as
	// taken.
	rootKeyID, err := g.newRootKeyID(ctx)
	if err != nil {
		return g.observe(ctx, err)
	}
	// Recorded BEFORE the node is asked. BakeMacaroon creates a root key in the
	// operator's macaroons.db, and anything that failed between that call and
	// the state write would leave a live key the guard has no record of and can
	// therefore never revoke — once an hour, for ever, on a box whose only
	// symptom is "not linked yet".
	if err := g.state.update(func(st *State) {
		st.PendingRootKeyIDs = append(st.PendingRootKeyIDs, rootKeyID)
	}); err != nil {
		return err
	}
	macaroon, err := g.node.BakeMacaroon(ctx, lnd.URIPermissions(c.permissions), rootKeyID)
	if err != nil {
		return g.observe(ctx, fmt.Errorf("guard: baking the %s macaroon: %w", c.kind, err))
	}
	g.observe(ctx, nil) //nolint:errcheck // nil in, nil out; this records the success

	expiry := now.Add(CredentialLifetime)
	caveats, err := g.credentialCaveats(c, expiry)
	if err != nil {
		return err
	}
	if macaroon, err = lnd.AddCaveats(macaroon, caveats); err != nil {
		return err
	}
	if err := VerifyBaked(c.kind, c.guardCaveat, macaroon); err != nil {
		return err
	}
	// And that the caveats say what they were meant to say. The names are the
	// easy half; a wrong address or an unparseable time is what the node
	// actually rejects — and d24.7 measured that a macaroon locked to the wrong
	// container satisfies every name-level check and fails only at LND.
	if err := lnd.RequireCaveatValues(macaroon, g.ipCaveatValue(), expiry); err != nil {
		return fmt.Errorf("guard: the %s macaroon failed verification: %w", c.kind, err)
	}
	if err := WriteCredential(g.credentialPath(c.file), macaroon, 0o600); err != nil {
		return err
	}
	// ONE state write records the new key and remembers the old one.
	//
	// The OLD key becoming PENDING is what makes it revocable later (tna.5 G3).
	// It used to be revoked a few lines below with its return value discarded —
	// the very bool d24.10 added so a failed revocation keeps the id for a later
	// sweep, and which is honoured at the sweepPending call below. The state had
	// already been rewritten to name the NEW key, so the previous id existed
	// nowhere: one failed DeleteMacaroonID, or a `docker stop` landing between
	// the state write and the call, left a spend-capable key live at the node
	// with NO RECORD ANYWHERE. The guard cannot revoke what it cannot name, and a
	// later "Disable sending" then audits "the node deleted the root key" as
	// success while the older key is still honoured.
	//
	// SAME WRITE, not a second one, because a crash between two writes is the
	// window this is closing. It is the invariant already written beside the new
	// key — RECORD BEFORE MINT, SO NOTHING IS FORGOTTEN — applied to the old one.
	// The sweep below revokes it with keep-on-failure semantics, so the common
	// case is unchanged: one bake, one revocation, and the id gone from the state
	// by the end of the same call.
	previousKey := c.rootKeyOf(previous)
	if err := g.state.update(func(st *State) {
		c.record(st, rootKeyID, now)
		if previousKey != 0 && previousKey != rootKeyID &&
			!slices.Contains(st.PendingRootKeyIDs, previousKey) {
			st.PendingRootKeyIDs = append(st.PendingRootKeyIDs, previousKey)
		}
		// And the key just recorded as CURRENT is never left pending: the sweep
		// would take the running install's own credential out from under it.
		st.PendingRootKeyIDs = slices.DeleteFunc(st.PendingRootKeyIDs,
			func(id uint64) bool { return id == rootKeyID })
	}); err != nil {
		return err
	}
	g.audit(ctx, slog.LevelInfo, c.kind+" macaroon baked", logging.EventMacaroonBake,
		map[string]string{
			"permissions": strconv.Itoa(len(c.permissions)),
			// The caveats in full, values included: an IP and an expiry are not
			// secrets, and an operator reading the Security page wants to know
			// WHAT the credential is locked to, not merely that it is locked.
			// The root key id is NOT here: it is the kill switch's target.
			"caveats": strings.Join(caveats, ", "),
			"reason":  reason,
		})

	// Every key an earlier attempt created and never recorded as current, plus
	// the one just superseded.
	// They may have been the other credential's attempts; either way they are
	// keys this guard made and nothing is using. All of them, because a bake
	// that failed after BakeMacaroon leaves one behind and the next bake is the
	// only thing that will ever look.
	kept := g.sweepPending(ctx, c.kind, append(previous.PendingRootKeyIDs, previousKey), rootKeyID)
	if err := g.state.update(func(st *State) {
		st.PendingRootKeyIDs = slices.DeleteFunc(st.PendingRootKeyIDs, func(id uint64) bool {
			return id != rootKeyID && !slices.Contains(kept, id)
		})
	}); err != nil {
		g.log.Warn("could not forget the swept pending root keys", "error", err.Error())
	}
	return nil
}

// wouldRepeatItself refuses a bake that cannot change anything.
//
// The credential on disk already meets the policy and was baked recently, so
// the only thing another bake produces is a fresh root key on the node and two
// more audit rows. Something outside this guard's knowledge is wrong — most
// likely the address LND observes is not the one configuration says to lock to —
// and that is a state for the operator to see, not a loop to run.
//
// BOTH credentials, from d24.1. It was written for the receive path, where the
// server re-asks once a minute; the spend path has no such fast retry today,
// but the hourly renewal is enough to create a root key an hour, for ever, on a
// misconfigured install with sending enabled. It takes the state the caller has
// already read rather than loading it again.
func (g *Guard) wouldRepeatItself(ctx context.Context, c credential, state State, now time.Time) error {
	bakedAt := c.bakedAtOf(state)
	if bakedAt.IsZero() || now.Sub(bakedAt) >= MinBakeInterval {
		return nil
	}
	if g.credentialNeedsBaking(c, c.rootKeyOf(state)) != nil {
		return nil // it does not meet the policy, so a bake genuinely differs
	}
	// The one signal that distinguishes the two reasons a node rejects our
	// credential. If it no longer lists our root key, the node's macaroons were
	// rotated and a re-bake is exactly the recovery §6 describes — refusing
	// would turn a 30-second repair into a 30-minute one. If it DOES still list
	// the key, the key is fine and the rejection is about the connection, which
	// a fresh macaroon carrying the same caveats cannot fix.
	ids, err := g.node.ListMacaroonIDs(ctx)
	if err != nil {
		return nil // cannot tell, so do not refuse
	}
	if !slices.Contains(ids, c.rootKeyOf(state)) {
		return nil
	}
	return fmt.Errorf("the %s credential on disk already meets the policy, was baked %s ago, and "+
		"the node still honours its root key; re-baking would produce the same caveats. If the "+
		"node is rejecting it, the address it observes is not %s",
		c.kind, now.Sub(bakedAt).Round(time.Second), g.ipCaveatValue())
}

// ipCaveatValue is the address this build locks credentials to.
func (g *Guard) ipCaveatValue() string {
	switch {
	case g.serverIP.IsValid():
		return g.serverIP.String()
	case g.networkCIDR.IsValid():
		return g.networkCIDR.String()
	default:
		return ""
	}
}

// sweepPending revokes every orphaned root key and returns the ones that are
// STILL THERE.
//
// One function for both sweep sites — the end of a bake, and RevokeSpend —
// because they had grown opposite polarities, one accumulating the keys that
// were gone and the other the keys that were kept. An inversion in either is
// silent and produces exactly the d24.10 bug this replaced: a live root key
// with no record of it anywhere.
func (g *Guard) sweepPending(ctx context.Context, kind string, ids []uint64, current uint64) []uint64 {
	var kept []uint64
	for _, orphan := range ids {
		if !g.revokePrevious(ctx, kind, orphan, current) {
			kept = append(kept, orphan)
		}
	}
	return kept
}

// revokePrevious deletes the root key an earlier credential was baked under.
//
// Best-effort: the new credential is already written and working, and a node
// that will not delete an old key is a state the Security page can show — not a
// reason to fail a bake that succeeded.
//
// ONE function for both credentials, parameterised by kind. Two would be two
// places for the ordering rule to drift, which is the mistake §6 records about
// the caveat lists.
//
// It reports whether the key is GONE from the node — which is not the same as
// "we deleted it" (d24.10). Nothing to revoke, and a key the node was no longer
// listing, both count as gone; only an error does not. The callers that sweep
// PendingRootKeyIDs keep the ids this returns false for, because forgetting a
// key whose revocation FAILED leaves it live at the node with no record
// anywhere — the exact failure that field exists to prevent, reintroduced by
// the code that tidies it.
func (g *Guard) revokePrevious(ctx context.Context, kind string, previous, current uint64) bool {
	if previous == 0 || previous == current {
		return true // nothing of ours is left honouring it
	}
	deleted, err := g.node.DeleteMacaroonID(ctx, previous)
	if err != nil {
		g.log.Warn("could not revoke the previous root key; a stolen copy of the old "+
			"credential stays valid until it expires, and the id is kept so a later sweep "+
			"can try again", "kind", kind, "error", err.Error())
		return false
	}
	if !deleted {
		// The node is not listing it. Nothing more to do about it, ever.
		g.log.Warn("the node did not delete the previous root key; it was not listing it",
			"kind", kind)
		return true
	}
	g.audit(ctx, slog.LevelInfo, "previous "+kind+" macaroon revoked",
		logging.EventMacaroonRevoke, nil)
	return true
}

// EnsureReceiveMacaroon bakes the receive macaroon when the credential volume
// has none, or when the one it has no longer meets §6's policy.
//
// §19's gate says normal setup must not require one-off commands, so a fresh
// install links itself on the guard's first start. Conformance is checked for
// the same reason in reverse: an install that upgraded from a build which baked
// UNCONSTRAINED credentials would otherwise keep using one forever, because a
// file was present and nothing looked at what was in it (d46.26).
func (g *Guard) EnsureReceiveMacaroon(ctx context.Context) error {
	why := g.receiveMacaroonNeedsBaking()
	if why == nil {
		// Everything above is a property of the FILE, and after a macaroon
		// rotation all of it still holds: present, hardened, baked under a real
		// root key, unexpired — and useless, because the node has forgotten the
		// key. The guard exits on rotation precisely so the restart can
		// re-link, and without this it came back, said "already present and
		// within policy", and waited 39 seconds for the server to ask (as0.7).
		if state, err := g.state.load(); err == nil && g.nodeForgotReceiveKey(ctx, state.ReceiveRootKeyID) {
			why = errors.New("the node no longer lists the root key it was baked under")
		}
	}
	if why == nil {
		g.log.Info("receive macaroon already present and within policy")
		return nil
	}
	g.log.Info("baking the receive macaroon", "reason", why.Error())
	return g.bake(ctx, receiveCredential, why.Error())
}

// receiveMacaroonNeedsBaking says why the stored credential will not do, or nil
// when it will.
//
// An error rather than a (string, bool): the bool was derivable from the string,
// and this composes with lnd.RequireHardening, which already returns one.
func (g *Guard) receiveMacaroonNeedsBaking() error {
	state, err := g.state.load()
	if err != nil {
		return errors.New("the guard's state could not be read")
	}
	return g.credentialNeedsBaking(receiveCredential, state.ReceiveRootKeyID)
}

// lacksGuardCaveat is "this credential is obsolete for this version", said once.
//
// Two callers ask it moments apart — credentialNeedsBaking, deciding whether a
// bake would differ, and spendCredentialIsObsolete, deciding whether Ruling 1
// applies — and they had two copies of the predicate. That is the d46.26 shape
// the comments around here claim to have removed: a second condition would move
// one copy and not the other.
func lacksGuardCaveat(c credential, raw []byte) bool {
	return c.guardCaveat && !lnd.HasGuardCaveat(raw)
}

// credentialNeedsBaking is that policy for EITHER credential.
//
// One function, like credentialCaveats: "presence is not conformance" is a rule
// about baked credentials, not about the receive one, and a second copy is how
// the spend credential would quietly acquire a weaker version of it.
func (g *Guard) credentialNeedsBaking(c credential, rootKeyID uint64) error {
	raw, err := os.ReadFile(g.credentialPath(c.file))
	if err != nil || len(raw) == 0 {
		return errors.New("there is none")
	}
	if err := lnd.RequireHardening(raw); err != nil {
		// The upgrade path from a build that baked no caveats at all.
		return err
	}
	if lacksGuardCaveat(c, raw) {
		// The upgrade path from a build BEFORE P4: a spend credential LND will
		// honour without ever consulting the guard, so the hard cap does not
		// apply to it (tna.1 Ruling 1).
		return errors.New("it carries no " + lnd.GuardCaveatName + " caveat, so payments made " +
			"with it would not be counted against the spend limit")
	}
	if rootKeyID == 0 {
		// Baked under LND's default key, so it cannot be revoked without taking
		// every other app's credentials with it.
		return errors.New("it is baked under the node's default root key")
	}
	expiry, ok := lnd.Expiry(raw)
	if !ok {
		return errors.New("its expiry cannot be read")
	}
	if !g.rotation.clock().Add(RenewBefore).Before(expiry) {
		return fmt.Errorf("it expires within %s", RenewBefore)
	}
	return nil
}

// nodeForgotReceiveKey reports whether the node has stopped listing the root
// key the stored credential was baked under (as0.7).
//
// Kept OUT of receiveMacaroonNeedsBaking, which reads only local state. Asking here means one caller, one round trip, and the
// disposition on "cannot tell" is visible at the call site rather than buried
// in a helper — which matters, because the two callers that ask this question
// need opposite answers when the node is unreachable.
//
// FALSE when the node cannot be reached. Unknown is not rotated: treating an
// outage as "the key is gone" would re-bake on every blip, and each bake is a
// fresh root key on the operator's node plus two audit rows — the storm Wave
// 9's circuit-breaker exists to prevent.
func (g *Guard) nodeForgotReceiveKey(ctx context.Context, rootKeyID uint64) bool {
	if rootKeyID == 0 {
		return false
	}
	ids, err := g.node.ListMacaroonIDs(ctx)
	if err != nil {
		g.observe(ctx, err) //nolint:errcheck // arms the prober; the value here does not matter
		g.log.Warn("could not ask the node which root keys it honours; leaving the credential "+
			"alone", "error", err.Error())
		return false
	}
	g.observe(ctx, nil) //nolint:errcheck // nil in, nil out; this records the success
	return !slices.Contains(ids, rootKeyID)
}

// Status is everything the server may learn about its own credentials. Anything
// needing macaroon:read is answered here, because the server's own macaroons do
// not have it, by design (§6).
func (g *Guard) Status(ctx context.Context) (Status, error) {
	state, err := g.state.load()
	if err != nil {
		return Status{}, err
	}
	status := Status{
		ReceiveMacaroonPresent: g.credentialExists(lnd.ReceiveMacaroon),
		SpendMacaroonPresent:   g.credentialExists(lnd.SpendMacaroon),
		// From the CREDENTIAL, not the state file. WriteCredential precedes the
		// state update, so a failed update would leave the state naming an
		// expiry for a credential that has already been replaced — and the
		// macaroon on disk is the thing LND will actually judge.
		ReceiveExpiry: credentialExpiry(g.credentialPath(lnd.ReceiveMacaroon)),
		// Likewise, and for the same reason: after a revocation the file is gone
		// while a failed state write could still name an expiry, and the server
		// would read that as sending still being on.
		SpendExpiry: credentialExpiry(g.credentialPath(lnd.SpendMacaroon)),
		// Straight from the guard's own configuration and its own store, so the
		// page and the enforcement have ONE source (tna.4, `06v`).
		SendingPermitted:           g.sendingPermitted(state),
		SendingAllowedByDeployment: g.allowSending,
		SendingLatched:             state.SendingLatch,
		AuthorisationLocation:      g.operatorAuthorisationLocation(),
		MaxPaymentMsat:             state.MaxPaymentMsat,
		// From the middleware goroutine, which is the only thing that knows
		// whether LND accepted the registration (tna.1).
		MiddlewareRegistered: g.middlewareUp.Load(),
		// From the state ALREADY LOADED above, not a second read of the same
		// file: two loads could straddle a concurrent update and report a used
		// total against a limit from a different version of the state.
		SpendUsedMsat:  spendUsedIn(state, g.rotation.clock()),
		SpendLimitMsat: state.MaxSpendMsat,
	}
	// The pending grant, WITHOUT its code. The server is told that one exists,
	// what it is for and when it dies, so the page can ask for it — and is told
	// nothing that would let it redeem one (`06v`, Ruling 3).
	if a := state.Authorisation; a != nil && !a.expired(g.rotation.clock()) {
		status.AuthorisationPending = true
		status.AuthorisationExpiresAt = a.ExpiresAt
		status.AuthorisationChange = a.Change.describe()
		status.AuthorisationControl = string(a.Change.Control)
		status.AuthorisationMsat = a.Change.Msat
	}
	// Reachability is a report, not an error: a node that is down is a state the
	// admin UI shows, not a failure the server has to interpret (§11).
	if _, err := g.node.GetInfo(ctx); err != nil {
		g.observe(ctx, err)
	} else {
		g.observe(ctx, nil)
		status.LNDReachable = true
		if state.SpendRootKeyID != 0 {
			status.SpendRootKeyRecorded = true
			if ids, err := g.node.ListMacaroonIDs(ctx); err == nil {
				status.SpendRootKeyChecked = true
				status.SpendRootKeyListed = slices.Contains(ids, state.SpendRootKeyID)
			}
		}
	}
	return status, nil
}

// credentialExpiry reads the time-before caveat off a credential on disk.
func credentialExpiry(path string) time.Time {
	raw, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}
	expiry, _ := lnd.Expiry(raw)
	return expiry
}

func (g *Guard) credentialExists(name string) bool {
	return credentialFileExists(g.credentialPath(name))
}

// credentialFileExists is the same question asked of a path rather than of a
// guard, because the state store's migration has to ask it before a Guard
// exists — see operatorSeed.
func credentialFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

// Handle dispatches one request. It is the only entry point the socket exposes.
//
// Every answer carries the guard's recent security events back with it, whether
// the operation succeeded or not. That is not a fifth operation: the request
// still says nothing but which of the four to run (§6), and the server is being
// told something rather than asking for it (§12, d46.18).
func (g *Guard) Handle(ctx context.Context, req Request) Response {
	resp := g.dispatch(ctx, req)
	resp.Events = g.recentAuditEvents()
	return resp
}

func (g *Guard) dispatch(ctx context.Context, req Request) Response {
	switch req.Op {
	case OpStatus:
		status, err := g.Status(ctx)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Status: &status}
	case OpBakeReceive:
		if err := g.BakeReceive(ctx); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case OpBakeSpend:
		if err := g.BakeSpend(ctx); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case OpRevokeSpend:
		if err := g.RevokeSpend(ctx); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case OpRequestAuthorisation:
		if req.Change == nil {
			return Response{Error: "guard: request_authorisation carried no change"}
		}
		if err := g.RequestAuthorisation(ctx, *req.Change); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case OpApplyChange:
		if req.Change == nil {
			return Response{Error: "guard: apply_change carried no change"}
		}
		if err := g.ApplyChange(ctx, *req.Change, req.Code); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	default:
		return Response{Error: fmt.Sprintf("guard: unknown operation %q", req.Op)}
	}
}

// observe feeds the rotation detector. A run of authentication failures against
// admin.macaroon means the node's macaroons were rotated, and a single-file
// bind mount follows the inode — so no amount of retrying inside this process
// will ever see the replacement (§6).
func (g *Guard) observe(ctx context.Context, err error) error {
	if err == nil {
		g.rotation.Success()
		return nil
	}
	if !lnd.IsAuthFailure(err) {
		return err
	}
	// Whatever noticed, the guard now starts watching for ITSELF (as0.8) — and
	// this observation arms the loop without advancing it. Only the guard's own
	// probes count toward the threshold, because a caller must not be able to
	// push the guard toward its own exit: Re-link has no rate limit, and
	// clicking it is exactly what an operator does while the node is rejecting.
	g.rotation.Rejected()
	g.log.Warn("lnd rejected admin.macaroon", "error", err.Error())
	return err
}

// observeProbe is observe for the guard's OWN samples: the only observations
// that advance the run toward §6's threshold.
func (g *Guard) observeProbe(ctx context.Context, err error) {
	if err == nil {
		g.rotation.Success()
		return
	}
	if !lnd.IsAuthFailure(err) {
		// The node did not answer, so the credential was never tested. Not a
		// rejection, and deliberately not counted: unreachable means unknown.
		return
	}
	if !g.rotation.ProbeFailed() {
		return
	}
	g.audit(ctx, slog.LevelWarn, "lnd rejected admin.macaroon repeatedly; the node's macaroons "+
		"look rotated. exiting so the container restart re-resolves the bind mount",
		logging.EventMacaroonRotate, nil)
	g.declareRotated()
}

// probeRotation samples LND on the guard's OWN clock, so the rotation decision
// stops depending on how often something else happens to call in (as0.8, §6).
//
// It wakes every ProbeInterval and asks GetInfo only while a rejection is
// outstanding. Three consecutive rejected probes trip the detector; any success
// clears the run, which is the CONTINUITY that replaced the old window's
// density requirement as the false-positive protection.
//
// A node that does not answer at all is neither: the credential was never
// tested, so the sample is not counted and the loop keeps asking. Unreachable
// means unknown, and unknown must not mean rotated.
//
// The detector holds "is a rejection outstanding", so there is no second copy of
// that state here. An earlier version carried a signal channel and had to drain
// it after each run — which could discard a genuine rejection that arrived in
// the window between the last probe and the drain.
func (g *Guard) probeRotation(ctx context.Context) {
	// Its OWN timer, not the injected sleep. That hook is the rotation exit
	// delay, and at the §6 defaults the two durations are both ten seconds — so
	// sharing it made the two waits indistinguishable to a test, and the test
	// that asserts the exit was delayed had to be weakened to "one of these
	// durations matched". Separate timers, exact assertion.
	ticker := time.NewTicker(g.probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !g.rotation.Armed() {
			continue
		}
		_, err := g.node.GetInfo(ctx)
		g.observeProbe(ctx, err)
		if err == nil {
			g.log.Info("lnd is answering again; the credential was not rotated after all")
			continue
		}
		select {
		case <-g.rotated:
			// Already declared. Stop, or every further probe re-raises the
			// audit event for a decision that has been taken.
			return
		default:
		}
	}
}

func (g *Guard) declareRotated() {
	select {
	case <-g.rotated:
	default:
		close(g.rotated)
	}
}

// VerifyBaked asserts a freshly baked macaroon is what was asked for AND that it
// meets §6's policy, before it is written anywhere.
//
// §11 calls this the check that matters most. The point is not that baking
// usually fails — it is that when it silently stops applying caveats, nothing
// else notices: the macaroon works, the page is green, and the credential is
// unconstrained. Parsing is also what catches a node answering with something
// that is not a macaroon at all.
func VerifyBaked(kind string, guardCaveat bool, raw []byte) error {
	// The POLICY, not the list this particular bake happened to ask for.
	// Checking a credential against conditions we just chose ourselves passes
	// vacuously when we choose none — which is precisely how the receive
	// macaroon shipped unconstrained for the whole of P1 (d46.26).
	if err := lnd.RequireHardening(raw); err != nil {
		return fmt.Errorf("guard: the %s macaroon failed verification: %w", kind, err)
	}
	// And P4's caveat on the credential that carries it. Checked here rather
	// than trusted from the list this bake asked for, for the reason above: a
	// bake that quietly stopped asking would produce a credential LND accepts
	// WITHOUT consulting the guard, and every indicator would read green while
	// the hard cap applied to nothing (§14, tna.1).
	if guardCaveat && !lnd.HasGuardCaveat(raw) {
		return fmt.Errorf("guard: the %s macaroon carries no %s caveat, so LND would perform "+
			"payments with it without asking the guard", kind, lnd.GuardCaveatName)
	}
	return nil
}
