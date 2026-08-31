package guard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// BakeSpend bakes the spend macaroon, constrains it, writes it into the
// credential volume, and revokes the key the previous one was baked under.
//
// This is "Enable sending". It goes through the SAME bake as the receive
// credential — see Guard.bake and the credential type — because the two differ
// in their permission list and in nothing else. Two bake paths are what let the
// receive macaroon ship unconstrained for the whole of P1 (§6, d46.26).
//
// SpendPermissions cannot be influenced from outside this package. The request
// carries the operation and nothing else: a compromised server may ask for the
// spend macaroon it is already allowed to have, and can obtain nothing broader.
func (g *Guard) BakeSpend(ctx context.Context) error {
	state, err := g.state.load()
	if err != nil {
		return err
	}
	if err := g.refuseUnlessSendingIsPermitted(ctx, OpBakeSpend, state); err != nil {
		return err
	}
	return g.bake(ctx, spendCredential, "asked for")
}

// refuseUnlessSendingIsPermitted is tna.4's gate, reshaped by `06v` Ruling 4.
//
// IT IS NOW A CONJUNCTION of the deployment ceiling and the operator's stored
// latch — see Guard.sendingPermitted. GUARD_ALLOW_SENDING defaults to TRUE now,
// because `06v` established it was unreachable by any supported means on
// umbrelOS and a false default therefore shipped sending permanently
// unavailable. §6's receive-only default is preserved by the LATCH, which is off
// on a fresh install and can only be turned on through the operator's ceremony.
//
// WHAT IT REPLACES: nothing. `dispatch` mapped OpBakeSpend straight through to
// bake, whose only refusal — wouldRepeatItself — returns nil whenever nothing
// has been baked yet, so on a receive-only install it could never refuse. The
// whole of the access control was the socket's 0600 mode, and the server runs as
// the same uid: code execution in the server meant writing one line to
// /credentials/guard.sock, reading the macaroon the guard wrote, and dialling
// LND with spend authority.
//
// THE CHANNEL IS THE POINT. This reads the GUARD's environment, which the server
// has no way to write — the same precedent §6 sets for the hard cap. A flag in
// the server's database or its own environment would be a lock whose key is kept
// in the room it locks.
//
// BEFORE THE NODE IS ASKED. A refusal that returned an error after BakeMacaroon
// would leave a spend-capable root key on the operator's node, which is most of
// the damage; the assertion in the test is about what the node saw, not about
// what was returned.
//
// AUDITED, because an attempt to mint spend authority on an install whose
// operator has not permitted it is the loudest thing this guard can observe. It
// goes through the guard's own auditor — §16 gives it no mount for the server's
// database — so the row reaches §12's trail with the rest.
func (g *Guard) refuseUnlessSendingIsPermitted(ctx context.Context, op Op, state State) error {
	if g.sendingPermitted(state) {
		return nil
	}
	// TWO REFUSALS, TWO REMEDIES, and they must not share wording — the same
	// rule tna.4 set for the Sending page's two off-states, one layer down. One
	// is fixable by the operator in the app; the other is not fixable in the app
	// at all, and telling an operator to perform a ceremony that cannot work is
	// how they learn the app is broken rather than that it is locked.
	reason, remedy := "the operator has not enabled sending on this install",
		"enable sending on the Sending page, which needs the authorisation the guard writes"
	if !g.allowSending {
		reason = "this deployment does not permit sending at all"
		remedy = "GUARD_ALLOW_SENDING is false in the guard's environment; only whoever " +
			"deploys this app can change that, and no in-app action will"
	}
	if !g.auditReject(ctx) {
		g.log.Warn("refused to mint spend authority; past this hour's audit bound, so this one " +
			"is logged only")
		return errors.New("guard: " + reason + "; " + remedy)
	}
	g.audit(ctx, slog.LevelWarn, "refused to mint spend authority; "+reason,
		logging.EventGuardReject, map[string]string{
			"op": string(op),
			// The remedy, in the trail, because the operator reading this row is
			// being told their app refused something they may have asked for.
			"remedy": remedy,
		})
	return errors.New("guard: " + reason + "; " + remedy)
}

// RevokeSpend is the kill switch: it deletes the root key the guard itself
// recorded at bake time, removes spend.macaroon from the credential volume, and
// clears the state that says sending is on.
//
// It takes no parameter, and that is the security property rather than an
// omission. A caller-supplied root key id would turn this into DeleteMacaroonID
// pointed at any app's key on the box — a destructive cross-app primitive
// hiding inside a safe-looking revocation call (§6).
//
// THE ORDER IS THE DESIGN, and each step's failure is handled differently:
//
//  1. The node first. §6 is explicit that this is a node-side revocation and
//     not a local delete, because it must hold against an attacker who already
//     exfiltrated the macaroon. If the node refuses, NOTHING else happens and
//     the error is returned: reporting "sending disabled" while LND still
//     honours the key is the one lie this operation must never tell, and
//     keeping the credential and the recorded id is what lets a retry finish.
//  2. Then the file. If removing it fails the revocation has still SUCCEEDED —
//     the macaroon on disk is inert once its root key is gone — so this does not
//     fail the call. It is logged, and Status then reports the honest pair
//     (present, not listed) that §6 gives the UI for exactly this.
//  3. Then the state. Last, because a crash between 2 and 3 leaves a dead key
//     named in the state and no file, which Status reads correctly as "off". The
//     other order would leave a file with no recorded key — reachable by the
//     server and revocable by nobody.
func (g *Guard) RevokeSpend(ctx context.Context) error {
	// The bake lock, so a revoke cannot land between a bake's write and its
	// state update — which would clear the fields naming a credential that is
	// about to be written, leaving sending silently on.
	g.bakeMu.Lock()
	defer g.bakeMu.Unlock()

	state, err := g.state.load()
	if err != nil {
		return err
	}

	if !state.sendingEnabled() {
		// THE PENDING SWEEP RUNS ON BOTH OF THESE PATHS (tna.5 G4). They
		// returned before it, so a kill switch pressed while sending was already
		// off — or after the guard's store was lost — left every orphaned
		// spend-capable key live at the node. "Disable sending" is the control an
		// operator reaches for when they are worried, and it has to mean the same
		// thing whichever state it finds.
		kept, err := g.sweepAndForgetSpend(ctx, state.PendingRootKeyIDs)
		if err != nil {
			return err
		}
		// Nothing recorded. Either sending was never enabled — a clean no-op,
		// because "Disable sending" must not fail merely because it is already
		// off — or the guard's own store was lost while a credential remains.
		if !g.credentialExists(lnd.SpendMacaroon) {
			return nil
		}
		// The store was lost. Remove what the server can reach, which is the
		// part the guard CAN still do, and say plainly that the node-side half
		// was impossible: §6 forbids taking the id from the server, so an
		// exfiltrated copy stays valid until its time-before caveat expires.
		// A silent success here would be step 1's lie in a quieter voice.
		if err := g.removeSpendCredential(); err != nil {
			return err
		}
		// Audited BEFORE the return, and before anything else that can fail:
		// this is the loudest thing this function ever has to say, and an
		// earlier version could lose it to an error on the way out.
		//
		// "NO RECORD" ONLY WHEN THERE GENUINELY IS NONE (tna.5 G4). This string
		// is what an operator reads after a suspected compromise, and it used to
		// be said whenever SpendRootKeyID was zero — inaccurate whenever
		// PendingRootKeyIDs held ids. What is true either way is that the
		// credential's OWN key could not be identified; what the guard did with
		// the other ids it held is a second fact, and it reports what the SWEEP
		// ACHIEVED rather than what it attempted, because a node that refused
		// them leaves them live.
		reason := "the guard has no record of the root key it was baked under, so it could " +
			"not be revoked at the node"
		if len(state.PendingRootKeyIDs) > 0 {
			reason = "the guard held no CURRENT root key for this credential, so the key it " +
				"was baked under could not be revoked at the node; " + sweepOutcome(kept)
		}
		g.audit(ctx, slog.LevelWarn, "spend credential removed without a node-side revocation",
			logging.EventMacaroonRevoke, map[string]string{"reason": reason})
		return errors.New("guard: spend.macaroon was removed, but " + reason +
			"; a copy taken before now stays valid until it expires")
	}

	deleted, err := g.node.DeleteMacaroonID(ctx, state.SpendRootKeyID)
	if err != nil {
		return g.observe(ctx, fmt.Errorf("guard: revoking the spend macaroon at the node: %w", err))
	}
	g.observe(ctx, nil) //nolint:errcheck // nil in, nil out; this records the success

	// deleted == false means the node was not listing the key: an earlier revoke
	// got this far, or the node's macaroons were rotated out from under us.
	// Either way the key is gone, which is the outcome asked for — refusing to
	// continue would strand a half-finished revocation for ever.
	if err := g.removeSpendCredential(); err != nil {
		g.log.Warn("the spend root key was revoked at the node, but spend.macaroon could not be "+
			"removed from the credential volume; it is inert, and Status will report it as "+
			"present with its key no longer listed", "error", err.Error())
	}
	// Every key a FAILED spend bake left behind, too. One of those may have been
	// minted by LND under SpendPermissions before the bake failed on its way to
	// disk — a spend-capable key with no credential — and a kill switch that
	// leaves it live is not a kill switch. They are swept here rather than left
	// to the next bake, because after "Disable sending" there may never be one.
	// Sending is off afterwards, so there may never be another bake — which
	// makes this the one sweep that can lose an orphan for good (d24.10). What
	// the node would not revoke is kept, and the next RevokeSpend or BakeSpend
	// tries again.
	if _, err := g.sweepAndForgetSpend(ctx, state.PendingRootKeyIDs); err != nil {
		return err
	}
	g.audit(ctx, slog.LevelInfo, "spend macaroon revoked", logging.EventMacaroonRevoke,
		map[string]string{
			// The outcome, not the id. "already gone" is a materially different
			// event from "we deleted it" and an operator reading the trail after
			// a suspected compromise needs to tell them apart.
			"outcome": revocationOutcome(deleted),
		})
	return nil
}

// sweepOutcome says what the sweep ACHIEVED, not what it attempted.
//
// A node that refused a deletion leaves that key live, and an operator reading
// this row after a suspected compromise is reading it to find out what is still
// out there. "Have been swept" said on ids the node kept would be the same lie
// step 1 refuses to tell, one clause quieter.
func sweepOutcome(kept []uint64) string {
	if len(kept) > 0 {
		return strconv.Itoa(len(kept)) + " of the other ids it did hold could not be revoked " +
			"and are kept for a later sweep"
	}
	return "the other ids it did hold have been revoked at the node"
}

func revocationOutcome(deleted bool) string {
	if deleted {
		return "the node deleted the root key"
	}
	return "the node was no longer listing the root key"
}

func (g *Guard) removeSpendCredential() error {
	if err := os.Remove(g.credentialPath(lnd.SpendMacaroon)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("guard: removing %s: %w", lnd.SpendMacaroon, err)
	}
	return nil
}

// sweepAndForgetSpend revokes every pending id the node will take and then
// forgets the spend credential, keeping the ids it would not.
//
// The three places that end sending — the kill switch's two paths and an
// external revocation — all do exactly this, and they did it in three slightly
// different ways. What is kept is returned so the caller can say so.
func (g *Guard) sweepAndForgetSpend(ctx context.Context, pending []uint64) ([]uint64, error) {
	kept := g.sweepPending(ctx, "spend", pending, 0)
	return kept, g.clearSpendState(kept)
}

// clearSpendState forgets the spend credential, keeping any pending ids the
// node would not revoke.
//
// IT DROPS THE LATCH TOO — "off must latch off" (`06v`, Ruling 1). Every route
// into here is sending ending: the kill switch's two paths, and an external
// revocation the operator made at the node. Leaving the latch on would mean the
// renewal loop finds "the operator wants sending" true with no credential, and
// more importantly that turning sending back on afterwards would need no
// ceremony — so a compromised server could revoke and immediately re-mint,
// laundering a credential it already had into a fresh one under a new key.
//
// The ceremony is the price of the SAFE direction being free. A compromised
// server can turn sending off and the operator must perform a ceremony to
// restore it; that griefing is accepted by Ruling 1 and stated there.
func (g *Guard) clearSpendState(keepPending []uint64) error {
	return g.state.update(func(st *State) {
		st.SpendRootKeyID = 0
		st.SpendBakedAt = time.Time{}
		st.PendingRootKeyIDs = keepPending
		// Through apply for the same reason the seed goes through it: one write
		// site is what the direction check sits in front of, and this is the
		// second writer that would otherwise exist.
		st.apply(Change{Control: ControlSending, On: false})
	})
}

// EnsureSpendMacaroon replaces the spend credential when it is expiring, or
// restores it when the file has gone — but ONLY while sending is enabled.
//
// That last clause is d24.8's one spend-specific rule, and it is the subtlest
// thing in this file. A renewal loop that re-bakes on schedule turns "Disable
// sending" into "Disable sending for up to an hour": the operator revokes,
// walks away, and the guard quietly mints a fresh spend macaroon under a fresh
// key because the old one was expiring. Revoked must stay revoked; an explicit
// BakeSpend is the only thing that turns sending back on.
//
// "Sending is enabled" is read from the GUARD's own store and nowhere else. The
// server cannot be the authority here for the reason §6 gives about the spend
// cap: a compromised server would simply write itself an answer.
func (g *Guard) EnsureSpendMacaroon(ctx context.Context) error {
	state, err := g.state.load()
	if err != nil {
		return err
	}
	// P4's OBSOLETE-CREDENTIAL RULE, and it comes FIRST — before the gate, and
	// before "sending is off" (tna.1 Ruling 1).
	//
	// §14 says a spend macaroon baked without the `lnd-custom brollyguard`
	// caveat is re-baked at the first start after the upgrade. tna.4 changed the
	// ground under that: the gate defaults to false, EnsureSpendMacaroon returns
	// early when it is unset, and it deliberately leaves the credential on disk.
	// On an upgraded install that credential carries no custom caveat, so LND
	// honours it WITHOUT consulting the guard — and P4 would ship with its
	// enforcement inapplicable to exactly the installs that were already
	// sending, while §11's table claims the cap exists.
	//
	// THIS DOES NOT UNDERMINE tna.4's RULING A.4. That ruling refused to destroy
	// on an AMBIGUOUS signal: an Umbrel update restarts containers, so "started
	// with the gate off" is not evidence of operator intent. This signal is not
	// an inference about intent at all — the credential is STRUCTURALLY
	// OBSOLETE, missing a caveat this version requires. The two rules agree:
	// destroy on facts, never on guesses about what a restart meant.
	if g.spendCredentialIsObsolete() {
		return g.replaceOrRevokeObsoleteSpendCredential(ctx, state)
	}
	if !state.sendingEnabled() {
		return nil // sending is off; there is nothing to keep alive
	}
	if !g.sendingPermitted(state) {
		// The gate again, on the OTHER way a spend macaroon gets minted (tna.4).
		// A gate on the socket alone would be a gate on the door with the window
		// open: this loop bakes on a schedule whenever the guard's own state
		// says sending is enabled, and that state survives the operator turning
		// the gate off and restarting.
		//
		// QUIETLY, and NOT a revocation. At DEBUG because it repeats every tick
		// for as long as the condition holds, and the operator's view of it is
		// the Sending page rather than a log they would have to be watching. The
		// credential already on disk is deliberately left alone — see Ruling A.4
		// in tna.4: an Umbrel update restarts containers, so "started with the
		// gate off" is not a reliable signal of operator intent, and a
		// destructive act on an ambiguous signal is worse than a residual stated
		// out loud. Renewal stopping is what ends it, within CredentialLifetime.
		g.log.Debug("not renewing the spend macaroon; this install does not permit sending",
			"deployment_allows", g.allowSending, "operator_latch", state.SendingLatch)
		return nil
	}
	// AN EXTERNAL REVOCATION IS HONOURED, NOT REVERSED (tna.5 G2).
	//
	// The operator revoked the spend root key at the node — over SSH, with
	// lncli, or by rotating the macaroon set. Tier 2 blocks payments within
	// about ten seconds, and then, between an hour and about 4.7 days later,
	// this loop would find the credential expiring, bake a fresh one under a NEW
	// key, and hand the capability back. The operator removed it and the app put
	// it back.
	//
	// It is d24.8's own argument through another channel: that bead gated
	// renewal on "sending is enabled" so Disable sending could not mean "disable
	// sending for up to an hour". What changes here is the DEFINITION of
	// enabled — the recorded key still existing at the node is part of it.
	//
	// THE ASYMMETRY WITH THE RECEIVE SIDE IS THE POINT, and it is a rule rather
	// than an inconsistency:
	//
	//	Self-heal may restore capability the operator never removed, and must
	//	never restore capability the operator removed.
	//
	// EnsureReceiveMacaroon reads the identical signal — the node no longer
	// lists our key — as a fault to HEAL, and re-links (as0.7). Receiving is
	// what the app is for and nobody revokes it as a safety measure. Spending is
	// the capability an operator takes away when they are worried, so the same
	// evidence has to mean the opposite thing.
	//
	// §6's "the guard reads sending state from its own store and from nowhere
	// else" is not weakened: that sentence justifies itself "for the same reason
	// the hard cap is not read from the server's database" — it is about not
	// trusting the UNTRUSTED CONTAINER. LND is not the server, the guard already
	// holds admin.macaroon and already asks this same question on the receive
	// path, and the node is the only authority on which keys it honours.
	if g.nodeForgotSpendKey(ctx, state.SpendRootKeyID) {
		return g.acceptExternalRevocation(ctx, state.SpendRootKeyID)
	}
	why := g.credentialNeedsBaking(spendCredential, state.SpendRootKeyID)
	if why == nil {
		return nil
	}
	g.log.Info("baking the spend macaroon", "reason", why.Error())
	return g.bake(ctx, spendCredential, why.Error())
}

// spendCredentialIsObsolete reports whether a spend credential exists that this
// version cannot enforce against: one with no `lnd-custom brollyguard` caveat.
//
// A credential that is ABSENT is not obsolete — there is nothing to fix, and
// treating "none" as "obsolete" would make a receive-only install revoke a
// credential it does not have on every tick.
func (g *Guard) spendCredentialIsObsolete() bool {
	raw, err := os.ReadFile(g.credentialPath(spendCredential.file))
	if err != nil || len(raw) == 0 {
		return false
	}
	return lacksGuardCaveat(spendCredential, raw)
}

// replaceOrRevokeObsoleteSpendCredential is Ruling 1's two arms, and it FAILS
// CLOSED.
//
// Permitted: re-bake, which produces a credential carrying the caveat, so LND
// routes its payments through the guard from the next one on. The bake's own
// wouldRepeatItself does not block it — credentialNeedsBaking now reports a
// missing guard caveat, so a re-bake genuinely differs from what is on disk.
//
// Not permitted: REVOKE. Leaving it would be the one state where a spend
// macaroon is live and the cap does not apply to it, on an install whose
// operator has not permitted sending in the first place. RevokeSpend is the
// whole kill switch — node-side deletion, the file, the state — which is what
// makes the residual actually end rather than merely stop being renewed.
func (g *Guard) replaceOrRevokeObsoleteSpendCredential(ctx context.Context, state State) error {
	if g.sendingPermitted(state) {
		g.log.Warn("the spend macaroon predates this version's guard enforcement; re-baking it " +
			"so payments made with it are counted against the spend limit")
		return g.bake(ctx, spendCredential, "it carries no "+lnd.GuardCaveatName+" caveat")
	}
	g.audit(ctx, slog.LevelWarn, "revoking a spend macaroon this version cannot enforce against",
		logging.EventMacaroonRevoke, map[string]string{
			"reason": "it carries no " + lnd.GuardCaveatName + " caveat, so payments made with " +
				"it would not be counted against the spend limit, and this install does not " +
				"permit sending, so it cannot be re-baked",
			"remedy": "enable sending again on the Sending page; on a deployment that sets " +
				"GUARD_ALLOW_SENDING=false, nothing in the app can",
		})
	if err := g.RevokeSpend(ctx); err != nil {
		return fmt.Errorf("guard: revoking a spend macaroon with no %s caveat: %w",
			lnd.GuardCaveatName, err)
	}
	return nil
}

// nodeForgotSpendKey is nodeForgotReceiveKey's spend-side twin, and it answers
// the same question with the same disposition on "cannot tell".
//
// FALSE when the node cannot be reached, which is the arm that must not
// over-fire. Unknown is not revoked: reading an outage as an external revocation
// would tear a working install down every time the node blipped — and unlike the
// receive side, where the cost of guessing wrong is an extra bake, here it is
// destructive.
//
// A separate function from the receive one rather than a shared helper with a
// flag, because the two CALLERS want opposite things from the same answer and a
// parameterised helper would put that decision one level away from where it is
// made.
func (g *Guard) nodeForgotSpendKey(ctx context.Context, rootKeyID uint64) bool {
	if rootKeyID == 0 {
		// The caller's sendingEnabled() already implies this — it IS
		// SpendRootKeyID != 0 — so this arm is unreachable today. It stays
		// because without it "no key recorded" answers TRUE (the node does not
		// list zero) and the answer is acted on destructively; the receive twin
		// carries the same line for the same reason.
		return false
	}
	ids, err := g.node.ListMacaroonIDs(ctx)
	if err != nil {
		g.observe(ctx, err) //nolint:errcheck // arms the prober; the value here does not matter
		g.log.Warn("could not ask the node whether it still honours the spend root key; "+
			"leaving the credential alone", "error", err.Error())
		return false
	}
	g.observe(ctx, nil) //nolint:errcheck // nil in, nil out; this records the success
	return !slices.Contains(ids, rootKeyID)
}

// acceptExternalRevocation clears the spend state to match what the node says.
//
// No DeleteMacaroonID: the key is already gone, which is what brought us here.
// The credential file goes because it is inert and leaving it would make Status
// — and therefore the Sending page — report a spend macaroon that is present and
// ready. The pending ids are swept on the way, since this is the last moment
// anything will look at them: sending is off afterwards and there may never be
// another bake.
//
// UNDER THE BAKE LOCK, AND ON A FRESH READ, because this is the one destructive
// thing the renewal loop does and it decided to do it from a snapshot taken
// before a round trip to the node. RunRenewal and Serve are separate goroutines
// (cmd/brollyguard), so a socket BakeSpend can land inside that window: without
// this, its fresh credential would be deleted and its just-recorded root key
// erased from BOTH SpendRootKeyID and PendingRootKeyIDs — a live spend-capable
// key at the node with no record anywhere, which is precisely the failure G3
// exists to prevent, reintroduced by G2. `-race` cannot see it; stateStore has
// its own mutex, so it is a lost update rather than a data race.
//
// If the recorded key has MOVED, this answer is about a key that is no longer
// the current one and is dropped: the node was asked about a key this guard has
// since replaced, and the next tick asks again about the new one.
func (g *Guard) acceptExternalRevocation(ctx context.Context, forgotten uint64) error {
	g.bakeMu.Lock()
	defer g.bakeMu.Unlock()

	state, err := g.state.load()
	if err != nil {
		return err
	}
	if state.SpendRootKeyID != forgotten {
		g.log.Info("the spend root key changed while the node was being asked about the old " +
			"one; leaving it to the next renewal")
		return nil
	}

	g.log.Warn("the node no longer honours the spend root key; treating it as a revocation the " +
		"operator made and not re-baking")
	// Not fatal, and the same rule RevokeSpend states at step 2: the file is
	// inert once its root key is gone, so a failure to remove it must not stop
	// the state from being cleared — which is what stops the renewal loop from
	// re-baking, and what makes the page tell the truth.
	if err := g.removeSpendCredential(); err != nil {
		g.log.Warn("the spend root key is gone from the node, but spend.macaroon could not be "+
			"removed from the credential volume; it is inert, and Status will report it as "+
			"present with its key no longer listed", "error", err.Error())
	}
	if _, err := g.sweepAndForgetSpend(ctx, state.PendingRootKeyIDs); err != nil {
		return err
	}
	g.audit(ctx, slog.LevelWarn, "spend macaroon revoked", logging.EventMacaroonRevoke,
		map[string]string{
			"outcome": revocationOutcome(false),
			// WHO, as far as this guard can tell. "We deleted it" and "someone
			// else did" are materially different events for an operator reading
			// the trail after a suspected compromise, and this is the arm that
			// says the app was not the actor.
			"reason": "the node stopped listing the root key; sending was not re-enabled",
		})
	return nil
}
