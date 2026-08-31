package guard_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
)

// d24.1 criterion 1. Two URIs, exactly, and never entity:action.
//
// The comparison is worth stating because it is the whole reason the list is
// compiled into this package rather than passed over the socket: `offchain:write`
// would additionally grant SendToRouteV2 — arbitrary self-constructed routes, a
// probing and draining primitive — plus SendPaymentSync and DeleteAllPayments.
// None of those is reachable from two explicit URIs.
func TestBakeSpendGrantsExactlyTheSendingURIs(t *testing.T) {
	node := lndtest.Start(t)
	g, _ := newGuard(t, node)

	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}

	requests := node.BakeRequests()
	if len(requests) != 1 {
		t.Fatalf("the node saw %d bakes, want 1", len(requests))
	}
	var granted []string
	for _, p := range requests[0].Permissions {
		if p.Entity != "uri" {
			t.Errorf("permission %s:%s is not URI-scoped; an entity:action pair grants a whole "+
				"family of methods (spec §6)", p.Entity, p.Action)
			continue
		}
		granted = append(granted, p.Action)
	}
	// THREE since d24.4, and the list is written out rather than compared to
	// SpendPermissions: comparing a constant to itself asserts nothing, and the
	// point of this test is that a widening of the spend credential has to be
	// typed twice — here and in the spec — before it can ship.
	want := []string{
		"/lnrpc.Lightning/DecodePayReq",
		"/routerrpc.Router/SendPaymentV2",
		"/routerrpc.Router/TrackPaymentV2",
	}
	slices.Sort(granted)
	if !slices.Equal(granted, want) {
		t.Errorf("granted %v, want exactly %v", granted, want)
	}
}

// Criterion 3 and 4. The spend credential is hardened by the SAME function as
// the receive one — one policy, applied twice, because two lists are what let
// the two credentials drift apart until the receive macaroon carried nothing
// (d46.26).
func TestTheSpendMacaroonIsHardenedAndVerifiedByValue(t *testing.T) {
	node := lndtest.Start(t)
	g, credentials := newGuard(t, node)

	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	raw := readCredential(t, credentials, lnd.SpendMacaroon)
	assertHardened(t, raw, "spend")

	// By VALUE, and that half is spend-specific here only because this is where
	// it is asserted. d24.7 measured why it matters: RequireCaveats matches
	// condition NAMES, so a macaroon bound to the wrong container passes a
	// name-only check and is refused only by LND, mid-payment.
	if got, ok := lnd.CaveatValue(raw, lnd.CaveatIPAddr); !ok || got != "10.21.0.17" {
		t.Errorf("ipaddr caveat = %q (present %v), want the SERVER's address — the spend "+
			"credential is used by the server container, not the guard", got, ok)
	}
	if got := credentialMode(t, credentials, lnd.SpendMacaroon); got != 0o600 {
		t.Errorf("spend.macaroon mode = %o, want 600", got)
	}
}

// Criterion 2. Its own random nonzero root key, distinct from the receive one.
//
// Distinct BY CONSTRUCTION rather than by luck: newRootKeyID reads the node's
// ListMacaroonIDs, which already lists the receive key, so the collision retry
// treats it as taken. If the two ever coincided, revoking spend would revoke
// the receive credential with it — the kill switch would take the node's
// ability to receive as collateral.
func TestTheSpendKeyIsItsOwnAndTheReceiveKeyIsTreatedAsTaken(t *testing.T) {
	node := lndtest.Start(t)
	g, _ := newGuard(t, node)

	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}

	requests := node.BakeRequests()
	if len(requests) != 2 {
		t.Fatalf("the node saw %d bakes, want 2", len(requests))
	}
	receiveKey, spendKey := requests[0].RootKeyId, requests[1].RootKeyId
	if spendKey == 0 {
		t.Fatal("the spend macaroon was baked under root key 0; deleting that key would revoke " +
			"admin.macaroon and every other app's credentials on the box")
	}
	if spendKey == receiveKey {
		t.Fatal("the spend and receive macaroons share a root key, so RevokeSpend would revoke " +
			"the receive credential too")
	}
	// Both live, and the node knows both.
	listed := node.ListedRootKeyIDs()
	if !slices.Contains(listed, receiveKey) || !slices.Contains(listed, spendKey) {
		t.Errorf("the node lists %v, want both %d and %d", listed, receiveKey, spendKey)
	}
}

// Criterion 2's crash window. BakeMacaroon CREATES the key on the node, so a
// failure between that call and the state write leaves a live key the guard has
// no record of and can therefore never revoke.
func TestBakeSpendRecordsThePendingKeyBeforeAskingTheNode(t *testing.T) {
	node := lndtest.Start(t)
	g, d := newGuardWithDirs(t, node, guard.Options{})

	// The node fails the bake, so the only trace of the key it may have created
	// is what the guard wrote down first.
	node.SetBakedMacaroon([]byte("not a macaroon"))
	if err := g.BakeSpend(t.Context()); err == nil {
		t.Fatal("BakeSpend accepted bytes that are not a macaroon")
	}

	state := readGuardState(t, d.data)
	if len(state.PendingRootKeyIDs) == 0 {
		t.Fatal("no pending root key was recorded, so a key the node created during the failed " +
			"bake could never be revoked — once an hour, for ever")
	}
	if state.SpendRootKeyID != 0 {
		t.Error("the failed bake recorded a spend root key as if it had succeeded")
	}
}

// Criterion 6. One credential, one live root key, ever.
func TestReBakingSpendRevokesThePreviousKey(t *testing.T) {
	node := lndtest.Start(t)
	clock := &testClock{now: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)}
	g, credentials := newGuardWithOptions(t, node, guard.Options{Now: clock.Now})

	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("first BakeSpend: %v", err)
	}
	first := node.BakeRequests()[0].RootKeyId
	before := readCredential(t, credentials, lnd.SpendMacaroon)

	// Past the point where a second bake would merely repeat the first — the
	// same guard the receive path has, and see the test below for its own arm.
	clock.advance(guard.MinBakeInterval + time.Minute)
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("second BakeSpend: %v", err)
	}
	second := node.BakeRequests()[1].RootKeyId
	if second == first {
		t.Fatal("the re-bake reused the previous root key, so revoking it would revoke the " +
			"credential just written")
	}
	if got := node.DeletedRootKeyIDs(); !slices.Contains(got, first) {
		t.Errorf("the node was asked to delete %v, which does not include the superseded key %d",
			got, first)
	}
	if got := readCredential(t, credentials, lnd.SpendMacaroon); string(got) == string(before) {
		t.Error("the credential on disk was not replaced")
	}
	if listed := node.ListedRootKeyIDs(); slices.Contains(listed, first) {
		t.Errorf("the node still honours the superseded key %d", first)
	}
}

// The bake-storm guard, now covering spend too (d24.1).
//
// It was written for the receive path, where the server re-asks once a minute.
// The spend path has no such fast retry today — but the hourly renewal is
// enough to create a root key an hour, for ever, on an install where sending is
// enabled and the ipaddr caveat is one LND will not accept. Each attempt also
// writes two audit rows against a 10,000-row trail, which erases the evidence
// needed to diagnose it.
//
// The data for this control was already being written before the control
// existed: State.SpendBakedAt had no reader at all.
func TestASecondSpendBakeThatWouldChangeNothingIsRefused(t *testing.T) {
	node := lndtest.Start(t)
	clock := &testClock{now: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)}
	g, _ := newGuardWithOptions(t, node, guard.Options{Now: clock.Now})

	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}

	err := g.BakeSpend(t.Context())
	if err == nil {
		t.Fatal("a second bake moments later was accepted; it would produce the same caveats " +
			"from the same static config, and mint a root key on the operator's node for it")
	}
	if !strings.Contains(err.Error(), "already meets the policy") {
		t.Errorf("error = %v, want it to say the credential on disk already meets the policy", err)
	}
	if got := len(node.BakeRequests()); got != 1 {
		t.Errorf("the node saw %d bakes, want 1", got)
	}

	// And it is a PAUSE, not a wall: past MinBakeInterval the bake proceeds.
	// Asserting only the refusal would pass against a guard that never re-bakes,
	// which would let the credential expire and stop sending with no explanation.
	clock.advance(guard.MinBakeInterval + time.Minute)
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("a bake past MinBakeInterval was still refused: %v", err)
	}
	if got := len(node.BakeRequests()); got != 2 {
		t.Errorf("the node saw %d bakes, want 2", got)
	}
}

// d24.10: an orphan the node REFUSED to delete stays on the list.
//
// The sweep revokes best-effort and then forgets. If DeleteMacaroonID errors —
// a transient gRPC failure moments after the main call succeeded — the key is
// still live at the node and the guard has just discarded the only record of
// it. That is precisely the "live key the guard can never revoke" failure
// PendingRootKeyIDs exists to prevent, reintroduced by the code that sweeps it.
//
// Both sweep sites, because they are two chances to lose the same id: the one
// at the end of a bake, and the one inside RevokeSpend.
func TestAnOrphanTheNodeRefusedToDeleteIsKept(t *testing.T) {
	for _, sweep := range []struct {
		name string
		run  func(t *testing.T, g *guard.Guard)
	}{{
		name: "swept by the next bake",
		run: func(t *testing.T, g *guard.Guard) {
			if err := g.BakeSpend(t.Context()); err != nil {
				t.Fatalf("BakeSpend: %v", err)
			}
		},
	}, {
		name: "swept by RevokeSpend",
		run: func(t *testing.T, g *guard.Guard) {
			if err := g.RevokeSpend(t.Context()); err != nil {
				t.Fatalf("RevokeSpend: %v", err)
			}
		},
	}} {
		t.Run(sweep.name, func(t *testing.T) {
			node := lndtest.Start(t)
			clock := &testClock{now: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}
			g, d := newGuardWithDirs(t, node, guard.Options{Now: clock.Now})

			// Sending on, so RevokeSpend has something to revoke and the bake
			// path has a previous key — the orphan below is neither.
			if err := g.BakeSpend(t.Context()); err != nil {
				t.Fatalf("BakeSpend: %v", err)
			}

			// A bake that mints a key at the node and then fails, leaving it
			// orphaned.
			node.SetBakedMacaroon([]byte("not a macaroon"))
			clock.advance(guard.MinBakeInterval + time.Minute)
			_ = g.BakeSpend(t.Context())
			node.BakeRealMacaroons()
			orphans := readGuardState(t, d.data).PendingRootKeyIDs
			if len(orphans) != 1 {
				t.Fatalf("expected one orphan, got %v", orphans)
			}
			orphan := orphans[0]

			// The node refuses to delete THIS id and nothing else, so the sweep
			// runs normally around it.
			node.SetDeleteMacaroonIDError(orphan, errors.New("transient failure"))
			clock.advance(guard.MinBakeInterval + time.Minute)
			sweep.run(t, g)

			if !slices.Contains(node.ListedRootKeyIDs(), orphan) {
				t.Fatalf("the node deleted %d after all; this test is not exercising a failed "+
					"revocation", orphan)
			}
			if got := readGuardState(t, d.data).PendingRootKeyIDs; !slices.Contains(got, orphan) {
				t.Errorf("the guard forgot orphan %d whose revocation FAILED; it is still live "+
					"at the node and nothing will ever revoke it again (state: %v)", orphan, got)
			}

			// Revoking drops the operator's latch (`06v`, Ruling 1), so the
			// bake below needs the ceremony again — same as an operator would.
			// A no-op on the bake arm, where nothing was revoked.
			permitSending(t, g, d)

			// And once the node cooperates, the next sweep does finish the job —
			// which is what makes keeping the id worth anything.
			node.SetDeleteMacaroonIDError(orphan, nil)
			clock.advance(guard.MinBakeInterval + time.Minute)
			if err := g.BakeSpend(t.Context()); err != nil {
				t.Fatalf("BakeSpend after the node recovered: %v", err)
			}
			if slices.Contains(node.ListedRootKeyIDs(), orphan) {
				t.Errorf("the retry did not revoke orphan %d", orphan)
			}
			if got := readGuardState(t, d.data).PendingRootKeyIDs; slices.Contains(got, orphan) {
				t.Errorf("the state still names orphan %d after it was revoked: %v", orphan, got)
			}
		})
	}
}

// The hole in the kill switch, closed (d24.1, from the wave-20 altitude review).
//
// BakeMacaroon MINTS the key at the node. A spend bake that fails after that
// call — on the caveats, the verification, or the write — leaves a key LND will
// honour for SendPaymentV2, with no credential on disk and no way for the
// operator to see it. "Disable sending" used to revoke only SpendRootKeyID, so
// that key survived the kill switch and stayed live until some later bake
// happened to sweep it. After a revocation there may never be a later bake.
func TestRevokeSpendAlsoRevokesTheKeysFailedBakesLeftBehind(t *testing.T) {
	node := lndtest.Start(t)
	clock := &testClock{now: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)}
	g, d := newGuardWithDirs(t, node, guard.Options{Now: clock.Now})

	// A bake that reaches the node and then fails: the key exists, the
	// credential does not.
	node.SetBakedMacaroon([]byte("not a macaroon"))
	if err := g.BakeSpend(t.Context()); err == nil {
		t.Fatal("the bake was supposed to fail after the node minted the key")
	}
	orphans := readGuardState(t, d.data).PendingRootKeyIDs
	if len(orphans) != 1 {
		t.Fatalf("the guard recorded %v pending keys, want the one the node minted", orphans)
	}
	orphan := orphans[0]
	if !slices.Contains(node.ListedRootKeyIDs(), orphan) {
		t.Fatalf("the node does not list %d, so this test is not exercising a live key", orphan)
	}

	// Now a bake that works, so sending is genuinely on.
	node.BakeRealMacaroons()
	clock.advance(guard.MinBakeInterval + time.Minute)
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	// The successful bake sweeps it too — but a revoke must not DEPEND on that,
	// which is what the second half below is for.
	if slices.Contains(node.ListedRootKeyIDs(), orphan) {
		t.Errorf("the successful bake left the orphaned key %d live", orphan)
	}

	// The case that matters: an orphan created and then revoked, with no bake
	// in between to clean up after it.
	node.SetBakedMacaroon([]byte("not a macaroon"))
	clock.advance(guard.MinBakeInterval + time.Minute)
	_ = g.BakeSpend(t.Context())
	node.BakeRealMacaroons()
	second := readGuardState(t, d.data).PendingRootKeyIDs
	if len(second) != 1 {
		t.Fatalf("expected one new pending key, got %v", second)
	}

	if err := g.RevokeSpend(t.Context()); err != nil {
		t.Fatalf("RevokeSpend: %v", err)
	}
	if slices.Contains(node.ListedRootKeyIDs(), second[0]) {
		t.Errorf("the node still honours %d after Disable sending; it was minted under "+
			"SpendPermissions and can pay, so the kill switch did not kill everything that "+
			"can move money", second[0])
	}
	if got := readGuardState(t, d.data).PendingRootKeyIDs; len(got) != 0 {
		t.Errorf("the state still names pending keys after revocation: %v", got)
	}
}

// Criterion 1 of RevokeSpend, and the ORDER — which is the part that matters.
//
// Node-side revocation first. §6 is explicit that this is a node-side
// revocation and not a local delete, because it has to hold against an attacker
// who already exfiltrated the macaroon; a crash between the steps must leave
// the credential dead at LND rather than alive on disk with the state cleared.
func TestRevokeSpendKillsTheKeyThenTheFileThenTheState(t *testing.T) {
	node := lndtest.Start(t)
	g, d := newGuardWithDirs(t, node, guard.Options{})

	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	key := node.BakeRequests()[0].RootKeyId

	// Observed AT the moment of revocation: the file must still be there when
	// the node is asked, which is what proves the order rather than the outcome.
	var fileWasStillPresentAtRevocation bool
	node.SetOnDeleteMacaroonID(func(uint64) {
		_, err := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon))
		fileWasStillPresentAtRevocation = err == nil
	})

	if err := g.RevokeSpend(t.Context()); err != nil {
		t.Fatalf("RevokeSpend: %v", err)
	}

	if !fileWasStillPresentAtRevocation {
		t.Error("spend.macaroon was already gone when the node was asked to revoke; the local " +
			"delete must not precede the node-side revocation (spec §6)")
	}
	if !slices.Contains(node.DeletedRootKeyIDs(), key) {
		t.Errorf("the node was asked to delete %v, not the recorded spend key %d",
			node.DeletedRootKeyIDs(), key)
	}
	if slices.Contains(node.ListedRootKeyIDs(), key) {
		t.Error("the node still honours the revoked key; an exfiltrated copy would still pay")
	}
	if _, err := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); !os.IsNotExist(err) {
		t.Errorf("spend.macaroon is still in the credential volume (stat err = %v)", err)
	}
	state := readGuardState(t, d.data)
	if state.SpendRootKeyID != 0 || !state.SpendBakedAt.IsZero() || len(state.PendingRootKeyIDs) != 0 {
		t.Errorf("the state still describes a spend credential after revocation: %+v", state)
	}
}

// Criterion 2. The cross-app-destruction argument, made into a test.
//
// The request carries no root key id — §6's "no operation takes a parameter" —
// so the only id RevokeSpend can reach is the one the guard baked. Another
// app's key on the same node must survive, and this is the assertion that says
// so rather than the comment that claims it.
func TestRevokeSpendRevokesOnlyWhatTheGuardRecorded(t *testing.T) {
	node := lndtest.Start(t)
	g, _ := newGuard(t, node)

	// Another app's credential, and our own receive one: neither is ours to kill.
	const anotherAppsKey = 424242
	node.AddRootKeyForTest(anotherAppsKey)
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}
	receiveKey := node.BakeRequests()[0].RootKeyId
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	spendKey := node.BakeRequests()[1].RootKeyId

	if err := g.RevokeSpend(t.Context()); err != nil {
		t.Fatalf("RevokeSpend: %v", err)
	}

	if deleted := node.DeletedRootKeyIDs(); !slices.Equal(deleted, []uint64{spendKey}) {
		t.Errorf("the node was asked to delete %v, want only the spend key %d — a revocation "+
			"that reaches any other id is a cross-app destructive primitive (spec §6)",
			deleted, spendKey)
	}
	listed := node.ListedRootKeyIDs()
	if !slices.Contains(listed, anotherAppsKey) {
		t.Error("another app's root key was revoked; the box's other apps just lost their " +
			"credentials")
	}
	if !slices.Contains(listed, receiveKey) {
		t.Error("the receive key was revoked; disabling sending must not stop the node receiving")
	}
}

// The decision this wave had to make, recorded as behaviour: when the NODE
// refuses the revocation, nothing else happens.
//
// Reporting "sending disabled" while LND still honours the key is the one lie
// this operation must never tell — an exfiltrated copy would keep paying while
// the UI said it could not. So the credential stays on disk and the state keeps
// naming the key, which is what makes a retry able to finish the job.
func TestRevokeSpendChangesNothingWhenTheNodeRefuses(t *testing.T) {
	node := lndtest.Start(t)
	g, d := newGuardWithDirs(t, node, guard.Options{})

	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	key := node.BakeRequests()[0].RootKeyId

	node.SetReject(true)
	err := g.RevokeSpend(t.Context())
	if err == nil {
		t.Fatal("RevokeSpend reported success while the node refused it")
	}
	node.SetReject(false)

	if _, statErr := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); statErr != nil {
		t.Errorf("spend.macaroon was deleted even though the node still honours its key: %v",
			statErr)
	}
	if got := readGuardState(t, d.data).SpendRootKeyID; got != key {
		t.Errorf("the recorded spend key is %d, want %d kept so a retry can finish the job",
			got, key)
	}

	// And the retry does finish it.
	if err := g.RevokeSpend(t.Context()); err != nil {
		t.Fatalf("the retry failed: %v", err)
	}
	if slices.Contains(node.ListedRootKeyIDs(), key) {
		t.Error("the retry did not revoke the key")
	}
}

// Revoking when the guard has no record of a key: the file goes, and the guard
// says plainly that it could not perform a node-side revocation.
//
// A silent success here would be the same lie as above in a quieter voice. The
// guard cannot revoke what it did not record — §6 forbids taking an id from the
// server — so the honest report is that a copy stays valid until it expires.
func TestRevokeSpendWithNoRecordedKeySaysSoRatherThanClaimingSuccess(t *testing.T) {
	node := lndtest.Start(t)
	g, d := newGuardWithDirs(t, node, guard.Options{})

	// A credential on disk that this guard has no record of baking — a lost or
	// wiped guard-state.json.
	if err := guard.WriteCredential(filepath.Join(d.credentials, lnd.SpendMacaroon),
		lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2099-01-01T00:00:00Z"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := g.RevokeSpend(t.Context())
	if err == nil {
		t.Fatal("RevokeSpend claimed success with no recorded root key; nothing was revoked at " +
			"the node and an exfiltrated copy stays valid until it expires")
	}
	if !strings.Contains(err.Error(), "no record") {
		t.Errorf("error = %v, want it to say the guard has no record of the root key", err)
	}
	// The file still goes: removing what the server can reach is the part the
	// guard CAN do, and leaving it would let the server keep presenting a
	// credential nobody can revoke.
	if _, statErr := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); !os.IsNotExist(statErr) {
		t.Errorf("the unrevocable credential was left in the volume (stat err = %v)", statErr)
	}

	// And with nothing at all, it is a clean no-op: "disable" must not fail
	// merely because sending was already off.
	if err := g.RevokeSpend(t.Context()); err != nil {
		t.Errorf("revoking when sending is already off failed: %v", err)
	}
}

// Criterion 3. Status tells the truth afterwards.
func TestStatusReportsTheSpendCredentialAndThenItsAbsence(t *testing.T) {
	node := lndtest.Start(t)
	g, _ := newGuard(t, node)

	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.SpendMacaroonPresent {
		t.Error("Status says there is no spend macaroon just after baking one")
	}
	if !status.SpendRootKeyListed {
		t.Error("Status says the node does not list the spend root key just after baking under it")
	}
	if status.SpendExpiry.IsZero() {
		t.Error("Status carries no spend expiry; the server learns it only from here (§6)")
	}

	if err := g.RevokeSpend(t.Context()); err != nil {
		t.Fatalf("RevokeSpend: %v", err)
	}
	status, err = g.Status(t.Context())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.SpendMacaroonPresent {
		t.Error("Status still reports a spend macaroon after revocation")
	}
	if status.SpendRootKeyListed {
		t.Error("Status still reports the spend root key as listed after revocation")
	}
	if !status.SpendExpiry.IsZero() {
		t.Errorf("Status still reports a spend expiry (%v) after revocation", status.SpendExpiry)
	}
}

// The d24.8 rule, and the subtlest requirement in this wave.
//
// A revoked spend credential must STAY revoked. A renewal loop that re-bakes on
// schedule turns "Disable sending" into "Disable sending for up to an hour" —
// the operator revokes, walks away, and the guard quietly mints a fresh spend
// macaroon under a fresh key because the old one is expiring.
//
// The BAKE COUNT is the assertion, and getting it to mean something took two
// goes. The first version waited for "a bake happened" and then asserted the
// file was absent — but the tick renews receive as well, so it was waiting on
// the receive bake and racing the spend one. It passed against its own plant.
// This version removes the race instead of widening the timeout:
//
//   - the receive credential is baked FIRST and the clock does not move in
//     phase A, so a tick has nothing to do for receive and ANY bake is a spend
//     bake;
//   - revocation leaves no spend.macaroon at all, which is the strongest form
//     of "it is due" and needs no clock move to reach;
//   - two sends on an unbuffered channel are the barrier. The second send
//     cannot be received until the first tick's renewal has returned, and
//     waiting for the loop to exit covers the second.
func TestRenewalDoesNotResurrectARevokedSpendCredential(t *testing.T) {
	node := lndtest.Start(t)
	clock := &testClock{now: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)}
	g, d := newGuardWithDirs(t, node, guard.Options{Now: clock.Now})

	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	if err := g.RevokeSpend(t.Context()); err != nil {
		t.Fatalf("RevokeSpend: %v", err)
	}
	bakesBefore := len(node.BakeRequests())

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.RunRenewal(ctx, tick)
	}()

	// Phase A: the receive credential is fresh, so a tick should bake nothing at
	// all. The spend credential is absent, which is as due as a credential gets.
	tick <- clock.Now()
	tick <- clock.Now() // barrier: the first tick's renewal has returned
	if got := len(node.BakeRequests()); got != bakesBefore {
		t.Errorf("a renewal tick baked %d time(s) with a fresh receive credential and a REVOKED "+
			"spend one; the only thing it could have baked is the spend macaroon (d24.8)",
			got-bakesBefore)
	}

	// Phase B: now move past expiry, where the receive credential genuinely is
	// due. Bakes are expected — but none of them may be a spend bake.
	clock.advance(guard.CredentialLifetime + time.Hour)
	tick <- clock.Now()
	tick <- clock.Now()
	cancel()
	<-done

	for i, req := range node.BakeRequests()[bakesBefore:] {
		for _, p := range req.Permissions {
			if strings.Contains(p.Action, "routerrpc.Router") {
				t.Errorf("bake %d after revocation granted %s; sending was disabled and only an "+
					"explicit BakeSpend may turn it back on", bakesBefore+i, p.Action)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); !os.IsNotExist(err) {
		t.Fatal("the renewal loop re-baked a REVOKED spend credential; disabling sending would " +
			"last only until the next tick (d24.8)")
	}
	if got := readGuardState(t, d.data).SpendRootKeyID; got != 0 {
		t.Errorf("the state names spend root key %d after renewal ticks; revoked must stay "+
			"revoked", got)
	}
}

// The other half of the same rule: while sending IS enabled, the spend
// credential is renewed like any other.
//
// Asserting only the refusal above would pass against a guard that never renews
// spend at all — and a spend credential that silently expires is sending that
// stops working with no operator action and no explanation.
func TestRenewalReplacesAnExpiringSpendCredentialWhileSendingIsEnabled(t *testing.T) {
	node := lndtest.Start(t)
	clock := &testClock{now: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)}
	g, credentials := newGuardWithOptions(t, node, guard.Options{Now: clock.Now})

	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	first := readCredential(t, credentials, lnd.SpendMacaroon)
	firstKey := node.BakeRequests()[0].RootKeyId

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.RunRenewal(ctx, tick)
	}()

	// A tick while it is fresh changes nothing.
	tick <- clock.Now()
	if got := readCredential(t, credentials, lnd.SpendMacaroon); string(got) != string(first) {
		t.Fatal("a tick replaced a spend credential nowhere near expiry")
	}

	clock.advance(guard.CredentialLifetime - guard.RenewBefore + time.Minute)
	tick <- clock.Now()
	// The revocation is the LAST step of a bake; waiting on the credential
	// changing would be waiting on the second-to-last and racing the rest.
	lndtest.WaitFor(t, "the previous spend root key to be revoked", func() bool {
		return slices.Contains(node.DeletedRootKeyIDs(), firstKey)
	})

	renewed := readCredential(t, credentials, lnd.SpendMacaroon)
	if string(renewed) == string(first) {
		t.Fatal("the spend credential was not replaced")
	}
	if err := lnd.RequireHardening(renewed); err != nil {
		t.Errorf("the renewed spend credential is not hardened: %v", err)
	}
	expiry, ok := lnd.Expiry(renewed)
	if !ok || !expiry.After(clock.Now().Add(guard.RenewBefore)) {
		t.Errorf("renewed expiry %v is not comfortably ahead of %v", expiry, clock.Now())
	}
	cancel()
	<-done
}

// §13's seam: the server asks over the REAL socket and the credential appears
// in the volume.
//
// Through Serve and SocketClient, not by calling the methods — two well-tested
// sides with an untested wire between them is exactly what per-package coverage
// cannot see, and the wire here is the dispatch switch that returned
// "not enabled" for these two ops until this wave.
func TestTheSpendOperationsWorkOverTheRealSocket(t *testing.T) {
	node := lndtest.Start(t)
	g, d := newGuardWithDirs(t, node, guard.Options{})
	client := serveGuard(t, g)

	if err := client.RequestSpendBake(t.Context()); err != nil {
		t.Fatalf("RequestSpendBake over the socket: %v", err)
	}
	raw := readCredential(t, d.credentials, lnd.SpendMacaroon)
	if err := lnd.RequireHardening(raw); err != nil {
		t.Errorf("the credential the socket call produced is not hardened: %v", err)
	}

	status, err := client.Status(t.Context())
	if err != nil {
		t.Fatalf("Status over the socket: %v", err)
	}
	if !status.SpendMacaroonPresent || !status.SpendRootKeyListed {
		t.Errorf("status over the socket = %+v, want the spend credential present and its key "+
			"listed", status)
	}

	if err := client.RequestSpendRevoke(t.Context()); err != nil {
		t.Fatalf("RequestSpendRevoke over the socket: %v", err)
	}
	if _, err := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); !os.IsNotExist(err) {
		t.Errorf("spend.macaroon survived a revoke over the socket (stat err = %v)", err)
	}
	if status, err = client.Status(t.Context()); err != nil {
		t.Fatalf("Status over the socket: %v", err)
	}
	if status.SpendMacaroonPresent || status.SpendRootKeyListed {
		t.Errorf("status over the socket = %+v, want the spend credential gone", status)
	}
}

// §12: both operations are audit events, and the root key id is not in them.
//
// The id is the kill switch's target. It is not a credential, but it is the one
// value that makes a stolen guard-state.json actionable, and BakeReceive
// already keeps it out of the trail — so this follows rather than reasons afresh.
func TestTheSpendOperationsAreAuditedWithoutTheRootKeyID(t *testing.T) {
	node := lndtest.Start(t)
	g, _ := newGuard(t, node)

	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	key := node.BakeRequests()[0].RootKeyId
	if err := g.RevokeSpend(t.Context()); err != nil {
		t.Fatalf("RevokeSpend: %v", err)
	}

	events := g.Handle(t.Context(), guard.Request{Op: guard.OpStatus}).Events
	var baked, revoked bool
	for _, ev := range events {
		switch {
		case ev.Event == "macaroon.bake" && strings.Contains(ev.Attrs["caveats"], lnd.CaveatIPAddr):
			baked = true
		case ev.Event == "macaroon.revoke":
			revoked = true
		}
		for name, value := range ev.Attrs {
			if strings.Contains(value, strconv.FormatUint(key, 10)) {
				t.Errorf("audit event %s carries the root key id in %q; it is the kill switch's "+
					"target and BakeReceive keeps it out of the trail", ev.Event, name)
			}
		}
	}
	if !baked {
		t.Errorf("no macaroon.bake event naming the caveats; events = %+v", events)
	}
	if !revoked {
		t.Errorf("no macaroon.revoke event; events = %+v", events)
	}
}

// EnsureSpendMacaroon is the renewal loop's entry point, and it must not be a
// way to turn sending ON.
func TestEnsureSpendMacaroonNeverEnablesSending(t *testing.T) {
	node := lndtest.Start(t)
	g, d := newGuardWithDirs(t, node, guard.Options{})

	if err := g.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureSpendMacaroon on a guard that has never baked spend: %v", err)
	}
	if len(node.BakeRequests()) != 0 {
		t.Fatal("it baked a spend macaroon on an install where sending was never enabled")
	}
	if _, err := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); !os.IsNotExist(err) {
		t.Errorf("a spend credential appeared without anyone enabling sending (stat err = %v)", err)
	}
}

// A guard whose state says sending is enabled but whose credential volume has
// no spend.macaroon: the file was lost, and the renewal loop is what puts it
// back. Distinct from the revoked case above, and the pair is what stops
// "never bake" passing as "do not resurrect".
func TestEnsureSpendMacaroonRestoresALostCredentialWhileSendingIsEnabled(t *testing.T) {
	node := lndtest.Start(t)
	g, d := newGuardWithDirs(t, node, guard.Options{})

	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	if err := os.Remove(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Fatal(err)
	}

	if err := g.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureSpendMacaroon: %v", err)
	}
	raw := readCredential(t, d.credentials, lnd.SpendMacaroon)
	if err := lnd.RequireHardening(raw); err != nil {
		t.Errorf("the restored spend credential is not hardened: %v", err)
	}
}

// An unconstrained spend credential on disk — the upgrade path, and the same
// reasoning as the receive one: presence is not conformance.
func TestAnUnconstrainedSpendCredentialIsReplaced(t *testing.T) {
	node := lndtest.Start(t)
	g, d := newGuardWithDirs(t, node, guard.Options{})

	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	// Same key, no caveats: exactly what a build predating the caveat policy
	// would have left behind.
	if err := guard.WriteCredential(filepath.Join(d.credentials, lnd.SpendMacaroon),
		lndtest.Macaroon(t), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := g.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureSpendMacaroon: %v", err)
	}
	if err := lnd.RequireHardening(readCredential(t, d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Errorf("an unconstrained spend credential survived: %v", err)
	}
}

// A bake the guard cannot constrain must not happen at all — the same refusal
// credentialCaveats already makes for receive, asserted for spend because
// "never neither" is the contract that keeps an unconstrained spend macaroon
// off the box.
func TestBakeSpendRefusesWhenThereIsNoAddressToLockTo(t *testing.T) {
	node := lndtest.Start(t)
	g, d := newUnlockableGuard(t, node)

	err := g.BakeSpend(t.Context())
	if err == nil {
		t.Fatal("BakeSpend produced a credential with no ipaddr and no iprange caveat")
	}
	if !strings.Contains(err.Error(), "SERVER_IP") {
		t.Errorf("error = %v, want it to name the missing setting", err)
	}
	if _, statErr := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); !os.IsNotExist(statErr) {
		t.Errorf("an unconstrainable credential was written anyway (stat err = %v)", statErr)
	}
}

// --- helpers ---------------------------------------------------------------

// newGuardWithDirs is newGuardWithOptions for tests that need the DATA dir too,
// because the state file is where "revoked means revoked" is actually recorded.
func newGuardWithDirs(t *testing.T, node *lndtest.Node, opts guard.Options) (*guard.Guard, dirs) {
	t.Helper()
	d := guardDirs(t, node)
	return openGuard(t, node, d, opts), d
}

// newUnlockableGuard has neither SERVER_IP nor NETWORK_CIDR, so
// credentialCaveats can produce no IP lock — the "never neither" refusal path.
func newUnlockableGuard(t *testing.T, node *lndtest.Node) (*guard.Guard, dirs) {
	t.Helper()
	d := guardDirs(t, node)
	return openGuardAt(t, node, d, guard.Options{}, netip.Addr{}), d
}

// readGuardState reads the guard's own store, which is the only place the spend
// root key id exists.
func readGuardState(t *testing.T, dataDir string) guard.State {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dataDir, "guard-state.json"))
	if os.IsNotExist(err) {
		return guard.State{}
	}
	if err != nil {
		t.Fatalf("reading the guard state: %v", err)
	}
	var state guard.State
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("parsing the guard state: %v", err)
	}
	return state
}

func credentialMode(t *testing.T, dir, name string) os.FileMode {
	t.Helper()
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	return info.Mode().Perm()
}

// serveGuard runs the real socket server and returns the server's own client
// for it — the seam, not a shortcut around it.
func serveGuard(t *testing.T, g *guard.Guard) *guard.SocketClient {
	t.Helper()
	socket := socketPath(t)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = g.Serve(ctx, socket) }()

	client := guard.NewSocketClient(socket, guard.DiscardEvents)
	lndtest.WaitFor(t, "the socket to accept", func() bool {
		_, err := client.Status(ctx)
		return err == nil
	})
	return client
}
