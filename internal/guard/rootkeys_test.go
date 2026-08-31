package guard_test

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// tna.5 G2: a node-side revocation is not reversed by the renewal loop.
//
// The operator revokes the spend root key at the node — over SSH, or with
// lncli, or because they rotated the whole macaroon set. Tier 2 notices within
// about ten seconds and blocks payments. Then, between an hour and about 4.7
// days later, the renewal tick finds the credential expiring, bakes a fresh one
// under a NEW key, and the capability is back. The operator removed it and the
// app put it back.
//
// This is d24.8's own argument through another channel. That bead gated renewal
// on "sending is enabled" because otherwise Disable sending would mean "disable
// sending for up to an hour"; G2 is the same sentence with the operator acting
// at the node instead of at the page. What changes is the DEFINITION of enabled:
// the recorded root key still existing at the node is now part of it.
//
// THE ASYMMETRY IS DELIBERATE, and it is the rule this test pins:
//
//	Self-heal may restore capability the operator never removed, and must never
//	restore capability the operator removed.
//
// The receive side reads "the node forgot our key" as a fault to HEAL — as0.7,
// where re-linking is exactly right. The spend side reads the identical signal
// as an external REVOCATION and clears. Same evidence, opposite response.
func TestARevokedSpendKeyIsNotRestoredByTheRenewalLoop(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithSending(t, node, d, true)
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	baked := len(node.BakeRequests())

	// The operator revokes at the node, behind the guard's back.
	node.ForgetRootKeys()

	if err := g.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureSpendMacaroon: %v", err)
	}

	if got := len(node.BakeRequests()); got != baked {
		t.Errorf("the renewal loop baked %d more times after the operator revoked at the node; "+
			"it has just restored a capability they removed", got-baked)
	}
	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.SpendRootKeyRecorded {
		t.Error("the guard still records a spend root key the node has forgotten; sending reads " +
			"as on, and the next tick would bake again")
	}
	if _, err := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); !os.IsNotExist(err) {
		t.Errorf("spend.macaroon survived an external revocation (stat: %v); it is inert, and "+
			"leaving it makes the page say sending is ready", err)
	}
}

// And it says so in the trail, with the outcome the node actually gave.
func TestAnExternallyRevokedSpendKeyIsAudited(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithSending(t, node, d, true)
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	node.ForgetRootKeys()

	if err := g.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatal(err)
	}

	last := lastGuardEvent(t, g, logging.EventMacaroonRevoke)
	if got := last.Attrs["outcome"]; got != "the node was no longer listing the root key" {
		t.Errorf("the event says outcome %q; the guard did not delete this key — the node "+
			"already had, and an operator reading the trail after a suspected compromise needs "+
			"to tell those apart", got)
	}
	// And WHO, as far as this guard can tell. "We deleted it" and "someone else
	// did" are the materially different events the outcome attribute exists to
	// separate; this is the arm that says the app was not the actor.
	if got := last.Attrs["reason"]; !strings.Contains(got, "stopped listing the root key") {
		t.Errorf("the event's reason is %q; it does not say the node stopped listing the key, "+
			"which is the only evidence the guard has about who acted", got)
	}
}

// And a sweep the node REFUSED does not get reported as a success.
//
// THIS TEST EXISTS BECAUSE A PLANT PASSED. Collapsing sweepOutcome to its
// happy-path sentence changed nothing: every existing case swept cleanly, so the
// row said "have been revoked at the node" about keys the node had revoked, and
// the branch that matters — the node refused, the keys are still live — was
// never rendered. An operator reads this row after a suspected compromise to
// find out what is STILL OUT THERE, which makes a sweep reported as achieved
// when it was only attempted the same lie step 1 of RevokeSpend refuses to tell.
func TestASweepTheNodeRefusedIsNotReportedAsDone(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithSending(t, node, d, true)
	orphan := seedPendingRootKey(t, node, d)
	writeSpendCredentialFor(t, node, d, orphan)
	node.SetDeleteMacaroonIDError(orphan, errors.New("node is down"))

	if err := g.RevokeSpend(t.Context()); err == nil {
		t.Fatal("RevokeSpend reported plain success while it could not revoke the credential's " +
			"own key")
	}

	reason := lastGuardEvent(t, g, logging.EventMacaroonRevoke).Attrs["reason"]
	if strings.Contains(reason, "have been revoked at the node") {
		t.Errorf("the audit row says the other ids were revoked; the node refused, and %d is "+
			"still live: %q", orphan, reason)
	}
	if !strings.Contains(reason, "kept for a later sweep") {
		t.Errorf("the audit row does not say the ids are still live and kept for a retry: %q",
			reason)
	}
	// And the id really is still recorded, so a retry can find it.
	if pending := pendingRootKeys(t, d); !contains(pending, orphan) {
		t.Errorf("the key %d was forgotten after a FAILED revocation (%v)", orphan, pending)
	}
}

// lastGuardEvent is the most recent event of one kind that the guard has
// relayed, collected the way the server collects it.
//
// Over the SOCKET RESPONSE rather than from a log line: §16 gives the guard no
// mount for the database, so this ring is the durable half of §12 for everything
// the guard raises, and an assertion on the log line alone would pass while the
// trail stayed empty — which is how the Auditor went uncalled here for three
// waves.
func lastGuardEvent(t *testing.T, g *guard.Guard, kind logging.Event) logging.RelayedEvent {
	t.Helper()
	events := g.Handle(t.Context(), guard.Request{Op: guard.OpStatus}).Events
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Event == kind {
			return events[i]
		}
	}
	t.Fatalf("no %s event was relayed; the operator's durable record of this is that row "+
		"(events: %+v)", kind, events)
	return logging.RelayedEvent{}
}

// A bake that lands while the node is being asked about the OLD key is not
// erased by the answer.
//
// EnsureSpendMacaroon takes a state snapshot, makes a round trip to the node,
// and then acts destructively on what it read before the trip. RunRenewal and
// Serve are separate goroutines in cmd/brollyguard, so a socket BakeSpend fits
// inside that window: without a fresh read under the bake lock, its credential
// is deleted and its just-recorded root key erased from BOTH SpendRootKeyID and
// PendingRootKeyIDs — a live spend-capable key at the node with no record
// anywhere, which is precisely what G3 exists to prevent, reintroduced by G2.
//
// `-race` CANNOT SEE THIS. stateStore has its own mutex, so it is a lost update
// and not a data race, and no amount of -race runs would have found it.
func TestABakeThatLandsWhileTheNodeIsAskedIsNotErased(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithSending(t, node, d, true)
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	// The operator revokes at the node, so the next tick reads a revocation...
	node.ForgetRootKeys()
	// ...and the server asks for a fresh spend macaroon in the window between
	// the tick's question and its answer. Synchronously, inside the hook, which
	// is the interleaving itself rather than a race that might reproduce.
	// CompareAndSwap rather than sync.Once: the bake asks the node the same
	// question on its own way through, on another gRPC handler goroutine, and a
	// Once would still be inside Do when that arrives.
	var interleaved atomic.Bool
	node.SetOnListMacaroonIDs(func() {
		if !interleaved.CompareAndSwap(false, true) {
			return
		}
		if err := g.BakeSpend(t.Context()); err != nil {
			t.Errorf("the interleaved BakeSpend failed: %v", err)
		}
	})

	if err := g.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureSpendMacaroon: %v", err)
	}

	state := readGuardState(t, d.data)
	if state.SpendRootKeyID == 0 {
		t.Fatal("the renewal tick cleared a root key that had been recorded AFTER it asked the " +
			"node; the credential it names is live at the node and the guard can no longer name it")
	}
	if !contains(node.ListedRootKeyIDs(), state.SpendRootKeyID) {
		t.Errorf("the state names root key %d and the node is not listing it (%v)",
			state.SpendRootKeyID, node.ListedRootKeyIDs())
	}
	if contains(node.DeletedRootKeyIDs(), state.SpendRootKeyID) {
		t.Errorf("the key %d recorded by the interleaved bake was revoked by the tick that "+
			"asked about the old one", state.SpendRootKeyID)
	}
	if _, err := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Errorf("the interleaved bake's credential was removed: %v", err)
	}
}

// An UNREACHABLE node changes nothing at all.
//
// The arm that must not over-fire, and the reason the receive side's helper
// returns false on error. "Cannot tell" is not "revoked": treating an outage as
// an external revocation would tear down a working install every time the node
// blipped, which is the storm the circuit breaker exists to prevent — and here it
// would ALSO be destructive.
func TestAnUnreachableNodeDoesNotLookLikeARevocation(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithSending(t, node, d, true)
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	node.SetListMacaroonIDsError(errors.New("node is down"))

	if err := g.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureSpendMacaroon with an unreachable node: %v", err)
	}

	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !status.SpendRootKeyRecorded {
		t.Error("an unreachable node was read as an external revocation; the guard has just " +
			"forgotten a live root key it can no longer revoke")
	}
	if _, err := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Errorf("the credential was removed because the node could not be asked: %v", err)
	}
	if got := len(node.DeletedRootKeyIDs()); got != 0 {
		t.Errorf("%d revocations were attempted against an unreachable node", got)
	}
}

// tna.5 G3: the previous root key is RECORDED before it is forgotten.
//
// bake rewrote the state to name the new key and then called revokePrevious
// discarding its return — the very bool d24.10 added so a failed revocation keeps
// the id for a later sweep, and which is honoured at the other call site. One
// failed DeleteMacaroonID, or a `docker stop` between the state write and the
// call, left a spend-capable key live at the node with NO RECORD ANYWHERE: the
// guard cannot revoke what it cannot name, and a later "Disable sending" audits
// "the node deleted the root key" as success while the older key is still
// honoured.
//
// The invariant is the one already written beside the NEW key, applied to the
// old one: RECORD BEFORE MINT, SO NOTHING IS FORGOTTEN.
func TestAPreviousRootKeyThatWillNotDieIsKeptForALaterSweep(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithSending(t, node, d, true)
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("first BakeSpend: %v", err)
	}
	first := currentSpendRootKey(t, d)

	// The node will not delete it — a transient failure, or a node that has
	// opinions about macaroon deletion.
	node.SetDeleteMacaroonIDError(first, errors.New("cannot delete right now"))
	// Force a second bake: the credential is gone, so the renewal path must
	// mint a replacement.
	if err := os.Remove(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Fatal(err)
	}
	if err := g.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("second bake: %v", err)
	}

	pending := pendingRootKeys(t, d)
	if !contains(pending, first) {
		t.Fatalf("the previous root key %d is not in PendingRootKeyIDs (%v) after a failed "+
			"revocation; it is live at the node and NOTHING names it — the guard can never "+
			"revoke it, and Disable sending will report success while it is still honoured",
			first, pending)
	}

	// And a later sweep finishes the job once the node relents.
	node.SetDeleteMacaroonIDError(first, nil)
	if err := g.RevokeSpend(t.Context()); err != nil {
		t.Fatalf("RevokeSpend: %v", err)
	}
	if !contains(node.DeletedRootKeyIDs(), first) {
		t.Errorf("the kept key %d was never revoked by a later sweep; keeping it is only worth "+
			"anything if something comes back for it", first)
	}
}

// tna.5 G4: RevokeSpend's early returns run the pending sweep too.
//
// Both of them returned before sweepPending, so a kill switch pressed while
// sending was already off — or after the guard's store was lost — left every
// orphaned spend-capable key live at the node. "Disable sending" is the one
// control an operator reaches for when they are worried, and it has to mean the
// same thing whichever state it finds.
func TestRevokeSpendSweepsOrphansEvenWhenSendingIsAlreadyOff(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithSending(t, node, d, true)

	// A bake that failed on its way to disk leaves a key behind: the node minted
	// it, the guard recorded it as pending, and nothing is using it.
	orphan := seedPendingRootKey(t, node, d)

	// Sending is off — nothing was ever enabled — so this takes the early return.
	if err := g.RevokeSpend(t.Context()); err != nil {
		t.Fatalf("RevokeSpend with sending off: %v", err)
	}

	if !contains(node.DeletedRootKeyIDs(), orphan) {
		t.Errorf("the orphaned root key %d survived a revoke that took the sending-is-off path "+
			"(deleted: %v); a spend-capable key at the node outlived the kill switch",
			orphan, node.DeletedRootKeyIDs())
	}
	if pending := pendingRootKeys(t, d); contains(pending, orphan) {
		t.Errorf("the swept key %d is still recorded as pending (%v)", orphan, pending)
	}
}

// And "no record" is only said when there genuinely is none.
//
// The early return audited "the guard has no record of the root key it was baked
// under" whenever SpendRootKeyID was zero — which was inaccurate whenever
// PendingRootKeyIDs held one, and that string is what an operator reads after a
// suspected compromise.
func TestRevokeSpendDoesNotClaimNoRecordWhileItHoldsAPendingKey(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithSending(t, node, d, true)
	orphan := seedPendingRootKey(t, node, d)
	// A spend credential on disk with no current key recorded: the state was
	// lost, or a bake died between the write and the state update.
	writeSpendCredentialFor(t, node, d, orphan)

	err := g.RevokeSpend(t.Context())

	if err == nil {
		t.Fatal("RevokeSpend reported plain success while it could not revoke the credential's " +
			"own key; that is the one lie this operation must never tell")
	}
	// And it does NOT say "no record": the guard held an id, swept it, and said
	// which fact is true. That string is what an operator reads after a suspected
	// compromise (tna.5 G4).
	if got := err.Error(); !strings.Contains(got, "could not be revoked at the node") {
		t.Errorf("the error is %q", got)
	} else if strings.Contains(got, "no record of the root key") {
		t.Errorf("the error claims the guard had no record while it held a pending id: %q", got)
	}
	// THE DURABLE ROW, which is what the comment above is actually about: an
	// operator reading the trail after a suspected compromise reads §12's audit
	// event, not a Go error that went to one HTTP response. Asserting only the
	// error let the trail keep telling the story wrong.
	reason := lastGuardEvent(t, g, logging.EventMacaroonRevoke).Attrs["reason"]
	if strings.Contains(reason, "no record of the root key") {
		t.Errorf("the audit row claims the guard had no record while it held a pending id: %q",
			reason)
	}
	if !strings.Contains(reason, "have been revoked at the node") {
		t.Errorf("the audit row does not say what became of the ids the guard DID hold: %q; "+
			"what is still live at the node is the whole question being asked of this row",
			reason)
	}
	// The orphan it DID know about was still swept.
	if !contains(node.DeletedRootKeyIDs(), orphan) {
		t.Errorf("the pending key %d was not revoked on the way out (deleted: %v)",
			orphan, node.DeletedRootKeyIDs())
	}
}

// currentSpendRootKey is the key the guard has recorded for the spend
// credential right now.
func currentSpendRootKey(t *testing.T, d dirs) uint64 {
	t.Helper()
	id := readGuardState(t, d.data).SpendRootKeyID
	if id == 0 {
		t.Fatal("no spend root key is recorded; the test that needs one has nothing to work with")
	}
	return id
}

func pendingRootKeys(t *testing.T, d dirs) []uint64 {
	t.Helper()
	return readGuardState(t, d.data).PendingRootKeyIDs
}

func contains(ids []uint64, want uint64) bool { return slices.Contains(ids, want) }

// seedPendingRootKey produces a REAL orphan: a bake that the node completed and
// that then failed on its way to disk.
//
// Not a hand-written state file. The failure mode these tests are about is a key
// the node minted and the guard never finished using, and a fixture that wrote
// the id into the state directly would prove the sweep can read a list rather
// than that the list gets written when it matters.
func seedPendingRootKey(t *testing.T, node *lndtest.Node, d dirs) uint64 {
	t.Helper()
	g := openGuardWithSending(t, node, d, true)
	// The node mints the key and answers with something that is not a macaroon,
	// so the bake dies after BakeMacaroon and before the credential is written.
	node.SetBakedMacaroon([]byte("not a macaroon"))
	if err := g.BakeSpend(t.Context()); err == nil {
		t.Fatal("the seeded bake was supposed to fail after the node minted the key")
	}
	node.BakeRealMacaroons()

	pending := pendingRootKeys(t, d)
	if len(pending) != 1 {
		t.Fatalf("the failed bake left %v pending, want exactly one orphan", pending)
	}
	return pending[0]
}

// writeSpendCredentialFor puts a real, hardened spend macaroon on disk under a
// named root key while the guard's state names NO current key — the shape a
// crash between the credential write and the state update leaves behind.
func writeSpendCredentialFor(t *testing.T, node *lndtest.Node, d dirs, rootKeyID uint64) {
	t.Helper()
	raw, err := hex.DecodeString(node.MacaroonHexUnder(t, rootKeyID))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.credentials, lnd.SpendMacaroon), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A CURRENT key is never PENDING, which is what makes the sweep safe.
//
// The sweep runs at startup, right after the receive credential is baked or
// found, and deleting a current key would take the running install's own
// credential out from under it. Nothing checks for that, and nothing should: bake
// removes the key from PendingRootKeyIDs in the SAME state write that records it
// as current, so the two sets cannot overlap. This asserts the invariant rather
// than a guard against its absence — a check would have passed whether or not the
// invariant held, which is how the first version of this test came to pass
// against a sweep with the guard removed.
func TestACurrentRootKeyIsNeverLeftPending(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithSending(t, node, d, true)
	if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon: %v", err)
	}
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}

	state := readGuardState(t, d.data)
	for name, live := range map[string]uint64{
		"receive": state.ReceiveRootKeyID, "spend": state.SpendRootKeyID,
	} {
		if live == 0 {
			t.Fatalf("no %s root key is recorded; this test would prove nothing", name)
		}
		if contains(state.PendingRootKeyIDs, live) {
			t.Errorf("the CURRENT %s root key %d is also pending (%v); the startup sweep would "+
				"revoke the credential this install is using", name, live, state.PendingRootKeyIDs)
		}
	}

	// And neither was revoked along the way.
	for _, live := range []uint64{state.ReceiveRootKeyID, state.SpendRootKeyID} {
		if contains(node.DeletedRootKeyIDs(), live) {
			t.Errorf("a CURRENT root key was revoked (%d)", live)
		}
	}
	if _, err := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Errorf("the spend credential is gone: %v", err)
	}
}
