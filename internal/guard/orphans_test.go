package guard_test

import (
	"bytes"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	macaroon "gopkg.in/macaroon.v2"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// openGuardOnClock is openGuardWithSending on a clock the test moves, because two
// bakes of one credential inside MinBakeInterval are refused as a repeat — and
// every test here bakes a credential twice.
func openGuardOnClock(t *testing.T, node *lndtest.Node, d dirs, clock *testClock, permit bool,
	opts ...guard.Options) *guard.Guard {
	t.Helper()
	var o guard.Options
	if len(opts) == 1 {
		o = opts[0]
	}
	o.Now = clock.Now
	g := openGuardFull(t, node, d, o, netip.MustParseAddr("10.21.0.17"), true)
	if permit {
		permitSending(t, g, d)
	}
	return g
}

// pastTheRepeatGuard moves the clock far enough that the next bake is not
// refused as a repeat of the last.
func (c *testClock) pastTheRepeatGuard() { c.advance(guard.MinBakeInterval) }

// sweepRows is the attributes of every unattended-sweep row in the trail — the
// macaroon.revoke rows that carry a count, which the per-key rows do not.
func sweepRows(t *testing.T, g *guard.Guard) []map[string]string {
	t.Helper()
	var rows []map[string]string
	for _, event := range g.Handle(t.Context(), guard.Request{Op: guard.OpStatus}).Events {
		if event.Event == logging.EventMacaroonRevoke && event.Attrs["count"] != "" {
			rows = append(rows, event.Attrs)
		}
	}
	return rows
}

// errCrash stands in for the process dying at a chosen point in a bake.
var errCrash = errors.New("the process died here")

// bakedUnder is the root key the credential at path was baked under, read out of
// LNDTEST'S encoding of a macaroon id — the decimal id, which macaroonUnder puts
// there. This is the fake's format and not LND's, which is exactly why the guard
// cannot do the same in production (ADR 0001) and why the test can.
func bakedUnder(t *testing.T, path string) uint64 {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the credential on disk: %v", err)
	}
	var m macaroon.Macaroon
	if err := m.UnmarshalBinary(raw); err != nil {
		t.Fatalf("the credential on disk is not a macaroon: %v", err)
	}
	id, err := strconv.ParseUint(string(m.Id()), 10, 64)
	if err != nil {
		t.Fatalf("the credential's id %q is not lndtest's decimal root key id: %v", m.Id(), err)
	}
	return id
}

// sweepAsAtStartup runs the guard's renewal loop the way cmd/brollyguard starts
// it, with a schedule that ends at once: whatever it does on entry, and nothing
// on a tick.
func sweepAsAtStartup(t *testing.T, g *guard.Guard) {
	t.Helper()
	tick := make(chan time.Time)
	close(tick)
	g.RunRenewal(t.Context(), tick)
}

// interruptAfterWriting makes g die the moment the named credential file has been
// written — after WriteCredential, before the state records the bake. That is the
// window tna.5 G3 exists for, reached through a real bake rather than a
// hand-written state file.
func interruptAfterWriting(g *guard.Guard, file string) {
	guard.SetCredentialWriter(g, func(path string, data []byte, mode os.FileMode) error {
		if err := guard.WriteCredential(path, data, mode); err != nil {
			return err
		}
		if filepath.Base(path) == file {
			return errCrash
		}
		return nil
	})
}

// 2o1 criterion 11, and the bead's own acceptance: THE G3 WINDOW AS A TEST.
//
// A bake wrote the new credential and died before the state named its key, so the
// state still names the PREVIOUS key as current, and the new one — the key the
// file on disk actually depends on — sits in PendingRootKeyIDs. A startup sweep
// that trusted the state revoked it on every restart, under a green UI; that is
// why Wave 30's sweep was removed the day it was built. The sidecar is what lets
// the guard know better without reading the macaroon.
//
// Both credentials, separately, because each has its own state field and its own
// sidecar, and a sweep that consulted one of them would pass the other's test.
func TestAStartupSweepSparesTheKeyAnInterruptedBakeLeftOnDisk(t *testing.T) {
	for _, c := range []struct {
		kind string
		file string
		bake func(*guard.Guard) error
		key  func(guard.State) uint64
	}{
		{"receive", lnd.ReceiveMacaroon, func(g *guard.Guard) error { return g.BakeReceive(t.Context()) },
			func(st guard.State) uint64 { return st.ReceiveRootKeyID }},
		{"spend", lnd.SpendMacaroon, func(g *guard.Guard) error { return g.BakeSpend(t.Context()) },
			func(st guard.State) uint64 { return st.SpendRootKeyID }},
	} {
		t.Run(c.kind, func(t *testing.T) {
			node := lndtest.Start(t)
			d := guardDirs(t, node)
			clock := &testClock{now: time.Now().UTC()}
			g := openGuardOnClock(t, node, d, clock, true)
			if err := c.bake(g); err != nil {
				t.Fatalf("the first %s bake: %v", c.kind, err)
			}
			older := c.key(readGuardState(t, d.data))

			clock.pastTheRepeatGuard()
			interruptAfterWriting(g, c.file)
			if err := c.bake(g); !errors.Is(err, errCrash) {
				t.Fatalf("the interrupted bake returned %v, want the injected crash", err)
			}
			onDisk := bakedUnder(t, filepath.Join(d.credentials, c.file))
			state := readGuardState(t, d.data)
			// THE PREMISE, each half checked so a failure names which one broke.
			if onDisk == older {
				t.Fatal("the interrupted bake never replaced the credential; this proves nothing")
			}
			if c.key(state) != older {
				t.Fatalf("the state names %d as current, want the OLDER key %d — the crash landed "+
					"after the state write, so this is not the G3 window", c.key(state), older)
			}
			if !contains(state.PendingRootKeyIDs, onDisk) {
				t.Fatalf("the key on disk %d is not pending (%v); nothing would ever sweep it",
					onDisk, state.PendingRootKeyIDs)
			}

			restarted := openGuardOnClock(t, node, d, clock, true)
			sweepAsAtStartup(t, restarted)

			if contains(node.DeletedRootKeyIDs(), onDisk) {
				t.Fatalf("the startup sweep revoked %d, the root key the %s credential on disk was "+
					"baked under. The state named the older key and the sweep believed it: that "+
					"breaks the live credential on every restart, which is Wave 30's defect",
					onDisk, c.kind)
			}
			// The credential still works, asked the only way lndtest can answer it:
			// its root key is still listed. (lndtest's authorise does not look at
			// root keys, so a call made with the file would succeed either way.)
			if !contains(node.ListedRootKeyIDs(), onDisk) {
				t.Errorf("the node no longer lists %d, the key the credential on disk depends on",
					onDisk)
			}
			if contains(node.DeletedRootKeyIDs(), older) {
				t.Errorf("the sweep revoked the older key %d the state names as current", older)
			}
		})
	}
}

// 2o1 criterion 12: the inverse. A pending key NOTHING names — no state field, no
// sidecar — is revoked at startup, with no operator, on a RECEIVE-ONLY install.
//
// Receive-only is the case the bead is about: there the sweep ran only inside a
// bake or RevokeSpend, and an operator who never touches either left the key live
// at the node until it expired. DeleteMacaroonID is not spend-gated.
func TestAStartupSweepRevokesAKeyNothingNames(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Now().UTC()}
	g := openGuardOnClock(t, node, d, clock, false)
	if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon: %v", err)
	}
	live := readGuardState(t, d.data).ReceiveRootKeyID
	// TWO, so one row per sweep and one row per key cannot both pass.
	orphans := []uint64{
		failAReceiveBakeAfterTheNodeMintedItsKey(t, node, g, d, clock),
		failAReceiveBakeAfterTheNodeMintedItsKey(t, node, g, d, clock),
	}

	restarted := openGuardOnClock(t, node, d, clock, false)
	sweepAsAtStartup(t, restarted)

	for _, orphan := range orphans {
		if contains(node.ListedRootKeyIDs(), orphan) {
			t.Errorf("the orphan %d is still listed at the node after a startup sweep (deleted: %v)",
				orphan, node.DeletedRootKeyIDs())
		}
		if contains(pendingRootKeys(t, d), orphan) {
			t.Errorf("the revoked orphan %d is still recorded as pending", orphan)
		}
	}
	if contains(node.DeletedRootKeyIDs(), live) {
		t.Errorf("the sweep revoked the live receive key %d", live)
	}
	// ONE audit row for the sweep, naming the count, not a row per key.
	rows := sweepRows(t, restarted)
	if len(rows) != 1 {
		t.Fatalf("%d sweep rows in the trail, want exactly one", len(rows))
	}
	if rows[0]["count"] != "2" {
		t.Errorf("the sweep's row counts %q revoked, want 2", rows[0]["count"])
	}
}

// A sidecar counts only BESIDE ITS CREDENTIAL. The kill switch removes
// spend.macaroon and leaves its sidecar; when the node refused that revocation the
// key is kept pending, and a sidecar still naming it must not spare it from every
// later sweep — there is no credential left for it to protect.
func TestASidecarWithNoCredentialSparesNothing(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Now().UTC()}
	g := openGuardOnClock(t, node, d, clock, true)
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	key := currentSpendRootKey(t, d)
	// Kept pending by a bake whose revocation of it failed: supersede it once.
	node.SetDeleteMacaroonIDError(key, errors.New("not now"))
	clock.pastTheRepeatGuard()
	if err := os.Remove(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Fatal(err)
	}
	if err := g.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("the superseding bake: %v", err)
	}
	if !contains(pendingRootKeys(t, d), key) {
		t.Fatalf("premise: the superseded key %d should be pending", key)
	}
	// The spend credential goes, and a STALE sidecar naming the old key is left
	// where the new one was.
	if err := os.Remove(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(d.credentials, lnd.SpendMacaroon+guard.RootKeySidecarSuffix)
	if err := os.WriteFile(stale, []byte(strconv.FormatUint(key, 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	node.SetDeleteMacaroonIDError(key, nil)

	sweepAsAtStartup(t, openGuardOnClock(t, node, d, clock, true))
	if !contains(node.DeletedRootKeyIDs(), key) {
		t.Errorf("a sidecar with no credential beside it spared %d from the sweep", key)
	}
}

// And the kill switch is not softened by the sidecar rule. A FIRST spend bake that
// died after writing the credential leaves the file and its sidecar naming K, no
// current spend key, and K pending — tna.5 G4's shape. "Disable sending" must
// revoke K: it is the spend credential's own key, and ending sending is exactly
// the operation that must reach it.
func TestTheKillSwitchRevokesTheSpendKeyItsOwnSidecarNames(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Now().UTC()}
	g := openGuardOnClock(t, node, d, clock, true)
	interruptAfterWriting(g, lnd.SpendMacaroon)
	if err := g.BakeSpend(t.Context()); !errors.Is(err, errCrash) {
		t.Fatalf("the interrupted bake returned %v, want the injected crash", err)
	}
	key := bakedUnder(t, filepath.Join(d.credentials, lnd.SpendMacaroon))
	if readGuardState(t, d.data).SpendRootKeyID != 0 {
		t.Fatal("premise: a first bake that died before its state write records no spend key")
	}

	restarted := openGuardOnClock(t, node, d, clock, true)
	_ = restarted.RevokeSpend(t.Context()) // it reports the missing record as an error, by design
	if !contains(node.DeletedRootKeyIDs(), key) {
		t.Errorf("the kill switch left %d live — the spend credential's own key — because its "+
			"sidecar named it", key)
	}
}

// And on the hourly tick, not only at startup: an orphan a failed bake leaves
// while the guard is running is swept by the next tick, without a restart.
func TestTheRenewalTickSweepsAnOrphanWithoutARestart(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Now().UTC()}
	g := openGuardOnClock(t, node, d, clock, false)
	if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon: %v", err)
	}
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.RunRenewal(t.Context(), tick)
	}()
	// A BARRIER, not a tick for its own sake. The send on an unbuffered channel
	// completes only once the loop is in its select, i.e. after the entry sweep —
	// so the orphan below is made after that sweep has run, and only a TICK's
	// sweep can revoke it. Without this the entry sweep, scheduled late, could do
	// it and the test would pass with no tick sweep at all.
	tick <- time.Now()
	orphan := failAReceiveBakeAfterTheNodeMintedItsKey(t, node, g, d, clock)
	tick <- time.Now()
	close(tick)
	<-done

	if contains(node.ListedRootKeyIDs(), orphan) {
		t.Errorf("the orphan %d survived a renewal tick (deleted: %v)", orphan, node.DeletedRootKeyIDs())
	}
}

// failAReceiveBakeAfterTheNodeMintedItsKey leaves a REAL orphan: the node mints
// the key and answers with something that is not a macaroon, so the bake dies
// after BakeMacaroon and before anything is written.
func failAReceiveBakeAfterTheNodeMintedItsKey(t *testing.T, node *lndtest.Node, g *guard.Guard, d dirs,
	clock *testClock) uint64 {
	t.Helper()
	clock.pastTheRepeatGuard()
	before := pendingRootKeys(t, d)
	node.SetBakedMacaroon([]byte("not a macaroon"))
	if err := g.BakeReceive(t.Context()); err == nil {
		t.Fatal("the seeded bake was supposed to fail after the node minted the key")
	}
	node.BakeRealMacaroons()
	for _, id := range pendingRootKeys(t, d) {
		if !contains(before, id) {
			return id
		}
	}
	t.Fatal("the failed bake left nothing pending")
	return 0
}

// 2o1 criterion 13, and where the brief and the bead part: AN UPGRADED INSTALL,
// whose credentials were written before sidecars existed.
//
// The brief asked that a pending key the state does not name be revoked here. The
// bead's acceptance is that the sweep PROVABLY cannot revoke a key a credential on
// disk depends on — and with no sidecar, the one case where that is at risk is
// exactly G3's window, crashed into before the upgrade: the guard cannot tell the
// orphan from the live key. So an unattended sweep that finds a credential with no
// sidecar revokes NOTHING and waits for that credential's next bake, which writes
// one. That is today's behaviour for those keys, and never worse.
func TestAnUnattendedSweepRevokesNothingBesideACredentialWithNoSidecar(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Now().UTC()}
	g := openGuardOnClock(t, node, d, clock, false)
	if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon: %v", err)
	}
	older := readGuardState(t, d.data).ReceiveRootKeyID
	clock.pastTheRepeatGuard()
	interruptAfterWriting(g, lnd.ReceiveMacaroon)
	if err := g.BakeReceive(t.Context()); !errors.Is(err, errCrash) {
		t.Fatalf("the interrupted bake returned %v, want the injected crash", err)
	}
	onDisk := bakedUnder(t, filepath.Join(d.credentials, lnd.ReceiveMacaroon))
	if onDisk == older {
		t.Fatal("premise: the interrupted bake did not replace the credential")
	}
	// The install predates sidecars.
	sidecar := filepath.Join(d.credentials, lnd.ReceiveMacaroon+guard.RootKeySidecarSuffix)
	if err := os.Remove(sidecar); err != nil {
		t.Fatalf("removing the sidecar to model an upgraded install: %v", err)
	}

	var logs bytes.Buffer
	restarted := openGuardOnClock(t, node, d, clock, false,
		guard.Options{Log: logging.New(&logs, logging.NewLevelVar(slog.LevelInfo))})
	sweepAsAtStartup(t, restarted)
	sweepAsAtStartup(t, restarted)

	if deleted := node.DeletedRootKeyIDs(); len(deleted) != 0 {
		t.Errorf("an unattended sweep revoked %v beside a credential with no sidecar; the key "+
			"on disk is %d and the guard has no way to know that", deleted, onDisk)
	}
	// Said, once, and not fatal.
	if n := strings.Count(logs.String(), "no root key sidecar"); n != 1 {
		t.Errorf("the missing sidecar was logged %d times over two sweeps, want once:\n%s", n, logs.String())
	}

	// And the credential's next bake writes the sidecar and finishes the job.
	clock.pastTheRepeatGuard()
	if err := restarted.BakeReceive(t.Context()); err != nil {
		t.Fatalf("the next receive bake: %v", err)
	}
	if !contains(node.DeletedRootKeyIDs(), onDisk) {
		t.Errorf("the next bake did not sweep the superseded key %d", onDisk)
	}
}

// And with no credential on disk at all there is nothing a sidecar could protect,
// so the sweep runs as the brief described: state-named keys spared, the rest
// revoked.
func TestAnUnattendedSweepWithNoCredentialsRevokesOnlyWhatNothingNames(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Now().UTC()}
	g := openGuardOnClock(t, node, d, clock, false)
	orphan := failAReceiveBakeAfterTheNodeMintedItsKey(t, node, g, d, clock)

	restarted := openGuardOnClock(t, node, d, clock, false)
	sweepAsAtStartup(t, restarted)
	if !contains(node.DeletedRootKeyIDs(), orphan) {
		t.Errorf("the orphan %d was not revoked on an install with no credentials", orphan)
	}
}

// The sidecar is written BEFORE the macaroon (criterion 14's second plant has
// something to fail): a bake interrupted between its two credential-volume writes
// must leave either the old macaroon, or a new one whose sidecar names it — never
// a new macaroon the sidecar does not name, which is the file a sweep would break.
//
// The crash is placed on the SECOND write of the bake, whichever that is, so this
// test does not encode the order it is checking.
func TestABakeInterruptedBetweenItsWritesLeavesNoUnnamedMacaroon(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Now().UTC()}
	g := openGuardOnClock(t, node, d, clock, false)
	if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon: %v", err)
	}
	clock.pastTheRepeatGuard()
	writes := 0
	guard.SetCredentialWriter(g, func(path string, data []byte, mode os.FileMode) error {
		writes++
		if writes == 2 {
			return errCrash
		}
		return guard.WriteCredential(path, data, mode)
	})
	if err := g.BakeReceive(t.Context()); !errors.Is(err, errCrash) {
		t.Fatalf("the bake returned %v, want the injected crash on its second write", err)
	}
	if writes != 2 {
		t.Fatalf("the bake made %d credential-volume writes before dying, want 2", writes)
	}

	restarted := openGuardOnClock(t, node, d, clock, false)
	sweepAsAtStartup(t, restarted)
	onDisk := bakedUnder(t, filepath.Join(d.credentials, lnd.ReceiveMacaroon))
	if !contains(node.ListedRootKeyIDs(), onDisk) {
		t.Errorf("after a bake died between its writes and the guard restarted, the node no "+
			"longer lists %d — the key the receive credential on disk depends on", onDisk)
	}
}

// "Sharing the sidecar rule": the OPERATOR-triggered sweeps spare another
// credential's live key too. A receive bake interrupted in G3's window leaves
// its live key pending, and the spend bake's sweep and the kill switch's sweep
// both walk the whole pending set — so without the rule, pressing "Enable
// sending" or "Disable sending" would break zap receiving.
func TestTheOperatorSweepsSpareTheOtherCredentialsLiveKey(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Now().UTC()}
	g := openGuardOnClock(t, node, d, clock, true)
	if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon: %v", err)
	}
	clock.pastTheRepeatGuard()
	interruptAfterWriting(g, lnd.ReceiveMacaroon)
	if err := g.BakeReceive(t.Context()); !errors.Is(err, errCrash) {
		t.Fatalf("the interrupted bake returned %v, want the injected crash", err)
	}
	guard.SetCredentialWriter(g, guard.WriteCredential)
	receiving := bakedUnder(t, filepath.Join(d.credentials, lnd.ReceiveMacaroon))

	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	if contains(node.DeletedRootKeyIDs(), receiving) {
		t.Fatalf("a spend bake revoked %d, the key the receive credential on disk depends on", receiving)
	}
	if err := g.RevokeSpend(t.Context()); err != nil {
		t.Fatalf("RevokeSpend: %v", err)
	}
	if contains(node.DeletedRootKeyIDs(), receiving) {
		t.Fatalf("the kill switch revoked %d, the key the receive credential on disk depends on", receiving)
	}
	if !contains(pendingRootKeys(t, d), receiving) {
		t.Errorf("the spared key %d was dropped from pending; nothing would ever sweep it once "+
			"the receive credential is re-baked", receiving)
	}
}

// Criterion 13's first half: a pending id the STATE names as current is spared.
//
// HAND-WRITTEN STATE, and that is the point rather than a shortcut. No real path
// produces it — bake removes a key from the pending set in the same write that
// records it as current (TestACurrentRootKeyIsNeverLeftPending) — so the spare is
// defence in depth against a state from somewhere else: an older build, a restore,
// a hand edit. A bake-driven fixture could not reach the branch, which is how a
// mutation deleting it went unnoticed.
func TestAnUnattendedSweepSparesAKeyTheStateNamesAsCurrent(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Now().UTC()}
	g := openGuardOnClock(t, node, d, clock, false)
	if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon: %v", err)
	}
	live := readGuardState(t, d.data).ReceiveRootKeyID

	editGuardStateJSON(t, d, func(fields map[string]any) {
		fields["pending_root_key_ids"] = []uint64{live}
	})
	// And the sidecar goes too, so it is the STATE that has to spare it — the
	// sidecar would otherwise answer first. With no sidecar beside a credential
	// the sweep stops altogether, so the credential goes as well: what is left is
	// a state naming a current key that is also pending, and nothing on disk.
	for _, name := range []string{lnd.ReceiveMacaroon + guard.RootKeySidecarSuffix, lnd.ReceiveMacaroon} {
		if err := os.Remove(filepath.Join(d.credentials, name)); err != nil {
			t.Fatal(err)
		}
	}

	sweepAsAtStartup(t, openGuardOnClock(t, node, d, clock, false))
	if contains(node.DeletedRootKeyIDs(), live) {
		t.Errorf("the sweep revoked %d, which the state names as the current receive key", live)
	}
}

// A key the node REFUSES to delete is kept pending, and no row says it was
// revoked: the next sweep tries again (d24.10's keep-on-failure, unchanged).
func TestAnUnattendedSweepKeepsWhatTheNodeWouldNotRevoke(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Now().UTC()}
	g := openGuardOnClock(t, node, d, clock, false)
	orphan := failAReceiveBakeAfterTheNodeMintedItsKey(t, node, g, d, clock)
	node.SetDeleteMacaroonIDError(orphan, errors.New("not now"))

	sweepAsAtStartup(t, g)
	if !contains(pendingRootKeys(t, d), orphan) {
		t.Fatalf("the sweep forgot %d after the node refused to revoke it; it is live at the node "+
			"with no record anywhere", orphan)
	}
	for _, row := range sweepRows(t, g) {
		t.Errorf("a sweep that revoked nothing wrote a row claiming %s", row["count"])
	}

	node.SetDeleteMacaroonIDError(orphan, nil)
	sweepAsAtStartup(t, g)
	if !contains(node.DeletedRootKeyIDs(), orphan) {
		t.Errorf("the next sweep did not come back for %d", orphan)
	}
}

// The operator-triggered sweeps still write a row PER REVOKED KEY, which the
// unattended sweep's one-row-per-pass shape must not have taken with it: since
// the simplify pass both go through one loop and a flag chooses, and no test
// before this one would have noticed the flag going the wrong way.
func TestABakeStillAuditsEachKeyItRevokes(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Now().UTC()}
	g := openGuardOnClock(t, node, d, clock, false)
	if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon: %v", err)
	}
	clock.pastTheRepeatGuard()
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("the superseding bake: %v", err)
	}
	for _, event := range g.Handle(t.Context(), guard.Request{Op: guard.OpStatus}).Events {
		if event.Event == logging.EventMacaroonRevoke && event.Attrs["count"] == "" {
			return
		}
	}
	t.Error("a bake that revoked the key it superseded wrote no macaroon.revoke row for it")
}
