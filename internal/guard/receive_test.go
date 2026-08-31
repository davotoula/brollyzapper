package guard_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
)

// d46.26 criterion 2. Before this, the receive macaroon was the only credential
// in the system with no caveats — baked under LND's default root key and living
// inside the backup scope. A stolen copy, used over LND's Tor-published gRPC,
// streams every invoice on the node for every app, reads any invoice by hash,
// and fills the invoice database. It cannot move a satoshi; it can read
// everything the node has ever received.
//
// §11 calls post-bake caveat verification the check that matters most, and this
// is that check applied to the credential that previously skipped it.
func TestTheReceiveMacaroonIsHardenedLikeTheSpendOne(t *testing.T) {
	node := lndtest.Start(t)
	g, credentials := newGuard(t, node)
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}
	// Identical policy to the spend macaroon: the two credentials differ in
	// permissions and never in hardening, which is why there is one caveat
	// function, one bake, and — see assertHardened — one assertion.
	assertHardened(t, readCredential(t, credentials, lnd.ReceiveMacaroon), "receive")
}

// The plant d46.8 used, on the credential that previously had nothing to strip:
// remove a caveat after baking and the verification must name it.
func TestStrippingACaveatFailsReceiveVerification(t *testing.T) {
	full := lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2099-01-01T00:00:00Z")
	if err := guard.VerifyBaked("receive", false, full); err != nil {
		t.Fatalf("a fully constrained macaroon was refused: %v", err)
	}

	for _, tc := range []struct {
		name    string
		caveats []string
		want    string
	}{
		{"no ip lock", []string{"time-before 2099-01-01T00:00:00Z"}, "ipaddr"},
		{"no expiry", []string{"ipaddr 10.21.0.17"}, "time-before"},
		{"nothing at all", nil, "ipaddr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stripped := lndtest.Macaroon(t, tc.caveats...)
			err := guard.VerifyBaked("receive", false, stripped)
			if err == nil {
				t.Fatal("a stripped macaroon passed verification")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to name %q", err, tc.want)
			}
		})
	}

	// And the policy check catches a bake that asked for nothing — the shape
	// that let the receive macaroon ship unconstrained for the whole of P1.
	if err := guard.VerifyBaked("receive", false, lndtest.Macaroon(t)); err == nil {
		t.Error("a macaroon with no caveats passed verification; that is exactly how this " +
			"credential shipped unconstrained")
	}
}

// Criterion 3: its own root key, so revocation is possible at all. Under LND's
// default key 0 the only revoke is rotating macaroons.db, which invalidates
// every other app's credentials on the box.
func TestTheReceiveMacaroonHasItsOwnRootKey(t *testing.T) {
	node := lndtest.Start(t)
	g, _ := newGuard(t, node)
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}
	requests := node.BakeRequests()
	if len(requests) != 1 {
		t.Fatalf("the node saw %d bakes, want 1", len(requests))
	}
	if requests[0].RootKeyId == 0 {
		t.Fatal("baked under root key 0; deleting that key would revoke admin.macaroon and " +
			"every other app's credentials with it")
	}
	if got := node.ListedRootKeyIDs(); !slices.Contains(got, requests[0].RootKeyId) {
		t.Errorf("the node lists %v, which does not include the key we baked under (%d)",
			got, requests[0].RootKeyId)
	}
}

// Criterion 3's other half: a re-bake revokes the key the previous credential
// was under — and does it AFTER the new one is written, so there is never a
// window with no valid credential for the server's self-heal to fire into.
func TestARebakeRevokesThePreviousRootKey(t *testing.T) {
	node := lndtest.Start(t)
	clock := &testClock{now: time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)}
	g, credentials := newGuardWithOptions(t, node, guard.Options{Now: clock.Now})
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("first BakeReceive: %v", err)
	}
	first := node.BakeRequests()[0].RootKeyId
	before := readCredential(t, credentials, lnd.ReceiveMacaroon)

	// Past the point where a second bake would merely repeat the first.
	clock.advance(guard.MinBakeInterval + time.Minute)
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("second BakeReceive: %v", err)
	}
	second := node.BakeRequests()[1].RootKeyId
	if second == first {
		t.Fatal("the re-bake reused the previous root key, so revoking it would revoke the " +
			"credential just written")
	}
	if got := node.DeletedRootKeyIDs(); !slices.Contains(got, first) {
		t.Errorf("deleted %v, want the previous key %d revoked — a stolen copy of the old "+
			"credential otherwise stays valid", got, first)
	}
	if slices.Contains(node.DeletedRootKeyIDs(), second) {
		t.Error("the re-bake revoked the key it had just baked under")
	}
	if after := readCredential(t, credentials, lnd.ReceiveMacaroon); string(after) == string(before) {
		t.Error("the credential on disk did not change")
	}
}

// The ORDER is the property: bake, write, THEN revoke. The other order leaves a
// window in which the old credential is dead and the new one is not on disk —
// and the server's self-heal fires into exactly that window.
func TestTheOldKeyIsRevokedOnlyAfterTheNewCredentialIsOnDisk(t *testing.T) {
	node := lndtest.Start(t)
	clock := &testClock{now: time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)}
	g, credentials := newGuardWithOptions(t, node, guard.Options{Now: clock.Now})
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("first BakeReceive: %v", err)
	}
	first := readCredential(t, credentials, lnd.ReceiveMacaroon)

	// The FIRST revocation, not the last: a re-bake that revoked early and then
	// again later would otherwise look correct because the second observation
	// overwrote the damning one.
	var onDiskAtRevocation []byte
	var revocations int
	clock.advance(guard.MinBakeInterval + time.Minute)
	node.SetOnDeleteMacaroonID(func(uint64) {
		revocations++
		if revocations == 1 {
			onDiskAtRevocation = readCredential(t, credentials, lnd.ReceiveMacaroon)
		}
	})
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("second BakeReceive: %v", err)
	}
	if onDiskAtRevocation == nil {
		t.Fatal("no revocation happened, so the ordering was not exercised")
	}
	if string(onDiskAtRevocation) == string(first) {
		t.Error("the old key was revoked while the OLD credential was still on disk; for that " +
			"moment the server holds a credential the node has just invalidated")
	}
	if revocations != 1 {
		t.Errorf("the re-bake revoked %d times, want 1", revocations)
	}
}

func readCredential(t *testing.T, dir, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return raw
}

// Criterion 5: a credential with a time-before caveat needs something to
// replace it, or a healthy install expires itself. Driven with an injected
// clock, so the test costs microseconds and cannot pass by waiting.
func TestTheScheduledRenewalReplacesAnExpiringCredential(t *testing.T) {
	node := lndtest.Start(t)
	// The clock is read by the renewal goroutine and moved by this one, so it
	// is guarded — an unsynchronised test variable is a data race whatever the
	// production code does.
	clock := &testClock{now: time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)}
	g, credentials := newGuardWithOptions(t, node, guard.Options{Now: clock.Now})
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}
	first := readCredential(t, credentials, lnd.ReceiveMacaroon)
	firstKey := node.BakeRequests()[0].RootKeyId

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.RunRenewal(ctx, tick)
	}()

	// A tick while the credential is fresh changes nothing.
	tick <- clock.Now()
	if got := readCredential(t, credentials, lnd.ReceiveMacaroon); string(got) != string(first) {
		t.Fatal("a tick replaced a credential that was nowhere near expiry")
	}

	// Now move the clock to inside the renewal window.
	clock.advance(guard.CredentialLifetime - guard.RenewBefore + time.Minute)
	tick <- clock.Now()
	// Wait for the REVOCATION, which is the last step of a bake — not for the
	// credential to change, which is the second-to-last. Waiting on the earlier
	// signal and then asserting the later one is a race the test wins on a fast
	// machine and loses on a loaded CI runner, and the gap between them is the
	// bake ordering this wave deliberately introduced: write first, revoke
	// after, so there is never a moment with no valid credential.
	lndtest.WaitFor(t, "the previous root key to be revoked", func() bool {
		return slices.Contains(node.DeletedRootKeyIDs(), firstKey)
	})

	renewed := readCredential(t, credentials, lnd.ReceiveMacaroon)
	if string(renewed) == string(first) {
		t.Fatal("the credential was not replaced")
	}
	if err := lnd.RequireHardening(renewed); err != nil {
		t.Errorf("the renewed credential is not hardened: %v", err)
	}
	expiry, ok := lnd.Expiry(renewed)
	if !ok || !expiry.After(clock.Now().Add(guard.RenewBefore)) {
		t.Errorf("renewed expiry %v is not comfortably ahead of %v", expiry, clock.Now())
	}
	cancel()
	<-done
}

// The upgrade path, and the reason existence is not enough: an install that
// came from a build baking UNCONSTRAINED credentials has a recv.macaroon on
// disk, so a check for presence alone would keep using it for ever.
func TestAnUnconstrainedCredentialIsReplacedOnStart(t *testing.T) {
	// Two independent reasons a stored credential will not do, each planted on
	// its own so neither can be the one that saves the other.
	t.Run("no ip lock", func(t *testing.T) {
		node := lndtest.Start(t)
		g, credentials := newGuard(t, node)
		bakeOnceToRecordARootKey(t, g) // so the root-key check cannot be what fires
		// A READABLE expiry and no IP lock, so neither the expiry check nor the
		// root-key check can be what triggers the re-bake — only the policy.
		legacy := lndtest.Macaroon(t, "time-before 2099-01-01T00:00:00Z")
		writeLegacy(t, credentials, legacy)

		if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
			t.Fatalf("EnsureReceiveMacaroon: %v", err)
		}
		got := readCredential(t, credentials, lnd.ReceiveMacaroon)
		if string(got) == string(legacy) {
			t.Fatal("a credential with no IP lock survived a start; the upgrade would leave " +
				"the finding unfixed on every existing install")
		}
		if err := lnd.RequireHardening(got); err != nil {
			t.Errorf("the replacement is not hardened: %v", err)
		}
	})

	t.Run("exactly what P1 shipped: no caveats at all", func(t *testing.T) {
		node := lndtest.Start(t)
		g, credentials := newGuard(t, node)
		legacy := lndtest.Macaroon(t)
		writeLegacy(t, credentials, legacy)
		if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
			t.Fatalf("EnsureReceiveMacaroon: %v", err)
		}
		if got := readCredential(t, credentials, lnd.ReceiveMacaroon); string(got) == string(legacy) {
			t.Fatal("the credential P1 shipped survived an upgrade")
		}
	})

	t.Run("hardened but under the node's default root key", func(t *testing.T) {
		node := lndtest.Start(t)
		g, credentials := newGuard(t, node)
		// Correctly caveated, so only the root key can be what triggers it.
		legacy := lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2099-01-01T00:00:00Z")
		writeLegacy(t, credentials, legacy)

		if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
			t.Fatalf("EnsureReceiveMacaroon: %v", err)
		}
		if got := readCredential(t, credentials, lnd.ReceiveMacaroon); string(got) == string(legacy) {
			t.Error("a credential under root key 0 survived a start; it cannot be revoked " +
				"without taking every other app's credentials with it")
		}
	})

	t.Run("a conforming credential is left alone", func(t *testing.T) {
		node := lndtest.Start(t)
		g, credentials := newGuard(t, node)
		if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
			t.Fatalf("EnsureReceiveMacaroon: %v", err)
		}
		before := readCredential(t, credentials, lnd.ReceiveMacaroon)
		if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
			t.Fatalf("second EnsureReceiveMacaroon: %v", err)
		}
		if after := readCredential(t, credentials, lnd.ReceiveMacaroon); string(after) != string(before) {
			t.Error("a conforming credential was re-baked on a second start, so the node's " +
				"root key list would grow without bound")
		}
	})
}

func writeLegacy(t *testing.T, credentials string, raw []byte) {
	t.Helper()
	if err := guard.WriteCredential(filepath.Join(credentials, lnd.ReceiveMacaroon), raw, 0o600); err != nil {
		t.Fatalf("planting a legacy credential: %v", err)
	}
}

// bakeOnceToRecordARootKey gets a non-zero ReceiveRootKeyID into the state
// file, so a later assertion can isolate the caveat check from the key check.
func bakeOnceToRecordARootKey(t *testing.T, g *guard.Guard) {
	t.Helper()
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}
}

// Status is how the server learns anything needing macaroon:read, and the
// expiry is what the Node page shows (§6, §9).
func TestStatusCarriesTheReceiveExpiry(t *testing.T) {
	node := lndtest.Start(t)
	g, _ := newGuard(t, node)
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}
	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.ReceiveExpiry.IsZero() {
		t.Fatal("Status carries no receive expiry, so the Node page cannot show one")
	}
	if !status.ReceiveExpiry.After(time.Now()) {
		t.Errorf("ReceiveExpiry = %v, want it in the future", status.ReceiveExpiry)
	}
}

// Adopting backupIgnore for data/credentials means a RESTORE arrives without
// that directory, Docker creates the bind-mount source itself, and what Docker
// creates is owned by root while the containers run as uid 1000. The symptom
// would be a bake that succeeds against the node and then fails to write —
// which reads like a bake failure and is not.
func TestTheCredentialVolumeIsProvedWritableBySayingWhatToFix(t *testing.T) {
	t.Run("a writable volume passes", func(t *testing.T) {
		if err := guard.PreflightCredentialsDir(t.TempDir()); err != nil {
			t.Errorf("a writable directory was refused: %v", err)
		}
	})
	t.Run("a missing volume is named", func(t *testing.T) {
		err := guard.PreflightCredentialsDir(filepath.Join(t.TempDir(), "gone"))
		if err == nil {
			t.Fatal("a missing credential volume passed")
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("an unwritable volume names the fix", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root, which can write anything")
		}
		dir := filepath.Join(t.TempDir(), "readonly")
		if err := os.Mkdir(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		err := guard.PreflightCredentialsDir(dir)
		if err == nil {
			t.Fatal("an unwritable credential volume passed the check")
		}
		if !strings.Contains(err.Error(), "chown") {
			t.Errorf("error = %v, want it to name the command that fixes it", err)
		}
	})
	t.Run("the probe leaves nothing behind", func(t *testing.T) {
		dir := t.TempDir()
		if err := guard.PreflightCredentialsDir(dir); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("the write probe left %d entries behind", len(entries))
		}
	})
}

// testClock is a clock two goroutines share.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// The loop this closes: an ipaddr the node does not agree with makes every RPC
// fail, the server asks for a re-bake once a minute, and the guard bakes the
// SAME wrong caveat from the same static config every time. Each attempt makes
// a root key on the node and writes two audit rows — 2880 a day against a
// 10,000-row trail, erasing the evidence needed to diagnose it within four days.
func TestABakeThatCannotChangeAnythingIsRefused(t *testing.T) {
	node := lndtest.Start(t)
	clock := &testClock{now: time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)}
	g, _ := newGuardWithOptions(t, node, guard.Options{Now: clock.Now})
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}

	for range 10 {
		clock.advance(time.Minute)
		if err := g.BakeReceive(t.Context()); err == nil {
			t.Fatal("a bake that would produce the same credential was allowed")
		}
	}
	if got := len(node.BakeRequests()); got != 1 {
		t.Errorf("the node was asked to bake %d times, want 1 — each extra one leaves a root "+
			"key behind and two audit rows", got)
	}

	// But a node that has FORGOTTEN our root key is the rotation case, and
	// re-baking is exactly the recovery §6 describes. Refusing there would turn
	// a 30-second repair into a 30-minute one.
	for _, id := range node.ListedRootKeyIDs() {
		if _, err := node.DeleteRootKeyForTest(id); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("a re-bake after the node forgot our root key was refused: %v", err)
	}
	if got := len(node.BakeRequests()); got != 2 {
		t.Errorf("the node was asked to bake %d times, want 2", got)
	}
}

// A bake that reaches the node and then fails locally must not leave a live root
// key nothing has a record of: only `lncli deletemacaroonid` over SSH could ever
// remove one, and the failing path repeats every hour.
func TestAKeyCreatedByAFailedBakeIsRevokedByTheNextOne(t *testing.T) {
	node := lndtest.Start(t)
	clock := &testClock{now: time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)}
	g, credentials := newGuardWithOptions(t, node, guard.Options{Now: clock.Now})

	// Make the write fail after the node has already created the key: a
	// directory where the credential file goes is exactly what a bad restore
	// leaves behind (§6, d46.12).
	if err := os.MkdirAll(filepath.Join(credentials, lnd.ReceiveMacaroon), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := g.BakeReceive(t.Context()); err == nil {
		t.Fatal("the bake succeeded despite the credential path being a directory")
	}
	orphaned := node.BakeRequests()[0].RootKeyId
	if !slices.Contains(node.ListedRootKeyIDs(), orphaned) {
		t.Fatal("the node did not create a key, so there is no orphan to clean up")
	}

	// Repair the volume and bake again: the orphan must be revoked.
	if err := os.RemoveAll(filepath.Join(credentials, lnd.ReceiveMacaroon)); err != nil {
		t.Fatal(err)
	}
	clock.advance(guard.MinBakeInterval + time.Minute)
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive after repair: %v", err)
	}
	if !slices.Contains(node.DeletedRootKeyIDs(), orphaned) {
		t.Errorf("the key the failed bake created (%d) was never revoked; deleted %v",
			orphaned, node.DeletedRootKeyIDs())
	}
}
