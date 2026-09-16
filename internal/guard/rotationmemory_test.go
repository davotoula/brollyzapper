package guard_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// as0.10: the rotation exit is sanctioned ONCE per rotation, not forever.
//
// Since as0.8 the guard reaches its threshold unattended, which is right for a
// stale bind mount and wrong for a PERMANENTLY wrong one: rejection, three
// probes, exit 3, restart into the same bytes, rejection, … — a crash loop §11
// forbids, and the guard being down is exactly what takes the Node and Security
// pages' diagnosis away. These tests hold the memory that breaks the loop.

// fastProbes is the options every test here runs a serving guard under: probes
// that do not make the test wait, and an exit delay that does not either.
func fastProbes(opts guard.Options) guard.Options {
	opts.ProbeInterval = 2 * time.Millisecond
	if opts.Sleep == nil {
		opts.Sleep = func(context.Context, time.Duration) error { return nil }
	}
	return opts
}

// serving is a guard running Serve over the socket, with Serve's result
// observable — serveGuard discards it, and whether Serve RETURNED is the claim.
type serving struct {
	client *guard.SocketClient
	done   chan error
}

func startServing(t *testing.T, g *guard.Guard) serving {
	t.Helper()
	socket := socketPath(t)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	s := serving{client: guard.NewSocketClient(socket, guard.DiscardEvents), done: make(chan error, 1)}
	go func() { s.done <- g.Serve(ctx, socket) }()
	lndtest.WaitFor(t, "the socket to accept", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})
	return s
}

// waitForExit is the rotation exit, or the test's failure to see one.
func (s serving) waitForExit(t *testing.T, why string) {
	t.Helper()
	select {
	case err := <-s.done:
		if !errors.Is(err, guard.ErrMacaroonRotated) {
			t.Fatalf("Serve = %v, want ErrMacaroonRotated (%s)", err, why)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the guard did not take its rotation exit: %s", why)
	}
}

// waitForDegraded waits for the kind to reach Status over the socket — and fails
// AS THE CRASH LOOP, not as a timeout, if Serve returns first.
func (s serving) waitForDegraded(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-s.done:
			t.Fatalf("Serve returned %v on the second rejection run over the same bytes; that is "+
				"the crash loop — restarting into the same bad file cannot fix it", err)
		default:
		}
		if status, err := s.client.Status(t.Context()); err == nil &&
			status.RefusalKind == guard.KindAdminMacaroonStillRejected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("Status never carried %q", guard.KindAdminMacaroonStillRejected)
}

// exitForRotation drives a fresh guard over d through its one sanctioned exit,
// the way production reaches it: one rejection from outside, the rest its own
// probes. The node must already be rejecting.
func exitForRotation(t *testing.T, node *lndtest.Node, d dirs, opts guard.Options) {
	t.Helper()
	g := openGuard(t, node, d, fastProbes(opts))
	s := startServing(t, g)
	_ = g.Handle(t.Context(), guard.Request{Op: guard.OpBakeReceive})
	s.waitForExit(t, "the first rejection run, which is the one exit §6 sanctions")
}

// storedState reads guard-state.json the way a restarted guard would find it.
func storedState(t *testing.T, d dirs) guard.State {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(d.data, "guard-state.json"))
	if err != nil {
		t.Fatalf("reading the guard's state: %v", err)
	}
	var st guard.State
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("parsing the guard's state: %v", err)
	}
	return st
}

// mountedIdentity is the content hash of what is mounted at the guard's
// admin-macaroon path right now.
func mountedIdentity(t *testing.T, d dirs) string {
	t.Helper()
	raw, err := os.ReadFile(d.admin)
	if err != nil {
		t.Fatalf("reading the mounted admin macaroon: %v", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func auditCount(st guard.State, event logging.Event) int {
	n := 0
	for _, e := range st.RecentAudit {
		if e.Event == event {
			n++
		}
	}
	return n
}

// lockedBuffer is a log sink a test can read while the guard's goroutines are
// still writing to it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func capturedLog() (*slog.Logger, *lockedBuffer) {
	sink := &lockedBuffer{}
	return slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug})), sink
}

// The exit is written down BEFORE the process leaves: the settling delay is the
// last thing Serve does, so the state is read from inside it. A memory written
// after — or never, because the write raced the exit — is no memory at all.
func TestTheRotationExitIsRecordedBeforeTheGuardExits(t *testing.T) {
	node := lndtest.Start(t)
	node.SetReject(true)
	d := guardDirs(t, node)
	log, sink := capturedLog()

	// Read raw inside the hook and parsed afterwards: the hook runs on Serve's
	// goroutine, where t.Fatal is not allowed.
	var atExit []byte
	var sleptOnce sync.Once
	exitForRotation(t, node, d, guard.Options{
		Log: log,
		Sleep: func(context.Context, time.Duration) error {
			sleptOnce.Do(func() { atExit, _ = os.ReadFile(filepath.Join(d.data, "guard-state.json")) })
			return nil
		},
	})

	var st guard.State
	if err := json.Unmarshal(atExit, &st); err != nil {
		t.Fatalf("the state file at the moment of exit did not parse (%v): %q", err, atExit)
	}
	exit := st.RotationExit
	if exit == nil {
		t.Fatal("the guard exited for rotation with nothing in guard-state.json saying so; the " +
			"restart cannot tell its second rejection run from its first, and a wrong mount " +
			"crash-loops")
	}
	if want := mountedIdentity(t, d); exit.MountedSHA256 != want {
		t.Errorf("the recorded identity is %q, want the hash of the mounted file %q", exit.MountedSHA256, want)
	}
	if exit.At.IsZero() {
		t.Error("the recorded exit carries no time")
	}
	// A hash of a secret is still about a secret (§11): it lives in the state
	// file, in a volume the server has no mount for, and never in a log line.
	if strings.Contains(sink.String(), exit.MountedSHA256) {
		t.Error("the admin macaroon's hash reached the guard's log")
	}
}

// The heart of it: a restart that changed nothing gets no second exit.
//
// OVER THE SOCKET, so the kind is read where the server reads it — knownKind
// drops a token the build does not list, and a Status that set the kind in
// process and lost it on the wire would leave every page test green.
func TestASecondRejectionRunOverTheSameBytesDoesNotExitAgain(t *testing.T) {
	node := lndtest.Start(t)
	node.SetReject(true)
	d := guardDirs(t, node)
	exitForRotation(t, node, d, guard.Options{})

	// The restart: the same volumes, the same mounted bytes, a node that still
	// rejects them.
	g := openGuard(t, node, d, fastProbes(guard.Options{}))
	s := startServing(t, g)
	_ = g.Handle(t.Context(), guard.Request{Op: guard.OpBakeReceive})

	s.waitForDegraded(t)
	status, err := s.client.Status(t.Context())
	if err != nil {
		t.Fatalf("Status over the socket: %v", err)
	}
	if status.LNDReachable {
		t.Error("Status says LND is reachable while the node rejects the guard's credential")
	}

	// THE PROBE LOOP GOES ON, which is also the proof there was no exit: the loop
	// returns once rotation is declared, so rejected probes still arriving after
	// the transition mean it was not. Nothing else calls the node from here on.
	seen := len(node.SeenMacaroons())
	lndtest.WaitFor(t, "the probe loop to keep probing past the threshold", func() bool {
		return len(node.SeenMacaroons()) >= seen+3*guard.DefaultRotationThreshold
	})
	select {
	case err := <-s.done:
		t.Fatalf("Serve returned %v on the second rejection run over the same bytes; that is the "+
			"crash loop — restarting into the same bad file cannot fix it", err)
	default:
	}

	st := storedState(t, d)
	if st.RotationExit == nil {
		t.Error("the memory was cleared although nothing succeeded; the next restart would exit again")
	}
	if n := auditCount(st, logging.EventPreflightRefuse); n != 1 {
		t.Errorf("preflight.refuse raised %d times across the degraded run, want exactly 1 at the "+
			"transition — every further probe is the same finding", n)
	}
	if n := auditCount(st, logging.EventMacaroonRotate); n != 1 {
		t.Errorf("macaroon.rotate raised %d times, want 1: the first run's exit, and no second", n)
	}
}

// The identity is what tells "unchanged" from "changed and also wrong". A node
// that rotated again while the guard restarted presents DIFFERENT bad bytes, and
// one more exit is exactly the repair — so a memory keyed on time alone would
// sit degraded where §6's recovery works.
//
// BOTH SHAPES, because the check happens in two places: at start (the restart
// re-resolved the mount onto a new file) and at the threshold (the file changed
// in place while the guard ran). Either alone passes with the other broken.
func TestAChangedAdminMacaroonGetsItsOwnExit(t *testing.T) {
	t.Run("changed before the restart", func(t *testing.T) {
		node := lndtest.Start(t)
		node.SetReject(true)
		d := guardDirs(t, node)
		exitForRotation(t, node, d, guard.Options{})

		lndtest.WriteFile(t, d.admin, []byte{0xad, 0x22, 0x22, 0x22})
		log, sink := capturedLog()
		g := openGuard(t, node, d, fastProbes(guard.Options{Log: log}))
		if st := storedState(t, d); st.RotationExit != nil {
			t.Error("the guard started over a different admin macaroon and kept the memory of " +
				"the old one")
		}
		if !strings.Contains(sink.String(), "has changed since") {
			t.Errorf("no line says the changed mount was noticed; the operator's evidence that "+
				"their fix registered is missing:\n%s", sink.String())
		}

		s := startServing(t, g)
		_ = g.Handle(t.Context(), guard.Request{Op: guard.OpBakeReceive})
		s.waitForExit(t, "a different file, still rejected, is a new rotation and gets its one exit")
		if st := storedState(t, d); st.RotationExit == nil || st.RotationExit.MountedSHA256 != mountedIdentity(t, d) {
			t.Errorf("the second exit recorded %+v, want the identity of the file now mounted", st.RotationExit)
		}
	})

	t.Run("changed in place while the guard runs", func(t *testing.T) {
		node := lndtest.Start(t)
		node.SetReject(true)
		d := guardDirs(t, node)
		exitForRotation(t, node, d, guard.Options{})

		g := openGuard(t, node, d, fastProbes(guard.Options{}))
		lndtest.WriteFile(t, d.admin, []byte{0xad, 0x33, 0x33, 0x33})
		s := startServing(t, g)
		_ = g.Handle(t.Context(), guard.Request{Op: guard.OpBakeReceive})
		s.waitForExit(t, "the bytes the node is rejecting now are not the ones the last exit was about")
	})
}

// The memory never outlives a success: a node that accepts this credential has
// nothing to remember about it. And the loop that observes the fix is the probe
// loop itself — nothing else calls in until the memory is gone.
//
// WRITES ARE COUNTED FROM THE FILE, not the code: the state is replaced by an
// atomic rename, so a write is a new inode, and os.SameFile says whether one
// happened. A healthy guard must never write on success — Status runs per page
// render, and an fsync per render is a cost nobody would see arrive.
func TestASuccessClearsTheMemoryOnceAndAHealthyGuardNeverWrites(t *testing.T) {
	node := lndtest.Start(t)
	node.SetReject(true)
	d := guardDirs(t, node)
	exitForRotation(t, node, d, guard.Options{})

	g := openGuard(t, node, d, fastProbes(guard.Options{}))
	s := startServing(t, g)
	_ = g.Handle(t.Context(), guard.Request{Op: guard.OpBakeReceive})
	s.waitForDegraded(t)

	// The operator fixes the mount in place; the next PROBE sees it.
	node.SetReject(false)
	lndtest.WaitFor(t, "the probe loop to clear the memory", func() bool {
		return storedState(t, d).RotationExit == nil
	})
	status, err := s.client.Status(t.Context())
	if err != nil {
		t.Fatalf("Status over the socket: %v", err)
	}
	if status.RefusalKind != "" || !status.LNDReachable {
		t.Errorf("after the node accepted the credential, Status = kind %q reachable %v; want no "+
			"kind and reachable — the page would go on accusing a mount that is fixed",
			status.RefusalKind, status.LNDReachable)
	}

	// The receive credential was never baked while the node rejected everything;
	// baking it now is a legitimate write, so it happens before the baseline.
	if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon on a healthy node: %v", err)
	}
	path := filepath.Join(d.data, "guard-state.json")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if _, err := s.client.Status(t.Context()); err != nil {
			t.Fatalf("Status: %v", err)
		}
	}
	if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon on a healthy node: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Error("guard-state.json was rewritten by successful calls to a healthy node; clearing " +
			"the memory must write only when there is a memory to clear")
	}
	select {
	case err := <-s.done:
		t.Fatalf("Serve returned %v on a guard whose node accepts it", err)
	default:
	}
}

// Losing the memory must not cost the recovery: a state file that cannot be
// written is logged, and the exit a rotation needs still happens. The failure
// mode of a failed write is today's behaviour, never a guard stuck up.
func TestAStateWriteThatFailsDoesNotStopTheRotationExit(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through directory permissions; this needs a write that fails")
	}
	node := lndtest.Start(t)
	node.SetReject(true)
	d := guardDirs(t, node)
	g := openGuard(t, node, d, fastProbes(guard.Options{}))
	if err := os.Chmod(d.data, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(d.data, 0o700) })

	s := startServing(t, g)
	_ = g.Handle(t.Context(), guard.Request{Op: guard.OpBakeReceive})
	s.waitForExit(t, "a rotation with an unwritable state file is still a rotation")
}
