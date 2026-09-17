package guard_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
)

// dqd. LND refuses a macaroon it will not accept with code Unknown — and refuses
// EVERY call with code Unknown while it is starting or its wallet is locked,
// because its state interceptor runs before its macaroon interceptor
// (rpcperms/interceptor.go, v0.21.2-beta). On the wire the two are one answer.
// So the probe asks the node's State service first, and only a node in a stage
// that lets a call reach the macaroon check can have its refusal counted.

// rejectedLine is the WARN a counted rejection writes, matched as the whole
// message: the exit's audit line starts with the same words.
const rejectedLine = "lnd rejected admin.macaroon"

func rejectedLines(t *testing.T, log string) int {
	t.Helper()
	n := 0
	for line := range strings.SplitSeq(log, "\n") {
		if line == "" {
			continue
		}
		var r struct{ Msg string }
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("a log line is not JSON: %q", line)
		}
		if r.Msg == rejectedLine {
			n++
		}
	}
	return n
}

// However long it lasts, and whatever the macaroon call would say: the fake
// rejects like LND AND is not ready, and LND never gets as far as the macaroon.
// Before dqd's second ruling this was one needless exit and then a hold with a
// Security row blaming a mount that is fine.
func TestANodeThatIsNotReadyIsNeverCountedAsARotation(t *testing.T) {
	for _, state := range []lnrpc.WalletState{
		lnrpc.WalletState_LOCKED,
		lnrpc.WalletState_UNLOCKED,
		lnrpc.WalletState_WAITING_TO_START,
		lnrpc.WalletState_NON_EXISTING,
	} {
		t.Run(state.String(), func(t *testing.T) {
			node := lndtest.Start(t)
			node.SetWalletState(state)
			node.SetRejectLikeLND(true)
			d := guardDirs(t, node)
			log, sink := capturedLog()
			g := openGuard(t, node, d, fastProbes(guard.Options{Log: log}))
			s := startServing(t, g)
			// Arms the loop: the node refuses with Unknown, which is a rejection
			// code — the probe is what decides it was not about the credential.
			_ = g.Handle(t.Context(), guard.Request{Op: guard.OpBakeReceive})

			lndtest.WaitFor(t, "the probe loop to ask the node's stage many times over", func() bool {
				// An exit ends the loop, so it would otherwise surface as this
				// wait timing out; failing here names it.
				s.assertStillServing(t)
				calls, _ := node.StateCalls()
				return calls >= 10*guard.DefaultRotationThreshold
			})
			s.assertStillServing(t)
			if st := readGuardState(t, d.data); st.RotationExit != nil {
				t.Errorf("a node in %s was recorded as a rotation exit: %+v", state, st.RotationExit)
			}
			if n := rejectedLines(t, sink.String()); n != 0 {
				t.Errorf("%q logged %d times for a node in %s, which never looked at the macaroon",
					rejectedLine, n, state)
			}
			status, err := s.client.Status(t.Context())
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if status.RefusalKind != "" {
				t.Errorf("Status carries kind %q for a node that is not ready", status.RefusalKind)
			}
		})
	}
}

// The other half: both stages checkRPCState admits let a rejection count. A node
// in RPC_ACTIVE answers GetInfo and refuses a bad macaroon like any other, so
// counting only SERVER_ACTIVE would miss a rotation for as long as that lasts.
func TestARejectionCountsInBothStagesThatAdmitCalls(t *testing.T) {
	for _, state := range []lnrpc.WalletState{lnrpc.WalletState_RPC_ACTIVE, lnrpc.WalletState_SERVER_ACTIVE} {
		t.Run(state.String(), func(t *testing.T) {
			node := lndtest.Start(t)
			node.SetWalletState(state)
			node.SetRejectLikeLND(true)
			d := guardDirs(t, node)
			log, sink := capturedLog()
			exitForRotation(t, node, d, guard.Options{Log: log})
			// Once per run, from the probe that knows the stage — not once per
			// probe, and not from every caller that saw a refusal.
			if n := rejectedLines(t, sink.String()); n != 1 {
				t.Errorf("%q logged %d times across one rejection run, want 1:\n%s",
					rejectedLine, n, sink.String())
			}
		})
	}
}

// Our own client failing to read admin.macaroon still arms and counts. That is
// what the guard sees when the mount's source is deleted and reads as absent —
// Docker Desktop on macOS, which is how rotation.sh passes there — and grpc-go
// reports it as Unauthenticated before anything is sent.
//
// The REAL failure, not SetReject's imitation of it: the file is removed. Warm
// first, because that is the production shape and the only one where the error
// is a status at all — a client that has never dialled refuses with
// ErrNotLinked instead, which is no answer from any node.
func TestAnAdminMacaroonTheGuardCanNoLongerReadIsStillARejection(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuard(t, node, d, fastProbes(guard.Options{}))
	s := startServing(t, g)

	if err := os.Remove(d.admin); err != nil {
		t.Fatal(err)
	}
	_ = g.Handle(t.Context(), guard.Request{Op: guard.OpBakeReceive})
	s.waitForExit(t, "a guard that can no longer read its admin macaroon must still take the exit "+
		"that re-resolves the mount")
	if len(node.SeenMacaroons()) == 0 {
		t.Fatal("the node never saw the guard's macaroon, so the connection was never warm and " +
			"this test did not reach the per-RPC credential")
	}
}

// Status says WHICH stage the node is in when the guard cannot reach it, as a
// value — over the socket, so the seam to the server is what is asserted.
func TestStatusCarriesTheNodesStageWhenTheGuardCannotReachIt(t *testing.T) {
	node := lndtest.Start(t)
	g, _ := newGuard(t, node)
	client := serveGuard(t, g)

	node.SetWalletState(lnrpc.WalletState_LOCKED)
	status, err := client.Status(t.Context())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.LNDReachable || status.NodeWalletState != lnd.WalletLocked {
		t.Errorf("with the wallet locked, Status = reachable %v, stage %q; want unreachable, %q",
			status.LNDReachable, status.NodeWalletState, lnd.WalletLocked)
	}

	node.SetWalletState(lnrpc.WalletState_SERVER_ACTIVE)
	status, err = client.Status(t.Context())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	// Not asked when the node answered: a stage beside "reachable" says nothing.
	if !status.LNDReachable || status.NodeWalletState != "" {
		t.Errorf("with the node answering, Status = reachable %v, stage %q; want reachable, no stage",
			status.LNDReachable, status.NodeWalletState)
	}
}

// "The credential was not rotated after all" is a sentence about a rejection the
// probe COUNTED. Arming is broad since dqd — a node that is starting refuses the
// middleware registration and Status with code Unknown, so every LND restart arms
// the loop — and a success after nothing was counted must not tell an operator
// reading the log that a rotation had been suspected.
func TestTheNotRotatedAfterAllLineFollowsOnlyACountedRejection(t *testing.T) {
	const recovered = "lnd is answering again; the credential was not rotated after all"
	// Slow enough that one counted rejection cannot become three before the
	// node is put right, which would be an exit rather than this line.
	const interval = 40 * time.Millisecond

	t.Run("the node was starting", func(t *testing.T) {
		node := lndtest.Start(t)
		d := guardDirs(t, node)
		log, sink := capturedLog()
		g := openGuard(t, node, d, fastProbes(guard.Options{Log: log, ProbeInterval: interval}))
		s := startServing(t, g)

		node.SetWalletState(lnrpc.WalletState_WAITING_TO_START)
		_ = g.Handle(t.Context(), guard.Request{Op: guard.OpBakeReceive})
		lndtest.WaitFor(t, "a probe to find the node not ready", func() bool {
			calls, _ := node.StateCalls()
			return calls >= 2
		})
		seen := len(node.SeenMacaroons())
		node.SetWalletState(lnrpc.WalletState_SERVER_ACTIVE)
		lndtest.WaitFor(t, "a probe to find the node accepting the credential", func() bool {
			return len(node.SeenMacaroons()) > seen
		})
		// The line would be written straight after that probe returns; the next
		// ticks are the proof the loop has gone quiet, so it had its chance.
		time.Sleep(5 * interval)
		s.assertStillServing(t)
		if strings.Contains(sink.String(), recovered) {
			t.Errorf("a node that was only starting was reported as a rotation that was not:\n%s", sink.String())
		}
	})

	t.Run("the node refused the credential", func(t *testing.T) {
		node := lndtest.Start(t)
		d := guardDirs(t, node)
		log, sink := capturedLog()
		g := openGuard(t, node, d, fastProbes(guard.Options{Log: log, ProbeInterval: interval}))
		s := startServing(t, g)

		node.SetRejectLikeLND(true)
		_ = g.Handle(t.Context(), guard.Request{Op: guard.OpBakeReceive})
		lndtest.WaitFor(t, "a probe to count a rejection", func() bool {
			return rejectedLines(t, sink.String()) == 1
		})
		node.SetRejectLikeLND(false)
		lndtest.WaitFor(t, "the recovery line", func() bool {
			s.assertStillServing(t)
			return strings.Contains(sink.String(), recovered)
		})
	})
}
