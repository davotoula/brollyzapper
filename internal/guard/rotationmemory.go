package guard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/davotoula/brollyzapper/internal/logging"
)

// The rotation exit's memory (as0.10). Why it exists is on RotationExit.
//
// The brief's table, as code: at the threshold, the SAME bytes as the recorded
// exit hold the exit (holdExit); anything else records this exit and takes it
// (recordRotationExit); any success forgets it (nodeAccepted); and a start over
// a different file forgets it early, for the log line (forgetExitOverAnotherFile).

// recordRotationExit decides and records in one read-modify-write: it returns
// the recorded exit when this rejection run is over the very bytes that exit
// was taken over, and otherwise records this one and returns nil — the caller
// then exits.
//
// Asked once per probe while held: a file read and a state read every
// ProbeInterval, and it is what lets a file changed IN PLACE still get its exit.
//
// "CANNOT TELL" MEANS EXIT, as before as0.10. An unreadable mount has no
// identity to compare, and a state file that will not load or save cannot hold
// the memory; withholding the one recovery a real rotation has on a guess would
// trade a lap of a loop for a guard that never recovers. So a failed write is
// logged and the exit still happens — the next run then behaves as every run
// did before as0.10. The mount cannot be unreadable for long here anyway: the
// node only rejects a macaroon it was sent.
func (g *Guard) recordRotationExit() *RotationExit {
	identity := g.mountedIdentity()
	at := g.rotation.clock()
	var held *RotationExit
	err := g.state.updateIf(func(st *State) bool {
		if identity != "" && st.RotationExit != nil && st.RotationExit.MountedSHA256 == identity {
			held = st.RotationExit
			return false
		}
		st.RotationExit = &RotationExit{At: at, MountedSHA256: identity}
		return true
	})
	if err != nil {
		g.log.Error("could not record the rotation exit; if the restart finds the same file the "+
			"node rejects, it will exit again", "error", err.Error())
	}
	return held
}

// holdExit is the guard staying up instead of exiting a second time: the restart
// re-resolved nothing, so this is not a rotation, and another restart would be
// the crash loop §11 forbids. It says so through Status and one audit event per
// transition, and the probe loop goes on — a success is what ends it.
func (g *Guard) holdExit(ctx context.Context, exit *RotationExit) {
	if !g.holdingExit.CompareAndSwap(false, true) {
		return
	}
	// Through the auditor, so it reaches the Security page's trail. The time of
	// the earlier exit is not a secret and is the operator's evidence that this
	// is the second lap; the hash never appears.
	g.audit(ctx, slog.LevelWarn, "lnd still rejects admin.macaroon, and the file mounted into "+
		"the guard is the one it rejected before the last rotation restart: this is not a "+
		"rotation, so the guard is staying up. mount the node's current admin.macaroon, then "+
		"restart the guard",
		logging.EventPreflightRefuse, map[string]string{
			"exited_for_rotation_at": exit.At.UTC().Format(time.RFC3339),
		})
}

// refusalKind is Status's one kind field: the held exit while there is one, the
// last bake refusal otherwise. The held exit wins because while it holds no bake
// can succeed or be refused for its address — both need the node to answer.
func (g *Guard) refusalKind() ErrorKind {
	if g.holdingExit.Load() {
		return KindAdminMacaroonStillRejected
	}
	return g.lastRefusalKind()
}

// nodeAccepted is every observation that the node accepted admin.macaroon.
//
// It clears the memory along with the detector's run: a node that accepts this
// credential has nothing to remember about it. Through updateIf, because this
// runs on every successful call — every Status, so every uncached page render —
// and a healthy guard with no memory must not pay an fsync for each one.
func (g *Guard) nodeAccepted() {
	g.rotation.Success()
	g.holdingExit.Store(false)
	if err := g.state.updateIf(func(st *State) bool {
		if st.RotationExit == nil {
			return false
		}
		st.RotationExit = nil
		return true
	}); err != nil {
		g.log.Warn("could not clear the record of the last rotation exit", "error", err.Error())
	}
}

// forgetExitOverAnotherFile clears the memory at start when the file mounted now
// is not the one the guard exited over — the restart re-resolved the mount onto
// something new, so what the memory was about is gone.
//
// Done at start for the LINE, not for the decision: recordRotationExit compares
// the identity itself, so a guard that skipped this would still exit correctly.
// The line is the operator's evidence that the fix they made was noticed, and it
// comes before anything the node says about the new file.
//
// An unreadable mount leaves the memory alone: unknown is not changed.
func (g *Guard) forgetExitOverAnotherFile() {
	identity := g.mountedIdentity()
	if identity == "" {
		return
	}
	var exitedAt time.Time
	if err := g.state.updateIf(func(st *State) bool {
		if st.RotationExit == nil || st.RotationExit.MountedSHA256 == identity {
			return false
		}
		exitedAt = st.RotationExit.At
		st.RotationExit = nil
		return true
	}); err != nil {
		g.log.Warn("could not read or clear the record of the last rotation exit", "error", err.Error())
		return
	}
	if !exitedAt.IsZero() {
		g.log.Info("the admin.macaroon mounted into the guard has changed since the guard exited "+
			"for rotation; the next rejection, if any, is treated as a new rotation",
			"exited_for_rotation_at", exitedAt.UTC().Format(time.RFC3339))
	}
}

// mountedIdentity is the content hash of admin.macaroon as the node client reads
// it, or "" when it cannot be read — through the client's own source, so an empty
// or missing file is "cannot tell" here exactly as it is not-linked there. See
// RotationExit.MountedSHA256.
func (g *Guard) mountedIdentity() string {
	raw, err := g.adminMacaroon.Macaroon()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
