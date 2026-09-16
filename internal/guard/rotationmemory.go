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
// The brief's table, as code: at the threshold, recordRotationExit holds the exit
// over the SAME bytes as the recorded one and otherwise records this exit for the
// caller to take; any success forgets it (nodeAccepted); and a start over a
// different file forgets it early, for the log line (forgetExitOverAnotherFile).

// exitOutcome is what a rejection run past the threshold comes to.
type exitOutcome int

const (
	// exitTake: recorded (or, with no identity, not recorded); the caller exits.
	exitTake exitOutcome = iota
	// exitHoldBegins: the same bytes as the recorded exit, and this call began
	// the hold — the caller raises the one audit event.
	exitHoldBegins
	// exitHeld: the same bytes, already held.
	exitHeld
	// exitStale: the node accepted a call after this probe was sent, so its
	// rejection is not current evidence of anything.
	exitStale
)

type exitDecision struct {
	outcome  exitOutcome
	exitedAt time.Time // the recorded exit's time, on exitHoldBegins
}

// recordRotationExit decides and records in one read-modify-write, UNDER THE
// STATE LOCK — which nodeAccepted also takes — so a success and a rejection run
// cannot interleave inside the decision (go-review M1: the hold used to be set
// after the lock, and a success landing in between left it set against a node
// that accepts, with a durable row saying otherwise). sent is g.acceptances as it
// stood when the probe went out; nodeAccepted bumps it BEFORE taking the lock, so
// a success that landed while the probe was out is always seen here.
//
// Asked once per probe while held: a file read and a state read every
// ProbeInterval, and it is what lets a file changed IN PLACE still get its exit.
//
// "CANNOT TELL" MEANS EXIT, as before as0.10. An unreadable mount has no
// identity to compare, and a state file that will not load or save cannot hold
// the memory; withholding the one recovery a real rotation has on a guess would
// trade a lap of a loop for a guard that never recovers. So a failed write is
// logged and the exit still happens — the next run then behaves as every run
// did before as0.10. An unreadable mount records nothing either: the memory it
// already holds stays, rather than being replaced by an identity that can never
// match (go-review L1). It cannot be unreadable for long anyway: the node only
// rejects a macaroon it was sent.
func (g *Guard) recordRotationExit(sent uint64) exitDecision {
	identity := g.mountedIdentity()
	at := g.rotation.clock()
	d := exitDecision{outcome: exitTake}
	err := g.state.updateIf(func(st *State) bool {
		switch {
		case g.acceptances.Load() != sent:
			d.outcome = exitStale
			return false
		case identity == "":
			return false
		case st.RotationExit != nil && st.RotationExit.MountedSHA256 == identity:
			d.outcome = exitHeld
			if g.holdingExit.CompareAndSwap(false, true) {
				d = exitDecision{outcome: exitHoldBegins, exitedAt: st.RotationExit.At}
			}
			return false
		}
		st.RotationExit = &RotationExit{At: at, MountedSHA256: identity}
		return true
	})
	if err != nil {
		g.log.Error("could not record the rotation exit; if the restart finds the same file the "+
			"node rejects, it will exit again", "error", err.Error())
	}
	return d
}

// auditHold is the one event for the guard staying up instead of exiting a second
// time: the restart re-resolved nothing, so this is not a rotation, and another
// restart would be the crash loop §11 forbids. The probe loop goes on — a success
// is what ends the hold.
//
// Through the auditor, so it reaches the Security page's trail. The time of the
// earlier exit is not a secret and is the operator's evidence that this is the
// second lap; the hash never appears.
func (g *Guard) auditHold(ctx context.Context, exitedAt time.Time) {
	g.audit(ctx, slog.LevelWarn, "lnd still rejects admin.macaroon, and the file mounted into "+
		"the guard is the one it rejected before the last rotation restart: this is not a "+
		"rotation, so the guard is staying up. mount the node's current admin.macaroon, then "+
		"restart the guard",
		logging.EventPreflightRefuse, map[string]string{
			"exited_for_rotation_at": exitedAt.UTC().Format(time.RFC3339),
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
//
// THE ORDER IS THE POINT (go-review M1): the count first, so any rejection sent
// before this success reads as stale; the hold reset INSIDE the lock
// recordRotationExit decides under, so a hold that began just before cannot be
// set again just after.
func (g *Guard) nodeAccepted() {
	g.acceptances.Add(1)
	g.rotation.Success()
	if err := g.state.updateIf(func(st *State) bool {
		g.holdingExit.Store(false)
		if st.RotationExit == nil {
			return false
		}
		st.RotationExit = nil
		return true
	}); err != nil {
		// The state would not load, so no decision can have run under the lock
		// either; the hold still ends, because the node answered.
		g.holdingExit.Store(false)
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
