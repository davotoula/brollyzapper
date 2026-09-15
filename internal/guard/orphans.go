package guard

import (
	"context"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/davotoula/brollyzapper/internal/logging"
)

// sidecarOf reads the root key id a credential's sidecar names (2o1), and whether
// the credential file itself is on disk.
//
// A SIDECAR COUNTS ONLY BESIDE ITS CREDENTIAL. RevokeSpend removes spend.macaroon
// and leaves the sidecar, and a sidecar naming a revoked-and-failed key would
// otherwise spare that key for ever; with no file there is nothing it protects.
//
// A missing or unreadable sidecar beside a present credential names nothing
// (id 0), is said once per process and credential, and is never fatal: every
// install upgrading to this build has credentials and no sidecars until each is
// next baked. What the unattended sweep DOES with that answer is sweepOrphans's
// decision, not this function's.
func (g *Guard) sidecarOf(c credential) (id uint64, present bool) {
	if !g.credentialExists(c.file) {
		return 0, false
	}
	path := g.credentialPath(c.file) + RootKeySidecarSuffix
	raw, err := os.ReadFile(path)
	if err != nil {
		g.noteSidecar(c, "the "+c.kind+" credential has no root key sidecar yet; the unattended "+
			"root key sweep waits for its next bake, which writes one", slog.LevelInfo, err)
		return 0, true
	}
	id, err = strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || id == 0 {
		g.noteSidecar(c, "the "+c.kind+" credential's root key sidecar is unreadable; the "+
			"unattended root key sweep waits for its next bake, which rewrites it", slog.LevelWarn, err)
		return 0, true
	}
	return id, true
}

// noteSidecar says a sidecar problem once per credential kind for the life of the
// process. A sweep runs every hour, and the answer does not change until a bake.
func (g *Guard) noteSidecar(c credential, msg string, level slog.Level, err error) {
	if _, said := g.sidecarNoted.LoadOrStore(c.kind, true); said {
		return
	}
	attrs := []any{"kind", c.kind}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	g.log.Log(context.Background(), level, msg, attrs...)
}

// sidecarRootKeys is every root key id the named credentials' sidecars name, for
// the sweeps to spare.
func (g *Guard) sidecarRootKeys(credentials ...credential) []uint64 {
	var ids []uint64
	for _, c := range credentials {
		if id, _ := g.sidecarOf(c); id != 0 {
			ids = append(ids, id)
		}
	}
	return ids
}

// sweepOrphans revokes, with no operator present, every pending root key that no
// credential on disk can depend on (2o1).
//
// WHY IT EXISTS. tna.5 G3 records a superseded or failed-bake key as pending so a
// later sweep can revoke it, but the sweeps ran only inside a bake and RevokeSpend.
// On a receive-only install nobody presses either, and a key a failed bake left
// live stayed live at the node until it expired.
//
// WHY WAVE 30'S VERSION WAS REMOVED, and what is different. A bake that dies
// between writing the credential and writing the state leaves the state naming
// the PREVIOUS key while the file was baked under the NEW one, which is pending.
// A sweep that trusted the state revoked the key the live credential depended on,
// on every restart, under a green UI. The guard cannot read a macaroon's key
// (ADR 0001), so bake now writes the id beside the file before the file itself,
// and this sweep never revokes an id that the state names as current OR that
// either credential's sidecar names.
//
// A CREDENTIAL WITH NO SIDECAR STOPS THE SWEEP. The bead's acceptance is that
// this cannot revoke a key a credential on disk depends on, and beside a file with
// no sidecar — an install upgraded from before sidecars — the guard has no way to
// tell that file's key from an orphan: it is exactly G3's window, crashed into
// before the upgrade. So it revokes nothing and waits for that credential's next
// bake, whose own sweep runs with a sidecar written. That is today's behaviour for
// those keys and never more aggressive. (The brief asked for the state-only rule
// here; this is the stricter reading, reported.)
//
// UNDER bakeMu, for the reason bake is: a sweep interleaved with a bake could read
// the pending set before the bake records its new key and revoke it after the file
// is written.
//
// ONE AUDIT ROW per sweep that revoked something, naming how many — not one per
// key, because this runs every hour and a row per key is the trail filling itself.
// No kind per id: a pending id does not record which credential it was minted for,
// and a row that guessed would be wrong exactly when it mattered.
func (g *Guard) sweepOrphans(ctx context.Context) {
	g.bakeMu.Lock()
	defer g.bakeMu.Unlock()
	state, err := g.state.load()
	if err != nil {
		g.log.Warn("could not read the guard's state to sweep orphaned root keys; will try again",
			"error", err.Error())
		return
	}
	if len(state.PendingRootKeyIDs) == 0 {
		return
	}
	spare := []uint64{state.ReceiveRootKeyID, state.SpendRootKeyID}
	for _, c := range []credential{receiveCredential, spendCredential} {
		id, present := g.sidecarOf(c)
		if present && id == 0 {
			return
		}
		spare = append(spare, id)
	}

	swept := state.PendingRootKeyIDs
	kept, revoked := g.sweepPending(ctx, "orphaned", swept, 0, spare, false)
	// Forgets only what THIS sweep saw go, inside the update's own read: nothing
	// else can add to the set while bakeMu is held, but the closure is where the
	// state is current, so it is where the decision is made. updateIf, so a pass
	// that forgot nothing — every id spared, or the node unreachable — does not
	// rewrite the state file on an SD card every hour.
	if err := g.state.updateIf(func(st *State) bool {
		before := len(st.PendingRootKeyIDs)
		st.PendingRootKeyIDs = slices.DeleteFunc(st.PendingRootKeyIDs, func(id uint64) bool {
			return slices.Contains(swept, id) && !slices.Contains(kept, id)
		})
		return len(st.PendingRootKeyIDs) != before
	}); err != nil {
		g.log.Warn("could not forget the swept pending root keys", "error", err.Error())
	}
	if revoked > 0 {
		g.audit(ctx, slog.LevelInfo, "orphaned root keys revoked", logging.EventMacaroonRevoke,
			map[string]string{
				"count":  strconv.Itoa(revoked),
				"reason": "keys an interrupted or superseded bake left at the node, which no credential on disk uses",
			})
	}
}
