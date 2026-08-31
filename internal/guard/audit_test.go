package guard_test

import (
	"os"
	"testing"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// d46.18 criterion 3, the "not lost" half. The guard cannot learn whether the
// server stored a report, so it keeps reporting — including after a restart,
// which its own rotation path performs deliberately. The event survives in the
// guard's OWN state file: it writes to nothing the server owns (§16).
func TestTheGuardKeepsReportingItsEventsAcrossARestart(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	ctx := t.Context()

	first := openGuard(t, node, d, guard.Options{})
	if err := first.EnsureReceiveMacaroon(ctx); err != nil {
		t.Fatalf("EnsureReceiveMacaroon: %v", err)
	}
	before := bakeEvents(t, first.Handle(ctx, guard.Request{Op: guard.OpStatus}).Events)
	if len(before) != 1 {
		t.Fatalf("the guard reported %d bake events after baking once, want 1", len(before))
	}
	if before[0].ID == "" {
		t.Error("the reported event carries no id; the server could not tell a redelivery " +
			"from a new event and would append a row per poll")
	}
	if err := first.Close(); err != nil {
		t.Fatalf("closing the first guard: %v", err)
	}

	// A restart. The credential is already in the volume, so nothing is re-baked
	// — the event has to come from the state file or not at all.
	second := openGuard(t, node, d, guard.Options{})
	if err := second.EnsureReceiveMacaroon(ctx); err != nil {
		t.Fatalf("EnsureReceiveMacaroon after the restart: %v", err)
	}
	after := bakeEvents(t, second.Handle(ctx, guard.Request{Op: guard.OpStatus}).Events)
	if len(after) != 1 || after[0].ID != before[0].ID {
		t.Fatalf("after a restart the guard reported %d bake events %v, want the same one (%s)",
			len(after), ids(after), before[0].ID)
	}
}

// The dedup id must not survive a wiped DATA_DIR. A guard that has lost its
// state re-bakes, and that bake is a NEW event — an id that collided with the
// server's record of the previous guard would silently dedup it away, which is
// the same invisible failure d46.18 is about.
func TestAWipedGuardStateProducesFreshEventIDs(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	ctx := t.Context()

	first := openGuard(t, node, d, guard.Options{})
	if err := first.BakeReceive(ctx); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}
	before := bakeEvents(t, first.Handle(ctx, guard.Request{Op: guard.OpStatus}).Events)
	if err := first.Close(); err != nil {
		t.Fatalf("closing the first guard: %v", err)
	}

	if err := os.RemoveAll(d.data); err != nil {
		t.Fatalf("wiping the guard's data dir: %v", err)
	}
	second := openGuard(t, node, d, guard.Options{})
	if err := second.BakeReceive(ctx); err != nil {
		t.Fatalf("BakeReceive after the wipe: %v", err)
	}
	after := bakeEvents(t, second.Handle(ctx, guard.Request{Op: guard.OpStatus}).Events)
	if len(after) != 1 {
		t.Fatalf("the wiped guard reported %d bake events, want 1", len(after))
	}
	if after[0].ID == before[0].ID {
		t.Errorf("a wiped guard re-used the event id %q; the re-bake would be deduped away",
			after[0].ID)
	}
}

// Spec §12: only the sanctioned vocabulary reaches the trail, and the guard is
// no exception just because its events arrive over a socket.
func TestGuardEventsUseTheSpecVocabulary(t *testing.T) {
	node := lndtest.Start(t)
	g := openGuard(t, node, guardDirs(t, node), guard.Options{})
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}
	events := g.Handle(t.Context(), guard.Request{Op: guard.OpStatus}).Events
	if len(events) == 0 {
		t.Fatal("the guard reported no events at all")
	}
	for _, ev := range events {
		if !ev.Event.Valid() {
			t.Errorf("the guard reported %q, which is not one of the §12 events", ev.Event)
		}
		if ev.At.IsZero() {
			t.Errorf("%s carries no timestamp; the row would be stamped at delivery time", ev.Event)
		}
	}
}

// --- helpers ---------------------------------------------------------------

func bakeEvents(t *testing.T, events []logging.RelayedEvent) []logging.RelayedEvent {
	t.Helper()
	var out []logging.RelayedEvent
	for _, ev := range events {
		if ev.Event == logging.EventMacaroonBake {
			out = append(out, ev)
		}
	}
	return out
}

func ids(events []logging.RelayedEvent) []string {
	out := make([]string, len(events))
	for i, ev := range events {
		out[i] = ev.ID
	}
	return out
}
