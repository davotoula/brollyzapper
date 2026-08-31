package guard_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// A cap change's durable row must say which way it moved (BrollyZap-66t).
//
// Change.describe() is direction-blind for the CAPS, because a Change carries
// its own new position only for sending — whether a cap moves up or down
// depends on the STORED value, which a Change does not hold. describe() was
// written for the authorisation FILE, which is only ever written for a
// loosening, so "RAISE" is true there by construction. Reused for the audit
// attribute, which is written for BOTH directions, it produced a row reading
//
//	change  = "RAISE THE SPENDING LIMIT to 50,000 sats in any 24 hours"
//	outcome = "tightening"
//
// — a row contradicting itself, in §12's trail, about a security control's
// direction. Every existing test of describe() goes through the file, where
// only loosenings arrive, which is why this reached a box.
func TestACapChangesAuditRowSaysWhichWayItMoved(t *testing.T) {
	for _, c := range []struct {
		name    string
		control guard.Control
		// start is the stored pair; to is the cap asked for. The per-payment cap
		// must stay under the 24-hour one or the guard refuses the change on its
		// own merits, which would test the wrong thing.
		start caps
		to    int64
	}{
		{"the 24-hour cap lowered", guard.ControlSpendCap,
			caps{window: 100_000_000, payment: 1_000_000}, 50_000_000},
		{"the per-payment cap lowered", guard.ControlPaymentCap,
			caps{window: 100_000_000, payment: 10_000_000}, 1_000_000},
	} {
		t.Run(c.name, func(t *testing.T) {
			node := lndtest.Start(t)
			d := guardDirs(t, node)
			g := openGuardWithCaps(t, node, d, c.start)

			// A tightening needs no code — it applies immediately (Ruling 1),
			// which is exactly the path that writes the contradictory row.
			if err := g.ApplyChange(t.Context(), guard.Change{Control: c.control, Msat: c.to}, ""); err != nil {
				t.Fatalf("lowering the cap: %v", err)
			}

			row := lastGuardEvent(t, g, logging.EventGuardAuthorise)
			if got := row.Attrs["outcome"]; got != "tightening" {
				t.Fatalf("outcome = %q, want \"tightening\"; the rest of this test reads on that", got)
			}
			change := row.Attrs["change"]
			if !strings.Contains(strings.ToUpper(change), "LOWER") {
				t.Errorf("the row says %q; a cap that was LOWERED must not be recorded as "+
					"anything else — this is the durable account of a security control", change)
			}
			if strings.Contains(strings.ToUpper(change), "RAISE") {
				t.Errorf("the row says %q beside outcome \"tightening\"; the two contradict "+
					"each other", change)
			}
		})
	}
}

// And a RAISE still reads as one, so the fix cannot have simply inverted the
// sentence.
func TestARaisedCapsAuditRowStillSaysRaise(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 10_000_000, payment: 1_000_000})

	change := guard.Change{Control: guard.ControlSpendCap, Msat: 50_000_000}
	if err := g.RequestAuthorisation(t.Context(), change); err != nil {
		t.Fatalf("requesting the authorisation: %v", err)
	}
	if err := g.ApplyChange(t.Context(), change, readAuthorisationCode(t, d)); err != nil {
		t.Fatalf("redeeming it: %v", err)
	}

	row := lastGuardEvent(t, g, logging.EventGuardAuthorise)
	if got := row.Attrs["outcome"]; got != "authorised" {
		t.Fatalf("outcome = %q, want \"authorised\"", got)
	}
	if !strings.Contains(row.Attrs["change"], "RAISE") {
		t.Errorf("a raised cap's row says %q, want it to say RAISE", row.Attrs["change"])
	}
}

// The trail's RAISE sentence and the authorisation file's are the same words.
//
// They are rendered separately, so an audit change cannot reword the file —
// whose sentence is what the operator compares against what they asked for, and
// is itself a security control. Two statements of one fact is the shape that
// drifts, so this is the line that stops it: for a raise, the one direction both
// render, they must agree.
func TestTheTrailAndTheFileUseTheSameWordsForARaise(t *testing.T) {
	for _, c := range []struct {
		name    string
		control guard.Control
		start   caps
		to      int64
	}{
		// BOTH caps, because the agreement is per-control: an earlier version of
		// this test checked only the 24-hour limit, leaving the per-payment
		// wording free to drift in one renderer and not the other.
		{"the 24-hour limit", guard.ControlSpendCap,
			caps{window: 10_000_000, payment: 1_000_000}, 50_000_000},
		{"the per-payment limit", guard.ControlPaymentCap,
			caps{window: 100_000_000, payment: 1_000_000}, 10_000_000},
	} {
		t.Run(c.name, func(t *testing.T) {
			node := lndtest.Start(t)
			d := guardDirs(t, node)
			g := openGuardWithCaps(t, node, d, c.start)

			change := guard.Change{Control: c.control, Msat: c.to}
			if err := g.RequestAuthorisation(t.Context(), change); err != nil {
				t.Fatalf("requesting the authorisation: %v", err)
			}
			file, err := os.ReadFile(filepath.Join(d.data, "authorisation.txt"))
			if err != nil {
				t.Fatalf("the operator has nothing to read: %v", err)
			}
			if err := g.ApplyChange(t.Context(), change, readAuthorisationCode(t, d)); err != nil {
				t.Fatalf("redeeming it: %v", err)
			}

			sentence := lastGuardEvent(t, g, logging.EventGuardAuthorise).Attrs["change"]
			if !strings.Contains(string(file), sentence) {
				t.Errorf("the trail says %q and the file does not contain that sentence; an "+
					"operator comparing the row against the file they kept would find two "+
					"accounts of one change:\n%s", sentence, file)
			}
		})
	}
}
