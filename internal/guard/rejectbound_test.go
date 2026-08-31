package guard_test

import (
	"testing"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// t0b: a burst of refused BakeSpend calls does not flush the guard's ring.
//
// THE ASSERTION IS THE SURVIVING EVENT, not the count. §16 gives the guard no
// database, so its 32-slot ring is the ONLY way a guard event reaches §12's
// trail, and nothing drains it — every socket response carries the whole ring
// and the server dedupes by id. `tna.4` then made `guard.reject` live on every
// refused BakeSpend, and the server is the container this design assumes may be
// compromised: thirty-two socket calls would evict `macaroon.bake`, which is the
// row an operator most needs after exactly the incident that produced the flood.
func TestABurstOfRefusalsDoesNotEvictTheBakeItFollowed(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithSending(t, node, d, false)

	// A bake first, so there is something to lose. The receive credential is
	// baked on every install and needs no operator.
	if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon: %v", err)
	}
	if _, ok := findEvent(g.Handle(t.Context(), guard.Request{Op: guard.OpStatus}).Events,
		logging.EventMacaroonBake); !ok {
		t.Fatal("no macaroon.bake to lose; this test would prove nothing")
	}

	// The flood: far more than the ring can hold.
	for range 200 {
		_ = g.BakeSpend(t.Context())
	}

	events := g.Handle(t.Context(), guard.Request{Op: guard.OpStatus}).Events
	if _, ok := findEvent(events, logging.EventMacaroonBake); !ok {
		var kinds []string
		for _, e := range events {
			kinds = append(kinds, string(e.Event))
		}
		t.Fatalf("the macaroon.bake row was evicted by a burst of refusals (%v)\n\nThe server "+
			"may not have collected it yet, and the guard's ring is the only copy", kinds)
	}
}

// And the bound ANNOUNCES ITSELF, once, so the operator can tell "bounded" from
// "nothing happened".
//
// A bound that silently stops writing hides a flood from the person it is meant
// to inform. One row per window says the rest are in the log.
func TestTheRejectionBoundSaysThatItIsBounding(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithSending(t, node, d, false)

	for range 50 {
		_ = g.BakeSpend(t.Context())
	}

	events := g.Handle(t.Context(), guard.Request{Op: guard.OpStatus}).Events
	var rejects, announcements int
	for _, e := range events {
		if e.Event != logging.EventGuardReject {
			continue
		}
		rejects++
		if e.Attrs["bound"] != "" {
			announcements++
		}
	}
	if rejects >= 50 {
		t.Errorf("%d of 50 refusals reached the ring; the bound is not bounding", rejects)
	}
	if announcements != 1 {
		t.Errorf("%d rows say the bound was reached, want exactly 1 — silence would leave the "+
			"operator unable to tell a quiet hour from a flood they are not being shown",
			announcements)
	}
}

func findEvent(events []logging.RelayedEvent, kind logging.Event) (logging.RelayedEvent, bool) {
	for _, e := range events {
		if e.Event == kind {
			return e, true
		}
	}
	return logging.RelayedEvent{}, false
}
