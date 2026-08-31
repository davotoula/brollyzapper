package nwc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"
)

// uhg's test that matters: tighten a limit with a payment IN FLIGHT, and the
// NEXT payment sees the new number — no restart.
//
// It tightens the PER-PAYMENT CAP, and that choice is the test. The obvious
// version tightens the budget and proves nothing: budget_msat is compared inside
// ReserveNWCBudget's guarded UPDATE, so it reads the database row every time and
// was already live before this wave. The cap and the permissions are read from
// the connection object the service holds — a copy taken at startup — so they
// are what a reload has to refresh, and what a missing reload silently ignores.
// Planting the reload away is what showed the difference.
func TestATightenedCapTakesEffectWithoutARestart(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.setBudget(1_000_000)
	h.decodesTo("lnbcrt1first", 100_000, "the first payment")
	h.decodesTo("lnbcrt1second", 100_000, "the second payment")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	conn := h.openConnection(ctx, h.conn.row())
	conn.identity = h.counting
	live := map[int64]*connection{conn.row().ID: conn}
	done := make(chan struct{})
	go func() { defer close(done); h.service.serve(ctx, conn, testRelay) }()

	// A payment is in flight while the operator tightens the budget.
	releasePayment := make(chan struct{})
	h.spend.beforePay = func() { <-releasePayment }
	h.relays.deliver(h.request(t, h.client, MethodPayInvoice, payParams("lnbcrt1first", 0)))
	waitFor(t, "the first payment to be in flight", func() bool { return h.spend.payments() == 1 })

	// The operator lowers the per-payment cap below what the next payment needs,
	// and signals. The service is running and nothing restarts.
	cap := int64(50_000)
	if _, err := h.db.SetNWCConnectionLimits(t.Context(), conn.row().ID, conn.row().Permissions,
		conn.row().BudgetMsat, store.BudgetDaily, h.clock.at.Add(time.Hour), &cap); err != nil {
		t.Fatal(err)
	}
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatalf("reload: %v", err)
	}

	close(releasePayment)
	h.spend.beforePay = nil
	waitFor(t, "the first payment to finish", func() bool { return len(h.relays.published()) == 1 })

	// The NEXT payment is measured against the new number.
	h.relays.deliver(h.request(t, h.client, MethodPayInvoice, payParams("lnbcrt1second", 0)))
	waitFor(t, "the second payment to be answered", func() bool {
		return len(h.relays.published()) == 2
	})
	answer := h.relays.published()[1]
	plaintext := h.open(t, answer)
	if !strings.Contains(plaintext, "QUOTA_EXCEEDED") {
		t.Errorf("the second payment answered %q; it must be measured against the cap the "+
			"operator just set, not the one the process started with", plaintext)
	}

	cancel()
	conn.close()
	<-done
}

// A revoked connection stops answering, without a restart.
func TestARevokedConnectionStopsAnsweringOnReload(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	conn := h.openConnection(ctx, h.conn.row())
	conn.identity = h.counting
	live := map[int64]*connection{conn.row().ID: conn}
	done := make(chan struct{})
	go func() { defer close(done); h.service.serve(ctx, conn, testRelay) }()

	if _, err := h.db.RevokeNWCConnection(t.Context(), conn.row().ID); err != nil {
		t.Fatal(err)
	}
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if len(live) != 0 {
		t.Errorf("%d connections are still served after a revoke", len(live))
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("the revoked connection's goroutine is still running")
	}
	cancel()
}

// A connection created while the service runs is served, and announced.
func TestANewConnectionIsServedOnReload(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	live := map[int64]*connection{}

	if err := h.service.reload(ctx, live); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if len(live) != 1 {
		t.Fatalf("%d connections are served, want the one in the database", len(live))
	}
	// The info event is what a wallet app builds its UI from, so a new
	// connection has to be announced rather than merely subscribed. Waited for
	// rather than asserted: since d24.18 the dial and the announcement that
	// follows it happen on the relay session's own goroutine.
	waitFor(t, "the new connection to be announced", func() bool {
		return len(h.relays.infoEvents()) > 0
	})
	for _, conn := range live {
		conn.close()
	}
	cancel()
}

// A capability change republishes the info event; an unchanged one does not.
//
// §8 says republish "whenever capabilities change", and a service that
// republished on every reload would put an event on the relay each time an
// operator saved an unrelated setting.
func TestOnlyACapabilityChangeRepublishesTheInfoEvent(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	live := map[int64]*connection{}
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, conn := range live {
			conn.close()
		}
	}()
	// Waited for the announcement to be RECORDED, not merely published. announce
	// publishes at run.go:414 and calls setAnnounced at :421, and a wait that
	// keyed only on the published event could return between the two — where the
	// next reload correctly sees "nothing announced yet" and announces again.
	// That is this test failing for a reason the code is right about, and it
	// cost a -race -count=20 run to find (`xmc`); the ordering in announce is
	// deliberate and is not what changed.
	waitFor(t, "the first announcement to be recorded", func() bool {
		if len(h.relays.infoEvents()) != 1 {
			return false
		}
		for _, conn := range live {
			if len(conn.announced()) == 0 {
				return false
			}
		}
		return true
	})
	before := len(h.relays.infoEvents())

	// A reload that changes nothing.
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}
	if got := len(h.relays.infoEvents()); got != before {
		t.Errorf("%d info events after a no-op reload, want %d — a relay does not need to hear "+
			"that nothing changed", got, before)
	}

	// Now the operator grants the pay group.
	h.sendEnabled(true)
	row := h.conn.row()
	row.Permissions = append(row.Permissions, store.PermissionPay)
	if _, err := h.db.SetNWCConnectionLimits(t.Context(), row.ID, row.Permissions,
		row.BudgetMsat, row.BudgetPeriod, row.BudgetRenewsAt, row.MaxPaymentMsat); err != nil {
		t.Fatal(err)
	}
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}
	if got := len(h.relays.infoEvents()); got <= before {
		t.Errorf("%d info events after a capability change, want more than %d — a wallet app "+
			"builds its buttons from this", got, before)
	}
	cancel()
}

// Turning SENDING on republishes every paying connection's info event, and this
// is its own test because the obvious one misses it.
//
// TestOnlyACapabilityChangeRepublishesTheInfoEvent flips sending AND grants the
// pay group in one step, so the row change carries the assertion. Sending alone
// changes no row at all — it changes a setting that advertised() reads live —
// and the first version compared advertised() before the swap with advertised()
// after it, both read after the handler had already written the setting. They
// were equal, so nothing was republished and a wallet app holding `pay` saw no
// pay button until its socket next reconnected. Found by review.
func TestTogglingSendingAloneRepublishesTheInfoEvent(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	live := map[int64]*connection{}
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, conn := range live {
			conn.close()
		}
	}()
	waitFor(t, "the first announcement", func() bool { return len(h.relays.infoEvents()) == 1 })
	before := len(h.relays.infoEvents())

	// The operator enables sending. NO row changes — only the setting.
	h.sendEnabled(true)
	if err := h.service.reload(ctx, live); err != nil {
		t.Fatal(err)
	}

	if got := len(h.relays.infoEvents()); got <= before {
		t.Errorf("%d info events after sending was enabled, want more than %d — a wallet app "+
			"holding the pay group should see a pay button appear, and §8 requires the "+
			"republish whenever capabilities change", got, before)
	}
	cancel()
}

// A revoked connection whose workers are all busy answers NOTHING more.
//
// dispatchOne blocks on a free slot, and it used to wait only on that or the
// service's context. So a request arriving while all four workers were busy sat
// in that select; the revocation closed the subscription; a worker finished; and
// the waiting request was then dispatched — one more answer, carrying the
// operator's balance or history, for a pairing they had just revoked. Found by
// review, and the window is exactly when it matters: four in-flight requests is
// what an app that is being used looks like.
func TestARevokedConnectionAnswersNothingEvenWithEveryWorkerBusy(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Every slot taken, as if InFlightPerConnection requests were mid-flight.
	for range InFlightPerConnection {
		h.conn.slots <- struct{}{}
	}
	event := h.request(t, h.client, MethodGetBalance, nil)
	before := len(h.relays.published())

	h.conn.close()

	returned := make(chan struct{})
	go func() {
		h.service.dispatchOne(ctx, h.conn, event)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatchOne is still waiting for a slot on a CLOSED connection; it will " +
			"answer the request as soon as a worker frees up")
	}

	h.conn.working.Wait()
	if got := len(h.relays.published()); got != before {
		t.Errorf("a revoked connection published %d responses, want the %d it had already sent",
			got, before)
	}
}
