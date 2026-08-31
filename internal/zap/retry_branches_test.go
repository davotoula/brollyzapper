package zap_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/store"
)

// pending reads the queued receipt for one payment hash, or reports that there
// is none. Far-future "now", because the question is what the row SAYS, not
// whether it happens to be due.
func (h *harness) pending(t *testing.T, hash string) (store.PendingReceipt, bool) {
	t.Helper()
	due, err := h.db.DueZapReceipts(t.Context(), h.clock().Add(100*24*time.Hour), 50)
	if err != nil {
		t.Fatalf("DueZapReceipts: %v", err)
	}
	for _, r := range due {
		if r.PaymentHash == hash {
			return r, true
		}
	}
	return store.PendingReceipt{}, false
}

// dueAt reports whether the retry loop would pick this receipt up at that
// instant — the only observable the schedule has.
func (h *harness) dueAt(t *testing.T, hash string, at time.Time) bool {
	t.Helper()
	due, err := h.db.DueZapReceipts(t.Context(), at, 50)
	if err != nil {
		t.Fatalf("DueZapReceipts: %v", err)
	}
	for _, r := range due {
		if r.PaymentHash == hash {
			return true
		}
	}
	return false
}

func (h *harness) abandonedCount(t *testing.T) int {
	t.Helper()
	events, err := h.db.AuditEvents(t.Context(), 50)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	var n int
	for _, e := range events {
		if e.Event == logging.EventZapReceiptAbandoned {
			n++
		}
	}
	return n
}

// zu5.4 criteria 1, 2 and 4, and the branch the coverage analysis (§3.6) singles
// out: a stored zap request that no longer parses is DROPPED, not retried.
//
// The comment beside it explains why — "retrying would be a loop that never ends
// and never succeeds" — and if that arm ever regressed to a reschedule, the
// symptom is a permanent hot loop in production against a green suite here.
//
// Asserting "no retry was scheduled" alone is not enough, and that is the point
// of the second half: a drop and a silent loss look identical from the queue.
// The sender's wallet was credited and the sender will never be told, which is
// the fact §12 keeps a durable trail for. Until this bead that path wrote only a
// log line, which rotates; the question it answers arrives weeks later.
func TestAnUnparseableStoredRequestIsAbandonedRatherThanRetriedForever(t *testing.T) {
	h := newHarness(t)
	// Stored bytes that parsed once and do not any more. Whatever the cause —
	// a truncated write, a tightened validator — the retry cannot fix it.
	hash := h.settle(t, []byte(`{"kind":9734,"tags":[],"content":"`))

	h.publisher().PublishNow(t.Context(), hash)

	if _, queued := h.pending(t, hash); queued {
		t.Error("the receipt is still queued; every retry will fail the same way, forever")
	}
	if h.pool.count() != 0 {
		t.Errorf("%d publish attempts were made with nothing publishable to send", h.pool.count())
	}
	if got := h.abandonedCount(t); got != 1 {
		t.Errorf("%d %s rows, want exactly 1 — the wallet was credited and the sender will "+
			"never be told, and a log line does not survive rotation",
			got, logging.EventZapReceiptAbandoned)
	}

	// And it stays abandoned: a later sweep must not resurrect it.
	h.advance(time.Hour)
	h.publisher().RetryDue(t.Context())
	if h.pool.count() != 0 {
		t.Error("a later retry sweep picked it up again")
	}
}

// zu5.4 criterion 1: the backoff's terminal case. The next attempt is clamped to
// the give-up time, so the last retry lands exactly on the window's edge rather
// than past it — past it means the row is due only after the code has already
// decided to give up, which is a receipt that is never tried again and never
// abandoned either.
func TestTheNextAttemptIsClampedToTheGiveUpTime(t *testing.T) {
	h := newHarness(t)
	h.pool.setRefuse(true)
	hash := h.settle(t, zapRequest(t, nil))
	h.publisher().PublishNow(t.Context(), hash)

	queued, ok := h.pending(t, hash)
	if !ok {
		t.Fatal("a refused receipt was not queued")
	}
	// Far enough in that an unclamped backoff would overshoot, but still inside
	// the window so the give-up branch is not the one under test.
	h.advance(queued.GiveUpAt.Sub(h.clock()) - time.Second)
	h.publisher().RetryDue(t.Context())

	after, ok := h.pending(t, hash)
	if !ok {
		t.Fatal("the receipt was dropped rather than rescheduled; the window has not passed yet")
	}

	// Asserted through WHEN THE ROW COMES DUE, not by reading next_attempt_at:
	// that column is deliberately never selected back (see dueZapReceiptsSQL),
	// and the clamp's whole purpose is the due time, not the number. Without it
	// the row would come due after the give-up moment, so the retry loop would
	// reach it only once reschedule has already decided to stop — never tried
	// again, and never abandoned either.
	if !h.dueAt(t, hash, after.GiveUpAt) {
		t.Errorf("the receipt is not due at its give-up time %v; the last attempt falls "+
			"outside the window and will never happen", after.GiveUpAt)
	}
	if h.dueAt(t, hash, after.GiveUpAt.Add(-time.Second)) {
		t.Error("the receipt is due a second BEFORE the give-up time, so the clamp is not " +
			"what put it there and this test would pass without one")
	}
}

// emptyPool answers every publish with no results at all, which is what a pool
// says when it had nowhere to send: every relay was filtered, or the list was
// empty. Distinct from "every relay was tried and refused", and the two must not
// be recorded as the same thing — one is a configuration problem the operator
// can fix, the other is the relays being down.
type emptyPool struct{ attempts int }

func (e *emptyPool) Publish(context.Context, gonostr.Event, ...string) []nostr.PublishResult {
	e.attempts++
	return nil
}

// zu5.4 criterion 1: "no relay was tried", distinct from every relay failing.
func TestNoRelayTriedIsRecordedAsItsOwnCause(t *testing.T) {
	h := newHarness(t)
	var logged bytes.Buffer
	hash := h.settle(t, zapRequest(t, nil))
	h.publisherWith(&emptyPool{}, &logged).PublishNow(t.Context(), hash)

	if _, ok := h.pending(t, hash); !ok {
		t.Fatal("a receipt that reached no relay was not queued for retry")
	}
	// The cause is stored in last_error and that column is never selected back,
	// so the log line is where it actually reaches anybody.
	if !strings.Contains(logged.String(), "no relay was tried") {
		t.Errorf("the cause was not reported as \"no relay was tried\"; an operator reading "+
			"a relay error would go looking at relays that were never contacted:\n%s",
			logged.String())
	}

	// The other direction, so this cannot pass by reporting that phrase always.
	var refused bytes.Buffer
	h.pool.setRefuse(true)
	h.publisherWith(h.pool, &refused).PublishNow(t.Context(), hash)
	if strings.Contains(refused.String(), "no relay was tried") {
		t.Errorf("relays that WERE tried and refused were reported as untried:\n%s",
			refused.String())
	}
}

// zu5.4 criterion 3: the hand-off channel being full falls through to the
// durable queue rather than blocking or dropping (Wave 11's design).
//
// The channel is unexported, so it is filled the way production fills it — by
// settling faster than anything drains it, with no publishing goroutine running.
// The assertion is that the receipt is still OWED afterwards: the fast path is
// an optimisation, and the durable row is what makes the promise.
func TestAFullHandOffStillLeavesTheReceiptOwed(t *testing.T) {
	h := newHarness(t)
	hash := h.settle(t, zapRequest(t, nil))
	p := h.publisher()

	// Nothing is consuming p.settled here, so this overruns the buffer. The
	// exact depth is zap's business; well past it is the point.
	for range 200 {
		p.OnSettled(t.Context(), hash)
	}

	queued, ok := h.pending(t, hash)
	if !ok {
		t.Fatal("the hand-off overflowed and the receipt was forgotten; the durable queue " +
			"is what stops a burst of settlements losing receipts")
	}
	if queued.GiveUpAt.IsZero() {
		t.Error("the queued row carries no give-up time, so it would never be abandoned either")
	}
	if h.pool.count() != 0 {
		t.Error("OnSettled published synchronously; it must not block a settlement (§7)")
	}
}
