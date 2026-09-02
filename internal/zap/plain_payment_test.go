package zap_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/zap"
)

// 0vk.16: a plain LNURL payment — one with no zap request, which is also what a
// Primal profile zap looks like on the wire — settles like any other and owes
// no receipt. OnSettled cannot know that: it queues the obligation before
// reading anything, deliberately, so that "a receipt is owed" is durable from
// the moment the money lands. The not-a-zap case is therefore discovered at the
// first attempt, and has to be cleared THERE, quietly.
//
// Before this test, every such payment left its row for the retry tick, which
// dropped it at ERROR — one line per ordinary payment, about 45s after it
// settled (0.1.11 trip, §F1). ERROR is what an operator scans for, and a line
// that fires on correct behaviour is how a log stops being read.
func TestAPlainPaymentOwesNoReceiptAndWritesNoError(t *testing.T) {
	h := newHarness(t)
	var logged bytes.Buffer
	hash := h.settle(t, nil) // no zap request: an ordinary LNURL payment
	p := h.publisherWith(h.pool, &logged)

	p.OnSettled(t.Context(), hash)
	p.PublishNow(t.Context(), hash) // what the publishing goroutine does with the hand-off

	if _, owed := h.pending(t, hash); owed {
		t.Error("a plain payment is still queued as owing a receipt after its first " +
			"attempt found no zap behind it")
	}
	h.advance(zap.FirstBackoff + time.Second)
	p.RetryDue(t.Context())

	if strings.Contains(logged.String(), `"level":"ERROR"`) {
		t.Errorf("an ordinary payment produced an ERROR line:\n%s", logged.String())
	}
	if h.pool.count() != 0 {
		t.Error("a receipt was published for a payment that was not a zap")
	}
}

// The same row, met by the retry loop instead: a restart between the settlement
// and its first attempt leaves it that way. It is cleared, and it is not an
// error — nothing is wrong, the payment was simply not a zap.
func TestTheRetryLoopClearsAPlainPaymentsRowQuietly(t *testing.T) {
	h := newHarness(t)
	var logged bytes.Buffer
	hash := h.settle(t, nil)
	if err := h.db.QueueZapReceipt(t.Context(), store.PendingReceipt{
		PaymentHash:   hash,
		GiveUpAt:      h.clock().Add(zap.RetryWindow),
		NextAttemptAt: h.clock(),
	}); err != nil {
		t.Fatalf("QueueZapReceipt: %v", err)
	}

	h.publisherWith(h.pool, &logged).RetryDue(t.Context())

	if _, owed := h.pending(t, hash); owed {
		t.Error("the retry loop left a plain payment's row queued")
	}
	if strings.Contains(logged.String(), `"level":"ERROR"`) {
		t.Errorf("clearing a plain payment's row was reported as an error:\n%s", logged.String())
	}
	// The clearing is still visible, below ERROR, so "nothing happened" and
	// "cleared as not a zap" can be told apart by someone reading at DEBUG.
	if !strings.Contains(logged.String(), "not a zap") {
		t.Errorf("the row was cleared without saying why:\n%s", logged.String())
	}
}
