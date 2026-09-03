package zap_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/zap"
)

// fakePool records what it was asked to publish and answers as told.
type fakePool struct {
	mu       sync.Mutex
	refuse   bool
	attempts int
	last     gonostr.Event
	extra    []string
	// block, when set, holds each publish until it is closed — standing in for
	// a relay that accepts a connection and then says nothing.
	block chan struct{}
}

func (f *fakePool) Publish(_ context.Context, event gonostr.Event, extra ...string) []nostr.PublishResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	f.last, f.extra = event, extra
	if f.block != nil {
		blocked := f.block
		f.mu.Unlock()
		<-blocked
		f.mu.Lock()
	}
	if f.refuse {
		return []nostr.PublishResult{
			{Relay: "wss://relay.example", Err: errors.New("connection refused")},
			{Relay: "wss://second.example", Err: errors.New("connection refused")},
		}
	}
	return []nostr.PublishResult{{Relay: "wss://relay.example"}}
}

func (f *fakePool) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts
}

func (f *fakePool) setRefuse(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refuse = v
}

// signer signs with a throwaway key, standing in for nostr.Signer.
type signer struct{ sk string }

func (s signer) Sign(_ context.Context, event *gonostr.Event) error { return event.Sign(s.sk) }

// harness stands the publisher up over a REAL store, because criterion 9 is
// about what survives a restart and an in-memory fake cannot answer that.
type harness struct {
	db   *store.Store
	pool *fakePool
	now  time.Time
	mu   sync.Mutex
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &harness{db: db, pool: &fakePool{}, now: settleTime}
}

// publisher builds a NEW Publisher over the same store — which is how the
// restart in criterion 9 is expressed.
func (h *harness) publisher() *zap.Publisher { return h.publisherWithPool(h.pool) }

// publisherWithPool is the same, for the one branch that needs a pool answering
// something the shared fake cannot say.
func (h *harness) publisherWithPool(pool zap.Pool) *zap.Publisher {
	return h.publisherWith(pool, io.Discard)
}

// publisherWith also sends the publisher's own log somewhere a test can read.
// Some of what this package decides is visible ONLY there — last_error is
// stored and deliberately never selected back (see dueZapReceiptsSQL), so the
// warning line is where an operator, and a test, actually meet it.
func (h *harness) publisherWith(pool zap.Pool, logTo io.Writer) *zap.Publisher {
	return zap.New(h.db, signer{sk: gonostr.GeneratePrivateKey()}, pool,
		logging.NewAuditor(logging.New(io.Discard, logging.NewLevelVar(slog.LevelError)), h.db),
		h.clock, logging.New(logTo, logging.NewLevelVar(slog.LevelDebug)))
}

func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.now = h.now.Add(d)
}

// settle mints and settles a zap invoice, leaving exactly the rows a real
// settlement leaves.
func (h *harness) settle(t *testing.T, raw []byte) string {
	t.Helper()
	return h.settleAs(t, strings.Repeat("f", 64), raw)
}

// settleAs is settle with a caller-chosen payment hash, for the one test that
// needs MANY settled zaps: invoices.payment_hash is unique, so a fixed hash
// caps a test at one.
func (h *harness) settleAs(t *testing.T, hash string, raw []byte) string {
	t.Helper()
	if err := h.db.CreateInvoice(t.Context(), store.Invoice{
		PaymentHash:     hash,
		AmountMsat:      21_000,
		DescriptionHash: "dh",
		Bolt11:          "lnbcrt210n1example",
		ZapRequest:      string(raw),
		ZapRelays:       `["wss://relay.example","wss://second.example"]`,
		CreatedAt:       settleTime.Add(-time.Minute),
		ExpiresAt:       settleTime.Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}
	if _, err := h.db.CreditSettledInvoice(t.Context(), hash, strings.Repeat("9", 64),
		21_000, settleTime, true); err != nil {
		t.Fatalf("CreditSettledInvoice: %v", err)
	}
	return hash
}

func (h *harness) receiptID(t *testing.T, hash string) string {
	t.Helper()
	id, err := h.db.ZapReceiptID(t.Context(), hash)
	if err != nil {
		t.Fatalf("ZapReceiptID: %v", err)
	}
	return id
}

// Criteria 6 and 8: the receipt reaches the sender's relays, and the event id
// is recorded against the settled txn.
func TestAPublishedReceiptRecordsItsEventIdAndReachesTheSendersRelays(t *testing.T) {
	h := newHarness(t)
	hash := h.settle(t, zapRequest(t, nil))

	h.publisher().PublishNow(t.Context(), hash)

	id := h.receiptID(t, hash)
	if id == "" {
		t.Fatal("txns.zap_receipt_id was not recorded after a successful publish")
	}
	if id != h.pool.last.ID {
		t.Errorf("recorded %s, want the published event id %s", id, h.pool.last.ID)
	}
	if got := h.pool.extra; len(got) != 2 || got[0] != "wss://relay.example" {
		t.Errorf("published to extra relays %v, want the two the sender named", got)
	}
}

// Criterion 7. Publication never blocks or fails settlement: the credit
// commits, and the receipt is a consequence of it. Every relay refuses here,
// and the money must be exactly where it would have been anyway.
func TestEveryRelayRefusingLeavesTheWalletCreditedAndTheInvoiceSettled(t *testing.T) {
	h := newHarness(t)
	h.pool.setRefuse(true)
	hash := h.settle(t, zapRequest(t, nil))

	h.publisher().PublishNow(t.Context(), hash)

	inv, ok, err := h.db.Invoice(t.Context(), hash)
	if err != nil || !ok {
		t.Fatalf("Invoice: %v (found=%v)", err, ok)
	}
	if inv.State != store.InvoiceSettled {
		t.Errorf("invoice state = %q, want settled — a refusing relay must not "+
			"unsettle a paid invoice", inv.State)
	}
	balance, err := h.db.BalanceMsat(t.Context())
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if balance != 21_000 {
		t.Errorf("balance = %d msat, want 21000 — the credit is not a consequence "+
			"of the receipt", balance)
	}
	if id := h.receiptID(t, hash); id != "" {
		t.Errorf("zap_receipt_id = %q after every relay refused", id)
	}
}

// Criterion 9, the one §7 says prevents "reads as theft". Every relay fails,
// the receipt is PERSISTED, and a NEW Publisher over the same store — the
// restart — picks it up and finishes the job.
func TestAFailedReceiptSurvivesARestartAndIsEventuallyPublished(t *testing.T) {
	h := newHarness(t)
	h.pool.setRefuse(true)
	hash := h.settle(t, zapRequest(t, nil))

	h.publisher().PublishNow(t.Context(), hash)
	if h.pool.count() != 1 {
		t.Fatalf("the first attempt ran %d times, want 1", h.pool.count())
	}
	if id := h.receiptID(t, hash); id != "" {
		t.Fatal("a receipt no relay accepted recorded an event id")
	}

	// Nothing is due yet, so a restart that retried immediately would be
	// ignoring the backoff rather than resuming the queue.
	restarted := h.publisher()
	restarted.RetryDue(t.Context())
	if h.pool.count() != 1 {
		t.Errorf("a retry ran before the backoff elapsed (%d attempts)", h.pool.count())
	}

	// Now the backoff has passed and the relays are back.
	h.advance(zap.FirstBackoff + time.Second)
	h.pool.setRefuse(false)
	h.publisher().RetryDue(t.Context())

	if id := h.receiptID(t, hash); id == "" {
		t.Error("a queued receipt was not published after a restart; the sender was " +
			"credited and never told")
	}
	// And the queue is empty, so it does not publish for ever.
	h.advance(time.Hour)
	before := h.pool.count()
	h.publisher().RetryDue(t.Context())
	if h.pool.count() != before {
		t.Error("a published receipt is still queued")
	}
}

// Criterion 9's other end: the window is bounded. After 24 hours the receipt is
// given up on rather than retried for ever — and it is given up LOUDLY, because
// the wallet was credited and the sender was never told.
func TestTheRetryWindowIsBoundedAtTwentyFourHours(t *testing.T) {
	h := newHarness(t)
	h.pool.setRefuse(true)
	hash := h.settle(t, zapRequest(t, nil))
	h.publisher().PublishNow(t.Context(), hash)

	for range 200 {
		h.advance(zap.MaxBackoff)
		h.publisher().RetryDue(t.Context())
	}
	h.advance(time.Hour)
	before := h.pool.count()
	h.publisher().RetryDue(t.Context())
	if h.pool.count() != before {
		t.Errorf("the receipt is still being retried %v after settlement", zap.RetryWindow)
	}

	// And giving up leaves a DURABLE record, not just a log line. This is the
	// one fact this package produces that somebody may come asking about weeks
	// later — "you took my sats and I never got a receipt" — and §12 keeps a
	// trail precisely so log rotation cannot erase the answer. CLAUDE.md names
	// an uncalled Auditor as a failure this project has already had three times.
	events, err := h.db.AuditEvents(t.Context(), 20)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	var found bool
	for _, e := range events {
		if e.Event == logging.EventZapReceiptAbandoned {
			found = true
		}
	}
	if !found {
		t.Errorf("abandoning a receipt wrote no %s row; the trail is where that "+
			"question gets answered after the logs have rotated",
			logging.EventZapReceiptAbandoned)
	}
}

// Criterion 10. The loop is driven by a tick channel the caller owns, and a
// test that never ticks proves nothing happens by the mere passage of time.
func TestTheRetryLoopDoesNothingWithoutATick(t *testing.T) {
	h := newHarness(t)
	h.pool.setRefuse(true)
	hash := h.settle(t, zapRequest(t, nil))
	h.publisher().PublishNow(t.Context(), hash)
	h.advance(zap.RetryWindow / 2)

	ctx, cancel := context.WithCancel(t.Context())
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() { defer close(done); h.publisher().RunRetry(ctx, tick) }()

	before := h.pool.count()
	h.pool.setRefuse(false)
	// A real wait, and it has to be: the claim is "nothing happens over an
	// interval", and there is no way to observe that without letting an
	// interval pass. Cancelling immediately — which is what this test did
	// first — made a timer-driven loop a coin flip, so the plant that added an
	// internal ticker passed. 100ms is far longer than any retry cadence a
	// mistake would plausibly use.
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if h.pool.count() != before {
		t.Errorf("the retry loop published without a tick (%d attempts, was %d)",
			h.pool.count(), before)
	}

	// And it does act when ticked, or the assertion above would pass on a loop
	// that never works at all.
	ctx2, cancel2 := context.WithCancel(t.Context())
	defer cancel2()
	tick2 := make(chan time.Time)
	go h.publisher().RunRetry(ctx2, tick2)
	tick2 <- h.clock()
	deadline := time.After(2 * time.Second)
	for h.receiptID(t, hash) == "" {
		select {
		case <-deadline:
			t.Fatal("a ticked retry loop published nothing")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// §7: publication must never block settlement. An earlier version of this
// satisfied only half of that — it never returned an ERROR to the settlement
// path, but it published inline on the invoice stream's own goroutine, which is
// strictly serial and writes its durable resume point only after the handler
// returns. One unreachable relay therefore stalled the next settlement for as
// long as the pool's publish timeout, and left the settle-index checkpoint that
// stale.
//
// Not preventing an error is not the same as not blocking, so this measures the
// thing the spec actually promises.
func TestOnSettledDoesNotWaitForTheRelays(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	h.pool.block = release
	hash := h.settle(t, zapRequest(t, nil))

	// ONE publisher: the hand-off channel belongs to the instance, and
	// h.publisher() deliberately mints a fresh one each call so the other tests
	// can model a restart. Two instances here would be two channels, and the
	// loop would sit waiting on the wrong one.
	publisher := h.publisher()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tick := make(chan time.Time)
	go publisher.RunRetry(ctx, tick)

	done := make(chan struct{})
	go func() { defer close(done); publisher.OnSettled(ctx, hash) }()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("OnSettled was still waiting a second after a settlement; it is publishing " +
			"on the caller's goroutine and the invoice stream is stalled behind it")
	}

	// And the hand-off is really drained, or "does not block" would just mean
	// "does nothing".
	deadline := time.After(2 * time.Second)
	for h.pool.count() == 0 {
		select {
		case <-deadline:
			t.Fatal("the settled zap was handed off and never published")
		case <-time.After(5 * time.Millisecond):
		}
	}
	close(release)
}

// A zap's receipt obligation must be durable from the moment the money lands,
// not from the moment an attempt has already failed.
//
// Two things rest on it. The Wallet page reads a receipt's state off what is
// recorded, and "no receipt id and nothing queued" used to be true both of a
// genuinely abandoned receipt AND of a healthy one in the seconds before its
// first attempt — so a good zap rendered as "abandoned", the most alarming of
// the three words. And a crash in that same window left nothing saying a
// receipt was owed at all.
func TestASettledZapOwesAReceiptBeforeAnyAttemptIsMade(t *testing.T) {
	h := newHarness(t)
	h.pool.setRefuse(true)
	hash := h.settle(t, zapRequest(t, nil))

	// OnSettled only hands off; nothing has been published yet.
	h.publisher().OnSettled(t.Context(), hash)

	due, err := h.db.DueZapReceipts(t.Context(), h.clock().Add(zap.RetryWindow), 10)
	if err != nil {
		t.Fatalf("DueZapReceipts: %v", err)
	}
	if len(due) != 1 || due[0].PaymentHash != hash {
		t.Fatalf("queued %d receipts, want 1 for %s — a settled zap must owe a receipt "+
			"before any attempt has been made", len(due), hash)
	}
	if h.pool.count() != 0 {
		t.Error("OnSettled published on the caller's goroutine")
	}
}

// And a receipt that succeeds first time leaves nothing behind.
func TestAFirstAttemptSuccessClearsTheObligation(t *testing.T) {
	h := newHarness(t)
	hash := h.settle(t, zapRequest(t, nil))
	h.publisher().PublishNow(t.Context(), hash)

	if id := h.receiptID(t, hash); id == "" {
		t.Fatal("the receipt was not published")
	}
	due, err := h.db.DueZapReceipts(t.Context(), h.clock().Add(zap.RetryWindow), 10)
	if err != nil {
		t.Fatalf("DueZapReceipts: %v", err)
	}
	if len(due) != 0 {
		t.Errorf("%d receipts are still queued after a successful publish", len(due))
	}
}

// t0b: a burst of abandoned receipts does not flush §12's trail.
//
// A STRANGER DRIVES THIS ONE. Anybody can pay zap invoices, and a relay outage
// abandons every queued receipt at the end of its retry window — so an unbounded
// writer here lets somebody who is not the operator evict `macaroon.bake` from a
// 10 000-row ring. The two writers that already bounded their remote-triggerable
// events did so for exactly this reason; this one had no bound because nothing
// said the rule was general, which is a rule with an exemption nobody decided.
//
// AND THE BOUND IS OBSERVABLE. One row per window says the rest are in the log,
// so an operator can tell "bounded" from "nothing happened".
func TestABurstOfAbandonedReceiptsIsBoundedAndSaysSo(t *testing.T) {
	h := newHarness(t)
	h.pool.setRefuse(true)
	publisher := h.publisher()

	// Well past the bound, all inside one hour so the window cannot roll.
	const receipts = logging.DefaultRefusalsPerHour * 3
	for i := range receipts {
		hash := h.settleAs(t, fmt.Sprintf("%064x", i), zapRequest(t, nil))
		publisher.PublishNow(t.Context(), hash)
		h.advance(zap.RetryWindow + time.Hour)
		publisher.RetryDue(t.Context())
		// Back, so every abandonment falls in the same audit window. The retry
		// schedule cares about the receipt's own deadline; the bound cares about
		// the hour, and they are different clocks.
		h.advance(-(zap.RetryWindow + time.Hour))
	}

	events, err := h.db.AuditEvents(t.Context(), 500)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	var abandoned, announcements int
	for _, e := range events {
		if e.Event != logging.EventZapReceiptAbandoned {
			continue
		}
		abandoned++
		// The ATTRIBUTE, not the message: Auditor.Record puts only the attrs in
		// the durable row, so a marker in the prose would not survive to the
		// place an operator reads it.
		if strings.Contains(e.Detail, `"bound"`) {
			announcements++
		}
	}
	if abandoned >= receipts {
		t.Errorf("%d of %d abandonments reached the trail; the bound is not bounding, and a "+
			"relay outage would evict every other event an operator needs", abandoned, receipts)
	}
	if abandoned == 0 {
		t.Error("no abandonment reached the trail at all; the bound must not silence the event, " +
			"only the repetition")
	}
	if announcements != 1 {
		t.Errorf("%d rows say the bound was reached, want exactly 1 — without it an operator "+
			"cannot tell a quiet hour from a flood they are not being shown", announcements)
	}
}

// slowPool stands in for a publish that takes measurable time.
//
// A fake that returned instantly would let publish_ms be a hardcoded zero and
// the assertion below would still pass — which is how a measurement comes to
// exist without measuring.
type slowPool struct {
	fakePool
	takes time.Duration
}

func (s *slowPool) Publish(ctx context.Context, event gonostr.Event,
	extra ...string) []nostr.PublishResult {
	time.Sleep(s.takes)
	return s.fakePool.Publish(ctx, event, extra...)
}

// du9 criterion 2 / k2z item 4: the receipt line carries how long the publish
// took.
//
// The interval between "relays chosen for this publish" and this line is where a
// flat fifteen seconds hid for weeks. The two lines bracketed it and neither
// stated it, so it was findable only by a human holding two timestamps side by
// side on a box — which is what eventually happened, and only by chance.
func TestTheReceiptLineSaysHowLongThePublishTook(t *testing.T) {
	const takes = 40 * time.Millisecond
	h := newHarness(t)
	hash := h.settle(t, zapRequest(t, nil))
	var logged bytes.Buffer

	h.publisherWith(&slowPool{takes: takes}, &logged).PublishNow(t.Context(), hash)

	line := ""
	for _, candidate := range strings.Split(strings.TrimSpace(logged.String()), "\n") {
		if strings.Contains(candidate, "zap receipt published") {
			line = candidate
		}
	}
	if line == "" {
		t.Fatalf("no receipt line was logged at all:\n%s", logged.String())
	}
	var record struct {
		PublishMS int64 `json:"publish_ms"`
	}
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatalf("the receipt line is not JSON: %s", line)
	}
	// Against the fake's own delay, so the number has to come from the clock
	// rather than from a constant. Halved, because a sleep is a floor and a
	// loaded CI box rounds the wrong way often enough to matter.
	if floor := (takes / 2).Milliseconds(); record.PublishMS < floor {
		t.Errorf("publish_ms = %d, want at least %d — the publish took %s and the line must "+
			"say so:\n%s", record.PublishMS, floor, takes, line)
	}
}
