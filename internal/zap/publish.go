package zap

import (
	"context"
	"errors"
	"log/slog"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/store"
)

// §7's retry window, and the shape of the backoff inside it.
const (
	// RetryWindow is how long a receipt keeps trying. §7: a zap that credits
	// the wallet but never publishes a receipt is invisible to the sender and
	// reads as theft — so the answer to "every relay is down" is to keep
	// trying, for long enough to outlast an outage a person would sleep through.
	RetryWindow = 24 * time.Hour
	// FirstBackoff and MaxBackoff bound the doubling between attempts. The
	// first retry is soon because the commonest failure is a relay that dropped
	// one connection; the cap stops a day-long window from being spent on four
	// attempts.
	FirstBackoff = 30 * time.Second
	MaxBackoff   = 30 * time.Minute
	// BatchSize bounds how many due receipts one tick publishes. A box that has
	// been offline comes back with everything due at once, and publishing them
	// all together would open a websocket per relay per receipt simultaneously.
	BatchSize = 8
	// queueDepth is how many freshly settled zaps can be waiting for the
	// publisher before OnSettled falls back to the durable queue. Small on
	// purpose: this is a hand-off buffer, not a second queue — the real one is
	// the table, and it survives restarts.
	queueDepth = 32
)

// Store is the slice of the database this package needs. Declared here, by the
// consumer: it can read a settled zap and manage the retry queue, and it has no
// way to credit a wallet or settle an invoice.
type Store interface {
	SettledZapFor(ctx context.Context, paymentHash string) (store.SettledZap, error)
	QueueZapReceipt(ctx context.Context, r store.PendingReceipt) error
	DueZapReceipts(ctx context.Context, now time.Time, limit int) ([]store.PendingReceipt, error)
	DropZapReceipt(ctx context.Context, paymentHash string) error
	RecordZapReceipt(ctx context.Context, paymentHash, eventID string) error
}

// Signer signs a receipt with the identity currently in force.
type Signer interface {
	Sign(ctx context.Context, event *gonostr.Event) error
}

// Pool publishes to relays and says what each one answered.
type Pool interface {
	Publish(ctx context.Context, event gonostr.Event, extra ...string) []nostr.PublishResult
}

// Auditor writes a security event to the log AND to the durable trail (§12).
// Declared here by the consumer, holding the one method this package needs.
type Auditor interface {
	Record(ctx context.Context, level slog.Level, msg string, event logging.Event,
		attrs ...slog.Attr) error
}

// Publisher builds and publishes zap receipts, and keeps trying.
type Publisher struct {
	store   Store
	signer  Signer
	pool    Pool
	now     func() time.Time
	log     *slog.Logger
	auditor Auditor

	// abandonBudget bounds how many abandoned receipts reach §12's trail in an
	// hour. See abandon for why this writer needs one at all.
	abandonBudget *logging.RefusalBudget

	// settled hands freshly settled payment hashes to the single publishing
	// goroutine. See OnSettled for why publication must not happen on the
	// caller's own goroutine.
	settled chan string
}

// New wires the publisher.
func New(db Store, signer Signer, pool Pool, auditor Auditor, now func() time.Time,
	log *slog.Logger) *Publisher {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = logging.Default()
	}
	return &Publisher{
		store: db, signer: signer, pool: pool, auditor: auditor, now: now, log: log,
		abandonBudget: logging.NewRefusalBudget(0, now),
		settled:       make(chan string, queueDepth),
	}
}

// OnSettled asks for the receipt of a freshly settled invoice, WITHOUT waiting
// for it.
//
// §7 says publication must never block or fail settlement, and an earlier
// version of this satisfied only the second half. It published inline, on the
// invoice stream's own goroutine — and internal/lnd's stream is strictly
// serial: receive, handle, then write the durable resume point. A publish is
// bounded only by the pool's 30-second timeout, so one unreachable relay stalled
// the next settlement for half a minute and left the settle-index checkpoint
// that stale. Ten zaps during a relay outage was five minutes of stopped
// stream. Preventing the error from propagating is not the same as not blocking.
//
// So this hands off and returns. When the hand-off buffer is full — a burst
// larger than the publisher is draining — it falls back to the DURABLE queue
// with an immediate due time, which is the same path a failed publish takes and
// needs no new machinery. Either way the caller is not kept waiting, and either
// way the receipt is not lost.
func (p *Publisher) OnSettled(ctx context.Context, paymentHash string) {
	// Queue the obligation BEFORE handing off, so "a receipt is owed" is a
	// durable fact from the moment the money lands rather than only after an
	// attempt has failed.
	//
	// Two things depend on it. The Wallet page infers a receipt's state from
	// what is recorded, and without this a healthy zap shows as "abandoned" —
	// the most alarming of the three words — for the seconds between settling
	// and its first attempt, because "no receipt id and nothing queued" was
	// also what a genuinely abandoned one looked like. And a crash in that
	// same window left no trace at all that a receipt was owed (bead 6b4's
	// window, narrowed again here).
	//
	// The row is dropped as soon as the publish succeeds, so a receipt that
	// works first time costs one insert and one delete.
	if err := p.store.QueueZapReceipt(ctx, store.PendingReceipt{
		PaymentHash:   paymentHash,
		GiveUpAt:      p.now().Add(RetryWindow),
		NextAttemptAt: p.now().Add(FirstBackoff),
	}); err != nil {
		p.log.Error("could not record that a zap receipt is owed",
			logging.PaymentHash(paymentHash), "error", err.Error())
	}

	select {
	case p.settled <- paymentHash:
	default:
		// Already queued above, so the retry loop will pick it up; nothing to
		// do but say so.
		p.log.Warn("the zap receipt hand-off is full; the retry loop will take it",
			logging.PaymentHash(paymentHash))
	}
}

// PublishNow builds and publishes the receipt for one settled invoice,
// synchronously. It is what the publishing goroutine does with a hand-off, and
// what the retry loop does with a due row.
func (p *Publisher) PublishNow(ctx context.Context, paymentHash string) {
	zap, err := p.store.SettledZapFor(ctx, paymentHash)
	if errors.Is(err, store.ErrNotFound) {
		// An ordinary LNURL payment, or a settlement for something this node
		// did not mint. Neither has a receipt.
		return
	}
	if err != nil {
		p.log.Error("could not read a settled zap; no receipt will be published",
			logging.PaymentHash(paymentHash), "error", err.Error())
		return
	}
	p.attempt(ctx, zap, store.PendingReceipt{
		PaymentHash: paymentHash,
		GiveUpAt:    p.now().Add(RetryWindow),
	})
}

// attempt builds, signs and publishes one receipt, queueing a retry if no relay
// took it.
func (p *Publisher) attempt(ctx context.Context, zap store.SettledZap, pending store.PendingReceipt) {
	// One hash, one variable. Both copies were always the same value and the
	// two halves of this function had drifted into reading different ones.
	pending.PaymentHash = zap.PaymentHash
	event, relays, err := Build(zap)
	if err != nil {
		// Unpublishable rather than unlucky: a stored zap request that no
		// longer parses will not parse on the next attempt either, so retrying
		// would be a loop that never ends and never succeeds.
		//
		// Abandoned rather than merely dropped (zu5.4). This is the same fact
		// the retry window's give-up records — the wallet was credited and the
		// sender was never told — and it is worse here, because it is decided
		// on the FIRST attempt and no further attempt will revisit it. It went
		// only to the log, which rotates; the question it answers arrives weeks
		// later.
		p.abandon(ctx, pending, "a settled zap cannot be turned into a receipt; not retrying", err)
		return
	}
	// Signed with the key READ NOW, on every attempt including retries: an
	// operator who replaces the nostr key mid-retry gets receipts from the
	// identity their address currently announces (§7, criterion 5).
	if err := p.signer.Sign(ctx, event); err != nil {
		p.reschedule(ctx, pending, err)
		return
	}

	results := p.pool.Publish(ctx, *event, relays...)
	accepted := nostr.Accepted(results)
	if accepted == 0 {
		p.reschedule(ctx, pending, relayFailure(results))
		return
	}

	if err := p.store.RecordZapReceipt(ctx, zap.PaymentHash, event.ID); err != nil {
		p.log.Error("published a zap receipt but could not record its id",
			logging.PaymentHash(zap.PaymentHash), "error", err.Error())
	}
	p.drop(ctx, pending)
	p.log.Info("zap receipt published", logging.PaymentHash(zap.PaymentHash),
		"event_id", logging.Short(event.ID), "relays", len(results), "accepted", accepted)
}

// reschedule queues the next attempt, or gives up once the window has passed.
func (p *Publisher) reschedule(ctx context.Context, pending store.PendingReceipt, cause error) {
	now := p.now()
	pending.Attempts++
	pending.LastError = cause.Error()

	if !now.Before(pending.GiveUpAt) {
		p.abandon(ctx, pending, "giving up on a zap receipt after the retry window; "+
			"the sender was credited but never told", cause)
		return
	}

	pending.NextAttemptAt = now.Add(backoff(pending.Attempts))
	if pending.NextAttemptAt.After(pending.GiveUpAt) {
		pending.NextAttemptAt = pending.GiveUpAt
	}
	// WithoutCancel: this write is what makes "retry after a restart" true, and
	// the commonest reason a publish fails at all is that the process is being
	// shut down — the very moment ctx is cancelled. Writing the queue row on
	// the caller's ctx meant the row failed to appear in exactly the case the
	// queue exists for, leaving a credited zap with no record that a receipt
	// was owed.
	if err := p.store.QueueZapReceipt(context.WithoutCancel(ctx), pending); err != nil {
		p.log.Error("could not queue a zap receipt for retry",
			logging.PaymentHash(pending.PaymentHash), "error", err.Error())
		return
	}
	p.log.Warn("no relay accepted a zap receipt; queued for retry",
		logging.PaymentHash(pending.PaymentHash), "attempts", pending.Attempts,
		"next_attempt", pending.NextAttemptAt, "error", pending.LastError)
}

// drop clears a queued receipt. Every receipt is queued at settlement now, so
// this always has a row to remove — the unconditional-delete comment that used
// to live here described the earlier design, where a first-attempt success had
// never been recorded.
// abandon records a receipt that will never be published, then clears its row.
//
// §7's worst case, and it is worth saying loudly rather than quietly dropping a
// row: the wallet was credited and the sender was never told. Through the
// Auditor, so the row outlives log rotation. This is the one fact this package
// produces that somebody may come asking about weeks later — "you took my sats
// and I never got a receipt" — and §12 keeps a durable trail for exactly that
// question.
//
// ONE door for both permanent failures. They had drifted apart: the retry
// window's give-up recorded an audit event and the unparseable-request drop
// wrote a log line, so the same fact was durable or not depending on which way
// it happened.
func (p *Publisher) abandon(ctx context.Context, pending store.PendingReceipt, why string, cause error) {
	// BOUNDED, because a stranger drives this one (t0b). Anybody can pay zap
	// invoices, and a relay outage abandons every receipt in the queue at the
	// end of its retry window — so an unbounded writer here lets somebody who is
	// not the operator flush §12's 10 000-row ring and take `macaroon.bake` with
	// it. The first rows of an outage carry the whole story; the five hundredth
	// says the same thing and costs a row that recorded something else.
	//
	// The refusal still HAPPENS and is still logged at ERROR either way. And the
	// bound announces itself once per window, so an operator can tell a quiet
	// hour from a flood they are not being shown.
	record, sayBounded := p.abandonBudget.Allow()
	switch {
	case p.auditor == nil:
	case record:
		if err := p.auditor.Record(ctx, slog.LevelError, why, logging.EventZapReceiptAbandoned,
			logging.PaymentHash(pending.PaymentHash),
			slog.Int("attempts", pending.Attempts),
			slog.String("error", cause.Error())); err != nil {
			p.log.Error("could not write the audit trail",
				logging.PaymentHash(pending.PaymentHash), "error", err.Error())
		}
	case sayBounded:
		if err := p.auditor.Record(ctx, slog.LevelError,
			"more zap receipts are being abandoned than this hour's audit bound allows; "+
				"the rest are in the log only",
			logging.EventZapReceiptAbandoned,
			slog.Int("bound", logging.DefaultRefusalsPerHour)); err != nil {
			p.log.Error("could not write the audit trail", "error", err.Error())
		}
	}
	if !record {
		p.log.Error(why, logging.PaymentHash(pending.PaymentHash),
			slog.Int("attempts", pending.Attempts), "error", cause.Error(),
			"audited", false)
	}
	p.drop(ctx, pending)
}

func (p *Publisher) drop(ctx context.Context, pending store.PendingReceipt) {
	if err := p.store.DropZapReceipt(ctx, pending.PaymentHash); err != nil {
		p.log.Error("could not clear a queued zap receipt",
			logging.PaymentHash(pending.PaymentHash), "error", err.Error())
	}
}

// backoff doubles from FirstBackoff up to MaxBackoff.
func backoff(attempts int) time.Duration {
	wait := FirstBackoff
	for range attempts - 1 {
		if wait >= MaxBackoff {
			break
		}
		wait *= 2
	}
	return min(wait, MaxBackoff)
}

// relayFailure summarises why nothing took the receipt.
//
// It is only called when no relay accepted, so every result carries an error
// and the first one is representative — the errors on this path are almost
// always the same connection failure repeated. Joining them would put a
// paragraph in last_error for no extra information.
func relayFailure(results []nostr.PublishResult) error {
	if len(results) == 0 {
		return errors.New("no relay was tried")
	}
	return results[0].Err
}

// RunRetry is the single publishing goroutine: it drains freshly settled zaps
// and republishes queued ones, until ctx ends.
//
// ONE goroutine, deliberately. It is what keeps a settlement and a retry from
// being in flight for the same payment hash at once — which would publish the
// same receipt twice and race the attempt counter — and it bounds how many
// relay connections this node opens at a time to one receipt's worth.
//
// The tick channel is the caller's, so a test drives the schedule instead of
// waiting for it, and a test that never ticks proves nothing passes by the mere
// passage of time (criterion 10). Same shape as the reconciliation and
// guard-event loops.
func (p *Publisher) RunRetry(ctx context.Context, tick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case paymentHash := <-p.settled:
			p.PublishNow(ctx, paymentHash)
		case _, ok := <-tick:
			if !ok {
				return
			}
			p.RetryDue(ctx)
		}
	}
}

// RetryDue publishes one batch of receipts whose next attempt has arrived.
func (p *Publisher) RetryDue(ctx context.Context) {
	due, err := p.store.DueZapReceipts(ctx, p.now(), BatchSize)
	if err != nil {
		p.log.Error("could not read due zap receipts", "error", err.Error())
		return
	}
	for _, pending := range due {
		zap, err := p.store.SettledZapFor(ctx, pending.PaymentHash)
		if err != nil {
			p.log.Error("a queued zap receipt has no settled zap behind it; dropping",
				logging.PaymentHash(pending.PaymentHash), "error", err.Error())
			p.drop(ctx, pending)
			continue
		}
		p.attempt(ctx, zap, pending)
	}
}
