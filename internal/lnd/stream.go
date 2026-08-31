package lnd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
)

// ErrStreamAlreadyRunning is returned by a second RunInvoiceStream. Spec §6
// says subscribe ONCE for the process lifetime — a second subscription would
// double-deliver every settlement and race the resume point.
var ErrStreamAlreadyRunning = errors.New("lnd: the invoice stream is already running")

// SettleIndexStore persists the stream's resume point across restarts.
// internal/store implements it; declared here so this package needs no
// database (§3).
type SettleIndexStore interface {
	LastSettleIndex(ctx context.Context) (uint64, error)
	SetLastSettleIndex(ctx context.Context, index uint64) error
}

// InvoiceHandler is called once for each settled invoice, in settle order. It
// must be idempotent: LND re-delivers after a reconnect, and the guarantee that
// a replay is a no-op comes from UNIQUE(payment_hash) in the posting
// transaction, not from this loop (§6).
type InvoiceHandler func(ctx context.Context, invoice *lnrpc.Invoice) error

// RunInvoiceStream holds one SubscribeInvoices stream open for as long as ctx
// lives, reconnecting with capped exponential backoff forever.
//
// It returns only when ctx ends, or immediately if a stream is already running.
// It never terminates the process: an unreachable node, a rotated macaroon and
// an empty credential volume are all states plus a retry (§6, §11).
func (c *Client) RunInvoiceStream(ctx context.Context, resume SettleIndexStore, handle InvoiceHandler) error {
	if !c.streamRunning.CompareAndSwap(false, true) {
		return ErrStreamAlreadyRunning
	}
	defer c.streamRunning.Store(false)

	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		started := time.Now()
		received, err := c.streamOnce(ctx, resume, handle)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A stream that delivered something, or that simply stayed up longer
		// than the ceiling, was working — so the next failure starts from one
		// second again.
		//
		// Without this, attempt only ever increases: after half a dozen drops
		// in the process's whole life the delay pins at the maximum, and a
		// one-second blip a month later costs a full minute of not receiving.
		// That is the same symptom d46.20 was raised for — the box sitting at
		// "connecting" long after the cause had passed — reached by a second
		// route, and RetryNow only fixes the half an operator is watching.
		//
		// Two signals rather than one: a delivery is proof on a busy node, and
		// elapsed time is the only proof available on a quiet one, where a
		// month of clean uptime would otherwise leave the delay where the last
		// bad night put it.
		if received || time.Since(started) >= c.maxBackoff {
			attempt = 0
		}
		if err != nil {
			// The connection is dropped rather than reused so the next attempt
			// re-reads tls.cert, which LND regenerates on expiry.
			c.reconnect()
			c.log.Warn("invoice stream dropped; reconnecting",
				"error", err.Error(), "attempt", attempt+1, "state", string(c.State()))
		}
		if err := c.waitBeforeRetry(ctx, backoffDelay(attempt, c.minBackoff, c.maxBackoff)); err != nil {
			return err
		}
	}
}

// streamOnce opens the stream and pumps it until it ends, reporting whether it
// received anything — which is what tells the caller the stream was working
// rather than merely opened.
func (c *Client) streamOnce(ctx context.Context, resume SettleIndexStore, handle InvoiceHandler) (bool, error) {
	last, err := resume.LastSettleIndex(ctx)
	if err != nil {
		return false, fmt.Errorf("reading the resume point: %w", err)
	}
	client, err := c.lightning()
	if err != nil {
		return false, c.observeStream(ctx, err)
	}

	// LND sends every settlement with a settle_index STRICTLY GREATER than the
	// value given, so the resume point is the last index handled — not the next
	// one. Sending last+1 would skip exactly one settlement per reconnect, and
	// the symptom is an invoice that settles on the node and never credits the
	// wallet (proto: lnrpc.InvoiceSubscription.settle_index).
	stream, err := client.SubscribeInvoices(ctx, &lnrpc.InvoiceSubscription{SettleIndex: last})
	if err != nil {
		return false, c.observeStream(ctx, err)
	}

	var received bool
	for {
		invoice, err := stream.Recv()
		if err != nil {
			return received, c.observeStream(ctx, err)
		}
		received = true
		c.observeStream(ctx, nil)
		if invoice.State != lnrpc.Invoice_SETTLED {
			continue
		}
		if err := handle(ctx, invoice); err != nil {
			return received, fmt.Errorf("handling settlement at index %d: %w",
				invoice.SettleIndex, err)
		}
		if invoice.SettleIndex > 0 {
			if err := resume.SetLastSettleIndex(ctx, invoice.SettleIndex); err != nil {
				return received, fmt.Errorf("persisting the resume point: %w", err)
			}
		}
	}
}

// waitBeforeRetry waits out the backoff, returning early when RetryNow is
// called — which is what makes POST /node/relink take effect at once instead of
// after as much as a minute (d46.20).
func (c *Client) waitBeforeRetry(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.retry:
		return nil
	case <-timer.C:
		return nil
	}
}

// backoffDelay doubles from min up to max. There is exactly one client and one
// node, so there is no herd to spread out and no jitter to add.
func backoffDelay(attempt int, minDelay, maxDelay time.Duration) time.Duration {
	if attempt <= 0 {
		return minDelay
	}
	delay := minDelay
	for range attempt {
		delay *= 2
		if delay >= maxDelay {
			return maxDelay
		}
	}
	return delay
}
