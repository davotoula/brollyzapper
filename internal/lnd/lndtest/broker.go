package lndtest

import (
	"context"
	"sync"

	"github.com/davotoula/brollyzapper/internal/lnd"
)

// Broker is a fake credential broker: what internal/guard supplies in
// production, and what both the lnd client and the admin UI need a stand-in for
// in tests.
type Broker struct {
	mu    sync.Mutex
	calls int
	bakes int
	// Answer is what Status returns.
	Answer lnd.BrokerStatus
	Err    error
}

// RequestReceiveBake records the request and returns the configured error.
func (b *Broker) RequestReceiveBake(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bakes++
	return b.Err
}

// Status records the call and returns the configured answer.
func (b *Broker) Status(context.Context) (lnd.BrokerStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	return b.Answer, b.Err
}

// Bakes is how many times a re-bake was requested.
func (b *Broker) Bakes() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.bakes
}

// StatusCalls is how many times Status reached this broker — the number a TTL
// cache is meant to keep down.
func (b *Broker) StatusCalls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

// SetError makes every call fail, the way an absent guard socket does.
func (b *Broker) SetError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Err = err
}
