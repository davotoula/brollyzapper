package api

import (
	"context"
	"sync"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd"
)

// NodeStatusTTL is how long one answer from the guard is reused.
//
// Deliberately a package-level constant rather than a number inside a handler:
// guard.Status makes one or two gRPC calls to LND per invocation and caches
// nothing itself, so the Node and Security pages — which are exactly the ones
// an operator leaves open — would otherwise poll LND on every refresh.
const NodeStatusTTL = 10 * time.Second

// CachedBroker wraps the guard's socket client with a short TTL.
//
// It implements lnd.CredentialBroker itself, so the same value serves the admin
// UI and the LND client's re-bake path.
type CachedBroker struct {
	broker lnd.CredentialBroker
	ttl    time.Duration
	now    func() time.Time

	mu       sync.Mutex
	status   lnd.BrokerStatus
	fetched  time.Time
	hasValue bool
}

// NewCachedBroker wraps broker. A nil clock gets time.Now.
func NewCachedBroker(broker lnd.CredentialBroker, ttl time.Duration, now func() time.Time) *CachedBroker {
	if now == nil {
		now = time.Now
	}
	return &CachedBroker{broker: broker, ttl: ttl, now: now}
}

// Status returns a cached answer when one is fresh enough.
//
// Errors are never cached: the guard's socket appearing has to show up on the
// next page load, not one TTL after it.
func (c *CachedBroker) Status(ctx context.Context) (lnd.BrokerStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hasValue && c.now().Sub(c.fetched) < c.ttl {
		return c.status, nil
	}
	status, err := c.broker.Status(ctx)
	if err != nil {
		return lnd.BrokerStatus{}, err
	}
	c.status, c.fetched, c.hasValue = status, c.now(), true
	return status, nil
}

// Invalidate drops the cached answer, for the paths that change what Status
// reports — baking or revoking a macaroon.
func (c *CachedBroker) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hasValue = false
}

// RequestReceiveBake passes straight through and invalidates, because it
// changes what Status would say.
func (c *CachedBroker) RequestReceiveBake(ctx context.Context) error {
	err := c.broker.RequestReceiveBake(ctx)
	c.Invalidate()
	return err
}
