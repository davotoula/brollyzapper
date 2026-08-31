package api_test

import (
	"errors"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
)

// Criterion 10: guard.Status() makes one or two gRPC calls per invocation with
// no caching of its own. A Node or Security page that polls it without a TTL
// turns the admin UI into a load generator against LND.
func TestGuardStatusIsCachedForItsTTL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	upstream := &lndtest.Broker{Answer: lnd.BrokerStatus{LNDReachable: true}}
	cached := api.NewCachedBroker(upstream, api.NodeStatusTTL, func() time.Time { return now })

	for range 20 {
		if _, err := cached.Status(t.Context()); err != nil {
			t.Fatalf("Status: %v", err)
		}
	}
	if got := upstream.StatusCalls(); got != 1 {
		t.Errorf("20 polls made %d calls to the guard, want 1 inside the TTL", got)
	}

	now = now.Add(api.NodeStatusTTL + time.Second)
	if _, err := cached.Status(t.Context()); err != nil {
		t.Fatalf("Status after the TTL: %v", err)
	}
	if got := upstream.StatusCalls(); got != 2 {
		t.Errorf("after the TTL expired the guard was called %d times, want 2", got)
	}
}

// A failing guard must not be cached as though it were an answer: the socket
// coming back has to be visible on the next page load, not one TTL later.
func TestAFailedStatusIsNotCached(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	upstream := &lndtest.Broker{Err: errors.New("guard: dialling /credentials/guard.sock: no such file")}
	cached := api.NewCachedBroker(upstream, api.NodeStatusTTL, func() time.Time { return now })

	for range 3 {
		if _, err := cached.Status(t.Context()); err == nil {
			t.Fatal("Status hid the guard's error")
		}
	}
	if got := upstream.StatusCalls(); got != 3 {
		t.Errorf("a failing guard was called %d times, want 3 — failures are not cached", got)
	}
}

// The cache is a decorator: it must still satisfy the interface internal/lnd
// declared, so the same value can be handed to the lnd client.
func TestCachedBrokerIsStillACredentialBroker(t *testing.T) {
	var _ lnd.CredentialBroker = api.NewCachedBroker(&lndtest.Broker{}, time.Second, nil)
}
