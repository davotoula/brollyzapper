package lnd_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
)

// RunMiddleware does not return while a decision is still running.
//
// It answers on its own goroutines, and the Interceptor it answers with belongs
// to the caller — the guard, whose state store the caller is about to close. A
// return that raced a decision would be a write to a store nobody owns any more,
// and `-race` cannot see it because the two never touch the same variable: the
// hazard is lifetime, not memory.
func TestRunMiddlewareWaitsForDecisionsInFlight(t *testing.T) {
	node := lndtest.Start(t)
	client := middlewareClient(t, node.Address(), node)

	in := &blockingInterceptor{parked: make(chan struct{}), finish: make(chan struct{})}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- client.RunMiddleware(ctx, in) }()

	lndtest.WaitFor(t, "the registration", func() bool { return in.registered.Load() })
	go node.Intercept(t, &lnrpc.RPCMiddlewareRequest{
		RequestId: 1,
		InterceptType: &lnrpc.RPCMiddlewareRequest_Request{Request: &lnrpc.RPCMessage{
			MethodFullUri: lndtest.SendPaymentMethod,
		}},
	})
	<-in.parked // a decision is in flight and will not finish until we say so

	cancel()
	// The stream is gone — the fake's handler returns when its context is
	// cancelled — so RunMiddleware has had every chance to return. Waiting for
	// an OBSERVABLE consequence of the cancel rather than for a moment in time
	// is what makes this deterministic in both directions: with the wait in
	// place `done` cannot have fired, and without it, it will have.
	lndtest.WaitFor(t, "the stream to end", func() bool { return !node.MiddlewareIsLive() })
	select {
	case err := <-done:
		t.Fatalf("RunMiddleware returned (%v) while a decision was still running; the guard's "+
			"caller closes its store as soon as this returns, and the decision is about to "+
			"write to it", err)
	default:
	}

	close(in.finish)
	if err := <-done; err == nil {
		t.Error("RunMiddleware returned nil after its context was cancelled")
	}
	if n := in.inFlight.Load(); n != 0 {
		t.Errorf("%d decisions were still running when RunMiddleware returned", n)
	}
}

type blockingInterceptor struct {
	registered atomic.Bool
	// parked is closed once a decision is in flight; finish releases it.
	parked   chan struct{}
	finish   chan struct{}
	inFlight atomic.Int64
	once     atomic.Bool
}

func (b *blockingInterceptor) MiddlewareRegistered() { b.registered.Store(true) }

func (b *blockingInterceptor) InterceptRequest(ctx context.Context, _ lnd.Interception) error {
	if !b.once.CompareAndSwap(false, true) {
		return nil
	}
	b.inFlight.Add(1)
	defer b.inFlight.Add(-1)
	close(b.parked)
	// Deliberately ignores ctx, which is what makes the wait observable: an
	// implementation that returned on cancel would let RunMiddleware return
	// either way and the test would prove nothing. Real implementations must
	// NOT do this — see the Interceptor doc.
	<-b.finish
	return nil
}

func (b *blockingInterceptor) ObserveResponse(context.Context, lnd.Interception) {}

// "The node is down" and "the node will not have us" are different answers.
//
// They arrive at the SAME call — grpc-go's NewStream is fail-fast, so an
// unreachable node fails exactly where a refusal does — and only the status code
// separates them. Conflating them costs the operator an ERROR every backoff
// during any ordinary LND restart, pointing at `rpcmiddleware.enable`, a setting
// that is fine. The doc comment said the distinction existed before this test
// did; it did not.
func TestARefusedRegistrationIsDistinguishedFromAnUnreachableNode(t *testing.T) {
	t.Run("the node refuses", func(t *testing.T) {
		node := lndtest.Start(t)
		node.SetMiddlewareRegistrationError(errors.New("rpc middleware not enabled in config"))
		client := middlewareClient(t, node.Address(), node)

		err := client.RunMiddleware(t.Context(), &blockingInterceptor{
			parked: make(chan struct{}), finish: make(chan struct{})})

		if !errors.Is(err, lnd.ErrMiddlewareUnavailable) {
			t.Errorf("a node that refused the registration gave %v; the operator needs to be "+
				"told to check rpcmiddleware.enable", err)
		}
	})
	t.Run("the node is unreachable", func(t *testing.T) {
		node := lndtest.Start(t)
		client := middlewareClient(t, "127.0.0.1:1", node)

		err := client.RunMiddleware(t.Context(), &blockingInterceptor{
			parked: make(chan struct{}), finish: make(chan struct{})})

		if err == nil {
			t.Fatal("dialling nothing succeeded")
		}
		if errors.Is(err, lnd.ErrMiddlewareUnavailable) {
			t.Errorf("an unreachable node reads as one that refuses the registration (%v); "+
				"every LND restart would tell the operator to change a setting that is fine", err)
		}
	})
}

func middlewareClient(t *testing.T, address string, node *lndtest.Node) *lnd.Client {
	t.Helper()
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, lndtest.Macaroon(t))
	client := lnd.New(address, lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon),
		testOptions(&lndtest.Broker{}))
	t.Cleanup(func() { _ = client.Close() })
	return client
}
