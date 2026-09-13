package api_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/preflight"
)

// `20i.21` criterion 4. Nothing exercised the SERVER's credential against LND
// until an address was configured: "LND reachable from the guard" is the guard's
// view, and trip A2 had to configure a LAN-only address on a throwaway instance
// to force the call.
//
// THE COUNT IS THE HALF THAT MATTERS. A check that dials LND on every admin page
// load is `e0n` made worse, so the probe is asked once per interval however many
// pages render — here, the Node page and the Security panel, five times each.
func TestTheServerCredentialLineSaysNoAsOfAndAsksTheNodeOncePerInterval(t *testing.T) {
	var calls atomic.Int32
	now := time.Date(2026, 9, 13, 14, 5, 9, 0, time.UTC)
	clock := func() time.Time { return now }
	probe := preflight.NewCredentialProbe(t.Context(), func(context.Context) error {
		calls.Add(1)
		return status.Error(codes.Unauthenticated, "verification failed: signature mismatch")
	}, preflight.ProbeOptions{Interval: time.Minute, Now: clock, Spawn: func(f func()) { f() }})

	h := newHarness(t, livePreflight(lnd.StateReady, func(in *preflight.Inputs) {
		in.ServerCredential = probe.Result
	}))
	h.broker.Answer = lnd.BrokerStatus{ReceiveMacaroonPresent: true, LNDReachable: true}
	cookie := h.login(t)

	var node, security string
	for range 5 {
		node = h.get(t, "/node", cookie).Body.String()
		security = h.get(t, "/security", cookie).Body.String()
	}

	if got := calls.Load(); got != 1 {
		t.Errorf("ten admin renders inside one interval asked the node %d times, want 1", got)
	}
	if !strings.Contains(node, "<dt>LND reachable from the server</dt><dd>no, as of 14:05:09 UTC</dd>") {
		t.Errorf("the Node page does not say the server's credential failed, with its time:\n%s", node)
	}
	if !strings.Contains(security, "refused") || !strings.Contains(security, "as of 14:05:09 UTC") {
		t.Errorf("the Security panel does not carry the server-credential check:\n%s", security)
	}
	if strings.Contains(node+security, "signature mismatch") {
		t.Error("a page carries the node's own error text")
	}
}
