package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/nwc"
)

// `v7u`: the node's identity is read ONCE, however many payments ask for it.
//
// The rung that recognises a self-payment runs on every pay_invoice, and the
// question it asks has a constant answer — a running node's identity is the
// node. A GetInfo per payment would put a round trip on the path of every
// payment to learn something that cannot have changed, which is the one way this
// containment fix could cost more than the failure it prevents.
func TestTheNodesIdentityIsReadOnceAndRemembered(t *testing.T) {
	var reads int
	spend := nwcSpend{log: quietLog(), identity: &nodeIdentity{
		info: func(context.Context) (nwc.NodeInfo, error) {
			reads++
			return nwc.NodeInfo{Pubkey: "02aaaa"}, nil
		},
	}}

	for range 5 {
		if got := spend.NodeIdentity(t.Context()); got != "02aaaa" {
			t.Fatalf("NodeIdentity = %q, want the node's pubkey", got)
		}
	}
	if reads != 1 {
		t.Errorf("GetInfo was called %d times for 5 payments, want 1 — the identity of a "+
			"running node cannot change under it", reads)
	}
}

// A FAILURE IS NOT REMEMBERED, and it does not refuse.
//
// Both halves matter and they pull in opposite directions. Caching the failure
// would leave a node that was unreachable at its first pay_invoice permanently
// unable to recognise its own invoices — for the life of the process, with no
// way to clear it. Refusing on it would take sending away for a transient, which
// is a worse outage than the misclick this rung exists to catch.
func TestAFailedIdentityReadIsNotCachedAndDoesNotRefuse(t *testing.T) {
	var reads int
	failing := true
	spend := nwcSpend{log: quietLog(), identity: &nodeIdentity{
		info: func(context.Context) (nwc.NodeInfo, error) {
			reads++
			if failing {
				return nwc.NodeInfo{}, errors.New("the node is not answering")
			}
			return nwc.NodeInfo{Pubkey: "02aaaa"}, nil
		},
	}}

	// Empty, which the ladder's rung reads as "could not tell" and never as a
	// match — see the no-destination case in internal/nwc's table.
	if got := spend.NodeIdentity(t.Context()); got != "" {
		t.Errorf("NodeIdentity = %q after a failed read, want empty", got)
	}

	failing = false
	if got := spend.NodeIdentity(t.Context()); got != "02aaaa" {
		t.Errorf("NodeIdentity = %q once the node answered, want the pubkey — a failure that "+
			"stuck would disable the self-payment rung for the life of the process", got)
	}
	if reads != 2 {
		t.Errorf("the identity was read %d times, want 2: one failure, then one success", reads)
	}
}

// And the seam: the pubkey the ladder compares against is the one the NODE
// reports, through a real client and a real GetInfo.
//
// THROUGH THE RECEIVE MACAROON, which is not a detail — GetInfo is in
// ReceivePermissions and NOT in SpendPermissions (§6), so the spend client the
// rest of nwcSpend uses cannot ask this question at all. A wiring that pointed
// the memo at the spend client would fail here rather than in the field, where
// it would surface as a self-payment rung that never fires.
func TestTheIdentityMemoReadsThroughTheReceiveClient(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, lndtest.Macaroon(t, "receive"))
	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon),
		lnd.Options{MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })

	spend := nwcSpend{log: quietLog(), identity: &nodeIdentity{info: nwcNode{node: client}.Info}}

	if got := spend.NodeIdentity(t.Context()); got != "02aaaa" {
		t.Errorf("NodeIdentity = %q, want the identity_pubkey the node reported", got)
	}
}

// A zero adapter answers empty rather than panicking.
//
// Not defensive noise: nwcSpend is a value type and several tests build one with
// only the fields they care about, so a nil memo is a shape this method really
// meets. The same reason SendingBlocked answers "preflight.unavailable" for a
// nil checks function.
func TestAnAdapterWithNoIdentityMemoAnswersEmpty(t *testing.T) {
	if got := (nwcSpend{}).NodeIdentity(t.Context()); got != "" {
		t.Errorf("NodeIdentity = %q on an adapter with no memo, want empty", got)
	}
}
