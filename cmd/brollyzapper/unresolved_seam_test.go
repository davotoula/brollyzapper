package main

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/recon"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/wallet"
)

// u0u, the whole bead in one arc, over real components.
//
// Boot with a payment a previous run left in flight and a node that will not
// answer. The app must START (§11: a missing dependency is a degraded state,
// never a refusal to run) — and spending must be HELD, because the ceiling is
// carrying a reservation whose fate nobody knows. Then the node comes back,
// reconciliation's demand fires, the payment resolves, and the hold lifts with
// no operator action and no restart.
//
// The wire is what this is for. The wallet's freeze reads a store query, the
// resolver writes through the wallet, and the recon loop drives it — three
// packages whose own tests each pass with the seam broken.
func TestSpendingIsHeldUntilAPreviousRunsPaymentResolves(t *testing.T) {
	node := lndtest.Start(t)
	db, dir := openSeamStore(t)

	// --- the previous run: a payment reserved and never resolved ------------
	past := time.Now().Add(-time.Hour)
	previous := wallet.New(db, wallet.Options{
		Now:       func() time.Time { return past },
		StartedAt: past,
	})
	if err := previous.Allocate(t.Context(), 1_000_000, "float"); err != nil {
		t.Fatal(err)
	}
	hashHex := hex.EncodeToString([]byte{0x0f, 0xf1, 0xce})
	_, err := previous.Reserve(t.Context(), wallet.Reservation{AmountMsat: 30_000, MaxFeeMsat: 900, PaymentHash: hashHex, Ref: "the run that died"})
	if err != nil {
		t.Fatal(err)
	}

	// --- this run boots, and the node is not answering ----------------------
	startedAt := time.Now()
	purse := wallet.New(db, wallet.Options{StartedAt: startedAt})
	node.SetRejectWith(errors.New("the node is not up yet"))
	client := seamClient(t, node, dir)

	// The startup pass runs and fails. That must not stop anything.
	if err := resolvePendingPayments(t.Context(), db, purse, client, db, startedAt,
		quietLog()); err == nil {
		t.Fatal("the startup pass reported success against a node that was refusing everything")
	}

	// Held — and this is the invariant that used to be an ordering.
	if _, err := purse.Reserve(t.Context(), wallet.Reservation{AmountMsat: 1_000, MaxFeeMsat: 10, PaymentHash: "new", Ref: "this run"}); !errors.Is(err,
		wallet.ErrPaymentsUnresolved) {
		t.Fatalf("Reserve = %v, want the unresolved-payments hold; §6 says a pending payment is "+
			"resolved BEFORE new ones are accepted, and a failed startup pass must leave the "+
			"invariant standing rather than drop it", err)
	}

	// --- the node comes back, and reconciliation notices --------------------
	node.SetRejectWith(nil)
	node.SetTrackedPayment([]byte{0x0f, 0xf1, 0xce}, lndtest.Succeeded(120))

	demand := make(chan struct{}, 1)
	reconciler := recon.New(nodeBalance{}, purse, noAudit{}, recon.Options{
		Log: quietLog(),
		ResolvePayments: func(ctx context.Context) error {
			return resolvePendingPayments(ctx, db, purse, client, db, startedAt, quietLog())
		},
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	never := make(chan time.Time)
	checked := make(chan error, 4)
	go reconciler.Run(ctx, never, demand, func(err error) { checked <- err })

	// The tick channel never fires, so anything below is the DEMAND — the same
	// signal a ceiling change uses, and the reason "the node came back" means
	// "resolved now" rather than "resolved within five minutes".
	demand <- struct{}{}
	select {
	case <-checked:
	case <-time.After(5 * time.Second):
		t.Fatal("reconciliation never ran")
	}

	if got := txnState(t, db, hashHex); got != store.TxnSettled {
		t.Errorf("the stale payment is %q, want settled — the node said it succeeded", got)
	}
	if _, err := purse.Reserve(t.Context(), wallet.Reservation{AmountMsat: 1_000, MaxFeeMsat: 10, PaymentHash: "after", Ref: "this run"}); err != nil {
		t.Errorf("Reserve after the payment resolved: %v — the hold must lift by itself, with "+
			"no operator action and no restart", err)
	}
}

// nodeBalance is recon.Node reduced to what this test needs.
//
// The balance comparison is not the subject — the resolver riding the loop is —
// so it answers a fixed figure and lets Check run to completion. A real client
// here would make the test about reconciliation instead.
type nodeBalance struct{}

func (nodeBalance) ChannelBalance(context.Context) (*lnrpc.ChannelBalanceResponse, error) {
	return &lnrpc.ChannelBalanceResponse{
		LocalBalance: &lnrpc.Amount{Msat: 1_000_000_000},
	}, nil
}

// noAudit discards the reconciler's events. §12's trail is asserted where §12
// is the subject; here it would only be noise.
type noAudit struct{}

func (noAudit) Record(context.Context, slog.Level, string, logging.Event, ...slog.Attr) error {
	return nil
}
