package api_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/preflight"
	"github.com/davotoula/brollyzapper/internal/recon"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/wallet"
)

// seamWallet is everything this test drives: the admin UI's slice, the
// reconciler's slice, and the outbound path it asserts gets frozen. Declared
// here because the implementation is unexported — which is the point of §3's
// seam and the reason consumers name what they need.
type seamWallet interface {
	api.Wallet
	recon.Wallet
	Reserve(ctx context.Context, req wallet.Reservation) (wallet.ReservationID, error)
	Reverse(ctx context.Context, id wallet.ReservationID) error
	CreditInvoice(ctx context.Context, paymentHash, preimage string, amountPaidMsat int64,
		settledAt time.Time) (bool, error)
}

// nodeBalance is a stand-in for LND reporting its spendable balance.
type nodeBalance struct{ msat int64 }

func (n *nodeBalance) ChannelBalance(context.Context) (*lnrpc.ChannelBalanceResponse, error) {
	return &lnrpc.ChannelBalanceResponse{LocalBalance: &lnrpc.Amount{Msat: uint64(n.msat)}}, nil
}

// Criterion 7, and the seam §13 now warns about: both halves of this wire
// already existed and the wire itself had never been tested. The Auditor was
// built in the foundation wave and went uncalled for three waves while every
// component's own tests passed — so this asserts the END-TO-END fact, from a
// real shortfall to the Security panel and the frozen capability.
func TestARealShortfallReachesTheSecurityPanelAndFreezesSpending(t *testing.T) {
	h, node, reconciler, purse := newReconSeam(t, nil)
	ctx := t.Context()
	cookie := h.login(t)

	// The operator allocates more than the node can send.
	if err := purse.Allocate(ctx, 3_000_000_000, "over-allocated"); err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	// Before reconciliation runs, nothing knows — and the probe reservation is
	// reversed so it does not move the numbers this test asserts on.
	probe, err := purse.Reserve(ctx, wallet.Reservation{AmountMsat: 1_000, MaxFeeMsat: 100, PaymentHash: aPaymentHash(), Ref: "before"})
	if err != nil {
		t.Fatalf("Reserve before the check: %v", err)
	}
	if err := purse.Reverse(ctx, probe); err != nil {
		t.Fatalf("Reverse: %v", err)
	}

	if err := reconciler.Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}

	// 1. The capability is frozen.
	if _, err := purse.Reserve(ctx, wallet.Reservation{AmountMsat: 1_000, MaxFeeMsat: 100, PaymentHash: aPaymentHash(), Ref: "after"}); err == nil {
		t.Error("spending was not frozen by the shortfall")
	}

	// 2. The Security panel shows it, with the amount and a cause.
	panel := h.get(t, "/security", cookie).Body.String()
	if !strings.Contains(panel, "2000000000") {
		t.Errorf("the security panel does not show the shortfall amount:\n%s", panel)
	}
	if !strings.Contains(strings.ToLower(panel), "frozen") {
		t.Error("the security panel does not say spending is frozen")
	}
	if !strings.Contains(panel, "wallet.shortfall") {
		t.Error("the durable trail has no wallet.shortfall row for the freeze")
	}

	// 3. The degraded banner on every other page says so too — one report.
	walletPage := h.get(t, "/", cookie).Body.String()
	if !strings.Contains(walletPage, "spending is frozen") {
		t.Errorf("the wallet page does not carry the freeze in its banner:\n%s", walletPage)
	}

	// 4. Receiving is untouched.
	mintInvoiceFor(t, h.store, "hash-during-freeze", 21_000)
	credited, err := purse.CreditInvoice(ctx, "hash-during-freeze", "preimage", 21_000, time.Now().UTC())
	if err != nil || !credited {
		t.Errorf("CreditInvoice during the freeze = %v, %v; receiving must stay enabled", credited, err)
	}

	// 5. Recovery: the node grows, the freeze lifts with no operator action.
	node.msat = 9_000_000_000
	if err := reconciler.Check(ctx); err != nil {
		t.Fatalf("Check after recovery: %v", err)
	}
	if _, err := purse.Reserve(ctx, wallet.Reservation{AmountMsat: 1_000, MaxFeeMsat: 100, PaymentHash: aPaymentHash(), Ref: "recovered"}); err != nil {
		t.Errorf("Reserve after the shortfall cleared = %v, want it to succeed", err)
	}
	panel = h.get(t, "/security", cookie).Body.String()
	if strings.Contains(strings.ToLower(panel), "spending is frozen") {
		t.Error("the security panel still says spending is frozen after recovery")
	}
}

// dataDirAt700 matches what store.Open creates; t.TempDir does not, and a
// wide directory would add an unrelated failed check to the panel.
func dataDirAt700(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("securing the fixture data dir: %v", err)
	}
	return dir
}

func mintInvoiceFor(t *testing.T, db *store.Store, paymentHash string, amountMsat int64) {
	t.Helper()
	err := db.CreateInvoice(t.Context(), store.Invoice{
		PaymentHash: paymentHash, AmountMsat: amountMsat, DescriptionHash: "dh",
		Bolt11: "lnbcrt" + paymentHash, State: store.InvoiceOpen,
		CreatedAt: authTime, ExpiresAt: authTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}
}

// d46.21 criterion 3, and the seam that matters: the ceiling moves through the
// real form, and the Security page tells the truth on the very next render.
//
// Measured on the box: a ceiling allocated past the node's balance rendered
// `pass` for ~3.6 minutes, until recon's five-minute tick came round. §11's own
// words are that a checklist of green ticks bounding nothing is worse than no
// checklist, and a stale green tick is that failure in a different dress.
//
// The tick channel here NEVER fires. Anything this test observes is the
// allocation's own demand, so it cannot pass by waiting.
func TestAllocatingPastTheNodeShowsOnTheVeryNextSecurityRender(t *testing.T) {
	demand := make(chan struct{}, 1)
	h, _, reconciler, _ := newReconSeam(t, demand)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	never := make(chan time.Time)
	checked := make(chan error, 4)
	go reconciler.Run(ctx, never, demand, func(err error) { checked <- err })

	cookie := h.login(t)
	if before := h.get(t, "/security", cookie).Body.String(); strings.Contains(before, "2000000000") {
		t.Fatal("the panel showed a shortfall before one existed")
	}

	// 3,000,000 sats of ceiling against a node that can send 1,000,000.
	rec := h.postForm(t, "/wallet/allocate", cookie, url.Values{
		"sats": {"3000000"}, "note": {"d46.21"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /wallet/allocate = %d %q, want 303", rec.Code, rec.Body)
	}

	select {
	case err := <-checked:
		if err != nil {
			t.Fatalf("the reconciliation the allocation asked for failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("moving the ceiling asked for no reconciliation; the Security page would " +
			"show a confident green tick until the next five-minute tick")
	}

	panel := h.get(t, "/security", cookie).Body.String()
	if !strings.Contains(panel, "2000000000") {
		t.Errorf("the next Security render does not show the shortfall the allocation "+
			"just created:\n%s", panel)
	}
}

// newReconSeam wires the REAL chain: a real wallet over the real store, a real
// reconciler over it, and preflight reading the reconciler. That is the wiring
// these tests exist to exercise, and it lives in one place so a new
// preflight.Inputs field cannot be wired into one test and forgotten in the
// other.
func newReconSeam(t *testing.T, demand chan struct{}) (*harness, *nodeBalance,
	*recon.Reconciler, seamWallet) {
	t.Helper()
	quiet := logging.New(io.Discard, logging.NewLevelVar(slog.LevelDebug))
	node := &nodeBalance{msat: 1_000_000_000}
	dataDir := dataDirAt700(t)

	var purse seamWallet
	var reconciler *recon.Reconciler
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		purse = wallet.New(db, wallet.Options{Now: func() time.Time { return authTime }})
		reconciler = recon.New(node, purse, opts.Auditor, recon.Options{
			Now: func() time.Time { return authTime }, Log: quiet,
		})
		opts.Wallet = purse
		opts.Log = quiet
		if demand != nil {
			opts.ReconDemand = demand
		}
		opts.Preflight = func(ctx context.Context) preflight.Report {
			return preflight.Run(ctx, preflight.Inputs{
				NodeState: func() lnd.State { return lnd.StateReady },
				DataDir:   dataDir,
				Domain:    func(context.Context) (string, bool, string) { return "zap.example", true, "" },
				Shortfall: reconciler.Shortfall,
				Now:       func() time.Time { return authTime },
			})
		}
	})
	return h, node, reconciler, purse
}

// aPaymentHash is a distinct hash per call.
//
// txns.payment_hash is UNIQUE and these tests reserve more than once, so a
// shared literal would collide on the second reservation — and Reserve now
// REQUIRES one, because a pending payment_out without a hash is the
// unresolvable row §6 forbids reversing.
var paymentHashSeq atomic.Int64

func aPaymentHash() string { return fmt.Sprintf("%064x", paymentHashSeq.Add(1)) }
