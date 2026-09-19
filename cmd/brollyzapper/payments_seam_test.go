package main

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/wallet"
)

// §13's seam: the process dies mid-payment and a NEW one finishes the job.
//
// Everything here is real except the node — a real sqlite store, the real
// wallet, the real lnd client over a real gRPC connection — because the thing
// under test is the WIRE between them. Per-package coverage cannot see it: the
// wallet's tests prove Reserve/Settle, the client's tests prove SendPayment,
// and neither can prove that a reservation made by one process is resolved by
// the next using a hash written by the first.
//
// The crash is simulated for real rather than described: the node accepts the
// payment and resolves it, the sending call dies before it hears the answer,
// and a second resolver — a different instance over the same database, which is
// what a restart is — reconciles them.
//
// BOTH directions, because they differ by one branch and the difference is
// money: a payment that succeeded while we were dead is SETTLED, and one that
// failed is REVERSED. A resolver that always settled would pass the first.
func TestACrashMidPaymentIsResolvedByTheNextProcess(t *testing.T) {
	for _, tc := range []struct {
		name string
		// what the node says when asked afterwards
		outcome *lnrpc.Payment
		// what the ceiling must look like once the dust settles
		wantSpentMsat int64
		wantState     string
	}{{
		name:    "it succeeded while we were dead",
		outcome: lndtest.Succeeded(300),
		// The amount, plus the fee the route ACTUALLY used — not the 1_000 that
		// was reserved. The rest comes back.
		wantSpentMsat: 50_000 + 300,
		wantState:     store.TxnSettled,
	}, {
		name:    "it failed while we were dead",
		outcome: lndtest.FailedBecause(lnrpc.PaymentFailureReason_FAILURE_REASON_NO_ROUTE),
		// Nothing. A failed payment consumes no budget (§5).
		wantSpentMsat: 0,
		wantState:     store.TxnFailed,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			node := lndtest.Start(t)
			db, dir := openSeamStore(t)
			purse := wallet.New(db, wallet.Options{})
			if err := purse.Allocate(t.Context(), 1_000_000, "float"); err != nil {
				t.Fatal(err)
			}
			before, err := purse.Balance(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			const bolt11 = "lnbcrt500u1pseam"
			hashHex := hex.EncodeToString([]byte{0xde, 0xad, 0xbe, 0xef})
			node.SetPaymentDispatchedThenLost(bolt11, hashHex, tc.outcome)

			// --- process one: reserve, send, and die before the answer -------
			client := seamClient(t, node, dir)
			_, err = payInvoice(t.Context(), payment{
				bolt11: bolt11, amountMsat: 50_000, maxFeeMsat: 1_000,
				paymentHash: hashHex, ref: "seam",
			}, purse, client, quietLog())
			if err == nil {
				t.Fatal("the send was supposed to die before hearing the outcome")
			}
			_ = client.Close()

			// The reservation is pending and carries its hash — which is the
			// only reason process two has anything to ask the node about.
			pending, err := db.PendingPaymentsBefore(t.Context(), laterThanNow())
			if err != nil {
				t.Fatal(err)
			}
			if len(pending) != 1 || pending[0].PaymentHash != hashHex {
				t.Fatalf("pending = %+v, want one row carrying %s", pending, hashHex)
			}
			held, err := purse.Balance(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if held != before-51_000 {
				t.Fatalf("balance = %d, want the full reservation (amount + max fee) held", held)
			}

			// --- process two: a fresh client and resolver, same database -----
			resolverClient := seamClient(t, node, dir)
			if err := resolvePendingPayments(t.Context(), db, purse, resolverClient, db,
				laterThanNow(), quietLog()); err != nil {
				t.Fatalf("the resolver could not finish the job: %v", err)
			}

			if left, err := db.PendingPaymentsBefore(t.Context(), laterThanNow()); err != nil {
				t.Fatal(err)
			} else if len(left) != 0 {
				t.Errorf("%d payments are still pending after the resolver ran: %+v", len(left), left)
			}
			after, err := purse.Balance(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if spent := before - after; spent != tc.wantSpentMsat {
				t.Errorf("the payment cost %d msat, want %d — the reserve was 1_000 and only the "+
					"route's actual fee is kept (§5)", spent, tc.wantSpentMsat)
			}
			if got := txnState(t, db, hashHex); got != tc.wantState {
				t.Errorf("txn state = %q, want %q", got, tc.wantState)
			}
		})
	}
}

// The resolver is re-runnable: running it twice must not settle anything twice.
//
// It is the first thing that runs at startup, and a crash DURING resolution
// leaves some rows closed and some not — so the next start runs it over a
// database it has already partly worked through. If a second pass moved money,
// every restart would be a fresh charge.
func TestRunningTheResolverTwiceCostsNothingExtra(t *testing.T) {
	node := lndtest.Start(t)
	db, dir := openSeamStore(t)
	purse := wallet.New(db, wallet.Options{})
	if err := purse.Allocate(t.Context(), 1_000_000, "float"); err != nil {
		t.Fatal(err)
	}
	before, err := purse.Balance(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	const bolt11 = "lnbcrt500u1ptwice"
	hashHex := hex.EncodeToString([]byte{0x01, 0x02})
	node.SetPaymentDispatchedThenLost(bolt11, hashHex, lndtest.Succeeded(200))

	client := seamClient(t, node, dir)
	_, _ = payInvoice(t.Context(), payment{
		bolt11: bolt11, amountMsat: 20_000, maxFeeMsat: 900, paymentHash: hashHex, ref: "twice",
	}, purse, client, quietLog())

	for pass := 1; pass <= 2; pass++ {
		if err := resolvePendingPayments(t.Context(), db, purse, client, db, laterThanNow(), quietLog()); err != nil {
			t.Fatalf("resolver pass %d: %v", pass, err)
		}
	}

	after, err := purse.Balance(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if spent := before - after; spent != 20_000+200 {
		t.Errorf("two resolver passes cost %d msat, want one payment's %d", spent, 20_000+200)
	}
}

// laterThanNow is "process two started after process one made its payment".
//
// A whole second, because created_at is stored as Unix seconds and the cutoff
// is strictly-before: a real restart takes far longer than that, but a test
// that reserves and resolves in the same millisecond would otherwise be asking
// for rows created strictly before the second they were created in.
func laterThanNow() time.Time { return time.Now().Add(time.Second) }

func openSeamStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, t.TempDir()
}

// seamClient is the payment path's real client: the SPEND macaroon, and no
// broker — the payment path never asks for a re-bake (§6, o34.10).
func seamClient(t *testing.T, node *lndtest.Node, credentialDir string) *lnd.Client {
	t.Helper()
	node.WriteCredentialVolume(t, credentialDir, lnd.SpendMacaroon, lndtest.Macaroon(t, "spend"))
	c := lnd.New(node.Address(), lnd.VolumeCredentials(credentialDir, lnd.SpendMacaroon),
		lnd.Options{MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// txnState reads one payment's state through RecentTxns — the store's existing
// query — rather than adding a production method for one assertion.
func txnState(t *testing.T, db *store.Store, paymentHash string) string {
	t.Helper()
	txns, err := db.RecentTxns(t.Context(), store.MaxHistoryRows)
	if err != nil {
		t.Fatalf("reading transactions: %v", err)
	}
	for _, txn := range txns {
		if txn.PaymentHash == paymentHash {
			return txn.State
		}
	}
	t.Fatalf("no transaction carries payment hash %s", paymentHash)
	return ""
}

// `v7u`, end to end on the seam: a payment the node REFUSES without initiating
// it is reversed by the next resolver pass, and sending is never held.
//
// The incident on the reference box, reproduced through everything real except
// the node: the real sqlite store, the real wallet, the real lnd client over a
// real gRPC connection. Per-package coverage cannot see this one either, and for
// a sharper reason than usual — the defect WAS the seam. internal/lnd's tests
// prove SendPayment returns the stream's error, cmd's tests prove the unknown
// arm keeps its marker, and both were right; what nobody had asserted was what
// the pair does when LND validates a request inside a stream it has already
// opened.
//
// The assertion that would have failed on main is the LAST one: the row reaches
// a terminal state. Before the fix it stayed pending and marked, which is what
// holds the ceiling and the sending freeze indefinitely.
func TestARefusedPaymentIsReversedRatherThanStrandedForEver(t *testing.T) {
	node := lndtest.Start(t)
	db, dir := openSeamStore(t)
	purse := wallet.New(db, wallet.Options{})
	if err := purse.Allocate(t.Context(), 1_000_000, "float"); err != nil {
		t.Fatal(err)
	}
	before, err := purse.Balance(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	const bolt11 = "lnbcrt310n1pselfpay"
	hashHex := hex.EncodeToString([]byte{0xa9, 0x20, 0x01, 0x4e})
	// The measured answer, from the box: LND refuses inside the handler and
	// records nothing, so TrackPaymentV2 answers NotFound for the hash.
	node.SetPaymentRefused(bolt11, "self-payments not allowed")

	if _, err := payInvoice(t.Context(), payment{
		bolt11: bolt11, amountMsat: 31_000, maxFeeMsat: 10_000,
		paymentHash: hashHex, ref: "selfpay",
	}, purse, seamClient(t, node, dir), quietLog()); err == nil {
		t.Fatal("a payment the node refused was reported as success")
	}

	// The marker is off. That is the whole fix: a marked row is one the
	// resolver's dispatched arm refuses to touch (`t4t`), for ever.
	pending, err := db.PendingPaymentsBefore(t.Context(), laterThanNow())
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %+v, want the one reservation", pending)
	}
	if pending[0].Dispatched {
		t.Fatal("the refused payment is still marked dispatched; the resolver will refuse to " +
			"touch it and the sending freeze it feeds never lifts (`v7u`)")
	}

	if err := resolvePendingPayments(t.Context(), db, purse, seamClient(t, node, dir), db,
		laterThanNow(), quietLog()); err != nil {
		t.Fatalf("the resolver could not finish the job: %v", err)
	}

	if left, err := db.PendingPaymentsBefore(t.Context(), laterThanNow()); err != nil {
		t.Fatal(err)
	} else if len(left) != 0 {
		t.Errorf("%d payments are still pending after the resolver ran: %+v — this is the "+
			"state that held sending off for 22 hours", len(left), left)
	}
	if got := txnState(t, db, hashHex); got != store.TxnFailed {
		t.Errorf("txn state = %q, want %q — nothing was paid", got, store.TxnFailed)
	}
	after, err := purse.Balance(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("the ceiling is %d msat short; a payment the node never made consumes no "+
			"budget (§5)", before-after)
	}
}

// `v7u` review: a stream that breaks mid-request, through the REAL client, keeps
// its marker — the node is not asked, and nothing is concluded.
//
// The unit test above proves the rule against a fake payer. This proves the code
// survives the wire: the fake node ends the stream with a real gRPC status, the
// real lnd client carries it through consume and observe, and payInvoice still
// sees a broken connection rather than a refusal. A layer that rewrapped the
// error as a plain one would turn it into Unknown — the refusal's code — and
// promote it; this is the test that would notice.
//
// The node has NO record here, and that is the point of the fixture: it is the
// window the review found, where LND has the request but has not yet written it.
// A check made now gets NotFound for a payment that is about to exist.
func TestAStreamThatBreaksMidRequestIsNotTakenForARefusal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		code    codes.Code
		message string
	}{
		{"the transport closed", codes.Unavailable, "error reading from server: EOF"},
		{"the stream was reset", codes.Internal,
			"stream terminated by RST_STREAM with error code: INTERNAL_ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := lndtest.Start(t)
			db, dir := openSeamStore(t)
			purse := wallet.New(db, wallet.Options{})
			if err := purse.Allocate(t.Context(), 1_000_000, "float"); err != nil {
				t.Fatal(err)
			}

			const bolt11 = "lnbcrt310n1pdropped"
			hashHex := hex.EncodeToString([]byte{0xd0, 0x0d})
			node.SetPaymentDroppedBeforeRecorded(bolt11, tc.code, tc.message)

			_, err := payInvoice(t.Context(), payment{
				bolt11: bolt11, amountMsat: 31_000, maxFeeMsat: 10_000,
				paymentHash: hashHex, ref: "dropped",
			}, purse, seamClient(t, node, dir), quietLog())
			if err == nil {
				t.Fatal("a payment whose stream broke was reported as success")
			}
			if errors.Is(err, lnd.ErrNotSent) {
				t.Errorf("err carries lnd.ErrNotSent: %v — the payer is told the payment did "+
					"not happen and the budget comes back, for one LND may be paying now", err)
			}
			if asked := node.TrackedHashes(); len(asked) != 0 {
				t.Errorf("the node was asked about %v after the stream broke; its NotFound here "+
					"is a race with its own write, not a proof", asked)
			}

			pending, err := db.PendingPaymentsBefore(t.Context(), laterThanNow())
			if err != nil {
				t.Fatal(err)
			}
			if len(pending) != 1 || !pending[0].Dispatched {
				t.Errorf("pending = %+v, want the one reservation, still marked dispatched — "+
					"its fate is unknown and §6 forbids concluding anything", pending)
			}
		})
	}
}
