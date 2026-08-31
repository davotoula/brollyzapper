package lnd_test

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/store"
)

// testOptions keep the retry loop instant and silent.
func testOptions(broker lnd.CredentialBroker) lnd.Options {
	return lnd.Options{
		Broker:     broker,
		MinBackoff: time.Millisecond,
		MaxBackoff: time.Millisecond,
	}
}

func TestClientVerifiesTLSAndSendsTheMacaroonAsHex(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	macaroon := []byte{0x02, 0x01, 0x03, 0xff}
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, macaroon)

	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), testOptions(&lndtest.Broker{}))
	defer client.Close()

	info, err := client.GetInfo(t.Context())
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info.Alias != "fake-node" {
		t.Errorf("Alias = %q, want fake-node", info.Alias)
	}
	seen := node.SeenMacaroons()
	if len(seen) == 0 {
		t.Fatal("the node saw no macaroon metadata")
	}
	if want := hex.EncodeToString(macaroon); seen[0] != want {
		t.Errorf("macaroon metadata = %q, want the hex encoding %q", seen[0], want)
	}
	if got := client.State(); got != lnd.StateReady {
		t.Errorf("State = %q after a successful call, want %q", got, lnd.StateReady)
	}
}

// Spec §6: the server must tolerate the credential volume being empty — the
// guard starts first via depends_on, but ordering is not a guarantee.
func TestMissingCredentialsAreANotLinkedStateNotACrash(t *testing.T) {
	node := lndtest.Start(t)
	empty := t.TempDir()

	client := lnd.New(node.Address(), lnd.VolumeCredentials(empty, lnd.ReceiveMacaroon), testOptions(&lndtest.Broker{}))
	defer client.Close()

	if got := client.State(); got != lnd.StateNotLinked {
		t.Errorf("State = %q with an empty credential dir, want %q", got, lnd.StateNotLinked)
	}
	_, err := client.GetInfo(t.Context())
	if !errors.Is(err, lnd.ErrNotLinked) {
		t.Errorf("GetInfo with no credentials = %v, want ErrNotLinked", err)
	}
	// ...and it recovers the moment the guard writes them, with no restart.
	node.WriteCredentialVolume(t, empty, lnd.ReceiveMacaroon, []byte{0x09})
	if _, err := client.GetInfo(t.Context()); err != nil {
		t.Errorf("GetInfo after the guard wrote credentials: %v", err)
	}
}

// Spec §6: the server mounts the credential volume read-only and reloads on
// change — a re-bake must not need a restart.
func TestCredentialsReloadWithoutARestart(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})

	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), testOptions(&lndtest.Broker{}))
	defer client.Close()

	if _, err := client.GetInfo(t.Context()); err != nil {
		t.Fatalf("first GetInfo: %v", err)
	}
	lndtest.WriteFile(t, filepath.Join(dir, lnd.ReceiveMacaroon), []byte{0x02, 0x02})
	if _, err := client.GetInfo(t.Context()); err != nil {
		t.Fatalf("second GetInfo: %v", err)
	}

	seen := node.SeenMacaroons()
	if len(seen) < 2 {
		t.Fatalf("the node saw %d macaroons, want 2", len(seen))
	}
	if seen[len(seen)-1] != hex.EncodeToString([]byte{0x02, 0x02}) {
		t.Errorf("last macaroon = %q, want the re-baked one — the client did not reload", seen[len(seen)-1])
	}
}

// The bead's sharpest test. LND's settle_index is documented as "strictly
// greater than this value", so resuming at last+1 silently skips exactly one
// settlement per reconnect — invoices that settle on the node and never credit.
func TestInvoiceStreamResumesWithoutSkippingOrReplaying(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
	node.SetLedger(
		lndtest.SettledInvoice("hash-1", 1, 1_000),
		lndtest.SettledInvoice("hash-2", 2, 2_000),
		lndtest.SettledInvoice("hash-3", 3, 3_000),
	)
	node.SetBreakAfter(2) // the stream dies after two invoices

	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), testOptions(&lndtest.Broker{}))
	defer client.Close()
	resume := &memoryResume{}

	handled := make(chan uint64, 8)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.RunInvoiceStream(ctx, resume, func(_ context.Context, inv *lnrpc.Invoice) error {
			handled <- inv.SettleIndex
			return nil
		})
	}()

	var got []uint64
	for range 3 {
		select {
		case index := <-handled:
			got = append(got, index)
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out after handling %v", got)
		}
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("RunInvoiceStream = %v, want nil or context.Canceled", err)
	}

	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Errorf("handled settle indexes %v, want [1 2 3] exactly once each", got)
	}
	points := node.ResumePoints()
	if len(points) < 2 {
		t.Fatalf("the client opened %d subscriptions, want at least 2", len(points))
	}
	if points[0] != 0 {
		t.Errorf("first subscription resumed at %d, want 0", points[0])
	}
	if points[1] != 2 {
		t.Errorf("second subscription resumed at %d, want 2 — the last index handled, "+
			"not last+1 (LND sends settle_index strictly greater than the value given)", points[1])
	}
	if resume.index != 3 {
		t.Errorf("persisted settle index = %d, want 3", resume.index)
	}
}

// Spec §6: subscribe ONCE for the process lifetime.
func TestOnlyOneInvoiceStreamMayRun(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})

	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), testOptions(&lndtest.Broker{}))
	defer client.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	running := make(chan struct{})
	go func() {
		close(running)
		_ = client.RunInvoiceStream(ctx, &memoryResume{}, func(context.Context, *lnrpc.Invoice) error { return nil })
	}()
	<-running

	// Give the first stream a moment to claim the slot, then try to open a second.
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := client.RunInvoiceStream(ctx, &memoryResume{}, func(context.Context, *lnrpc.Invoice) error { return nil })
		if errors.Is(err, lnd.ErrStreamAlreadyRunning) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("a second RunInvoiceStream returned %v, want ErrStreamAlreadyRunning", err)
		}
	}
}

// Spec §6: on auth failure the server shows a re-link state and re-requests a
// bake through the guard. It never exits.
func TestAuthFailureAsksTheGuardToReBakeAndKeepsRunning(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
	node.SetLedger(lndtest.SettledInvoice("hash-1", 1, 1_000))
	node.SetReject(true)

	broker := &lndtest.Broker{}
	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), testOptions(broker))
	defer client.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	handled := make(chan uint64, 4)
	done := make(chan error, 1)
	go func() {
		done <- client.RunInvoiceStream(ctx, &memoryResume{}, func(_ context.Context, inv *lnrpc.Invoice) error {
			handled <- inv.SettleIndex
			return nil
		})
	}()

	// The rejection must produce a re-link state and a bake request, not an exit.
	lndtest.WaitFor(t, "re-link state", func() bool { return client.State() == lnd.StateRelink })
	lndtest.WaitFor(t, "a bake request", func() bool { return broker.Bakes() > 0 })

	// Once the guard has re-baked, the same process recovers on its own.
	node.SetReject(false)
	select {
	case index := <-handled:
		if index != 1 {
			t.Errorf("handled settle index %d, want 1", index)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the stream never recovered after the macaroon was accepted again")
	}
	lndtest.WaitFor(t, "ready state", func() bool { return client.State() == lnd.StateReady })

	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("RunInvoiceStream = %v, want nil or context.Canceled", err)
	}
}

// Spec §6: handling is idempotent — a replayed settlement is a no-op, enforced
// by UNIQUE(payment_hash) inside the posting transaction.
func TestReplayedSettlementFromTheStreamDoesNotCreditTwice(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
	// The same payment hash arriving twice under two settle indexes is what a
	// re-delivery after a reconnect looks like.
	node.SetLedger(
		lndtest.SettledInvoice("hash-dup", 1, 21_000),
		lndtest.SettledInvoice("hash-dup", 2, 21_000),
	)

	db, err := store.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()
	now := time.Unix(1_700_000_000, 0).UTC()
	if err := db.CreateInvoice(t.Context(), store.Invoice{
		PaymentHash: "hash-dup", AmountMsat: 21_000, DescriptionHash: "dh", Bolt11: "lnbcrt1",
		State: store.InvoiceOpen, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}

	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), testOptions(&lndtest.Broker{}))
	defer client.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	credits := make(chan bool, 4)
	go func() {
		_ = client.RunInvoiceStream(ctx, &memoryResume{}, func(ctx context.Context, inv *lnrpc.Invoice) error {
			credited, err := db.CreditSettledInvoice(ctx, string(inv.RHash), hex.EncodeToString(inv.RPreimage), inv.AmtPaidMsat, now, true)
			if err != nil {
				return err
			}
			credits <- credited
			return nil
		})
	}()

	var results []bool
	for range 2 {
		select {
		case credited := <-credits:
			results = append(results, credited)
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out after %d settlements", len(results))
		}
	}
	cancel()

	if len(results) != 2 || !results[0] || results[1] {
		t.Errorf("credited = %v, want [true false] — the replay must be a no-op", results)
	}
	balance, err := db.BalanceMsat(t.Context())
	if err != nil {
		t.Fatalf("BalanceMsat: %v", err)
	}
	if balance != 21_000 {
		t.Errorf("balance = %d, want 21000 — the wallet was credited twice", balance)
	}
}

// memoryResume is the resume point without a database, for the tests that do
// not need one.
type memoryResume struct{ index uint64 }

func (m *memoryResume) LastSettleIndex(context.Context) (uint64, error) { return m.index, nil }

func (m *memoryResume) SetLastSettleIndex(_ context.Context, index uint64) error {
	m.index = index
	return nil
}

// d46.20, and the reason it was invisible until the box. A corrupted
// recv.macaroon made LND answer:
//
//	code = Unknown  desc = cannot determine data format of binary-encoded macaroon
//
// That is the node's macaroon PARSER refusing the bytes — it never got as far
// as verifying anything, so there is no Unauthenticated. IsAuthFailure said no,
// the stream reconnected with capped backoff forever, and the credential stayed
// bad until an operator clicked Re-link 45 seconds later.
//
// TestAuthFailureAsksTheGuardToReBakeAndKeepsRunning passed throughout, because
// the fake node rejects with Unauthenticated: the spec's scenario, not the
// field's. This drives the field's, verbatim.
func TestACredentialTheNodeCannotParseAsksTheGuardToReBake(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
	node.SetLedger(lndtest.SettledInvoice("hash-1", 1, 1_000))
	node.SetRejectWith(status.Error(codes.Unknown,
		"cannot determine data format of binary-encoded macaroon"))

	broker := &lndtest.Broker{}
	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), testOptions(broker))
	defer client.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.RunInvoiceStream(ctx, &memoryResume{}, func(context.Context, *lnrpc.Invoice) error {
			return nil
		})
	}()

	lndtest.WaitFor(t, "a bake request for a credential the node cannot parse",
		func() bool { return broker.Bakes() > 0 })

	// But NOT the re-link state. "Re-link needed" is an operator-facing claim
	// that the node verified our macaroon and refused it, and LND answers
	// codes.Unknown while it is merely restarting. The reaction is broad; the
	// sentence on the page is narrow.
	if got := client.State(); got == lnd.StateRelink {
		t.Errorf("State = %q for a credential the node could not parse; that sentence "+
			"belongs to a macaroon the node verified and refused", got)
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("RunInvoiceStream = %v, want nil or context.Canceled", err)
	}
}

// The re-bake is bounded, because the rate is otherwise set by whatever is
// failing. The recon path has no backoff of its own — one ceiling change is one
// demand is one check is one rejected call — and every successful bake writes a
// macaroon.bake row, so an unbounded loop trims §12's trail down to nothing but
// itself.
func TestReBakeRequestsAreRateLimited(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
	node.SetRejectWith(status.Error(codes.Unknown, "cannot determine data format"))

	broker := &lndtest.Broker{}
	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon),
		testOptions(broker))
	defer client.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.RunInvoiceStream(ctx, &memoryResume{}, func(context.Context, *lnrpc.Invoice) error {
			return nil
		})
	}()

	// The stream reconnects at ~1ms, so this is hundreds of rejections.
	lndtest.WaitFor(t, "the first bake request", func() bool { return broker.Bakes() > 0 })
	lndtest.WaitFor(t, "many refused attempts", func() bool { return len(node.SeenMacaroons()) > 50 })
	if got := broker.Bakes(); got != 1 {
		t.Errorf("%d refused stream attempts asked the guard to bake %d times, want 1 — "+
			"the guard is asked at most once per %v", len(node.SeenMacaroons()), got,
			lnd.ReBakeInterval)
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("RunInvoiceStream = %v, want nil or context.Canceled", err)
	}
}

// d46.20 criterion 3. Re-baking against a node that is not answering is noise:
// the credential is fine, the network is not, and the existing backoff is the
// right response. The classification must separate "the node would not accept
// what we sent" from "the node did not answer".
func TestConnectivityFailuresDoNotAskForAReBake(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
	node.SetRejectWith(status.Error(codes.Unavailable, "connection refused"))

	broker := &lndtest.Broker{}
	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon),
		testOptions(broker))
	defer client.Close()

	for range 5 {
		if _, err := client.GetInfo(t.Context()); err == nil {
			t.Fatal("the node accepted a call it was told to refuse")
		}
	}
	if got := broker.Bakes(); got != 0 {
		t.Errorf("%d bake requests for an unanswering node; that is not a credential problem", got)
	}
	if got := client.State(); got == lnd.StateRelink {
		t.Errorf("State = %q for an unanswering node, want anything but re-link", got)
	}
}

// d46.20 criterion 4. §6's capped backoff is right for a node that is not
// answering and wrong for a credential that has just been replaced: on the box
// the UI sat at "connecting" for minutes after Re-link had already fixed the
// macaroon, which reads as a failed repair.
func TestRelinkInterruptsAnInFlightBackoff(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
	// A settlement waiting on the node, so recovery is observable: the stream
	// reports ready when it receives, not when it subscribes.
	node.SetLedger(lndtest.SettledInvoice("hash-1", 1, 1_000))
	node.SetReject(true)

	// A backoff far longer than this test is willing to wait, so an attempt
	// arriving promptly can only be RetryNow's doing.
	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon),
		lnd.Options{Broker: &lndtest.Broker{}, MinBackoff: time.Minute, MaxBackoff: time.Minute})
	defer client.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.RunInvoiceStream(ctx, &memoryResume{}, func(context.Context, *lnrpc.Invoice) error {
			return nil
		})
	}()

	lndtest.WaitFor(t, "the first attempt to be refused", func() bool {
		return len(node.SeenMacaroons()) >= 1
	})
	settled := len(node.SeenMacaroons())

	// The operator fixes the credential and clicks Re-link.
	node.SetReject(false)
	client.RetryNow()

	lndtest.WaitFor(t, "a retry without waiting out the minute", func() bool {
		return len(node.SeenMacaroons()) > settled
	})
	lndtest.WaitFor(t, "ready state", func() bool { return client.State() == lnd.StateReady })

	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("RunInvoiceStream = %v, want nil or context.Canceled", err)
	}
}

// The two classifications are deliberately different — the server re-bakes on
// the broad question, the guard exits on the narrow one — so the IMPLICATION
// between them is asserted rather than left to drift. Anything the guard treats
// as rotation, the server must also treat as a rejected credential.
//
// Every code, not the two IsAuthFailure happens to name today: a version that
// listed those two would still pass if IsAuthFailure were widened to include
// Unavailable, which is exactly the drift — the guard exiting on connectivity —
// that the asymmetry exists to prevent.
func TestEveryAuthFailureIsAlsoACredentialRejection(t *testing.T) {
	var narrow int
	for code := codes.OK; code <= codes.Unauthenticated; code++ {
		err := status.Error(code, "refused")
		if !lnd.IsAuthFailure(err) {
			continue
		}
		narrow++
		if !lnd.IsCredentialRejected(err) {
			t.Errorf("IsAuthFailure(%s) is true but IsCredentialRejected(%s) is false; the "+
				"guard would exit over something the server ignores", code, code)
		}
	}
	if narrow == 0 {
		t.Fatal("no code satisfied IsAuthFailure; the implication was asserted over nothing")
	}
}

// The classification is a whitelist of benign codes, so this pins which side of
// the line each answer falls on — and in particular that a code nobody
// anticipated lands on the re-bake side rather than the ignore side.
func TestCredentialRejectionClassifiesByWhatTheNodeAnswered(t *testing.T) {
	rejected := []codes.Code{
		codes.Unauthenticated, codes.PermissionDenied,
		codes.Unknown,  // the box: LND's macaroon parser refusing the bytes
		codes.Internal, // unanticipated: fail toward re-baking, not toward silence
	}
	benign := []codes.Code{
		codes.Canceled, codes.DeadlineExceeded, codes.Unavailable,
		codes.NotFound, codes.AlreadyExists, codes.InvalidArgument,
		codes.FailedPrecondition, codes.OutOfRange, codes.ResourceExhausted,
		codes.Unimplemented,
	}
	for _, code := range rejected {
		if !lnd.IsCredentialRejected(status.Error(code, "x")) {
			t.Errorf("IsCredentialRejected(%s) = false, want true", code)
		}
	}
	for _, code := range benign {
		if lnd.IsCredentialRejected(status.Error(code, "x")) {
			t.Errorf("IsCredentialRejected(%s) = true; that answer is about the request or "+
				"the network, not the credential", code)
		}
	}
	if lnd.IsCredentialRejected(nil) {
		t.Error("IsCredentialRejected(nil) = true")
	}
	if lnd.IsCredentialRejected(errors.New("loading tls.cert: no such file")) {
		t.Error("a local error that never reached the node was classified as a rejection; " +
			"re-baking cannot fix an unreadable certificate")
	}
}

// A reconnect delay that only ever grows is the same symptom d46.20 was raised
// for, reached by a different route: after a handful of drops in the process's
// whole life the delay pins at the ceiling, and a one-second blip weeks later
// costs a full minute of not receiving. RetryNow fixes only the half an
// operator is watching.
func TestABackoffResetsAfterAStreamThatWorked(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
	node.SetLedger(
		lndtest.SettledInvoice("hash-1", 1, 1_000),
		lndtest.SettledInvoice("hash-2", 2, 1_000),
	)
	// Deliver one, then drop — so every reconnect follows a stream that
	// genuinely worked. The resume point is pinned at zero so the node replays
	// from the start each time and the cycle repeats.
	node.SetBreakAfter(1)

	// A backoff with room to GROW, or this test cannot tell a reset from a
	// ceiling it never reached: doubling from 1ms towards 1s, twenty
	// reconnects cost about ten seconds unreset and about twenty milliseconds
	// reset.
	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon),
		lnd.Options{Broker: &lndtest.Broker{}, MinBackoff: time.Millisecond, MaxBackoff: time.Second})
	defer client.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	handled := make(chan uint64, 64)
	done := make(chan error, 1)
	go func() {
		done <- client.RunInvoiceStream(ctx, pinnedResume{}, func(_ context.Context, inv *lnrpc.Invoice) error {
			handled <- inv.SettleIndex
			return nil
		})
	}()

	// Twenty reconnects, each after a working stream, inside a window far
	// shorter than an unreset backoff would need.
	deadline := time.After(4 * time.Second)
	for i := range 20 {
		select {
		case <-handled:
		case <-deadline:
			t.Fatalf("only %d reconnects completed; the backoff is not resetting after a "+
				"stream that worked", i)
		}
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("RunInvoiceStream = %v, want nil or context.Canceled", err)
	}
}

// pinnedResume never advances, so the node replays its ledger on every
// subscription. Real resumption is asserted by
// TestInvoiceStreamResumesWithoutSkippingOrReplaying; this one needs a stream
// that can keep failing after having worked.
type pinnedResume struct{}

func (pinnedResume) LastSettleIndex(context.Context) (uint64, error)  { return 0, nil }
func (pinnedResume) SetLastSettleIndex(context.Context, uint64) error { return nil }

// o34.10. AddInvoice is about to sit behind the PUBLIC LNURL callback, and LND
// reports most handler errors as codes.Unknown — a bad amount, a duplicate
// hash, an expiry out of range. Under d46.20's classification every one of
// those becomes a guard BakeMacaroon RPC and a macaroon.bake row, so an
// unauthenticated caller could drive the credential broker and trim the
// 10,000-row audit trail down to nothing but itself.
//
// A per-request call answers about the REQUEST. Only the invoice stream may
// conclude anything about the credential.
func TestAPerRequestFailureNeverAsksTheGuardToReBake(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*lnd.Client) error
	}{
		{"AddInvoice", func(c *lnd.Client) error {
			_, err := c.AddInvoice(context.Background(), &lnrpc.Invoice{ValueMsat: 1})
			return err
		}},
		{"LookupInvoice", func(c *lnd.Client) error {
			_, err := c.LookupInvoice(context.Background(), []byte{0x01})
			return err
		}},
		{"ChannelBalance", func(c *lnd.Client) error {
			_, err := c.ChannelBalance(context.Background())
			return err
		}},
		{"GetInfo", func(c *lnd.Client) error {
			_, err := c.GetInfo(context.Background())
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := lndtest.Start(t)
			dir := t.TempDir()
			node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})
			// Exactly what the box measured, and what LND returns for most
			// handler errors.
			node.SetRejectWith(status.Error(codes.Unknown,
				"cannot determine data format of binary-encoded macaroon"))

			broker := &lndtest.Broker{}
			client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon),
				testOptions(broker))
			defer client.Close()

			if err := tc.call(client); err == nil {
				t.Fatal("the node accepted a call it was told to refuse")
			}
			if got := broker.Bakes(); got != 0 {
				t.Errorf("a failed %s asked the guard to bake %d times; a per-request call "+
					"answers about the request, and this one is reachable from the public "+
					"LNURL callback", tc.name, got)
			}
		})
	}
}
