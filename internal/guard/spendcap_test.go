package guard_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc/routerrpc"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// tna.1 criterion 1: a payment over the rolling cap is rejected BY THE GUARD,
// with the server's own check nowhere in the picture.
//
// The stub is the point, and here it is total: there is no server in this test
// at all. §5's working ceiling is checked by the server before it calls
// SendPaymentV2, and a compromised server simply does not run that check — it
// holds the spend macaroon and can call the RPC directly. What stops it is this
// path: LND forwards the request to the guard because the macaroon carries the
// guard's custom caveat, and will not perform the RPC until the guard answers.
func TestAPaymentOverTheWindowIsRefusedInsideLNDsRequestPath(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 10_000, payment: 10_000})
	serveMiddleware(t, node, g)

	// Two payments of 6 000 msat against a 10 000 msat window.
	first := attempt(t, node, 1, invoiceFor(t, node, "first", 6_000))
	if first.GetError() != "" {
		t.Fatalf("the first payment was refused under the cap: %q", first.GetError())
	}
	second := attempt(t, node, 2, invoiceFor(t, node, "second", 6_000))

	if second.GetError() == "" {
		t.Fatal("a payment taking the window to 12 000 msat over a 10 000 msat limit was " +
			"allowed; the hard cap is what bounds a compromised server to one window's spend")
	}
	if !strings.Contains(second.GetError(), "10000") {
		t.Errorf("the refusal %q does not name the limit it hit; the person who asked for the "+
			"payment reads this text", second.GetError())
	}
}

// Criterion 2: killing the guard makes LND reject the spend macaroon outright.
//
// THE REJECTION, not the absence of the middleware. §14's fail-closed property
// is the reason P4 is safe to ship — a custom caveat with no middleware
// registered for it is refused by LND, so a guard that dies takes sending with
// it rather than leaving it unrestricted — and only the node can demonstrate it.
// This dials the node with the credential the guard actually baked.
func TestKillingTheGuardMakesTheNodeRejectTheSpendMacaroon(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 1_000_000, payment: 1_000_000})
	if err := g.CopyCertificate(); err != nil {
		t.Fatal(err)
	}
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	stop := serveMiddleware(t, node, g)

	spender := lnd.New(node.Address(), lnd.FileCredentials(
		filepath.Join(d.credentials, lnd.CertFile),
		filepath.Join(d.credentials, lnd.SpendMacaroon)), lnd.Options{Log: quietLog(t)})
	t.Cleanup(func() { _ = spender.Close() })

	// While the guard is up the credential works.
	if _, err := spender.Decode(t.Context(), invoiceFor(t, node, "alive", 1_000)); err != nil {
		t.Fatalf("the spend macaroon was rejected while the guard was registered: %v", err)
	}

	stop()
	lndtest.WaitFor(t, "the middleware stream to end", func() bool { return !node.MiddlewareIsLive() })

	_, err := spender.Decode(t.Context(), invoiceFor(t, node, "dead", 1_000))
	if err == nil {
		t.Fatal("the node still honoured the spend macaroon with no middleware registered; the " +
			"custom caveat has to FAIL CLOSED, or a guard that dies leaves sending unrestricted")
	}
	if !strings.Contains(err.Error(), lnd.GuardCaveatName) {
		t.Errorf("the node's rejection %q does not name the caveat it could not honour", err)
	}
}

// Criterion 3: the counter increments on the ATTEMPT, not on settlement.
//
// A payment whose outcome the guard never observes still counts against the
// window (§14). Nothing here ever sends a response: the guard is left in exactly
// the position it is in when LND restarts, when the stream drops, or when the
// guard itself is stopped mid-payment — and the money may still have moved.
func TestAnAttemptCountsEvenWhenItsOutcomeIsNeverSeen(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 100_000})
	serveMiddleware(t, node, g)

	if feedback := attempt(t, node, 7, invoiceFor(t, node, "unseen", 4_000)); feedback.GetError() != "" {
		t.Fatalf("the attempt was refused: %q", feedback.GetError())
	}

	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.SpendUsedMsat < 4_000 {
		t.Errorf("the window holds %d msat after an attempt of 4 000; counting on settlement "+
			"means a payment the guard stops watching costs the operator nothing against the "+
			"limit, which is the whole hole attempt-based counting closes", status.SpendUsedMsat)
	}
}

// Criterion 4, first half: the PER-PAYMENT cap. Two caps, two assertions.
func TestASinglePaymentOverThePerPaymentCapIsRefused(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	// A window far above the payment, so only the per-payment cap can refuse.
	g := openGuardWithCaps(t, node, d, caps{window: 100_000_000, payment: 5_000})
	serveMiddleware(t, node, g)

	feedback := attempt(t, node, 1, invoiceFor(t, node, "big", 9_000))

	if feedback.GetError() == "" {
		t.Fatal("a 9 000 msat payment was allowed under a 5 000 msat per-payment cap")
	}
	if !strings.Contains(feedback.GetError(), "per-payment") {
		t.Errorf("the refusal %q does not say which of the two limits it hit; they have "+
			"different remedies", feedback.GetError())
	}
	// And the window was not charged for a payment that never happened.
	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.SpendUsedMsat != 0 {
		t.Errorf("the window holds %d msat after a REFUSED payment; a refusal is not a spend",
			status.SpendUsedMsat)
	}
}

// Past the audit bound, a refused payment must cost no disk write at all.
//
// A refusal writes at most once, and deliberately: the guard.reject row is
// durable and must be. But that row is bounded per hour (auditRejectBound)
// precisely because refusals are what a compromised server can drive as fast as
// the socket allows — and stateStore.updateIf exists so that once the bound is
// spent, the flood costs nothing. For a while nothing called it:
// InterceptRequest used update, which always saves, so every refusal past the
// bound still paid an fsync and a rename. The bound made the trail cheap and
// the layer below made it expensive again.
//
// Asserted on the file's mtime AND its bytes, because a refusal rewrites the
// same content it read: a save that changed nothing is still a save, and
// comparing content alone could not see it.
func TestPastTheAuditBoundARefusedPaymentDoesNotWriteState(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	// A window far above the payment, so only the per-payment cap can refuse.
	g := openGuardWithCaps(t, node, d, caps{window: 100_000_000, payment: 5_000})
	serveMiddleware(t, node, g)

	// Spend the audit bound, generously — as rejectbound_test.go does, rather
	// than reaching for the unexported constant, so a bound that grows makes
	// this test slower rather than wrong. Each of these refusals legitimately
	// writes its guard.reject row; the one after them is the one that must not.
	over := invoiceFor(t, node, "big", 9_000)
	for i := range uint64(20) {
		if f := attempt(t, node, i+1, over); f.GetError() == "" {
			t.Fatalf("refusal %d: a 9 000 msat payment was allowed under a 5 000 msat cap", i+1)
		}
	}

	path := filepath.Join(d.data, "guard-state.json")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Coarse filesystem timestamps would make an immediate second write look
	// like no write at all.
	time.Sleep(10 * time.Millisecond)

	if f := attempt(t, node, 100, over); f.GetError() == "" {
		t.Fatal("the payment over the per-payment cap was allowed")
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	afterBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("a refusal past the audit bound rewrote the state file (mtime %s -> %s); "+
			"it records nothing that must survive a restart, and saveLocked is an fsync and "+
			"a rename on a path a flood can drive", before.ModTime(), after.ModTime())
	}
	if !bytes.Equal(beforeBytes, afterBytes) {
		t.Error("a refusal past the audit bound changed the stored state")
	}
}

// Criterion 4, second half: refused BEFORE LND performs the RPC.
//
// The assertion is about the feedback carrying an error, which is what makes LND
// abort the call — §14's "an attempt that would exceed the window or the
// per-payment cap is rejected before LND sees it". A guard that allowed the
// request and compensated afterwards would pass a test that only checked the
// counter.
func TestARefusedAttemptAbortsTheCallRatherThanBeingCompensated(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 1_000, payment: 1_000})
	serveMiddleware(t, node, g)

	feedback := attempt(t, node, 1, invoiceFor(t, node, "over", 5_000))

	if feedback.GetError() == "" {
		t.Fatal("the guard allowed the request and would have had to undo the payment afterwards")
	}
	if feedback.GetReplaceResponse() {
		t.Error("the guard tried to REPLACE the message rather than refuse it; LND forbids a " +
			"middleware altering responses to unencumbered macaroons and this app alters none")
	}
	if got := len(node.SendPaymentRequests()); got != 0 {
		t.Errorf("the node saw %d payment requests for a refused attempt", got)
	}
}

// Criterion 5: a terminal FAILED decrements; anything less does NOT.
//
// THE NEGATIVE ARM IS THE ONE THAT MATTERS (Ruling 2). The distinction is not
// failure-versus-success, it is OBSERVED versus UNOBSERVED: a stream that closes
// or errors is a payment nobody is watching any more, and it may well settle.
// Refunding there hands the window back for money that moved.
func TestOnlyAnObservedTerminalFailureReturnsTheWindow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outcome *lnrpc.Payment
		refund  bool
	}{
		{"terminal failure", &lnrpc.Payment{Status: lnrpc.Payment_FAILED,
			FailureReason: lnrpc.PaymentFailureReason_FAILURE_REASON_NO_ROUTE}, true},
		{"still in flight", &lnrpc.Payment{Status: lnrpc.Payment_IN_FLIGHT}, false},
		{"succeeded", &lnrpc.Payment{Status: lnrpc.Payment_SUCCEEDED}, false},
		{"initiated", &lnrpc.Payment{Status: lnrpc.Payment_INITIATED}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := lndtest.Start(t)
			d := guardDirs(t, node)
			g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 100_000})
			serveMiddleware(t, node, g)

			if f := attempt(t, node, 3, invoiceFor(t, node, tc.name, 4_000)); f.GetError() != "" {
				t.Fatalf("the attempt was refused: %q", f.GetError())
			}
			node.Intercept(t, lndtest.PaymentIntercept(t, 3, tc.outcome))

			used := spendUsed(t, g)
			if tc.refund && used != 0 {
				t.Errorf("the window still holds %d msat after an observed terminal failure; a "+
					"node with routing failures would burn its whole daily cap on payments that "+
					"never moved money", used)
			}
			if !tc.refund && used == 0 {
				t.Errorf("the window was returned on %q; that is not an observed failure, and "+
					"a payment that settles after it would be spend the cap never saw", tc.name)
			}
		})
	}
}

// And the shapes that are NOT a status at all leave the window alone.
//
// An error message on the response stream carries a string, not a Payment: LND
// reports transport failures this way, and a transport failure says nothing
// about whether the payment was made. The same goes for a stream that simply
// stops — there is no message for that at all, which is why "spent" has to be
// the default rather than something the guard remembers to do.
func TestAnErroredOrAbandonedStreamDoesNotReturnTheWindow(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 100_000})
	serveMiddleware(t, node, g)

	if f := attempt(t, node, 11, invoiceFor(t, node, "errored", 4_000)); f.GetError() != "" {
		t.Fatalf("the attempt was refused: %q", f.GetError())
	}
	// THE FLAG DECIDES, NOT THE BYTES. The payload here would decode to a FAILED
	// payment if anything tried, which is the whole point: LND has said this is
	// an error string, and a guard that parsed it anyway would be reading a
	// message type that is not there. A plain "rpc error: …" string does not
	// prove that — it fails to parse, so removing the IsError check changes
	// nothing and the test passes over the bug.
	node.Intercept(t, &lnrpc.RPCMiddlewareRequest{
		RequestId: 11,
		InterceptType: &lnrpc.RPCMiddlewareRequest_Response{Response: &lnrpc.RPCMessage{
			MethodFullUri: lndtest.SendPaymentMethod,
			StreamRpc:     true,
			TypeName:      "error",
			IsError:       true,
			Serialized:    marshal(t, &lnrpc.Payment{Status: lnrpc.Payment_FAILED}),
		}},
	})

	if used := spendUsed(t, g); used == 0 {
		t.Error("an ERROR on the response stream returned the window; LND reports transport " +
			"failures this way and the payment may still be in flight at the node")
	}
}

// Criterion 6: at the record bound the guard REJECTS rather than evicts.
//
// Ruling 3, and the reason is arithmetic rather than tidiness: an evicted record
// leaves its amount out of the sum, so the window under-counts and the cap
// silently rises. Every other ring in this codebase drops its oldest entry; this
// one must not, and the difference is worth a test that fills the bound.
func TestAtTheRecordBoundTheGuardRefusesRatherThanForgetting(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	// Amount limits far above what the fillers spend, so ONLY the record bound
	// can refuse — and a bound of three, because the behaviour at the bound is
	// the same whatever it is and filling five thousand records means rewriting
	// a growing file five thousand times.
	g := openGuardFull(t, node, d, guard.Options{MaxWindowAttempts: 3},
		netip.MustParseAddr("10.21.0.17"), true, caps{window: 1_000_000, payment: 1_000_000})
	serveMiddleware(t, node, g)

	for i := range 3 {
		bolt11 := invoiceFor(t, node, "filler"+strconv.Itoa(i), 1_000)
		if f := attempt(t, node, uint64(i+1), bolt11); f.GetError() != "" {
			t.Fatalf("filling attempt %d was refused: %q", i, f.GetError())
		}
	}
	before := spendUsed(t, g)

	feedback := attempt(t, node, 99, invoiceFor(t, node, "over the bound", 1_000))

	if feedback.GetError() == "" {
		t.Fatal("the guard accepted an attempt at its record bound; if it evicted one to make " +
			"room, that record's amount left the window and the cap rose by it")
	}
	if !strings.Contains(feedback.GetError(), "will not lose one") {
		t.Errorf("the refusal %q does not say the guard refused rather than forgot", feedback.GetError())
	}
	if used := spendUsed(t, g); used != before {
		t.Errorf("the window holds %d msat, want the %d it held before the refusal; the bound "+
			"must not cost the window a record", used, before)
	}
	if got := len(readGuardState(t, d.data).SpendAttempts); got != 3 {
		t.Errorf("%d records survive, want 3 — nothing may be evicted to make room", got)
	}
}

// Criterion 7, first arm: an upgraded install whose gate permits sending has its
// pre-P4 spend macaroon RE-BAKED, with the caveat.
//
// Ruling 1. Without this, a spend macaroon baked before P4 carries no custom
// caveat, LND honours it without consulting anyone, and the hard cap applies to
// nothing — on precisely the installs that were already sending.
func TestAnUpgradedInstallRebakesASpendMacaroonWithNoGuardCaveat(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 100_000})
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	stripGuardCaveat(t, node, d)

	if err := g.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureSpendMacaroon: %v", err)
	}

	raw := readCredential(t, d.credentials, lnd.SpendMacaroon)
	if !lnd.HasGuardCaveat(raw) {
		caveats, _ := lnd.Caveats(raw)
		t.Errorf("the spend macaroon still carries no %s caveat (%v); LND would perform "+
			"payments with it without ever asking the guard", lnd.GuardCaveatName, caveats)
	}
	if _, err := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Errorf("the credential is gone on an install that PERMITS sending: %v", err)
	}
}

// Criterion 7, second arm, and the one that is new since Wave 30: with the gate
// off it is REVOKED, because it cannot be re-baked.
//
// tna.4's Ruling A.4 says do not auto-revoke on finding the gate off, and this
// does not contradict it. A.4 refused to destroy on an AMBIGUOUS signal — an
// Umbrel update restarts containers, so "started with the gate off" is not
// evidence of intent. This signal is a FACT ABOUT THE CREDENTIAL: it is missing
// a caveat this version requires. Destroy on facts, never on guesses about what
// a restart meant.
func TestAnUncappableSpendMacaroonIsRevokedWhenItCannotBeRebaked(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	permitted := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 100_000})
	if err := permitted.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	rootKey := currentSpendRootKey(t, d)
	stripGuardCaveat(t, node, d)

	// The DEPLOYMENT does not permit sending, so a re-bake is not available. The
	// ceiling rather than the latch because this arm is about a restart finding
	// the gate shut (`06v`): the latch is stored state and a restart cannot move
	// it, so the ceiling is the only half that can differ across one.
	refused := openGuardWithDeploymentCeiling(t, node, d, false)
	if err := refused.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureSpendMacaroon: %v", err)
	}

	if _, err := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); !os.IsNotExist(err) {
		t.Errorf("an uncappable spend macaroon survived on an install that cannot re-bake it "+
			"(stat: %v); it is the one state where a spend credential is live and the hard "+
			"cap does not apply to it", err)
	}
	if !contains(node.DeletedRootKeyIDs(), rootKey) {
		t.Errorf("the root key %d was not revoked at the node (deleted: %v); removing the file "+
			"leaves an exfiltrated copy working", rootKey, node.DeletedRootKeyIDs())
	}
	if pendingRootKeys(t, d) != nil {
		t.Errorf("pending keys survived the revocation: %v", pendingRootKeys(t, d))
	}
}

// Criterion 8: a node that will not take the registration is a STATE, not a
// crash.
//
// §14 requires this by name: rpcmiddleware.enable lives in an Umbrel-generated
// file a future umbrelOS release could change. The failure is safe — the caveat
// fails closed, so nothing can spend — but the guard must stay up, keep
// answering Status, and say so, because it still holds the kill switch and still
// bakes the receive credential that zap receiving depends on.
func TestANodeThatRefusesTheRegistrationIsAStateAndNotACrash(t *testing.T) {
	node := lndtest.Start(t)
	node.SetMiddlewareRegistrationError(errors.New("unknown method RegisterRPCMiddleware"))
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 100_000})
	serveMiddleware(t, node, g)

	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatalf("Status stopped answering when the registration failed: %v", err)
	}
	if status.MiddlewareRegistered {
		t.Error("the guard reports itself as enforcing while the node refused the registration")
	}
	// And the rest of the guard is untouched: receiving still works, which is
	// the whole reason this must not be fatal.
	if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Errorf("the receive credential could not be baked with the middleware down: %v", err)
	}
}

// And a registration that SUCCEEDS says so, under the caveat name it bakes.
//
// One constant for both, because a registration that does not match the caveat
// means LND rejects every spend RPC and nothing else goes wrong — the quietest
// possible way to break sending.
func TestTheGuardRegistersUnderTheCaveatNameItBakes(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 100_000})
	serveMiddleware(t, node, g)
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}

	registrations := node.MiddlewareRegistrations()
	if len(registrations) != 1 {
		t.Fatalf("%d registrations, want 1", len(registrations))
	}
	baked := readCredential(t, d.credentials, lnd.SpendMacaroon)
	if !lnd.HasGuardCaveat(baked) {
		t.Fatal("the spend macaroon carries no guard caveat, so nothing would be intercepted")
	}
	if got := registrations[0].GetCustomMacaroonCaveatName(); got != lnd.GuardCaveatName {
		t.Errorf("registered for caveat %q, baked %q — LND forwards nothing and rejects "+
			"everything", got, lnd.GuardCaveatName)
	}
	// NOT read-only mode, which would forward every RPC on the node — including
	// every other app's — to this guard.
	if registrations[0].GetReadOnlyMode() {
		t.Error("the guard registered in read-only mode; that intercepts every RPC on the node")
	}
	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !status.MiddlewareRegistered {
		t.Error("Status does not report the registration the node confirmed")
	}
}

// Criterion 9: the counter is in the GUARD's own store.
//
// An arch rule already stops the guard importing the server's database. This is
// the other half — that the thing the cap is computed from is actually written
// where the server cannot reach it, rather than being held in memory and lost on
// every restart, which would reset the window on demand.
func TestTheSpendWindowIsPersistedInTheGuardsOwnStore(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 100_000})
	serveMiddleware(t, node, g)

	if f := attempt(t, node, 5, invoiceFor(t, node, "persisted", 7_000)); f.GetError() != "" {
		t.Fatalf("the attempt was refused: %q", f.GetError())
	}

	// A RESTART: a second guard over the same volumes, which is what the binary
	// does on its next start.
	restarted := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 100_000})
	if used := spendUsed(t, restarted); used < 7_000 {
		t.Errorf("the window holds %d msat after a restart; a counter that does not survive "+
			"one is a cap a compromised server clears by restarting the container", used)
	}
}

// Criterion 10: two simultaneous attempts must not both pass a cap only one fits
// under.
//
// The lost update stateStore.update was given a mutex for in Wave 2, named in
// its own doc comment as "P4's rolling spend counter". Read the window, decide,
// then record, and two interceptions racing each other both read the same
// "used" and both pass.
func TestTwoSimultaneousAttemptsCannotBothPassACapOnlyOneFitsUnder(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	// Room for exactly one 6 000 msat payment.
	g := openGuardWithCaps(t, node, d, caps{window: 10_000, payment: 10_000})
	bolt11 := invoiceFor(t, node, "race", 6_000)

	const racers = 8
	// STRAIGHT AT InterceptRequest, not through the middleware stream, and that
	// is what makes this test mean something. LND delivers intercepted messages
	// down one bidi stream, so pushing eight through it hands them to the guard
	// one at a time and each finishes before the next arrives — a guard that
	// read the window, decided, and only then recorded passed a version of this
	// test that raced over the wire. Here the eight callers are genuinely
	// parallel.
	//
	// HELD INSIDE THE PRICING until all eight have arrived, so they reach the
	// window together rather than by luck.
	var arrived sync.WaitGroup
	arrived.Add(racers)
	release := make(chan struct{})
	node.SetOnDecodePayReq(func() {
		arrived.Done()
		<-release
	})
	go func() {
		arrived.Wait()
		close(release)
	}()

	results := make(chan error, racers)
	var running sync.WaitGroup
	for i := range racers {
		running.Add(1)
		go func() {
			defer running.Done()
			results <- g.InterceptRequest(t.Context(), lnd.Interception{
				RequestID:  uint64(100 + i),
				MethodURI:  lndtest.SendPaymentMethod,
				Serialized: marshal(t, payFor(bolt11)),
			})
		}()
	}
	running.Wait()
	close(results)

	allowed := 0
	for err := range results {
		if err == nil {
			allowed++
		}
	}
	if allowed != 1 {
		t.Errorf("%d of %d concurrent attempts were allowed against a window that fits one; "+
			"a lost update here lets two payments both pass the hard cap", allowed, racers)
	}
	if used := spendUsed(t, g); used != 6_000 {
		t.Errorf("the window holds %d msat, want 6 000 — one payment's worth", used)
	}
}

// WHAT THIS TEST DOES NOT CATCH, measured rather than assumed. Splitting the
// decision into a load and a later update, with nothing in between, leaves a
// racy window a few instructions wide, and eight goroutines released from the
// barrier above did not hit it in repeated runs. Put ANY real work between the
// two — the plant that catches it re-reads the invoice, which is the shape the
// mistake actually takes — and this test fails immediately. What guarantees the
// narrow case is not the race: it is that the check and the record are one
// stateStore.update, which is why Wave 2 gave that method the lock in the first
// place.

func marshal(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	raw, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A method the cap is not about goes through untouched.
//
// The spend macaroon grants three RPCs and the other two move no money.
// Refusing what it does not recognise would make this middleware a second
// permission list, silently diverging from SpendPermissions — the drift §6 spent
// d46.26 removing — and it would break the crash-recovery path, which resolves
// an in-flight payment through TrackPaymentV2.
func TestAMethodTheCapIsNotAboutIsNotRefused(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 1, payment: 1})
	serveMiddleware(t, node, g)

	feedback := node.Intercept(t, &lnrpc.RPCMiddlewareRequest{
		RequestId: 1,
		InterceptType: &lnrpc.RPCMiddlewareRequest_Request{Request: &lnrpc.RPCMessage{
			MethodFullUri: "/routerrpc.Router/TrackPaymentV2",
			StreamRpc:     true,
			TypeName:      "routerrpc.TrackPaymentRequest",
		}},
	})

	if feedback.GetError() != "" {
		t.Errorf("TrackPaymentV2 was refused by the spend cap: %q; it moves no money, and it "+
			"is how an in-flight payment is resolved after a crash", feedback.GetError())
	}
	if used := spendUsed(t, g); used != 0 {
		t.Errorf("the window was charged %d msat for a method that spends nothing", used)
	}
}

// EVERY intercepted message is answered, including the ones there is nothing to
// say about.
//
// LND blocks the intercepted RPC until the middleware replies with the matching
// ref_msg_id. Silence is not "allow" — it is a stalled call and, at the
// interceptor timeout, a rejected one, so a middleware that answered only the
// messages it had an opinion about would break every payment while looking like
// it was working. StreamAuth is the first message of a SendPaymentV2 call and
// carries no request body at all, which is exactly why it is easy to miss.
func TestEveryInterceptedMessageIsAnsweredIncludingStreamAuth(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 1, payment: 1})
	serveMiddleware(t, node, g)

	// Intercept fails the test if no answer arrives, which IS the assertion:
	// LND would sit here until its interceptor timeout and then reject the call.
	feedback := node.Intercept(t, &lnrpc.RPCMiddlewareRequest{
		RequestId: 42,
		InterceptType: &lnrpc.RPCMiddlewareRequest_StreamAuth{
			StreamAuth: &lnrpc.StreamAuth{MethodFullUri: lndtest.SendPaymentMethod},
		},
	})

	if feedback.GetError() != "" {
		t.Errorf("the guard refused the stream at StreamAuth: %q; that is one message too "+
			"early to know the amount, and it would refuse every payment", feedback.GetError())
	}
}

// The amount comes from the NODE, not from the request message.
//
// A compromised server holding the spend macaroon writes the request. If the
// guard priced an invoice by a field in that message, the cap would be a number
// the attacker chooses — and §6 has already ruled on the alternative to asking
// the node: "a second bolt11 parser in this repo, which would be a second
// opinion about where money goes".
func TestTheAmountIsTakenFromTheInvoiceAndNotFromTheRequest(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 10_000, payment: 10_000})
	serveMiddleware(t, node, g)

	// An invoice for 50 000 msat, in a request that claims 1 msat.
	bolt11 := invoiceFor(t, node, "understated", 50_000)
	feedback := node.Intercept(t, lndtest.SendPaymentIntercept(t, 1, "",
		&routerrpc.SendPaymentRequest{PaymentRequest: bolt11, AmtMsat: 1}))

	if feedback.GetError() == "" {
		t.Fatal("a 50 000 msat invoice was allowed under a 10 000 msat cap because the request " +
			"said it was worth 1 msat; the field the attacker writes is not a limit")
	}
}

// An attempt the guard cannot price is REFUSED, not waved through.
//
// The fail-closed direction, and the one a parser bug reaches: a payment request
// this build cannot read is a payment it cannot count, and letting it through
// would be the single case where the cap does not apply — reachable by sending a
// message shaped to defeat the parser.
func TestAnAttemptTheGuardCannotPriceIsRefused(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 100_000})
	serveMiddleware(t, node, g)

	for _, tc := range []struct {
		name string
		msg  *lnrpc.RPCMiddlewareRequest
	}{
		{"unreadable request", &lnrpc.RPCMiddlewareRequest{
			RequestId: 1,
			InterceptType: &lnrpc.RPCMiddlewareRequest_Request{Request: &lnrpc.RPCMessage{
				MethodFullUri: lndtest.SendPaymentMethod,
				TypeName:      "routerrpc.SendPaymentRequest",
				Serialized:    []byte{0xff, 0xff, 0xff, 0xff},
			}},
		}},
		{"an invoice the node will not decode", lndtest.SendPaymentIntercept(t, 2, "",
			&routerrpc.SendPaymentRequest{PaymentRequest: "lnbc-nonsense"})},
		{"no amount anywhere", lndtest.SendPaymentIntercept(t, 3, "",
			&routerrpc.SendPaymentRequest{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if feedback := node.Intercept(t, tc.msg); feedback.GetError() == "" {
				t.Error("an attempt the guard could not price was allowed through")
			}
		})
	}
	if used := spendUsed(t, g); used != 0 {
		t.Errorf("the window holds %d msat after three refusals", used)
	}
}

// A refusal reaches §12's durable trail.
//
// §12 calls a burst of guard rejections the highest-signal event in the system,
// and this is the only place a payment the operator's own limits forbid is
// stopped. Asserted as a RELAYED EVENT rather than a log line: the guard has no
// mount for the database (§16), so the socket response is the only way the trail
// can hold one.
func TestARefusedPaymentIsAudited(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 1_000, payment: 1_000})
	serveMiddleware(t, node, g)

	attempt(t, node, 1, invoiceFor(t, node, "audited", 9_000))

	event := lastGuardEvent(t, g, logging.EventGuardReject)
	if event.Attrs["op"] != "send_payment" {
		t.Errorf("the event names op %q; a trail that does not say WHAT was refused cannot "+
			"answer what was attempted", event.Attrs["op"])
	}
	if !strings.Contains(event.Attrs["reason"], "limit") {
		t.Errorf("the event's reason is %q; it does not say which limit stopped the payment",
			event.Attrs["reason"])
	}
}

// --- helpers -------------------------------------------------------------

// serveMiddleware runs the guard's middleware loop and waits until LND has
// confirmed the registration. It returns a function that stops it.
func serveMiddleware(t *testing.T, node *lndtest.Node, g *guard.Guard) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		defer running.Done()
		g.RunMiddleware(ctx)
	}()
	stop := sync.OnceFunc(func() {
		cancel()
		running.Wait()
	})
	t.Cleanup(stop)
	// Registration either lands or is refused; both are settled states, and a
	// test that waited only for success would hang on the refusal case. What it
	// must NOT do is return before the attempt has reached the node at all —
	// the first version keyed on `!node.MiddlewareIsLive()`, which is true
	// before the guard has even dialled, so it returned immediately and a test
	// asserting on the registration found none.
	lndtest.WaitFor(t, "the middleware to settle", func() bool {
		if node.MiddlewareAttempts() == 0 {
			return false
		}
		status, err := g.Status(ctx)
		return err == nil && (status.MiddlewareRegistered || !node.MiddlewareIsLive())
	})
	return stop
}

// attempt pushes one SendPaymentV2 request through the middleware.
func attempt(t *testing.T, node *lndtest.Node, requestID uint64, bolt11 string) *lnrpc.InterceptFeedback {
	t.Helper()
	return node.Intercept(t, lndtest.SendPaymentIntercept(t, requestID, "", payFor(bolt11)))
}

func payFor(bolt11 string) *routerrpc.SendPaymentRequest {
	return &routerrpc.SendPaymentRequest{PaymentRequest: bolt11}
}

// invoiceFor scripts the node's DecodePayReq, which is where the guard reads an
// amount from.
func invoiceFor(t *testing.T, node *lndtest.Node, name string, msat int64) string {
	t.Helper()
	bolt11 := "lnbc" + name
	node.SetDecoded(bolt11, &lnrpc.PayReq{PaymentHash: name, NumMsat: msat})
	return bolt11
}

func spendUsed(t *testing.T, g *guard.Guard) int64 {
	t.Helper()
	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return status.SpendUsedMsat
}

// stripGuardCaveat replaces the spend credential with one baked the way a
// pre-P4 build baked it: hardened, but with no custom caveat.
func stripGuardCaveat(t *testing.T, node *lndtest.Node, d dirs) {
	t.Helper()
	raw := readCredential(t, d.credentials, lnd.SpendMacaroon)
	expiry, ok := lnd.Expiry(raw)
	if !ok {
		t.Fatal("the baked credential carries no expiry to copy")
	}
	old := lndtest.Macaroon(t, lnd.CaveatIPAddr+" 10.21.0.17",
		lnd.CaveatTimeBefore+" "+expiry.UTC().Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(d.credentials, lnd.SpendMacaroon), old, 0o600); err != nil {
		t.Fatal(err)
	}
	if lnd.HasGuardCaveat(readCredential(t, d.credentials, lnd.SpendMacaroon)) {
		t.Fatal("the fixture still carries the caveat; this test would prove nothing")
	}
}

func quietLog(t *testing.T) *slog.Logger {
	t.Helper()
	return logging.New(io.Discard, logging.NewLevelVar(slog.LevelDebug))
}

// The three new Status fields cross the SOCKET, which is where the server reads
// them.
//
// THIS TEST EXISTS BECAUSE THE PAGE AND THE GUARD TESTS BOTH MISSED IT — the same
// blind spot tna.4 found and this wave reintroduced one layer down. The guard
// tests call g.Status directly and the api tests set lnd.BrokerStatus by hand,
// so hardcoding `MiddlewareRegistered: true` in SocketClient.Status left the
// whole gate green. §11 blocks sending on that field: a server that always reads
// true shows a healthy spend-cap row while the guard is not registered and every
// payment is being rejected by the node.
func TestTheSpendCapStateReachesTheServerOverTheSocket(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 77_000, payment: 25_000})
	serveMiddleware(t, node, g)
	client := serveGuard(t, g)

	if f := attempt(t, node, 1, invoiceFor(t, node, "socket", 5_000)); f.GetError() != "" {
		t.Fatalf("the attempt was refused: %q", f.GetError())
	}

	status, err := client.Status(t.Context())
	if err != nil {
		t.Fatalf("Status over the socket: %v", err)
	}
	if !status.MiddlewareRegistered {
		t.Error("the server was told the guard is not registered while it is; §11 blocks " +
			"sending on this, so the operator would be told sending is broken when it works")
	}
	if status.SpendLimitMsat != 77_000 {
		t.Errorf("the server was told the limit is %d, want 77 000 — the page states this "+
			"number, and a wrong one is worse than none", status.SpendLimitMsat)
	}
	if status.SpendUsedMsat != 5_000 {
		t.Errorf("the server was told %d msat is spoken for, want 5 000", status.SpendUsedMsat)
	}
}

// And the FALSE direction crosses it too.
//
// The positive case alone is satisfied by a mapping that hardcodes `true` — an
// early version of this test was, and the plant sailed through. §11 blocks
// sending on this field, so `true` is the answer that hides the failure: a
// server always told the guard is enforcing shows a healthy spend-cap row while
// the node rejects every payment.
func TestAnUnregisteredGuardSaysSoOverTheSocket(t *testing.T) {
	node := lndtest.Start(t)
	node.SetMiddlewareRegistrationError(errors.New("rpc middleware not enabled in config"))
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 10_000, payment: 10_000})
	serveMiddleware(t, node, g)
	client := serveGuard(t, g)

	status, err := client.Status(t.Context())
	if err != nil {
		t.Fatalf("Status over the socket: %v", err)
	}
	if status.MiddlewareRegistered {
		t.Error("the server was told the guard is enforcing while the node refused the " +
			"registration; §11 would show a healthy spend-cap row over an install where " +
			"every payment is refused by the node")
	}
}

// A stream that dies takes the "enforcing" claim with it.
//
// The macaroon stops working the moment the registration goes — LND rejects a
// custom caveat with no middleware behind it — so a guard that kept reporting
// itself as registered would show a green spend-cap row over an install where
// every payment is refused, which is the one diagnosis §11's row exists to give.
func TestAStreamThatDiesStopsTheGuardClaimingToEnforce(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 100_000})
	stop := serveMiddleware(t, node, g)

	if status, err := g.Status(t.Context()); err != nil || !status.MiddlewareRegistered {
		t.Fatalf("the guard did not report itself registered to begin with (%+v, %v)", status, err)
	}
	stop()

	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.MiddlewareRegistered {
		t.Error("the guard still reports itself as enforcing after its stream ended; the node " +
			"is refusing the spend macaroon and the page would say everything is fine")
	}
}

// A refused registration is RETRIED, which is what the operator is promised.
//
// §11's spend-cap row tells them "the guard retries on its own". That sentence
// was unverified: a version that gave up after the first failure passed every
// test, and the operator would have been told to wait for a retry that never
// came.
func TestTheGuardKeepsTryingToRegister(t *testing.T) {
	node := lndtest.Start(t)
	node.SetMiddlewareRegistrationError(errors.New("rpc middleware not enabled in config"))
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 100_000})
	serveMiddleware(t, node, g)

	// The node starts accepting registrations — an operator setting
	// rpcmiddleware.enable and restarting LND, which is the documented remedy.
	node.SetMiddlewareRegistrationError(nil)

	lndtest.WaitFor(t, "the guard to register after the node started accepting", func() bool {
		status, err := g.Status(t.Context())
		return err == nil && status.MiddlewareRegistered
	})
}

// Records leave the window by AGE, and the window is 24 hours.
//
// "Rolling, not calendar" is the property that stops a compromised server
// waiting for midnight and spending a second full cap, and nothing exercised it:
// no test had ever put a record older than the window into the state.
func TestRecordsLeaveTheWindowByAge(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	now := time.Unix(1_700_000_000, 0).UTC()
	clock := &testClock{now: now}
	g := openGuardFull(t, node, d, guard.Options{Now: clock.Now},
		netip.MustParseAddr("10.21.0.17"), true, caps{window: 10_000, payment: 10_000})
	serveMiddleware(t, node, g)

	if f := attempt(t, node, 1, invoiceFor(t, node, "aged", 9_000)); f.GetError() != "" {
		t.Fatalf("the attempt was refused: %q", f.GetError())
	}

	// One second short of the window: still counted, so a second payment does
	// not fit.
	clock.advance(guard.SpendWindow - time.Second)
	if used := spendUsed(t, g); used != 9_000 {
		t.Errorf("the window holds %d msat one second before the record ages out, want 9 000",
			used)
	}
	// And past it: gone, so the cap is available again.
	clock.advance(2 * time.Second)
	if used := spendUsed(t, g); used != 0 {
		t.Errorf("the window still holds %d msat after %s; it is a ROLLING window and a record "+
			"outside it is outside the question", used, guard.SpendWindow)
	}
	if f := attempt(t, node, 2, invoiceFor(t, node, "later", 9_000)); f.GetError() != "" {
		t.Errorf("a payment a full window later was refused: %q", f.GetError())
	}
}

// A record made on one middleware stream cannot be decremented from another.
//
// THE BUG THIS CATCHES WAS REAL AND FOUND BY REVIEW. LND numbers intercepted
// requests from a counter built at ITS OWN startup, so an LND restart makes the
// ids begin again at 1 while the guard reconnects and carries on. Keyed on the
// request id alone, a 1 000 msat payment failing after the restart would return
// a 90 000 msat record made before it — a decrement on loss of observation,
// which §14 forbids, and one a compromised server can drive on purpose by
// walking the ids with payments certain to fail.
func TestARecordFromAnEarlierStreamIsNotDecrementedByALaterOne(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 1_000_000, payment: 1_000_000})

	first := serveMiddleware(t, node, g)
	if f := attempt(t, node, 1, invoiceFor(t, node, "big", 90_000)); f.GetError() != "" {
		t.Fatalf("the first attempt was refused: %q", f.GetError())
	}
	// The stream dies with LND, so its outcome is never observed. Ruling 2: that
	// record stays counted.
	first()
	lndtest.WaitFor(t, "the stream to end", func() bool { return !node.MiddlewareIsLive() })

	// LND restarts; ids begin again at 1.
	serveMiddleware(t, node, g)
	if f := attempt(t, node, 1, invoiceFor(t, node, "dust", 1_000)); f.GetError() != "" {
		t.Fatalf("the second attempt was refused: %q", f.GetError())
	}
	node.Intercept(t, lndtest.PaymentIntercept(t, 1, &lnrpc.Payment{Status: lnrpc.Payment_FAILED}))

	if used := spendUsed(t, g); used != 90_000 {
		t.Errorf("the window holds %d msat, want 90 000: a 1 000 msat failure returned the "+
			"90 000 msat record from the previous stream. That is a decrement on loss of "+
			"observation, and after any LND restart a compromised server can walk the request "+
			"ids with payments certain to fail and empty the window", used)
	}
}

// The audit row says HOW MUCH, and it is a warning.
//
// §12 calls a burst of guard rejections the highest-signal event in the system.
// A trail that records that something was refused, without the amount, cannot
// answer the question an operator is actually asking after a suspected
// compromise — how much was attempted.
func TestARefusedPaymentsRowCarriesTheAmountAndIsAWarning(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 1_000, payment: 1_000})
	serveMiddleware(t, node, g)

	attempt(t, node, 1, invoiceFor(t, node, "loud", 9_000))

	event := lastGuardEvent(t, g, logging.EventGuardReject)
	if event.Attrs["msat"] != "9000" {
		t.Errorf("the event says msat %q, want 9000 — the trail has to say how much was "+
			"attempted", event.Attrs["msat"])
	}
	if event.Level != slog.LevelWarn {
		t.Errorf("the event is at %v, want WARN", event.Level)
	}
}

// Every bake gets a FRESH nonce.
//
// It is what makes two credentials distinguishable in the node's logs and in an
// intercepted request. A constant would still route correctly, so nothing else
// would ever notice.
func TestEachBakeGetsAFreshCaveatNonce(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 100_000})

	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	firstNonce := guardCaveatOf(t, readCredential(t, d.credentials, lnd.SpendMacaroon))
	if err := g.RevokeSpend(t.Context()); err != nil {
		t.Fatalf("RevokeSpend: %v", err)
	}
	// Revoking drops the operator's latch — "off must latch off" (`06v`, Ruling
	// 1) — so turning sending back on is a fresh ceremony, exactly as it is for
	// an operator. Without it the second bake is refused and this test would
	// report a nonce problem it does not have.
	permitSending(t, g, d)
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("second BakeSpend: %v", err)
	}
	secondNonce := guardCaveatOf(t, readCredential(t, d.credentials, lnd.SpendMacaroon))

	if firstNonce == "" || firstNonce == secondNonce {
		t.Errorf("two bakes produced the caveat %q twice; the nonce is what tells two "+
			"credentials apart in the node's log and in an intercepted request", firstNonce)
	}
}

func guardCaveatOf(t *testing.T, raw []byte) string {
	t.Helper()
	caveats, err := lnd.Caveats(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, caveat := range caveats {
		if strings.HasPrefix(caveat, lnd.CaveatLNDCustom+" "+lnd.GuardCaveatName+" ") {
			return caveat
		}
	}
	return ""
}

// What an attempt COSTS is the amount plus the fee limit, and both halves of
// each are counted in msat.
//
// NONE OF THIS WAS EXERCISED. Every other test prices a plain invoice through
// SetDecoded, so a build that counted no fee at all, or that read a
// sat-denominated amount as msat — a thousandfold under-count on the one number
// the whole bead is about — passed the suite.
func TestAnAttemptCostsItsAmountPlusItsFeeLimit(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *routerrpc.SendPaymentRequest
		cost int64
	}{
		{"invoice plus an msat fee limit",
			&routerrpc.SendPaymentRequest{FeeLimitMsat: 2_000}, 7_000},
		{"invoice plus a SAT fee limit",
			&routerrpc.SendPaymentRequest{FeeLimitSat: 3}, 8_000},
		{"the msat fee limit wins when both are set",
			&routerrpc.SendPaymentRequest{FeeLimitMsat: 1_000, FeeLimitSat: 99}, 6_000},
		{"no fee limit at all — LND then sends no fee",
			&routerrpc.SendPaymentRequest{}, 5_000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := lndtest.Start(t)
			d := guardDirs(t, node)
			g := openGuardWithCaps(t, node, d, caps{window: 1_000_000, payment: 1_000_000})
			serveMiddleware(t, node, g)

			tc.req.PaymentRequest = invoiceFor(t, node, "priced", 5_000)
			if f := node.Intercept(t, lndtest.SendPaymentIntercept(t, 1, "", tc.req)); f.GetError() != "" {
				t.Fatalf("the attempt was refused: %q", f.GetError())
			}

			if used := spendUsed(t, g); used != tc.cost {
				t.Errorf("the window was charged %d msat, want %d — §6's cap is on outbound "+
					"TOTAL, and the fee goes outbound too", used, tc.cost)
			}
		})
	}
}

// An amount the request names itself is read in the right unit.
//
// A zero-amount invoice, and a keysend with no invoice at all, are the two cases
// where the number in the request IS what LND will send — so reading it is not
// trust, it is the fact. Amt is SATOSHIS and AmtMsat is millisatoshis, and
// confusing them under-counts by a thousand.
func TestAnAmountNamedByTheRequestIsCountedInTheRightUnit(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *routerrpc.SendPaymentRequest
		cost int64
	}{
		{"a zero-amount invoice, paid in msat",
			&routerrpc.SendPaymentRequest{AmtMsat: 4_500}, 4_500},
		{"a zero-amount invoice, paid in sats",
			&routerrpc.SendPaymentRequest{Amt: 7}, 7_000},
		{"a keysend with no invoice at all",
			&routerrpc.SendPaymentRequest{Dest: []byte("a pubkey"), Amt: 9}, 9_000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := lndtest.Start(t)
			d := guardDirs(t, node)
			g := openGuardWithCaps(t, node, d, caps{window: 1_000_000, payment: 1_000_000})
			serveMiddleware(t, node, g)

			if tc.req.GetDest() == nil {
				// An invoice that names NO amount: LND then sends what the
				// request says, so that is what the guard must count.
				tc.req.PaymentRequest = invoiceFor(t, node, "amountless", 0)
			}
			if f := node.Intercept(t, lndtest.SendPaymentIntercept(t, 1, "", tc.req)); f.GetError() != "" {
				t.Fatalf("the attempt was refused: %q", f.GetError())
			}

			if used := spendUsed(t, g); used != tc.cost {
				t.Errorf("the window was charged %d msat, want %d", used, tc.cost)
			}
		})
	}
}

// Numbers that would wrap are refused, including the ones that wrap POSITIVE.
//
// The dangerous direction is not a negative cost — amount <= 0 catches that —
// it is a satoshi figure near 2^63/1000, which wraps through the ×1000 to a
// small positive msat value and is then priced at almost nothing. Both fields
// are written by the container this cap exists to bound.
func TestAnAmountThatWouldWrapIsRefused(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 1_000_000, payment: 1_000_000})
	serveMiddleware(t, node, g)
	amountless := invoiceFor(t, node, "wrapping", 0)
	// 2^64 + 384, in satoshis, so ×1000 lands on 384.
	const wrapsToTiny int64 = 18_446_744_073_709_552

	for _, tc := range []struct {
		name string
		req  *routerrpc.SendPaymentRequest
	}{
		// 18446744073709552 × 1000 is 2^64 + 384, so it wraps to 384 msat — a
		// SMALL POSITIVE number, which is the arm that matters: a negative
		// result is caught by the amount <= 0 check, and this one would be
		// priced at less than a satoshi and let through.
		{"a satoshi amount that wraps to a small positive through ×1000",
			&routerrpc.SendPaymentRequest{PaymentRequest: amountless, Amt: wrapsToTiny}},
		{"a satoshi fee limit that wraps the same way",
			&routerrpc.SendPaymentRequest{PaymentRequest: amountless, AmtMsat: 1_000,
				FeeLimitSat: wrapsToTiny}},
		{"a satoshi amount that wraps negative",
			&routerrpc.SendPaymentRequest{PaymentRequest: amountless, Amt: math.MaxInt64/1000 + 2}},
		{"an msat amount and fee that overflow when added",
			&routerrpc.SendPaymentRequest{PaymentRequest: amountless,
				AmtMsat: math.MaxInt64 - 10, FeeLimitMsat: 100}},
		{"a negative amount", &routerrpc.SendPaymentRequest{PaymentRequest: amountless, AmtMsat: -5}},
		{"a negative fee limit", &routerrpc.SendPaymentRequest{PaymentRequest: amountless,
			AmtMsat: 1_000, FeeLimitMsat: -5_000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f := node.Intercept(t, lndtest.SendPaymentIntercept(t, 1, "", tc.req)); f.GetError() == "" {
				t.Error("an attempt whose cost the guard cannot compute was allowed through")
			}
		})
	}
	if used := spendUsed(t, g); used != 0 {
		t.Errorf("the window holds %d msat after five refusals", used)
	}
}

// VerifyBaked refuses a spend macaroon with no guard caveat, on its own.
//
// It is the belt-and-braces half of the same rule credentialCaveats implements:
// checked against the POLICY rather than against the list this bake happened to
// ask for. Its arm had never failed — every test call site passed false, and
// through bake() the caveat is always there — so a build that dropped it would
// have looked exactly like this one.
func TestVerifyBakedRefusesASpendMacaroonWithNoGuardCaveat(t *testing.T) {
	hardened := []string{lnd.CaveatIPAddr + " 10.21.0.17", lnd.CaveatTimeBefore + " 2033-01-01T00:00:00Z"}

	if err := guard.VerifyBaked("spend", true, lndtest.Macaroon(t, hardened...)); err == nil {
		t.Error("a spend macaroon with no guard caveat passed verification; LND would perform " +
			"payments with it without ever asking the guard, and the hard cap would apply to " +
			"nothing while every indicator read green")
	} else if !strings.Contains(err.Error(), lnd.GuardCaveatName) {
		t.Errorf("the error %q does not name the missing caveat", err)
	}
	// With it, it passes...
	withCaveat := append(append([]string(nil), hardened...), lnd.GuardCaveat("nonce"))
	if err := guard.VerifyBaked("spend", true, lndtest.Macaroon(t, withCaveat...)); err != nil {
		t.Errorf("a correctly baked spend macaroon was rejected: %v", err)
	}
	// ...and the RECEIVE credential is not asked for one, which is the half that
	// keeps zap receiving alive across a guard restart.
	if err := guard.VerifyBaked("receive", false, lndtest.Macaroon(t, hardened...)); err != nil {
		t.Errorf("a receive macaroon was required to carry the guard caveat: %v", err)
	}
}

// The registration NAME matches the caveat name too, not only the caveat field.
//
// Two fields, one constant, and only one of them was asserted. LND logs the
// middleware name and scopes interception by the caveat name; a mismatch between
// what we bake and what we register means LND forwards nothing and rejects
// everything — the quietest possible way to break sending.
func TestTheRegistrationNamesMatchTheCaveatOnBothFields(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	serveMiddleware(t, node, openGuardWithCaps(t, node, d, caps{window: 1, payment: 1}))

	registrations := node.MiddlewareRegistrations()
	if len(registrations) != 1 {
		t.Fatalf("%d registrations, want 1", len(registrations))
	}
	if got := registrations[0].GetMiddlewareName(); got != lnd.GuardCaveatName {
		t.Errorf("registered under the middleware name %q, want %q — one constant for both, "+
			"because a mismatch is invisible until every payment fails", got, lnd.GuardCaveatName)
	}
}

// A cap of ZERO refuses everything; it does not mean "no cap".
//
// Both deployments set real defaults, so zero is always something a person typed
// on purpose — into a setting called "maximum spend", where it plainly means "do
// not spend". Reading it as unlimited would be the worst available reading of a
// security limit, and the config cross-check cannot catch it: a zero window
// against a zero per-payment cap satisfies `payment > window`.
func TestAZeroCapRefusesEverythingRatherThanMeaningNoCap(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{})
	serveMiddleware(t, node, g)

	feedback := attempt(t, node, 1, invoiceFor(t, node, "any", 1))

	if feedback.GetError() == "" {
		t.Fatal("a payment was allowed with both caps set to zero; an operator who types 0 into " +
			"\"maximum spend\" has just been given unlimited spend")
	}
	if used := spendUsed(t, g); used != 0 {
		t.Errorf("the window holds %d msat after a refusal", used)
	}
}
