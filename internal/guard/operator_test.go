package guard_test

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc/routerrpc"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// `06v`, Ruling 1: TIGHTENING IS FREE, LOOSENING NEEDS THE CEREMONY.
//
// The table is the rule, said once. Every row is a change an operator might
// make, and the only thing that decides whether it needs a code is the direction
// it moves relative to the guard's OWN stored state — never the caller's
// account of it.
//
// The reasoning is that a compromised server gains nothing by restricting
// itself, so a ceremony on that direction costs the operator and buys nothing.
// The consequence is that a compromised server CAN grief an install into
// tightness, which Ruling 1 accepts out loud: it is an availability attack by
// the thing that is the availability.
func TestOnlyLooseningNeedsAnAuthorisation(t *testing.T) {
	const window, payment = 100_000, 50_000
	for _, tc := range []struct {
		name     string
		change   guard.Change
		loosens  bool
		expected string
	}{
		{"turning sending on", guard.Change{Control: guard.ControlSending, On: true}, true,
			"a compromised server would mint itself spend authority"},
		{"turning sending off", guard.Change{Control: guard.ControlSending, On: false}, false,
			"an operator turning sending off must not have to find a file first"},
		{"raising the window cap", guard.Change{Control: guard.ControlSpendCap, Msat: window + 1},
			true, "a server that can raise its own ceiling harms every sending install"},
		{"lowering the window cap", guard.Change{Control: guard.ControlSpendCap, Msat: window - 1},
			false, "lowering a limit is the cheapest safety action there is"},
		{"raising the per-payment cap",
			guard.Change{Control: guard.ControlPaymentCap, Msat: payment + 1}, true,
			"the per-payment cap bounds one theft, and raising it is a loosening"},
		{"lowering the per-payment cap",
			guard.Change{Control: guard.ControlPaymentCap, Msat: payment - 1}, false,
			"lowering a limit is the cheapest safety action there is"},
		{"setting a cap to what it already is",
			guard.Change{Control: guard.ControlSpendCap, Msat: window}, false,
			"a no-op is not a loosening, and asking for a ceremony to perform one " +
				"teaches the operator the ceremony is a formality"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := lndtest.Start(t)
			d := guardDirs(t, node)
			// A FRESH INSTALL: sending not yet permitted, so "turn sending on"
			// is genuinely a loosening. openGuardWithCaps performs the ceremony
			// itself, and a test that used it here would find the latch already
			// thrown and pass without exercising anything.
			g := openGuardUnpermitted(t, node, d, caps{window: window, payment: payment})

			// WITH NO CODE, which is what a compromised server has.
			err := g.ApplyChange(t.Context(), tc.change, "")

			if tc.loosens && err == nil {
				t.Fatalf("%s applied with no authorisation: %s", tc.name, tc.expected)
			}
			if !tc.loosens && err != nil {
				t.Fatalf("%s was refused (%v): %s", tc.name, err, tc.expected)
			}
		})
	}
}

// The whole ceremony, end to end, in the operator's own steps.
//
// This is the seam `06v`'s brief names: the server relays a code it cannot mint,
// and the guard verifies it against state the server cannot read. Testing the
// two ends separately would leave the wire between them untested, which is this
// project's named recurring failure (§13).
func TestTheOperatorCeremonyEnablesSendingEndToEnd(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardFull(t, node, d, guard.Options{}, serverAddr(), true)
	client := serveGuard(t, g)
	change := guard.Change{Control: guard.ControlSending, On: true}

	// 1. A fresh install is receive-only. The SERVER's own attempt gets nowhere.
	if err := client.ApplyChange(t.Context(), change, ""); err == nil {
		t.Fatal("sending was turned on over the socket with no authorisation; the ceremony is " +
			"the only thing standing between a compromised server and spend authority")
	}

	// 2. The operator asks for one, through the server, which is their only
	//    channel to the app.
	if err := client.RequestAuthorisation(t.Context(), change); err != nil {
		t.Fatalf("requesting an authorisation: %v", err)
	}

	// 3. They read the guard's own file — in a volume the server has no mount
	//    for — and it tells them, in the guard's words, what is being asked.
	raw, err := os.ReadFile(filepath.Join(d.data, "authorisation.txt"))
	if err != nil {
		t.Fatalf("the operator has nothing to read: %v", err)
	}
	if !strings.Contains(string(raw), "TURN SENDING ON") {
		t.Errorf("the authorisation file does not say what is being authorised; it is the one "+
			"account of the pending change the server did not write, and it is the only "+
			"reason typing the code is safe:\n%s", raw)
	}

	// 4. They type the code back in, and the server relays it.
	code := readAuthorisationCode(t, d)
	if err := client.ApplyChange(t.Context(), change, code); err != nil {
		t.Fatalf("redeeming the authorisation: %v", err)
	}

	// 5. Sending is now permitted, and the bake the page performs next works.
	if err := client.RequestSpendBake(t.Context()); err != nil {
		t.Fatalf("the bake after a completed ceremony: %v", err)
	}
	if _, err := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Errorf("no spend.macaroon after the whole ceremony: %v", err)
	}

	// 6. The grant is SPENT, and replaying it is the first thing a server that
	//    captured a code would try. The replay that matters is the one after a
	//    tightening: turn sending off — free, by Ruling 1 — and the old code must
	//    not turn it back on.
	if _, err := os.Stat(filepath.Join(d.data, "authorisation.txt")); !os.IsNotExist(err) {
		t.Errorf("the authorisation file survived being spent (stat: %v); an operator "+
			"returning to a stale code is told it is wrong, which reads as a broken app", err)
	}
	if err := client.ApplyChange(t.Context(),
		guard.Change{Control: guard.ControlSending, On: false}, ""); err != nil {
		t.Fatalf("turning sending off: %v", err)
	}
	if err := client.ApplyChange(t.Context(), change, code); err == nil {
		t.Error("a spent authorisation code turned sending back on. A server that captured " +
			"one could wait for the operator to disable and then re-mint spend authority " +
			"without them")
	}
}

// The SERVER NEVER LEARNS THE CODE, by any route it has.
//
// This is the property everything else rests on, and it is worth asserting
// directly rather than inferring from the absence of a field: the socket is the
// server's whole view of the guard, so if the code is not in any response to any
// operation, it cannot be relayed to the thing it defends against.
func TestNoSocketResponseCarriesTheAuthorisationCode(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardFull(t, node, d, guard.Options{}, serverAddr(), true)
	change := guard.Change{Control: guard.ControlSending, On: true}
	if err := g.RequestAuthorisation(t.Context(), change); err != nil {
		t.Fatal(err)
	}
	code := readAuthorisationCode(t, d)

	for _, req := range []guard.Request{
		{Op: guard.OpStatus},
		{Op: guard.OpBakeSpend},
		{Op: guard.OpRevokeSpend},
		{Op: guard.OpRequestAuthorisation, Change: &change},
		{Op: guard.OpApplyChange, Change: &change, Code: "WRONG-COD"},
	} {
		resp := g.Handle(t.Context(), req)
		rendered := render(t, resp)
		if strings.Contains(strings.ToUpper(rendered), strings.ToUpper(code)) {
			t.Errorf("the answer to %s carries the authorisation code; the server relaying it "+
				"is the whole design, and a server that can READ it can mint its own spend "+
				"authority:\n%s", req.Op, rendered)
		}
	}
}

// An authorisation is bound to the CHANGE, value and all.
//
// Checking only the control would leave the operator's sentence true and the
// applied change something else entirely: they read "raise the limit to 50k
// sats", type the code, and a compromised server spends it on five million.
func TestAnAuthorisationCannotBeSpentOnADifferentChange(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardUnpermitted(t, node, d, caps{window: 100_000, payment: 50_000})

	modest := guard.Change{Control: guard.ControlSpendCap, Msat: 150_000}
	if err := g.RequestAuthorisation(t.Context(), modest); err != nil {
		t.Fatal(err)
	}
	code := readAuthorisationCode(t, d)

	greedy := guard.Change{Control: guard.ControlSpendCap, Msat: 5_000_000_000}
	if err := g.ApplyChange(t.Context(), greedy, code); err == nil {
		t.Fatal("a code issued for a modest raise was spent on a large one; the operator read " +
			"one sentence and authorised another")
	}
	if got := spendLimit(t, g); got != 100_000 {
		t.Errorf("the cap is now %d msat; nothing should have been applied", got)
	}
	// And a different CONTROL entirely, which is the phishing shape: the
	// operator is shown "confirm this" for something harmless.
	if err := g.ApplyChange(t.Context(),
		guard.Change{Control: guard.ControlSending, On: true}, code); err == nil {
		t.Fatal("a code issued to raise a cap turned sending on")
	}
}

// A new request supersedes an outstanding one.
//
// Two live codes would mean two sentences on disk describing two pending
// operations, and an operator typing the code they can see for the change they
// did not read — the phishing this design exists to prevent, assembled out of
// two honest halves.
func TestANewAuthorisationSupersedesTheOutstandingOne(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardUnpermitted(t, node, d, caps{window: 100_000, payment: 50_000})

	first := guard.Change{Control: guard.ControlSpendCap, Msat: 150_000}
	if err := g.RequestAuthorisation(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	firstCode := readAuthorisationCode(t, d)

	second := guard.Change{Control: guard.ControlSending, On: true}
	if err := g.RequestAuthorisation(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	if secondCode := readAuthorisationCode(t, d); secondCode == firstCode {
		t.Fatal("the second request reused the first code; a superseded grant that shares a " +
			"code is not superseded")
	}
	if err := g.ApplyChange(t.Context(), first, firstCode); err == nil {
		t.Error("the superseded code still worked")
	}
}

// A wrong code is bounded, and the grant is spent when the bound is reached.
//
// The code is 40 bits, so this is not what stops a brute force — it is what
// makes one VISIBLE and finite. Three wrong codes on a grant the operator never
// asked for is a server behaving like an attacker.
func TestWrongCodesAreBoundedAndSpendTheAuthorisation(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 50_000})
	change := guard.Change{Control: guard.ControlSpendCap, Msat: 150_000}
	if err := g.RequestAuthorisation(t.Context(), change); err != nil {
		t.Fatal(err)
	}
	code := readAuthorisationCode(t, d)

	for attempt := 1; attempt <= 3; attempt++ {
		if err := g.ApplyChange(t.Context(), change, "0000-0000"); err == nil {
			t.Fatalf("attempt %d: a wrong code was accepted", attempt)
		}
	}

	// The RIGHT code no longer works: the grant is spent, not merely locked.
	if err := g.ApplyChange(t.Context(), change, code); err == nil {
		t.Error("the correct code still worked after the attempt bound; the grant survived a " +
			"run of guesses, which leaves it a standing target")
	}
	if got := spendLimit(t, g); got != 100_000 {
		t.Errorf("the cap is now %d msat; nothing should have been applied", got)
	}
}

// An expired authorisation is refused, and the guard's own clock decides.
func TestAnExpiredAuthorisationIsRefused(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)}
	g := openGuardFull(t, node, d, guard.Options{Now: clock.Now}, serverAddr(), true)
	change := guard.Change{Control: guard.ControlSending, On: true}

	if err := g.RequestAuthorisation(t.Context(), change); err != nil {
		t.Fatal(err)
	}
	code := readAuthorisationCode(t, d)
	// THE EXPIRY THE SERVER IS TOLD, not one the test computes: Status is the
	// wire's own account of the pending grant, so a page that renders "the code
	// stops working at X" and a guard that refuses it at Y would be caught here.
	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.AuthorisationExpiresAt.IsZero() {
		t.Fatal("the guard reports no expiry for an outstanding grant; the page cannot tell " +
			"the operator when their code dies")
	}
	// Exactly at the expiry, not past it: a boundary tested one second late
	// leaves the boundary itself untested, and "expires at" has to mean it.
	clock.now = status.AuthorisationExpiresAt

	err = g.ApplyChange(t.Context(), change, code)

	if err == nil {
		t.Fatal("a code was redeemed at its stated expiry")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("the refusal says %q; an operator whose code timed out needs to be told to "+
			"ask for a new one, not that they typed it wrong", err)
	}
}

// The ceremony reaches §12's durable trail — every issue, redemption and
// refusal — and NEVER carries the code.
//
// Through the guard's own auditor, which relays to the server: §16 gives the
// guard no mount for the database. Asserted as relayed events rather than log
// lines, because the Auditor went uncalled for three waves in this repository
// while every component's tests passed.
func TestTheCeremonyIsAuditedAndTheCodeIsNever(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	// Unpermitted, so the only ceremony events in the trail are this test's own
	// — the harness's own permitSending would otherwise put two 'sending' rows
	// in front of them.
	g := openGuardUnpermitted(t, node, d, caps{window: 100_000, payment: 50_000})
	change := guard.Change{Control: guard.ControlSpendCap, Msat: 150_000}
	if err := g.RequestAuthorisation(t.Context(), change); err != nil {
		t.Fatal(err)
	}
	code := readAuthorisationCode(t, d)
	_ = g.ApplyChange(t.Context(), change, "0000-0000")
	if err := g.ApplyChange(t.Context(), change, code); err != nil {
		t.Fatal(err)
	}

	var outcomes []string
	events := g.Handle(t.Context(), guard.Request{Op: guard.OpStatus}).Events
	for _, event := range events {
		if event.Event != logging.EventGuardAuthorise {
			continue
		}
		outcomes = append(outcomes, event.Attrs["outcome"])
		if event.Attrs["control"] != string(guard.ControlSpendCap) {
			t.Errorf("an event names control %q; the trail has to answer WHICH control was "+
				"changed", event.Attrs["control"])
		}
	}
	for _, want := range []string{"issued", "wrong code", "authorised"} {
		if !containsString(outcomes, want) {
			t.Errorf("the trail holds outcomes %v, missing %q — it is the durable answer to "+
				"'who raised the spending limit, and when', asked by someone who cannot trust "+
				"the server's own account of it", outcomes, want)
		}
	}
	if rendered := render(t, events); strings.Contains(strings.ToUpper(rendered),
		strings.ToUpper(code)) {
		t.Errorf("the audit trail carries the code. It is written to the server's database, "+
			"which is the container the code exists to keep out:\n%s", rendered)
	}
}

// §6's outer bound holds over the STORED values, not only over the environment.
//
// config.LoadGuard makes this check at load. It has to be made here too, because
// the operator changes one cap at a time: lowering the window below the
// per-payment cap would leave a per-payment limit that can never be reached — a
// number on the page that means nothing, which is worse than a refusal saying
// why.
func TestThePerPaymentCapCanNeverBeLeftAboveTheWindowCap(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 50_000})

	// A LOWERING, so it needs no code — and it must still be refused. The
	// monotonic split is about who may ask; it is not a licence to write an
	// inconsistent pair.
	err := g.ApplyChange(t.Context(),
		guard.Change{Control: guard.ControlSpendCap, Msat: 40_000}, "")

	if err == nil {
		t.Fatal("the 24-hour cap was lowered below the per-payment cap; the per-payment limit " +
			"can now never be reached, and the page states a number that means nothing")
	}
	if got := spendLimit(t, g); got != 100_000 {
		t.Errorf("the window cap is %d msat after a refused change, want 100000", got)
	}
}

// The stored caps are what the MIDDLEWARE enforces, not the environment ones.
//
// The seam again, and the one that matters most: a cap the operator lowered that
// the payment path never reads is a control that appears to work and does not.
// Asserted through InterceptRequest, which is the code LND actually consults.
func TestALoweredCapIsWhatThePaymentPathEnforces(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 100_000})

	// 60_000 msat passes under the configured caps.
	if err := g.InterceptRequest(t.Context(), sendPaymentOf(t, 60_000)); err != nil {
		t.Fatalf("a payment inside the configured caps was refused: %v", err)
	}
	if err := g.ApplyChange(t.Context(),
		guard.Change{Control: guard.ControlPaymentCap, Msat: 50_000}, ""); err != nil {
		t.Fatalf("lowering the per-payment cap: %v", err)
	}

	err := g.InterceptRequest(t.Context(), sendPaymentOf(t, 60_000))

	if err == nil {
		t.Fatal("the payment path allowed a payment over the cap the operator had just " +
			"lowered; the control is on a page and not in the code that enforces it")
	}
}

// --- helpers -------------------------------------------------------------

// serverAddr is the address every guard in this file locks its credentials to.
func serverAddr() netip.Addr { return netip.MustParseAddr("10.21.0.17") }

// render is how a test asks "does this value contain the code anywhere".
//
// JSON rather than %+v, because JSON is exactly what crosses the socket and
// exactly what the server's database stores — so a field the guard forgot to
// exclude shows up here in the same shape it would show up there.
func render(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("rendering %T: %v", v, err)
	}
	return string(raw)
}

// spendLimit reads the window cap back through the guard's own Status, which is
// the only account of it the rest of the system ever sees.
func spendLimit(t *testing.T, g *guard.Guard) int64 {
	t.Helper()
	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	return status.SpendLimitMsat
}

// sendPaymentOf builds the interception LND would make for a payment of msat.
//
// It does not go through a real invoice: this file's subject is the CAP, and the
// pricing path has its own tests. What matters here is that the number the
// middleware compares against comes from the guard's stored state.
func sendPaymentOf(t *testing.T, msat int64) lnd.Interception {
	t.Helper()
	return lnd.Interception{
		RequestID:  uint64(msat),
		MethodURI:  lndtest.SendPaymentMethod,
		Serialized: marshal(t, &routerrpc.SendPaymentRequest{AmtMsat: msat}),
	}
}

// containsString is contains for the outcome strings the trail carries.
func containsString(all []string, want string) bool { return slices.Contains(all, want) }

// 8vj: the refusal must name the control the operator is NOT editing.
//
// The invariant is right and the refusal is right — a per-payment limit above
// the 24-hour window can never be reached, and a number on the page that means
// nothing is worse than a refusal that says why. The REMEDY was correct in one
// direction only. Lowering the window below the standing per-payment cap told
// the operator to "change the 24-hour limit first": the control they had just
// typed into. What has to move is the other one.
//
// PAID FOR ON THE BOX, 2026-09-02, from the guard's own audit trail. An operator
// holding a 250-sat per-payment cap tried to set a 100-sat 24-hour ceiling, was
// refused with the backwards remedy, tried 10,000, and settled at 1,000 — ten
// times looser than they wanted, on the control whose whole purpose is bounding
// loss. A message that obstructs TIGHTENING is backwards for a security control:
// §6's asymmetry makes the safe direction the free one, and this message was
// charging for it.
//
// BOTH DIRECTIONS IN ONE TABLE, because the defect is that they were the SAME
// string. A test asserting one direction passes against the bug, and so does one
// that only matches a substring the two share — which is why each case also
// refuses the other's remedy.
func TestTheCapPairRefusalNamesTheControlTheOperatorIsNotEditing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  guard.Change
		want    string
		notWant string
	}{{
		// TIGHTENING, and the case from the box. It needs no code, and it is
		// refused anyway — correctly — so the message is the operator's only
		// signal about what to do next.
		name:    "lowering the 24-hour window below the standing per-payment cap",
		change:  guard.Change{Control: guard.ControlSpendCap, Msat: 40_000},
		want:    "a per-payment limit of 50 sats is above the 24-hour limit of 40 sats, so it could never be reached; lower the per-payment limit first",
		notWant: "24-hour limit first",
	}, {
		// LOOSENING, and the direction the old message was written for. It is
		// refused by the cap-pair check BEFORE the authorisation check, which is
		// why an empty code reaches this error rather than errAuthorisationRequired.
		name:    "raising the per-payment cap above the standing 24-hour window",
		change:  guard.Change{Control: guard.ControlPaymentCap, Msat: 150_000},
		want:    "a per-payment limit of 150 sats is above the 24-hour limit of 100 sats, so it could never be reached; raise the 24-hour limit first",
		notWant: "per-payment limit first",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			node := lndtest.Start(t)
			d := guardDirs(t, node)
			g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 50_000})

			err := g.ApplyChange(t.Context(), tc.change, "")
			if err == nil {
				t.Fatal("the cap pair was left inconsistent; the per-payment limit can now " +
					"never be reached, and the page states a number that means nothing")
			}
			if got := err.Error(); !strings.Contains(got, tc.want) {
				t.Errorf("the refusal reads\n  %s\nwant it to contain\n  %s", got, tc.want)
			}
			if got := err.Error(); strings.Contains(got, tc.notWant) {
				t.Errorf("the refusal reads\n  %s\nand names %q — the control the operator is "+
					"already editing, which is the whole of 8vj", got, tc.notWant)
			}
		})
	}
}
