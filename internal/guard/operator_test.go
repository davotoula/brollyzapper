package guard_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
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

// TestThePerPaymentCapCanNeverBeLeftAboveTheWindowCap STOOD HERE (`l4g`).
//
// Its fixture and its change were identical to the first case of
// TestTheCapPairRefusalNamesTheControlTheOperatorIsNotEditing below; only the
// assertion differed, and that assertion is now a per-case field of that table,
// made in BOTH directions rather than only the tightening one. The name is left
// in this comment on purpose: it states the invariant — §6's outer bound holds
// over the STORED values, not only over the environment — and it was a grep
// target, so a reader who comes looking for it should find where it went rather
// than an absence.

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

// storedCaps is the PAIR the guard has stored, which is the unit §6's outer
// bound is about — one number cannot see a refusal that moved the other.
func storedCaps(t *testing.T, g *guard.Guard) caps {
	t.Helper()
	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	return caps{window: status.SpendLimitMsat, payment: status.MaxPaymentMsat}
}

// spendLimit reads the window cap back through the guard's own Status, which is
// the only account of it the rest of the system ever sees.
func spendLimit(t *testing.T, g *guard.Guard) int64 {
	t.Helper()
	return storedCaps(t, g).window
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
// What it cost on the box is in checkCapPair's own doc comment, which is where
// that argument belongs; it is not repeated here.
//
// BOTH DIRECTIONS IN ONE TABLE, because the defect is that they were the SAME
// string. A test asserting one direction passes against the bug.
//
// EACH CASE ALSO REFUSES THE OTHER'S REMEDY, and the reason is narrower than it
// looks. It is not needed to catch the old string or the swapped one — `want`
// carries the whole remedy clause, so both of those already fail it. What it
// catches is a message that offers BOTH remedies at once, which reads like a
// kindness and is not: an operator lowering the 24-hour limit cannot act on
// "raise the 24-hour limit", so offering it there puts back the misdirection
// this bead exists to remove.
func TestTheCapPairRefusalNamesTheControlTheOperatorIsNotEditing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  guard.Change
		want    string
		notWant string
		// THE CAPS THIS CASE STARTS WITH — and, because the change is refused,
		// the caps it must still have afterwards (`l4g`).
		//
		// ONE FIELD FOR BOTH, so neither can drift into being a second copy of
		// the other. The refusal is only half the guarantee: a guard that said
		// the right sentence and wrote the change anyway would leave the very
		// pair this check exists to prevent. Per case rather than hoisted, so a
		// row needing different numbers states them once and gets the fixture
		// and the assertion from the same field.
		fixture caps
	}{{
		// TIGHTENING, and the case from the box. It needs no code, and it is
		// refused anyway — correctly — so the message is the operator's only
		// signal about what to do next.
		name:    "lowering the 24-hour window below the standing per-payment cap",
		change:  guard.Change{Control: guard.ControlSpendCap, Msat: 40_000},
		want:    "a per-payment limit of 50 sats is above the 24-hour limit of 40 sats, so it could never be reached; lower the per-payment limit first",
		notWant: "24-hour limit first",
		fixture: caps{window: 100_000, payment: 50_000},
	}, {
		// LOOSENING, and the direction the old message was written for. It is
		// refused by the cap-pair check BEFORE the authorisation check, which is
		// why an empty code reaches this error rather than errAuthorisationRequired.
		name:    "raising the per-payment cap above the standing 24-hour window",
		change:  guard.Change{Control: guard.ControlPaymentCap, Msat: 150_000},
		want:    "a per-payment limit of 150 sats is above the 24-hour limit of 100 sats, so it could never be reached; raise the 24-hour limit first",
		notWant: "per-payment limit first",
		fixture: caps{window: 100_000, payment: 50_000},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			node := lndtest.Start(t)
			d := guardDirs(t, node)
			g := openGuardWithCaps(t, node, d, tc.fixture)

			err := g.ApplyChange(t.Context(), tc.change, "")
			if err == nil {
				t.Fatal("the cap pair was left inconsistent; the per-payment limit can now " +
					"never be reached, and the page states a number that means nothing")
			}
			got := err.Error()
			if !strings.Contains(got, tc.want) {
				t.Errorf("the refusal reads\n  %s\nwant it to contain\n  %s", got, tc.want)
			}
			if strings.Contains(got, tc.notWant) {
				t.Errorf("the refusal reads\n  %s\nand names %q — the control the operator is "+
					"already editing, which is the whole of 8vj", got, tc.notWant)
			}
			// BOTH CAPS, not only the one being edited: a refusal that moved the
			// OTHER control would leave exactly the inconsistent pair §6's outer
			// bound exists to forbid, and checking one number cannot see it.
			if stored := storedCaps(t, g); stored != tc.fixture {
				t.Errorf("the caps are %+v after a REFUSED change, want the fixture %+v "+
					"untouched; the guard said no and wrote anyway, so the per-payment limit "+
					"can never be reached and the page states a number that means nothing",
					stored, tc.fixture)
			}
		})
	}
}

// pou: a request that could never be applied is refused at the REQUEST, and
// costs nothing on the way.
//
// checkCapPair ran only in ApplyChange, which is the end of the ceremony. So
// raising the per-payment cap above the 24-hour limit issued a code, wrote the
// file an operator has to go and read, audited the request — and refused only
// when they came back and typed the code in. A whole ceremony spent on a change
// that could never be applied, with the ordering rule learned at the most
// expensive possible moment. 6zd names that order on the Sending page and in
// OPERATING.md; this is the half that stops the walk.
//
// THE THREE THINGS THAT MUST NOT HAPPEN are asserted separately, because each is
// a different cost to a different person: no code file (the operator is not sent
// to read one), no stored grant (nothing is outstanding to redeem or supersede),
// and no audit row (a refused request must not spend the ceremony's audit
// budget, or a caller who never holds a code can exhaust the trail).
func TestARequestThatCouldNeverBeAppliedIsRefusedBeforeAnyCodeExists(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardUnpermitted(t, node, d, caps{window: 100_000, payment: 50_000})

	// A LOOSENING, so it gets past the "does not need an authorisation" refusal
	// and would have been issued a code before pou.
	err := g.RequestAuthorisation(t.Context(),
		guard.Change{Control: guard.ControlPaymentCap, Msat: 150_000})

	if err == nil {
		t.Fatal("a per-payment cap above the 24-hour limit was granted a ceremony; it can " +
			"never be applied, so the operator would have fetched a code to be refused with it")
	}
	if !strings.Contains(err.Error(), "raise the 24-hour limit first") {
		t.Errorf("the refusal reads %q, want the guard's own remedy — the request and the "+
			"apply must say the same thing about the same pair", err)
	}
	if _, statErr := os.Stat(filepath.Join(d.data, "authorisation.txt")); statErr == nil {
		t.Error("an authorisation file was written for a change that can never be applied; " +
			"the operator is sent to read a code that buys them a refusal")
	}
	if status, statusErr := g.Status(t.Context()); statusErr != nil {
		t.Fatalf("Status: %v", statusErr)
	} else if !status.AuthorisationExpiresAt.IsZero() {
		t.Error("a grant is outstanding after a refused request; it would supersede a real " +
			"one and would be redeemable against a change the guard has already refused")
	}

	// AND NO AUDIT ROW, asserted directly rather than inferred from the absence
	// of a grant. Every response carries the guard's recent events back to the
	// server, so this is the same view the server gets. auditAuthorisation draws
	// on authoriseBudget on every call, and a bound that a REFUSED request can
	// spend is a bound a caller can exhaust without ever holding a code.
	resp := g.Handle(t.Context(), guard.Request{
		Op:     guard.OpRequestAuthorisation,
		Change: &guard.Change{Control: guard.ControlPaymentCap, Msat: 150_000},
	})
	for _, event := range resp.Events {
		if event.Event == logging.EventGuardAuthorise {
			t.Errorf("a refused request recorded %s (%v); the ceremony's audit budget must "+
				"not be spent by a change the guard refused before issuing anything",
				event.Event, event.Attrs)
		}
	}
	// ANTI-VACUITY: if the socket path stopped answering this operation at all,
	// the loop above would pass over an empty slice and assert nothing.
	if resp.Error == "" {
		t.Error("the socket path granted the request that the direct call refused; the two " +
			"must agree, or the server can obtain what the guard would not give")
	}
}

// And ApplyChange keeps its own check, which is not redundant.
//
// The state can move between the request and the redemption: a grant for a
// per-payment raise is outstanding, and the operator meanwhile lowers the
// 24-hour limit — a tightening, free and needing no code — so the pair is
// consistent when the code is issued and inconsistent when it is spent. Only the
// check at apply time can see that, which is why pou ADDS a check rather than
// moving one.
func TestAPairMadeInconsistentAfterTheRequestIsStillRefusedAtApply(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardUnpermitted(t, node, d, caps{window: 200_000, payment: 50_000})

	// Consistent at request time: 150k per-payment sits under the 200k window.
	raise := guard.Change{Control: guard.ControlPaymentCap, Msat: 150_000}
	if err := g.RequestAuthorisation(t.Context(), raise); err != nil {
		t.Fatalf("the request should have been issued; the pair is consistent: %v", err)
	}
	code := readAuthorisationCode(t, d)

	// Then the window comes down under it — a tightening, so no code needed.
	if err := g.ApplyChange(t.Context(),
		guard.Change{Control: guard.ControlSpendCap, Msat: 100_000}, ""); err != nil {
		t.Fatalf("lowering the window is a tightening and must be free: %v", err)
	}

	// The grant is still valid, the code is still right, and the change is now
	// unapplicable. This is the case the request-time check cannot see.
	err := g.ApplyChange(t.Context(), raise, code)
	if err == nil {
		t.Fatal("a stale grant applied a per-payment cap above the window; the pair is only " +
			"inconsistent at apply time, which is why both checks exist")
	}
	if !strings.Contains(err.Error(), "raise the 24-hour limit first") {
		t.Errorf("the refusal reads %q, want the cap-pair remedy", err)
	}
}

// The cap-pair refusal carries its KIND across the socket (`0vk.53`).
//
// 8vj's remedy is correct and reached only the log and the trail, because the
// wire carries a message and the server must not repeat a guard-authored one:
// every ApplyChange failure looked the same to the page, so a tightening refused
// by the cap-pair check was reported as a code that was not accepted. The kind
// is what lets the server tell them apart without ever rendering the guard's
// sentence — and it has to survive the socket, because in production the server
// never holds the guard's error, only a copy rebuilt from JSON.
//
// BOTH SIDES OF THE SEAM, and the direct call is not the interesting half: a
// kind that worked in-process and was dropped by the encoder would pass any test
// that called ApplyChange directly, and fail on every box.
//
// THE BAD CODE IS ASSERTED TOO, because a KindOf that returned cap_pair for
// everything would satisfy the first half and put the cap-pair message in front
// of an operator who really did mistype a code.
func TestTheCapPairRefusalCarriesItsKindOverTheSocket(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 50_000})
	ctx := t.Context()

	direct := g.ApplyChange(ctx, guard.Change{Control: guard.ControlSpendCap, Msat: 40_000}, "")
	if got := guard.KindOf(direct); got != guard.KindCapPair {
		t.Errorf("the guard's own error carries kind %q, want %q (%v)",
			got, guard.KindCapPair, direct)
	}

	client := serveGuard(t, g)
	relayed := client.ApplyChange(ctx, guard.Change{Control: guard.ControlSpendCap, Msat: 40_000}, "")
	if relayed == nil {
		t.Fatal("the cap pair was left inconsistent across the socket")
	}
	if got := guard.KindOf(relayed); got != guard.KindCapPair {
		t.Errorf("the relayed error carries kind %q, want %q; the page cannot tell this "+
			"refusal from a bad code, which is the whole of 0vk.53 (%v)",
			got, guard.KindCapPair, relayed)
	}
	// The text still crosses, because the LOG and the trail are where it belongs.
	if !strings.Contains(relayed.Error(), "lower the per-payment limit first") {
		t.Errorf("the relayed refusal reads %q; the guard's reason is what the operator's "+
			"support path reads out of docker logs", relayed)
	}

	// AND THE SECOND KIND OVER THE SAME SOCKET (`0vk.55`): a loosening that
	// arrives with nothing to redeem. 80k sats clears the 100k window and is
	// above the standing 50k per-payment cap, so it passes the cap pair, counts
	// as a loosening, and reaches redeem with no grant.
	//
	// ACROSS THE SOCKET RATHER THAN IN PROCESS, for the reason the cap pair is:
	// errAuthorisationRequired is a package-level *Refusal, so a direct call
	// returns the very pointer the guard holds and errors.As would find its kind
	// even if nothing were ever encoded. Only the relayed copy proves the wire.
	needsCode := client.ApplyChange(ctx,
		guard.Change{Control: guard.ControlPaymentCap, Msat: 80_000}, "")
	if needsCode == nil {
		t.Fatal("a loosening applied with no code and no grant")
	}
	if got := guard.KindOf(needsCode); got != guard.KindAuthorisationRequired {
		t.Errorf("the relayed refusal carries kind %q, want %q; the page cannot tell "+
			"'this needs a code' from 'that code was wrong' (%v)",
			got, guard.KindAuthorisationRequired, needsCode)
	}

	// A refusal with no kind stays kindless over the same socket.
	loosening := guard.Change{Control: guard.ControlPaymentCap, Msat: 80_000}
	if err := client.RequestAuthorisation(ctx, loosening); err != nil {
		t.Fatalf("requesting an authorisation for a legitimate loosening: %v", err)
	}
	badCode := client.ApplyChange(ctx, loosening, "000000")
	if badCode == nil {
		t.Fatal("a wrong code applied a loosening")
	}
	if got := guard.KindOf(badCode); got != "" {
		t.Errorf("a wrong code carries kind %q, want none; it is exactly the case the "+
			"ceremony's own message is written for", got)
	}
}

// An error kind this build does not know reads as NO kind.
//
// The forward-compatibility case, and the reason it is not merely tidy: a guard
// newer than the server can name a kind the server has no copy for. Passed
// through, that token reaches a map lookup, misses, and — before the fallback
// was written — would render a blank flash: a page that says nothing happened
// when something did. Read as no kind, it renders the generic refusal, which is
// what the server showed before this field existed.
//
// A HAND-WRITTEN SERVER, because no real guard can produce the token: this
// asserts what the CLIENT does with one, which is the half that has to hold when
// the two containers are different versions.
func TestAnUnknownErrorKindReadsAsNoKind(t *testing.T) {
	socket := socketPath(t)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = json.NewEncoder(conn).Encode(guard.Response{
				Error:     "guard: a refusal from a later build",
				ErrorKind: "invented_in_a_later_build",
			})
			_ = conn.Close()
		}
	}()

	client := guard.NewSocketClient(socket, guard.DiscardEvents)
	err = client.ApplyChange(t.Context(), guard.Change{Control: guard.ControlSpendCap}, "")
	if err == nil {
		t.Fatal("a refusal was read as a success")
	}
	if got := guard.KindOf(err); got != "" {
		t.Errorf("an unknown token was admitted as kind %q; it would pick no message and the "+
			"page would render a blank flash", got)
	}
}

// A grant nobody comes back for is swept, file and row together (`0vk.54`).
//
// Found on the 0.1.20-rc1 trip, finding D: an authorisation.txt written for a
// raise sat on disk after its expiry and across two container recreates. Inert —
// single-use, expired — but it made "is the file absent?" an ambiguous check,
// and the trip had to verify `pou` by mtime instead. An expired grant was
// discarded only inside redeem, so one nobody returned for was never cleared;
// Status hid it while the row and the file stayed.
//
// THE INVARIANT THE RULING ASKS FOR is that the file's presence means exactly
// "a live code exists". So both halves are asserted here: a sweep that removed
// the file and left the row would make Status and the disk disagree, which is a
// different defect wearing this one's fix.
//
// THE AUDIT ROW IS redeem's OWN VOCABULARY, "expired", deliberately. The trail
// already says that when a returning operator is refused; a grant that timed out
// unattended is the same fact observed by a different route, and a second word
// for it would make the trail's vocabulary depend on who happened to look.
func TestAGrantThatExpiresUnattendedIsSweptAway(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)}
	g := openGuardFull(t, node, d, guard.Options{Now: clock.Now}, serverAddr(), true)
	change := guard.Change{Control: guard.ControlSending, On: true}

	if err := g.RequestAuthorisation(t.Context(), change); err != nil {
		t.Fatal(err)
	}
	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !status.AuthorisationPending {
		t.Fatal("no grant is pending, so this test would sweep nothing and pass")
	}
	clock.now = status.AuthorisationExpiresAt

	// The Status call is the route this takes in production: runGuardEvents polls
	// the guard every five minutes and a page render asks at most every ten
	// seconds while somebody is looking, so nothing has to run on a timer of its
	// own. (The first version of this comment said "every few seconds", which was
	// wrong by two orders of magnitude — found by review.)
	events := g.Handle(t.Context(), guard.Request{Op: guard.OpStatus}).Events

	if _, err := os.Stat(filepath.Join(d.data, "authorisation.txt")); !os.IsNotExist(err) {
		t.Errorf("the code file outlived its grant (stat: %v); its presence is supposed to "+
			"mean a live code exists, and an operator checking for one cannot tell", err)
	}
	// THE ROW IS GONE, NOT MERELY HIDDEN BY THE CLOCK, and that is what the
	// rewind asks. Status masks an expired grant whether or not it was swept, so
	// asserting !AuthorisationPending at the expired time is satisfied by a sweep
	// that removed the FILE and left the row — which is the wrong-mechanism
	// outcome the ruling names, Status and the disk disagreeing. Winding the
	// clock back is the only question that separates them.
	clock.now = status.AuthorisationExpiresAt.Add(-time.Minute)
	after, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if after.AuthorisationPending {
		t.Error("the grant's row outlived its file: the guard reports a pending " +
			"authorisation whose code the operator cannot read, and the next request " +
			"would supersede something rather than start clean")
	}
	var outcomes []string
	for _, event := range events {
		if event.Event == logging.EventGuardAuthorise {
			outcomes = append(outcomes, event.Attrs["outcome"])
		}
	}
	// "expired", which is the word redeem writes for the same fact when a
	// returning operator hits it — asserted as the literal the trail carries, not
	// as a phrase this test composes.
	if !containsString(outcomes, "expired") {
		t.Errorf("the trail holds %v, missing the discard; §12 answers 'what happened to that "+
			"authorisation' and an unattended expiry is one of the answers", outcomes)
	}
}

// A LIVE grant survives a restart with its file intact (`0vk.54`).
//
// The other half of the ruling, and the one a careless sweep breaks: clearing an
// unexpired grant at start would cost the operator a whole ceremony on every
// container recreate — and umbrelOS recreates the container for a settings
// change. This is existing behaviour; it is pinned here because 0vk.54 adds the
// code that could take it away.
func TestALiveGrantSurvivesARestart(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	// A FIXED "now", not a testClock: nothing here advances time, and the whole
	// point is that a grant which has NOT expired survives.
	now := func() time.Time { return time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC) }
	g := openGuardFull(t, node, d, guard.Options{Now: now}, serverAddr(), true)
	change := guard.Change{Control: guard.ControlSending, On: true}
	if err := g.RequestAuthorisation(t.Context(), change); err != nil {
		t.Fatal(err)
	}
	code := readAuthorisationCode(t, d)

	// The restart: a second guard over the same volumes, which is what a
	// container recreate is.
	restarted := openGuardFull(t, node, d, guard.Options{Now: now}, serverAddr(), true)
	restarted.SweepExpiredAuthorisation(t.Context())

	if _, err := os.Stat(filepath.Join(d.data, "authorisation.txt")); err != nil {
		t.Fatalf("a live code file did not survive a restart: %v", err)
	}
	if err := restarted.ApplyChange(t.Context(), change, code); err != nil {
		t.Errorf("the code written before the restart no longer redeems: %v; the operator "+
			"paid for a ceremony the restart threw away", err)
	}
}

// An apply-time cap-pair refusal leaves the live grant alone (`0vk.54`).
//
// RULED (David, 8 Sep): consistent with the invariant, because the grant is
// still live — the operator may raise the 24-hour limit and redeem this same
// code within its TTL. It is the one path that reaches a refusal with a grant
// outstanding and must NOT sweep, which is why it is asserted rather than
// assumed: checkCapPair runs before redeem, so a sweep placed carelessly at the
// top of ApplyChange would take the grant with it.
func TestAnApplyTimeCapPairRefusalLeavesTheGrantAlone(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithCaps(t, node, d, caps{window: 100_000, payment: 50_000})
	// A legitimate loosening of the per-payment cap, granted a code.
	change := guard.Change{Control: guard.ControlPaymentCap, Msat: 80_000}
	if err := g.RequestAuthorisation(t.Context(), change); err != nil {
		t.Fatal(err)
	}
	code := readAuthorisationCode(t, d)
	// Now the 24-hour limit drops below it — a tightening, no ceremony — so the
	// outstanding change no longer passes the cap pair.
	if err := g.ApplyChange(t.Context(),
		guard.Change{Control: guard.ControlSpendCap, Msat: 60_000}, ""); err != nil {
		t.Fatal(err)
	}
	if err := g.ApplyChange(t.Context(), change, code); err == nil {
		t.Fatal("a per-payment cap above the 24-hour limit was applied")
	}

	if _, err := os.Stat(filepath.Join(d.data, "authorisation.txt")); err != nil {
		t.Errorf("the cap-pair refusal took the operator's live code with it: %v", err)
	}
	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !status.AuthorisationPending {
		t.Error("the grant is gone after a refusal that did not consume it; the operator " +
			"has to walk the whole ceremony again to make a change the guard would accept")
	}
}

// A sweep whose state write fails does not claim it discarded anything
// (`0vk.54`).
//
// discardAuthorisation raises its row whether or not the write succeeded, which
// is right for redeem — that is one operator action and it happened. The sweep
// runs on the POLLED path, so the same behaviour turns one unwritable state file
// into an attempt every five minutes, forever: auditAuthorisation draws on
// authoriseBudget BEFORE it writes, so each attempt spends one of the eight
// rows an hour that bound reserves for the events an operator actually needs.
// And the claim would be false — a grant the guard failed to clear is still in
// the state file and still redeemable.
//
// ASSERTED ON THE LOG, NOT THE TRAIL, and the first version of this test got
// that wrong: Guard.audit persists each event through g.state.update, which is
// the very write that has just failed, so the row never reaches
// Response.Events either way and the assertion passed against the defect. The
// log line is written before that, unconditionally, so it is the one place the
// two behaviours differ. Found by planting the defect and watching the test
// stay green.
func TestASweepThatCannotWriteClaimsNothing(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)}
	var logged bytes.Buffer
	g := openGuardFull(t, node, d, guard.Options{
		Now: clock.Now,
		Log: logging.New(&logged, logging.NewLevelVar(slog.LevelDebug)),
	}, serverAddr(), true)
	change := guard.Change{Control: guard.ControlSending, On: true}
	if err := g.RequestAuthorisation(t.Context(), change); err != nil {
		t.Fatal(err)
	}
	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !status.AuthorisationPending {
		t.Fatal("no grant is pending, so this test would sweep nothing and pass")
	}
	clock.now = status.AuthorisationExpiresAt
	logged.Reset()

	// The state file's DIRECTORY, made unwritable: stateStore.saveLocked writes
	// beside the state and renames, so this is what a read-only volume or a full
	// disk looks like from inside the guard.
	if err := os.Chmod(d.data, 0o500); err != nil {
		t.Fatal(err)
	}
	g.SweepExpiredAuthorisation(t.Context())
	if err := os.Chmod(d.data, 0o700); err != nil {
		t.Fatal(err)
	}

	// THE POSITIVE CONTROL, without which this proves nothing: if the write in
	// fact succeeded there was never a discard to suppress. The clock is wound
	// back because Status masks an expired grant whether or not it was swept.
	clock.now = status.AuthorisationExpiresAt.Add(-time.Minute)
	after, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !after.AuthorisationPending {
		t.Skip("the guard cleared the grant with its data directory at 0500, so this test " +
			"cannot create the failure it is about (running as root?)")
	}

	if !strings.Contains(logged.String(), "could not clear an expired authorisation") {
		t.Errorf("the sweep failed silently; the log has to say why a code file is still "+
			"there:\n%s", logged.String())
	}
	if strings.Contains(logged.String(), "an authorisation was discarded") {
		t.Errorf("a sweep that could not write said it discarded the grant. The grant is "+
			"still in the state file and still redeemable, so the claim is false — and on "+
			"the polled path it is one authoriseBudget slot every five minutes, spent on a "+
			"row that never lands:\n%s", logged.String())
	}
}
