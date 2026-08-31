package guard_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// tna.4: the guard does not mint spend authority on its own say-so.
//
// Before this, `dispatch` mapped OpBakeSpend → BakeSpend → bake with NO gate of
// any kind. The only refusal in the path was wouldNotRepeatItself, which returns
// nil whenever nothing has been baked — so on a receive-only install it could
// never refuse. The whole of the access control was the socket's 0600 mode, and
// the server runs as the same uid: code execution in the server meant writing
// `{"op":"bake_spend"}` to the socket, reading the macaroon the guard wrote, and
// opening a gRPC connection to LND with spend authority.
//
// THE ASSERTION IS ABOUT THE NODE, not about the error. A refusal that returned
// an error after asking LND to bake would have left a spend-capable root key on
// the operator's node, which is most of the damage.
func TestBakeSpendIsRefusedWhenTheGuardDoesNotPermitSending(t *testing.T) {
	node := lndtest.Start(t)
	g, credentials := newGuardWithoutSending(t, node)

	err := g.BakeSpend(t.Context())

	if err == nil {
		t.Fatal("BakeSpend succeeded with GUARD_ALLOW_SENDING unset; a compromised server can " +
			"mint itself spend authority through the socket")
	}
	if got := len(node.BakeRequests()); got != 0 {
		t.Errorf("the node saw %d bake requests; the refusal must happen BEFORE the node is "+
			"asked, or a spend-capable root key exists on the operator's node either way", got)
	}
	if _, err := os.Stat(filepath.Join(credentials, lnd.SpendMacaroon)); !os.IsNotExist(err) {
		t.Errorf("spend.macaroon exists after a refused bake (stat: %v)", err)
	}
}

// The same refusal on the renewal path, which is the other way a bake happens.
//
// A gate on the socket alone would be a gate on the door with the window open:
// EnsureSpendMacaroon bakes on a schedule whenever the guard's own state says
// sending is enabled, and that state survives the operator turning the gate off
// and restarting.
func TestTheRenewalTickDoesNotBakeWhenTheDeploymentCeilingIsOff(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)

	// Sending was enabled while the gate allowed it.
	permitted := openGuardWithSending(t, node, d, true)
	if err := permitted.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend with the gate on: %v", err)
	}
	baked := len(node.BakeRequests())

	// The DEPLOYMENT turns its ceiling off and the container restarts. The
	// guard's state still says sending is on — that is exactly the case Ruling
	// A.4 is about, since an Umbrel update restarts containers too.
	refused := openGuardWithDeploymentCeiling(t, node, d, false)
	// And the credential is gone from disk, so the renewal path has every reason
	// to bake: "there is none" is the strongest of them.
	if err := os.Remove(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Fatal(err)
	}

	if err := refused.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureSpendMacaroon returned an error rather than declining quietly: %v", err)
	}

	if got := len(node.BakeRequests()); got != baked {
		t.Errorf("the renewal tick baked %d more times with the gate off; the socket is not the "+
			"only way a spend macaroon gets minted", got-baked)
	}
}

// The same rule on the OTHER half of the gate (`06v`): the operator's latch.
//
// The two halves are ANDed and either one alone must stop the renewal loop, so
// each needs its own test — a conjunction tested on one arm is a conjunction
// half of which has never been exercised. This arm is the one an operator
// reaches: they turn sending off, and the loop must not put the credential back
// on the next tick.
//
// The latch here is dropped through ApplyChange — a TIGHTENING, so it needs no
// code, which is Ruling 1's whole point — rather than through RevokeSpend, so
// that the state under test is the awkward one: the guard still holds a root key
// id and a live credential, and only the operator's intent has changed.
func TestTheRenewalTickDoesNotBakeWhenTheOperatorLatchIsOff(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithSending(t, node, d, true)
	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend with sending permitted: %v", err)
	}
	baked := len(node.BakeRequests())

	// No code: turning sending OFF is a tightening, and ceremony on the safe
	// direction would cost the operator and buy nothing.
	if err := g.ApplyChange(t.Context(),
		guard.Change{Control: guard.ControlSending, On: false}, ""); err != nil {
		t.Fatalf("turning sending off needed something: %v", err)
	}
	if err := os.Remove(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Fatal(err)
	}

	if err := g.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureSpendMacaroon returned an error rather than declining quietly: %v", err)
	}
	if got := len(node.BakeRequests()); got != baked {
		t.Errorf("the renewal tick baked %d more times after the operator turned sending off; "+
			"'Disable sending' would mean 'disable sending for up to an hour'", got-baked)
	}
}

// With the gate on, both paths work exactly as they did.
//
// A test that only proves refusal cannot tell a gate from a broken bake path,
// and "sending no longer works at all" would pass it.
func TestWithTheGateOnSpendingIsBakedAsBefore(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithSending(t, node, d, true)

	if err := g.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend with the gate on: %v", err)
	}
	if got := len(node.BakeRequests()); got != 1 {
		t.Fatalf("the node saw %d bakes, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Errorf("no spend.macaroon after a permitted bake: %v", err)
	}

	// And the renewal path keeps it alive rather than refusing.
	if err := os.Remove(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Fatal(err)
	}
	if err := g.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureSpendMacaroon with the gate on: %v", err)
	}
	if got := len(node.BakeRequests()); got != 2 {
		t.Errorf("the node saw %d bakes after a renewal, want 2 — the gate being ON must leave "+
			"the path exactly as it was", got)
	}
}

// The refusal reaches §12's durable trail, not only the guard's stdout.
//
// Through the guard's auditor, which is the one that relays to the server —
// §16 gives the guard no mount for the database. Asserted as a RELAYED EVENT
// rather than as a log line: the Auditor went uncalled for three waves in this
// repository while every component's tests passed.
func TestARefusedBakeSpendIsAudited(t *testing.T) {
	node := lndtest.Start(t)
	g, _ := newGuardWithoutSending(t, node)

	_ = g.BakeSpend(t.Context())

	events := g.Handle(t.Context(), guard.Request{Op: guard.OpStatus}).Events
	var rejects []logging.RelayedEvent
	for _, event := range events {
		if event.Event == logging.EventGuardReject {
			rejects = append(rejects, event)
		}
	}
	if len(rejects) != 1 {
		t.Fatalf("%d guard.reject events after a refused bake, want 1; the operator's only "+
			"record of an attempt to mint spend authority is this row", len(rejects))
	}
	if rejects[0].Attrs["op"] != string(guard.OpBakeSpend) {
		t.Errorf("the event names op %q, want %q — a trail that does not say WHAT was refused "+
			"cannot answer what was attempted", rejects[0].Attrs["op"], guard.OpBakeSpend)
	}
	// And the remedy, in the row itself. The operator reading this is being told
	// their app refused something they may have asked for, and a row that does
	// not say what to change leaves them with a mystery.
	//
	// THE REMEDY IS THE IN-APP ONE HERE, because this install's refusal is the
	// operator's own latch (`06v`). Naming GUARD_ALLOW_SENDING would send them
	// to a variable that is fine, and — since `06v` — one they cannot reach.
	remedy := rejects[0].Attrs["remedy"]
	if !strings.Contains(remedy, "Sending page") {
		t.Errorf("the event's remedy is %q; it does not name the in-app action that would "+
			"change it", remedy)
	}
	if strings.Contains(remedy, "GUARD_ALLOW_SENDING") {
		t.Errorf("the event's remedy is %q; it points at an environment variable that is not "+
			"the cause, and that `06v` established the operator cannot reach anyway", remedy)
	}
}

// The OTHER refusal, and it must not share the first one's wording (`06v`).
//
// The same rule tna.4 set for the Sending page's two off-states, one layer down
// and in the durable trail. One refusal is fixable by the operator in the app;
// the other is not fixable in the app at all. A row that told an operator on a
// GUARD_ALLOW_SENDING=false deployment to "enable sending on the Sending page"
// would send them round a loop that cannot terminate, which is how they learn
// the app is broken rather than that it is locked.
func TestTheDeploymentCeilingRefusalNamesTheVariableAndNotTheCeremony(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardWithDeploymentCeiling(t, node, d, false)

	err := g.BakeSpend(t.Context())
	if err == nil {
		t.Fatal("BakeSpend succeeded with GUARD_ALLOW_SENDING=false")
	}
	if !strings.Contains(err.Error(), "GUARD_ALLOW_SENDING") {
		t.Errorf("the refusal says %q; it does not name the one thing that would change it", err)
	}
	if strings.Contains(err.Error(), "Sending page") {
		t.Errorf("the refusal says %q; it offers an in-app remedy for a ceiling no in-app "+
			"action can lift", err)
	}

	events := g.Handle(t.Context(), guard.Request{Op: guard.OpStatus}).Events
	var remedy string
	for _, event := range events {
		if event.Event == logging.EventGuardReject {
			remedy = event.Attrs["remedy"]
		}
	}
	if !strings.Contains(remedy, "GUARD_ALLOW_SENDING") {
		t.Errorf("the trail's remedy is %q; it does not name the variable", remedy)
	}
}

// The gate being off does NOT revoke a credential that already exists.
//
// Ruling A.4, and the reasoning is the whole of it: an Umbrel update restarts
// containers, so "started with the gate off" is not a reliable signal of operator
// intent, and a destructive action on an ambiguous signal is worse than a
// residual stated out loud. The residual is bounded — renewal stops, so the
// credential dies within CredentialLifetime — and an operator who wants it gone
// now has Disable, which revokes.
func TestTurningTheGateOffDoesNotRevokeWhatIsAlreadyMinted(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	permitted := openGuardWithSending(t, node, d, true)
	if err := permitted.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}

	// A restart with the DEPLOYMENT CEILING off, and the renewal path running as
	// it would. It is the ceiling rather than the latch because the latch cannot
	// be turned off by a restart at all — it is stored state — so the ceiling is
	// the only half of the gate that can change under a running install without
	// the operator having acted in the app (`06v`).
	refused := openGuardWithDeploymentCeiling(t, node, d, false)
	if err := refused.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureSpendMacaroon: %v", err)
	}

	if _, err := os.Stat(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Errorf("the existing spend.macaroon was removed when the gate turned off: %v", err)
	}
	if got := len(node.DeletedRootKeyIDs()); got != 0 {
		t.Errorf("%d root keys were revoked on finding the gate off; a container restart is not "+
			"an operator decision, and this one is destructive", got)
	}
	status, err := refused.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !status.SpendMacaroonPresent || !status.SpendRootKeyListed {
		t.Errorf("the credential no longer reads as live: %+v — the page has to be able to "+
			"state the residual, which means the residual has to still be true", status)
	}
}

// The gate travels the socket, which is the whole reason the server reads it
// from Status rather than from its own environment.
//
// THIS TEST EXISTS BECAUSE THE PAGE TESTS COULD NOT SEE IT. They set the field
// on the broker fake, so deleting the line that fills it in Status left every one
// of them green — the page was asserted to render what it was handed, and nothing
// asserted it was handed the truth. Two well-tested sides with an untested wire
// between them (§13), in the one place where a disagreement means offering an
// operator a button the guard will refuse.
func TestTheGateReachesTheServerOverTheSocket(t *testing.T) {
	for _, permitted := range []bool{true, false} {
		t.Run(map[bool]string{true: "permitted", false: "refused"}[permitted], func(t *testing.T) {
			node := lndtest.Start(t)
			d := guardDirs(t, node)
			client := serveGuard(t, openGuardWithSending(t, node, d, permitted))

			status, err := client.Status(t.Context())
			if err != nil {
				t.Fatalf("Status over the socket: %v", err)
			}
			if status.SendingPermitted != permitted {
				t.Errorf("the server was told SendingPermitted=%v, want %v — the page renders "+
					"what this says, and only the guard knows what the guard will do",
					status.SendingPermitted, permitted)
			}
			// And the two HALVES, because the page has to explain a no and the
			// two explanations have different remedies (`06v`). The deployment
			// ceiling is on in both arms here; what differs is the latch.
			if !status.SendingAllowedByDeployment {
				t.Error("the server was told the deployment forbids sending; it does not, and " +
					"the page would offer a remedy no in-app action can reach")
			}
			if status.SendingLatched != permitted {
				t.Errorf("the server was told SendingLatched=%v, want %v",
					status.SendingLatched, permitted)
			}
		})
	}
}

// And the socket path itself refuses, end to end.
//
// BakeSpend is tested directly above; this is the wire — the dispatch switch is
// what a compromised server actually reaches, and a gate applied to the method
// but not reachable through the socket would be a gate on nothing.
func TestTheSocketRefusesToBakeSpendWhenSendingIsNotPermitted(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	client := serveGuard(t, openGuardWithSending(t, node, d, false))

	err := client.RequestSpendBake(t.Context())

	if err == nil {
		t.Fatal("a spend bake over the socket succeeded on an install that does not permit " +
			"sending; this is the path a compromised server has")
	}
	// The refusal names what would change it, because the operator seeing it may
	// be the one who wants to change it — and since `06v` that is the in-app
	// ceremony rather than an environment variable they cannot reach.
	if !strings.Contains(err.Error(), "Sending page") {
		t.Errorf("the refusal says %q; it has to name the action that would change it", err)
	}
	if got := len(node.BakeRequests()); got != 0 {
		t.Errorf("the node saw %d bake requests over the socket path", got)
	}
}
