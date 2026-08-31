package guard_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
)

// `06v`, Migration: AN INSTALL THAT WAS ALREADY SENDING KEEPS SENDING.
//
// THE FAILURE THIS PREVENTS IS AN OUTAGE THIS CHANGE WOULD HAVE CAUSED. Before
// `06v` the operator's intent lived in GUARD_ALLOW_SENDING and nothing else; the
// latch is new, and a new bool defaults to false. An upgrade would therefore
// have found every working wallet's latch off, declined to renew, and taken the
// credential away within CredentialLifetime — silently, on a box whose operator
// changed nothing.
//
// The evidence is a FACT ABOUT THE INSTALL, not a guess: a recorded
// SpendRootKeyID or a spend macaroon on disk means a bake happened, and a bake
// only happens when an operator asked for one. The converse risk is nil — an
// install with a live spend credential has already granted a compromised server
// everything the latch could withhold, because the credential is readable from
// the server's own mount.
func TestAnUpgradeKeepsSendingOnForAnInstallThatWasAlreadySending(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)

	// The install as 0.1.12 left it: sending enabled, credential on disk, and a
	// state file that has never heard of a latch.
	before := openGuardWithSending(t, node, d, true)
	if err := before.BakeSpend(t.Context()); err != nil {
		t.Fatalf("BakeSpend: %v", err)
	}
	stripOperatorIntent(t, d)

	// The upgrade: a new guard over the same volumes.
	after := openGuardWithDeploymentCeiling(t, node, d, true)

	status, err := after.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !status.SendingLatched {
		t.Fatal("the upgrade found a working wallet and turned its latch off. Renewal stops, " +
			"the credential dies within CredentialLifetime, and the operator changed nothing")
	}
	// And the renewal path agrees, which is the half that actually keeps the
	// wallet alive. Asserted through the node, not through the status: the
	// status is what the page shows and the bake is what the wallet needs.
	if err := os.Remove(filepath.Join(d.credentials, lnd.SpendMacaroon)); err != nil {
		t.Fatal(err)
	}
	baked := len(node.BakeRequests())
	if err := after.EnsureSpendMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureSpendMacaroon after the upgrade: %v", err)
	}
	if len(node.BakeRequests()) == baked {
		t.Error("the renewal tick declined to re-bake after the upgrade; the operator's " +
			"wallet stops working for a reason nothing on the box explains")
	}
}

// And the other arm: an install that was NOT sending stays receive-only.
//
// §6's default survives the flip of GUARD_ALLOW_SENDING to true. The env var
// stopped being the operator's gate; the latch became it, and a migration that
// seeded it on for everyone would have handed every receive-only install the
// property `06v` says is the gate's entire remaining value.
func TestAnUpgradeLeavesAReceiveOnlyInstallReceiveOnly(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	// A 0.1.12 install that never enabled sending: a receive credential and
	// nothing else.
	before := openGuardWithDeploymentCeiling(t, node, d, true)
	if err := before.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}
	stripOperatorIntent(t, d)

	after := openGuardWithDeploymentCeiling(t, node, d, true)

	status, err := after.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.SendingLatched || status.SendingPermitted {
		t.Error("the upgrade permitted sending on an install that had never enabled it; the " +
			"one property a receive-only install has is that there is no spend.macaroon to steal")
	}
	if err := after.BakeSpend(t.Context()); err == nil {
		t.Error("a spend bake succeeded straight after the upgrade with no ceremony")
	}
}

// The caps seed from the environment, and only once.
//
// IDEMPOTENT AND RESTART-SAFE are §19's words, and the second is what this
// half is about: an operator who lowers a cap must not find the package's
// default back after a restart. The seed is a MIGRATION, not a default applied
// on every load, and the difference is invisible until someone restarts.
func TestTheCapsSeedFromTheEnvironmentOnceAndThenBelongToTheOperator(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	limits := caps{window: 100_000, payment: 50_000}
	first := openGuardUnpermitted(t, node, d, limits)

	if got := spendLimit(t, first); got != limits.window {
		t.Fatalf("a fresh install's window cap is %d msat, want the configured %d",
			got, limits.window)
	}
	if err := first.ApplyChange(t.Context(),
		guard.Change{Control: guard.ControlSpendCap, Msat: 60_000}, ""); err != nil {
		t.Fatalf("lowering the window cap: %v", err)
	}

	// A restart with the SAME environment. The package still says 100k.
	second := openGuardUnpermitted(t, node, d, limits)

	if got := spendLimit(t, second); got != 60_000 {
		t.Errorf("the window cap is %d msat after a restart, want the operator's 60000. The "+
			"package's default came back, and the operator's lowering was undone by something "+
			"they did not do", got)
	}
}

// A fresh install gets the configured caps rather than zero, and zero MEANS
// zero.
//
// This arm is not a formality. Zero is not "no cap" — InterceptRequest refuses
// everything at zero, deliberately, because an operator who types 0 into a
// setting called "maximum spend" means "do not spend". So a state store that
// returned the bare zero value for an install with no file yet would hand every
// new install a cap of zero: sending enabled, every payment refused, and the
// number on the page contradicting the manifest.
func TestAFreshInstallGetsTheConfiguredCapsAndNotZero(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardUnpermitted(t, node, d, caps{window: 100_000, payment: 50_000})

	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.SpendLimitMsat != 100_000 || status.MaxPaymentMsat != 50_000 {
		t.Errorf("a fresh install reports caps %d/%d msat, want 100000/50000",
			status.SpendLimitMsat, status.MaxPaymentMsat)
	}
}

// stripOperatorIntent removes the operator-intent fields from a stored state,
// which is what an install upgrading from ≤0.1.12 actually has.
//
// It edits the JSON rather than constructing a State, because a State built in
// Go would carry whatever fields the CURRENT type has — including the seed
// marker — and the thing under test is precisely a file written by a version
// that had none. Constructing one would test the migration against its own
// output.
func stripOperatorIntent(t *testing.T, d dirs) {
	t.Helper()
	path := filepath.Join(d.data, "guard-state.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the state to age it: %v", err)
	}
	var fields map[string]any
	// UseNumber, and it is not a nicety: root key ids are uint64 and the ones
	// LND mints are routinely above 2^53. Decoding into `any` gives float64,
	// which silently rounds them — the aged file then names a key the node has
	// never heard of, the guard reads that as an external revocation, and this
	// test would report a migration failure it invented itself. Cost one debug
	// round.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&fields); err != nil {
		t.Fatalf("parsing the state to age it: %v", err)
	}
	for _, key := range []string{
		"sending_latch", "max_spend_msat", "max_payment_msat", "operator_intent_seeded",
	} {
		delete(fields, key)
	}
	aged, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, aged, 0o600); err != nil {
		t.Fatal(err)
	}
}
