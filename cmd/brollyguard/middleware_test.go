package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
)

// tna.1 at the COMPOSITION POINT: the binary actually registers the middleware.
//
// THIS TEST EXISTS BECAUSE THE WHOLE FEATURE COULD BE UNWIRED AND THE GATE STAYED
// GREEN. Deleting both new blocks from run() — the startup EnsureSpendMacaroon
// call and the RunMiddleware goroutine — left `go test ./...` at exit 0. Every
// piece was tested; nothing tested that they were connected. In the shipped
// binary the middleware would never register, LND would reject every spend RPC
// carrying the caveat, and sending would be dead on arrival.
func TestTheBinaryRegistersTheMiddlewareWithTheNode(t *testing.T) {
	node := lndtest.Start(t)
	e := nodeEnv(t, node)
	var stdout, stderr bytes.Buffer

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() { done <- run(ctx, nil, env(e), &stdout, &stderr) }()

	lndtest.WaitFor(t, "the guard to register as a middleware", func() bool {
		return len(node.MiddlewareRegistrations()) > 0
	})
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("run = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if got := node.MiddlewareRegistrations()[0].GetCustomMacaroonCaveatName(); got != lnd.GuardCaveatName {
		t.Errorf("registered for caveat %q, want %q", got, lnd.GuardCaveatName)
	}
}

// And it settles the spend credential at startup, not only on the renewal tick.
//
// §14 says a spend macaroon baked without P4's caveat is dealt with "at the
// first start after the upgrade". Waiting for the tick would leave an upgraded
// install spending uncapped for up to an hour. With the gate off — the default,
// and what an upgraded install has — the credential cannot be re-baked, so
// Ruling 1 revokes it.
func TestTheBinarySettlesAnUncappableSpendCredentialAtStartup(t *testing.T) {
	node := lndtest.Start(t)
	e := nodeEnv(t, node)
	spend := filepath.Join(e["CREDENTIALS_DIR"], lnd.SpendMacaroon)
	// A pre-P4 credential: hardened, and carrying no guard caveat.
	if err := os.WriteFile(spend, lndtest.Macaroon(t,
		lnd.CaveatIPAddr+" 10.21.0.17", lnd.CaveatTimeBefore+" 2033-01-01T00:00:00Z"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run(serveCtx(t), nil, env(e), &stdout, &stderr); code != 0 {
		t.Fatalf("run = %d, want 0 (stderr: %s)", code, stderr.String())
	}

	if _, err := os.Stat(spend); !os.IsNotExist(err) {
		t.Errorf("an uncappable spend macaroon survived startup (stat: %v); LND honours it "+
			"without consulting the guard, so the hard cap does not apply to it", err)
	}
}

// nodeEnv is validEnv pointed at a real node, with the operator factor on.
func nodeEnv(t *testing.T, node *lndtest.Node) map[string]string {
	t.Helper()
	e := validEnv(t)
	mounts := t.TempDir()
	certPath := filepath.Join(mounts, "tls.cert")
	macaroonPath := filepath.Join(mounts, "admin.macaroon")
	node.WriteMounts(t, certPath, macaroonPath)
	e["LND_ADDRESS"] = node.Address()
	e["LND_CERT_FILE"] = certPath
	e["LND_ADMIN_MACAROON"] = macaroonPath
	e["GUARD_ALLOW_SENDING"] = "false"
	return e
}

// `0vk.54` at the COMPOSITION POINT: the binary sweeps a grant that timed out
// while the container was down.
//
// THE SAME ARGUMENT AS THE MIDDLEWARE TEST ABOVE, and it is why this is a binary
// test rather than a guard one. The polled Status sweeps an expired grant during
// normal operation, so every test in internal/guard passes with the start-up
// call deleted — and the case start-up exists for is exactly the one Status
// cannot reach: an install whose server never comes up leaves authorisation.txt
// on disk indefinitely, which is how the 0.1.20-rc1 trip found one that had
// survived two container recreates.
//
// THE GRANT IS AGED BY MOVING THE GUARD'S CLOCK, not by editing the state file:
// a harness that wrote that JSON would hold a second copy of the state format,
// and the ceremony it drives here is the operator's real one.
func TestTheBinarySweepsAnExpiredAuthorisationAtStartup(t *testing.T) {
	node := lndtest.Start(t)
	e := nodeEnv(t, node)
	cfg, err := config.LoadGuard(env(e))
	if err != nil {
		t.Fatal(err)
	}
	// A guard whose "now" is years ago, over the volumes the binary will open.
	// Its grant is therefore long expired by the time the binary — which uses
	// real time — reads the same state.
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	aged, err := guard.New(cfg, guard.Options{Now: func() time.Time { return past }})
	if err != nil {
		t.Fatal(err)
	}
	// A loosening: the 24-hour limit above the value the environment seeded.
	change := guard.Change{Control: guard.ControlSpendCap, Msat: cfg.MaxSpendMsat * 2}
	if err := aged.RequestAuthorisation(t.Context(), change); err != nil {
		t.Fatal(err)
	}
	if err := aged.Close(); err != nil {
		t.Fatal(err)
	}
	// guard.AuthorisationFile, not the literal: its own doc says it was exported
	// because the name had been re-typed at four sites and a rename would have
	// compiled cleanly and failed at regtest runtime.
	codeFile := filepath.Join(cfg.DataDir, guard.AuthorisationFile)
	if _, err := os.Stat(codeFile); err != nil {
		t.Fatalf("the ceremony wrote no code file, so this test would sweep nothing: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := run(serveCtx(t), nil, env(e), &stdout, &stderr); code != 0 {
		t.Fatalf("run = %d, want 0 (stderr: %s)", code, stderr.String())
	}

	if _, err := os.Stat(codeFile); !os.IsNotExist(err) {
		t.Errorf("an expired code file survived startup (stat: %v); its presence is supposed "+
			"to mean a live code exists, and an operator checking for one cannot tell", err)
	}
}
