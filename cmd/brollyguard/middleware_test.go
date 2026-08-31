package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

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
