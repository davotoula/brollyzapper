package main

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
)

// `20i.21`: the Node page's server line goes through the SERVER's credential —
// the RECEIVE one — and mints nothing.
//
// HOW "THROUGH THE RECEIVE CLIENT" IS ASSERTED. The server holds two clients over
// two macaroons (d24.2), and the wiring is a closure in serve() that no unit test
// reaches. So this runs the real serve() against a fake node that records every
// macaroon presented to it, with BOTH credentials on disk and distinguishable,
// and asserts the spend macaroon's bytes never reach the node while the page
// comes to say "yes". Wiring the probe to spendNode instead makes the node see
// the spend macaroon, and this goes red. A type cannot say it: both clients are
// *lnd.Client.
//
// AND IT MINTS NOTHING: no AddInvoice reaches the node. GetInfo is in
// ReceivePermissions and is read-only.
func TestTheServerCredentialLineUsesTheReceiveCredentialAndMintsNothing(t *testing.T) {
	node := lndtest.Start(t)
	const password = "correct-horse-battery-staple"
	environ := validEnv(t)
	environ["LND_ADDRESS"] = node.Address()
	environ["ADMIN_PASSWORD"] = password
	environ["SESSION_SECRET"] = "0123456789abcdef0123456789abcdef"

	receive := lndtest.Macaroon(t)
	// A caveat only so the two serialise differently: the fake node honours it
	// like any other, so a probe wired to the spend client would SUCCEED — the
	// assertion is on what was presented, not on whether it worked.
	spend := lndtest.Macaroon(t, "time-before 2099-01-01T00:00:00Z")
	node.WriteCredentialVolume(t, environ["CREDENTIALS_DIR"], lnd.ReceiveMacaroon, receive)
	lndtest.WriteFile(t, filepath.Join(environ["CREDENTIALS_DIR"], lnd.SpendMacaroon), spend)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var stdout, stderr syncBuffer
	exit := make(chan int, 1)
	go func() { exit <- run(ctx, nil, env(environ), &stdout, &stderr) }()

	base := "http://" + environ["LISTEN_ADDR"]
	client := newBrowser(t)
	waitForHTTP(t, client, base+"/health")
	signIn(t, client, base, password)

	// The first render starts the probe; a later one reads its answer.
	lndtest.WaitFor(t, "the Node page to report the server's own credential working", func() bool {
		return strings.Contains(fetch(t, client, base+"/node"),
			"<dt>LND reachable from the server</dt><dd>yes, as of")
	})

	spendHex := hex.EncodeToString(spend)
	if slices.Contains(node.SeenMacaroons(), spendHex) {
		t.Error("the spend macaroon reached the node; the server-credential line must go through " +
			"the receive client, which can never spend")
	}
	if !slices.Contains(node.SeenMacaroons(), hex.EncodeToString(receive)) {
		t.Error("the receive macaroon never reached the node, so nothing here observed a probe")
	}
	if minted := node.InvoiceRequests(); len(minted) != 0 {
		t.Errorf("the probe minted %d invoice(s); it must be read-only", len(minted))
	}

	cancel()
	select {
	case <-exit:
	case <-time.After(30 * time.Second):
		t.Fatal("the server did not shut down when its context ended")
	}
}
