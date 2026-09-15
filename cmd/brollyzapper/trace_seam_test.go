package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/preflight"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/wallet"
	"github.com/davotoula/brollyzapper/internal/web"
	"github.com/davotoula/brollyzapper/internal/zap"
)

// acceptingRelays stands in for the relays: every one takes the receipt. The
// relay leg's own records are internal/nostr's; this seam is about the three
// legs' lines.
type acceptingRelays struct{}

func (acceptingRelays) Publish(_ context.Context, _ gonostr.Event, extra ...string) []nostr.PublishResult {
	out := make([]nostr.PublishResult, 0, len(extra))
	for _, relay := range extra {
		out = append(out, nostr.PublishResult{Relay: relay})
	}
	return out
}

// o34.8, and d46.4's acceptance 7 at the seam rather than in the helpers: ONE
// GREP ON THE PAYMENT HASH RECONSTRUCTS ALL THREE LEGS of a zap — the LNURL
// callback, the settlement minutes later, and the receipt publish after that —
// with req_id on the HTTP leg, and the full hash nowhere.
//
// internal/logging's TestPaymentHashAndRequestIDCorrelateAcrossTheTracedPath
// writes its own lines and so proves the helpers. This drives the real
// components — the public server and its callback gate, the LNURL service, the
// invoice stream over gRPC, handleSettlement, the wallet, the receipt publisher —
// through one logger, as serve() wires them, with a fake node and fake relays.
// Here in package main because the settlement leg's line is handleSettlement's.
func TestOneGrepOnThePaymentHashReconstructsAllThreeLegs(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var logged syncBuffer
	log := logging.New(&logged, logging.NewLevelVar(slog.LevelDebug))
	quiet := quietLog()

	node := lndtest.Start(t)
	credentials := t.TempDir()
	node.WriteCredentialVolume(t, credentials, lnd.ReceiveMacaroon, []byte{0x01})
	// The node's client logs about the STREAM, not about any one payment, so it
	// is not on a leg and does not write to the captured log.
	client := lnd.New(node.Address(), lnd.VolumeCredentials(credentials, lnd.ReceiveMacaroon),
		lnd.Options{Log: quiet})
	defer client.Close()

	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()
	for key, value := range map[string]string{
		api.SettingAddressName: "bob",
		api.SettingDomain:      "zap.example",
	} {
		if err := db.SetSetting(ctx, key, value); err != nil {
			t.Fatalf("seeding %s: %v", key, err)
		}
	}
	if _, err := nostr.LoadOrCreate(ctx, db); err != nil {
		t.Fatalf("minting the nostr identity: %v", err)
	}
	purse := wallet.New(db, wallet.Options{Log: quiet})
	auditor := logging.NewAuditor(quiet, db)
	receipts := zap.New(db, nostr.NewSigner(db), acceptingRelays{}, auditor, time.Now, log)

	auth, err := api.NewAuth(ctx, db, api.AuthOptions{
		AdminPassword: secret.New("correct-horse-battery-staple"), PasswordManaged: true,
		SessionSecret: secret.New("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	renderer, err := web.New("test")
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	server, err := api.NewServer(api.ServerOptions{
		Auth: auth, Renderer: renderer, Wallet: purse, Auditor: auditor, Audit: db,
		Settings: db, AllSettings: db, Invoices: db, History: db,
		Level: logging.NewLevelVar(slog.LevelDebug), ProbeToken: "probe-token",
		Ready:     func() bool { return true },
		NodeState: client.State,
		Preflight: func(context.Context) preflight.Report { return preflight.Report{} },
		LNURL:     api.NewLNURLRoutes(lnurl.NewService(client, db, db, time.Now), log),
		Log:       log,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// --- leg 1: the LNURL callback ---------------------------------------------
	zapRequest := lnurltest.SignedZapRequest(t, nil)
	request := httptest.NewRequest(http.MethodGet,
		"/lnurlp/bob/callback?amount=21000&nostr="+url.QueryEscape(string(zapRequest)), nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"pr"`) {
		t.Fatalf("the callback did not mint: %d %s", response.Code, response.Body)
	}
	minted := node.MintedHashes()
	if len(minted) != 1 {
		t.Fatalf("the node minted %d invoices, want 1", len(minted))
	}
	hash := minted[0]
	httpLeg := logged.String()

	// --- legs 2 and 3: the settlement, then the receipt ---------------------------
	rHash, err := hex.DecodeString(hash)
	if err != nil {
		t.Fatal(err)
	}
	node.SetLedger(&lnrpc.Invoice{
		RHash: rHash, RPreimage: []byte("a preimage that is thirty-two b!"),
		State: lnrpc.Invoice_SETTLED, SettleIndex: 1, AmtPaidMsat: 21_000,
		SettleDate: time.Now().Unix(),
	})
	var legs sync.WaitGroup
	legs.Go(func() { receipts.RunRetry(ctx, nil) })
	legs.Go(func() { runInvoiceStream(ctx, client, db, purse, receipts, log) })
	// ON THE LAST STEP: the receipt's LINE, not its row. The publisher records
	// the receipt id before it logs, so waiting on the row and then reading the
	// log is a race — lost once under -race before this waited on the line.
	lndtest.WaitFor(t, "the receipt line to be logged", func() bool {
		return strings.Contains(logged.String(), `"msg":"zap receipt published"`)
	})
	// Joined before reading, so nothing on either leg writes after the snapshot
	// and neither goroutine outlives the client and store deferred above.
	cancel()
	legs.Wait()
	everything := logged.String()
	laterLegs := strings.TrimPrefix(everything, httpLeg)

	// --- the trace --------------------------------------------------------------
	want := logging.Short(hash)
	lines := func(chunk string) []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(chunk), "\n") {
			if line == "" {
				continue
			}
			// A line that is not JSON fails rather than dropping out of "every
			// line carries the hash".
			var record map[string]any
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatalf("a captured line is not JSON: %q", line)
			}
			out = append(out, record)
		}
		return out
	}
	// Anti-vacuity, per leg: a leg that logs nothing carries no hash and would
	// pass "every line carries it" by having no lines.
	for leg, msg := range map[string]string{
		"the settlement":      "invoice settled",
		"the receipt publish": "zap receipt published",
	} {
		if !strings.Contains(laterLegs, `"msg":"`+msg+`"`) {
			t.Errorf("%s leg logged no %q line; nothing on it can be found by the hash:\n%s",
				leg, msg, laterLegs)
		}
	}
	http := lines(httpLeg)
	if len(http) == 0 {
		t.Errorf("the LNURL callback leg logged nothing at all; a grep on the payment hash " +
			"cannot find the request that minted it")
	}
	// THE HTTP LEG IS JOINED BY req_id, and that is the design rather than a
	// concession. The gate's lines are written before an invoice exists — its
	// relay filtering, a rate limit — so no hash can be on them. The mint line
	// carries both, so a grep on the hash finds it and its req_id finds the rest
	// of that request.
	var requestID string
	var mintLine bool
	for _, record := range http {
		if record["payment_hash"] == want {
			mintLine = true
		} else if record["payment_hash"] != nil {
			t.Errorf("an HTTP-leg line carries another payment_hash: %v", record)
		}
		id, _ := record["req_id"].(string)
		if id == "" {
			t.Errorf("an HTTP-leg line carries no req_id: %v", record)
		}
		if requestID != "" && id != requestID {
			t.Errorf("one request logged under two req_ids, %q and %q", requestID, id)
		}
		requestID = id
	}
	if !mintLine {
		t.Errorf("no HTTP-leg line carries payment_hash=%s; a grep on the hash cannot find the "+
			"request that minted it:\n%s", want, httpLeg)
	}
	legOf := map[string]string{"invoice settled": "settlement", "zap receipt published": "receipt publish"}
	for _, record := range lines(laterLegs) {
		if record["payment_hash"] != want {
			leg := legOf[record["msg"].(string)]
			if leg == "" {
				leg = "settlement or receipt publish"
			}
			t.Errorf("the %s leg's line %q does not carry payment_hash=%s: %v", leg, record["msg"], want, record)
		}
	}
	if strings.Contains(everything, hash) {
		t.Errorf("the full payment hash reached the log; §12 truncates it:\n%s", everything)
	}
	t.Logf("the trace:\n%s", everything)
}
