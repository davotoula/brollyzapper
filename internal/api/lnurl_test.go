package api_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/store"
)

// lnurlHarness stands the public endpoints up over a real store and a real
// (fake) LND, the way cmd wires them.
type lnurlHarness struct {
	*harness
	node *lndtest.Node
	// client is the REAL lnd.Client the endpoints mint through, so a test can
	// assert the state a stranger's request left it in.
	client *lnd.Client
}

func newLNURLHarness(t *testing.T, overrides ...func(*api.ServerOptions, *store.Store)) *lnurlHarness {
	t.Helper()
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, []byte{0x01})

	out := &lnurlHarness{node: node}
	out.harness = newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		out.client = lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon),
			lnd.Options{Broker: opts.Broker, MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond})
		client := out.client
		t.Cleanup(func() { _ = client.Close() })
		for key, value := range map[string]string{
			api.SettingAddressName: "bob",
			api.SettingDomain:      "zap.example",
			api.SettingNostrPubkey: strings.Repeat("a", 64),
		} {
			if err := db.SetSetting(t.Context(), key, value); err != nil {
				t.Fatalf("seeding %s: %v", key, err)
			}
		}
		for _, override := range overrides {
			override(opts, db)
		}
		// AFTER the overrides, and that ordering is the point: the routes take
		// the SERVER's logger rather than a discarded one of their own, and a
		// test that wants to read those lines sets opts.Log. `q22` put three
		// lines on this path, and a harness that silently discards half the
		// application's output is a harness that hides exactly this kind of
		// hole. With no override it is the same io.Discard every other test gets.
		routeLog := opts.Log
		if routeLog == nil {
			routeLog = logging.New(io.Discard, logging.NewLevelVar(slog.LevelDebug))
		}
		opts.LNURL = api.NewLNURLRoutes(
			lnurl.NewService(client, db, db, func() time.Time { return authTime }),
			routeLog)
	})
	return out
}

// §7 criterion 3: the document a wallet reads, including the nostr fields
// o34.1 made real.
func TestTheLNURLPayRequestMatchesTheSpecDocument(t *testing.T) {
	h := newLNURLHarness(t)

	rec := h.get(t, "/.well-known/lnurlp/bob", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET the address = %d %q", rec.Code, rec.Body)
	}
	var got lnurl.PayResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("the response is not JSON: %v (%s)", err, rec.Body)
	}
	if got.Tag != "payRequest" {
		t.Errorf("tag = %q, want payRequest", got.Tag)
	}
	if got.Callback != "https://zap.example/lnurlp/bob/callback" {
		t.Errorf("callback = %q", got.Callback)
	}
	if got.Metadata != lnurl.Metadata("bob", "zap.example") {
		t.Errorf("metadata = %q, want the string description_hash is built from", got.Metadata)
	}
	if !got.AllowsNostr || got.NostrPubkey != strings.Repeat("a", 64) {
		t.Errorf("allowsNostr=%v nostrPubkey=%q; the identity o34.1 writes must be announced",
			got.AllowsNostr, got.NostrPubkey)
	}
	if got.MinSendable != lnurl.MinSendableMsat || got.MaxSendable != lnurl.MaxSendableMsat {
		t.Errorf("sendable range = %d..%d", got.MinSendable, got.MaxSendable)
	}
	// §9: the self-probe recognises this instance by the header.
	if rec.Header().Get(api.ProbeHeader) == "" {
		t.Error("the LNURL response carries no probe header, so the self-probe cannot " +
			"tell this instance from any other server answering that domain")
	}
}

// §7: anything but the configured name is a plain 404 with no hint — a probe
// must not learn which addresses exist here.
func TestAnUnknownAddressIs404WithNoHint(t *testing.T) {
	h := newLNURLHarness(t)
	for _, path := range []string{"/.well-known/lnurlp/alice", "/lnurlp/alice/callback?amount=21000"} {
		rec := h.get(t, path, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "bob") {
			t.Errorf("GET %s leaked the configured name: %s", path, rec.Body)
		}
	}
}

// Criterion 4: the callback mints, answers with the invoice, and expires it at
// §7's 600 seconds.
func TestTheCallbackMintsAnInvoiceAndRecordsIt(t *testing.T) {
	h := newLNURLHarness(t)

	rec := h.get(t, "/lnurlp/bob/callback?amount=21000", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback = %d %q", rec.Code, rec.Body)
	}
	var got lnurl.CallbackResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, rec.Body)
	}
	if got.PaymentRequest == "" {
		t.Fatalf("no payment request in %s", rec.Body)
	}
	if got.Routes == nil {
		t.Error("routes is absent; LUD-06 requires the field even though it is always empty")
	}
	if rec.Header().Get(api.ProbeHeader) == "" {
		t.Error("the callback carries no probe header")
	}

	invoices := h.minted(t)
	if len(invoices) != 1 {
		t.Fatalf("recorded %d invoices, want 1", len(invoices))
	}
	inv := invoices[0]
	if inv.AmountMsat != 21_000 {
		t.Errorf("amount = %d, want 21000", inv.AmountMsat)
	}
	if want := lnurl.InvoiceExpirySeconds; inv.ExpiresAt.Sub(inv.CreatedAt) != time.Duration(want)*time.Second {
		t.Errorf("expiry window = %v, want %ds", inv.ExpiresAt.Sub(inv.CreatedAt), want)
	}
	if inv.ZapRequest != "" {
		t.Errorf("a plain payment recorded a zap request: %q", inv.ZapRequest)
	}
	// A plain payment hashes the metadata string it served.
	want, err := lnurl.MetadataHash(lnurl.Metadata("bob", "zap.example"))
	if err != nil {
		t.Fatal(err)
	}
	if inv.DescriptionHash != hex.EncodeToString(want[:]) {
		t.Errorf("description_hash = %s, want sha256 of the metadata %s",
			inv.DescriptionHash, hex.EncodeToString(want[:]))
	}
}

// Criteria 2 and 5, at the seam: the zap request survives the URL round trip
// byte-for-byte, is hashed as those bytes, and is STORED as those bytes for
// o34.3's receipt.
func TestAZapRequestIsHashedAndStoredAsTheBytesItArrivedAs(t *testing.T) {
	h := newLNURLHarness(t)
	raw := lnurltest.NonCanonicalZapRequest(t, nil)

	rec := h.get(t, "/lnurlp/bob/callback?amount=21000&nostr="+url.QueryEscape(string(raw)), nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"pr"`) {
		t.Fatalf("a valid zap was refused: %d %s", rec.Code, rec.Body)
	}

	invoices := h.minted(t)
	if len(invoices) != 1 {
		t.Fatalf("recorded %d invoices, want 1", len(invoices))
	}
	if invoices[0].ZapRequest != string(raw) {
		t.Fatalf("the stored zap request is not what arrived:\n got %s\nwant %s",
			invoices[0].ZapRequest, raw)
	}
	want, err := lnurl.ZapHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	if invoices[0].DescriptionHash != hex.EncodeToString(want[:]) {
		t.Errorf("description_hash = %s, want sha256 of the raw request %s",
			invoices[0].DescriptionHash, hex.EncodeToString(want[:]))
	}
}

// Criterion 8: a rejection names the rule and mints NOTHING.
func TestARefusedZapRequestMintsNothingAndSaysWhy(t *testing.T) {
	h := newLNURLHarness(t)

	rec := h.get(t, "/lnurlp/bob/callback?amount=21000&nostr="+url.QueryEscape(`{"kind":1}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("LNURL errors ride inside a 200; got %d", rec.Code)
	}
	var answer map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, rec.Body)
	}
	if answer["status"] != "ERROR" || !strings.Contains(answer["reason"], "kind 9734") {
		t.Errorf("answer = %v, want an ERROR naming the rule", answer)
	}
	if n := len(h.minted(t)); n != 0 {
		t.Errorf("a refused zap minted %d invoices", n)
	}
	if len(h.node.SeenMacaroons()) != 0 {
		t.Error("a refused zap reached the node; validation must come first (§11)")
	}
}

// o34.2 criterion 9, and the reason o34.10 blocked this bead: an AddInvoice
// failure on a PUBLIC endpoint must not reach the credential broker. Driven
// with the box's exact code, through the real handler.
func TestAFailedMintOnThePublicCallbackNeverAsksTheGuardToReBake(t *testing.T) {
	h := newLNURLHarness(t)
	h.node.SetRejectWith(status.Error(codes.Unknown, "invoice expiry out of range"))

	for range 5 {
		rec := h.get(t, "/lnurlp/bob/callback?amount=21000", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("callback = %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "ERROR") {
			t.Fatalf("the node was told to refuse and the callback succeeded: %s", rec.Body)
		}
		// And it tells a stranger nothing about our node.
		if strings.Contains(rec.Body.String(), "expiry out of range") {
			t.Errorf("the callback quoted LND's error to an anonymous caller: %s", rec.Body)
		}
	}
	if got := h.broker.Bakes(); got != 0 {
		t.Errorf("five failed public callbacks asked the guard to bake %d times; an "+
			"unauthenticated caller must not be able to drive the credential broker", got)
	}
	events, err := h.store.AuditEvents(t.Context(), 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Event == logging.EventMacaroonBake {
			t.Error("a failed public callback produced a macaroon.bake row; a re-bake storm " +
				"trims the audit trail down to nothing but itself")
		}
	}
}

// --- helpers ---------------------------------------------------------------

// minted reads back what the node was asked to mint, looked up by the hashes
// the node itself reports. There is no list query on the store and this does not
// add one: a test-only method on a production type drifts from the thing it
// guards, which this repo has already been bitten by.
func (h *lnurlHarness) minted(t *testing.T) []store.Invoice {
	t.Helper()
	var out []store.Invoice
	for _, hash := range h.node.MintedHashes() {
		inv, ok, err := h.store.Invoice(t.Context(), hash)
		if err != nil {
			t.Fatalf("reading invoice %s: %v", hash, err)
		}
		if ok {
			out = append(out, inv)
		}
	}
	return out
}

// The lnurlp document is static and wants caching. The callback returns a
// single-use bolt11, and an intermediary that served one twice would hand two
// payers one invoice: LND settles a payment hash once, so the second payment is
// gone with nothing recorded.
func TestTheCallbackIsUncacheableAndTheAddressDocumentIsNot(t *testing.T) {
	h := newLNURLHarness(t)

	if got := h.get(t, "/lnurlp/bob/callback?amount=21000", nil).Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("callback Cache-Control = %q, want no-store — the pr is single-use", got)
	}
	if got := h.get(t, "/.well-known/lnurlp/bob", nil).Header().Get("Cache-Control"); got != "" {
		t.Errorf("the address document carries Cache-Control %q; it is static and wants "+
			"caching", got)
	}
}

// o34.10's other half: a stranger hitting the public callback must not be able
// to clear the operator-facing "re-link needed" state that the invoice stream
// set while the credential is genuinely bad.
func TestAPublicCallbackCannotClearTheRelinkState(t *testing.T) {
	h := newLNURLHarness(t)

	// The stream's view, through the real stream: the node verified our
	// macaroon and refused it. Only this path may reach that conclusion.
	h.node.SetReject(true)
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_ = h.client.RunInvoiceStream(ctx, noResume{}, func(context.Context, *lnrpc.Invoice) error {
			return nil
		})
	}()
	lndtest.WaitFor(t, "the stream to reach re-link", func() bool {
		return h.client.State() == lnd.StateRelink
	})
	// Stop it, so what follows can only be the callback's doing. Leaving it
	// running would let the stream react to the changed error and the test would
	// be measuring the wrong path.
	cancel()
	<-stopped
	if got := h.client.State(); got != lnd.StateRelink {
		t.Fatalf("State = %q once the stream stopped, want %q", got, lnd.StateRelink)
	}

	// Now a stranger makes AddInvoice fail the way LND reports handler errors.
	h.node.SetRejectWith(status.Error(codes.Unknown, "invoice expiry out of range"))
	for range 3 {
		if rec := h.get(t, "/lnurlp/bob/callback?amount=21000", nil); rec.Code != http.StatusOK {
			t.Fatalf("callback = %d", rec.Code)
		}
	}
	if got := h.client.State(); got != lnd.StateRelink {
		t.Errorf("State = %q after three failed public callbacks, want it left at %q — a "+
			"stranger must not be able to hide the state d46.20 exists to show", got, lnd.StateRelink)
	}
}

// noResume keeps the stream from touching a settle-index store it does not need.
type noResume struct{}

func (noResume) LastSettleIndex(context.Context) (uint64, error)  { return 0, nil }
func (noResume) SetLastSettleIndex(context.Context, uint64) error { return nil }

// o34.12. The endpoint announces commentAllowed and length-checks what arrives,
// and then dropped it: a wallet showed "comment accepted" and the comment was
// gone. The ruling was to store it rather than to advertise commentAllowed: 0 —
// announcing a capability and discarding what it accepts was the option ruled
// out.
func TestACommentIsStoredAndCarriedToTheSettledTxn(t *testing.T) {
	h := newLNURLHarness(t)
	comment := "thanks for the write-up 🙏"

	rec := h.get(t, "/lnurlp/bob/callback?amount=21000&comment="+url.QueryEscape(comment), nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"pr"`) {
		t.Fatalf("a commented payment was refused: %d %s", rec.Code, rec.Body)
	}
	invoices := h.minted(t)
	if len(invoices) != 1 {
		t.Fatalf("minted %d invoices, want 1", len(invoices))
	}
	if invoices[0].Comment != comment {
		t.Errorf("stored comment = %q, want %q", invoices[0].Comment, comment)
	}
}

// Criterion 2: the advertised figure and the enforced one are the same number
// in the same units. Wave 8 fixed the smaller half of this — the check counted
// BYTES while the advertisement is characters, so a 200-character emoji comment
// was refused by an endpoint advertising 255 — and this is what keeps it fixed.
func TestTheAdvertisedCommentLengthIsTheEnforcedOneInTheSameUnits(t *testing.T) {
	h := newLNURLHarness(t)

	var doc lnurl.PayResponse
	if err := json.Unmarshal(h.get(t, "/.well-known/lnurlp/bob", nil).Body.Bytes(), &doc); err != nil {
		t.Fatalf("the address document is not JSON: %v", err)
	}
	if doc.CommentAllowed != lnurl.CommentAllowed {
		t.Fatalf("advertised commentAllowed = %d, want %d", doc.CommentAllowed, lnurl.CommentAllowed)
	}

	// Multi-byte on purpose: exactly the advertised number of CHARACTERS is far
	// more bytes, and a byte-counting check would refuse it.
	atLimit := strings.Repeat("🙏", doc.CommentAllowed)
	if len([]rune(atLimit)) != doc.CommentAllowed {
		t.Fatalf("the fixture is %d characters, want %d", len([]rune(atLimit)), doc.CommentAllowed)
	}
	if rec := h.get(t, "/lnurlp/bob/callback?amount=21000&comment="+
		url.QueryEscape(atLimit), nil); !strings.Contains(rec.Body.String(), `"pr"`) {
		t.Errorf("a comment of exactly the advertised length was refused: %s", rec.Body)
	}

	overLimit := atLimit + "🙏"
	rec := h.get(t, "/lnurlp/bob/callback?amount=21000&comment="+url.QueryEscape(overLimit), nil)
	if strings.Contains(rec.Body.String(), `"pr"`) {
		t.Errorf("a comment one character over the advertised length was accepted: %s", rec.Body)
	}
}

// The comment must NOT reach the description hash. LUD-12's comment is not
// LUD-06's metadata, and the hash is computed over the metadata — a wallet has
// already committed to that hash by the time it sends the comment, so folding
// it in would produce an invoice no wallet accepts.
func TestACommentDoesNotChangeTheDescriptionHash(t *testing.T) {
	h := newLNURLHarness(t)

	h.get(t, "/lnurlp/bob/callback?amount=21000", nil)
	h.get(t, "/lnurlp/bob/callback?amount=21000&comment="+url.QueryEscape("hello"), nil)

	invoices := h.minted(t)
	if len(invoices) != 2 {
		t.Fatalf("minted %d invoices, want 2", len(invoices))
	}
	if invoices[0].DescriptionHash != invoices[1].DescriptionHash {
		t.Errorf("description_hash differs with and without a comment:\n %s\n %s\n"+
			"the comment is feeding into the metadata, and the wallet has already "+
			"committed to the hash it was served",
			invoices[0].DescriptionHash, invoices[1].DescriptionHash)
	}
}

// The header reaches the wallet through the REAL server, not just through
// Compose with stand-in handlers (BrollyZap-z60).
//
// routes_test.go asserts the composition; this asserts the thing a browser
// actually receives, on the fully wired server with the real LNURL handlers
// behind it. Two well-tested halves with an untested wire between them is
// invisible to per-package coverage (§13), and the bug being fixed here was
// precisely a header nobody had checked end to end.
//
// Both legs, and a live 200 on each: a browser fails on the address document
// first, so a callback asserted only in isolation could regress unnoticed
// behind an address document that still worked.
func TestAWalletReadsTheLNURLResponsesCrossOriginThroughTheRealServer(t *testing.T) {
	h := newLNURLHarness(t)

	for _, path := range []string{"/.well-known/lnurlp/bob", "/lnurlp/bob/callback?amount=21000"} {
		rec := h.get(t, path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d %q; the CORS assertion below would be vacuous", path, rec.Code, rec.Body)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("%s sent Access-Control-Allow-Origin %q, want \"*\"; a browser wallet "+
				"cannot read this response", path, got)
		}
	}
}
