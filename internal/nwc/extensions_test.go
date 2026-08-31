package nwc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"
)

// extensionsTag reads the info event's `extensions` tag for a connection, or ""
// when it carries none.
func extensionsTag(t *testing.T, h *harness) string {
	t.Helper()
	event, err := h.service.infoEvent(t.Context(), h.conn)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "extensions" {
			return strings.Join(tag[1:], " ")
		}
	}
	return ""
}

// doy.3: the info event advertises 05 and 06 — AND THE TEST IS ONE TEST for a
// reason.
//
// THE TAG IS A SWITCH, NOT A DESCRIPTION. Amethyst is paired with wallets it
// does not control, and one that typed `metadata` narrowly would accept today's
// `"metadata": null` and then fail to decode a nested object — returning a
// params error and REFUSING THE PAYMENT. So rather than bet on every wallet's
// conformance it sends metadata only to a wallet whose info event says it
// understands it (read, not run: NwcSignerState.kt:182). Advertising is what
// makes clients start sending.
//
// WHY THIS IS ONE TEST AND NOT THREE, since review asked and the answer is not
// "regressions". A regression does fail whichever test owns it, wherever the
// tests are split. The risk this shape covers is the other one, and it is the
// one the bead was written about: the tag being added AHEAD of the feature. In
// that world there are no storage tests to go red, because there is no storage —
// and a tidy tag-only test passes on the first commit. A single test that cannot
// be satisfied without storing and echoing is the only shape that refuses that
// commit.
//
// So the legs below assert the PROMISE and nothing more; the shapes themselves
// belong to TestAPaymentCarriesTheZapRequestTheClientSigned and
// TestAnOutgoingRowCarriesItsPayeeAsMetadataNostr, which own them at unit level.
//
// The expected value is spelled out rather than compared against the constants,
// because a test that builds its expectation the way the code does asserts only
// that the code is self-consistent.
func TestTheExtensionsTagIsAdvertisedOnlyAlongsideStorageAndEcho(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	// A zap invoice, committing to the event the client will attach (y09).
	event := anOutgoingZapRequest(t, 21_000)
	h.decodesZapTo("lnbcrt1zap", 21_000, event)

	// --- the switch ---------------------------------------------------------
	if got := extensionsTag(t, h); got != "05 06" {
		t.Fatalf("the extensions tag reads %q, want \"05 06\" — 05 is list_transactions, "+
			"implemented and unadvertised since d24.12, and 06 is the metadata conventions "+
			"the rest of this test is about", got)
	}

	// --- what it promises, first half: we keep what you send -----------------
	resp := h.handle(t, MethodPayInvoice,
		payParamsWithMetadata("lnbcrt1zap", 21_000, nwcMetadata(event)))
	if resp.Error != nil {
		t.Fatalf("the payment was refused: %+v", resp.Error)
	}
	stored := h.spend.lastRequest().Metadata
	if stored != nwcMetadata(event) {
		t.Fatalf("the reservation carries %q; nothing was stored, so the tag above invites "+
			"clients to send what this node discards", stored)
	}

	// --- and the second: you can read it back --------------------------------
	h.invoices.txns = append(h.invoices.txns, store.Txn{
		Kind: "payment_out", State: "settled", AmountMsat: 21_000,
		PaymentHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		OutMetadata: stored,
		CreatedAt:   time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC),
	})
	h.handle(t, MethodListTransactions, nil)

	published := h.relays.published()
	if len(published) == 0 {
		t.Fatal("list_transactions published nothing")
	}
	var page struct {
		Result struct {
			Transactions []struct {
				Type     string          `json:"type"`
				Metadata json.RawMessage `json:"metadata"`
			} `json:"transactions"`
		} `json:"result"`
	}
	answer := h.open(t, published[len(published)-1])
	if err := json.Unmarshal([]byte(answer), &page); err != nil {
		t.Fatalf("the client's parser cannot read the page: %v\n%s", err, answer)
	}
	outgoing := 0
	for _, row := range page.Result.Transactions {
		if row.Type != "outgoing" {
			continue
		}
		outgoing++
		if payee := nostrMetadata(t, row.Metadata).pTag(); payee != aPayee {
			t.Errorf("the row came back with payee %q, want %q — the tag promises this "+
				"round trip", payee, aPayee)
		}
	}
	if outgoing != 1 {
		t.Fatalf("%d outgoing rows in the page, want 1", outgoing)
	}
}

// A pairing that may not read its history is not told it can (review).
//
// 05 IS list_transactions, one method behind one permission group, and
// advertised() already omits that method from the info event's content for a
// pairing without `history`. A node-wide extensions tag would have claimed it
// anyway — the same event naming a capability in one field and denying it in the
// one beside it. 06 stays, because no single group makes the metadata
// conventions false: a pairing holding only `pay` still understands the envelope
// on the one call it can make.
func TestAPairingWithoutHistoryIsNotToldItHasIt(t *testing.T) {
	h := newHarness(t)
	h.mutate(func(row *store.NWCConnection) {
		row.Permissions = []string{store.PermissionInfo, store.PermissionPay}
	})
	h.updateConnection()

	if got := extensionsTag(t, h); got != "06" {
		t.Errorf("the extensions tag reads %q, want \"06\" — this pairing cannot call "+
			"list_transactions, and the same event says so four fields away", got)
	}

	event, err := h.service.infoEvent(t.Context(), h.conn)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(event.Content, string(MethodListTransactions)) {
		t.Fatalf("the method list says %q; if this pairing CAN list transactions the test "+
			"above is asserting the wrong thing", event.Content)
	}
}
