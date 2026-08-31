package nwc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/store"
)

// aZapRequest is a kind 9735 zap request as one arrives — the blob the receipt
// publishes verbatim, and the blob a client turns into a name and a face.
const aZapRequest = `{"kind":9734,"pubkey":"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",` +
	`"created_at":1700000000,"content":"here is a coffee",` +
	`"tags":[["p","79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"],` +
	`["relays","wss://relay.example"]],"sig":"deadbeef"}`

// clientMetadata is `metadata` as A CLIENT READS IT, which is the only reading
// that matters: Amethyst takes `nostr`, reads its `pubkey` and walks its `tags`
// for the `p` tag, then resolves those against relays it already holds.
//
// One decoder for three tests — incoming, outgoing, and the round trip through a
// real list_transactions — because the wire shape is one fact and it was being
// re-declared per test, with the same anonymous struct and the same tag loop
// copied beside it (review).
type clientMetadata struct {
	Nostr struct {
		Kind    int        `json:"kind"`
		PubKey  string     `json:"pubkey"`
		Content string     `json:"content"`
		Tags    [][]string `json:"tags"`
	} `json:"nostr"`
	// The two NWC-06 siblings, which only outgoing rows carry. Here rather than
	// in a fourth anonymous struct beside the one test that reads them, which is
	// what the paragraph above is about.
	RecipientData struct {
		Identifier string `json:"identifier"`
	} `json:"recipient_data"`
	Comment string `json:"comment"`
}

// pTag is NIP-57's `p`, and WHO IT NAMES DEPENDS ON THE DIRECTION: on an incoming
// row it is us, the recipient; on an outgoing one it is the payee, and it is the
// only identity such a row has.
func (m clientMetadata) pTag() string {
	for _, tag := range m.Nostr.Tags {
		if len(tag) >= 2 && tag[0] == "p" {
			return tag[1]
		}
	}
	return ""
}

// nostrMetadata round-trips a row's metadata through JSON and decodes it the way
// a client would.
//
// THROUGH JSON deliberately: asserting on the Go value would pass for something
// that does not survive encoding, and encoding is what the client receives.
func nostrMetadata(t *testing.T, metadata any) clientMetadata {
	t.Helper()
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("the metadata does not encode: %v", err)
	}
	var decoded clientMetadata
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("the client's parser cannot read the metadata: %v\n%s", err, encoded)
	}
	return decoded
}

// d24.27: every history row says WHEN, and a zap says WHO.
//
// The operator compared this app's rows in Amethyst against the same screen
// backed by another wallet: ours were bare arrows with no times at all, theirs
// had a sender name, an avatar, the zap comment and a relative time on every row.
// Almost none of that gap was missing data — `txn.CreatedAt` was on the row and
// simply not emitted, and the zap request was read out of the database as the SQL
// expression `zap_request IS NOT NULL`, which throws the sender away and keeps
// the fact that there was one.
func TestAHistoryRowSaysWhenItHappened(t *testing.T) {
	at := time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC)
	settled := at.Add(9 * time.Second)
	row := txnResult(store.Txn{
		Kind: "invoice_in", State: "settled", AmountMsat: 21_000,
		PaymentHash: "hash", Bolt11: "lnbc210n1thezap",
		CreatedAt: at, SettledAt: settled,
	}, 0)

	// PER FIELD. "The object has more keys now" cannot say which one regressed.
	if got := row["created_at"]; got != at.Unix() {
		t.Errorf("created_at = %v, want %d — every row was undated, which is why the history "+
			"read as a column of bare arrows", got, at.Unix())
	}
	if got := row["settled_at"]; got != settled.Unix() {
		t.Errorf("settled_at = %v, want %d", got, settled.Unix())
	}
	if got := row["invoice"]; got != "lnbc210n1thezap" {
		t.Errorf("invoice = %v, want the row's bolt11", got)
	}
}

// A row that has not settled says so by OMITTING settled_at, rather than dating
// it to the epoch.
func TestAnUnsettledRowHasNoSettledAt(t *testing.T) {
	row := txnResult(store.Txn{
		Kind: "invoice_in", State: "open", AmountMsat: 21_000,
		CreatedAt: time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
	}, 0)

	if _, present := row["settled_at"]; present {
		t.Errorf("an unsettled row carries settled_at = %v; zero would read as 1970 and a "+
			"client would render it", row["settled_at"])
	}
	if _, present := row["invoice"]; present {
		t.Errorf("a row with no bolt11 carries invoice = %q", row["invoice"])
	}
}

// The sender's identity travels as `metadata.nostr`, and the assertion is that
// THE CLIENT'S PARSER succeeds — not that two strings match.
//
// Amethyst reads `metadata.nostr` as the zap request event itself: it takes
// `n["pubkey"]` and walks `n["tags"]` for the `p` tag, then resolves that pubkey
// to a display name and an avatar from relays it is already connected to. So this
// test does what that parser does, and a re-encoding that produced valid JSON of
// the wrong shape would fail it.
//
// IT IS NOT A NEW DISCLOSURE. The kind 9735 receipt this app publishes PUBLICLY
// already carries the zap request verbatim in its `description` tag, because
// NIP-57 requires a client to recompute description_hash from it. The sender
// pubkey and comment of every zap received are public by design; handing the same
// blob to the operator's own paired wallet tells it nothing the world cannot read.
func TestAZapCarriesItsSenderAsMetadataNostr(t *testing.T) {
	row := txnResult(store.Txn{
		Kind: "invoice_in", State: "settled", AmountMsat: 21_000,
		ZapRequest: aZapRequest,
		CreatedAt:  time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
	}, 0)

	if _, ok := row["metadata"].(map[string]any); !ok {
		t.Fatalf("metadata = %#v, want an object carrying the zap request", row["metadata"])
	}
	decoded := nostrMetadata(t, row["metadata"])
	if decoded.Nostr.PubKey != "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" {
		t.Errorf("metadata.nostr.pubkey = %q; this is the sender the client turns into a name "+
			"and an avatar", decoded.Nostr.PubKey)
	}
	if got := decoded.pTag(); got != "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" {
		t.Errorf("the p tag reads %q; the client walks the tags for it exactly this way", got)
	}
}

// A row that is not a zap carries NO metadata key at all.
//
// Not an empty object: a client that finds `metadata` present and empty has to
// decide what that means, and there is nothing to mean. Absent is the honest
// shape for "this payment had no zap request".
func TestANonZapRowHasNoMetadata(t *testing.T) {
	row := txnResult(store.Txn{
		Kind: "payment_out", State: "settled", AmountMsat: 21_000,
		CreatedAt: time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
	}, 0)

	if _, present := row["metadata"]; present {
		t.Errorf("a non-zap row carries metadata = %#v, want the key to be absent",
			row["metadata"])
	}
}

// A zap request that is not valid JSON is left out rather than passed through.
//
// The column is documented as "raw JSON exactly as received", and the receipt
// path verifies it — but this function is the one place that puts a stored blob
// inside a response it did not build, and a malformed one would make the WHOLE
// response unparseable rather than this one field absent. A client would then
// lose its history over one bad row.
func TestAMalformedZapRequestIsLeftOut(t *testing.T) {
	row := txnResult(store.Txn{
		Kind: "invoice_in", State: "settled", AmountMsat: 21_000,
		ZapRequest: `{"kind":9734,`,
		CreatedAt:  time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
	}, 0)

	if _, present := row["metadata"]; present {
		t.Errorf("a malformed zap request was passed through as %#v", row["metadata"])
	}
	if _, err := json.Marshal(row); err != nil {
		t.Errorf("the response does not encode at all: %v", err)
	}
}

// d24.27 criterion 5: none of this reaches the network.
//
// WHAT THIS PROVES AND WHAT IT DOES NOT, because the difference matters and the
// first version of the comment overstated it. txnResult takes a row and an id: no
// context, no client, no seam. Calling it from a test with no service and no
// fakes at all is a compile-time argument that nothing was PASSED to it to call
// out with — it is not proof that the function body contains no call, since a
// package-level client would not need passing. What makes that unlikely is the
// same thing the argument rests on: this package declares its collaborators as
// interfaces on the Service (§3), so a package-level HTTP client would be a
// visible departure rather than an oversight.
//
// Fetching kind 0 profile metadata is what would have made this otherwise — we
// send a pubkey, and the client turns it into a name using relays it already
// holds.
func TestBuildingAHistoryRowReachesNothing(t *testing.T) {
	row := txnResult(store.Txn{Kind: "invoice_in", ZapRequest: aZapRequest}, 0)
	if row["metadata"] == nil {
		t.Error("the row lost its metadata, which would make this test vacuous")
	}
}

// A full page of zapped history still fits inside what NIP-44 will encrypt.
//
// The highest-cost finding of this wave's review, and it was introduced by the
// fix above rather than found in old code: NIP-44 REFUSES a plaintext over 65535
// bytes, `list_transactions` defaults to MaxHistoryRows when a client sends no
// limit, and a realistic zap request is ~650 bytes — so a hundred rows went from
// ~23 kB to ~119 kB and crossed the ceiling at about 55. The encrypt then fails,
// NOTHING is published, and every retry fails identically: `list_transactions`
// dead for that pairing with nothing on the wire to say why. Which is the silent
// failure d24.27 exists to remove, reintroduced by it.
//
// The rows are kept and the decoration is dropped — see fitHistory for why that
// is the right way round.
func TestAFullPageOfZapsStillFitsInAResponse(t *testing.T) {
	h := newHarness(t)
	rows := make([]map[string]any, 0, store.MaxHistoryRows)
	for i := range store.MaxHistoryRows {
		rows = append(rows, txnResult(store.Txn{
			Kind: "invoice_in", State: "settled", AmountMsat: int64(i) * 1_000,
			PaymentHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Bolt11:      "lnbc210n1p" + strings.Repeat("q", 180),
			ZapRequest:  aZapRequest,
			CreatedAt:   time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
		}, 0))
	}

	rows = h.service.fitHistory(1, rows)

	encoded, err := encode(Response{ResultType: MethodListTransactions,
		Result: map[string]any{"transactions": rows}})
	if err != nil {
		t.Fatalf("encoding the page: %v", err)
	}
	if len(encoded) > MaxResponsePlaintext {
		t.Errorf("a full page of zapped history encodes to %d bytes, want at most %d — NIP-44 "+
			"refuses a plaintext over 65535 outright, and the client is told nothing at all",
			len(encoded), MaxResponsePlaintext)
	}
	// It really is encryptable, which is the fact the number is a proxy for.
	if _, err := h.counting.Encrypt(nostr.NIP44, h.client.PublicKey(), encoded); err != nil {
		t.Errorf("the page cannot be encrypted: %v", err)
	}

	// THE ROWS SURVIVE, all of them: `limit` is how a client pages, so a page
	// shorter than the one it asked for is how it learns the history has run out.
	if len(rows) != store.MaxHistoryRows {
		t.Errorf("%d rows survived the trim, want %d — trimming rows tells a client its "+
			"history ended", len(rows), store.MaxHistoryRows)
	}
}

// A page a person actually reads keeps its senders.
//
// The other half of the trade fitHistory makes: a client asking for the MAXIMUM
// gets a hundred rows without names, and one asking for a screenful gets both.
// Without this the trim could satisfy the test above by dropping every detail
// from every page, which is a correct response and a useless feature.
func TestAScreenfulOfZapsKeepsItsSenders(t *testing.T) {
	h := newHarness(t)
	const onScreen = 20
	rows := make([]map[string]any, 0, onScreen)
	for range onScreen {
		rows = append(rows, txnResult(store.Txn{
			Kind: "invoice_in", State: "settled", AmountMsat: 21_000,
			PaymentHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Bolt11:      "lnbc210n1p" + strings.Repeat("q", 380),
			ZapRequest:  aZapRequest,
			CreatedAt:   time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
		}, 0))
	}

	rows = h.service.fitHistory(1, rows)

	if len(rows) != onScreen {
		t.Fatalf("%d rows survived, want %d", len(rows), onScreen)
	}
	for i, row := range rows {
		if _, present := row["metadata"]; !present {
			t.Errorf("row %d of a %d-row page lost its sender; a page this size fits with "+
				"room to spare", i, onScreen)
		}
	}
}

// And the bound is actually WIRED IN: a real list_transactions over a history of
// zaps is answered.
//
// The test above calls fitHistory directly and cannot see the call site — with
// the `out = s.fitHistory(...)` line planted away it stayed green, which is the
// same blindness that let an earlier version of this wave read the sender as a
// boolean. This one goes through handle, so what it asserts is that a client
// asking for its history GETS one.
func TestAHistoryOfZapsIsAnswered(t *testing.T) {
	h := newHarness(t)
	for i := range store.MaxHistoryRows {
		h.invoices.txns = append(h.invoices.txns, store.Txn{
			Kind: "invoice_in", State: "settled", AmountMsat: int64(i+1) * 1_000,
			PaymentHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Bolt11:      "lnbc210n1p" + strings.Repeat("q", 380),
			ZapRequest:  aZapRequest,
			CreatedAt:   time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
		})
	}

	h.handle(t, MethodListTransactions, nil)

	if got := len(h.relays.published()); got != 1 {
		t.Fatalf("%d responses for a full history page, want 1 — over NIP-44's ceiling the "+
			"encrypt fails, nothing is published, and every retry fails the same way", got)
	}
	// It decrypts, which is the whole of what the ceiling is about.
	answer := h.open(t, h.relays.published()[0])
	if !strings.Contains(answer, "transactions") {
		t.Errorf("the answer is %q, want the history", answer)
	}
	if strings.Contains(h.logs.String(), "could not encrypt an NWC response") {
		t.Errorf("the response could not be encrypted:\n%s", h.logs.String())
	}
}

// A row with nothing to call itself has NO description key (doy.1).
//
// EVERY outgoing zap lands here. A NIP-57 invoice commits to a description_hash
// over the LNURL metadata and carries no plaintext memo at all, so d24.16's
// `boundedDescription(invoice.Description)` writes "" on exactly the rows the
// operator most wants labelled — and `txnResult` sent that empty string on.
//
// A client that falls back only on a MISSING field renders it: a line occupied,
// showing nothing, not even the word "Sent". Omitting the key lets every client
// use its own label, and it does so for history that ALREADY EXISTS — no client
// change, no migration.
//
// Not the same call as the preimage's a few lines below, which is deliberately
// an empty string: "not settled", "not yours" and "this field is new" must not
// be distinguishable there, and none of them is the client's business. A
// description has no such secret to keep.
func TestARowWithNoMemoHasNoDescription(t *testing.T) {
	row := txnResult(store.Txn{
		Kind: "payment_out", State: "settled", AmountMsat: 21_000,
		PaymentHash: "hash",
		CreatedAt:   time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
	}, 0)

	if _, present := row["description"]; present {
		t.Errorf("description = %#v on a row with no memo; a client that falls back only on "+
			"a missing field renders the empty string as a blank line", row["description"])
	}
}

// And a row that HAS something to say still says it, both ways round — the memo
// an outgoing row stores at reserve time, and the LUD-12 comment an incoming one
// carries. One field answers "what was this for" whichever way the money went,
// and the fix must not have cost that.
func TestARowWithAMemoStillCarriesIt(t *testing.T) {
	for _, c := range []struct {
		name string
		txn  store.Txn
		want string
	}{
		{"an outgoing row's invoice memo", store.Txn{
			Kind: "payment_out", Description: "a round of drinks",
		}, "a round of drinks"},
		{"an incoming row's zap comment", store.Txn{
			Kind: "invoice_in", Comment: "here is a coffee",
		}, "here is a coffee"},
	} {
		t.Run(c.name, func(t *testing.T) {
			row := txnResult(c.txn, 0)
			if got := row["description"]; got != c.want {
				t.Errorf("description = %#v, want %q", got, c.want)
			}
		})
	}
}

// The same call, one method over: an invoice with nothing to call itself has no
// description key either (doy.1, found by the review of doy.1's own diff).
//
// `lookup_invoice` reaches `invoiceResult`, and the adapter fills its
// Description from the invoice's LUD-12 comment (cmd/brollyzapper/nwc.go). That
// comment is OPTIONAL and stored unconditionally, so a zap invoice nobody left a
// note on answers a lookup with the same empty string list_transactions used to
// send — the identical blank line, reached by a client that checks one invoice
// instead of reading its history.
//
// `make_invoice`'s echo is the other caller and the same fix is harmless there:
// that Description is the client's own `params.description` coming back, so a
// client that asked for none is told it has none, which is what absence says.
func TestAnInvoiceWithNoDescriptionOmitsTheKey(t *testing.T) {
	minted := time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC)
	row := invoiceResult(Invoice{
		Bolt11: "lnbc210n1thezap", PaymentHash: "hash", AmountMsat: 21_000,
		CreatedAt: minted, ExpiresAt: minted.Add(time.Hour),
	})

	if _, present := row["description"]; present {
		t.Errorf("description = %#v on an invoice with no comment; the blank line doy.1 "+
			"removed from the history is still here on the single-invoice path",
			row["description"])
	}
	if got := row["payment_hash"]; got != "hash" {
		t.Errorf("payment_hash = %#v, want the invoice's — the rest of the row must be "+
			"unchanged", got)
	}
}

// An OUTGOING row carries its payee the same way an incoming one carries its
// sender: `metadata.nostr`, one shape, one parser (doy.2).
//
// The asymmetry is inside the event rather than in the field: on an incoming row
// the useful party is the signer's `pubkey`, on an outgoing one it is the `p`
// tag, because the signer is the payer — us, or a throwaway key for an anonymous
// zap. A client walks the tags either way, which is why the wire shape does not
// need to know the difference.
func TestAnOutgoingRowCarriesItsPayeeAsMetadataNostr(t *testing.T) {
	row := txnResult(store.Txn{
		Kind: "payment_out", State: "settled", AmountMsat: 21_000,
		OutMetadata: nwcMetadata(aZapRequest),
		CreatedAt:   time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
	}, 0)

	if got := row["type"]; got != "outgoing" {
		t.Fatalf("type = %v, want outgoing; the rest of this test reads on that", got)
	}
	decoded := nostrMetadata(t, row["metadata"])
	if decoded.Nostr.Kind != 9734 {
		t.Errorf("metadata.nostr.kind = %d, want 9734 — the same shape the incoming test "+
			"asserts, which is what lets one client parser read both directions",
			decoded.Nostr.Kind)
	}
	if payee := decoded.pTag(); payee != "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" {
		t.Errorf("the p tag reads %q; on an outgoing row this is the PAYEE, and it is the "+
			"only identity the row has", payee)
	}
}

// The two columns cannot cross over, and the check is the row's DIRECTION rather
// than whichever column happens to be filled.
//
// Nothing writes both today. That is exactly why this is asserted: an assumption
// nothing tests is a property the next writer can remove without noticing.
func TestAColumnIsReadOnlyForTheDirectionItBelongsTo(t *testing.T) {
	both := store.Txn{
		ZapRequest:  `{"kind":9734,"content":"incoming"}`,
		OutMetadata: nwcMetadata(`{"kind":9734,"content":"outgoing"}`),
		CreatedAt:   time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
	}
	for _, c := range []struct{ kind, want string }{
		{"invoice_in", "incoming"},
		{"payment_out", "outgoing"},
	} {
		t.Run(c.kind, func(t *testing.T) {
			txn := both
			txn.Kind = c.kind
			encoded, err := json.Marshal(txnResult(txn, 0)["metadata"])
			if err != nil {
				t.Fatalf("the metadata does not encode: %v", err)
			}
			if !strings.Contains(string(encoded), `"`+c.want+`"`) {
				t.Errorf("a %s row emitted %s, want the %s column — one is a fact this node "+
					"verified and the other is a paired client's claim, and a client has "+
					"nothing but the direction to tell them apart", c.kind, encoded, c.want)
			}
		})
	}
}

// Outgoing rows carrying metadata join the SAME budget, and at the page size the
// spec recommends there is room for all of them (doy.2).
//
// fitHistory needed no change for this and that is the claim being checked: it
// trims `metadata` oldest-first, generically, without caring which column the
// field came from. NWC-05 says clients SHOULD page at 20 and Amethyst's pageSize
// is 20 (read, not run), and ~650 bytes of zap request per row is ~13 kB against
// MaxResponsePlaintext's 40 kB — so a screenful keeps every payee.
//
// The mixed page is the realistic one. A history is not all one direction, and a
// test of twenty outgoing rows would miss a budget that only overflows when both
// columns are populated across the same page.
func TestAScreenfulOfOutgoingZapsKeepsItsPayees(t *testing.T) {
	h := newHarness(t)
	const onScreen = 20
	rows := make([]map[string]any, 0, onScreen)
	for i := range onScreen {
		txn := store.Txn{
			Kind: "payment_out", State: "settled", AmountMsat: 21_000,
			PaymentHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Bolt11:      "lnbc210n1p" + strings.Repeat("q", 380),
			OutMetadata: nwcMetadata(aZapRequest),
			CreatedAt:   time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
		}
		if i%2 == 0 {
			txn.Kind, txn.ZapRequest, txn.OutMetadata = "invoice_in", aZapRequest, ""
		}
		rows = append(rows, txnResult(txn, 0))
	}

	rows = h.service.fitHistory(1, rows)

	if len(rows) != onScreen {
		t.Fatalf("%d rows survived, want %d", len(rows), onScreen)
	}
	for i, row := range rows {
		if _, present := row["metadata"]; !present {
			t.Errorf("row %d of a %d-row page lost its party; a page this size fits with "+
				"room to spare whichever way the money went", i, onScreen)
		}
	}
}

// And the full page still fits, with metadata on every row in both directions —
// the ceiling case, where the trim has to do its job.
func TestAFullPageOfOutgoingZapsStillFitsInAResponse(t *testing.T) {
	h := newHarness(t)
	rows := make([]map[string]any, 0, store.MaxHistoryRows)
	for i := range store.MaxHistoryRows {
		rows = append(rows, txnResult(store.Txn{
			Kind: "payment_out", State: "settled", AmountMsat: int64(i) * 1_000,
			PaymentHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Bolt11:      "lnbc210n1p" + strings.Repeat("q", 180),
			OutMetadata: nwcMetadata(aZapRequest),
			CreatedAt:   time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
		}, 0))
	}

	rows = h.service.fitHistory(1, rows)

	encoded, err := encode(Response{ResultType: MethodListTransactions,
		Result: map[string]any{"transactions": rows}})
	if err != nil {
		t.Fatalf("encoding the page: %v", err)
	}
	if len(encoded) > MaxResponsePlaintext {
		t.Errorf("a full page of SENT zaps encodes to %d bytes, want at most %d — the new "+
			"column joined the budget without joining the trim", len(encoded),
			MaxResponsePlaintext)
	}
	// It really is encryptable, which is the fact the byte count is a proxy for
	// — the incoming twin of this test asserts it and this copy had dropped it.
	if _, err := h.counting.Encrypt(nostr.NIP44, h.client.PublicKey(), encoded); err != nil {
		t.Errorf("the page cannot be encrypted: %v", err)
	}
	if len(rows) != store.MaxHistoryRows {
		t.Errorf("%d rows survived the trim, want %d — trimming rows tells a client its "+
			"history ended", len(rows), store.MaxHistoryRows)
	}
}

// The whole NWC-06 object comes back, not just its `nostr` member.
//
// A client's own row renderer falls back to `recipient_data.identifier` — the
// payee's lightning address — when a kind 0 profile has not resolved, so a
// `nostr`-only round trip handed every row back nameless. The symptom was
// specific and worth remembering: right comment, no name, because
// `displayComment()` falls back to the event's content while the address has
// nowhere to fall back to.
func TestAnOutgoingRowEchoesTheWholeMetadataObject(t *testing.T) {
	const metadata = `{"nostr":` + aZapRequest +
		`,"recipient_data":{"identifier":"alice@example.com"},"comment":"for the write-up"}`

	row := txnResult(store.Txn{
		Kind: "payment_out", State: "settled", AmountMsat: 21_000,
		OutMetadata: metadata,
		CreatedAt:   time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
	}, 0)

	decoded := nostrMetadata(t, row["metadata"])
	if decoded.RecipientData.Identifier != "alice@example.com" {
		t.Errorf("recipient_data.identifier came back as %q; without it a client renders "+
			"the row nameless until a profile resolves", decoded.RecipientData.Identifier)
	}
	if decoded.Comment != "for the write-up" {
		t.Errorf("comment came back as %q", decoded.Comment)
	}
	if decoded.Nostr.Kind != 9734 {
		t.Errorf("the nostr member came back as kind %d; it is the payee itself",
			decoded.Nostr.Kind)
	}
	// NOT DOUBLE-WRAPPED. The stored value already IS an NWC-06 object; wrapping
	// it again would bury the event at metadata.nostr.nostr and no client would
	// find it.
	encoded, err := json.Marshal(row["metadata"])
	if err != nil {
		t.Fatalf("the metadata does not encode: %v", err)
	}
	if strings.Contains(string(encoded), `"nostr":{"nostr"`) {
		t.Errorf("the object was wrapped a second time:\n%s", encoded)
	}
}

// The invoice's commitment travels with the row, so a client can CHECK the
// attribution rather than trust this node for it.
//
// It matters because the history is served to every pairing, not only the one
// that made the payment. A client hashes `metadata.nostr` and compares; equal
// names the payee, different means the row's event is unattributed, absent means
// no claim was made.
func TestAnOutgoingRowCarriesTheInvoicesCommitment(t *testing.T) {
	const hash = "5c3f8b1d0a9e7c6b4d2f8a1e0c9b7d6a5f4e3c2b1a0908070605040302010fed"
	row := txnResult(store.Txn{
		Kind: "payment_out", State: "settled", AmountMsat: 21_000,
		OutMetadata: nwcMetadata(aZapRequest), OutDescriptionHash: hash,
		CreatedAt: time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
	}, 0)

	if got := row["description_hash"]; got != hash {
		t.Errorf("description_hash = %#v, want the invoice's own commitment %q — a hash we "+
			"derived from the blob we are handing over would agree with it by construction "+
			"and prove nothing", got, hash)
	}

	// ABSENT rather than empty on a row that has none, which is the same call
	// every other optional field on this row makes: no claim is not a failed
	// claim, and a client must not read one as the other.
	bare := txnResult(store.Txn{
		Kind: "invoice_in", State: "settled", AmountMsat: 21_000,
		CreatedAt: time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC),
	}, 0)
	if _, present := bare["description_hash"]; present {
		t.Errorf("description_hash = %#v on a row with none", bare["description_hash"])
	}
}
