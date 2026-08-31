package nwc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/store"
)

// d24.12 / test-spec D5: every parameter reaches the query, or is refused.
//
// Asserted on the FILTER the dispatch built rather than on the rows that came
// back, because the bug was a parameter parsed and then dropped — and a
// row-shaped assertion passes against exactly that when the fixture happens to
// match.
func TestListTransactionsPassesEveryParameterThrough(t *testing.T) {
	h := newHarness(t)

	h.handle(t, MethodListTransactions, json.RawMessage(
		`{"from":1700000000,"until":1700003600,"limit":7,"offset":3,"unpaid":true,"type":"outgoing"}`))

	if len(h.invoices.filters) != 1 {
		t.Fatalf("the history was read %d times, want 1", len(h.invoices.filters))
	}
	got := h.invoices.filters[0]
	want := store.TxnFilter{
		From:      time.Unix(1_700_000_000, 0).UTC(),
		Until:     time.Unix(1_700_003_600, 0).UTC(),
		Limit:     7,
		Offset:    3,
		Paid:      store.IncludingUnpaid,
		Direction: store.Outgoing,
	}
	if !got.From.Equal(want.From) || !got.Until.Equal(want.Until) {
		t.Errorf("time window = %v..%v, want %v..%v", got.From, got.Until, want.From, want.Until)
	}
	if got.Limit != want.Limit || got.Offset != want.Offset {
		t.Errorf("limit/offset = %d/%d, want %d/%d", got.Limit, got.Offset, want.Limit, want.Offset)
	}
	if got.Paid != want.Paid {
		t.Error("unpaid was dropped; a client asking for unpaid invoices got settled ones")
	}
	if got.Direction != want.Direction {
		t.Errorf("direction = %v, want outgoing only", got.Direction)
	}
}

// The narrower unpaid parameters, which the test spec names as their own cases.
func TestListTransactionsHonoursTheDirectionalUnpaidParameters(t *testing.T) {
	cases := []struct {
		name   string
		params string
		paid   store.PaidFilter
		dir    store.Direction
	}{
		{"unpaid_incoming", `{"unpaid_incoming":true}`, store.UnpaidOnly, store.Incoming},
		{"unpaid_outgoing", `{"unpaid_outgoing":true}`, store.UnpaidOnly, store.Outgoing},
		{"both", `{"unpaid_incoming":true,"unpaid_outgoing":true}`, store.UnpaidOnly, store.EitherDirection},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)

			h.handle(t, MethodListTransactions, json.RawMessage(tc.params))

			if len(h.invoices.filters) != 1 {
				t.Fatalf("the history was read %d times, want 1", len(h.invoices.filters))
			}
			got := h.invoices.filters[0]
			if got.Paid != tc.paid || got.Direction != tc.dir {
				t.Errorf("filter = paid %v, direction %v; want %v and %v",
					got.Paid, got.Direction, tc.paid, tc.dir)
			}
		})
	}
}

// The other half of D5's rule: a parameter this build does not support is an
// ERROR, never silence. Silently ignoring a filter returns more than the client
// asked for, and it renders that as truth.
func TestListTransactionsRefusesWhatItDoesNotSupport(t *testing.T) {
	cases := []struct {
		name   string
		params string
		code   string
	}{
		{"an unknown type", `{"type":"sideways"}`, CodeOther},
		{"a direction named twice", `{"unpaid_incoming":true,"type":"outgoing"}`, CodeOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)

			resp := h.handle(t, MethodListTransactions, json.RawMessage(tc.params))

			if resp.Error == nil || resp.Error.Code != tc.code {
				t.Fatalf("%s answered %+v, want %s", tc.name, resp, tc.code)
			}
			if len(h.invoices.filters) != 0 {
				t.Errorf("the history was read anyway, with %+v; a refused filter must not "+
					"return a list the client will treat as filtered", h.invoices.filters[0])
			}
		})
	}
}

// Test-spec D4: an unknown hash is NOT_FOUND, not an empty success.
//
// An empty success says "this invoice exists and has no properties", which a
// client renders as a real invoice with blank fields.
func TestLookupInvoiceForAnUnknownHashIsNotFound(t *testing.T) {
	h := newHarness(t)

	resp := h.handle(t, MethodLookupInvoice,
		json.RawMessage(`{"payment_hash":"0000000000000000000000000000000000000000000000000000000000000000"}`))

	if resp.Error == nil || resp.Error.Code != CodeNotFound {
		t.Errorf("lookup_invoice for an unknown hash answered %+v, want NOT_FOUND", resp)
	}
}

// Test-spec B4: the info event names both schemes, in preference order.
//
// It is what a client uses to choose, so a list that named only what we happen
// to have implemented first would push every client onto NIP-04.
func TestTheInfoEventNamesBothEncryptionSchemes(t *testing.T) {
	h := newHarness(t)

	event, err := h.service.infoEvent(t.Context(), h.conn)
	if err != nil {
		t.Fatal(err)
	}

	tag := event.Tags.GetFirst([]string{"encryption"})
	if tag == nil {
		t.Fatal("the info event carries no encryption tag; a client cannot tell what we speak")
	}
	if got := tag.Value(); got != "nip44_v2 nip04" {
		t.Errorf("encryption = %q, want %q — NIP-44 first, because the order is a preference "+
			"and NIP-04 is the fallback", got, "nip44_v2 nip04")
	}
}

// Test-spec C4, AMENDED — see the dated note in the test spec.
//
// C4 asked for a replay re-encrypted under the retry's scheme "when it differs
// from the original's". That case cannot occur: the encryption tag and the
// content are both covered by the event id, and d24.3's CheckID gate refuses an
// event whose id does not match its body. A redelivery of request id X therefore
// always carries X's scheme, and one that carried another would not be a replay
// — it would be a forgery, and is refused as one.
//
// What IS true, and is what the plaintext cache buys, is asserted here: the
// replay is FRESHLY SEALED rather than served as stored ciphertext. The stored
// row is plaintext, so the answer can still be produced after anything that
// invalidates old ciphertext — a rotated service key being the case that
// matters — and each delivery gets its own nonce.
func TestAReplayIsFreshlySealedFromPlaintext(t *testing.T) {
	h := newHarness(t)
	h.wallet.balance = 4_242

	first := h.requestWith(t, h.client, nostr.NIP44, MethodGetBalance, nil, h.clock.at)
	if _, answered := h.service.handle(t.Context(), h.conn, first); !answered {
		t.Fatal("the first request was not answered")
	}

	// The cache row is PLAINTEXT: readable without a key, which is the whole
	// reason the response can be re-sealed rather than replayed byte for byte.
	stored, found, err := h.db.NWCHandledResponse(t.Context(), first.ID)
	if err != nil || !found {
		t.Fatalf("NWCHandledResponse: found=%v err=%v", found, err)
	}
	if !strings.Contains(stored, "4242") {
		t.Errorf("the cached row is %q; §8 stores the response as plaintext", stored)
	}

	before := h.wallet.balanceCalls()
	if _, answered := h.service.handle(t.Context(), h.conn, first); !answered {
		t.Fatal("the replay was not answered")
	}
	if h.wallet.balanceCalls() != before {
		t.Error("the replay executed the request again")
	}

	published := h.relays.published()
	if len(published) != 2 {
		t.Fatalf("%d responses were published, want 2", len(published))
	}
	if published[0].Content == published[1].Content {
		t.Error("the replay reused the first response's ciphertext byte for byte; each sealing " +
			"must have its own nonce")
	}
	for i, event := range published {
		plaintext, err := h.client.Decrypt(nostr.NIP44, h.conn.row().ServicePubkey, event.Content)
		if err != nil {
			t.Fatalf("response %d could not be read by the client that asked: %v", i, err)
		}
		if !strings.Contains(plaintext, "4242") {
			t.Errorf("response %d is %q, want the balance", i, plaintext)
		}
	}
}
