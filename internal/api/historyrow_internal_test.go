package api

import (
	"strings"
	"testing"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/web"
)

// The receipt switch reports on receipts, and an OUTGOING row has none to report
// on (doy.2).
//
// It is not that an outgoing zap's receipt is missing — there is no such thing.
// The kind 9735 receipt is what a node publishes for a zap it RECEIVED; a zap
// this node sent is acknowledged by the payee's node, not by ours. So every arm
// of this switch is a statement about the wrong direction, and the default arm is
// the one that lands: "receipt abandoned", which §7 calls the case that reads as
// theft. On the operator's own history, on every zap they sent.
//
// The gate is IsZap, which the store derives from `zap_request` alone. This test
// is the rendering half of the same guarantee internal/store's
// TestAnOutgoingZapRequestRoundTripsWithoutMakingTheRowAZap makes at the storage
// end — two halves, because either one could be undone alone.
func TestAnOutgoingRowRendersNoReceiptState(t *testing.T) {
	const metadata = `{"nostr":{"kind":9734,"pubkey":"79be6","content":"thanks",` +
		`"tags":[["p","04c91"]]}}`
	row := historyRow(store.Txn{
		Kind: "payment_out", State: "settled", AmountMsat: 21_000,
		PaymentHash: "hash", OutMetadata: metadata,
	})

	if row.Receipt != "" {
		t.Errorf("an outgoing zap renders Receipt = %q. There is no receipt for a zap this "+
			"node SENT — the kind 9735 is published by the payee's node — so any state here "+
			"is a claim about the wrong direction, and %q in particular is the one that "+
			"reads as theft.", row.Receipt, web.ReceiptAbandoned)
	}
	if row.ReceiptID != "" {
		t.Errorf("ReceiptID = %q on an outgoing row", row.ReceiptID)
	}
}

// And the incoming case still reaches every arm, so the fix cannot have been "do
// not render receipts".
func TestAnIncomingZapStillReportsItsReceiptState(t *testing.T) {
	for _, c := range []struct {
		name string
		txn  store.Txn
		want string
	}{
		{"published", store.Txn{
			Kind: "invoice_in", IsZap: true, ZapReceiptID: "abcdef0123456789",
		}, web.ReceiptPublished},
		{"pending", store.Txn{
			Kind: "invoice_in", IsZap: true, ReceiptPending: true,
		}, web.ReceiptPending},
		{"abandoned", store.Txn{
			Kind: "invoice_in", IsZap: true,
		}, web.ReceiptAbandoned},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := historyRow(c.txn).Receipt; got != c.want {
				t.Errorf("Receipt = %q, want %q", got, c.want)
			}
		})
	}
}

// doy.5: an outgoing zap says who it paid and what it said, on the operator's
// own page.
//
// The same information the paired NWC client gets, one screen over. Before this
// the operator's history showed a column of unlabelled debits while every
// incoming row carried its zap comment — the same blank, on the same data, for
// the same reason.
//
// A SHORTENED npub AND NO FETCH. Resolving a kind 0 profile to a display name
// would be a new outbound path from the server container, at page-render time,
// against relays chosen by whoever the operator paid. This function has no
// context to make a request with, which is how that stays true rather than being
// remembered.
func TestAnOutgoingZapNamesItsPayeeAndCarriesItsComment(t *testing.T) {
	// From the shared builder rather than a hand-rolled JSON literal: three
	// packages once each grew their own zap-request fixture, which is the reason
	// lnurltest exists.
	const payee = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	event := string(lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
		e.Content = "thanks for the write-up"
		e.Tags = gonostr.Tags{{"p", payee}, {"relays", "wss://relay.example"}}
	}))
	// The whole NWC-06 object, as the column now holds it — including the
	// sibling this page must NOT render. See the last assertion.
	metadata := `{"nostr":` + event + `,"recipient_data":{"identifier":"trusted@example.com"}}`

	row := historyRow(store.Txn{
		Kind: "payment_out", State: "settled", AmountMsat: 21_000,
		PaymentHash: "hash", OutMetadata: metadata,
	})

	want := shortNpub(payee)
	if want == "" {
		t.Fatal("the fixture's payee is not a pubkey; every assertion below is vacuous")
	}
	if !strings.HasPrefix(want, "npub1") || !strings.Contains(want, "…") {
		t.Fatalf("shortNpub gave %q, which is not a shortened npub — the row would be "+
			"showing something else entirely", want)
	}
	if row.Payee != want {
		t.Errorf("Payee = %q, want %q", row.Payee, want)
	}
	if row.Comment != "thanks for the write-up" {
		t.Errorf("Comment = %q, want the zap message the operator wrote", row.Comment)
	}
	// AND THE LIGHTNING ADDRESS IS NOT THE NAME, which is the security half of
	// reading only `nostr`. `recipient_data.identifier` is the friendlier label
	// and it is NOT covered by the invoice's commitment — the hash is over the
	// event — so a bound event can travel beside a lying address. It is stored
	// for the client that sent it and it is never presented here as the payee.
	if strings.Contains(row.Payee, "trusted@example.com") ||
		strings.Contains(row.Comment, "trusted@example.com") {
		t.Errorf("the page rendered recipient_data.identifier (Payee=%q Comment=%q); that "+
			"field is an unverified claim and naming it would reopen exactly the "+
			"substitution the commitment closes", row.Payee, row.Comment)
	}
	// AND STILL NO RECEIPT STATE. The label must not have arrived by routing
	// this row through the switch that would also give it one.
	if row.Receipt != "" {
		t.Errorf("Receipt = %q; labelling the row must not have taken it through the "+
			"receipt switch", row.Receipt)
	}
}

// A payee this node cannot make sense of leaves the row exactly as it was.
//
// The pubkey comes out of a blob a paired client sent us, so "render whatever is
// in the column" would put a client-chosen string on the operator's page. A row
// shows a payee or it shows none.
func TestAnUnreadableOutgoingZapLeavesTheRowUnlabelled(t *testing.T) {
	for _, c := range []struct{ name, event string }{
		{"not an object at all", `{"nostr":{"kind":9734,`},
		{"no nostr member", `{"recipient_data":{"identifier":"alice@example.com"}}`},
		{"no p tag", `{"nostr":{"kind":9734,"content":"hi",` +
			`"tags":[["relays","wss://r.example"]]}}`},
		{"a payee that is not a pubkey",
			`{"nostr":{"kind":9734,"content":"hi","tags":[["p","<script>alert(1)</script>"]]}}`},
		{"two payees", `{"nostr":{"kind":9734,"content":"hi","tags":[["p","` +
			strings.Repeat("a", 64) + `"],["p","` + strings.Repeat("b", 64) + `"]]}}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			row := historyRow(store.Txn{
				Kind: "payment_out", State: "settled", OutMetadata: c.event,
			})
			if row.Payee != "" {
				t.Errorf("Payee = %q, want nothing at all", row.Payee)
			}
			if row.Comment != "" {
				t.Errorf("Comment = %q; a row with no readable payee has no readable "+
					"comment either — both come out of the same blob", row.Comment)
			}
		})
	}
}

// An outgoing row with no zap request is untouched, which is every ordinary
// payment.
func TestAnOrdinaryOutgoingRowIsUnchanged(t *testing.T) {
	row := historyRow(store.Txn{
		Kind: "payment_out", State: "settled", AmountMsat: 21_000,
		Note: "a pasted bolt11", Description: "dinner",
	})
	if row.Payee != "" {
		t.Errorf("Payee = %q on a payment that carried no zap request", row.Payee)
	}
	if row.Note != "a pasted bolt11" {
		t.Errorf("Note = %q, want the operator's own reason", row.Note)
	}
}

// A payee the page cannot encode renders as nothing at all.
//
// The pubkey comes out of a blob a paired client sent us, so "render whatever
// was in the column" would put a client-chosen string onto the operator's page.
// This is the second gate — lnurl.ReadOutgoingMetadata already refuses a
// malformed payee — and it is here because the first one closing is not a reason
// for the last one before the template to be open.
func TestShortNpubRendersNothingForAnythingThatIsNotAPubkey(t *testing.T) {
	for _, bad := range []string{
		"",
		"not hex",
		"79be667e",
		strings.Repeat("z", 64),
		"npub1already",
		"<script>alert(1)</script>",
	} {
		if got := shortNpub(bad); got != "" {
			t.Errorf("shortNpub(%q) = %q, want nothing", bad, got)
		}
	}
}

// And a real one keeps both ends of the npub it shortened, because the ends are
// what a person compares against what their own client shows them.
func TestShortNpubKeepsBothEndsOfTheRealNpub(t *testing.T) {
	const pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	full, err := nostr.Npub(pubkey)
	if err != nil {
		t.Fatal(err)
	}
	short := shortNpub(pubkey)
	head, tail, found := strings.Cut(short, "…")
	if !found {
		t.Fatalf("shortNpub = %q, which carries no ellipsis; an identifier that does not "+
			"look shortened invites a character-by-character comparison", short)
	}
	if !strings.HasPrefix(full, head) || !strings.HasSuffix(full, tail) {
		t.Errorf("shortNpub = %q, which is not the two ends of %q", short, full)
	}
	if len(short) >= len(full) {
		t.Errorf("shortNpub = %q, no shorter than the npub itself", short)
	}
}
