package zap

import (
	"errors"
	"fmt"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/store"
)

// ReceiptKind is NIP-57's kind for the receipt this node publishes once a zap
// invoice settles.
const ReceiptKind = 9735

// ErrNotAZap is returned for an invoice that carries no zap request. It is an
// ordinary LNURL payment, and there is nothing to publish.
var ErrNotAZap = errors.New("zap: the invoice carries no zap request")

// Build assembles the unsigned kind 9735 receipt for a settled invoice (§7).
//
// created_at is the invoice's SETTLE time, carried on the row. Never now():
// a receipt built during a retry — which §7 allows to run for a day — would
// otherwise tell every reader the zap happened a day after it did, and the
// sender's client orders and matches on that timestamp.
//
// The zap request is re-parsed through lnurl.ParseZapRequest rather than
// trusted because it came out of our own database. That re-checks the
// signature AND the event id, which matters in the direction Wave 8 found from
// the other side: CheckSignature recomputes the id and never reads the id
// field, so an event can carry a valid signature and a wrong id. A receipt
// whose description tag holds such an event verifies locally and is discarded
// by every conforming client — after the invoice has been paid.
func Build(z store.SettledZap) (*gonostr.Event, []string, error) {
	if z.ZapRequest == "" {
		return nil, nil, ErrNotAZap
	}
	// The bytes as stored, which are the bytes that were hashed into the
	// invoice's description_hash and the bytes whose signature was checked at
	// the callback. Not a re-serialisation: §16's failure in a third place.
	//
	// The description tag below takes them from the VERIFIED request rather than
	// from this local, so the two cannot be different bytes. They are the same
	// today, but ParseZapRequest is no longer an identity on Raw — rule 3's
	// double-encoding fallback (BrollyZap-w0i) returns the decoded form — and
	// "the tag is the bytes whose signature was checked" must hold by
	// construction rather than because two lines happen to agree.
	raw := []byte(z.ZapRequest)
	// AGAINST THE MINTED AMOUNT, not the paid one (`0vk.15`). Appendix D rule 5
	// compares the request's `amount` tag with what the sender asked for, which
	// is what the invoice was minted for; NIP-57 never relates the tag to what
	// LND received. LND accepts overpayment, so checking against the paid amount
	// meant an overpaid zap was credited and then left with no receipt.
	verified, err := lnurl.ParseZapRequest(raw, z.MintedMsat)
	if err != nil {
		return nil, nil, fmt.Errorf("zap: the stored zap request for %s no longer parses: %w",
			z.PaymentHash, err)
	}
	request := verified.Request()

	tags := gonostr.Tags{
		{"p", request.Recipient},
		{"bolt11", z.Bolt11},
		// The description tag is the zap request verbatim. A client recomputes
		// sha256 over exactly these bytes and compares it to the invoice's
		// description_hash, so anything that re-encodes them here breaks every
		// receipt this node will ever publish (§7, §16).
		{"description", string(request.Raw)},
		// The sender's own pubkey, so a client can attribute the zap without
		// re-parsing the description tag. Uppercase P per NIP-57, and it is the
		// REQUEST's author — the optional lowercase-P override inside the
		// request names who paid on whose behalf and is not this.
		{"P", request.Event.PubKey},
	}
	// e and a only when the request carried them. A profile zap has neither,
	// and the prior art nil-dereferences exactly here (§7).
	if request.EventID != "" {
		tags = append(tags, gonostr.Tag{"e", request.EventID})
	}
	if request.Coordinate != "" {
		tags = append(tags, gonostr.Tag{"a", request.Coordinate})
	}
	// k, the same way: only when the request carried one (o34.20). NIP-57's
	// Appendix E example receipt has one, and a client that reads it here is
	// spared fetching the zapped event to learn what kind it was.
	if request.TargetKind != "" {
		tags = append(tags, gonostr.Tag{"k", request.TargetKind})
	}
	// The ONE place the preimage is revealed. §11 keeps preimages out of logs;
	// NIP-57 puts this one in a public event on purpose, as the sender's proof
	// that the invoice they paid actually settled. Deliberate, named, and not
	// something a formatted struct can do by accident.
	if preimage := z.Preimage.Reveal(); preimage != "" {
		tags = append(tags, gonostr.Tag{"preimage", preimage})
	}

	// The relays come from the parse just performed, not from a stored copy.
	// internal/lnurl already filtered, normalised and deduplicated them on the
	// way in, and reading them back out of invoices.zap_relays made that list a
	// SECOND copy of a derived value — with its own silent-failure path on both
	// sides of the round trip, and a guarantee that the two stay identical
	// which nothing asserted and a future tightening of keepDialable would
	// break for old rows.
	return &gonostr.Event{
		Kind:      ReceiptKind,
		CreatedAt: gonostr.Timestamp(z.SettledAt.Unix()),
		// Empty, per §7. The receipt says nothing the tags do not.
		Content: "",
		Tags:    tags,
	}, request.Relays, nil
}
