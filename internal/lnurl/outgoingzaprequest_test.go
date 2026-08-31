package lnurl_test

import (
	"encoding/hex"
	"strings"
	"testing"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
)

// commits is the description_hash a NIP-57 zap invoice minted for these bytes
// would carry: sha256 of the raw zap request, hex, which is exactly what
// lnurl.ZapHash produces on the minting side.
//
// Every case below passes the commitment to the bytes it is handing over, so
// each one still tests the rule it was written for rather than tripping over the
// binding on its way there. The binding has its own test.
func commits(t *testing.T, raw []byte) string {
	t.Helper()
	if len(raw) == 0 {
		return ""
	}
	hash, err := lnurl.ZapHash(raw)
	if err != nil {
		t.Fatalf("hashing the fixture: %v", err)
	}
	return hex.EncodeToString(hash[:])
}

// doy.4: an OUTGOING zap request is checked before it is stored, by the rules
// that mean something in that direction and by no others.
//
// THE AUDIT THIS BEAD REQUIRED, recorded here because a finding that lives only
// in a report is lost. ParseZapRequest was written for the inbound LNURL path,
// and four of its rules do not transfer:
//
//   - THE RELAYS TAG IS MANDATORY THERE, and it is mandatory because the relays
//     are where WE publish the receipt: a sender naming nowhere to read it is
//     what §7 calls reading as theft. On an outgoing request we publish nothing.
//     The payee's node does, to relays of its own choosing, and the tag is a
//     fact about someone else's publishing.
//   - keepDialable's SSRF FILTER drops relays this node must not dial, because
//     an inbound tag is a stranger choosing our outbound connections next to a
//     home router's admin page. Outbound, nothing is dialled at all, so the
//     filter's whole reason is absent — and applying it would silently discard a
//     payee's identity because their client happened to name a LAN relay.
//   - MaxZapRequestBytes is 8 KiB under a different spec. The metadata bound is
//     NWC-06's 4096 and is applied before this is ever reached, so the larger
//     one is dead here; sharing it would tie two limits with different threat
//     models.
//   - THE DOUBLE-ENCODING RESCUE is a tolerance for one client's URL escaping
//     (w0i). Metadata arrives as JSON inside a JSON-RPC request, so the rescue
//     has no transport to rescue and is deliberately not reached.
//
// AND THE ASSUMPTION THE BRIEF WARNED ABOUT IS NOT THERE. "Anything that assumes
// the p tag names THIS node" — checked, and nothing does: readTags validates the
// p tag's FORM and never compares it to our pubkey. So the p tag needed no
// special handling; it needed only to be required, because on an outgoing row it
// is the payee and the payee is the entire reason to keep the event.
func TestAnOutgoingZapRequestIsCheckedByTheRulesThatApplyToIt(t *testing.T) {
	const paid = 21_000

	t.Run("a signed request with no relays tag is accepted", func(t *testing.T) {
		// The single most important case here. Inbound this is a refusal; the
		// rule exists so a receipt has somewhere to go, and an outgoing request
		// produces no receipt of ours.
		raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
			e.Tags = gonostr.Tags{{"p", lnurltest.Hex64('a')}}
		})
		if err := lnurl.CheckOutgoingZapRequest(raw, paid, commits(t, raw)); err != nil {
			t.Errorf("refused a relayless outgoing request: %v — that rule is about where WE "+
				"publish a receipt, and we publish none for a zap we sent", err)
		}
	})

	t.Run("a relay this node would never dial is accepted", func(t *testing.T) {
		raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
			e.Tags = gonostr.Tags{
				{"p", lnurltest.Hex64('a')},
				{"relays", "ws://192.168.77.1", "ws://127.0.0.1"},
			}
		})
		if err := lnurl.CheckOutgoingZapRequest(raw, paid, commits(t, raw)); err != nil {
			t.Errorf("refused over a LAN relay: %v — nothing here is dialled, so the SSRF "+
				"filter would only be discarding a payee's identity", err)
		}
	})

	t.Run("no amount tag is accepted", func(t *testing.T) {
		raw := lnurltest.SignedZapRequest(t, nil)
		if err := lnurl.CheckOutgoingZapRequest(raw, paid, commits(t, raw)); err != nil {
			t.Errorf("the amount tag is optional in NIP-57: %v", err)
		}
	})

	t.Run("the amount tag must agree with what was paid", func(t *testing.T) {
		raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
			e.Tags = append(e.Tags, gonostr.Tag{"amount", "21000"})
		})
		if err := lnurl.CheckOutgoingZapRequest(raw, paid, commits(t, raw)); err != nil {
			t.Fatalf("an agreeing amount tag was refused: %v", err)
		}
		if err := lnurl.CheckOutgoingZapRequest(raw, 1_000_000, commits(t, raw)); err == nil {
			t.Error("an amount tag saying 21,000 msat was accepted for a 1,000,000 msat " +
				"payment; the row would claim the operator zapped an amount they did not")
		}
	})
}

// The three checks that carry the whole value of doing this at all.
//
// A stored outgoing request that has passed these is a fact this node checked,
// not a claim the client made — which is what lets it sit in a column read the
// same way as the incoming one.
func TestAnOutgoingZapRequestMustBeSignedIntactAndBeAZapRequest(t *testing.T) {
	const paid = 21_000
	valid := lnurltest.SignedZapRequest(t, nil)

	t.Run("the fixture itself passes", func(t *testing.T) {
		if err := lnurl.CheckOutgoingZapRequest(valid, paid, commits(t, valid)); err != nil {
			t.Fatalf("the valid fixture was refused, so every case below proves nothing: %v",
				err)
		}
	})

	t.Run("a tampered content breaks the signature", func(t *testing.T) {
		// A VALUE, not a key: corrupting a key makes the JSON parse into an
		// event missing a field, which is refused before the signature is ever
		// checked — proving the parser works rather than the signature does.
		tampered := strings.Replace(string(valid), `"content":""`, `"content":"stolen"`, 1)
		if tampered == string(valid) {
			t.Fatal("the tamper matched nothing; this test would pass on any implementation")
		}
		if err := lnurl.CheckOutgoingZapRequest([]byte(tampered), paid, commits(t, []byte(tampered))); err == nil {
			t.Error("a request whose content was rewritten after signing was accepted")
		}
	})

	t.Run("a rewritten id is refused", func(t *testing.T) {
		// go-nostr's CheckSignature recomputes the id and verifies against THAT,
		// never looking at the id field — so an event can carry a good signature
		// and a wrong id, and only CheckID notices.
		rewritten := lnurltest.WithRewrittenID(t, valid, lnurltest.Hex64('b'))
		if err := lnurl.CheckOutgoingZapRequest(rewritten, paid, commits(t, rewritten)); err == nil {
			t.Error("an event whose id field was rewritten was accepted; the id is what a " +
				"client uses to recognise the event, and the signature does not cover it")
		}
	})

	// The three that are one shape: sign a well-formed event with one thing
	// wrong about it, and it must be refused.
	for _, c := range []struct {
		name   string
		mutate func(*gonostr.Event)
		why    string
	}{
		{"another kind", func(e *gonostr.Event) { e.Kind = 1 },
			"a kind 1 note was accepted as a zap request"},
		// The payee rule is not a safety one — it is completeness. The p tag IS
		// the payee on an outgoing row, and an event without one has nothing
		// this column exists to carry.
		{"no payee", func(e *gonostr.Event) {
			e.Tags = gonostr.Tags{{"relays", "wss://relay.example"}}
		}, "a zap request naming no payee was accepted; there is nothing to label the row with"},
		{"two p tags", func(e *gonostr.Event) {
			e.Tags = append(e.Tags, gonostr.Tag{"p", lnurltest.Hex64('c')})
		}, "two p tags were accepted; NIP-57 says exactly one, and a row cannot show two " +
			"payees for one payment"},
	} {
		t.Run(c.name+" is refused", func(t *testing.T) {
			raw := lnurltest.SignedZapRequest(t, c.mutate)
			if err := lnurl.CheckOutgoingZapRequest(raw, paid, commits(t, raw)); err == nil {
				t.Error(c.why)
			}
		})
	}

	t.Run("junk is refused", func(t *testing.T) {
		for _, raw := range []string{``, `not json`, `{}`, `null`, `[]`} {
			if err := lnurl.CheckOutgoingZapRequest([]byte(raw), paid, commits(t, []byte(raw))); err == nil {
				t.Errorf("%q was accepted", raw)
			}
		}
	})
}

// y09: the invoice's own commitment is the only rule here that consults
// something the client did not write, and it is what makes the rest add up to a
// fact rather than a claim.
//
// Outbound the signer is the PAYER — the paying app chose that key — so a valid
// signature over a well-formed event proves only that the app authored it. The
// event's `p` tag is the payee an operator's history will name, and before this
// nothing said the event was about the payment it arrived with.
func TestAnOutgoingZapRequestMustHashToWhatTheInvoiceCommittedTo(t *testing.T) {
	const paid = 21_000
	mine := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
		e.Content = "for the write-up"
	})
	// Signed just as validly, and about a different payment entirely — which is
	// the attack: a bolt11 to a destination the caller controls, labelled with
	// somebody else's npub.
	somebodyElses := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
		e.Content = "monthly support"
		e.Tags = gonostr.Tags{{"p", lnurltest.Hex64('d')}, {"relays", "wss://relay.example"}}
	})

	if err := lnurl.CheckOutgoingZapRequest(mine, paid, commits(t, mine)); err != nil {
		t.Fatalf("the event the invoice commits to was refused: %v", err)
	}
	if err := lnurl.CheckOutgoingZapRequest(somebodyElses, paid,
		commits(t, mine)); err == nil {
		t.Error("an event the invoice does not commit to was accepted; it is signed and " +
			"self-consistent, and it names a payee this payment never had")
	}
	// A commitment nobody supplied rejects too, so a caller that forgets the
	// argument cannot silently get the old behaviour back.
	if err := lnurl.CheckOutgoingZapRequest(mine, paid, ""); err == nil {
		t.Error("an empty description_hash was accepted; passing no commitment must not " +
			"mean \"do not check\"")
	}
	// LND spells the hash in whatever case it spells it; a case difference is
	// not a mismatch.
	if err := lnurl.CheckOutgoingZapRequest(mine, paid,
		strings.ToUpper(commits(t, mine))); err != nil {
		t.Errorf("an upper-case commitment was refused: %v", err)
	}
}
