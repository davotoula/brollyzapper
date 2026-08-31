package lnurl

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/nostr"
)

// ZapRequestKind is NIP-57's kind for the request a client sends to the
// callback.
const ZapRequestKind = 9734

// Bounds on what an anonymous caller may send.
//
// Every one of these is a disk or a socket an unauthenticated stranger would
// otherwise choose the size of. A real zap request is well under 2 KB and names
// a handful of relays.
const (
	// MaxZapRequestBytes bounds the parameter before it is parsed, hashed or
	// stored. invoices.zap_request keeps the bytes verbatim and ExpireInvoices
	// only marks rows expired — it never deletes them — so an unbounded
	// parameter is permanent growth on an SD card, paid for by nobody.
	MaxZapRequestBytes = 8 << 10
	// MaxZapRelays bounds the relays tag. These are the URLs o34.3 publishes
	// the receipt to, so an unbounded list lets the sender choose how many
	// outbound WebSocket connections this node opens, and to where.
	//
	// Eight, down from thirty-two (0ak). NIP-57 clients name three to eight in
	// practice; the old ceiling was picked without a measurement, and it is the
	// number of sockets a stranger can ask this node to open at once.
	//
	// Relays beyond the cap are DROPPED, not grounds for refusing the zap. A
	// sender naming nine relays has done nothing wrong, and answering a
	// well-formed zap with a rejection because the cap moved would turn a
	// tightening of ours into their failed payment. The refusal is reserved for
	// a request that names nowhere at all.
	//
	// An ECHO of the pool's own bound, not a second opinion (zmn). The package
	// that owns the sockets owns the number; this one applies it early, where a
	// caller can still be told why, and where it also bounds what gets stored.
	// Two independently written eights would have been two numbers that agree
	// until someone changes one.
	MaxZapRelays = nostr.MaxTransientRelays
)

// Rejection is a refusal an anonymous caller may be shown.
//
// The reason names the RULE that failed rather than describing internals: §7
// requires a clear reason, and the caller is a stranger's wallet whose author
// needs to know which of Appendix D's seven rules it broke.
type Rejection struct{ Reason string }

func (r *Rejection) Error() string { return r.Reason }

func reject(format string, args ...any) error {
	return &Rejection{Reason: fmt.Sprintf(format, args...)}
}

// ZapRequest is a validated NIP-57 request, kept with the bytes the sender
// SIGNED.
//
// Raw is the whole point: it is what description_hash covers and what o34.3's
// receipt carries verbatim as its description tag (§7, §16). Nothing here is
// ever re-serialised back into it.
//
// "Signed" rather than "as it arrived", and the difference is new: rule 3's
// double-encoding fallback (BrollyZap-w0i) can return the DECODED form of what
// arrived. Signed is the stronger claim and the one every consumer actually
// needs — it is what the signature was checked over and what a client
// recomputes the id from.
type ZapRequest struct {
	Raw       []byte
	Event     gonostr.Event
	Recipient string
	// EventID and Coordinate are the optional e and a tags. Empty when absent —
	// a PROFILE zap has neither, and the prior art nil-dereferences exactly
	// there (§7).
	EventID    string
	Coordinate string
	// TargetKind is the optional k tag: the stringified kind of the event being
	// zapped (NIP-57 Appendix A). Empty when absent, and carried to the receipt
	// verbatim like e and a — Appendix E's own example receipt has one, and a
	// client reading it there is spared fetching the event to learn what it is
	// (o34.20).
	TargetKind string
	// Sender is the optional P tag: who paid, when a service zaps on behalf of
	// someone.
	Sender string
	Relays []string
	// RelayDrops is what the relays tag lost here and why. The kept list alone
	// cannot answer "why fewer relays than the sender named", which is the
	// first question an operator asks about a receipt that went nowhere.
	RelayDrops RelayDrops
}

// RelayDrops accounts for every relay a zap request named.
//
// Named == kept + the three reasons + duplicates, always. An accounting that
// does not close is worse than none: it leaves a reader wondering which bucket
// the missing one fell into, which is the state this exists to end.
//
// Duplicates are counted even though the PM's ruling named three reasons. A
// sender listing the same relay twice is not an error and not interesting, but
// leaving it uncounted would break the arithmetic above and make the line
// unreadable in exactly the case it is needed.
type RelayDrops struct {
	// Named is how many values the relays tag carried, before anything.
	Named int
	// LiteralPrivate is the allow-list's refusals: a LAN address, loopback, a
	// single-label name, a reserved range.
	LiteralPrivate int
	// OverCap is everything past MaxZapRelays. The filter stops there, so
	// these were never examined — "we did not try", not "we tried and said no".
	OverCap int
	// BadScheme is anything that is not a ws:// or wss:// URL at all.
	BadScheme int
	// Duplicate is a relay the tag named more than once.
	Duplicate int
}

// Dropped is how many of the named relays did not survive.
func (d RelayDrops) Dropped() int {
	return d.LiteralPrivate + d.OverCap + d.BadScheme + d.Duplicate
}

// VerifiedZapRequest is a zap request this package has checked: signature,
// event id, and the whole of Appendix D. It is the only way to hand a zap
// request to Service.Callback.
//
// It is an INTERFACE with an unexported method, implemented by an unexported
// type, and that is the entire design. §11 and §16 require the signature to be
// checked before anything is minted, and that invariant used to hold for a dull
// reason: the check and the mint were in the same function. Moving the parse
// out to the api gate — so an honest sender is not charged two schnorr
// verifications for one zap — moves the invariant across a package boundary,
// and a boundary can only carry an invariant if it carries PROOF rather than a
// claim.
//
// A *ZapRequest plus a `verified bool` would be a claim: the receiver would
// have to trust the sender of the value. This is proof. No package outside
// internal/lnurl can construct one, because the concrete type is unexported;
// no package outside can implement the interface, because verified() is
// unexported; and no package can write a composite literal for it, because it
// is an interface. A callback holding one has necessarily been through
// ParseZapRequest, and ParseZapRequest constructs one only after both checks
// have passed.
type VerifiedZapRequest interface {
	// Request is the parsed request. Reading it is safe precisely because
	// holding this value means it was verified.
	Request() *ZapRequest
	// verified cannot be implemented outside this package. It is what makes
	// this type a proof rather than a label.
	verified()
}

// verifiedZapRequest is the only implementation, and is unexported so that no
// value satisfying VerifiedZapRequest can originate anywhere else.
type verifiedZapRequest struct{ request *ZapRequest }

func (v verifiedZapRequest) Request() *ZapRequest { return v.request }

func (verifiedZapRequest) verified() {}

// newVerifiedZapRequest is the SOLE constructor.
//
// Unexported, and called from exactly one place: the end of ParseZapRequest,
// after CheckSignature and CheckID have both succeeded. An arch rule asserts
// both of those facts, because they are what the type's guarantee rests on — a
// second call site somewhere that had not verified would make the proof a
// label again.
func newVerifiedZapRequest(request *ZapRequest) VerifiedZapRequest {
	return verifiedZapRequest{request: request}
}

// ZapParam is the ONE parse of a callback's nostr parameter, carried from the
// caller that performed it to the Service that mints on it.
//
// It holds a PROOF or a rejection, never a claim: verified cannot be
// constructed outside this package, and err is a reason to forward rather than
// a verdict to trust. Both nil — the zero value — means the request carried no
// nostr parameter, which is an ordinary LNURL payment. That is also what a
// caller which never parsed at all yields, and it is the safe reading: a plain
// invoice with no zap request attached, rather than one whose signature was
// never checked.
//
// The fields are unexported so the invariant "exactly one of these, or
// neither" is the type's rather than a sentence someone has to honour.
type ZapParam struct {
	verified VerifiedZapRequest
	err      error
	// rescued records that rule 3's fallback had to percent-decode this
	// delivery a second time before it would parse (BrollyZap-w0i). It lives
	// here rather than on ZapRequest because it is a fact about how these bytes
	// ARRIVED, not about the request: the same request re-parsed from the
	// database would set it false, and the gate is the only thing that reads it.
	rescued bool
}

// ParseZapParam performs the single verification of a callback's nostr
// parameter.
//
// A missing or unparseable amount yields the zero value rather than an error:
// the amount has its own refusal with its own reason, and §7's order is amount,
// then comment, then the zap request. Reporting a nostr problem to a caller
// whose amount is malformed sends a wallet author to the wrong line.
func ParseZapParam(query url.Values) ZapParam {
	raw := RawParam(query, "nostr")
	if len(raw) == 0 {
		return ZapParam{}
	}
	amountMsat, err := AmountMsat(query)
	if err != nil {
		return ZapParam{}
	}
	verified, err := ParseZapRequest(raw, amountMsat)
	if err != nil {
		return ZapParam{err: err}
	}
	// DERIVED, not carried on the request. Rewriting Raw is the only thing
	// ParseZapRequest can do to these bytes, so the comparison is exact — and
	// the rescue is a fact about how this DELIVERY arrived, not about the
	// request. Stored on ZapRequest it would read false when zap.Build
	// re-parses the same request off the database, which is the tell that it
	// was on the wrong type; ZapParam is the transport-scoped value, and this
	// is the only thing that needs to know (BrollyZap-w0i).
	return ZapParam{verified: verified, rescued: !bytes.Equal(raw, verified.Request().Raw)}
}

// SenderKey is the verified sender pubkey and whether this is a zap at all.
//
// Verified, not claimed. Keying a rate-limit bucket on a merely asserted pubkey
// would let anyone spend a specific honest sender's bucket by naming them —
// griefing one identified person rather than the anonymous crowd, which is
// worse than the collision problem such a bucket exists to fix.
func (z ZapParam) SenderKey() (string, bool) {
	if z.verified == nil {
		return "", false
	}
	return z.verified.Request().Event.PubKey, true
}

// DoubleEncodingRescue reports whether rule 3's fallback had to decode this
// request twice, and the client tag it named if it carried one — which is the
// only thing here that identifies WHOSE encoder needs fixing.
func (z ZapParam) DoubleEncodingRescue() (client string, rescued bool) {
	if !z.rescued {
		return "", false
	}
	// Tags.Find, not a hand-rolled scan: it already means "the first tag with
	// this key that also has a value", and it returns a nil SLICE when absent
	// rather than the nil *Tag that GetFirst hands back — which is the shape
	// that took the process down in `xmc`.
	if tag := z.verified.Request().Event.Tags.Find("client"); tag != nil {
		return tag[1], true
	}
	return "", true
}

// RelayDrops is what the relays tag lost at this parse, and whether there was a
// zap request to account for at all.
//
// Exposed on the param rather than reached through Request() so the caller does
// not have to hold the verified request to log about it, and cannot be tempted
// to read anything else off it on the way past.
func (z ZapParam) RelayDrops() (RelayDrops, bool) {
	if z.verified == nil {
		return RelayDrops{}, false
	}
	return z.verified.Request().RelayDrops, true
}

// Rejected reports whether a nostr parameter was present and failed. A caller
// uses it to skip work that a request which cannot mint would only waste.
func (z ZapParam) Rejected() bool { return z.err != nil }

// AmountMsat reads the callback's amount parameter, with §7's own reason for
// refusing it. One definition, because the limiter and the mint both need it
// and two would drift.
func AmountMsat(query url.Values) (int64, error) {
	amountMsat, err := strconv.ParseInt(strings.TrimSpace(query.Get("amount")), 10, 64)
	if err != nil {
		return 0, reject("amount must be a number of millisatoshis")
	}
	return amountMsat, nil
}

// decodeDoubleEncoded undoes ONE extra layer of percent-encoding, for a client
// that encoded the nostr parameter twice (BrollyZap-w0i, Primal Web).
//
// TEMPORARY. Remove once Primal Web ships its fix — reviewed 2026-10-01. The
// upstream report and the reasoning for tolerating it at all are in the
// project's private notes; the summary is the paragraph above.
// ZapRequest.RescuedDoubleEncoding drives the DEBUG line that says whether
// anything still needs this.
//
// GUARDED ON THE PREFIX, not on the parse error. A doubly-encoded JSON event can
// begin with nothing but an encoded `{` or `"`, so this stays off every other
// malformed input and the refusal reason still means what it says for genuine
// garbage. Either hex case, because RFC 3986 permits both and an encoder that
// gets the layering wrong is not one to trust about capitalisation.
//
// ONCE, never in a loop: two encodings is the bug in the wild, and a loop makes
// the failure mode unbounded.
//
// PathUnescape rather than QueryUnescape, which also turns "+" into a space.
// Only one of those two directions is safe, and it is not a matter of taste: on
// a form-encoded inner layer QueryUnescape would reproduce the original content
// and therefore VERIFY, so a literal "+" inside a signed body could be rewritten
// as a space and the request ACCEPTED with content the sender never wrote.
// Leaving "+" alone can only ever fail the signature, which is a loud refusal.
// Pinned by TestAFormEncodedInnerLayerIsRefusedRatherThanCorrupted, which goes
// red under QueryUnescape.
//
// The caller attempts this ONLY after a parse has already failed, which is what
// keeps a well-formed request carrying a literal percent sequence in its content
// from being quietly rewritten.
func decodeDoubleEncoded(raw []byte) ([]byte, bool) {
	head := raw
	if len(head) > 3 {
		head = head[:3]
	}
	if !strings.EqualFold(string(head), "%7B") && !strings.EqualFold(string(head), "%22") {
		return nil, false
	}
	decoded, err := url.PathUnescape(string(raw))
	if err != nil {
		return nil, false
	}
	return []byte(decoded), true
}

// checkSignedZapRequest is the part both directions share: this is a kind 9734
// event, it is signed by the pubkey it names, and its id is the one its contents
// hash to.
//
// ABOVE ParseZapRequest ON PURPOSE, and internal/arch cares. The rule that a
// VerifiedZapRequest is never constructed above its own verification reads this
// file's LAST CheckSignature/CheckID lines; moving this helper below the
// constructor's call site would trip it. The rule also recognises a call to this
// function, so the ordering it asserts is the real one rather than a coincidence
// of where the text sits.
func checkSignedZapRequest(event *gonostr.Event) error {
	if event.Kind != ZapRequestKind {
		return reject("a zap request is kind %d, not %d", ZapRequestKind, event.Kind)
	}
	// Before ANY invoice is minted (§11). Signature first, so a forged request
	// costs the node nothing.
	valid, err := event.CheckSignature()
	if err != nil || !valid {
		return reject("the zap request signature is not valid")
	}
	// CheckSignature recomputes the id from the serialisation and verifies
	// against THAT — it never looks at the id field. So an event can carry a
	// valid signature and a wrong id, and these bytes are what o34.3's receipt
	// carries verbatim as its description tag: a conforming client recomputes
	// the id, finds it does not match, and discards the receipt — after the
	// invoice has been paid.
	if !event.CheckID() {
		return reject("the zap request id does not match its contents")
	}
	return nil
}

// CheckOutgoingZapRequest verifies a zap request this node did NOT receive: one
// a paired NWC client signed and handed us with a payment it asked us to make
// (NWC-06, doy.4).
//
// A NARROWER VERIFIER RATHER THAN A REUSE OF ParseZapRequest, and the audit that
// settled it is written out in the test beside this file. In short: four of that
// function's rules are inbound-only — the mandatory relays tag and keepDialable's
// SSRF filter exist because an inbound tag decides where WE publish and what WE
// dial, and outbound we do neither; MaxZapRequestBytes belongs to another spec
// and is dead behind NWC-06's tighter bound; and w0i's double-encoding rescue is
// a tolerance for one client's URL escaping, which JSON-RPC metadata has no
// transport to need. What DOES transfer is everything that makes the row a fact:
// kind, signature, id, the amount tag against the amount actually paid, and
// exactly one well-formed p tag — which is not a safety rule but a completeness
// one, since outbound that tag IS the payee and a row without it has nothing
// this column exists to carry.
//
// SIGNATURE AND ID ARE SELF-CONSISTENCY, NOT TRUTH, which is why descriptionHash
// is a parameter (y09, from a security review of the branch that added this).
// Outbound the signer is the PAYER, so the caller chose that key: a valid
// signature over a well-formed event proves only that the caller authored it.
// Nothing in kind, signature, id or the p tag's shape says the event is about
// THIS payment, and the amount tag is optional, so omitting it skipped the one
// external cross-check there was. A paired app could therefore name any payee it
// liked on any payment it made.
//
// The invoice's own commitment is what closes that. A NIP-57 zap invoice commits
// to description_hash = sha256 of the raw zap request — the rule ZapHash mints
// with, read backwards — and it covers the payee, the comment and the amount in
// one comparison. Pass the hash the node decoded off the invoice being paid; a
// caller with no such hash should not be calling this, and passing "" rejects.
//
// IT MINTS NO VerifiedZapRequest. That type is §11's proof that a signature was
// checked before an invoice was minted, on the inbound path, and there is
// exactly one place it may come into existence. This answers a different
// question — "is this worth storing" — and an error is the whole of its answer.
//
// THE CALLER MUST NOT FAIL A PAYMENT OVER THIS. An error means the blob is
// dropped and the money still moves; a cosmetic field that can block a payment
// is a worse bug than a blank row.
func CheckOutgoingZapRequest(raw []byte, amountMsat int64, descriptionHash string) error {
	var event gonostr.Event
	if len(raw) == 0 || event.UnmarshalJSON(raw) != nil {
		return reject("the metadata's nostr member is not a JSON event")
	}
	if err := checkSignedZapRequest(&event); err != nil {
		return err
	}
	// The one cross-check against something OUTSIDE the event, and the only
	// reason it means anything here: the client fetched the invoice with this
	// amount, and we are about to pay that invoice. A row claiming an amount the
	// operator did not send is a wrong statement about their own money.
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "amount" {
			if err := checkAmountTag(tag[1], amountMsat); err != nil {
				return err
			}
		}
	}
	if err := payeeProblem(outgoingZapFields(&event)); err != nil {
		return err
	}
	// THE ONLY RULE HERE THAT CONSULTS SOMETHING THE CLIENT DID NOT WRITE, and
	// the reason the rest of them add up to a fact rather than a claim.
	committed, err := ZapHash(raw)
	if err != nil {
		// Unreachable: raw is non-empty by the first check above. Its own arm
		// rather than folded into the comparison, so an internal condition can
		// never be reported to an operator as a hash mismatch.
		return reject("the nostr member is empty")
	}
	if !strings.EqualFold(hex.EncodeToString(committed[:]), descriptionHash) {
		// EqualFold because the hex is LND's spelling of the invoice's own bytes,
		// and a case difference is not a mismatch.
		return reject("the event does not hash to the invoice's description_hash")
	}
	return nil
}

// OutgoingZap is what a stored outgoing zap request says about itself, for a
// page that has to label the row (doy.5).
type OutgoingZap struct {
	// Payee is the p tag: the party this payment paid. NOT the event's pubkey,
	// which outbound is the payer — the operator, or a throwaway key for an
	// anonymous zap.
	Payee string
	// Comment is the event's content: the zap message, in the operator's own
	// words.
	Comment string
}

// NostrMember is the `nostr` member of an NWC-06 `metadata` object: its raw
// bytes, empty when the object carries none, and ok false when what was handed
// over is not a JSON object at all.
//
// THE ENVELOPE'S SHAPE IS DECLARED ONCE, here, because two packages read it: the
// pay path, which needs the member to bind it against the invoice, and the row
// reader below, which needs it to find the payee. Two anonymous structs is two
// places to change when NWC-06 grows a member (review).
//
// The two outcomes are kept apart because their callers act differently on them:
// "not an object" is a client fault worth logging, and "no nostr member" is the
// ordinary case — a pasted bolt11 sends `recipient_data` and a comment, or
// nothing.
func NostrMember(metadata []byte) (json.RawMessage, bool) {
	var envelope struct {
		Nostr json.RawMessage `json:"nostr"`
	}
	if err := json.Unmarshal(metadata, &envelope); err != nil {
		return nil, false
	}
	return bytes.TrimSpace(envelope.Nostr), true
}

// ReadOutgoingMetadata reads the two things a row displays out of the NWC-06
// metadata object this node has already stored.
//
// FROM THE `nostr` MEMBER AND NOTHING ELSE, which is a security decision rather
// than a convenience. The object's `recipient_data.identifier` — the payee's
// lightning address — is the friendlier label and it is NOT covered by the
// invoice's commitment: the hash is over the event, so a bound event can travel
// beside a lying address. It is stored, because it is the client's own data going
// back to the client, and it is not read here, because this node must not present
// an unverified name as the payee. The `p` tag is what the commitment covers.
//
// NO VERIFICATION, deliberately. The signature, the id, the amount and the
// binding were all checked once, before the row was written. Re-running a schnorr
// verification per row to draw a table would be paying for the same answer on
// every page load, and would make a rendering path fail for a reason that belongs
// to the write path.
//
// ok is false when there is no readable event naming a single payee — in which
// case the row simply carries no label, which is what it carried before this
// existed.
func ReadOutgoingMetadata(raw string) (OutgoingZap, bool) {
	nostr, ok := NostrMember([]byte(raw))
	if !ok || len(nostr) == 0 {
		return OutgoingZap{}, false
	}
	var event gonostr.Event
	if event.UnmarshalJSON(nostr) != nil {
		return OutgoingZap{}, false
	}
	zap, pTags := outgoingZapFields(&event)
	if payeeProblem(zap, pTags) != nil {
		return OutgoingZap{}, false
	}
	return zap, true
}

// payeeProblem is NIP-57's exactly-one-p-tag rule, stated once (review).
//
// The verifier needs the reason and the reader needs a yes or no, which is how
// the two came to spell the same predicate differently — one as two ifs with
// messages, one as an OR. An error covers both: the reader tests it for nil.
//
// EXACTLY ONE PAYEE is also the point of storing an outgoing request at all: the
// p tag is the only identity such a row has, and a row cannot show two payees
// for one payment.
func payeeProblem(zap OutgoingZap, pTags int) error {
	if pTags != 1 {
		return reject("a zap request carries exactly one p tag, not %d", pTags)
	}
	if !gonostr.IsValid32ByteHex(zap.Payee) {
		return reject("the p tag is not a 32-byte hex pubkey")
	}
	return nil
}

// outgoingZapFields walks the tags once for the payee, and reports how many p
// tags it saw so a caller can insist on exactly one.
//
// Shared by the verifier and the reader so the two cannot come to disagree about
// which field is the payee — the asymmetry between the directions (pubkey
// inbound, p tag outbound) is the kind of thing that gets remembered in one
// place and forgotten in the other.
func outgoingZapFields(event *gonostr.Event) (OutgoingZap, int) {
	zap := OutgoingZap{Comment: event.Content}
	pTags := 0
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "p" {
			pTags++
			zap.Payee = tag[1]
		}
	}
	return zap, pTags
}

// ParseZapRequest applies §7's Appendix D rules in order, refusing with a
// reason naming the rule that failed.
//
// amountMsat is the callback's own amount parameter, because rule 5 compares
// the two: a request that says one figure while the invoice is minted for
// another produces a receipt the sender's client will not match up.
func ParseZapRequest(raw []byte, amountMsat int64) (VerifiedZapRequest, error) {
	if len(raw) == 0 {
		return nil, reject("the nostr parameter is empty")
	}
	if len(raw) > MaxZapRequestBytes {
		return nil, reject("a zap request may be at most %d bytes", MaxZapRequestBytes)
	}
	var event gonostr.Event
	if event.UnmarshalJSON(raw) != nil {
		decoded, ok := decodeDoubleEncoded(raw)
		if !ok || event.UnmarshalJSON(decoded) != nil {
			return nil, reject("the nostr parameter is not a JSON event")
		}
		// The DECODED bytes become the request's, not the ones received. Raw is
		// what ZapHash commits the invoice to and what the receipt carries as
		// its description; keeping the percent-encoded form here would accept
		// the zap and then mint an invoice hashed over text the client never
		// signed. It is also what lets ParseZapParam tell that a rescue
		// happened, without this fact having to live on the request itself.
		raw = decoded
	}
	if err := checkSignedZapRequest(&event); err != nil {
		return nil, err
	}

	request := &ZapRequest{Raw: raw, Event: event}
	if err := request.readTags(amountMsat); err != nil {
		return nil, err
	}
	// The one place a VerifiedZapRequest comes into existence, and it is below
	// both checks above rather than beside them.
	return newVerifiedZapRequest(request), nil
}

func (z *ZapRequest) readTags(amountMsat int64) error {
	var pTags, eTags, aTags, kTags, bigPTags, relayTags, relayValues int
	for _, tag := range z.Event.Tags {
		if len(tag) == 0 {
			continue
		}
		value := ""
		if len(tag) > 1 {
			value = tag[1]
		}
		switch tag[0] {
		case "p":
			pTags++
			z.Recipient = value
		case "e":
			eTags++
			z.EventID = value
		case "a":
			aTags++
			z.Coordinate = value
		case "k":
			kTags++
			z.TargetKind = value
		case "P":
			bigPTags++
			z.Sender = value
		case "relays":
			relayTags++
			z.Relays = append(z.Relays, tag[1:]...)
			// Counting the tag NAME would let a bare ["relays"] satisfy the
			// rule with no relay at all — the sender naming nowhere to read the
			// receipt, which §7 says reads as theft, passing the check written
			// to catch exactly that.
			relayValues += len(tag) - 1
		case "amount":
			if err := checkAmountTag(value, amountMsat); err != nil {
				return err
			}
		}
	}

	switch {
	case pTags != 1:
		return reject("a zap request carries exactly one p tag, not %d", pTags)
	case !gonostr.IsValid32ByteHex(z.Recipient):
		return reject("the p tag is not a 32-byte hex pubkey")
	case eTags > 1:
		// Zero is correct and common: a PROFILE zap has no e tag at all.
		return reject("a zap request carries at most one e tag, not %d", eTags)
	case eTags == 1 && !gonostr.IsValid32ByteHex(z.EventID):
		return reject("the e tag is not a 32-byte hex event id")
	case relayTags == 0 || relayValues == 0:
		return reject("a zap request must carry a relays tag naming at least one relay")
	case aTags > 1:
		return reject("a zap request carries at most one a tag, not %d", aTags)
	case aTags == 1 && !validCoordinate(z.Coordinate):
		return reject("the a tag is not a valid event coordinate")
	case kTags > 1:
		return reject("a zap request carries at most one k tag, not %d", kTags)
	case kTags == 1 && !validKind(z.TargetKind):
		return reject("the k tag is not a nostr event kind")
	case bigPTags > 1:
		return reject("a zap request carries at most one P tag, not %d", bigPTags)
	case bigPTags == 1 && !gonostr.IsValid32ByteHex(z.Sender):
		return reject("the P tag is not a 32-byte hex pubkey")
	}
	// Only relays this node would actually dial are kept. go-nostr maps a bare
	// host to ws://, so IsValidRelayURL alone does not stop a stranger naming a
	// LAN address as somewhere to publish to.
	z.Relays, z.RelayDrops = keepDialable(z.Relays)
	if len(z.Relays) == 0 {
		return reject("the relays tag names no usable websocket relay")
	}
	return nil
}

// keepDialable drops anything this node must not dial, preserving order and
// dropping duplicates.
//
// A zap request's relays tag is a STRANGER choosing which outbound connections
// this node opens. The node sits on a home LAN, next to the router's admin
// interface, the Umbrel dashboard and every other app on the box — so the tag
// is an SSRF vector wearing a protocol's clothes, and "it only opens a
// websocket" is not much comfort when the target is 169.254.169.254.
//
// Two filters, and the second one is the one that was missing. Wave 8 wrote
// this function with a comment saying it stopped a stranger naming a LAN
// address, and it did not: it checked the scheme and nothing else, so
// ws://192.168.77.1 and ws://127.0.0.1 both passed. The comment had outrun the
// code for three waves, and re-planting the rule in 0ak is what found it.
//
// The allow-list itself lives in internal/nostr, which owns the dialling and is
// the choke point every outbound URL passes; this is the polite early refusal,
// which can answer the caller with a reason. A hostname is not resolved here —
// a DNS lookup on the callback path would let an anonymous caller choose what
// this node looks up — so a name that RESOLVES to a private address passes this
// filter and is stopped at the pool instead (z9k).
func keepDialable(relays []string) ([]string, RelayDrops) {
	var out []string
	drops := RelayDrops{Named: len(relays)}
	for i, relay := range relays {
		relay = strings.TrimSpace(relay)
		// One parse. gonostr.IsValidRelayURL is url.Parse plus exactly this
		// scheme check, and Hostname() needs the parsed form anyway.
		parsed, err := url.Parse(relay)
		if err != nil || (parsed.Scheme != "ws" && parsed.Scheme != "wss") {
			drops.BadScheme++
			continue
		}
		if !nostr.Dialable(parsed.Hostname()) {
			drops.LiteralPrivate++
			continue
		}
		if normalised := gonostr.NormalizeURL(relay); !slices.Contains(out, normalised) {
			out = append(out, normalised)
		} else {
			drops.Duplicate++
		}
		// Stop at the cap rather than filtering the whole tag and truncating
		// after. Both forms keep the first MaxZapRelays distinct dialable
		// relays in order, so the guarantee above is unchanged — but the
		// filter-then-truncate form left `out` unbounded during the loop, which
		// made slices.Contains O(n²) over a list an anonymous caller chooses
		// the length of. Measured: a request naming the ~520 relays that fit in
		// MaxZapRequestBytes cost 470µs and 360KB of garbage more than a
		// three-relay one, all of it discarded two lines later. That inverts
		// the point of checking the signature first — the post-signature work
		// was a hundred times the signature check.
		if len(out) == MaxZapRelays {
			// The rest are never examined, which is the point — see above. They
			// are still ACCOUNTED for, or the arithmetic would not close.
			drops.OverCap = len(relays) - i - 1
			break
		}
	}
	return out, drops
}

func checkAmountTag(value string, amountMsat int64) error {
	tagged, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return reject("the amount tag is not a number of millisatoshis")
	}
	if tagged != amountMsat {
		return reject("the amount tag says %d msat but the request asks for %d",
			tagged, amountMsat)
	}
	return nil
}

// validKind checks NIP-57 Appendix A's "stringified kind of the target event".
//
// Held to the same standard as e and a rather than waved through: a malformed
// optional tag is a malformed request, and the receipt copies this value into a
// public event verbatim.
//
// NIP-01 puts a kind in 0-65535, which is what the bit size expresses. The
// round trip is the canonical-spelling rule: "01" and "1" must not be two
// spellings of one kind, because clients compare these as strings. ParseUint
// alone would accept the first.
func validKind(value string) bool {
	kind, err := strconv.ParseUint(value, 10, 16)
	return err == nil && strconv.FormatUint(kind, 10) == value
}

// validCoordinate checks NIP-01's `kind:pubkey:identifier` form.
func validCoordinate(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 3 {
		return false
	}
	// The same notion of "a kind" the k tag uses. It was strconv.Atoi here,
	// which accepts -1, +5 and 01 — so the file held two incompatible answers
	// to one question, twelve lines apart. This tightens a-tag validation
	// slightly, deliberately: a coordinate is compared by clients as a whole
	// string, so a non-canonical kind inside one is the same hazard.
	if !validKind(parts[0]) {
		return false
	}
	if len(parts[1]) != 64 {
		return false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return false
	}
	return true
}

// AsRejection reports the caller-safe reason for an error, and whether it had
// one. Anything else is ours and must not be shown to a stranger.
func AsRejection(err error) (string, bool) {
	var rejection *Rejection
	if errors.As(err, &rejection) {
		return rejection.Reason, true
	}
	return "", false
}
