package nwc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"
)

// The NIP-47 event kinds (§8).
const (
	KindInfo     = 13194
	KindRequest  = 23194
	KindResponse = 23195
)

// The optional NWC extension specs this build implements, as the kind 13194 info
// event's `extensions` tag names them (doy.3).
//
// THE TAG IS A SWITCH, NOT A DESCRIPTION, which is why advertising 06 is the last
// thing this epic did. Amethyst is paired with wallets it does not control, and
// one that typed `metadata` narrowly would accept today's `"metadata": null` and
// then fail to decode a nested object — a params error, and a refused payment. So
// it sends metadata only to a wallet advertising 06 (read, not run:
// NwcSignerState.kt:182). Advertising is what makes clients start sending;
// advertising before there was somewhere to put what they send would have lost
// the data silently.
//
// THE TWO ARE NOT THE SAME KIND OF CLAIM, which is why they are separate
// constants assembled per connection rather than one string (review):
//
//   - 05 is list_transactions, one method behind one permission group. A pairing
//     without `history` cannot call it, and its info event already omits it from
//     the method list — so the tag has to omit it too or the same event
//     contradicts itself. It belongs here independently of this epic: the method
//     has been served since d24.12 and was simply never advertised.
//   - 06 is the metadata conventions, and no single group makes it false. It
//     spans storing on pay_invoice and echoing on list_transactions, and a
//     pairing holding only `pay` still genuinely understands the envelope on the
//     one call it can make. Node-wide is the right claim, and it is a decision
//     rather than an accident of sharing a constant with 05.
const (
	ExtensionTransactionHistory  = "05"
	ExtensionMetadataConventions = "06"
)

// SettingSince is where the subscription's resume point lives (§4, §8).
//
// PERSISTED and advanced as requests are handled — never a naive `startup − 1h`.
// §8 explains why: reaching backwards an hour on every start re-delivers every
// request in that window, and a service whose replay protection is in memory
// then executes them again. Ours is durable, so the resume point is the second
// half of the same answer rather than a substitute for it.
const SettingSince = "nwc_since"

// RequestWindow is how far from now a request's created_at may be (§8 step 3).
//
// Requests outside it are refused whether or not they were seen before, which is
// what bounds the durable cache's job to exactly the window a restart spans.
const RequestWindow = 60 * time.Second

// HandledRetention is how long the replay cache keeps a response (§8).
const HandledRetention = 24 * time.Hour

// PruneInterval is how often the cache is swept (§8: hourly).
const PruneInterval = time.Hour

// SiblingDeliveryWindow is how recently a request must have been claimed for a
// second delivery of it to be another RELAY'S copy rather than a client asking
// again (d24.18).
//
// Since a pairing names several relays, one request arrives once per relay,
// within milliseconds. The loser of the claim race must not answer those with the
// in-flight placeholder: that would put "this request is already being processed"
// on the same relays the winner is about to publish the real answer to, and a
// client that takes the first response it sees would show a failure for a request
// that succeeded.
//
// Two seconds, which is enormous against the milliseconds a relay fan-out takes
// and small against the seconds a human waits before asking again. The cost of
// being wrong is asymmetric and that is why it is generous: a sibling misread as
// a re-send publishes a confusing answer, while a re-send misread as a sibling
// merely stays quiet until the real answer arrives on every relay anyway.
//
// EXPIRY CONDITION: it separates two populations by arrival time. If a relay ever
// delivers a duplicate seconds late — a redelivery after a reconnect is the case
// to watch — this stops separating them, and the discriminator has to become
// something other than a clock.
const SiblingDeliveryWindow = 2 * time.Second

// InFlightPerConnection is how many of one connection's requests are handled at
// once.
//
// Small, and it is a bound rather than a target. One is what a paying client
// needs plus a little room for the reads a wallet app fires alongside — the
// balance it refreshes while a payment is running is the case this exists for.
// Higher would let a paired app hold more of this process for itself, which is
// what a per-connection rate limit is for (l3j) and not what a worker count
// should be doing.
const InFlightPerConnection = 4

// ReconnectBackoff is how long a connection waits before re-subscribing after
// its relay drops it.
//
// Flat, not exponential, and short. The relay is the operator's own or one they
// chose; the failure being waited out is a home connection blipping or a relay
// restarting, which resolves in seconds. An exponential backoff optimises for
// not hammering a stranger's server — the wrong trade here, where the cost of a
// long wait is a wallet app that stays broken after the network came back.
//
// SOMETHING ELSE LEANS ON IT BEING FLAT (du9.1). internal/nostr's Subscribe
// dials under connectBudget rather than a budget of its own, and the argument
// for five seconds is that a shorter dial only brings the next attempt forward,
// because THIS backoff has no exponential term to compound it. Make it
// exponential and that argument goes with it: say so there, in Subscribe's doc,
// which carries the same expiry condition from the other side.
const ReconnectBackoff = 5 * time.Second

// Method is a NIP-47 method name.
type Method string

// The methods this build answers, pay_invoice included since d24.4 landed §8's
// rejection ladder — the ladder is what makes paying safe, and a method that
// dispatched without it would be a spend path with no limits. An unlisted method
// answers NOT_IMPLEMENTED, which is the honest shape and is what a client shows
// the user.
const (
	MethodGetInfo          Method = "get_info"
	MethodGetBalance       Method = "get_balance"
	MethodMakeInvoice      Method = "make_invoice"
	MethodLookupInvoice    Method = "lookup_invoice"
	MethodListTransactions Method = "list_transactions"
	MethodPayInvoice       Method = "pay_invoice"
)

// methodGroup maps a method to the permission group that grants it (§8 step 4).
var methodGroup = map[Method]string{
	MethodGetInfo:          "info",
	MethodGetBalance:       "balance",
	MethodMakeInvoice:      "invoice",
	MethodLookupInvoice:    "lookup",
	MethodListTransactions: "history",
	MethodPayInvoice:       "pay",
}

// Supported is every method this build answers, in §8's order.
//
// Written out rather than derived, because §8's order is editorial and neither
// methodGroup (a map) nor dispatch (a switch) has one. The info event is a
// PROMISE, though, and a list that drifted from what dispatch answers would show
// a client a method that returns NOT_IMPLEMENTED — so the drift is caught by a
// test instead: every entry here has a group, and none of them dispatches to
// NOT_IMPLEMENTED.
//
// pay_invoice joined it in d24.4, with the ladder that makes paying safe. Being
// here is not enough to be advertised: see advertised, which also asks whether
// this connection may use it and whether sending is on at all.
func Supported() []Method {
	return []Method{MethodGetInfo, MethodGetBalance, MethodMakeInvoice,
		MethodLookupInvoice, MethodListTransactions, MethodPayInvoice}
}

// maxMethodLength bounds what an unknown method name may be echoed back as.
//
// Generous next to the longest name NIP-47 defines (multi_pay_keysend, 17), so
// a method added by a future NIP is still named in the error rather than
// truncated into confusion — and short enough that the response and the cached
// row stay small whatever a client sends.
const maxMethodLength = 64

// listFilter reads NIP-47's list_transactions parameters (d24.12, test-spec D5).
//
// EVERY parameter this build understands is honoured, and anything it does not
// is REFUSED rather than ignored. That rule is the test spec's and the reason is
// what d24.12 was filed about: a client asking for unpaid outgoing and getting
// everything has been told a falsehood about its own filter, and will render it
// as truth.
//
// `unpaid_incoming` and `unpaid_outgoing` are NIP-47's later spelling of "only
// the open ones". They are implemented rather than refused because the test spec
// names both as cases, and because the combination they express — unpaid, in one
// direction — is the one a wallet app asks for most.
func listFilter(req Request) (store.TxnFilter, *Response) {
	var params struct {
		From           int64  `json:"from"`
		Until          int64  `json:"until"`
		Limit          int    `json:"limit"`
		Offset         int    `json:"offset"`
		Unpaid         bool   `json:"unpaid"`
		UnpaidIncoming bool   `json:"unpaid_incoming"`
		UnpaidOutgoing bool   `json:"unpaid_outgoing"`
		Type           string `json:"type"`
	}
	if err := json.Unmarshal(nonNull(req.Params), &params); err != nil {
		resp := errorResponse(req.Method, CodeOther, "could not read the parameters")
		return store.TxnFilter{}, &resp
	}

	filter := store.TxnFilter{Limit: params.Limit, Offset: params.Offset}
	switch params.Type {
	case "":
		// Both directions, which is NIP-47's default.
	case "incoming":
		filter.Direction = store.Incoming
	case "outgoing":
		filter.Direction = store.Outgoing
	default:
		resp := errorResponse(req.Method, CodeOther, "type must be incoming or outgoing")
		return store.TxnFilter{}, &resp
	}

	switch {
	case params.UnpaidIncoming && params.UnpaidOutgoing:
		filter.Paid, filter.Direction = store.UnpaidOnly, store.EitherDirection
	case params.UnpaidIncoming:
		filter.Paid, filter.Direction = store.UnpaidOnly, store.Incoming
	case params.UnpaidOutgoing:
		filter.Paid, filter.Direction = store.UnpaidOnly, store.Outgoing
	case params.Unpaid:
		filter.Paid = store.IncludingUnpaid
	}
	// The narrower parameters name their own direction, so a `type` that
	// contradicts them is a request that cannot be answered as asked.
	if (params.UnpaidIncoming != params.UnpaidOutgoing) && params.Type != "" {
		resp := errorResponse(req.Method, CodeOther,
			"unpaid_incoming and unpaid_outgoing already name a direction; do not also send type")
		return store.TxnFilter{}, &resp
	}

	if params.From > 0 {
		filter.From = time.Unix(params.From, 0).UTC()
	}
	if params.Until > 0 {
		filter.Until = time.Unix(params.Until, 0).UTC()
	}
	return filter, nil
}

// Error codes, §8 step 5.
const (
	CodeRateLimited           = "RATE_LIMITED"
	CodeNotImplemented        = "NOT_IMPLEMENTED"
	CodeInsufficientBalance   = "INSUFFICIENT_BALANCE"
	CodeQuotaExceeded         = "QUOTA_EXCEEDED"
	CodeRestricted            = "RESTRICTED"
	CodeUnauthorized          = "UNAUTHORIZED"
	CodeInternal              = "INTERNAL"
	CodeUnsupportedEncryption = "UNSUPPORTED_ENCRYPTION"
	CodePaymentFailed         = "PAYMENT_FAILED"
	CodeNotFound              = "NOT_FOUND"
	CodeOther                 = "OTHER"
)

// Request is a decrypted kind 23194 payload.
type Request struct {
	Method Method          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is a kind 23195 payload, before encryption.
type Response struct {
	ResultType Method         `json:"result_type"`
	Error      *ResponseError `json:"error,omitempty"`
	Result     any            `json:"result,omitempty"`
}

// ResponseError is NIP-47's error object.
type ResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// errText renders an error for a log attribute, tolerating a nil one — the
// fork's CheckSignature returns (false, nil) for a malformed signature.
func errText(err error) string {
	if err == nil {
		return "the signature does not verify"
	}
	return err.Error()
}

// inProgress is what a claim stores until the real answer exists.
//
// A well-formed NIP-47 error rather than an empty string, because a delivery
// that loses the claim is answered with it: a client that sent the same request
// twice is told the first one is still running, and retries. The alternative —
// answering nothing — looks identical to a service that is down, and for
// pay_invoice would invite a second payment under a new request id.
const inProgressMessage = "this request is already being processed"

func inProgress(method Method) string {
	encoded, err := encode(errorResponse(method, CodeOther, inProgressMessage))
	if err != nil {
		// Unreachable: the value is a struct of strings. A placeholder that
		// could not be rendered would still have to claim the id, so the
		// fallback keeps the claim rather than the message.
		return `{"error":{"code":"` + CodeOther + `","message":"` + inProgressMessage + `"}}`
	}
	return encoded
}

func errorResponse(method Method, code, message string) Response {
	return Response{ResultType: method, Error: &ResponseError{Code: code, Message: message}}
}

// encode renders a response for the cache and the wire. One encoder, because
// the replayed copy must be byte-identical to the original: §8 says a known id
// returns its cached response, and a re-rendered one that differed would be a
// different answer to the same question.
func encode(resp Response) (string, error) {
	raw, err := json.Marshal(resp)
	if err != nil {
		return "", fmt.Errorf("nwc: encoding the response: %w", err)
	}
	return string(raw), nil
}

// permits reports whether a connection's groups allow a method (§8 step 4).
//
// An unknown method is not permitted by anything — it has no group — so it can
// only reach NOT_IMPLEMENTED, never a dispatch.
func permits(groups []string, method Method) bool {
	group, known := methodGroup[method]
	if !known {
		return false
	}
	for _, g := range groups {
		if g == group {
			return true
		}
	}
	return false
}

// MaxPanicsPerConnection is how many requests may crash the handler on one
// pairing before the app stops serving it (`xmc` Fix C).
//
// WHY A QUARANTINE AT ALL. Containing a panic converts a crash loop into a panic
// loop: the same client sends the same request, it fails the same way, and the
// app survives to do it again in a few seconds. On 2026-08-26 that was fifteen
// times in seven minutes, and it ended only because somebody fixed the client.
// Something on this side has to stop asking.
//
// THREE, and the trade is this. Too low and one flaky request disables a working
// pairing the operator then has to notice and re-enable; too high and a broken
// client generates incidents all day. I erred LOW, because after Fix A a panic
// here is not a flaky request — it is a defect in our own handling of something
// a client sent, and three of them on one pairing is a pattern rather than bad
// luck. The cost of being wrong in this direction is one click on the
// Connections page; the cost in the other is the incident this bead is about.
//
// EXPIRY CONDITION: raise it if a panic is ever observed that is NOT
// deterministic in the request — a timeout, a transient store failure — because
// then three says nothing about the client. Lower it only if a paused pairing
// turns out to be routinely reached before the operator can act, which would
// mean the number is not protecting anything. A number justified only by the
// incident that produced it is a trap for whoever meets the next one.
const MaxPanicsPerConnection = 3
