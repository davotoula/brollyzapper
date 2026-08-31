package lnd

import (
	"context"
	"fmt"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
)

// Bolt11 is what §8's rejection ladder needs to know about an invoice before it
// reserves anything: how much, which payment, and whether it is still payable.
//
// Not the whole PayReq. The ladder's decisions are these three plus the
// description it echoes back, and a struct that carried the route hints would
// invite a caller to make a routing decision this app has no business making.
//
// DescriptionHash is the fifth and it is not a routing hint (y09): it is what an
// invoice COMMITS TO, and the only thing that can tie a client's claim about a
// payment to the payment itself.
type Bolt11 struct {
	PaymentHash string
	// AmountMsat is zero for an amountless invoice, which is a state and not an
	// error: §8's ladder pays one when the request supplies an amount and
	// refuses it otherwise (test-spec E4). Deciding here would take that from
	// the only place that can see the request.
	AmountMsat  int64
	Description string
	// DescriptionHash is the invoice's committed hash, lowercase hex, empty when
	// it has none.
	//
	// NIP-57 makes it sha256 of the raw zap request, which is how a payer can
	// check that the event a client hands it is the event this invoice is for —
	// the exact inverse of the rule lnurl.ZapHash mints with. Without it a
	// paired app can attach any well-formed event it likes to any payment, and
	// the signature it carries proves only that the app signed it (y09).
	DescriptionHash string
	ExpiresAt       time.Time
}

// Decode reads a bolt11 through the node that will pay it.
//
// THE NODE'S PARSER, deliberately. ADR 0001 keeps the LND module out of go.mod
// — an arch rule asserts it — so the alternative is a second bolt11 parser, and
// a second parser is a second opinion about what an invoice says. The opinion
// that decides where the money goes belongs to the thing that sends it, so
// asking it is the only way the ladder's amount and the paid amount cannot
// disagree.
//
// It costs one round trip before every payment. That is the right trade: the
// ladder refuses malformed, expired and amountless invoices BEFORE a reservation
// exists (test-spec E2, E3, E4), and refusing them needs the invoice read.
//
// On the SPEND client, which is where the payment is made from — and like
// SendPayment it concludes nothing about the credential: observe, never
// observeStream. A client that treated "this invoice is nonsense" as "our
// macaroon was rejected" would let anyone who can send a request drive the
// credential broker one BakeMacaroon at a time (§6).
func (c *Client) Decode(ctx context.Context, bolt11 string) (Bolt11, error) {
	client, err := c.lightning()
	if err != nil {
		return Bolt11{}, c.observe(err)
	}
	req, err := client.DecodePayReq(ctx, &lnrpc.PayReqString{PayReq: bolt11})
	if err != nil {
		return Bolt11{}, c.observe(fmt.Errorf("lnd: decoding a bolt11: %w", err))
	}
	decoded := Bolt11{
		PaymentHash:     req.PaymentHash,
		AmountMsat:      req.NumMsat,
		Description:     req.Description,
		DescriptionHash: req.DescriptionHash,
	}
	if req.Timestamp > 0 && req.Expiry > 0 {
		decoded.ExpiresAt = time.Unix(req.Timestamp+req.Expiry, 0).UTC()
	}
	return decoded, nil
}
