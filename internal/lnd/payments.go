package lnd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc/routerrpc"
	"github.com/davotoula/brollyzapper/internal/secret"
)

// PaymentTimeout is what SendPaymentV2 is given as timeout_seconds (spec §6).
//
// It bounds how long LND keeps trying routes. It is NOT the caller's context
// deadline and must not be confused with it: a caller that gives up early
// leaves the payment in flight at the node, which is precisely the case the
// resolver exists to finish.
const PaymentTimeout = 60 * time.Second

// ErrPaymentNotFound means the node has no record of a payment at all.
//
// Its own error because it is the only failure that licenses REVERSING a
// reservation: it is the node saying the payment was never dispatched. Every
// other failure — unreachable, refused, timed out — leaves the payment's fate
// unknown, and §6 forbids reversing an unresolved reservation, because doing so
// would double-spend the ceiling if the payment later settled.
var ErrPaymentNotFound = errors.New("lnd: the node has no record of this payment")

// ErrNotSent means the payment request never reached the node.
//
// The two ways that happens are both BEFORE the stream carries anything: the
// client cannot get a connection at all, or the stream cannot be established.
// Neither leaves LND with a payment request to act on, so — unlike every other
// send failure — the fate is KNOWN.
//
// Typed because t4t's dispatch marker turns on exactly this distinction. The
// marker is written before the send so that its absence is safe; a send that
// never left makes the marker a lie, and a lie in that direction is a
// reservation the resolver will refuse to touch for ever. Told apart here,
// where the difference is visible, rather than guessed at by a caller reading
// error strings.
var ErrNotSent = errors.New("lnd: the payment was not sent to the node")

// PaymentResult is a payment's TERMINAL state.
//
// It is a value rather than an error even when the payment failed, because a
// failure is an answer: §5 says a failed payment consumes no budget, and the
// caller's move is to reverse the reservation. An error means something else
// entirely — the fate is unknown and nothing may be concluded.
type PaymentResult struct {
	Status lnrpc.Payment_PaymentStatus
	// FeeMsat is the route's ACTUAL fee, which is what settles the reservation.
	// It is normally less than the limit that was reserved; §5's refund
	// arithmetic lives in the wallet and is fed this number and nothing else.
	FeeMsat       int64
	FailureReason lnrpc.PaymentFailureReason

	// Preimage is the proof the invoice was paid, and it arrives with d24.4
	// because that is the wave where something needs it: NIP-47's pay_invoice
	// response returns it, and the client that asked for the payment is entitled
	// to its proof.
	//
	// It was deliberately absent until then — §12 lists preimages with the
	// macaroons and the private keys, and a secret.String nobody reads is
	// write-only state. It is secret.String rather than string for the same
	// reason: internal/arch caught it the moment this struct first carried one
	// as a plain string, and PaymentResult's own LogValue is what stops the
	// fields AROUND it dragging it into a log line.
	Preimage secret.String
}

// LogValue keeps the preimage out of a log line even when the whole result is
// handed to slog (§12).
//
// The status and the fee are what an operator debugging a payment needs; the
// preimage is what the client needs, and those are different audiences.
func (r PaymentResult) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("status", r.Status.String()),
		slog.Int64("fee_msat", r.FeeMsat),
		slog.String("failure_reason", r.FailureReason.String()),
	)
}

// Succeeded reports whether the payment settled.
func (r PaymentResult) Succeeded() bool { return r.Status == lnrpc.Payment_SUCCEEDED }

// Failed reports whether the node finished with it and it did not settle.
func (r PaymentResult) Failed() bool { return r.Status == lnrpc.Payment_FAILED }

// terminal reports whether the node has finished with this payment.
func (r PaymentResult) terminal() bool { return r.Succeeded() || r.Failed() }

// SendPayment pays a bolt11 invoice and returns its terminal state.
//
// feeLimitMsat is the caller's — it is wallet.MaxFee, the same number the
// reservation debited, and nothing here recomputes or adjusts it (§5, §6). An
// arch rule already asserts the wallet is the only place that arithmetic lives.
//
// This is a per-request RPC on the SPEND client, and it deliberately does not
// conclude anything about the credential: it calls observe, never observeStream.
// LND reports no-route, expired-invoice and insufficient-balance as
// codes.Unknown, so a payment path that acted on them would let whoever asked
// for the payment drive the credential broker one BakeMacaroon at a time
// (§6, o34.10 — and an arch rule).
func (c *Client) SendPayment(ctx context.Context, bolt11 string, feeLimitMsat int64) (PaymentResult, error) {
	client, err := c.router()
	if err != nil {
		// No connection, so no request: NOTHING reached the node.
		return PaymentResult{}, fmt.Errorf("%w: %w", ErrNotSent, c.observe(err))
	}
	// Cancelled on the way out, and that is not optional. consume returns the
	// moment a terminal update arrives, which leaves the stream unfinished —
	// grpc-go releases a client stream only on a Recv error, a cancelled stream
	// context, or a closed ClientConn, and an unfinished stream also holds the
	// connection's idleness refcount, so a single payment would pin the TCP+TLS
	// transport to LND open for the life of the process.
	//
	// Cancelling does NOT cancel the payment: LND has persisted it by then,
	// which is the entire reason TrackPaymentV2 exists.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := client.SendPaymentV2(ctx, &routerrpc.SendPaymentRequest{
		PaymentRequest: bolt11,
		FeeLimitMsat:   feeLimitMsat,
		TimeoutSeconds: int32(PaymentTimeout / time.Second),
	})
	if err != nil {
		// The stream could not be established, so the request message was never
		// sent and LND has nothing to act on. Errors from consume() below are a
		// different animal entirely: by then the payment is in flight.
		return PaymentResult{}, fmt.Errorf("%w: %w", ErrNotSent, c.observe(err))
	}
	return c.consume(stream)
}

// TrackPayment resolves a payment the node already knows about, by hash.
//
// This is the resolver's instrument: after a crash there is a reserved
// row and no idea what became of it, and the node is the only thing that knows.
// The hash is what the row carries, recorded at reserve time — there is no
// bolt11 to offer here.
func (c *Client) TrackPayment(ctx context.Context, paymentHash []byte) (PaymentResult, error) {
	client, err := c.router()
	if err != nil {
		return PaymentResult{}, c.observe(err)
	}
	// Cancelled on the way out, for the reason SendPayment gives above.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// No notFound() here, and the asymmetry with the Recv below is the point: a
	// server-streaming stub call does not carry the server's status. LND's
	// NotFound arrives on the first Recv, inside consume, which is where it is
	// mapped. Wrapping here would be a branch that cannot fire.
	stream, err := client.TrackPaymentV2(ctx, &routerrpc.TrackPaymentRequest{
		PaymentHash: paymentHash,
	})
	if err != nil {
		return PaymentResult{}, c.observe(err)
	}
	return c.consume(stream)
}

// consume reads a payment stream to its TERMINAL update.
//
// Not the first message: LND streams IN_FLIGHT updates as htlcs are attempted,
// and treating one as the outcome would report "still going" for a payment that
// went on to succeed — leaving the reservation pending and the invoice paid.
//
// End-of-stream without a terminal update is an ERROR, not a quiet zero value.
// The zero PaymentResult has status UNKNOWN, which is neither succeeded nor
// failed, and a caller that switched on it would fall through to "do nothing" —
// the same silent-pending outcome by a different route. EOF can only ever mean
// that here: the loop returns the instant a terminal update arrives, so reaching
// EOF is by definition reaching it without one.
func (c *Client) consume(stream grpc.ServerStreamingClient[lnrpc.Payment]) (PaymentResult, error) {
	var last PaymentResult
	for {
		update, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return PaymentResult{}, c.observe(fmt.Errorf(
				"lnd: the payment stream ended at %v without a terminal state", last.Status))
		}
		if err != nil {
			return PaymentResult{}, c.observe(notFound(err))
		}
		last = PaymentResult{
			Status:        update.Status,
			FeeMsat:       update.FeeMsat,
			FailureReason: update.FailureReason,
			Preimage:      secret.New(update.PaymentPreimage),
		}
		if last.terminal() {
			// Answered. The stream may have more to say; the caller does not
			// need it, and holding it open would keep an htlc-level subscription
			// alive for a payment that is over.
			return last, nil
		}
	}
}

// notFound maps LND's NotFound to ErrPaymentNotFound and leaves everything else
// alone.
//
// Narrow on purpose. Widening it is how "the node is down" becomes "the payment
// was never sent", and the action that follows is an irreversible reversal of a
// reservation whose payment may still be in flight.
func notFound(err error) error {
	if status.Code(err) == codes.NotFound {
		return fmt.Errorf("%w: %v", ErrPaymentNotFound, err)
	}
	return err
}

// router is the Router service on this client's connection.
//
// It shares the connection, the TLS certificate and the per-RPC macaroon with
// lightning() — which is what makes "the payment client presents the spend
// macaroon" true of every RPC it makes, rather than of the ones someone
// remembered.
func (c *Client) router() (routerrpc.RouterClient, error) {
	conn, err := c.connection()
	if err != nil {
		return nil, err
	}
	return routerrpc.NewRouterClient(conn), nil
}
