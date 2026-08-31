package lndtest

import (
	"encoding/hex"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc/routerrpc"
)

// The fake node's routerrpc half (d24.2).
//
// It IMPLEMENTS the two payment RPCs rather than calling them, which is why the
// arch rule that keeps BakeMacaroon and friends inside the guard allows this
// package to name them.
//
// Both RPCs are server-streaming and both stream lnrpc.Payment, so a scripted
// answer is a SEQUENCE of updates: the interesting behaviour under test is that
// the client consumes to a terminal state rather than believing the first
// message, and a fake that could only answer once could not express that.

// router is the Router service, kept as its own type so Node's method set does
// not gain two Unimplemented embeddings that could shadow each other.
type router struct {
	routerrpc.UnimplementedRouterServer
	node *Node
}

// paymentScript is what a payment will report, in order.
type paymentScript struct {
	updates []*lnrpc.Payment
	// dieAfterDispatch makes SendPaymentV2 break the stream instead of reporting
	// the terminal update, while still recording the payment so TrackPaymentV2
	// can answer for it later. See SetPaymentDispatchedThenLost.
	dieAfterDispatch bool
}

// InFlight is an intermediate update: real, and not an answer.
func InFlight() *lnrpc.Payment {
	return &lnrpc.Payment{Status: lnrpc.Payment_IN_FLIGHT}
}

// Succeeded is a terminal update carrying the route's ACTUAL fee — which is
// what settles the reservation, and is normally less than the limit that was
// reserved (§5's refund arithmetic).
func Succeeded(feeMsat int64) *lnrpc.Payment {
	return &lnrpc.Payment{
		Status:          lnrpc.Payment_SUCCEEDED,
		FeeMsat:         feeMsat,
		PaymentPreimage: "00ff",
	}
}

// SucceededWithPreimage is a terminal success whose preimage the test chose.
//
// Succeeded's is a fixed placeholder, which cannot tell "the preimage travelled"
// from "the preimage was invented" — d24.4's pay_invoice response returns it to
// the client, so which one arrives is the assertion.
func SucceededWithPreimage(feeMsat int64, preimage string) *lnrpc.Payment {
	return &lnrpc.Payment{
		Status:          lnrpc.Payment_SUCCEEDED,
		FeeMsat:         feeMsat,
		PaymentPreimage: preimage,
	}
}

// FailedBecause is a terminal failure. The reason travels because the operator
// sees it: "no route" and "incorrect payment details" are different problems.
func FailedBecause(reason lnrpc.PaymentFailureReason) *lnrpc.Payment {
	return &lnrpc.Payment{Status: lnrpc.Payment_FAILED, FailureReason: reason}
}

// SetPaymentUpdates scripts what SendPaymentV2 reports for one bolt11.
func (n *Node) SetPaymentUpdates(bolt11 string, updates ...*lnrpc.Payment) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.payments[bolt11] = paymentScript{updates: updates}
}

// SetTrackedPayment scripts what TrackPaymentV2 reports for one payment hash.
//
// Keyed separately from SetPaymentUpdates because the resolver reaches
// the node with a hash and nothing else — it has no bolt11 to offer, which is
// the whole reason payment_hash is recorded at reserve time.
func (n *Node) SetTrackedPayment(paymentHash []byte, updates ...*lnrpc.Payment) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.tracked[hex.EncodeToString(paymentHash)] = paymentScript{updates: updates}
}

// SetPaymentDispatchedThenLost scripts a payment the node ACCEPTS and resolves,
// while the sending call dies before it hears the answer.
//
// This is the crash the resolver exists for, and it is the one shape a
// simple failure cannot express: a payment that failed to send is not the
// dangerous case — a payment that WENT and whose caller never learned the
// outcome is. TrackPaymentV2 answers for it afterwards exactly as a real node
// would, because from the node's side nothing went wrong at all.
func (n *Node) SetPaymentDispatchedThenLost(bolt11, paymentHash string, outcome *lnrpc.Payment) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.payments[bolt11] = paymentScript{dieAfterDispatch: true}
	n.tracked[paymentHash] = paymentScript{updates: []*lnrpc.Payment{outcome}}
}

// SendPaymentRequests is every SendPaymentV2 call the node received, so a test
// can assert the fee limit and timeout it was ASKED for rather than inferring
// them from the outcome.
func (n *Node) SendPaymentRequests() []*routerrpc.SendPaymentRequest {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]*routerrpc.SendPaymentRequest(nil), n.sendRequests...)
}

// TrackedHashes is every hash TrackPaymentV2 was asked about, hex, in order.
func (n *Node) TrackedHashes() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.trackedHashes...)
}

func (r *router) SendPaymentV2(in *routerrpc.SendPaymentRequest,
	stream grpc.ServerStreamingServer[lnrpc.Payment]) error {
	n := r.node
	if err := n.authorise(stream.Context()); err != nil {
		return err
	}
	n.mu.Lock()
	n.sendRequests = append(n.sendRequests, in)
	script, ok := n.payments[in.PaymentRequest]
	n.mu.Unlock()
	if !ok {
		// An unscripted bolt11 fails the way LND fails an undecodable one: a
		// bare Unknown, which is the code the o34.10 story is about.
		return status.Error(codes.Unknown, "invalid bolt11: checksum failed")
	}
	if script.dieAfterDispatch {
		// The node has it; the caller will never hear how it went.
		return status.Error(codes.Unavailable, "transport is closing")
	}
	return script.send(stream)
}

func (r *router) TrackPaymentV2(in *routerrpc.TrackPaymentRequest,
	stream grpc.ServerStreamingServer[lnrpc.Payment]) error {
	n := r.node
	if err := n.authorise(stream.Context()); err != nil {
		return err
	}
	key := hex.EncodeToString(in.PaymentHash)
	n.mu.Lock()
	n.trackedHashes = append(n.trackedHashes, key)
	script, ok := n.tracked[key]
	n.mu.Unlock()
	if !ok {
		// LND's own answer for a hash it has no record of. The resolver treats
		// this code specifically, so the fake must produce it exactly.
		return status.Error(codes.NotFound, "payment isn't initiated")
	}
	return script.send(stream)
}

func (s paymentScript) send(stream grpc.ServerStreamingServer[lnrpc.Payment]) error {
	for _, update := range s.updates {
		if err := stream.Send(update); err != nil {
			return err
		}
	}
	return nil
}
