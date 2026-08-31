package lndtest

import (
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc/routerrpc"
)

// middleware is the node's side of one RegisterRPCMiddleware stream.
//
// A REAL bidi stream over the real gRPC server, not a stub of the handler. The
// thing most likely to be wrong about a middleware is the framing — a message
// answered with the wrong ref_msg_id, a registration replied to when it must
// not be — and none of that is visible to a fake that calls the policy
// directly.
type middleware struct {
	mu sync.Mutex
	// registrations is what each stream asked to register as.
	registrations []*lnrpc.MiddlewareRegistration
	// intercepts carries a message to whichever stream is live.
	intercepts chan *lnrpc.RPCMiddlewareRequest
	// waiting maps a message id to the caller waiting for its feedback.
	waiting map[uint64]chan *lnrpc.InterceptFeedback
	nextMsg uint64
	// registerErr makes registration fail, which is the state §14 requires be
	// surfaced: an install whose rpcmiddleware support is off.
	registerErr error
	// attempts counts every registration that has SETTLED — accepted or refused.
	// A test waiting for the middleware to settle needs both outcomes, and
	// waiting only for success hangs on the refusal case.
	//
	// It moves when the outcome is known, NOT when the RPC begins. Counting the
	// call instead cost a CI failure on 2026-08-26: a waiter reading
	// `attempts > 0 && !MiddlewareIsLive()` as "settled, and refused" is also
	// reading it that way in the window between the handler starting and the
	// registration arriving, when live is still 0 because the guard has not
	// sent its message yet. On a loaded runner that window is wide enough to
	// lose, and the test that asserts on the registration found none. An
	// accepted registration is recorded in the SAME critical section as this
	// counter, so anything that sees the count sees the registration.
	attempts int
	// live counts the streams currently held open. A registration that has
	// ENDED must not keep honouring the caveat — that is precisely the "the
	// guard died" case, and the whole point is that the macaroon dies with it.
	live int
}

// RegisterRPCMiddleware is LND's side of the handshake: accept the registration
// message, confirm it, then forward whatever the test intercepts.
func (n *Node) RegisterRPCMiddleware(stream lnrpc.Lightning_RegisterRPCMiddlewareServer) error {
	if err := n.authorise(stream.Context()); err != nil {
		return err
	}
	n.middleware.mu.Lock()
	registerErr := n.middleware.registerErr
	n.middleware.mu.Unlock()
	if registerErr != nil {
		n.middlewareSettled()
		return status.Error(codes.Unimplemented, registerErr.Error())
	}

	first, err := stream.Recv()
	if err != nil {
		n.middlewareSettled()
		return err
	}
	registration := first.GetRegister()
	if registration == nil {
		n.middlewareSettled()
		return status.Error(codes.InvalidArgument, "the first message must be a registration")
	}
	if registration.GetCustomMacaroonCaveatName() != "" && registration.GetReadOnlyMode() {
		// LND's own rule, and worth enforcing here: a middleware that asked for
		// both would be rejected on a real node and accepted by a lax fake.
		n.middlewareSettled()
		return status.Error(codes.InvalidArgument,
			"custom_macaroon_caveat_name and read_only_mode are mutually exclusive")
	}
	n.middleware.mu.Lock()
	n.middleware.registrations = append(n.middleware.registrations, registration)
	n.middleware.live++
	n.middleware.attempts++
	n.middleware.mu.Unlock()
	defer func() {
		n.middleware.mu.Lock()
		n.middleware.live--
		n.middleware.mu.Unlock()
	}()

	if err := stream.Send(&lnrpc.RPCMiddlewareRequest{
		InterceptType: &lnrpc.RPCMiddlewareRequest_RegComplete{RegComplete: true},
	}); err != nil {
		return err
	}

	// The reader half. Feedback arrives asynchronously and is routed back to
	// whichever Intercept call is waiting on that message id.
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			n.middleware.mu.Lock()
			reply := n.middleware.waiting[msg.GetRefMsgId()]
			delete(n.middleware.waiting, msg.GetRefMsgId())
			n.middleware.mu.Unlock()
			if reply != nil {
				reply <- msg.GetFeedback()
			}
			select {
			case <-done:
				return
			default:
			}
		}
	}()

	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case msg := <-n.middleware.intercepts:
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

// MiddlewareRegistrations is what has registered so far — the assertion that
// the guard registered under the caveat name it bakes, and not in read-only
// mode.
func (n *Node) MiddlewareRegistrations() []*lnrpc.MiddlewareRegistration {
	n.middleware.mu.Lock()
	defer n.middleware.mu.Unlock()
	return append([]*lnrpc.MiddlewareRegistration(nil), n.middleware.registrations...)
}

// middlewareSettled records a registration that ended without being accepted.
// The accepted case counts itself, beside the registration it recorded.
func (n *Node) middlewareSettled() {
	n.middleware.mu.Lock()
	defer n.middleware.mu.Unlock()
	n.middleware.attempts++
}

// MiddlewareAttempts is how many registrations have SETTLED, refused ones
// included.
func (n *Node) MiddlewareAttempts() int {
	n.middleware.mu.Lock()
	defer n.middleware.mu.Unlock()
	return n.middleware.attempts
}

// MiddlewareIsLive reports whether any middleware stream is currently held
// open — what the fail-closed check above keys on.
func (n *Node) MiddlewareIsLive() bool {
	n.middleware.mu.Lock()
	defer n.middleware.mu.Unlock()
	return n.middleware.live > 0
}

// SetMiddlewareRegistrationError makes RegisterRPCMiddleware fail, the way a
// node with rpcmiddleware disabled would.
func (n *Node) SetMiddlewareRegistrationError(err error) {
	n.middleware.mu.Lock()
	defer n.middleware.mu.Unlock()
	n.middleware.registerErr = err
}

// Intercept pushes one message through the live middleware stream and returns
// the feedback the middleware gave. An empty Error means it allowed the call.
func (n *Node) Intercept(t testing.TB, msg *lnrpc.RPCMiddlewareRequest) *lnrpc.InterceptFeedback {
	t.Helper()
	reply := make(chan *lnrpc.InterceptFeedback, 1)
	n.middleware.mu.Lock()
	n.middleware.nextMsg++
	msg.MsgId = n.middleware.nextMsg
	n.middleware.waiting[msg.MsgId] = reply
	n.middleware.mu.Unlock()

	select {
	case n.middleware.intercepts <- msg:
	case <-time.After(WaitTimeout):
		t.Fatal("no middleware stream took the interception; the guard has not registered")
	}
	select {
	case feedback := <-reply:
		return feedback
	case <-time.After(WaitTimeout):
		t.Fatal("the middleware never answered the interception; LND would block the RPC " +
			"until its interceptor timeout and then reject it")
		return nil
	}
}

// SendPaymentIntercept is the request message LND forwards when something asks
// to pay with a macaroon carrying the guard's caveat.
func SendPaymentIntercept(t testing.TB, requestID uint64, nonce string, req *routerrpc.SendPaymentRequest) *lnrpc.RPCMiddlewareRequest {
	t.Helper()
	raw, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return &lnrpc.RPCMiddlewareRequest{
		RequestId:             requestID,
		CustomCaveatCondition: nonce,
		InterceptType: &lnrpc.RPCMiddlewareRequest_Request{Request: &lnrpc.RPCMessage{
			MethodFullUri: SendPaymentMethod,
			StreamRpc:     true,
			TypeName:      "routerrpc.SendPaymentRequest",
			Serialized:    raw,
		}},
	}
}

// PaymentIntercept is one update on the response half of that same call.
func PaymentIntercept(t testing.TB, requestID uint64, payment *lnrpc.Payment) *lnrpc.RPCMiddlewareRequest {
	t.Helper()
	raw, err := proto.Marshal(payment)
	if err != nil {
		t.Fatal(err)
	}
	return &lnrpc.RPCMiddlewareRequest{
		RequestId: requestID,
		InterceptType: &lnrpc.RPCMiddlewareRequest_Response{Response: &lnrpc.RPCMessage{
			MethodFullUri: SendPaymentMethod,
			StreamRpc:     true,
			TypeName:      "lnrpc.Payment",
			Serialized:    raw,
		}},
	}
}

// SendPaymentMethod is the RPC the guard's cap is about.
const SendPaymentMethod = "/routerrpc.Router/SendPaymentV2"

// WaitTimeout bounds one interception round trip. Generous: the point of a
// timeout here is a legible failure rather than a hung test, and a real LND
// gives its middleware two seconds by default.
const WaitTimeout = 10 * time.Second
