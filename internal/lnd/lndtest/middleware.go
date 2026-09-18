package lndtest

import (
	"errors"
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
	// waiting maps a message id to the caller waiting for its outcome.
	waiting map[uint64]chan InterceptOutcome
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
	// forwarded is every message id this stream took off `intercepts`. Taking
	// one is taking ownership: no other stream can ever see it, so if this
	// handler returns with the message unanswered, nothing will answer it.
	// Written and read only on this goroutine — the loop below and the defer
	// that follows — which is why it needs no lock of its own.
	forwarded := map[uint64]struct{}{}
	defer func() {
		n.middleware.mu.Lock()
		defer n.middleware.mu.Unlock()
		n.middleware.live--
		// End every interception this stream still owes an answer for. LND
		// fails an RPC whose middleware disconnects rather than holding it, so
		// the caller is told the stream ended instead of waiting out
		// WaitTimeout — which, from a goroutine whose test had returned, used
		// to be a t.Fatal that panicked the package run (zu5.9).
		//
		// Sending under the lock is safe because every reply channel is
		// buffered (1) and is delivered to at most once: whoever sends claimed
		// the entry with a delete under this same lock, so the sweep, the
		// reader goroutine and a timed-out caller cannot both have it. If the
		// buffering changes, this must stop being a send under the lock.
		for id := range forwarded {
			reply, pending := n.middleware.waiting[id]
			if !pending {
				continue
			}
			delete(n.middleware.waiting, id)
			reply <- InterceptOutcome{
				Feedback: &lnrpc.InterceptFeedback{Error: ErrMiddlewareStreamEnded.Error()},
				Err:      ErrMiddlewareStreamEnded,
			}
		}
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
				reply <- InterceptOutcome{Feedback: msg.GetFeedback()}
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
			// Recorded BEFORE the send, not after: a send that fails has still
			// consumed the message, and the caller waiting on it is exactly the
			// one the sweep above exists for.
			forwarded[msg.GetMsgId()] = struct{}{}
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

// InterceptOutcome is how one interception ended: the feedback the middleware
// gave, or the reason there will never be one.
type InterceptOutcome struct {
	Feedback *lnrpc.InterceptFeedback
	Err      error
}

// ErrMiddlewareStreamEnded is the outcome of an interception whose stream ended
// before the middleware answered it. A real LND fails such an RPC rather than
// holding it, and so does this fake.
var ErrMiddlewareStreamEnded = errors.New(
	"the middleware stream ended before it answered the interception")

var (
	errNoMiddlewareStream = errors.New(
		"no middleware stream took the interception; the guard has not registered")
	errMiddlewareSilent = errors.New(
		"the middleware never answered the interception; LND would block the RPC " +
			"until its interceptor timeout and then reject it")
)

// Intercept pushes one message through the live middleware stream and returns
// the feedback the middleware gave. An empty Error means it allowed the call.
//
// It calls t.Fatal, so it may only be used ON the test goroutine. Off it — a
// message deliberately left unanswered, say — use InterceptAsync: a t.Fatal
// from a goroutine whose test has returned panics the whole package run, which
// is what zu5.9 was.
func (n *Node) Intercept(t testing.TB, msg *lnrpc.RPCMiddlewareRequest) *lnrpc.InterceptFeedback {
	t.Helper()
	out := n.awaitIntercept(n.beginIntercept(msg), msg)
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	return out.Feedback
}

// InterceptAsync is Intercept for a caller that is not the test goroutine: it
// pushes the message and hands the outcome back over a channel instead of
// calling any testing.TB method. The channel is buffered, so the interception
// always ends whether or not anyone reads it — but a test that starts one is
// expected to read it before returning, which is what proves the interception
// did not outlive it.
func (n *Node) InterceptAsync(msg *lnrpc.RPCMiddlewareRequest) <-chan InterceptOutcome {
	reply := n.beginIntercept(msg)
	out := make(chan InterceptOutcome, 1)
	go func() { out <- n.awaitIntercept(reply, msg) }()
	return out
}

// beginIntercept assigns the message its id and registers the channel its
// outcome will arrive on. Synchronous in both forms: the id has to be settled
// before InterceptAsync returns, or two interceptions could be numbered in the
// order their goroutines happened to be scheduled.
func (n *Node) beginIntercept(msg *lnrpc.RPCMiddlewareRequest) chan InterceptOutcome {
	reply := make(chan InterceptOutcome, 1)
	n.middleware.mu.Lock()
	defer n.middleware.mu.Unlock()
	n.middleware.nextMsg++
	msg.MsgId = n.middleware.nextMsg
	n.middleware.waiting[msg.MsgId] = reply
	return reply
}

func (n *Node) awaitIntercept(reply chan InterceptOutcome, msg *lnrpc.RPCMiddlewareRequest) InterceptOutcome {
	select {
	case n.middleware.intercepts <- msg:
	case <-time.After(WaitTimeout):
		n.abandonIntercept(msg.MsgId)
		return InterceptOutcome{Err: errNoMiddlewareStream}
	}
	select {
	case out := <-reply:
		return out
	case <-time.After(WaitTimeout):
		n.abandonIntercept(msg.MsgId)
		return InterceptOutcome{Err: errMiddlewareSilent}
	}
}

// abandonIntercept drops a timed-out interception from the waiting set, so a
// fake that ran a hundred of them is not still holding a hundred channels.
func (n *Node) abandonIntercept(msgID uint64) {
	n.middleware.mu.Lock()
	defer n.middleware.mu.Unlock()
	delete(n.middleware.waiting, msgID)
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
