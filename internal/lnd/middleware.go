package lnd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
)

// Interception is one gRPC message LND is asking the middleware about.
//
// It is a flattened RPCMiddlewareRequest with the transport removed: the guard
// decides policy and must not have to know about oneof wrappers, message ids or
// feedback framing. What it keeps is what a decision can be made from.
type Interception struct {
	// RequestID identifies the intercepted gRPC CALL, not the message. A
	// request and every response on the same streaming call share it, which is
	// what lets a decision taken on the request be revisited when its outcome
	// arrives.
	RequestID uint64
	// MethodURI is the full RPC name, e.g. "/routerrpc.Router/SendPaymentV2".
	MethodURI string
	// Serialized is the message in binary protobuf form — or, when IsError, the
	// error string.
	Serialized []byte
	IsError    bool
	// CustomCaveatCondition is the <condition> half of the caveat that routed
	// this message here: the nonce the guard baked into the credential.
	//
	// Carried and deliberately NOT acted on, which is why it is here rather than
	// dropped: a future reader will wonder whether the guard should refuse a
	// nonce it did not bake, and the answer is no. The server holds an open gRPC
	// connection carrying the credential the guard replaces on renewal, so
	// matching it would refuse payments in flight across every re-bake. The root
	// key is what revokes an old credential, not the nonce.
	CustomCaveatCondition string
	// Session identifies the middleware STREAM this arrived on, and it exists
	// because RequestID does not identify a call across one.
	//
	// LND allocates request ids from a counter on its interceptor chain, which
	// is built at LND startup — so after an LND restart the ids begin again at
	// 1 while the middleware reconnects and carries on. A policy that keyed
	// per-call state on RequestID alone would then match a NEW call to an OLD
	// record: a 1 000 msat payment failing would return a 90 000 msat record
	// made before the restart, which is precisely the decrement on loss of
	// observation §14 forbids, and a compromised server can drive it on purpose
	// by walking the ids with payments certain to fail.
	//
	// It changes on every registration, so a record made on one stream can only
	// ever be matched by that stream.
	Session string
}

// Interceptor is the policy this package needs in order to run a middleware.
//
// Declared HERE, by the consumer of the policy, for the same reason
// CredentialBroker is: internal/guard supplies it and cmd/brollyguard wires the
// two together. internal/lnd must never import internal/guard (§3).
type Interceptor interface {
	// InterceptRequest decides whether an RPC may proceed. A non-nil error
	// ABORTS the call and its text is returned to the gRPC client, so it is
	// read by whoever asked for the payment.
	//
	// It is called before LND has acted on the request. That is the whole
	// property §14 asks for: an attempt over the cap is rejected before LND
	// sees it, not compensated afterwards.
	InterceptRequest(ctx context.Context, in Interception) error
	// ObserveResponse is told what came back. It cannot refuse anything — LND
	// forbids a middleware altering responses to unencumbered macaroons and we
	// do not alter them to ours either — and its errors are not the caller's
	// business, so it returns nothing.
	ObserveResponse(ctx context.Context, in Interception)
	// BOTH MUST RESPECT ctx. They run on the middleware's own goroutines, and
	// RunMiddleware waits for those before returning; an implementation that
	// blocks ignoring ctx wedges the guard's shutdown rather than merely being
	// slow. Each call also carries DecisionTimeout of its own, so an
	// implementation that simply passes ctx down is bounded for free.
	// MiddlewareRegistered is called once LND has confirmed the registration.
	// Until then the guard reports itself as not enforcing, which §11 blocks
	// sending on.
	MiddlewareRegistered()
}

// middlewareSessions numbers registrations within this process. Combined with
// the guard's per-process nonce it is unique across restarts as well.
var middlewareSessions atomic.Uint64

// ErrMiddlewareUnavailable means the node REFUSED a middleware registration —
// not that it could not be reached.
//
// The distinction is the whole reason this error exists, because the two have
// different remedies: an unreachable node is a retry and says nothing, while a
// node that answers "unknown method" is an install with `rpcmiddleware.enable`
// off, which §14 requires be surfaced. Conflating them costs the operator an
// ERROR every backoff during any ordinary LND restart, pointing at a setting
// that is fine — measured, not supposed.
var ErrMiddlewareUnavailable = errors.New("lnd: the node did not accept a middleware registration")

// refusedRegistration classifies a failure to register.
//
// BY gRPC STATUS CODE, because the transport cannot be told apart from the
// answer any other way: NewStream is fail-fast, so an unreachable node fails at
// exactly the same call as a node that will not have us. Unavailable and
// DeadlineExceeded are the node being absent; Unimplemented, InvalidArgument
// and PermissionDenied are the node answering.
func refusedRegistration(err error) bool {
	switch status.Code(err) {
	case codes.Unimplemented, codes.InvalidArgument, codes.PermissionDenied, codes.Unauthenticated:
		return true
	default:
		return false
	}
}

// DecisionTimeout bounds one interception.
//
// LND gives a middleware `rpcmiddleware.intercepttimeout` — two seconds by
// default — and rejects the RPC when it expires. Past that point our answer is
// worthless, so a decision still running is a goroutine held for nothing; on the
// path a compromised server can drive, that is unbounded goroutines held for
// nothing. Bounded here at the same two seconds rather than lower: refusing
// early would refuse payments LND would still have accepted.
const DecisionTimeout = 2 * time.Second

// maxConcurrentDecisions bounds the fan-out.
//
// One goroutine per intercepted message with no ceiling is a resource the
// SERVER controls: it holds the spend macaroon and can pipeline SendPaymentV2.
// Beyond this many in flight the read loop waits, which pushes back through the
// stream instead of allocating — and LND's own interceptor timeout turns a
// sustained flood into rejections, which is the fail-closed direction.
const maxConcurrentDecisions = 64

// RunMiddleware registers as an RPC middleware and serves interceptions until
// ctx ends or the stream fails.
//
// SCOPED BY CAVEAT NAME. LND forwards only requests whose macaroon carries
// `lnd-custom brollyguard <nonce>`, so every other app on the node — and this
// app's own receive macaroon — is untouched. That scoping is also what makes
// the failure mode safe: with no middleware registered under this name, LND
// rejects the spend macaroon outright instead of letting it through.
//
// NOT read-only mode, and not addmandatory. Read-only would forward every RPC
// on the node here, and `rpcmiddleware.addmandatory` would block ALL RPC when
// this middleware is absent, taking every other app down with the guard (§14,
// which forbids it by name).
//
// It returns on the first error rather than reconnecting: the caller owns the
// backoff, because the caller is also what reports the registration state, and
// a retry loop buried here would hide the very condition §14 says to surface.
func (c *Client) RunMiddleware(ctx context.Context, in Interceptor) error {
	client, err := c.lightning()
	if err != nil {
		return c.observe(err)
	}
	// Its own cancellable context, cancelled on the way out. A bidi stream is
	// released by grpc-go only on a Recv error, a cancelled stream context or a
	// closed ClientConn — the same rule SendPayment documents — and this one
	// lives for the process, so leaking it leaks the transport with it.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := client.RegisterRPCMiddleware(ctx)
	if err != nil {
		return registrationError(c.observe(err))
	}
	// One per registration, and never reused. See Interception.Session.
	session := strconv.FormatUint(middlewareSessions.Add(1), 10)
	registration := &lnrpc.RPCMiddlewareResponse{
		MiddlewareMessage: &lnrpc.RPCMiddlewareResponse_Register{
			Register: &lnrpc.MiddlewareRegistration{
				MiddlewareName: GuardCaveatName,
				// The caveat name, NOT read-only mode. The two are mutually
				// exclusive in LND, and read-only mode would forward every RPC
				// on the node to this guard.
				CustomMacaroonCaveatName: GuardCaveatName,
			},
		},
	}
	if err := stream.Send(registration); err != nil {
		// A BARE io.EOF HERE IS NOT AN ANSWER, it is grpc-go telling us to go and
		// ask for one. Its contract: Send returns io.EOF once the stream has
		// already terminated, and the real status is obtainable only from Recv.
		//
		// The refusal and this Send race. Usually Send buffers, the handler's
		// Unimplemented arrives at the Recv below, and the classification is
		// right; when the server's teardown wins instead, Send returns EOF,
		// status.Code(io.EOF) is Unknown, refusedRegistration reads Unknown as
		// "not a refusal", and we tell an operator whose rpcmiddleware really is
		// disabled that their node is unreachable. Measured at 1-5 per 100 runs
		// before this line existed, which is exactly often enough to reach CI
		// and look like flakiness rather than the bug the test was written for.
		if errors.Is(err, io.EOF) {
			if _, recvErr := stream.Recv(); recvErr != nil {
				err = recvErr
			}
		}
		return registrationError(c.observe(err))
	}

	// ONE GOROUTINE PER INTERCEPTION, and it is not an optimisation.
	//
	// Deciding costs a round trip to the node — the invoice has to be read
	// before the attempt can be priced — and doing that on the read loop would
	// make every payment wait for the one in front of it, against LND's
	// interceptor timeout. It also matters for correctness downstream: the
	// guard's window is a read-modify-write, and stateStore was given a mutex in
	// Wave 2 for exactly this shape. A serial loop would hide a lost update
	// rather than prevent one, which is worse — the protection would be
	// untestable and the first concurrent caller would find it missing.
	//
	// SENDS ARE SERIALISED. grpc-go forbids concurrent Send on one stream, and
	// answering out of order is fine: LND matches feedback by ref_msg_id, not by
	// arrival.
	var sending sync.Mutex
	var answering sync.WaitGroup
	slots := make(chan struct{}, maxConcurrentDecisions)
	// WAITED FOR before returning, so no goroutine touches the stream — or the
	// interceptor — after this function has handed its error back.
	defer answering.Wait()
	defer cancel()

	// BEFORE the handshake, a failure is an answer about the REGISTRATION; after
	// it, it is a stream that ended. LND reports "RPC middleware not enabled in
	// config" from the handler rather than from the stream setup, so a refusal
	// arrives here on the first Recv and not at RegisterRPCMiddleware — which is
	// exactly where the first version of this code stopped classifying, and it
	// then told every operator with a restarting node to go and check a setting.
	registered := false
	for {
		msg, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !registered {
				return registrationError(c.observe(err))
			}
			return c.observe(fmt.Errorf("lnd: the middleware stream ended: %w", err))
		}
		// The handshake. LND sends this once, after it has accepted the
		// registration, and it takes no feedback — replying to it is an error.
		if msg.GetRegComplete() {
			registered = true
			c.observe(nil) //nolint:errcheck // nil in, nil out; this records the success
			in.MiddlewareRegistered()
			continue
		}
		// Taken on the READ LOOP, so a flood stops being read rather than
		// becoming goroutines. Released by the decision that took it.
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		answering.Add(1)
		go func() {
			defer answering.Done()
			defer func() { <-slots }()
			feedback := c.decide(ctx, in, session, msg)
			sending.Lock()
			defer sending.Unlock()
			if err := stream.Send(feedback); err != nil && ctx.Err() == nil {
				// Not returned: this is not the read loop, and a failed send
				// means the stream is already going. Recv reports it, once,
				// with the error the caller acts on.
				c.log.Warn("could not answer an intercepted RPC; LND will reject it at its "+
					"interceptor timeout", "error", err.Error())
			}
		}()
	}
}

// decide turns one intercepted message into the feedback LND is waiting for.
//
// EVERY message gets an answer, including the ones there is nothing to say
// about. LND blocks the intercepted RPC until the middleware replies with the
// matching ref_msg_id, so a message this guard does not care about must still
// be answered — silence is not "allow", it is a stalled call and, at the
// interceptor timeout, a rejected one.
func (c *Client) decide(ctx context.Context, in Interceptor, session string, msg *lnrpc.RPCMiddlewareRequest) *lnrpc.RPCMiddlewareResponse {
	ctx, cancel := context.WithTimeout(ctx, DecisionTimeout)
	defer cancel()
	feedback := &lnrpc.InterceptFeedback{}
	switch {
	case msg.GetRequest() != nil:
		if err := in.InterceptRequest(ctx, interception(msg, session, msg.GetRequest())); err != nil {
			feedback.Error = err.Error()
		}
	case msg.GetResponse() != nil:
		in.ObserveResponse(ctx, interception(msg, session, msg.GetResponse()))
	}
	// StreamAuth and anything else falls through to an empty feedback, which is
	// LND's "accepted, carry on". Refusing at StreamAuth would refuse the whole
	// SendPaymentV2 stream before its request message ever arrived, which is
	// one message too early to know the amount.
	return &lnrpc.RPCMiddlewareResponse{
		RefMsgId:          msg.GetMsgId(),
		MiddlewareMessage: &lnrpc.RPCMiddlewareResponse_Feedback{Feedback: feedback},
	}
}

// registrationError says which of the two failures this was.
func registrationError(err error) error {
	if refusedRegistration(err) {
		return fmt.Errorf("%w: %w", ErrMiddlewareUnavailable, err)
	}
	return fmt.Errorf("lnd: could not reach the node to register a middleware: %w", err)
}

func interception(msg *lnrpc.RPCMiddlewareRequest, session string, body *lnrpc.RPCMessage) Interception {
	return Interception{
		RequestID:             msg.GetRequestId(),
		MethodURI:             body.GetMethodFullUri(),
		Serialized:            body.GetSerialized(),
		IsError:               body.GetIsError(),
		CustomCaveatCondition: msg.GetCustomCaveatCondition(),
		Session:               session,
	}
}
