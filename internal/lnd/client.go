package lnd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// State is what the admin UI shows about the node connection (spec §9). It is
// the alternative to exiting: every failure this package meets becomes one of
// these plus a retry (§11 forbids crash loops).
type State string

const (
	// StateNotLinked: the guard has not written the credentials yet.
	StateNotLinked State = "not_linked"
	// StateConnecting: credentials exist, the node has not answered yet.
	StateConnecting State = "connecting"
	// StateReady: the last call to the node succeeded.
	StateReady State = "ready"
	// StateRelink: the node rejected our macaroon — typically rotation. The
	// guard is being asked to re-bake; the server stays up throughout (§6).
	StateRelink State = "relink"
)

// Default reconnect bounds (spec §6: capped exponential backoff, forever).
const (
	DefaultMinBackoff = time.Second
	DefaultMaxBackoff = time.Minute
)

// Options configure a Client. The zero value is usable except for Broker, which
// only the wiring in cmd/brollyzapper can supply.
type Options struct {
	Log    *slog.Logger
	Broker CredentialBroker
	// MinBackoff and MaxBackoff bound the reconnect delay. Tests set them
	// small so the retry loop costs nothing.
	MinBackoff, MaxBackoff time.Duration
}

// Client is the server's connection to LND. It holds no admin credential and
// cannot mint its own: everything it uses was baked by the guard (§3, §6).
type Client struct {
	address string
	creds   CredentialSource
	broker  CredentialBroker
	log     *slog.Logger

	minBackoff, maxBackoff time.Duration

	// retry interrupts an in-flight reconnect backoff. Buffered so RetryNow
	// never blocks its caller, which is an HTTP handler.
	//
	// A token left in it while the stream is healthy skips exactly one future
	// backoff and cannot compound — the buffer is one deep and each wait
	// receives at most one. Deliberately not drained on success: an operator who
	// clicked Re-link wanted the next attempt sooner, whenever it comes.
	retry chan struct{}

	reBakeMu   sync.Mutex
	lastReBake time.Time

	state         atomic.Value // State
	streamRunning atomic.Bool

	mu   sync.Mutex
	conn *grpc.ClientConn
}

// New builds a client for the node at address, reading its credentials from
// creds. It performs no I/O: missing credentials are a state, not a
// construction failure.
func New(address string, creds CredentialSource, opts Options) *Client {
	c := &Client{
		address:    address,
		creds:      creds,
		broker:     opts.Broker,
		log:        opts.Log,
		minBackoff: opts.MinBackoff,
		maxBackoff: opts.MaxBackoff,
		retry:      make(chan struct{}, 1),
	}
	if c.log == nil {
		c.log = logging.Default()
	}
	if c.minBackoff <= 0 {
		c.minBackoff = DefaultMinBackoff
	}
	if c.maxBackoff < c.minBackoff {
		c.maxBackoff = max(DefaultMaxBackoff, c.minBackoff)
	}
	c.state.Store(StateNotLinked)
	if c.creds.Ready() {
		c.state.Store(StateConnecting)
	}
	return c
}

// RetryNow interrupts an in-flight reconnect backoff so the next attempt
// happens immediately.
//
// §6's capped backoff is right for a node that is not answering; it is wrong
// for a credential that has just been replaced. On the box the UI sat at
// "connecting" for minutes after Re-link had already fixed the macaroon, which
// reads as a failed repair (d46.20).
//
// It never blocks: the caller is an HTTP handler, and a retry already pending
// is the same request.
func (c *Client) RetryNow() {
	select {
	case c.retry <- struct{}{}:
	default:
	}
}

// State is the current connection state, for the admin UI.
func (c *Client) State() State {
	state, _ := c.state.Load().(State)
	return state
}

func (c *Client) setState(s State) { c.state.Store(s) }

// Close releases the connection. It is safe to call more than once.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *Client) closeLocked() error {
	conn := c.conn
	c.conn = nil
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// lightning returns the RPC client, dialling on first use.
//
// TLS is verified against the certificate in the credential volume. There is
// deliberately no option to turn that off: §16 names prior art that dials
// without verification, and an arch test asserts this tree cannot grow one.
func (c *Client) lightning() (lnrpc.LightningClient, error) {
	conn, err := c.connection()
	if err != nil {
		return nil, err
	}
	return lnrpc.NewLightningClient(conn), nil
}

// connection is the dial, and there is exactly one of it.
//
// Both services this client speaks — Lightning and, from d24.2, Router — are
// built over the same *grpc.ClientConn, so the TLS verification and the per-RPC
// macaroon have one implementation rather than two that can drift. That is the
// same reason CredentialSource exists, applied a level down.
func (c *Client) connection() (*grpc.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn, nil
	}
	if !c.creds.Ready() {
		c.setState(StateNotLinked)
		return nil, ErrNotLinked
	}
	transport, err := credentials.NewClientTLSFromFile(c.creds.CertPath(), "")
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", c.creds.CertPath(), err)
	}
	conn, err := grpc.NewClient(c.address,
		grpc.WithTransportCredentials(transport),
		// Connection-level, not per-call. grpc-go applies BOTH sets when a call
		// also carries credentials ("if these credentials are provided both via
		// dial options and call options, then both sets of credentials will be
		// applied" — its own comment), so two macaroons would travel under one
		// metadata key and LND would refuse the pair. One credential per client
		// is therefore not a stylistic choice: it is the only shape that works,
		// and it is what makes "the receive paths never present the spend
		// macaroon" structural (§6).
		grpc.WithPerRPCCredentials(macaroonCredential{source: c.creds}),
	)
	if err != nil {
		return nil, fmt.Errorf("dialling %s: %w", c.address, err)
	}
	c.conn = conn
	if c.State() == StateNotLinked {
		c.setState(StateConnecting)
	}
	return conn, nil
}

// reconnect drops the connection so the next call re-reads tls.cert. LND
// regenerates its certificate on expiry, and the guard re-copies it; without
// this the process would keep dialling with the old one.
func (c *Client) reconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.closeLocked()
}

// recordState maps a call's outcome onto the state the admin UI shows, and
// reports whether the node ANSWERED and would not accept what we sent.
//
// The state takes the narrow test even where the caller acts on the broad one:
// "re-link needed" is a sentence claiming the node verified our macaroon and
// refused it, and LND answers codes.Unknown while it is merely restarting.
func (c *Client) recordState(err error) bool {
	switch {
	case err == nil:
		c.setState(StateReady)
	case errors.Is(err, ErrNotLinked) || !c.creds.Ready():
		// Once the connection is cached, an absent credential no longer arrives
		// as the sentinel: grpc-go stringifies the per-RPC credential's error
		// into an Unauthenticated status, so errors.Is stops matching. Asking
		// the credential source directly is what keeps "the guard has not
		// written it yet" from being reported as "the node rejected it".
		c.setState(StateNotLinked)
	case IsAuthFailure(err):
		c.setState(StateRelink)
		return true
	case IsCredentialRejected(err):
		c.setState(StateConnecting)
		return true
	}
	return false
}

// observe records the outcome of a PER-REQUEST call. It moves the state and
// nothing else — and takes no context, because it asks nobody for anything.
// The asymmetry with observeStream below is the rule, visible in the signature.
//
// A per-request call's failure is an answer about the request (§6, o34.10).
// AddInvoice sits behind the public LNURL callback and LND reports most handler
// errors as codes.Unknown, so acting on one would let an unauthenticated caller
// drive the credential broker one BakeMacaroon RPC and one macaroon.bake row at
// a time — and a re-bake storm trims §12's 10,000-row trail down to nothing but
// itself. P3's SendPaymentV2 has the same shape: no route, expired invoice,
// insufficient balance.
//
// Losing nothing matters here, because the invoice stream is always running and
// is a complete self-heal path on its own. A second trigger would add risk
// without adding recovery.
func (c *Client) observe(err error) error {
	switch {
	case err == nil:
		c.setState(StateReady)
	case errors.Is(err, ErrNotLinked) || !c.creds.Ready():
		c.setState(StateNotLinked)
	}
	// Any other failure moves nothing. It is an answer about the request, and
	// on the public callback the requester is a stranger: letting one overwrite
	// "re-link needed" with "connecting" would let them hide the very state
	// d46.20 exists to show, while the credential is still bad.
	return err
}

// observeStream records the outcome of the invoice stream — the ONE path that
// may conclude anything about the credential, and ask the guard to re-bake.
//
// It qualifies because it carries no caller input and runs for the process
// lifetime: nothing a stranger sends can make it fail, and it will notice a bad
// credential within one backoff whether or not anyone is looking. An arch rule
// asserts this is the only call site.
func (c *Client) observeStream(ctx context.Context, err error) error {
	if c.recordState(err) {
		c.requestReBake(ctx, err)
	}
	return err
}

// ReBakeInterval is the shortest gap between two re-bake requests.
//
// Without it the request rate is set by whatever is failing. A node that
// answers a non-benign code for a reason a re-bake cannot fix — a permission
// the node does not recognise, say — turns every caller into a bake loop, and
// the recon path has no backoff of its own: one ceiling change is one demand is
// one Check is one rejected call is one bake, at socket speed. Each successful
// bake also writes a macaroon.bake row, so an unbounded loop trims §12's
// 10,000-row trail down to nothing but itself — log rotation erasing the answer,
// by another route.
const ReBakeInterval = time.Minute

// reBakeTimeout bounds one request to the guard. The caller is the invoice
// stream, and the socket's own deadline is 30 seconds: long enough that a wedged
// guard would hold the stream down for longer than the backoff it is about to
// wait anyway.
const reBakeTimeout = 5 * time.Second

// requestReBake is §6's recovery: the node stopped accepting our macaroon —
// almost always because it was rotated — so the guard is asked for a new one.
// The server does not exit; the guard's bounded exit is the only sanctioned
// one in the codebase.
func (c *Client) requestReBake(ctx context.Context, cause error) {
	// No broker means this process cannot re-link and must not say it can. The
	// guard builds a Client of its own with none, and "re-link needed" is a
	// sentence about the server (§6).
	if c.broker == nil {
		return
	}
	if !c.mayReBake() {
		c.log.Debug("not asking the guard to re-bake again yet",
			"error", cause.Error(), "interval", ReBakeInterval.String())
		return
	}
	c.log.Warn("lnd rejected our macaroon; re-link needed", "error", cause.Error())

	ctx, cancel := context.WithTimeout(ctx, reBakeTimeout)
	defer cancel()
	if err := c.broker.RequestReceiveBake(ctx); err != nil {
		c.log.Warn("the guard could not re-bake the receive macaroon", "error", err.Error())
	}
}

// mayReBake reports whether enough time has passed since the last request, and
// records this one if so.
func (c *Client) mayReBake() bool {
	c.reBakeMu.Lock()
	defer c.reBakeMu.Unlock()
	now := time.Now()
	if !c.lastReBake.IsZero() && now.Sub(c.lastReBake) < ReBakeInterval {
		return false
	}
	c.lastReBake = now
	return true
}

// IsAuthFailure reports whether the node VERIFIED our macaroon and refused it.
// Both codes appear: Unauthenticated for a macaroon LND cannot verify,
// PermissionDenied for one that verifies but grants too little.
//
// This is the narrow question, and it is the one the guard asks about
// admin.macaroon: a verified-and-refused macaroon means the node's macaroons
// were rotated, and a container restart re-resolves the bind mount onto the
// replacement. The server asks the broader question below — see the note there
// on why the two are deliberately different.
func IsAuthFailure(err error) bool {
	switch status.Code(err) {
	case codes.Unauthenticated, codes.PermissionDenied:
		return true
	default:
		return false
	}
}

// IsCredentialRejected reports whether the node answered and would not accept
// what we sent. It is what the SERVER acts on, because its recovery is to ask
// the guard for a fresh macaroon.
//
// It is a whitelist of benign codes rather than a list of rejection messages,
// and that is the whole point of d46.20. The failure measured on the box was
//
//	code = Unknown  desc = cannot determine data format of binary-encoded macaroon
//
// — LND's macaroon parser refusing the bytes before anything could verify them,
// so there was no Unauthenticated to match on. Matching that sentence would
// work until LND rewords it, and the regression would be silent and identical
// to the original bug: a credential that goes bad at 3am stays bad until
// morning, on an app whose entire purpose is to receive unattended.
//
// So this fails TOWARD re-baking, and ReBakeInterval is what makes that safe:
// the cost of a false positive is one request per minute, not one per failure.
// The operator-facing state takes the narrow test instead — see observe.
//
// Errors that never reached the node — an unreadable tls.cert, a dial failure —
// are not gRPC statuses at all and are excluded, because re-baking cannot fix
// them either.
func IsCredentialRejected(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch st.Code() {
	// The node did not answer, so the credential was never tested.
	case codes.OK, codes.Canceled, codes.DeadlineExceeded, codes.Unavailable,
		// The node answered the REQUEST — a hash it does not know, an argument
		// it will not take, a method it does not implement — which says nothing
		// about the credential that carried it.
		codes.NotFound, codes.AlreadyExists, codes.InvalidArgument,
		codes.FailedPrecondition, codes.OutOfRange, codes.ResourceExhausted,
		codes.Unimplemented:
		return false
	default:
		return true
	}
}

// GetInfo reads the node's identity and sync state.
func (c *Client) GetInfo(ctx context.Context) (*lnrpc.GetInfoResponse, error) {
	client, err := c.lightning()
	if err != nil {
		return nil, c.observe(err)
	}
	info, err := client.GetInfo(ctx, &lnrpc.GetInfoRequest{})
	return info, c.observe(err)
}

// AddInvoice mints an invoice.
func (c *Client) AddInvoice(ctx context.Context, invoice *lnrpc.Invoice) (*lnrpc.AddInvoiceResponse, error) {
	client, err := c.lightning()
	if err != nil {
		return nil, c.observe(err)
	}
	added, err := client.AddInvoice(ctx, invoice)
	return added, c.observe(err)
}

// LookupInvoice reads one invoice back from the node by payment hash.
func (c *Client) LookupInvoice(ctx context.Context, paymentHash []byte) (*lnrpc.Invoice, error) {
	client, err := c.lightning()
	if err != nil {
		return nil, c.observe(err)
	}
	invoice, err := client.LookupInvoice(ctx, &lnrpc.PaymentHash{RHash: paymentHash})
	return invoice, c.observe(err)
}

// ChannelBalance is what recon compares the wallet against (spec §5).
func (c *Client) ChannelBalance(ctx context.Context) (*lnrpc.ChannelBalanceResponse, error) {
	client, err := c.lightning()
	if err != nil {
		return nil, c.observe(err)
	}
	balance, err := client.ChannelBalance(ctx, &lnrpc.ChannelBalanceRequest{})
	return balance, c.observe(err)
}

// SleepContext waits for d, or until ctx is done, whichever comes first.
//
// Exported for the guard's rotation delay. The reconnect loop does NOT use it:
// its wait has a third case, an operator asking to stop waiting, and threading
// an interrupt channel through a helper whose only other caller always passes
// nil buys less than it costs (see waitBeforeRetry).
func SleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
