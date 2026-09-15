package preflight

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd"
)

// ServerCredentialInterval is how often the server's own credential is put to
// the node (`20i.21`).
//
// A MINUTE, because the answer changes when an operator changes something — an
// address, a network, a re-link — and a minute is shorter than it takes to walk
// from that change to the Node page and back. It bounds the cost the other way:
// this report is built on every admin render and before every payment, so at
// most one GetInfo a minute reaches the node however busy either is. Revisit if
// the probe stops being a single local read-only call.
const ServerCredentialInterval = time.Minute

// serverCredentialTimeout bounds one probe. Long enough for a node under load to
// answer a GetInfo; short enough that a wedged dial cannot hold a goroutine for
// longer than the interval it is rate-limited by.
const serverCredentialTimeout = 10 * time.Second

// ProbeResult is one answer to "does the server's own credential work", and when
// it was given. The zero value is "not asked yet", which is not a pass.
type ProbeResult struct {
	At  time.Time
	Err error
}

// ProbeOptions tunes a CredentialProbe. The zero value is production's.
type ProbeOptions struct {
	Interval time.Duration
	Now      func() time.Time
	// Spawn runs a refresh. Production's is `go`; a test that wants to read the
	// outcome without waiting passes a function that runs it inline.
	Spawn func(func())
}

// CredentialProbe puts the server's own credential to the node, at most once per
// interval, and caches the answer with its time (`20i.21`).
//
// A READ NEVER WAITS ON THE NODE. Result returns the last answer and, when that
// answer is due, starts a refresh beside it; the page says "as of", which is what
// makes a cached answer honest. A probe on the request path would put a GetInfo
// — and, against an unreachable node, a dial timeout — in front of every admin
// page and every payment, which is `e0n` made worse.
//
// THE INTERVAL IS TIMED FROM THE LAST ATTEMPT, not the last success, so a node
// that is failing is not asked on every render for exactly as long as it fails.
type CredentialProbe struct {
	ctx      context.Context
	probe    func(context.Context) error
	interval time.Duration
	now      func() time.Time
	spawn    func(func())

	mu        sync.Mutex
	last      ProbeResult
	attempted time.Time
	running   bool
	closed    bool
	// inFlight is joined by Close. Added to only under mu and only while not
	// closed, so no Add can race the Wait.
	inFlight sync.WaitGroup
}

// NewCredentialProbe builds a probe over probe, which the caller wires to the
// RECEIVE client's GetInfo: read-only, and the only credential the server may
// present outside a payment. ctx ends every probe still running at shutdown.
func NewCredentialProbe(ctx context.Context, probe func(context.Context) error, opts ProbeOptions) *CredentialProbe {
	if opts.Interval <= 0 {
		opts.Interval = ServerCredentialInterval
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Spawn == nil {
		opts.Spawn = func(f func()) { go f() }
	}
	return &CredentialProbe{ctx: ctx, probe: probe, interval: opts.Interval, now: opts.Now, spawn: opts.Spawn}
}

// Result is the last answer, starting a refresh first when one is due.
func (p *CredentialProbe) Result() ProbeResult {
	p.mu.Lock()
	now := p.now()
	due := !p.closed && !p.running && (p.attempted.IsZero() || now.Sub(p.attempted) >= p.interval)
	if due {
		p.running, p.attempted = true, now
		p.inFlight.Add(1)
	}
	p.mu.Unlock()

	if due {
		p.spawn(p.refresh)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last
}

// Close starts no further probes and waits for one in flight.
//
// serve() closes the node client when it returns, and joins every background
// goroutine first so none is mid-call when that happens. A probe is started by
// a render rather than by serve(), so it is joined here instead (go-review,
// `20i.21`).
func (p *CredentialProbe) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.inFlight.Wait()
}

func (p *CredentialProbe) refresh() {
	defer p.inFlight.Done()
	ctx, cancel := context.WithTimeout(p.ctx, serverCredentialTimeout)
	defer cancel()
	err := p.probe(ctx)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.last = ProbeResult{At: p.now(), Err: err}
	p.running = false
}

// serverCredentialCheck is `20i.21`'s row: the server's own credential, used.
//
// NOT A PASS BEFORE THE FIRST ANSWER (`d46.25`, §11). A tick over a credential no
// call has presented is the confidence without a bound that §11 calls worse than
// no checklist.
//
// THE DETAIL IS THE APP'S, never the node's status text, and it carries the time
// on both outcomes: this is the one row on the panel that is a cached answer
// rather than a fresh read, so it is the one that must say when it was true.
func serverCredentialCheck(in Inputs) (Check, *ProbeResult) {
	c := Check{
		ID:     CheckServerCredential,
		Title:  "The app's own credential works against your node",
		Threat: "Server credential refused while the guard's is accepted — the Node page's reachability line is the guard's view, so a server that cannot use its own receive macaroon (its address lock, on a container with more than one network) is otherwise invisible until a payment is due.",
		OK:     true,
		Blocks: BlocksNothing,
	}
	if in.ServerCredential == nil {
		return c, nil
	}
	result := in.ServerCredential()
	if result.At.IsZero() {
		c.OK = false
		c.Detail = "Not checked yet — opening an admin page asks your node, and the answer arrives within seconds."
		return c, &result
	}
	asOf := "as of " + clock(result.At)
	if result.Err == nil {
		c.Detail = "Your node accepted it, " + asOf + "."
		return c, &result
	}
	c.OK = false
	var nameErr *lnd.CertificateNameError
	switch {
	case errors.Is(result.Err, lnd.ErrNotLinked):
		c.Detail = "The app has no credential for your node yet; the guard writes it once it can reach LND"
	case errors.As(result.Err, &nameErr):
		c.Detail = "The app could not connect: your node's certificate does not name the address it dials — the certificate row says what to add"
	case lnd.IsAuthFailure(result.Err):
		c.Detail = "Your node refused the app's own credential"
	case lnd.IsCredentialRejected(result.Err):
		// The node ANSWERED, with a code that is neither an auth failure nor one
		// of the benign ones — d46.20's malformed macaroon arrives as Unknown, and
		// so does a node that is restarting. Not "refused", which claims the node
		// verified the credential; not "could not reach", which it plainly did.
		c.Detail = "Your node answered but would not accept the request made with the app's own credential"
	default:
		c.Detail = "The app could not reach your node with its own credential"
	}
	c.Detail = fmt.Sprintf("%s (%s).", c.Detail, asOf)
	return c, &result
}
