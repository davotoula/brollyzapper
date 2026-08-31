package nwc

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/store"
)

// The collaborators, declared HERE because this is the consumer (§3). Each is
// the narrowest slice this package needs — notably Wallet, which has Balance and
// nothing that can spend: pay_invoice is d24.4's, and a seam that cannot reach
// Reserve cannot grow one by accident before its ladder exists.

// Wallet is the ceiling. §8: get_balance returns THIS, never the node's.
type Wallet interface {
	Balance(ctx context.Context) (int64, error)
}

// Invoices is the receiving half, shared with the LNURL path so an NWC-minted
// invoice lands in the same table a zap does (§8).
type Invoices interface {
	Mint(ctx context.Context, amountMsat int64, description string) (Invoice, error)
	Lookup(ctx context.Context, paymentHash string) (Invoice, bool, error)
	List(ctx context.Context, filter store.TxnFilter) ([]store.Txn, error)
}

// Invoice is what Mint and Lookup answer with.
type Invoice struct {
	Bolt11      string
	PaymentHash string
	AmountMsat  int64
	Description string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	SettledAt   time.Time
	Settled     bool
}

// Node is the read-only node facts get_info reports.
type Node interface {
	Info(ctx context.Context) (NodeInfo, error)
}

// NodeInfo is §8's get_info payload, minus the parts we compute.
type NodeInfo struct {
	Alias       string
	Pubkey      string
	Network     string
	BlockHeight uint32
}

// Connections is the store slice this needs.
type Connections interface {
	ActiveNWCConnections(ctx context.Context) ([]store.NWCConnection, error)
	TouchNWCConnection(ctx context.Context, id int64, at time.Time) error
	RecordNWCRefusal(ctx context.Context, id int64, code, message string, at time.Time) error
	// NoteNWCPanic and PauseNWCConnection are Fix C's quarantine (`xmc`): a
	// pairing whose requests keep crashing the handler stops being served, and
	// the count survives the restarts a crash loop produces.
	NoteNWCPanic(ctx context.Context, id int64) (int, error)
	PauseNWCConnection(ctx context.Context, id int64, reason string, at time.Time) error
	ClaimNWCRequest(ctx context.Context, eventID string, connectionID int64,
		method, placeholderJSON string, at time.Time) (bool, string, time.Time, error)
	CompleteNWCRequest(ctx context.Context, eventID, responseJSON string, at time.Time) error
	PruneNWCHandled(ctx context.Context, before time.Time) (int64, error)
	ReserveNWCBudget(ctx context.Context, id, amountMsat int64, now, nextRenewal time.Time) (store.BudgetOutcome, error)
	AdjustNWCBudget(ctx context.Context, id, deltaMsat int64) error
	Setting(ctx context.Context, key string) (string, bool, error)
	SetSetting(ctx context.Context, key, value string) error
}

// Relays is the pool slice: one subscription per connection, and publishing the
// info and response events.
//
// PublishToConnection, never Publish, and the narrowing is the point (§3).
// Publish sends to the operator's configured relays plus whatever it is handed,
// so a service holding it could put an unencrypted info event — a connection's
// service pubkey and capabilities — on the operator's public zap-receipt relays.
// §8 step 6 is "the pairing's own relays", and this seam takes a type that only
// a connection row's list is meant to fill (nostr.ConnectionRelays), with an
// internal/arch rule policing where those values come from. Before d24.18 the
// seam took ONE relay URL and the guarantee was read as structural; it was
// narrower than that — it constrained the arity of a call, not the provenance of
// its argument, and a loop over DefaultRelays would have satisfied it.
type Relays interface {
	Subscribe(ctx context.Context, relayURL string, filter gonostr.Filter) (*nostr.Subscription, error)
	PublishToConnection(ctx context.Context, event gonostr.Event,
		relays nostr.ConnectionRelays) []nostr.PublishResult
}

// Options configure a Service. The zero value is usable except for Now.
type Options struct {
	Log *slog.Logger
	Now func() time.Time

	// Backoff is how long a connection waits before re-subscribing after its
	// relay drops it. Zero means ReconnectBackoff.
	//
	// A knob because a test that had to wait the real one would either be slow
	// or would assert nothing; the reconnect is the behaviour, and the delay is
	// a policy the caller owns — the same shape as Run's prune tick.
	Backoff time.Duration

	// Demand is the send end of the channel Run reads for reload requests. The
	// service nudges it when Fix C pauses a pairing, so the pause takes effect
	// at once rather than at the next thing the operator happens to do.
	//
	// The SAME channel cmd wires to Run and to the Connections page: "please
	// re-read the connection table" is one idea and deserves one lever.
	Demand chan<- struct{}

	// Audit writes a capability refusal to §12's durable trail (d24.14).
	//
	// NIL IS VALID, the same requirement internal/nostr's pool states: this
	// package's tests build services by the dozen and a constructor that
	// demanded a sink would make every one of them carry a fake for nothing.
	// Without one a refusal still LOGS — what is lost is the durable row, not
	// the control.
	Audit Auditor
}

// Auditor is the audit seam, declared HERE because this is the consumer (§3).
//
// Byte-identical to the interface internal/nostr, internal/zap and internal/recon
// declare under the same name: four consumers of one shape, findable by one
// grep, and none of them importing a database.
//
// One method, and it is logging.Auditor's, whose contract is the log line and
// the durable row TOGETHER. A service holding this does not also write its own
// WARN for the same event — two would be one refusal reported twice.
type Auditor interface {
	Record(ctx context.Context, level slog.Level, msg string, event logging.Event,
		attrs ...slog.Attr) error
}

// Service is §8's wallet service.
type Service struct {
	store    Connections
	relays   Relays
	purse    Wallet
	invoices Invoices
	node     Node
	spend    Spend
	log      *slog.Logger
	audit    Auditor
	now      func() time.Time
	backoff  time.Duration

	// refusals is the hourly bound on audited capability refusals. One window
	// for the service rather than one per connection: the trail is a single
	// fixed ring, so what has to be bounded is writes to IT.
	refusals *logging.RefusalBudget
	// demand is the SEND end of the very channel Run reads, so the service can
	// ask for a reload the same way the Connections page does (`xmc` Fix C).
	//
	// One mechanism, not two. A private channel here would mean a second select
	// arm in Run with a byte-identical body, and two things to keep in step
	// every time the reload path changes.
	//
	// The pause must not merely close the connection from the worker: reload
	// owns the map of live connections, and a closed entry left in it would be
	// found by the next reload, "refreshed", and kept — a pairing the operator
	// resumed that never comes back.
	//
	// NIL IS VALID, like Audit: a service nobody wired a channel to still pauses
	// the pairing, it just waits for the next reload somebody else triggers.
	demand chan<- struct{}
	// panics is the hourly bound on contained-panic rows, SEPARATE from
	// refusals on purpose (`xmc`): a client flooding capability refusals must
	// not be able to spend the budget that would have recorded the first panic.
	// A panic is rarer and worth more.
	panics *logging.RefusalBudget

	// serving is every relay-session goroutine, so a shutdown waits for what is
	// in flight. On the Service rather than a local in Run because reload starts
	// them too (uhg).
	serving sync.WaitGroup
	// forgetting is the small goroutine per connection that drops its health
	// once every session of that pairing has gone. Its own group because a
	// shutdown must wait for it too — it outlives the sessions by construction,
	// and a Run that returned while it ran would be a write to the map after the
	// service was done.
	forgetting sync.WaitGroup

	// health is what each pairing's relay session is doing, and reminder is how
	// often a failing one repeats itself in the log (d24.21). See health.go:
	// this is in-memory state about live sockets, deliberately not durable.
	healthMu sync.Mutex
	health   map[int64]*health
	reminder time.Duration

	// The response-delivery policy (d24.25), as fields for the same reason
	// backoff is one: a test that had to wait the real spacing would either be
	// slow or would assert nothing. The DEFAULTS are the policy — see publish.go
	// — and one test asserts each of them at its real value.
	attemptTimeout  time.Duration
	responseRetries []time.Duration
}

// New builds the service. It performs no I/O.
func New(db Connections, relays Relays, purse Wallet, invoices Invoices, node Node,
	spend Spend, opts Options) *Service {
	log := opts.Log
	if log == nil {
		log = logging.Default()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	backoff := opts.Backoff
	if backoff <= 0 {
		backoff = ReconnectBackoff
	}
	return &Service{store: db, relays: relays, purse: purse, invoices: invoices,
		node: node, spend: spend, log: log, audit: opts.Audit, now: now, backoff: backoff,
		reminder: FailureReminderInterval, health: map[int64]*health{},
		refusals:       logging.NewRefusalBudget(MaxAuditedRefusalsPerHour, now),
		panics:         logging.NewRefusalBudget(MaxAuditedPanicsPerHour, now),
		demand:         opts.Demand,
		attemptTimeout: ResponseAttemptTimeout, responseRetries: ResponseRetryDelays}
}

// signer is the connection's key, as this package uses it.
//
// An interface rather than nostr.Identity directly, and the reason is a test
// that could not otherwise exist: §8's step 1 says authorize BEFORE decrypting,
// and the OUTCOME is identical either way — a stranger gets no answer whether
// the check ran first or second. Only counting the crypto can tell them apart,
// and counting needs a seam. Consumer-declared, per §3.
type signer interface {
	PublicKey() string
	Sign(event *gonostr.Event) error
	Encrypt(scheme nostr.Encryption, peerPubkey, plaintext string) (string, error)
	Decrypt(scheme nostr.Encryption, peerPubkey, ciphertext string) (string, error)
}

// connection is one live pairing: its row plus the identity that signs for it.
type connection struct {
	// current is the connection's row, swapped ATOMICALLY on reload (uhg).
	//
	// A pointer to an immutable value rather than a mutable struct: the pay
	// ladder reads permissions, the budget and the per-payment cap through it
	// while a reload may be writing, and a torn read there is a payment measured
	// against half of one limit and half of another. Readers take row(), which
	// is one atomic load and no lock — this is on the path of every request.
	current  atomic.Pointer[store.NWCConnection]
	identity signer

	// slots bounds how many of this connection's requests are handled at once,
	// and working is what a shutdown waits on. See dispatchOne: requests are
	// handled concurrently because a payment can hold a worker for a minute,
	// which is also the whole freshness window.
	slots   chan struct{}
	working sync.WaitGroup

	// The subscriptions are REPLACED on every reconnect, and read by the teardown
	// on another goroutine, so they are behind a mutex rather than plain fields.
	// -race caught this the first time it was not.
	//
	// ONE PER RELAY since d24.18, keyed by relay URL. A pairing names up to
	// MaxPairingRelays of them and is reachable while any one is up; the sessions
	// group is how a teardown knows every one of them has finished.
	mu       sync.Mutex
	subs     map[string]*nostr.Subscription
	sessions sync.WaitGroup
	closed   bool
	// lastAnnounced is what the last info event advertised; see announced().
	lastAnnounced []string
	// done is closed when this connection is finished with, so serving stops on
	// OUR decision rather than on the relay library getting round to closing its
	// events channel. A revoked connection must stop being served now — that is
	// a security property, and waiting on someone else's goroutine to notice is
	// not the same thing (uhg).
	done chan struct{}
}

// announced is the method list this connection's last info event carried.
//
// Compared against, rather than against "what advertised() said a moment ago",
// because advertised() reads the sending setting LIVE — so after the Sending
// page writes it, a before-and-after comparison inside one reload sees no
// change and the republish §8 requires never fires. What was last ANNOUNCED is
// the only thing that cannot move under the comparison. Found by review.
func (c *connection) announced() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastAnnounced
}

func (c *connection) setAnnounced(methods []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastAnnounced = methods
}

// row is this connection's current state. Always non-nil after newConnection.
func (c *connection) row() store.NWCConnection { return *c.current.Load() }

// update swaps in a fresh row, for a reload (uhg).
//
// The whole row at once, because the limits are read together: a swap that
// updated the budget and then the cap would have an instant in which a payment
// could be measured against the new budget and the old cap.
//
// The guarantee only holds for a reader that takes ONE snapshot — see the
// `limits := conn.row()` in payInvoice, which is where the ladder cashes it in.
func (c *connection) update(row store.NWCConnection) { c.current.Store(&row) }

// newConnection builds one around its row.
func newConnection(row store.NWCConnection, identity signer) *connection {
	conn := &connection{
		identity: identity,
		slots:    make(chan struct{}, InFlightPerConnection),
		done:     make(chan struct{}),
	}
	conn.current.Store(&row)
	return conn
}

// attach installs a fresh subscription for one relay, or closes it immediately
// if the service is already shutting down — the window between "the teardown
// ran" and "this reconnect finished dialling" is otherwise a subscription nobody
// will ever close.
// It returns how many of the pairing's relays hold a subscription INCLUDING this
// one, counted under the lock the insert already holds. Read afterwards through a
// second call it would be a check-then-act across goroutines: reload starts one
// session per relay at once, and two of them attaching before either could look
// would both see the final count and neither would announce — a brand-new pairing
// publishing no info event at all until some later reload happened to rescue it
// (found by review).
func (c *connection) attach(relay string, sub *nostr.Subscription) (bool, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		sub.Close()
		return false, 0
	}
	if c.subs == nil {
		c.subs = map[string]*nostr.Subscription{}
	}
	if previous := c.subs[relay]; previous != nil {
		// THE INCUMBENT IS CLOSED, and it was not before d24.18's review found
		// it. A reconnect stores the replacement over the dead one, and nothing
		// else ever closed it: the pool's subscribed-refcount for that relay
		// never came back down (so the relay stayed permanently exempt from the
		// dial-time address check and permanently spared by the transient
		// teardown), and the context child created for it stayed registered on
		// the service's context for the life of the process. Pre-existing, and
		// now multiplied by the number of relays a pairing names.
		previous.Close()
	}
	c.subs[relay] = sub
	return true, len(c.subs)
}

// events is one relay's current subscription channel.
func (c *connection) events(relay string) <-chan *gonostr.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	sub := c.subs[relay]
	if sub == nil {
		return nil
	}
	return sub.Events
}

// relays is the pairing's relay list, in the order its URI named it.
func (c *connection) relays() []string { return c.row().Relays }

// detach drops one relay's subscription — the session is going away, and a
// closed subscription left in the map would make serving() lie.
func (c *connection) detach(relay string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sub := c.subs[relay]; sub != nil {
		sub.Close()
		delete(c.subs, relay)
	}
}

// close ends the connection for good; a reconnect after this is refused, on
// every relay.
func (c *connection) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.done)
	}
	for relay, sub := range c.subs {
		sub.Close()
		delete(c.subs, relay)
	}
}

// Handle runs one request event end to end and returns the response it
// published, if any (§8's six steps, in order).
//
// The bool is whether an answer was published. The SECOND return of handleOne's
// concern — whether the resume point may advance past this event — is not this
// function's to give: see inWindow.
//
// THE ORDER IS THE DESIGN. Each step exists because the one before it has not
// yet established something:
//
//  1. Authorize by pubkey, BEFORE any crypto. A foreign pubkey is refused
//     without a conversation key ever being derived — otherwise anyone on the
//     relay can make this node do elliptic-curve work by addressing it.
//  2. Decrypt with the scheme the client named; absent means NIP-04, and the
//     reply uses whatever they used.
//  3. Replay protection, and the two halves in this order: the freshness window
//     first, because a stale request is refused whether or not it was seen and
//     must NOT be cached; then the durable lookup, which returns the cached
//     response and executes nothing.
//  4. Permission group, else RESTRICTED.
//  5. Dispatch.
//  6. Encrypt and publish to the same relay.
func (s *Service) handle(ctx context.Context, conn *connection, event *gonostr.Event) (Response, bool) {
	// --- 1. authorize, before any crypto -----------------------------------
	if event.PubKey != conn.row().ClientPubkey {
		// Silently. §8: UNAUTHORIZED must never leak whether a connection
		// exists, and answering a stranger at all tells them this pubkey is
		// live. No response event, and no decryption was attempted.
		s.log.Debug("an NWC request from an unknown pubkey was ignored",
			"connection", conn.row().ID)
		return Response{}, false
	}

	// The id must be the one the signature covers, and go-nostr will not check
	// that: its CheckSignature recomputes the id from the body and never looks
	// at the ID field, so an event whose id has been rewritten still verifies
	// and is still delivered. Whoever last touched the event chooses that
	// field — including the relay, which is exactly the party the durable cache
	// defends against. A relay that varied the id on redelivery would strip
	// idempotency, and d24.4 puts pay_invoice behind this same key.
	//
	// Silently, and before any crypto, for the same reason the clause above is:
	// the e-tag of a reply would have to carry the id we just refused to trust.
	if !event.CheckID() {
		s.log.Warn("an NWC request whose id does not match its body was ignored",
			"connection", conn.row().ID)
		return Response{}, false
	}
	// And the signature, which the relay reader also checks — go-nostr refuses a
	// bad one unless Relay.AssumeValid is set, and nothing here sets it. Checked
	// again anyway, for the same reason internal/lnurl checks both on a zap
	// request: "a field of the fork we do not set" is not a guarantee this file
	// can see, and one schnorr verify per authorized request is not a cost worth
	// trading for that. AFTER the pubkey check, so a stranger still cannot make
	// this node do the work.
	if ok, err := event.CheckSignature(); !ok {
		s.log.Warn("an NWC request with a bad signature was ignored",
			"connection", conn.row().ID, "error", errText(err))
		return Response{}, false
	}

	// §8 step 2: the tag names the scheme, and ABSENT MEANS NIP-04 — a legal
	// request from every client written before NIP-44 existed.
	//
	// The one-liner this replaces read the tag's value straight out of GetFirst,
	// which returns a nil *Tag when the tag is not there; Value() has a VALUE
	// receiver, so calling it on that nil auto-dereferences and the process
	// takes a SIGSEGV. On 2026-08-26 one such request from one paired client
	// crash-looped the whole app — LNURL, zaps and the admin UI with it — and it
	// could not recover, because the resume cursor advances after this line
	// (`xmc`).
	//
	// Absent is legal; UNKNOWN still is not. The check below is unchanged: a tag
	// naming a scheme we do not implement gets an error response, because
	// guessing at it would be answering in a cipher the client did not ask for.
	// THE INBOUND REQUEST, ONCE, AFTER IT IS PROVEN (`xmc`).
	//
	// The 0.1.11 outage was diagnosed by stack-trace archaeology because nothing
	// logged the event: a box that crashed 32 times with DEBUG live could not
	// produce the request that did it. The tag names alone would have answered it
	// in seconds — the question was "was there an encryption tag?".
	//
	// PLACED HERE and not at the top of handle. Above the two checks these are
	// unproven attacker-supplied values, and an operator's log would be reading
	// them as fact; internal/arch's checkNWCRequestProof enforces that, and a log
	// line is a read like any other. Not moved into dispatchOne to get in
	// earlier either — that rule is scoped to handle, so stepping outside it
	// would evade rather than satisfy the reasoning.
	//
	// NAMES, NEVER VALUES, and never Content: the content is a paired client's
	// encrypted payload, which §12 lists among the things that do not reach a
	// log, and a tag value carries whatever the client chose to put in it.
	//
	// THE ONE EXCEPTION IS NOT AN EXCEPTION. The `encryption` field below names
	// the negotiated scheme, and it is a token THIS APP chose from a closed
	// vocabulary — see encryptionRequested. Where it coincides with the client's
	// text that is because the vocabulary is fixed, not because the value was
	// copied; an unsupported scheme logs the word "unsupported" and the client's
	// own string reaches nothing. So the rule above still holds as written.
	//
	// BEFORE THE LADDER, so it is written whether this request is answered,
	// refused, or kills the handler. A line that appears only on success is
	// worthless for the class of bug it exists for.
	//
	// DEBUG, and deliberately NOT bounded by a RefusalBudget: this fires once per
	// authorized request and the incident involved several a second, which is
	// exactly the burst an operator needs to see whole. A bound here would drop
	// the evidence. DEBUG is the bound — it is turned on for an investigation.
	//
	// The connection id is on the line because the panic report showed several
	// handlers dying together from one reader goroutine; with the id, that story
	// reads out of the log instead of out of stack traces.
	// READ ABOVE THE LINE, refused below it. Only the tag read moves: the
	// default, the ladder and the rejection are untouched, so an absent tag is
	// still NIP-04 and an unsupported one is still UNSUPPORTED_ENCRYPTION. What
	// changes is that the line can now say which of those happened.
	tag := event.Tags.GetFirst([]string{"encryption"})
	scheme, supported := nostr.NIP04, true
	if tag != nil {
		scheme, supported = nostr.EncryptionFromTag(tag.Value())
	}

	s.log.Debug("handling an NWC request", "connection", conn.row().ID,
		"event", event.ID, "kind", event.Kind, "tags", tagNames{event},
		"encryption", encryptionRequested(tag != nil, scheme, supported))

	if !supported {
		return s.respond(ctx, conn, event, nostr.NIP04,
			errorResponse("", CodeUnsupportedEncryption, "unsupported encryption scheme"), false)
	}

	// --- 2. decrypt --------------------------------------------------------
	plaintext, err := conn.identity.Decrypt(scheme, event.PubKey, event.Content)
	if err != nil {
		s.log.Warn("could not decrypt an NWC request from an authorized client",
			"connection", conn.row().ID, "error", err.Error())
		return s.respond(ctx, conn, event, scheme,
			errorResponse("", CodeOther, "could not decrypt the request"), false)
	}
	var req Request
	if err := json.Unmarshal([]byte(plaintext), &req); err != nil {
		return s.respond(ctx, conn, event, scheme,
			errorResponse("", CodeOther, "the request is not valid JSON"), false)
	}
	// The method is echoed back as result_type AND stored in the replay cache,
	// so its length is an attacker's choice unless it is bounded here: a NIP-44
	// payload holds ~64 kB, and a paired client could put all of it in a field
	// that ends up in a durable row on an SD card. A name nobody could have
	// meant is refused before it is repeated.
	if len(req.Method) > maxMethodLength {
		return s.respond(ctx, conn, event, scheme,
			errorResponse("", CodeNotImplemented, "this method is not implemented"), false)
	}

	// --- 3a. freshness, and NOT cached -------------------------------------
	if !inWindow(s.now(), event.CreatedAt.Time()) {
		// §8: a stale request gets an error so the client stops waiting, and is
		// deliberately not written to the cache — caching it would answer a
		// legitimate retry of the same id with "expired" for ever.
		return s.respond(ctx, conn, event, scheme,
			errorResponse(req.Method, CodeOther, "request expired"), false)
	}

	// --- 3b. the durable cache, CLAIMED before the work ---------------------
	//
	// One statement decides "have I seen this?" and "am I the one handling it?".
	// Looking it up and writing the row afterwards — Wave 23's shape — is safe
	// against a redelivery that arrives later and unsafe against one that
	// overlaps: both find nothing, both execute, and the second write is
	// discarded. That is two invoices for make_invoice and two payments for
	// pay_invoice, which is the failure this cache exists to prevent.
	placeholder := inProgress(req.Method)
	claimed, cached, claimedAt, err := s.store.ClaimNWCRequest(ctx, event.ID, conn.row().ID,
		string(req.Method), placeholder, s.now())
	if err != nil {
		// FATAL to the request, and this is the d24.4 hand-off: a spend whose
		// idempotency record did not land is a spend a redelivery makes again.
		// Nothing is executed, and the error is not cached — there is no row to
		// cache it in.
		s.log.Error("could not claim an NWC request; refusing to handle it",
			"connection", conn.row().ID, "method", req.Method, "error", err.Error())
		return s.respond(ctx, conn, event, scheme,
			errorResponse(req.Method, CodeInternal, "internal error"), false)
	}
	if !claimed {
		// Someone else has it — an earlier delivery that finished, or one still
		// running. Either way its stored answer is what this delivery gets, and
		// NOTHING executes. This is the LNbits lesson §8 cites.
		if cached == placeholder && s.now().Sub(claimedAt) < SiblingDeliveryWindow {
			// A SIBLING SOCKET'S COPY of the request we are already handling,
			// not a client asking again (d24.18). Since a pairing names several
			// relays, one request arrives once per relay — and publishing the
			// in-flight placeholder to each of them puts "this request is
			// already being processed" on the wire alongside the real answer the
			// winner is about to publish to those same relays. A client that
			// takes the first response it sees would then show a failure for a
			// request that succeeded, which is worse than the silence it
			// replaces: found by d24.18's own criterion 3, which asks for three
			// CONSISTENT answers.
			//
			// A duplicate that arrives LATER than the window is a client asking
			// again, and it still gets the placeholder — that answer exists so a
			// client is told its payment is in flight rather than being invited
			// to start a second one under a new request id.
			s.log.Debug("an NWC request arrived on more than one of this pairing's relays",
				"connection", conn.row().ID, "method", req.Method)
			return Response{}, false
		}
		s.log.Info("an NWC request was already handled; replaying its response",
			"connection", conn.row().ID, "method", req.Method)
		s.publishCached(ctx, conn, event, scheme, cached)
		return Response{}, true
	}

	// --- 4. permission ------------------------------------------------------
	if !permits(conn.row().Permissions, req.Method) {
		// §8 step 1 for pay_invoice, and every other method's group check in the
		// same place: a method whose group this connection does not hold is
		// RESTRICTED, and a method with no group at all is NOT_IMPLEMENTED —
		// which is what an unknown name gets, since permits() cannot allow one.
		code, message := CodeRestricted, "this connection may not use that method"
		if _, known := methodGroup[req.Method]; !known {
			code, message = CodeNotImplemented, "this method is not implemented"
		}
		resp := errorResponse(req.Method, code, message)
		s.reportOutcome(ctx, conn, req, resp)
		return s.respond(ctx, conn, event, scheme, resp, true)
	}

	// --- 5. dispatch --------------------------------------------------------
	resp := s.dispatch(ctx, conn, req)
	// Said out loud, at the level §12's ruling gives it (d24.14). BOTH exits
	// report, because the one this catches and the one above it are the same
	// answer to a client — a capability it does not have — and a trail that
	// recorded only the second would be missing the commonest case: a connection
	// created without the pay group.
	s.reportOutcome(ctx, conn, req, resp)
	// --- 6. encrypt and publish ---------------------------------------------
	return s.respond(ctx, conn, event, scheme, resp, true)
}

// advertised is what one connection may actually call — Supported() minus the
// groups it was not granted, minus pay_invoice when sending is off.
//
// ONE renderer, used by both the kind 13194 info event and get_info's methods
// list. They answer the same question, and a client that trusted a wider one
// would show the operator a button that RESTRICTED refuses.
//
// The sending toggle is in here rather than only in the ladder (ruling 6)
// because the info event is what a wallet app builds its UI from: with sending
// off, the operator should see a receive-only wallet, not a pay button that
// fails. A read failure hides pay_invoice — the conservative direction, and the
// same one §2's default takes.
func (s *Service) advertised(ctx context.Context, conn *connection) []string {
	sending, err := s.sendEnabled(ctx)
	if err != nil {
		s.log.Warn("could not read whether sending is enabled; advertising a receive-only "+
			"wallet", "error", err.Error())
	}
	methods := make([]string, 0, len(Supported()))
	for _, m := range Supported() {
		if !permits(conn.row().Permissions, m) {
			continue
		}
		if m == MethodPayInvoice && !sending {
			continue
		}
		methods = append(methods, string(m))
	}
	return methods
}

// extensions is the info event's `extensions` tag for THIS connection, in
// NIP-47's space-separated form (doy.3).
//
// Derived rather than constant, for the reason advertised() above is: the same
// event must not name a method in one place and deny it in another. See the
// constants for which of the two is per-connection and why the other is not.
func extensions(conn *connection) string {
	specs := make([]string, 0, 2)
	if permits(conn.row().Permissions, MethodListTransactions) {
		specs = append(specs, ExtensionTransactionHistory)
	}
	specs = append(specs, ExtensionMetadataConventions)
	return strings.Join(specs, " ")
}

// respond encrypts, publishes, and — when claimed is true — replaces the claim's
// placeholder with the real answer.
//
// Completed BEFORE publishing, deliberately: a response that reached the relay
// while the row still said "in progress" would answer a redelivery with the
// placeholder even though the work is done. The reverse order costs nothing —
// a completed row that was never published is a client that retries and gets
// the same answer, which is what the cache is for.
//
// A failed completion is logged and the response is still published. That is
// safe in a way the pre-claim shape was not: the row EXISTS, so a redelivery is
// answered with the placeholder rather than executing the request again. The
// client is told the truth now and told "already processing" if it retries,
// which for a payment is exactly the conservative direction.
//
// claimed is false only on the paths above the claim — an unreadable payload, a
// stale request, a failed claim — none of which may leave a cache row (§8: a
// stale request must not be cached, or a legitimate retry is told it expired
// for ever).
func (s *Service) respond(ctx context.Context, conn *connection, event *gonostr.Event,
	scheme nostr.Encryption, resp Response, claimed bool) (Response, bool) {
	encoded, err := encode(resp)
	if err != nil {
		s.log.Error("could not encode an NWC response", "error", err.Error())
		return resp, false
	}
	if claimed {
		if err := s.store.CompleteNWCRequest(ctx, event.ID, encoded, s.now()); err != nil {
			s.log.Error("could not record an NWC response for replay", "error", err.Error())
		}
	}
	s.publishCached(ctx, conn, event, scheme, encoded)
	return resp, true
}

// publishCached seals a rendered response and sends it to the connection's relay.
func (s *Service) publishCached(ctx context.Context, conn *connection, event *gonostr.Event,
	scheme nostr.Encryption, encoded string) {
	sealed, err := conn.identity.Encrypt(scheme, event.PubKey, encoded)
	if err != nil {
		s.log.Error("could not encrypt an NWC response", "error", err.Error())
		return
	}
	response := gonostr.Event{
		Kind:      KindResponse,
		CreatedAt: gonostr.Timestamp(s.now().Unix()),
		Content:   sealed,
		Tags: gonostr.Tags{
			{"e", event.ID},
			{"p", event.PubKey},
			{"encryption", string(scheme)},
		},
	}
	if err := conn.identity.Sign(&response); err != nil {
		s.log.Error("could not sign an NWC response", "error", err.Error())
		return
	}
	// RETRIED, and bounded by what the client can still hear (d24.25). See
	// publishResponse: one attempt and a WARN was the whole delivery policy, and
	// both field trips logged the WARN — which is a spinner on the phone for a
	// request that was handled and a payment that may have moved.
	s.publishResponse(ctx, conn, response, event.CreatedAt.Time())
}

// dispatch runs one permitted method (§8 step 5).
//
// The read methods answer while spending is held (u0u) and while sending is
// disabled: §8 is explicit that a receive-only install still answers balance and
// history, and make_invoice works there too. Nothing here touches the Spender,
// so neither freeze can reach it — which is the correct outcome, not an
// oversight.
func (s *Service) dispatch(ctx context.Context, conn *connection, req Request) Response {
	switch req.Method {
	case MethodGetInfo:
		info, err := s.node.Info(ctx)
		if err != nil {
			return errorResponse(req.Method, CodeInternal, "the node is not reachable")
		}
		return Response{ResultType: req.Method, Result: map[string]any{
			"alias":        info.Alias,
			"pubkey":       info.Pubkey,
			"network":      info.Network,
			"block_height": info.BlockHeight,
			// The SAME list the info event carries, filtered by this
			// connection's groups. Two renderings of "what can you do" that
			// disagreed would be worse than either alone: a client believing
			// get_info would show a pay button that RESTRICTED refuses.
			"methods": s.advertised(ctx, conn),
		}}
	case MethodGetBalance:
		// THE CEILING, never the node's. §8 puts this in bold and §2 is why: the
		// node's balance is shared with every other app on the box, and
		// reporting it would tell a paired wallet app how much bitcoin the
		// operator has — and invite it to try to spend it.
		balance, err := s.purse.Balance(ctx)
		if err != nil {
			return errorResponse(req.Method, CodeInternal, "could not read the balance")
		}
		return Response{ResultType: req.Method, Result: map[string]any{"balance": balance}}
	case MethodMakeInvoice:
		var params struct {
			AmountMsat  int64  `json:"amount"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(nonNull(req.Params), &params); err != nil {
			return errorResponse(req.Method, CodeOther, "could not read the parameters")
		}
		if params.AmountMsat <= 0 {
			return errorResponse(req.Method, CodeOther, "amount must be positive")
		}
		invoice, err := s.invoices.Mint(ctx, params.AmountMsat, params.Description)
		if err != nil {
			s.log.Warn("could not mint an invoice for an NWC request", "error", err.Error())
			return errorResponse(req.Method, CodeInternal, "could not create the invoice")
		}
		return Response{ResultType: req.Method, Result: invoiceResult(invoice)}
	case MethodLookupInvoice:
		var params struct {
			PaymentHash string `json:"payment_hash"`
			Invoice     string `json:"invoice"`
		}
		if err := json.Unmarshal(nonNull(req.Params), &params); err != nil {
			return errorResponse(req.Method, CodeOther, "could not read the parameters")
		}
		if params.PaymentHash == "" {
			return errorResponse(req.Method, CodeOther, "payment_hash is required")
		}
		invoice, found, err := s.invoices.Lookup(ctx, params.PaymentHash)
		if err != nil {
			return errorResponse(req.Method, CodeInternal, "could not read the invoice")
		}
		if !found {
			return errorResponse(req.Method, CodeNotFound, "no such invoice")
		}
		return Response{ResultType: req.Method, Result: invoiceResult(invoice)}
	case MethodListTransactions:
		filter, resp := listFilter(req)
		if resp != nil {
			return *resp
		}
		txns, err := s.invoices.List(ctx, filter)
		if err != nil {
			return errorResponse(req.Method, CodeInternal, "could not read the history")
		}
		out := make([]map[string]any, 0, len(txns))
		for _, txn := range txns {
			out = append(out, txnResult(txn, conn.row().ID))
		}
		out = s.fitHistory(conn.row().ID, out)
		return Response{ResultType: req.Method, Result: map[string]any{"transactions": out}}
	case MethodPayInvoice:
		// §8's rejection ladder, which is what makes paying safe. Everything
		// this method can do about money it does through it.
		return s.payInvoice(ctx, conn, req)
	default:
		// Unreachable: permits() refuses an unknown method above. Answered
		// rather than panicked, because "unreachable" has been wrong before.
		return errorResponse(req.Method, CodeNotImplemented, "this method is not implemented")
	}
}

// MaxResponsePlaintext bounds a response before it is encrypted (d24.27).
//
// NIP-44 REFUSES a plaintext over 65535 bytes outright, and there is no partial
// answer: the encrypt fails, nothing is published, and the client waits until it
// gives up. Every retry fails identically, so the method is dead for that pairing
// with nothing on the wire to say why — the silent failure d24.27 exists to
// remove, reintroduced by the fix for it.
//
// It was reachable the moment metadata was added. A hundred rows of history were
// ~23 kB; with a realistic 650-byte zap request on each they are ~119 kB, and the
// ceiling is crossed at about 55 rows. `list_transactions` defaults to
// MaxHistoryRows when a client sends no limit, so a node that has taken a couple
// of months of zaps reaches it without anyone asking for anything unusual.
//
// FORTY kilobytes rather than the protocol's 65535, because NIP-04 is the other
// half of the ceiling: its content is base64 of the ciphertext, about four thirds
// of the plaintext, and strfry's default maxEventSize is 65536 bytes. 40 kB of
// plaintext is ~55 kB of NIP-04 content plus the event's own fields, which fits
// both.
//
// EXPIRY CONDITION: it is the smaller of two limits owned by other people — a
// NIP's and a relay's. If either moves, or if this build ever answers a method
// whose result is naturally larger than a history page, this number is the one to
// re-derive rather than to raise by feel.
const MaxResponsePlaintext = 40 * 1024

// fitHistory drops what a row can spare, oldest first, until the page fits.
//
// THE DECORATION GOES BEFORE THE ROWS, which is the opposite of the obvious fix.
// Returning fewer rows would fit too, but `limit` is how a NIP-47 client pages: a
// page shorter than the one it asked for is how it learns there is no more
// history, so trimming rows tells it the truth has run out. What each row can
// spare, in order:
//
//  1. `metadata` — the sender's name and face. Worth having, worth losing.
//  2. `invoice` — the bolt11, which is long (a few hundred bytes a row) and which
//     a client can fetch for any row it cares about with lookup_invoice, since
//     the payment hash is still there.
//  3. the row itself, last and reluctantly.
//
// A full page of zaps cannot keep its senders: a hundred realistic rows are well
// past the budget with metadata on every one. That is the honest trade — a client
// asking for the MAXIMUM gets rows without names, and one asking for a page a
// person actually reads gets both.
//
// OLDEST FIRST because a client renders newest first, so what is on screen keeps
// its detail and what you would scroll to loses it.
func (s *Service) fitHistory(connectionID int64, rows []map[string]any) []map[string]any {
	total := 0
	for _, row := range rows {
		total += encodedSize(row)
	}
	trimmed := 0
	for _, field := range []string{"metadata", "invoice"} {
		for i := len(rows) - 1; i >= 0 && total > MaxResponsePlaintext; i-- {
			value, present := rows[i][field]
			if !present {
				continue
			}
			// An UNDER-estimate of what is saved — the key and its punctuation go
			// too — so the loop can stop late but never early.
			total -= encodedSize(value)
			delete(rows[i], field)
			trimmed++
		}
	}
	// THE LAST RESORT, and it should be unreachable: a row stripped of both is
	// about 300 bytes since y09's commitment joined the untrimmable set — so
	// MaxHistoryRows of them is three quarters of the budget rather than a
	// quarter, and the headroom before this loop is a good deal thinner than it
	// was when the number was written. It
	// exists because the alternative to a short page is NIP-44 refusing the whole
	// response and the client hearing nothing at all — and because "unreachable"
	// has been wrong in this package before.
	dropped := 0
	for len(rows) > 1 && total > MaxResponsePlaintext {
		total -= encodedSize(rows[len(rows)-1])
		rows = rows[:len(rows)-1]
		dropped++
	}
	if dropped > 0 {
		s.log.Warn("a history page was too large to send even without its details; the oldest "+
			"rows were dropped", "connection", connectionID, "dropped", dropped)
	} else if trimmed > 0 {
		s.log.Debug("trimmed details from a history page to fit the response",
			"connection", connectionID, "rows", len(rows), "trimmed", trimmed)
	}
	return rows
}

// encodedSize is how many bytes a value costs in the response, or zero if it
// cannot be encoded at all — in which case the response as a whole will fail and
// say so with everything in hand.
func encodedSize(value any) int {
	encoded, err := json.Marshal(value)
	if err != nil {
		return 0
	}
	return len(encoded)
}

// txnResult renders one history row in NIP-47's shape.
//
// The description and the preimage are d24.16, and the field trip is what asked
// for them: Amethyst rendered every outgoing row as an unlabelled debit with no
// preimage, while incoming rows carried their zap comment. The description now
// falls back the way the two kinds actually store it — an incoming row's label
// is the LUD-12 comment a stranger sent, an outgoing row's is the memo of the
// invoice this app paid — so ONE field answers "what was this for" whichever way
// the money went.
//
// THE PREIMAGE IS REVEALED ONLY FOR THIS CONNECTION'S OWN PAYMENTS, and the
// scoping is the whole of what makes revealing it defensible.
//
// The first version revealed it on every row, which review caught: the history
// filter has no connection dimension, so a pairing holding nothing but the
// default `history` group was handed the preimage of every zap the node had
// EVER received and of every payment any other app or the operator had made. A
// preimage is the proof-of-payment token — an app holding one can assert to
// anyone that it paid an invoice it never paid. "Lets this app list payments in
// and out" is not consent to that.
//
// Scoping is possible at all because d24.15 started writing nwc_connection_id,
// which is the same column the resolver needed. Rows with no connection —
// incoming invoices, the operator's own payments, everything written before this
// wave — keep their proof to themselves.
//
// THE PREIMAGE is the empty string rather than a missing key, so a client does
// not have to tell "not settled" from "not mine" from "this field is new"; none
// of those is its business, and all three mean the same thing to it. The
// description is the opposite call (doy.1) and the difference is that it has no
// secret to keep — see below.
func txnResult(txn store.Txn, connectionID int64) map[string]any {
	preimage := ""
	if txn.NWCConnectionID != 0 && txn.NWCConnectionID == connectionID {
		preimage = txn.Preimage.Reveal()
	}
	out := map[string]any{
		"type":         txnType(txn.Kind),
		"amount":       txn.AmountMsat,
		"fees_paid":    txn.FeeMsat,
		"payment_hash": txn.PaymentHash,
		"preimage":     preimage,
		"state":        txn.State,
		// WHEN, which is why every row in the operator's wallet app was an
		// undated arrow (d24.27). It was on the row the whole time;
		// invoiceResult sent it and this did not.
		"created_at": txn.CreatedAt.Unix(),
	}
	// ABSENT rather than zero for the several that may not exist. A settled_at of 0
	// renders as 1970, and an empty invoice string is a field a client has to
	// decide the meaning of; neither is a thing this row is saying.
	//
	// The description joined them in doy.1, and EVERY outgoing zap is why: a
	// NIP-57 invoice commits to a description_hash over the LNURL metadata and
	// carries no plaintext memo, so d24.16 writes "" on exactly the rows the
	// operator most wants labelled. A client that falls back only on a missing
	// field rendered that as an occupied line showing nothing — not even the word
	// "Sent". An empty description is not this row saying the payment is called
	// nothing; it is the row having nothing to say.
	if !txn.SettledAt.IsZero() {
		out["settled_at"] = txn.SettledAt.Unix()
	}
	if txn.Bolt11 != "" {
		out["invoice"] = txn.Bolt11
	}
	// ONE field answers "what was this for" whichever way the money went: an
	// outgoing row's label is the memo of the invoice this app paid, an incoming
	// row's is the LUD-12 comment a stranger sent.
	description := txn.Description
	if description == "" {
		description = txn.Comment
	}
	if description != "" {
		out["description"] = description
	}
	if metadata := zapMetadata(txn); metadata != nil {
		out["metadata"] = metadata
	}
	// THE INVOICE'S COMMITMENT, so a client can CHECK the attribution rather
	// than trust it: hash `metadata.nostr` and compare. It matters because this
	// history is served to every pairing, not only the one that made the
	// payment, and because the alternative is taking this node's word for who
	// was paid.
	//
	// Only where we hold one, and silence is not a downgrade: a row without it
	// is making no claim to check.
	if txn.OutDescriptionHash != "" {
		out["description_hash"] = txn.OutDescriptionHash
	}
	return out
}

// zapMetadata is NIP-47's `metadata` for a row that carried a zap request, and
// nil for one that did not (d24.27).
//
// ONE SHAPE, TWO COLUMNS, chosen by the row's DIRECTION (doy.2). An incoming row
// reads `zap_request` — raw JSON this node received and verified — and this
// function WRAPS it as `{"nostr": …}`, because a bare zap request is not an
// NWC-06 metadata object. An outgoing row reads `out_metadata`, which already IS
// one: the client sent the whole object and we stored it as sent, so it is
// emitted unwrapped. A client parses both the same way, which is the point: one
// parser, both directions.
//
// BY DIRECTION rather than by whichever column happens to be non-empty. Nothing
// writes both today, and selecting on emptiness would make that an assumption
// this function quietly depends on; selecting on the kind makes it impossible for
// an outgoing row to emit the incoming column whatever a future writer does.
//
// `metadata.nostr` IS the kind 9734 event. A client reads its pubkey and walks
// its tags for the `p` tag, then resolves those to a display name and an avatar
// using relays it is already connected to — which is how a zap in a wallet app's
// history gets a sender's name and face. We hold the event byte-identically
// because §7 needs it: the receipt's description tag carries it verbatim so the
// sender's client can recompute description_hash.
//
// IT IS NOT A NEW DISCLOSURE, which is the objection to have ready. That receipt
// is PUBLIC. The sender pubkey and comment of every zap this node receives are
// public by design, and handing the same blob to the operator's own paired wallet
// tells it nothing the world cannot already read.
//
// AND NOTHING IS FETCHED. We send a pubkey; the client turns it into a name.
// Resolving kind 0 profiles here would be a new outbound path from the server
// container for cosmetics, which is why this function has no context to make one
// with.
//
// A blob that is not a JSON OBJECT is left OUT rather than passed through: it
// would make the whole response unparseable rather than this one field absent,
// and a client would lose its history over one bad row. The column is documented
// as raw JSON exactly as received, so this should be unreachable — which is the
// reason to check rather than the reason not to. jsonObject below is that check,
// and carries the rest of the reasoning.
//
// "Byte-identical" is what the STORE holds, and it is not quite what travels:
// json.Marshal HTML-escapes a RawMessage's contents, so a `<` in the zap
// request's content arrives as `\u003c`. Semantically the same event, and the
// client's parser reads it the same way; the receipt path is where byte-identity
// actually matters, and that path does not go through here.
func zapMetadata(txn store.Txn) any {
	if outgoingKind(txn.Kind) {
		if object, ok := jsonObject(txn.OutMetadata); ok {
			return object
		}
		return nil
	}
	if object, ok := jsonObject(txn.ZapRequest); ok {
		return map[string]any{"nostr": object}
	}
	return nil
}

// jsonObject is raw JSON when the string holds an OBJECT, and not-ok otherwise.
//
// An object, not merely valid JSON. `json.Valid` accepts `null`, `123` and
// `"str"`, and a degenerate blob would emit `"metadata":null` or
// `"metadata":{"nostr":null}` — half a check, which is worse than none because
// it reads as a whole one (found by review).
func jsonObject(raw string) (json.RawMessage, bool) {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "{") || !json.Valid([]byte(trimmed)) {
		return nil, false
	}
	return json.RawMessage(trimmed), true
}

// invoiceResult renders one invoice in NIP-47's shape, for make_invoice and
// lookup_invoice.
//
// THE DESCRIPTION IS ABSENT WHEN EMPTY, the same call txnResult makes and for the
// same reason (doy.1). It matters on the LOOKUP path in particular: that
// Description is the invoice's LUD-12 comment, which is optional and stored
// unconditionally, so a zap invoice nobody left a note on answered with the same
// empty string that made a client render an occupied line showing nothing. Found
// by the review of doy.1's own diff, which is the shape worth naming — the bead
// said list_transactions, and the defect was a property of the empty string
// rather than of the method.
//
// Harmless on the make_invoice path, where the description is the client's own
// `params.description` handed back: a client that asked for none is told it has
// none, which is exactly what an absent key says.
func invoiceResult(inv Invoice) map[string]any {
	out := map[string]any{
		"type":         "incoming",
		"invoice":      inv.Bolt11,
		"payment_hash": inv.PaymentHash,
		"amount":       inv.AmountMsat,
		"created_at":   inv.CreatedAt.Unix(),
		"expires_at":   inv.ExpiresAt.Unix(),
	}
	if inv.Description != "" {
		out["description"] = inv.Description
	}
	if inv.Settled {
		out["settled_at"] = inv.SettledAt.Unix()
	}
	return out
}

func txnType(kind string) string {
	if outgoingKind(kind) {
		return "outgoing"
	}
	return "incoming"
}

// outgoingKind is the direction question, separated from the WORD NIP-47 uses
// for it (review, doy.2).
//
// zapMetadata asks which way a row went, and the first version asked by
// comparing txnType's output against the string "outgoing" — rendering the kind
// into wire vocabulary and parsing it straight back. Renaming that word for a
// protocol reason would then silently change which column an outgoing row reads
// from, with nothing for the compiler to catch.
func outgoingKind(kind string) bool { return strings.HasPrefix(kind, "payment_out") }

// nonNull makes an absent params object an empty one, so a request with no
// params decodes to zero values rather than failing.
func nonNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("{}")
	}
	return raw
}

// tagNames is the NAMES of an event's tags, sorted, for the one line that logs
// an inbound request.
//
// Names only. A tag's value is chosen by the client and can be anything at all;
// the name is what says which shape of request this is, and it is what the 0.1.11
// investigation needed. Sorted so two requests carrying the same tags produce the
// same line and a reader can compare them at a glance.
//
// A LogValuer rather than a function call, and that is not style: slog evaluates
// its arguments EAGERLY, so `tagNames(event)` as an argument would allocate,
// sort and join on every inbound request of every install — DEBUG is off on all
// of them. Measured before changing it. LogValue runs only when a handler
// actually formats the record, which is what makes this line free when nobody is
// investigating. The same reason PayResult has one.
type tagNames struct{ event *gonostr.Event }

func (t tagNames) LogValue() slog.Value {
	names := make([]string, 0, len(t.event.Tags))
	for _, tag := range t.event.Tags {
		if len(tag) > 0 {
			names = append(names, tag[0])
		}
	}
	slices.Sort(names)
	return slog.StringValue(strings.Join(names, ","))
}

// encryptionRequested names the scheme the client asked for, for the log.
//
// FOUR OUTCOMES, and they are four because the first two are different facts:
//
//	absent      no encryption tag — §8 step 2's implicit NIP-04 fallback
//	nip04       the client asked for NIP-04 explicitly
//	nip44_v2    the client asked for NIP-44
//	unsupported a scheme this build does not speak, refused on the next line
//
// LOGGING THE RESOLVED `scheme` WOULD NOT DO. It is defaulted to NIP04 when the
// tag is absent, so it collapses rows one and two — and telling an implicit
// fallback from an explicit choice is the entire question this field was added
// for. Hence the presence flag.
//
// A TOKEN, NEVER THE CLIENT'S STRING. The rule above this function's call site
// is that a tag value is whatever the client chose to put there, and it is not
// weakened for a diagnostic: an unsupported scheme is reported as the word
// "unsupported", so an operator learns it happened without arbitrary — and
// unbounded — client bytes landing in their log. The two supported rows print
// the constant that EncryptionFromTag canonicised to, not the text it parsed.
//
// The cost of that choice, stated so it is a decision rather than an oversight:
// WHICH unsupported scheme was asked for is not recoverable from the log. No
// client has ever sent one; if one does, this is the place to widen — bounded,
// and deliberately.
func encryptionRequested(present bool, scheme nostr.Encryption, supported bool) string {
	switch {
	case !present:
		return "absent"
	case supported:
		return string(scheme)
	default:
		return "unsupported"
	}
}
