package nostr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/logging"
)

// SettingRelays is the operator's relay list (spec §4).
const SettingRelays = "default_relays"

// DefaultRelays is the set used when the operator has configured none
// (o34.5). Small, widely reachable, and not run by one operator — a receipt
// published only where the sender does not read is invisible, which §7 says
// reads as theft.
//
// It is deliberately short. NIP-57 publishes to the union of these and the zap
// request's own relays tag, and the request's list is the one that actually
// determines whether the sender sees the receipt; a long default set buys
// little and costs a connection each.
//
// THE ORDER IS LOAD-BEARING, and d24.18 changed HOW rather than whether. The
// Connections form prefills the relays to pair on with the first few of the
// operator's list, and that list falls back to this one — so a stock pairing now
// lands on entries zero through two rather than on entry zero alone, and one of
// them being unreachable is no longer a total outage for that pairing.
//
// With this set at three, entries zero through two ARE all of it, and that is
// worth saying because it is how a dead entry here cost more than the receipt
// latency it was found through: until 2xw entry two was relay.nostr.band, so
// every stock pairing was prefilled with a relay that never connects.
//
// Entry zero still matters more than the rest, for a reason outside this
// codebase: NIP-47 says a connection URI's relay parameter "may be more than
// one", and a client that implements only the first pairs on exactly that one.
// Amethyst is such a client today — its parser takes
// `getQueryParameter("relay")?.firstOrNull()` and discards the rest — so for the
// wallet the field trips use, entry zero is still the whole of the pairing.
//
// nos.lol leads for that reason (25 Aug 2026, from the 0.1.10 field trip:
// relay.damus.io measured worst of the three the operator tested, and it was
// entry zero). relay.damus.io stays in the SET — it is large, many senders read
// there, and §7 says a receipt published only where the sender does not read is
// invisible. Removing it would trade a pairing problem for a receipt problem.
// RE-EXAMINED UNDER 2xw AND KEPT: it sheds connections rather than being down —
// 503 interleaved with 101 from every network probed, no consecutive run of
// either, TLS completing in 0.10-0.13 s every time — and a shed connection costs
// about a quarter of a second, not the budget.
//
// relay.nostr.band was REMOVED (2xw, 3 Sep 2026). The measurement is the reason,
// and it is the first one taken with du9's per-relay records: on the 0.1.19-rc1
// trip its record read not_connected at exactly 5000 ms — the whole connect
// budget — on every publish, while the relays that accepted answered in 195-806
// ms. A devops probe then found the same from three vantage points, twenty
// attempts each: TCP never completes, from the laptop, from the box's host and
// from inside the server's own network namespace, against a single stable A
// record. A relay that HANGS is the worst kind to ship, because it costs the
// whole budget every time where one that refuses costs nothing at all — it was
// the entire remaining publish cost on the reference box, ~5.2 s down to under
// half a second without it.
//
// NOTHING REPLACED IT, deliberately. sendit.nosflare.com was fastest on the one
// night anybody measured it, which is not a reason to ship it to every user;
// three good defaults beat four with a stranger, and the list is an operator
// setting for exactly this. Whether this set should be fixed at build time at
// all — rather than re-validated by a periodic probe, with a relay that fails N
// consecutive publishes named on the Security page — is the open question that
// would change this, and it is on 2xw.
var DefaultRelays = []string{
	"wss://nos.lol",
	"wss://relay.damus.io",
	"wss://relay.primal.net",
}

// ErrNoRelays means there was nowhere to publish — no configured relay and none
// named by the request.
var ErrNoRelays = errors.New("nostr: no relay to publish to")

// MaxPairingRelays bounds how many relays ONE pairing may name (d24.18).
//
// Three. Sockets are the scarce thing on a Pi — MaxTransientRelays exists for
// that reason — and this multiplies them by the list length: one subscription
// per relay per connection, held for the life of the pairing rather than for the
// length of a publish. Three covers the failure the field measured (one relay
// refusing 8 of 20 upgrades while two others took every one) with a spare.
//
// EXPIRY CONDITION, and there are two. Raise it if a trip measures a failure
// that three relays do not cover — correlated outages across a whole set, say.
// LOWER it if the socket budget on the target hardware becomes the binding
// constraint: the number that matters is connections × relays, and an operator
// with eight pairings is already holding twenty-four sockets at this cap.
const MaxPairingRelays = 3

// ConnectionRelays is the set of relays ONE pairing may be reached on.
//
// A NAMED TYPE with an unexported field, so a caller cannot hand the publish
// seam a []string it happens to be holding — the operator's own relay list being
// the one that matters. §8's argument is that the unencrypted kind 13194 info
// event must never be announced next to the operator's zap receipts, and before
// d24.18 that was structural only in a narrow sense: PublishTo took ONE relay
// URL, which constrains the arity of a single call and nothing about where the
// URL came from. A loop over DefaultRelays calling it would have been four lines
// with nothing to notice.
//
// So the guarantee is two things together, and neither is sufficient alone: this
// type, which stops an accidental []string reaching the seam, and the arch rule
// that nothing derived from DefaultRelays or the relays SETTING reaches it,
// which is what polices provenance across the whole path.
type ConnectionRelays struct {
	// urls is unexported so the zero value is an empty set rather than a nil
	// slice someone can append to from outside.
	urls []string
}

// PairingRelays builds the set from a connection row's stored list.
//
// The name says where they are allowed to come from. It is not a check — a
// caller determined to pass DefaultRelays can — and that is what the arch rule
// is for; what this stops is the ordinary accident of plumbing the wrong slice
// through a seam that used to take a string.
func PairingRelays(stored []string) ConnectionRelays {
	return ConnectionRelays{urls: slices.Clone(stored)}
}

// URLs is the set as the pairing named it, in ORDER.
//
// The order is load-bearing and not incidental. NIP-47 says the URI's relay
// parameter "may be more than one", and a client that implements only the first
// — Amethyst's parser takes `getQueryParameter("relay")?.firstOrNull()` and
// discards the rest — will pair on exactly the one at the front. So the first
// entry is the relay a single-relay client depends on entirely, which is the
// same lesson DefaultRelays' own ordering comment records, one layer along.
func (c ConnectionRelays) URLs() []string { return slices.Clone(c.urls) }

// MaxTransientRelays bounds how many sockets a STRANGER can make this node open
// at once.
//
// It lives here, in the package that owns the connections, and not two layers
// up where it started: a bound enforced only at parse time is a bound the layer
// holding the sockets does not know about, and Publish took an unbounded
// extra ...string. internal/lnurl echoes this constant for its own polite
// early refusal — one number, so the two cannot drift.
const MaxTransientRelays = 8

// publishTimeout bounds one publish across every relay. §7: publication is
// best-effort and must never block or fail a settlement — the money already
// arrived.
const publishTimeout = 30 * time.Second

// connectBudget bounds the CONNECT phase of one publish, per relay (du9, §7).
//
// It exists because nothing else could bound it. go-nostr's EnsureRelay dials
// under a hardcoded fifteen seconds hung off the POOL's context, so neither
// publishTimeout nor the caller's context reaches it, and PublishMany closes its
// result channel only when every per-relay goroutine has finished — so one relay
// that is simply down cost every zap receipt a flat 15.0 s, measured five times
// out of five on the box with relays=6 accepted=4. This app therefore connects
// first, itself, under this budget, and hands the library only relays that are
// already open.
//
// It bounds CONNECTING and nothing else. A relay that has answered the handshake
// and is slow to send its OK is still waited for, up to publishTimeout — §8's
// five-second NWC response budget must not leak onto the receipt path, and
// TestTheReceiptPathIsNotNarrowedToTheNWCResponseBudget is what holds that.
//
// FIVE SECONDS, and the reason is a measurement rather than a feeling: a TLS
// handshake to a healthy relay completes well under a second on the reference
// box, and the four relays that accepted on the last trip answered in
// milliseconds. Five leaves an order of magnitude of headroom for a relay having
// a bad day.
//
// EXPIRY CONDITION. Raise it if a trip shows a relay that would have answered
// being cut off — the DEBUG records below name which relay and how long it took,
// which is the evidence that would say so. Lower it if a receipt publish is ever
// on a path where a human is waiting; nobody is today, because §7 publishes
// after settlement and retries for 24 hours.
const connectBudget = 5 * time.Second

// errConnectBudget marks a dial that ran out of connect budget.
//
// A cause rather than a comparison against connectBudget on the clock: the dial
// context is derived from the publish context, so a caller that is already
// nearly out of time shortens the budget, and a wall-clock test would then
// report a budget that never applied.
//
// It is the context's cause AND is wrapped into the error dial returns (du9.3),
// which is not redundant: a cause dies with its context, and the question "did
// this relay HANG or fail fast" is asked later — by the DEBUG records now, and
// by o34.3's retry the day it decides to back off differently for the two. A
// relay that eats the whole budget on every attempt and one that refuses in
// 200 ms are the same failure to a caller that cannot tell them apart, and
// telling them apart was the whole of du9.3.
var errConnectBudget = errors.New("the connect budget ran out")

// errNoAnswer is the result for a relay the library reported nothing for.
//
// UNREACHABLE, and that is exactly why it exists. PublishMany sends one result
// per URL and closes the channel afterwards, so the loop in publishOne always
// runs — but a zero PublishResult has a nil Err, which reads as ACCEPTED. The
// one thing this must never do is turn a relay nobody heard from into a
// delivered receipt.
var errNoAnswer = errors.New("nostr: the relay reported no answer")

// PublishResult is one relay's answer.
//
// Per relay, never one bool for the batch. §7 retries for 24 hours when every
// relay refuses, and o34.3's retry has to know WHICH refused — a single failure
// flag turns "three of four accepted" into a retry storm against the three that
// already have the event.
type PublishResult struct {
	Relay string
	Err   error
}

// OK reports whether this relay accepted the event.
func (r PublishResult) OK() bool { return r.Err == nil }

// Accepted counts the relays that took it.
func Accepted(results []PublishResult) int {
	var n int
	for _, r := range results {
		if r.OK() {
			n++
		}
	}
	return n
}

// Pool is the process's relay connections.
//
// One for the process lifetime, like the invoice stream: go-nostr's pool
// reopens and de-duplicates connections, and a second pool would mean two sets
// of sockets to the same relays and two answers to "did this publish". An arch
// rule asserts there is exactly one construction site.
type Pool struct {
	pool   *gonostr.SimplePool
	relays func() []string

	// resolve answers what a stranger-named host points at, so the allow-list
	// applies to the address a name leads to and not only to the name.
	resolve Resolver

	log *slog.Logger

	// audit is §12's trail, and NIL IS VALID — see Options.Audit. A pool without
	// one still refuses and still logs; what it loses is the durable row.
	audit Auditor

	// The hourly bound on audited refusals. This event is driven by a stranger's
	// input, and the trail is a fixed ring; see MaxAuditedRefusalsPerHour.
	refusals *logging.RefusalBudget

	// dialable is the address policy the dial-time check applies. Always
	// dialableAddr in a shipped binary — it is a field, and not a direct call,
	// only so that export_test.go can stand it down.
	//
	// Unexported, and set by nothing outside this package, because every relay a
	// test can serve is on 127.0.0.1: a test about the LIFETIME of a stranger's
	// socket cannot open one at all under the real policy. Those tests used to
	// get that for free from the TOCTOU itself — they told the pre-check
	// "public" and let the dial go to loopback, which publicDNS's own comment
	// described as the seam. vz1.4 closes that gap, so the seam is declared
	// instead of exploited. Declared where the compiler can hold it, rather than
	// as an exported option that only a convention forbids setting.
	dialable func(netip.Addr) bool

	// exempt is the relay list the publish in flight treats as the operator's
	// own, as THAT publish read it. The dial hook runs on the dialer's
	// goroutine, so it is handed a snapshot rather than re-reading: see
	// checkDialAddress and exemptRelays.
	//
	// The same []string the send list and the teardown use, deliberately. Those
	// two already ask this question with slices.Contains over that very slice,
	// and the doc below insists all three agree about what "configured" meant —
	// which they do most convincingly by sharing one value rather than two
	// encodings of it. The list is the operator's own, so it is single digits.
	exempt atomic.Pointer[[]string]

	// subscribed counts the live NWC subscriptions per relay (§8). Those relays
	// are exempt from the dial-time address check — the operator typed them into
	// a connection — and are deliberately NOT publish targets; see
	// Pool.Subscribe.
	//
	// COUNTED, not a set. Pairing several apps against one relay is the ordinary
	// case, and with a set the first subscription to close would drop the
	// exemption out from under the others — which nothing would notice until one
	// of them reconnected and was refused for an address the operator chose.
	subscribedMu sync.Mutex
	subscribed   map[string]int

	// publishing serialises publishes, which is what makes the bound on
	// sender-named connections structural rather than a property of how many
	// goroutines happen to call in. Wave 11's publisher is single today; a
	// second one added later must not silently double the number of sockets a
	// stranger can have open at once (0ak criterion 4).
	publishing sync.Mutex
}

// Options are the pool's injectable parts.
type Options struct {
	// Resolve checks what a stranger-named hostname points at before it is
	// dialled. Nil means net.DefaultResolver — the tests supply their own,
	// because the cases worth asserting cannot be arranged in real DNS.
	Resolve Resolver

	// Log carries the one line per publish that says which relays were used
	// and which were dropped. Nil means slog.Default.
	Log *slog.Logger

	// Audit records the one thing this package produces that §12 wants durably:
	// a relay refused at DIAL time, which is a rebinding attempt in progress
	// rather than a bad relay list (bcf).
	//
	// NIL IS VALID, and that is a requirement rather than tolerance: the relay
	// fleet tests build dozens of pools, and a constructor that demanded a sink
	// would make every one of them carry a fake for nothing. Without one the
	// refusal still logs — what is lost is the durable row, not the control.
	Audit Auditor
}

// Auditor is the audit seam, declared HERE because this is the consumer (§3).
//
// Named for what it is, and matching internal/zap and internal/recon, which
// declare the byte-identical interface under the same name — three consumers of
// one shape, findable by one grep.
//
// One method, and it is logging.Auditor's: that type's contract is the log line
// and the durable row TOGETHER, so a pool holding this does not also write its
// own WARN. Two would be one event reported twice. Deliberately NOT
// logging.AuditSink, which is the persistence half alone.
type Auditor interface {
	Record(ctx context.Context, level slog.Level, msg string, event logging.Event,
		attrs ...slog.Attr) error
}

// NewPool builds the pool. relays is read fresh on every publish, so an edited
// relay list takes effect without a restart.
func NewPool(ctx context.Context, relays func() []string, opts Options) *Pool {
	if relays == nil {
		relays = func() []string { return nil }
	}
	if opts.Resolve == nil {
		opts.Resolve = net.DefaultResolver
	}
	if opts.Log == nil {
		opts.Log = logging.Default()
	}
	p := &Pool{relays: relays, resolve: opts.Resolve, log: opts.Log, audit: opts.Audit,
		dialable: dialableAddr,
		refusals: logging.NewRefusalBudget(MaxAuditedRefusalsPerHour, nil)}
	// The dial-time check (vz1.4). chooseTargets vets a stranger's relay by
	// resolving its host itself; the library then resolves again when it dials,
	// and the two answers can differ — a record that changes in between, or a
	// name that answers differently each time. That gap is the TOCTOU
	// dialableHost used to name as an accepted residual, and this shuts it: the
	// address on the socket is checked, on the socket's own resolution.
	p.pool = gonostr.NewSimplePool(ctx,
		gonostr.WithRelayOptions(gonostr.WithDialAddressCheck(p.checkDialAddress)))
	return p
}

// checkDialAddress is consulted by go-nostr immediately before it connects,
// with the relay's own URL and the address it actually resolved to.
//
// The URL half is what makes the policy expressible at all. The operator's own
// relays are exempt — an operator may deliberately point at a relay on their
// own LAN, and the regtest stack does exactly that by compose service name —
// while a stranger's relay reaching a private address is an attack. A check
// given only the resolved address could not tell those apart and would have to
// refuse both or allow both.
//
// The URL rather than its host, because a host is not an identity here: two
// relays can differ only by port or path, and the rest of this file — targets,
// the send list, closeTransient — keys on the normalised URL throughout. Both
// sides of this comparison come from gonostr.NormalizeURL, so they agree by
// construction rather than by a normalisation of our own that could drift.
//
// It runs PER CANDIDATE ADDRESS, not once per dial: net.Dialer calls Control for
// each address it tries and moves to the next when one is refused. So this
// cannot enforce "every address this name answers with must pass" — only that
// the address on the SOCKET passed. dialableHost is what enforces the set, and
// that is the reason it is not redundant; see its doc.
//
// A refusal here is LOGGED, and a refusal in dialableHost is not, which is the
// right way round. A stranger naming a LAN address is ordinary hostile input
// and the pre-check drops it in the publish's own summary line. Reaching THIS
// check means the pre-check was told the host was public and the socket got a
// private address anyway — a rebinding attempt in progress. Without a line here
// it would be silent: internal/zap discards per-relay errors whenever any relay
// accepted, so the one PublishResult carrying it never reaches an operator.
//
// It IS an audit event under §12 since bcf: an attack under way is exactly the
// kind of answer §12's trail exists to keep past log rotation. See
// recordRefusal.
func (p *Pool) checkDialAddress(_, relayURL, resolved string) error {
	if slices.Contains(p.exemptRelays(), relayURL) {
		return nil
	}

	addrPort, err := netip.ParseAddrPort(resolved)
	if err != nil {
		return fmt.Errorf("nostr: cannot read the address dialled for %s: %w", relayURL, err)
	}
	if !p.dialable(addrPort.Addr()) {
		// This is the rebinding case, caught at the only moment it can be:
		// chooseTargets saw a public address for this host and the dial got a
		// private one. An AUDIT event rather than a log line (bcf): §12's trail
		// exists so rotation cannot erase the answer to what happened, and an
		// attack on the relay allow-list is such an answer.
		//
		// The relay as NAMED travels with the address it resolved to, because
		// the pair is the evidence — either alone is unremarkable.
		p.recordRefusal(relayURL, addrPort.Addr())
		return fmt.Errorf("nostr: %s resolved to %s at dial time, which is not an address "+
			"a stranger may make this node connect to", relayURL, addrPort.Addr())
	}
	return nil
}

// exemptRelays reports the relays this dial must treat as the operator's own.
//
// It has two modes, and a nil snapshot is what distinguishes them.
//
// A publish in flight supplies a SNAPSHOT, not a fresh read. Publish's own
// comment says the operator's list is read once and that the exemption, the
// send list and the teardown must all agree on what "configured" meant for
// that publish; a hook that re-read it would be a fourth opinion, and would put
// a settings query on the single sqlite connection for every dial, inside the
// publish lock, on the path §7 says must never hold up a settlement.
//
// With no publish in flight there is no snapshot to honour and none of that
// applies — this is a §8 NWC connection, which has its own relay and dials on
// its own. Reading the list fresh is the answer there rather than treating the
// absent snapshot as an empty one: an operator whose NWC relay is the LAN relay
// they configured would otherwise have every NWC connection refused, by a check
// whose entire purpose is to allow exactly that.
//
// Be clear about what that second mode costs, because the paragraph above spends
// its argument avoiding exactly this: it DOES do the settings read, on the
// dialer's goroutine, once per candidate address. What it avoids is the part
// that mattered — the read is outside the publish lock and off the settlement
// path. If §8 ever makes NWC reconnect aggressively, the answer is a snapshot
// invalidated when the setting is written, not a per-dial query.
//
// NOT REACHED IN A SHIPPED BINARY TODAY, in the same sense as closeTransient's
// positive form below: nothing dials outside a publish until §8's NWC
// connections exist. It is covered by a test rather than left to that wave,
// because "untested and unreachable" is how the first version of this came to
// fail closed for the one case it was written for.
func (p *Pool) exemptRelays() []string {
	// A relay a live subscription is attached to is always exempt, in both
	// modes: an NWC connection's relay is one the operator typed, and it may
	// legitimately be on their own LAN — the regtest stack's is. It is added
	// rather than substituted because a publish running at the same time still
	// needs the operator's own list.
	if snapshot := p.exempt.Load(); snapshot != nil {
		return append(p.subscribedRelays(), *snapshot...)
	}
	return append(p.subscribedRelays(), targets(p.relays())...)
}

// MaxAuditedRefusalsPerHour bounds how many dial-time refusals reach §12's
// trail in an hour.
//
// This is the ONE audit event driven purely by unauthenticated remote input plus
// attacker-controlled DNS: a stranger names the relays in a zap request, and the
// check runs per candidate address. The trail is a fixed ring — §12 trims to
// 10,000 rows, oldest first — so an attacker who can flip a hostname from public
// to private between the pre-check and the dial could, given enough requests,
// evict macaroon.bake, guard.reject and wallet.shortfall. That would defeat
// exactly the durability this event was added for.
//
// Twenty is chosen for what the trail is FOR. An attack's first rows carry the
// whole story — the relay as named, what it resolved to, when it started — and
// the hundredth adds nothing an operator would act on differently. Over the
// refusals past the bound the control still works and still logs; what it
// declines to do is spend the trail on repetition.
//
// It is logging.DefaultRefusalsPerHour now (t0b), not a number of its own: this
// reasoning was written out twice, in two packages, and the two writers that had
// no bound at all had none because nothing said the rule was general. Kept as a
// named constant here because callers and tests refer to it by this name.
const MaxAuditedRefusalsPerHour = logging.DefaultRefusalsPerHour

// auditWriteTimeout bounds the trail write on the dial path.
//
// Generous against a local sqlite write and short against a human: the point is
// that a database which has stopped answering cannot pin a dialer, not to give
// up on a healthy one.
const auditWriteTimeout = 5 * time.Second

// recordRefusal writes the dial-time refusal to §12's trail, or to the log alone
// when this pool was built without a sink.
//
// The context is a BOUNDED Background one, and both halves are deliberate. Not
// the dial's context, because that is about to be cancelled by the very refusal
// being recorded, and an audit row lost because the thing it describes ended is
// the failure §12's durability exists to prevent. Bounded, because this runs on
// the DIALER's goroutine and the write is not the single local INSERT it first
// looks like: the store runs on one connection (SetMaxOpenConns(1)) and the
// append opens a transaction and trims the ring, so a wedged writer would hold a
// dial — and, through it, a publish — indefinitely.
func (p *Pool) recordRefusal(relayURL string, resolved netip.Addr) {
	if p.audit == nil {
		// A line, and deliberately NOT an audit= attribute. internal/arch caught
		// the first version doing that, correctly: the Auditor's contract is the
		// line and the durable row together, so an attribute written by hand
		// claims a trail entry that does not exist. Without a sink there is no
		// audit event — there is a refusal, and it says so.
		p.log.Warn("relay refused at dial time; no audit trail is attached to this pool",
			"relay", relayURL, "resolved", resolved.String())
		return
	}
	if !p.mayAuditRefusal() {
		// Past the hourly bound. The refusal still happened and still says so;
		// what it does not do is evict older rows that nothing else records.
		p.log.Warn("relay refused at dial time; past the hourly audit bound, so this one is "+
			"logged only", "relay", relayURL, "resolved", resolved.String())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), auditWriteTimeout)
	defer cancel()
	if err := p.audit.Record(ctx, slog.LevelWarn, "relay refused at dial time",
		logging.EventRelayRefuse,
		slog.String("relay", relayURL), slog.String("resolved", resolved.String())); err != nil {
		p.log.Error("could not write the audit trail for a refused relay", "error", err.Error())
	}
}

// mayAuditRefusal reports whether this refusal may be written to the trail, and
// counts it if so.
//
// A plain sliding hour rather than a token bucket: the question is "have we
// already told this story recently", and the answer only has to be right to the
// nearest burst.
func (p *Pool) mayAuditRefusal() bool {
	record, _ := p.refusals.Allow()
	return record
}

// Close drops every connection at shutdown.
//
// Each relay is closed explicitly first. go-nostr's SimplePool.Close only
// cancels the POOL's context, while EnsureRelay builds each relay from
// context.Background — so closing the pool alone leaves every websocket, its
// ping goroutine and its read goroutine running for the life of the process.
//
// This used to be the ONLY place connections were closed, and that was the
// hazard: a zap request names the relays a receipt is published to, so every
// distinct URL any stranger had ever named kept a websocket and two goroutines
// alive until the process ended. Publish now closes what it opened (see
// closeUnconfigured), and this handles the operator's own set at shutdown.
func (p *Pool) Close() {
	// Nothing is kept at shutdown, so neither clause spares anything. One
	// teardown path rather than two: whatever changes about how a relay is
	// closed should not have to be changed twice.
	p.closeTransient(nil, nil)
	p.pool.Close("shutting down")
}

// targets normalises a base list plus extras, in order, without duplicates.
//
// Split out so Publish can read the configured list ONCE. Calling Targets twice
// read it twice — and that list comes from the settings table, so it was two
// sqlite queries per publish on the single connection AND a window in which an
// operator saving a new relay between the two calls would have their newly
// configured relay treated as a stranger and closed.
func targets(base []string, extra ...string) []string {
	var out []string
	for _, url := range slices.Concat(base, extra) {
		url = strings.TrimSpace(url)
		if url == "" || !gonostr.IsValidRelayURL(url) {
			continue
		}
		if normalised := gonostr.NormalizeURL(url); !slices.Contains(out, normalised) {
			out = append(out, normalised)
		}
	}
	return out
}

// Publish sends the event to every target and reports what each one said.
//
// It never returns an error for the batch: "no relay accepted this" is a result
// the caller retries, not a failure of the call (§7).
//
// Sender-named relays are connected for THIS publish and closed when it
// finishes, success or failure. The pool holds persistent connections only to
// the operator's configured set (0ak).
//
// Not a bounded cache of strangers' relays: keeping them warm optimises for the
// attacker's traffic pattern, on the theory that the same URL will be named
// again. Per-publish-then-close is bounded by construction, and nothing is lost
// — o34.3's retry path rebuilds the receipt from the store on every attempt
// anyway, so a retry re-dials whatever the request named.
func (p *Pool) Publish(ctx context.Context, event gonostr.Event, extra ...string) []PublishResult {
	// One publish at a time. See the publishing field: this is what bounds the
	// sender-named connections that can exist at any instant, whatever the
	// caller does.
	p.publishing.Lock()
	defer p.publishing.Unlock()

	// The deadline covers EVERYTHING, resolving included. Choosing the targets
	// now costs a DNS lookup per stranger-named host, and a stranger picks both
	// the hosts and how many there are; leaving that outside publishTimeout
	// meant an anonymous caller could add to the 30 seconds rather than spend
	// them, while holding the publish lock. One number bounds the whole call.
	ctx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()

	// The operator's list is read ONCE. The exemption below, the send list and
	// the teardown must all agree on what "configured" meant for this publish:
	// reading it again in the deferred close reopened the window that splitting
	// targets out was meant to shut, and an operator saving a relay mid-publish
	// would have had it treated as a stranger's and closed.
	configured := targets(p.relays())
	// The same list the exemption, the send list and the teardown use, handed
	// to the dial hook so all four agree. Cleared on the way out so a dial with
	// no publish behind it — §8's NWC connections — cannot inherit it.
	p.exempt.Store(&configured)
	defer p.exempt.Store(nil)
	chosen := p.chooseTargets(ctx, configured, extra)
	sending := chosen.sending
	chosen.log(p.log)
	if len(sending) == 0 {
		// Distinguishable from "every relay refused": both are retryable, and
		// o34.3 must be able to tell "nowhere to send it" from "nobody took it".
		return []PublishResult{{Err: ErrNoRelays}}
	}
	// A publish leaves the pool as it found it. Snapshot first, close whatever
	// THIS publish added — stated as a positive rather than as "close anything
	// not configured", which is a different rule that happens to agree today.
	//
	// It will stop agreeing at §8: NWC gives each connection its own relay,
	// chosen per connection and not necessarily in default_relays, and an arch
	// rule guarantees NWC shares this one pool. The negative form would have
	// had every zap receipt silently close NWC's long-lived subscription
	// socket, with a green suite.
	//
	// NOT TESTED, because it is not yet observable: every connection this pool
	// holds today was opened by a publish, so both rules agree on all of them.
	// A test written now could only be vacuous — one was, and was deleted
	// rather than kept as decoration. The assertion belongs to the wave that
	// adds NWC subscriptions, and is filed there.
	//
	// Deferred, so a panic or an early return cannot leave a stranger's
	// connection behind — the failure this exists to close.
	before := p.Connected()
	defer func() { p.closeTransient(before, configured) }()

	// THE CONNECT PHASE IS OURS (du9, §7). Snapshot first, then dial: a relay
	// this publish opens must land outside `before` so the teardown above still
	// closes it, which is why this cannot move above the snapshot.
	//
	// The library is handed only relays that are already open, so EnsureRelay
	// finds each one connected and returns at once. That is what keeps the
	// invariant the three mechanisms around this call silently depend on — the
	// `before` snapshot, the `exempt` pointer and the publishing lock all assume
	// that when Publish returns, nothing it started is still dialling.
	//
	// AND IT IS NOT A BARRIER (d1o). du9's first version joined every dial
	// before sending anything, which made every healthy relay wait for the
	// slowest dead one — up to a whole connect budget, on a list with one stale
	// entry. Each relay is now dialled and sent to on its own goroutine, all of
	// them joined before this returns, so the invariant above is untouched;
	// what changed is that no relay waits for another. See sendAndDial.
	start := time.Now()
	results, cost := p.sendAndDial(ctx, sending, event)
	p.logRelayCosts(time.Since(start), results, cost)
	return results
}

// relayCost is what ONE relay cost, on its own (k2z item 3).
//
// Its own, and that is the whole design of the number. The two phases are
// barriers — every relay dials at once and the send starts when the slowest dial
// has finished — so a duration measured from the start of the publish would give
// every relay the same figure, and a record whose numbers are all equal names
// nobody. This is the relay's dial plus the relay's own wait for an OK, with the
// barrier between them subtracted out.
type relayCost struct {
	// outcome is one of:
	//
	//	accepted       it took the event
	//	refused        it connected and said no, or the send timed out
	//	over_budget    it never finished connecting and ate the whole budget
	//	not_connected  the dial failed on its own, fast and for free
	//	no_answer      the library reported nothing for a connected relay,
	//	               which should be unreachable
	//
	// no_answer WAS REMOVED AS DEAD BY THE /simplify PASS AND IS BACK, which is
	// worth explaining rather than looking like a revert. That reading was right
	// for the shape it was made against: results were APPENDED as PublishMany
	// reported them, so a relay it never reported simply had no result, and
	// logRelayCosts — which reads cost only through results — never looked the
	// label up. d1o publishes per relay into a pre-sized slot instead, so the
	// slot exists whether or not the library answers, and the zero PublishResult
	// in it has a NIL error, which Accepted counts as a success. The label and
	// its errNoAnswer are the fail-closed value of that slot: still unreachable,
	// but now the thing it guards is "a relay nobody heard from is reported as
	// having taken the receipt" rather than "a map entry goes unread".
	//
	// The distinctions are the diagnosis. over_budget versus not_connected is
	// du9.3 and is the one that costs money: the first names the relay this
	// publish waited for, the second a relay that was simply unavailable. refused
	// versus either is a working relay declining an event, which is not a
	// connectivity fault at all and must not be conflated with one.
	//
	// WHAT over_budget DOES NOT SPLIT, and why: a relay that completes TCP and
	// TLS and then rejects the HTTP upgrade — a 502 or 503 from a front proxy,
	// which is how relay.damus.io sheds load — lands in not_connected beside a
	// TCP reset. Telling those apart would mean matching text in a dependency's
	// error string: coder/websocket returns a plain fmt.Errorf for a non-101
	// status and DISCARDS the *http.Response (dial.go:243), and go-nostr's
	// NewConnection discards it again (connection.go:22). Neither the status nor
	// a typed error survives. That match would sit two libraries deep and break
	// silently on a bump, on the path o34.18 intends to replace. Both are "the
	// relay was not usable and it cost nothing", which is one operational fact.
	outcome string
	took    time.Duration
}

// logRelayCosts names, at DEBUG, what each relay cost — but only when the
// publish was SLOW or PARTIAL (§7 part 3, k2z item 3).
//
// Only then, because the ordinary case is four or six relays all accepting in
// milliseconds, and a line each for that is noise an operator would filter out —
// after which the lines would not be there on the day they were wanted. Slow is
// "longer than the connect budget", which is the shape of the fault this bead
// fixed; partial is "somebody refused", which is the shape of the one it did
// not.
//
// One record PER RELAY rather than one record carrying a group. The line is read
// by grepping a box's journal for the relay whose name is already suspected, and
// a group flattens differently in every log shipper, whereas relay= on its own
// line does not. It also keeps the width fixed however many relays a stranger
// named.
//
// Relay URLs only. They are logged already in "relays chosen for this publish",
// they are not secrets, and an operator cannot match a line against their own
// relay list if it is redacted. Nothing else is added — no payload, no identity,
// and deliberately not the relay's own error text, which is unbounded input from
// a stranger's relay.
// "Slow" is measured on the pool's own clock: from after the publishing lock,
// the exemption store and chooseTargets' resolver pre-check, to the last relay's
// answer. The receipt line's publish_ms (internal/zap) is taken around the whole
// Publish call and so also counts lock wait and the pre-check. The two numbers
// can differ, and a publish slowed by the resolver or by queueing behind the
// lock can exceed the budget on the receipt line while producing no records
// here — by design, because those records are about relays.
func (p *Pool) logRelayCosts(elapsed time.Duration, results []PublishResult,
	cost map[string]relayCost) {
	if elapsed <= connectBudget && Accepted(results) == len(results) {
		return
	}
	for _, result := range results {
		c := cost[result.Relay]
		p.log.Debug("relay outcome in a slow or partial publish",
			"relay", result.Relay, "outcome", c.outcome, "ms", c.took.Milliseconds())
	}
}

// sendAndDial publishes to every target, EACH ON ITS OWN GOROUTINE, so that no
// relay waits for another.
//
// THIS IS d1o, and the shape is the whole of it. du9's first version ran the
// connect phase as a BARRIER — every dial joined before anything was sent — so
// one relay that is simply down delayed every healthy relay's send by up to a
// whole connect budget. On the receipt path that is latency, which §7 tolerates
// because nobody is waiting on a receipt. On the NWC path it was a bug with
// teeth: §8's attempt budget is five seconds and connectBudget is five seconds,
// and the dial context derives from the attempt's, so a pairing holding one dead
// relay spent the ENTIRE attempt dialling it and then published to its live,
// already-subscribed relay against a context that had just expired. The frame
// still reached the client, because go-nostr writes it on the connection's own
// context before waiting for the OK, but the attempt was recorded as failed and
// retried — and every retry paid the five seconds again.
//
// PER RELAY RATHER THAN IN TWO PHASES, which is the stricter fix and the smaller
// code. Sending to the already-open relays first while the rest are dialled
// would leave the same barrier INSIDE the dialled group: on the first publish
// after a restart nothing is open yet, so a live relay would still wait for a
// dead one — the same bug, narrowed to the case where a subscription has
// dropped, which is exactly when the NWC path can least afford it.
//
// CONCURRENCY HERE IS NOT AN OPTIMISATION. In series, eight sender-named relays
// that are all down would cost eight budgets — forty seconds, past
// publishTimeout — on the path §7 says must never hold up a settlement.
//
// EVERY GOROUTINE IT STARTS IS JOINED BEFORE IT RETURNS. That is §7's invariant,
// and the reason the rejected shape — keep the library's fan-out and stop
// reading once the reachable relays have answered — was rejected: a straggler
// that connects after the teardown has run stores itself into the pool and is
// kept for ever. The teardown's `before` snapshot, the `exempt` pointer and the
// publishing lock all rest on it.
//
// RESULTS COME BACK IN TARGET ORDER, which is a small gain worth naming: the
// library's channel yielded them in completion order, so on a total failure
// internal/zap's relayFailure reported whichever goroutine happened to lose. It
// is now the first relay in the list, every time.
func (p *Pool) sendAndDial(ctx context.Context, targets []string,
	event gonostr.Event) ([]PublishResult, map[string]relayCost) {
	results := make([]PublishResult, len(targets))
	costs := make([]relayCost, len(targets))

	var wg sync.WaitGroup
	for i, url := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], costs[i] = p.publishOne(ctx, url, event)
		}()
	}
	wg.Wait()

	cost := make(map[string]relayCost, len(targets))
	for i, url := range targets {
		cost[url] = costs[i]
	}
	return results, cost
}

// publishOne connects one relay if it is not already open, sends, and reports
// what the relay said and what it cost.
//
// A relay already open is not re-dialled and its send starts at once. That is
// the ordinary case twice over: the operator's own set, which the pool holds
// between publishes, and a pairing's relays, which a subscription holds open for
// the life of the pairing.
//
// The cost is this relay's OWN — its dial plus its own wait for an OK, with
// nothing of any other relay's in it. That is what makes the DEBUG records name
// the relay that cost the time instead of reporting one number several times.
func (p *Pool) publishOne(ctx context.Context, url string,
	event gonostr.Event) (PublishResult, relayCost) {
	var dialled time.Duration
	if relay, ok := p.pool.Relays.Load(url); !ok || relay == nil || !relay.IsConnected() {
		began := time.Now()
		err := p.dial(ctx, url)
		dialled = time.Since(began)
		if err != nil {
			// One failed RESULT, never a failed publish: o34.3's retry reads
			// these per relay, and a relay that is down is not a reason to
			// re-send to the ones that already have the event.
			//
			// SPLIT (du9.3), because the two cost opposite amounts. A relay that
			// hung ate the whole budget and is why this publish was slow; one
			// that failed fast cost nothing and is merely unavailable. Both read
			// not_connected until then, and the first per-relay records ever
			// taken off a box had them side by side — nostr.band at 5000 ms and
			// damus at 241 ms, identically labelled.
			label := "not_connected"
			if errors.Is(err, errConnectBudget) {
				label = "over_budget"
			}
			return PublishResult{Relay: url, Err: err}, relayCost{outcome: label, took: dialled}
		}
	}

	// EnsureRelay finds this one open and returns at once, which is what makes
	// the timing below a measurement of the relay rather than of the dial.
	sendStart := time.Now()
	result := PublishResult{Relay: url, Err: errNoAnswer}
	cost := relayCost{outcome: "no_answer", took: dialled}
	for answer := range p.pool.PublishMany(ctx, []string{url}, event) {
		result = PublishResult{Relay: answer.RelayURL, Err: answer.Error}
		cost.outcome = "accepted"
		if answer.Error != nil {
			cost.outcome = "refused"
		}
		cost.took = dialled + time.Since(sendStart)
	}
	return result, cost
}

// dial connects one relay under the budget and stores it in the pool.
//
// THE OPTION HAS TO BE PASSED BY HAND. SimplePool.relayOptions is unexported, so
// a relay built here carries none of the pool's — the dial-time address check
// among them, which is the whole of vz1.4's protection against DNS rebinding.
// internal/arch's checkDialAddressCheckWiring is what keeps that true, and it is
// not the only guard: dropping the option here also turns
// dialable_test.go's rebinding test red, which is the behavioural half.
//
// context.Background() as the relay's own parent, matching EnsureRelay. The
// relay must outlive this publish — the operator's connections are held between
// publishes on purpose — and a relay parented on the publish context would have
// its socket torn down the instant Publish returned.
func (p *Pool) dial(ctx context.Context, url string) error {
	// Derived from the PUBLISH context, so a caller already near its own
	// deadline shortens this rather than extending past it. That is the
	// property go-nostr's hardcoded fifteen seconds lacked: it hangs off the
	// pool's context, where no caller can reach it.
	dialCtx, cancel := context.WithTimeoutCause(ctx, connectBudget, errConnectBudget)
	defer cancel()

	relay := gonostr.NewRelay(context.Background(), url,
		gonostr.WithDialAddressCheck(p.checkDialAddress))
	if err := relay.Connect(dialCtx); err != nil {
		// CLOSED, not dropped. NewRelay starts no goroutines until Connect
		// returns — verified against the pinned fork rather than assumed — so
		// what this releases is the relay's own context, and with it any
		// half-open socket the dial left behind.
		_ = relay.Close()
		if errors.Is(context.Cause(dialCtx), errConnectBudget) {
			return fmt.Errorf("nostr: %s: %w after %s: %w",
				url, errConnectBudget, connectBudget, err)
		}
		return fmt.Errorf("nostr: connecting to %s: %w", url, err)
	}

	// LOAD-OR-STORE, atomically, because namedLock is unexported: an NWC
	// subscription dialling this same URL at this same instant is a real race,
	// and two live *Relay for one URL is a leaked socket and two goroutines that
	// nothing will ever close — closeTransient can only see the one in the map.
	//
	// Compute rather than LoadOrStore, for the case LoadOrStore gets wrong: a
	// relay whose socket has dropped is still IN the map, because nothing
	// removes it, so LoadOrStore would hand that dead entry back and discard the
	// live relay this call just dialled. Be precise about the cost, because it
	// is smaller than it first looks: EnsureRelay would then re-dial the URL
	// itself and succeed, since this call has just proved the relay reachable —
	// so what LoadOrStore buys is a wasted dial, a second socket to the same
	// relay for the length of it, and a stale *Relay overwritten rather than
	// closed. Not the fifteen seconds, which needs the relay to go down in the
	// gap between the two dials. Compute costs the same line count and leaves
	// none of it, which is why it is the one used; the fifteen seconds is not
	// the argument for it.
	//
	// RESIDUAL, stated rather than implied away: EnsureRelay stores with a plain
	// Store under its own lock, so a Subscribe that began dialling this URL
	// before this call and finishes after it can still overwrite this entry and
	// orphan the socket. It cannot be closed without the library's per-URL lock,
	// the window is one concurrent subscribe to a relay a publish is dialling at
	// that instant, and it is filed as BrollyZap-du9.1.
	var duplicate *gonostr.Relay
	p.pool.Relays.Compute(url,
		func(existing *gonostr.Relay, loaded bool) (*gonostr.Relay, bool) {
			if loaded && existing != nil && existing.IsConnected() {
				duplicate = relay
				return existing, false
			}
			duplicate = existing
			return relay, false
		})
	if duplicate != nil {
		_ = duplicate.Close()
	}
	return nil
}

// PublishToConnection sends the event to ONE PAIRING'S OWN relays, and is §8's
// publish (step 6).
//
// It took a single relay URL until d24.18; what changed is the number, not the
// rule. The relays come from the connection row — which was written from the
// pairing URI — and never from the operator's configured set, which is what the
// ConnectionRelays type and the arch rule that guards this seam exist to keep
// true. Every one of them is a relay the client itself named, so none of them is
// a new party learning that this pairing exists.
//
// A separate entry point rather than Publish with the relays as extra targets,
// because Publish sends to the operator's configured list PLUS the extras — and
// for NWC that list is wrong twice over. A response would go to relays the
// client is not listening on; the kind 13194 info event is UNENCRYPTED and
// carries a connection's service pubkey and its capabilities, so publishing it
// to the operator's zap-receipt relays would announce every pairing next to that
// operator's receipts, from one IP. The per-connection service key exists so an
// observer cannot link the operator's apps; co-publication defeats it without
// any key being reused.
//
// It also has no business with the transient-relay machinery. That machinery
// exists for relays a STRANGER named in a zap request — the cap, the address
// filter, the close-what-we-opened teardown. These relays are neither a
// stranger's nor in default_relays: the operator paired on them and a
// subscription is holding each one open. So: no cap here beyond
// MaxPairingRelays, no snapshot, and nothing to tear down. The dial-time check
// still runs, and exempts them because they are subscribed.
//
// Not under the publishing lock, deliberately. That lock bounds how many
// stranger-named sockets can exist at once, and this opens none; taking it would
// put every NWC response behind a 30-second zap publish for no gain. The relay
// it uses is spared by closeTransient for exactly this reason.
func (p *Pool) PublishToConnection(ctx context.Context, event gonostr.Event,
	relays ConnectionRelays) []PublishResult {
	targets := make([]string, 0, len(relays.urls))
	results := make([]PublishResult, 0, len(relays.urls))
	for _, relay := range relays.urls {
		normalised := gonostr.NormalizeURL(strings.TrimSpace(relay))
		if normalised == "" || !gonostr.IsValidRelayURL(normalised) {
			// Reported per relay rather than failing the publish: one unusable
			// address in a pairing's list must not stop the event reaching the
			// others, which is the whole reason there is a list (d24.18).
			results = append(results, PublishResult{Relay: relay,
				Err: fmt.Errorf("nostr: %q is not a usable relay URL", relay)})
			continue
		}
		targets = append(targets, normalised)
	}
	if len(targets) == 0 {
		return results
	}
	ctx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()

	// THE SAME CONNECT BUDGET (du9). It was a delegated decision and the answer
	// is yes, for the reason that this path pays MORE for the bug rather than
	// less: §8 bounds an NWC response attempt at five seconds, and that bound is
	// on the caller's context, which go-nostr's connect timeout does not consult
	// — so a pairing naming a relay that is down waited the full fifteen and
	// blew a budget it appeared to be under. Dialling here derives from this
	// context, so the five seconds finally binds.
	//
	// Safe here for the same reasons it is safe above, and they are the ones
	// that made the shape worth checking separately. Nothing in this path has a
	// `before` snapshot or a teardown, so a relay opened here stays in the pool
	// exactly as EnsureRelay would have left it — the behaviour is unchanged,
	// only bounded. It is outside the publishing lock, so two of these can dial
	// one URL at once; Pool.dial stores with Compute for precisely that. And
	// these relays are subscribed, so the dial-time check exempts them through
	// exemptRelays' no-snapshot mode, which is what it was written for.
	//
	// AND THE PHASES OVERLAP (d1o), which this path needed more than the receipt
	// path did. ResponseAttemptTimeout is five seconds and connectBudget is five
	// seconds, and the dial context derives from the attempt's — so while the
	// connect phase was a BARRIER, one dead relay in a pairing's stored list
	// spent the entire attempt dialling, and the live, already-subscribed relay
	// was then published to against a context that had just expired. The frame
	// still reached the client, because go-nostr writes it on the connection's
	// own context before waiting for the OK, but the attempt was recorded as
	// failed and retried — and every retry paid the five seconds again. A
	// pairing's relays are subscribed and therefore already open, so they are
	// now sent to at once, while the dead one is still being dialled.
	//
	// The cost records are DISCARDED here: k2z keeps the NWC line, and du9
	// folded in only its receipt half. They are computed either way, which is
	// the price of ONE implementation of the two phases rather than two — and a
	// cheap one, at MaxPairingRelays entries. Two copies would have been two
	// chances to fix this barrier once.
	sent, _ := p.sendAndDial(ctx, targets, event)
	return append(results, sent...)
}

// transientChoice is what one publish decided about the relays it was handed.
//
// Three lists rather than a count, because the counts alone answer "how many"
// and the question an operator actually arrives with is "why did MY relay not
// get it". The 0.1.5 box trip named ten relays including a LAN address, the
// filter dropped it, the cap cut another — and nothing was logged at all, so
// invoices.zap_relays was the only evidence that existed anywhere.
type transientChoice struct {
	// sending is what the publish will use: the operator's relays plus the
	// stranger-named ones that survived, in the order they were named.
	sending []string
	// named counts the relays the SENDER named — normalised and deduplicated,
	// so a request naming one relay twice counts one, and an unusable URL counts
	// none.
	//
	// It counts them whether or not this node already has them (du9.4). It did
	// not until then: the loop skipped a relay that was also the operator's
	// before counting it, so a request naming exactly the relays already
	// configured logged named=0 kept=0 — indistinguishable from a request that
	// named nothing at all, which is what the relay probe hit and could not
	// explain from the line. The field's own doc said "the targets the caller
	// passed" throughout, which was the behaviour nobody had.
	named int
	// alreadyOurs counts the named ones this node was going to publish to
	// anyway. It is what makes named=2 kept=0 legible rather than alarming: they
	// were not dropped, they were already in the list.
	alreadyOurs int
	// refused is the ones the allow-list rejected — a LAN address, a name that
	// resolves to one, or a name nothing answers for.
	refused []string
	// overCap is the ones dropped for room rather than for content — past
	// MaxTransientRelays. "We did not try", which is what an operator needs to
	// tell apart from "we tried and it said no".
	overCap []string
}

// log is the one INFO line per publish, and therefore per accepted zap request.
//
// Through the normal logger with no audit= attribute: a stranger naming a LAN
// address is expected input on a public endpoint, not a security event, and
// filing it as one would put noise in the trail that §12 keeps for the things
// that matter. Relay URLs are not secrets and appear in full — an operator
// cannot match a line against their own relay list if it is redacted.
func (c transientChoice) log(log *slog.Logger) {
	dropped := len(c.refused) + len(c.overCap)
	log.Info("relays chosen for this publish",
		// THE ARITHMETIC CLOSES, and du9.4 widened it by one term rather than
		// breaking it: named == kept + dropped + already_ours. Every relay the
		// sender named is accounted for exactly once — we took it, we dropped
		// it, or we had it already.
		//
		// The operator's OWN relays are still not counted here. They are in
		// `relays`, they were never at risk of being dropped, and counting them
		// would make "dropped 2 of 10" read as though two of the operator's had
		// failed. already_ours is not that: it counts only relays the sender
		// named which happen to be ours too.
		"named", c.named,
		"kept", c.named-dropped-c.alreadyOurs,
		"dropped", dropped,
		"already_ours", c.alreadyOurs,
		"relays", c.sending,
		"refused", c.refused,
		"over_cap", c.overCap)
}

// chooseTargets decides which relays this publish will use.
//
// The check lives HERE, at the pool, and not only in internal/lnurl's parse:
// every outbound relay URL passes through this function, so a future caller
// handing Publish URLs from somewhere else cannot route around it. lnurl's
// parse-time filter stays as the polite early refusal — it can answer the
// caller with a reason, which this cannot.
//
// The operator's CONFIGURED relays are exempt, and are neither counted nor
// capped. An operator may deliberately point at a relay on their own LAN, and
// the regtest stack does exactly that by compose service name; the danger is a
// STRANGER choosing the address, not a private address as such. If a configured
// relay ever stops being dialled, this exemption is what is wrong, not the test
// that noticed.
//
// MaxTransientRelays caps the CANDIDATES, not the survivors, which is what makes
// it a bound on the work as well as on the sockets. Every stranger-named host
// costs a resolution and an anonymous caller picks how many there are, so a rule
// that kept resolving until it had eight SURVIVORS would let a list of five
// hundred refusals decide how long this takes. The cost is that a request whose
// first entry is a LAN address gets seven real relays rather than eight;
// internal/lnurl has already filtered and capped the list by the time it arrives
// here, so in practice the two rules choose the same relays.
//
// The candidates are resolved CONCURRENTLY. They are independent lookups, at
// most MaxTransientRelays of them, and doing them in series put the sum of eight
// resolver timeouts on a path §7 says must never hold up a settlement.
func (p *Pool) chooseTargets(ctx context.Context, configured, extra []string) transientChoice {
	sending := targets(configured, extra...)
	// What the SENDER said, normalised and deduplicated exactly as `sending`
	// was, so membership below is decided by one notion of relay identity
	// rather than two. Counting from `sending` instead is what du9.4 fixed:
	// it has the operator's list folded in, so a relay in both appears once
	// and the loop could not tell "the sender did not name it" from "the
	// sender named it and we had it".
	named := targets(nil, extra...)
	choice := transientChoice{sending: make([]string, 0, len(sending)), named: len(named)}

	var candidates []string
	for _, relay := range named {
		if slices.Contains(configured, relay) {
			// Already a target, so not a candidate and not capped — it consumes
			// no room, exactly as before. What changed is that it is now
			// counted instead of vanishing.
			choice.alreadyOurs++
			continue
		}
		if len(candidates) < MaxTransientRelays {
			candidates = append(candidates, relay)
			continue
		}
		choice.overCap = append(choice.overCap, relay)
	}

	dialable := make([]bool, len(candidates))
	var wg sync.WaitGroup
	for i, relay := range candidates {
		wg.Add(1)
		go func() {
			defer wg.Done()
			parsed, err := url.Parse(relay)
			dialable[i] = err == nil && p.dialableHost(ctx, parsed.Hostname())
		}()
	}
	wg.Wait()

	// Rebuilt in the order they were named, so the send list reads the way the
	// request wrote it and the operator's relays keep their place.
	kept := make(map[string]bool, len(candidates))
	for i, relay := range candidates {
		if dialable[i] {
			kept[relay] = true
			continue
		}
		choice.refused = append(choice.refused, relay)
	}
	for _, relay := range sending {
		if slices.Contains(configured, relay) || kept[relay] {
			choice.sending = append(choice.sending, relay)
		}
	}
	return choice
}

// closeTransient drops the connections this publish opened for a stranger.
//
// A connection is KEPT if it was already open before this publish, or if it is
// the operator's. Both clauses are needed and each catches a case the other
// misses: without `configured`, the very first publish finds nothing open and
// closes the operator's own relays with everything else (which is exactly what
// the first version of this did, and what its test caught); without `before`,
// a connection some other part of the app is holding — §8's NWC subscriptions,
// which share this pool by arch rule — goes down with every zap receipt.
//
// Both halves of the close matter too: closing the websocket stops its ping and
// read goroutines, and removing it from the pool's map stops go-nostr handing
// the dead relay back to the next publish that names the same URL.
func (p *Pool) closeTransient(before, configured []string) {
	// Deleting during Range is safe on xsync.MapOf, which its own docs state,
	// so this does not need the collect-then-delete second pass it started as.
	// A relay a subscription is attached to is kept too, and it is a third
	// clause rather than a case of `before`: a subscription that DIALLED during
	// this publish is in neither snapshot, and closing it would take down an NWC
	// connection with a zap receipt — the exact failure the `before` clause was
	// added to prevent, in the one window it cannot see.
	subscribed := p.subscribedRelays()
	p.pool.Relays.Range(func(url string, relay *gonostr.Relay) bool {
		if relay != nil && !slices.Contains(before, url) && !slices.Contains(configured, url) &&
			!slices.Contains(subscribed, url) {
			_ = relay.Close()
			p.pool.Relays.Delete(url)
		}
		return true
	})
}

// Connected is the relay URLs the pool currently holds open.
//
// It exists so the rule above can be ASSERTED rather than assumed — 0ak's
// criteria are a count, and counting from outside meant reaching into
// go-nostr's internals from a test. It is also the honest answer to "what is
// this node connected to", which is a question an operator may eventually get
// to ask.
func (p *Pool) Connected() []string {
	var out []string
	p.pool.Relays.Range(func(url string, relay *gonostr.Relay) bool {
		if relay != nil {
			out = append(out, url)
		}
		return true
	})
	slices.Sort(out)
	return out
}

// IsRelayURL reports whether raw is a usable relay address.
//
// Exported so the admin UI can refuse a typo at the form rather than storing it
// and letting a wallet app fail to pair against a relay that was never dialable.
// It is the SAME predicate ParseRelays filters on, deliberately: two notions of
// a valid relay is one more than this app can keep straight.
func IsRelayURL(raw string) bool { return gonostr.IsValidRelayURL(strings.TrimSpace(raw)) }

// ParseRelays reads a settings value: one relay per line or comma-separated,
// falling back to DefaultRelays when the operator has set none.
func ParseRelays(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	var out []string
	for _, field := range fields {
		if IsRelayURL(field) {
			out = append(out, field)
		}
	}
	if len(out) == 0 {
		return slices.Clone(DefaultRelays)
	}
	return out
}
