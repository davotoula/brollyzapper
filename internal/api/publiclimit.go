package api

import (
	"context"
	"github.com/davotoula/brollyzapper/internal/logging"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnurl"
)

// §7's limits on the public callback, as ruled on 22 Aug 2026.
//
// Three layers, each bounding a different thing, and each named in code for
// what it actually is. None of them is per-IP: the Cloudflare tunnel path
// flattens every internet client to one address (measured — 172.17.0.1, the
// bridge gateway, which app_proxy then writes into X-Forwarded-For), so a
// per-IP bucket there is not isolation, it is a global bucket that lets the
// first abusive caller throttle every honest one. The edge is the only place a
// real, authenticated client address exists, which is why Cloudflare WAF rate
// limiting is a REQUIRED operator step in the docs rather than an optional one.
const (
	// PerSenderPerMinute bounds one zap sender against the others. The key is
	// the zap request's signed pubkey, which is a cheap identity — anyone can
	// mint keys — so this is NOT a Sybil defence and must never be described as
	// one. What it buys is that two honest senders stop colliding, which is the
	// problem §7 actually names.
	PerSenderPerMinute = 10
	// PerSenderPerHour is the same bucket's slow window. §7 fixes the minute
	// figure and is silent on the hour; this mirrors the 10/100 ratio the
	// public pair carried before the split rather than inventing a new shape.
	PerSenderPerHour = 100

	// OpenInvoiceCap is the real resource bound: what a caller consumes by
	// reaching the callback is a row in LND's invoice database, and this is
	// what counts them. It self-clears — an unpaid LNURL invoice expires in 600
	// seconds — so a flood costs the node ten minutes at the ceiling rather
	// than anything permanent. NWC-minted invoices share the cap and expire in
	// an hour; with the pairing's own budget in front of them, they cannot
	// flood it. (The same caveat is on store.CountOpenInvoices, which is what
	// actually counts: the query has no source column, so BOTH kinds are in it.)
	OpenInvoiceCap = 100

	// The globalBackstop's defaults. This is the one layer the operator can
	// move, through public_rate_limit_per_min / _per_hour: their own zaps are
	// what bounce off it, and §7 has always expected them to raise it.
	DefaultGlobalBackstopPerMinute = 60
	DefaultGlobalBackstopPerHour   = 600
)

// Invoices is the slice of the invoice store the open-invoice cap needs.
//
// Declared here, by the consumer, and holding exactly one method: the cap needs
// to count open invoices and has no business being able to create or settle
// one.
type Invoices interface {
	CountOpenInvoices(ctx context.Context, now time.Time) (int64, error)
}

// callbackGate is §7's three layers on GET /lnurlp/{name}/callback.
//
// It is the callback and nothing else. The lnurlp DOCUMENT is deliberately not
// limited at all — see NewPublicMux — because it is static JSON that mints
// nothing, and limiting it made one zap cost two of the instance's requests.
type callbackGate struct {
	// globalBackstop is a ceiling on TOTAL anonymous traffic. It is named
	// backstop, never perClient, because it isolates nobody from anybody and
	// the next reader must not mistake it for something that does.
	globalBackstop *Limiter
	perSender      *Limiter
	invoices       Invoices
	cap            int64
	now            func() time.Time
	log            *slog.Logger

	// rescueOnce keeps the double-encoding notice to one line per process. See
	// noteDoubleEncodingRescue.
	rescueOnce sync.Once

	// lastCount is the most recent successful open-invoice count, and what a
	// failed count falls back to. See underInvoiceCap.
	countMu   sync.Mutex
	lastCount int64
	counted   bool
}

// Middleware applies all three layers.
//
// Every layer must pass, so the order changes only how much work a REFUSED
// request costs. The database check is last, and not because it is the most
// expensive one — verifying a zap signature costs more CPU than an indexed
// count over a hundred rows. It is last because it is the only layer that
// touches sqlite, which runs on a single connection shared with the invoice
// stream: a request the backstop was going to refuse anyway must not make a
// settlement wait.
func (g *callbackGate) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.globalBackstop.Allow(r) {
			g.refuse(w, r, "backstop",
				"this address is receiving more requests than it can answer; try again shortly", "")
			return
		}
		// The ONE parse of the nostr parameter, after the backstop and before
		// anything else. After, because a schnorr verification is the most
		// expensive thing on this path and an unbounded flood of forged
		// requests must not be able to demand it. Before the two layers below,
		// because both depend on what it found.
		zap := lnurl.ParseZapParam(r.URL.Query())
		r = r.WithContext(contextWithZap(r.Context(), zap))
		logRelayDrops(g.log, zap)
		g.noteDoubleEncodingRescue(zap)

		// Zap path only: a plain LNURL payment carries no sender identity, so
		// there is nothing to key on and the backstop above is its only bound.
		if key, isZap := zap.SenderKey(); isZap && !g.perSender.AllowKey(key) {
			g.refuse(w, r, "per_sender",
				"too many requests from this nostr key; try again shortly", key)
			return
		}
		// A rejected zap request cannot mint, so it must not spend a database
		// query on the single connection the invoice stream writes on. The
		// handler renders the refusal a moment later.
		if !zap.Rejected() && !g.underInvoiceCap(r.Context()) {
			g.refuse(w, r, "open_invoices",
				"this address has too many unpaid invoices open; "+
					"they expire within ten minutes", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// noteDoubleEncodingRescue reports a zap request that only parsed because rule
// 3's fallback decoded it a second time (BrollyZap-w0i).
//
// THIS LINE IS THE REMOVAL CONDITION. The fallback tolerates input that is
// malformed by specification, which is defensible only while a real client
// needs it — and leniency added with no signal for its own removal becomes
// permanent by default. When this line stops appearing, the workaround in
// lnurl.decodeDoubleEncoded goes. Reviewed 2026-10-01.
//
// INFO AND ONCE PER PROCESS, which is the shape that makes that sentence true.
// It was DEBUG, for logRelayDrops' reason — a callback is free, so a stranger
// choosing how fast this node writes to its own log is a real concern. But
// LOG_LEVEL defaults to info, so a DEBUG line is one a default deployment never
// emits, and "we stopped seeing it" would have been the default state rather
// than evidence of anything. A workaround whose removal signal cannot fire is
// exactly the permanent-by-default outcome this is meant to prevent.
//
// sync.Once is what buys the level back: one line per process lifetime is not a
// volume a stranger can drive, and a restart re-arms it — so each release
// re-tests whether anything still needs the workaround, which is the granularity
// the removal review actually wants.
//
// The client tag is the payload worth having: it names WHOSE encoder is wrong,
// which is the question the upstream report has to answer. An empty value simply
// says the request carried no such tag.
// rescueNotice is exported to the test through this package's own test file
// rather than repeated there: a removal signal asserted against a re-typed copy
// of its own message is one a reworded sentence silently switches off.
const rescueNotice = "a zap request parsed only after a second percent-decode; " +
	"the client encoded the nostr parameter twice"

func (g *callbackGate) noteDoubleEncodingRescue(zap lnurl.ZapParam) {
	client, rescued := zap.DoubleEncodingRescue()
	if !rescued {
		return
	}
	g.rescueOnce.Do(func() {
		g.log.Info(rescueNotice, "client", client)
	})
}

// logRelayDrops is zmn's second line: what the RELAYS TAG lost at the parse.
//
// The pool logs what it dropped at publish time, and that is the other half —
// "unresolvable" and "resolves to a private address" are facts only the pool
// learns. But by then the list has already been filtered and capped here, so
// the pool's `named` is what survived this function, not what the sender wrote.
// This is the first answer to "why fewer relays than the sender named", and
// without it that number simply never appears anywhere.
//
// DEBUG, not INFO, and that is the whole reason it is a separate line rather
// than a richer version of the pool's. A publish happens only on settlement,
// which a stranger cannot cause without paying; a CALLBACK is free and a
// stranger can drive it at the backstop rate, so an INFO line here is a stranger
// choosing how fast this node writes to its own log. §12 makes LOG_LEVEL
// changeable without a restart, so an operator diagnosing a delivery problem
// turns it on and asks again.
func logRelayDrops(log *slog.Logger, zap lnurl.ZapParam) {
	drops, isZap := zap.RelayDrops()
	if !isZap {
		return
	}
	// Logged even when nothing was dropped: "no line" would otherwise mean both
	// "no relay was lost" and "no zap request arrived", and an operator reading
	// for an absence cannot tell those apart.
	log.Debug("zap request relays filtered at the parse",
		"named", drops.Named,
		"kept", drops.Named-drops.Dropped(),
		"literal_private", drops.LiteralPrivate,
		"over_cap", drops.OverCap,
		"bad_scheme", drops.BadScheme,
		"duplicate", drops.Duplicate)
}

// underInvoiceCap reports whether another invoice may be minted.
//
// A counting failure falls back to the LAST SUCCESSFUL count, and only allows
// the request when there has never been one. Failing open outright was the
// obvious reading of §11 — receiving is never the dangerous operation, and
// refusing every zap because sqlite hiccupped turns a local fault into an
// outage of the thing this app exists to do. But the store runs on one
// connection shared with the invoice stream, so the likeliest cause of a count
// failing is contention under load, which is exactly the condition the cap
// exists to bound: failing open would remove the control at the only moment it
// matters. The last known value keeps the verdict roughly right through a blip
// while still letting a cold start serve.
func (g *callbackGate) underInvoiceCap(ctx context.Context) bool {
	open, err := g.invoices.CountOpenInvoices(ctx, g.now())

	g.countMu.Lock()
	defer g.countMu.Unlock()
	if err != nil {
		if !g.counted {
			g.log.Error("could not count open invoices, and there is no earlier count "+
				"to fall back on; allowing the callback", "error", err.Error())
			return true
		}
		g.log.Error("could not count open invoices; using the last known count",
			"error", err.Error(), "last_open", g.lastCount)
		return g.lastCount < g.cap
	}
	g.lastCount, g.counted = open, true
	return open < g.cap
}

// refuse answers a rate-limited callback AND says so in the log (`q22`).
//
// All three limits used to answer 429 with a reason and vanish, so a refused zap
// was invisible to the operator while being explained to the stranger. A line
// saying "a callback was refused" with no reason would repeat that defect one
// level up, so this carries WHICH limit fired — the three have three different
// remedies, and a single undifferentiated line cannot tell an operator which one
// they are looking at, nor a reader of this code which one is unreachable.
//
// `key` is the sender's nostr pubkey on the per-sender path and empty on the
// other two. Truncated through logging.Short, which is §12's rule for
// identifiers.
//
// The ZAP REQUEST BYTES ARE NOT HERE and must not be: it is a stranger's signed
// event, up to MaxZapRequestBytes, and the reason plus the sender key is what
// diagnoses this.
//
// DEBUG, like the other two lines this bead added: these paths are reachable by
// anyone, so an INFO line on them is a log-flood vector.
func (g *callbackGate) refuse(w http.ResponseWriter, r *http.Request, limit, reason, key string) {
	attrs := []any{"limit", limit, "reason", reason,
		"name", r.PathValue("name"), "amount", r.URL.Query().Get("amount")}
	if key != "" {
		attrs = append(attrs, "sender", logging.Short(key))
	}
	g.log.Debug("rate-limited an LNURL callback", attrs...)
	writeLNURLError(w, http.StatusTooManyRequests, reason)
}
