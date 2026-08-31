package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nwc"
	"github.com/davotoula/brollyzapper/internal/preflight"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/wallet"
	"github.com/davotoula/brollyzapper/internal/web"
)

// The admin group's rate limits (spec §7). CONSTANTS, not settings, and not
// defaults either — there is no key that moves them.
//
// An operator has no legitimate reason to raise their own brute-force ceiling,
// and until this wave one unlabelled settings pair moved these and the public
// limits together: raising the public ceiling so zaps stopped bouncing raised
// the login ceiling by the same amount, silently (d46.27). Splitting the pair
// and leaving the admin side adjustable would have kept the footgun and added
// a label to it.
//
// 30/minute is roughly a password a second for half a minute, which no operator
// reaches and no attacker finds useful. The public callback's limits are in
// publiclimit.go, where the three layers are.
const (
	AdminPerMinute = 30
	AdminPerHour   = 600
)

// Wallet is the slice of the wallet the admin UI needs.
//
// Note what is absent: Reserve, Settle and Reverse. The admin UI never spends,
// so it is never handed the ability to. §3's Spender seam only means anything
// if consumers ask for the narrowest thing that does their job — which is why
// the implementation is unexported and this interface is declared here, by the
// consumer, rather than imported from wallet.
type Wallet interface {
	Balance(ctx context.Context) (int64, error)
	Allocate(ctx context.Context, amountMsat int64, note string) error
	Deallocate(ctx context.Context, amountMsat int64, note string) error
	CreditReceived(ctx context.Context) (bool, error)
	SetCreditReceived(ctx context.Context, credit bool) error
	// Unresolvable is every pending payment the RESOLVER has given up on, and
	// AssertOutcome is the operator saying what became of one (`669`).
	//
	// Note what is still absent: Settle and Reverse. This is not a way for the
	// admin UI to close any payment it likes — the wallet re-checks, inside the
	// transaction that closes the row, that the resolver named it. §6 says only
	// the operator can say whether such a payment settled; it does not say they
	// may say it about a row the app is still working on.
	Unresolvable(ctx context.Context) ([]store.UnresolvablePayment, error)
	AssertOutcome(ctx context.Context, id wallet.ReservationID, settled bool) error
}

// NWCHealth reports what the NWC service currently knows about each pairing's
// relay session (d24.21). Declared here because this is the consumer (§3).
//
// One method, and it hands back a snapshot rather than a live view: this is read
// on an HTTP goroutine while connection goroutines write it.
type NWCHealth interface {
	Health() map[int64]nwc.ConnectionHealth
}

// Connections is what §9 item 4's page does to pairings, declared here because
// this is the consumer (§3).
//
// Note what is absent: nothing that reads a connection's secrets for any purpose
// but rendering its pairing URI, and no way to change a stored key.
type Connections interface {
	AllNWCConnections(ctx context.Context) ([]store.NWCConnection, error)
	CreateNWCConnection(ctx context.Context, conn store.NWCConnection, limits store.LimitPolicy) (store.NWCConnection, error)
	// UpdateNWCConnectionLimits changes a live pairing's groups and limits
	// (d24.17). It reports whether a row changed, so the page never claims a
	// change it did not make.
	UpdateNWCConnectionLimits(ctx context.Context, id int64, permissions []string,
		budgetMsat, maxPaymentMsat *int64, limits store.LimitPolicy,
		now time.Time) (store.NWCConnection, bool, error)
	RevokeNWCConnection(ctx context.Context, id int64) (bool, error)
	// ResumeNWCConnection undoes Fix C's quarantine (`xmc`): the app paused a
	// pairing whose requests kept crashing the handler, and this is the
	// operator's way back that does not cost them a re-pairing.
	ResumeNWCConnection(ctx context.Context, id int64) (bool, error)
	CountPayingNWCConnections(ctx context.Context) (int, error)
}

// SpendGuard is the guard operations §9 item 3's page drives.
//
// Bake, revoke and the operator's ceremony, and nothing else: the page that can
// enable sending must not be able to ask for a receive macaroon or read the
// guard's state beyond what Broker already exposes.
//
// THE CEREMONY IS HERE AND NOT ON Broker (`06v`), and the split is the same one
// that has always divided these two: Broker is the READ half and this is the
// WRITE half. Asking for an authorisation and redeeming one both change what the
// guard will do next, so they belong with bake and revoke — and keeping them off
// the read interface means the pages that only display state cannot start a
// ceremony as a side effect of rendering.
//
// NOTE WHAT IS STILL ABSENT: nothing here returns a code, and nothing here says
// whether a change is a loosening. Both are the guard's, and a method that
// handed either back to this container would end the property the ceremony
// exists for.
type SpendGuard interface {
	RequestSpendBake(ctx context.Context) error
	RequestSpendRevoke(ctx context.Context) error
	// RequestAuthorisation asks the guard to write a one-time grant where only
	// the operator can read it.
	RequestAuthorisation(ctx context.Context, change guard.Change) error
	// ApplyChange moves one operator control, relaying the operator's code. The
	// server passes what it has and the guard decides whether that was enough.
	ApplyChange(ctx context.Context, change guard.Change, code string) error
}

// History is the slice of the store the Wallet page's transaction list needs.
//
// Note what is absent: it reads txns and cannot write one, and it never touches
// balance_entries — §5 keeps the balance behind wallet.Spender, and a page that
// could reach the ledger directly would be a second answer to what the balance
// is.
type History interface {
	RecentTxns(ctx context.Context, limit int) ([]store.Txn, error)
	TxnCount(ctx context.Context) (int64, error)
}

// AuditLog is the §12 trail, for the Security page.
type AuditLog interface {
	AuditEvents(ctx context.Context, limit int) ([]logging.AuditEvent, error)
}

// ServerOptions is the wiring. Everything the HTTP layer touches arrives here,
// so cmd/brollyzapper is the only place that knows the concrete types.
type ServerOptions struct {
	Auth *Auth
	// Auditor writes a security event to the log AND to the durable trail.
	// §12: alongside the log line, never instead of it — log rotation must not
	// be able to erase the answer to "when did sending get enabled, and by
	// whom?".
	Auditor   *logging.Auditor
	Wallet    Wallet
	NodeState func() lnd.State
	Broker    *CachedBroker
	Audit     AuditLog
	Settings  SettingsStore
	// AllSettings reads the whole settings table at once, for the page renders
	// that need most of it.
	AllSettings AllSettings
	Renderer    *web.Renderer
	ProbeToken  string
	ProbeDemand chan<- struct{}
	// NWCDemand asks the NWC service to reload its connections (uhg). Creating,
	// revoking or re-permissioning a pairing has to take effect now: a
	// revocation that waited for a restart would be a revocation that did
	// nothing, and it is the operator's kill switch for one app.
	NWCDemand chan<- struct{}
	// Connections is the store slice §9 item 4's page needs.
	Connections Connections
	// NWCHealth is the running NWC service, asked whether each pairing can
	// currently reach its relay (d24.21).
	//
	// NIL IS VALID and means "nobody knows", which the page renders as exactly
	// that: the state lives in the service's memory, so a build without one — or
	// the second before the first reload lands after a restart — genuinely has
	// no answer. Claiming either one would be worse than saying so.
	NWCHealth NWCHealth
	// Guard bakes and revokes the spend macaroon for §9 item 3's page. Its own
	// field rather than reusing Broker, because this is the WRITE half — the
	// page that can turn spending on is the one surface that needs it.
	Guard SpendGuard
	// ReconDemand asks for an out-of-schedule reconciliation. A ceiling change
	// invalidates recon's verdict immediately, and waiting out the five-minute
	// interval left the Security page showing a confident green tick for a
	// shortfall that already existed (§5, §11, d46.21).
	ReconDemand chan<- struct{}
	// Level is the running log level. §12 requires LOG_LEVEL to change without
	// a restart, which means the Settings handler needs the LevelVar itself and
	// not just the settings row.
	Level *slog.LevelVar
	// LNURL serves §7's public endpoints, as two handlers rather than one
	// mux: the public route set is a security boundary asserted by equality,
	// and a handler that mounted routes of its own behind a prefix would put
	// them beyond the assertion's reach.
	LNURL LNURLRoutes
	// Preflight is §11's checks, computed fresh. The degraded banner and the
	// Security panel are two renderings of this one report: two independent
	// answers to "is this instance healthy" drift apart, and the failure mode
	// is one page saying the node is reachable while another shows a re-link
	// banner (§11, d46.10 criterion 10).
	Preflight func(ctx context.Context) preflight.Report
	// RetryNow asks the node connection to stop waiting out its reconnect
	// backoff and try again immediately. §6's backoff is right for a node that
	// is not answering and wrong for a credential the operator has just
	// replaced — without this, Re-link appears to do nothing for up to a
	// minute (d46.20).
	RetryNow func()
	// Ready backs /health.
	Ready func() bool
	// TrustedProxies is the environment's TRUSTED_PROXIES, parsed. §7 mirrors
	// it into settings, and the settings value wins once the operator sets one.
	//
	// The prefixes rather than a predicate over them, because the admin
	// limiter needs to answer a second question the predicate cannot: whether
	// ANY proxy is declared at all. With none, every request behind a proxy
	// arrives from the proxy's own address and the whole box shares one
	// bucket, which the 429 has to be able to say (d46.19). A predicate plus a
	// separate "is one configured" flag would be two statements of one fact.
	TrustedProxies []netip.Prefix
	// Invoices backs §7's open-invoice cap on the public callback.
	Invoices Invoices
	// History backs §9 item 2's transaction history. Optional: a build without
	// one renders the Wallet page without the section rather than not at all.
	History History
	Log     *slog.Logger
	Now     func() time.Time
}

// Server is the composed HTTP surface. It is an http.Handler, plus the few
// pieces of live state a caller legitimately needs to ask about.
type Server struct {
	handler http.Handler
	ServerOptions
	settings *settingsCache

	// trustMu guards the memoised parse of settings.trusted_proxies, so an
	// edited CIDR list is parsed once rather than per request.
	// trustRaw is "" until a settings value has been parsed, which is why no
	// separate parsed flag is needed: trustedPrefixes returns early when the
	// setting is empty, so a stored trustRaw is always a real one.
	trustMu       sync.Mutex
	trustRaw      string
	trustPrefixes []netip.Prefix
}

// ServeHTTP routes a request to the public or the admin group.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// TrustsProxyNow reports whether an address is currently believed as a proxy,
// which is the settings value when the operator has set one and the
// environment's TRUSTED_PROXIES otherwise (§7).
func (s *Server) TrustsProxyNow(addr netip.Addr) bool {
	return config.TrustsProxyIn(s.trustedPrefixes(), addr)
}

// ProxiesDeclared reports whether any trusted proxy is configured, so §11's
// Security panel can name the shared-admin-bucket blind spot (d46.19). It reads
// the same list the limiter's decision reads, so the panel and the behaviour
// cannot disagree.
func (s *Server) ProxiesDeclared() bool { return len(s.trustedPrefixes()) > 0 }

// clientIP derives the caller's address, resolving the trusted-proxy list ONCE.
//
// ClientIP consults the predicate for the peer and again for every
// X-Forwarded-For hop, and each consultation used to re-read the settings
// snapshot and take two mutexes. On the admin path that ran four to six times
// per request for a value that cannot change mid-request.
func (s *Server) clientIP(r *http.Request) netip.Addr {
	prefixes := s.trustedPrefixes()
	return ClientIP(r, func(addr netip.Addr) bool {
		return config.TrustsProxyIn(prefixes, addr)
	})
}

// NewServer composes the two route groups.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Auth == nil || opts.Renderer == nil {
		return nil, errors.New("api: the server needs auth and a renderer")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Log == nil {
		opts.Log = logging.Default()
	}
	if opts.Ready == nil {
		opts.Ready = func() bool { return true }
	}
	if opts.LNURL == nil {
		opts.LNURL = unavailableLNURL("LNURL endpoints arrive with zap receiving")
	}
	if opts.Auditor == nil {
		return nil, errors.New("api: the server needs an auditor; §12 requires the durable trail")
	}
	// Required, not nil-tolerant like the optional hooks above: the
	// open-invoice cap is the public callback's real resource bound (§7), and a
	// nil counter would silently mean "no cap" — a security control that is
	// absent rather than failing is the shape nobody notices.
	if opts.Invoices == nil {
		return nil, errors.New("api: the server needs an invoice counter for §7's open-invoice cap")
	}
	s := &Server{
		ServerOptions: opts,
		settings:      newSettingsCache(opts.AllSettings, settingsCacheTTL, opts.Now),
	}

	// The public group. It is handed a health handler and an LNURL handler and
	// nothing else — no Auth, no session store — so there is no auth path here
	// to skip rather than auth that happens to pass (§11).
	gate := &callbackGate{
		globalBackstop: NewLimiter(s.publicLimits(), KeyGlobal, opts.Now),
		perSender:      NewCallerKeyedLimiter(FixedLimits(PerSenderPerMinute, PerSenderPerHour), opts.Now),
		invoices:       opts.Invoices,
		cap:            OpenInvoiceCap,
		now:            opts.Now,
		log:            opts.Log,
	}
	payRequest, callback := opts.LNURL.Handlers()
	public := NewPublicMux(
		HealthHandler(opts.Ready),
		// The lnurlp DOCUMENT is deliberately NOT rate-limited (§7, ruled 22
		// Aug 2026). It is static JSON per address_name, it mints nothing, and
		// limiting it made one zap cost two of the instance's requests — which
		// put the worldwide ceiling at about five zaps a minute.
		//
		// §9's self-probe depends on this. The probe fetches this path over the
		// public internet to check the operator's own domain reaches this
		// instance; if it could be rate-limited, a stranger consuming the
		// bucket would make the Security page report the operator's address
		// unreachable — a false diagnosis wearing a measurement's clothes. It
		// is exempt by construction, which is why there is no probe bypass
		// anywhere in the limiter: a bypass would have to key on the
		// X-BrollyZapper-Probe token, and that token is stamped on every
		// response here, so any caller who ever fetched this address knows it.
		WithProbeToken(opts.ProbeToken, payRequest),
		// The callback is the one that mints, so it is the one that is limited.
		// The token is stamped OUTSIDE the gate so a refusal still carries it
		// and the prober can tell "us, refusing" from "somebody else answering".
		WithProbeToken(opts.ProbeToken, gate.Middleware(callback)),
	)

	admin := NewAdminMux()
	adminLimiter := NewLimiter(FixedLimits(AdminPerMinute, AdminPerHour),
		func(r *http.Request) string { return s.clientIP(r).String() }, opts.Now)
	admin.Handle("/static/", web.StaticHandler())
	admin.Handle("/login", adminLimiter.Middleware(s.refuseAdmin, http.HandlerFunc(s.login)))
	admin.Handle("/", opts.Auth.RequireSession(s.pages()))

	s.handler = Compose(public, admin)
	return s, nil
}

// pages is the authenticated surface.
func (s *Server) pages() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.wallet)
	mux.HandleFunc("GET /setup", s.setup)
	mux.HandleFunc("GET /sending", s.sendingPage)
	mux.HandleFunc("GET /connections", s.connectionsPage)
	mux.HandleFunc("GET /node", s.node)
	mux.HandleFunc("GET /security", s.security)
	mux.HandleFunc("GET /settings", s.settingsPage)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("POST /wallet/allocate", s.allocate)
	mux.HandleFunc("POST /wallet/deallocate", s.deallocate)
	mux.HandleFunc("POST /wallet/assert", s.assertPaymentOutcome)
	mux.HandleFunc("POST /settings", s.saveSettings)
	mux.HandleFunc("POST /settings/probe", s.probeNow)
	mux.HandleFunc("POST /settings/password", s.changePassword)
	mux.HandleFunc("POST /settings/nostr", s.importNostrKey)
	mux.HandleFunc("POST /node/relink", s.relink)
	mux.HandleFunc("POST /sending/enable", s.enableSending)
	mux.HandleFunc("POST /sending/disable", s.disableSending)
	mux.HandleFunc("POST /sending/caps", s.changeSpendCap)
	mux.HandleFunc("POST /connections/create", s.createConnection)
	mux.HandleFunc("POST /connections/update", s.updateConnection)
	mux.HandleFunc("POST /connections/revoke", s.revokeConnection)
	mux.HandleFunc("POST /connections/resume", s.resumeConnection)
	return mux
}

// publicLimits reads the operator's globalBackstop limits, falling back to §7's
// defaults. It is the PUBLIC pair and nothing else: the admin limiter takes
// FixedLimits(AdminPerMinute, AdminPerHour) and never reads a setting, which is
// what stops the two moving together again (d46.27).
func (s *Server) publicLimits() Limits {
	return func() (int, int) {
		values := s.settings.snapshot(context.Background())
		return int(values.int(SettingPublicRateLimitMinute, DefaultGlobalBackstopPerMinute)),
			int(values.int(SettingPublicRateLimitHour, DefaultGlobalBackstopPerHour))
	}
}

// refuseAdmin renders an admin 429.
//
// It says whether the bucket is shared, because whether it is depends on the
// deployment and the operator cannot see which case they are in. With no
// trusted proxy declared, every request behind one arrives from the proxy's own
// address, so "30 a minute per operator" is really 30 a minute for the whole
// box — and an operator locked out by their own browser tabs would otherwise
// have nothing to go on (d46.19). The Umbrel package sets TRUSTED_PROXIES, so
// this is the off-Umbrel case §19 requires to work.
func (s *Server) refuseAdmin(w http.ResponseWriter, _ *http.Request) {
	message := fmt.Sprintf("Too many requests — this instance allows %d sign-in requests a "+
		"minute per client address.", AdminPerMinute)
	if !s.ProxiesDeclared() {
		// The same sentence §11's Security panel shows, from the same constant:
		// the panel and the refusal are one claim, and an operator who is
		// already locked out should not be reading two versions of it.
		message += "\n\n" + preflight.SharedAdminBucket
	}
	http.Error(w, message, http.StatusTooManyRequests)
}

// trusts reports whether an address is a proxy whose forwarded-for header may
// be believed.
//
// §7 mirrors TRUSTED_PROXIES into settings.trusted_proxies, so an operator who
// adds their tunnel's ranges in Settings must actually change the decision —
// otherwise the field is decorative on a value that gates a security boundary.
// An unparseable setting falls back to the environment rather than to trusting
// nothing or everything.
// trustedPrefixes is the proxy list in force: settings.trusted_proxies when the
// operator has set one, TRUSTED_PROXIES otherwise.
//
// §7 mirrors the environment variable into settings, so an operator who adds
// their tunnel's ranges in Settings must actually change the decision —
// otherwise the field is decorative on a value that gates a security boundary.
// An unparseable setting falls back to the environment rather than to trusting
// nothing or everything. The parse is memoised, so an edited CIDR list is
// parsed once rather than per request.
func (s *Server) trustedPrefixes() []netip.Prefix {
	raw := strings.TrimSpace(s.settings.snapshot(context.Background()).get(SettingTrustedProxies))
	if raw == "" {
		return s.TrustedProxies
	}
	s.trustMu.Lock()
	defer s.trustMu.Unlock()
	if s.trustRaw != raw {
		prefixes, err := config.ParsePrefixList(raw)
		if err != nil {
			s.Log.Warn("settings.trusted_proxies is not a CIDR list; using TRUSTED_PROXIES instead",
				"error", err.Error())
			return s.TrustedProxies
		}
		s.trustRaw, s.trustPrefixes = raw, prefixes
	}
	return s.trustPrefixes
}

// audit records a security event in both places §12 requires. A failed trail
// write is logged and swallowed: losing the row must not also lose the request.
func (s *Server) audit(ctx context.Context, level slog.Level, msg string, event logging.Event, attrs ...slog.Attr) {
	if err := s.Auditor.Record(ctx, level, msg, event, attrs...); err != nil {
		s.Log.Error("could not write the audit trail", "event", string(event), "error", err.Error())
	}
}

// nudge asks for out-of-schedule work without blocking. A full channel means
// one is already queued, which answers the same question.
func nudge(ch chan<- struct{}) {
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

// retryNow asks the node connection to stop waiting out its backoff, if one is
// wired. Nil-tolerant like every other optional hook here.
func (s *Server) retryNow() {
	if s.RetryNow != nil {
		s.RetryNow()
	}
}

// auditRequest records a security event raised by an HTTP request, attaching
// the caller's address.
//
// Every handler-raised event goes through this rather than passing "remote" by
// hand. The key is what logging.Auditor matches on to fill audit_events.remote,
// so a handler that forgets it, or spells it differently, produces a row with
// no source address — which is exactly the attribution gap d46.23 was raised to
// close, reopened one handler at a time.
func (s *Server) auditRequest(r *http.Request, level slog.Level, msg string,
	event logging.Event, attrs ...slog.Attr) {
	attrs = append(attrs, slog.String("remote", s.clientIP(r).String()))
	// Deliberately not the request's context: the event describes something
	// that has already happened, and a browser that disconnects mid-redirect
	// must not be able to drop the row.
	s.audit(context.WithoutCancel(r.Context()), level, msg, event, attrs...)
}

// checks runs §11's preflight, or reports nothing when none is wired.
func (s *Server) checks(ctx context.Context) preflight.Report {
	if s.Preflight == nil {
		return preflight.Report{BlindSpots: preflight.BlindSpots}
	}
	return s.Preflight(ctx)
}

// degraded is one rendering of the preflight report: the failed checks, in the
// words an operator can act on. It computes nothing of its own, which is what
// stops it disagreeing with the Security panel.
func degraded(report preflight.Report) []string {
	var missing []string
	for _, c := range report.Failed() {
		if c.Detail == "" {
			missing = append(missing, c.Title)
			continue
		}
		missing = append(missing, c.Detail)
	}
	return missing
}

// page builds the common part of every render, and returns the settings
// snapshot with it so a handler never re-reads what another part just read.
// page builds the common part of every render. It returns the settings
// snapshot and the preflight report with it, because both are computed here and
// a handler that asked again would be doing the work twice — and, on the
// Security page, rendering a second answer to the question this report exists to
// answer exactly once.
func (s *Server) page(ctx context.Context, title string) (web.PageData, settingsSnapshot, preflight.Report) {
	values := s.settings.snapshot(ctx)
	report := s.checks(ctx)
	data := web.PageData{Title: title, Degraded: degraded(report)}
	if session, ok := SessionFrom(ctx); ok {
		data.CSRFToken = session.CSRFToken
	}
	return data, values, report
}

func (s *Server) render(w http.ResponseWriter, page string, data web.PageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.Renderer.Render(w, page, data); err != nil {
		s.Log.Error("rendering failed", "page", page, "error", err.Error())
		http.Error(w, "the page could not be rendered", http.StatusInternalServerError)
	}
}

// notYetHandler answers a route that exists structurally but whose
// implementation lands in a later phase. The route has to exist now because the
// public route set is a security boundary, asserted for equality.
func notYetHandler(what string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"status":"ERROR","reason":%q}`, what)
	})
}
