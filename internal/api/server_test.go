package api_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/preflight"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/wallet"
	"github.com/davotoula/brollyzapper/internal/web"
)

type harness struct {
	handler   http.Handler
	auth      *api.Auth
	store     *store.Store
	broker    *lndtest.Broker
	level     *slog.LevelVar
	server    *api.Server
	report    preflight.Report
	reports   int
	nodeState lnd.State
}

// clientIPFor asks the running server which address it would attribute a
// request to, through the same predicate the rate limiter keys on.
func (h *harness) clientIPFor(t *testing.T, remote, forwarded string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/lnurlp/bob", nil)
	r.RemoteAddr = remote
	r.Header.Set("X-Forwarded-For", forwarded)
	return api.ClientIP(r, h.server.TrustsProxyNow).String()
}

// newHarness builds the server every test in this package uses. Overrides are
// applied last and are handed the store, so a test can replace one dependency
// with a real one without standing up a second NewServer call site that drifts
// as ServerOptions grows.
func newHarness(t *testing.T, overrides ...func(*api.ServerOptions, *store.Store)) *harness {
	t.Helper()
	db := newTestStore(t)
	auth, err := api.NewAuth(t.Context(), db, api.AuthOptions{
		AppPassword:   secret.New("umbrel-derived-password"),
		SessionSecret: secret.New("0123456789abcdef0123456789abcdef"),
		Now:           func() time.Time { return authTime },
	})
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	renderer, err := web.New("test")
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	level := logging.NewLevelVar(slog.LevelInfo)
	h := &harness{auth: auth, store: db, broker: &lndtest.Broker{}, level: level, nodeState: lnd.StateReady}

	opts := api.ServerOptions{
		Auth:        auth,
		Auditor:     logging.NewAuditor(logging.New(io.Discard, level), db),
		Wallet:      wallet.New(db, wallet.Options{Now: func() time.Time { return authTime }}),
		NodeState:   func() lnd.State { return h.nodeState },
		Broker:      api.NewCachedBroker(h.broker, api.NodeStatusTTL, func() time.Time { return authTime }),
		Audit:       db,
		Settings:    db,
		Renderer:    renderer,
		AllSettings: db,
		Level:       level,
		ProbeToken:  "probe-token",
		Ready:       func() bool { return true },
		Invoices:    db,
		History:     db,
		Preflight: func(context.Context) preflight.Report {
			h.reports++
			return h.report
		},
		Now: func() time.Time { return authTime },
	}
	for _, override := range overrides {
		override(&opts, db)
	}
	handler, err := api.NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	h.handler = handler
	h.server = handler
	return h
}

// login returns a request cookie for an authenticated session. It goes through
// the same cookie-carrying browser every other login test uses, so there is one
// definition of "how a client logs in" rather than two that can drift.
func (h *harness) login(t *testing.T) *http.Cookie {
	t.Helper()
	b := h.browser()
	rec := b.submitLogin(t, csrfFrom(t, b.get(t, "/login").Body.String()), "umbrel-derived-password")
	if cookie, ok := b.cookies[api.SessionCookieName]; ok && cookie.Value != "" {
		return cookie
	}
	t.Fatalf("login did not issue a session: %d %s", rec.Code, rec.Body)
	return nil
}

func (h *harness) get(t *testing.T, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)
	return rec
}

func csrfFrom(t *testing.T, body string) string {
	t.Helper()
	const marker = `name="csrf_token" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no CSRF token in the rendered page: %s", body)
	}
	rest := body[i+len(marker):]
	return rest[:strings.Index(rest, `"`)]
}

func TestAdminPagesRequireASessionAndThenRender(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/", "/sending", "/connections", "/node", "/security", "/settings", "/setup"} {
		if got := h.get(t, path, nil); got.Code != http.StatusSeeOther {
			t.Errorf("GET %s unauthenticated = %d, want a redirect to /login", path, got.Code)
		}
	}
	cookie := h.login(t)
	for _, path := range []string{"/", "/sending", "/connections", "/node", "/security", "/settings", "/setup"} {
		got := h.get(t, path, cookie)
		if got.Code != http.StatusOK {
			t.Errorf("GET %s authenticated = %d, want 200", path, got.Code)
		}
		if !strings.Contains(got.Body.String(), "<!doctype html>") {
			t.Errorf("GET %s did not render a page", path)
		}
	}
}

// Criterion 8: the process survives every dependency being absent and serves a
// degraded admin UI that says WHICH one is missing.
func TestTheAdminUIDegradesAndNamesWhatIsMissing(t *testing.T) {
	h := newHarness(t)
	h.nodeState = lnd.StateNotLinked
	h.broker.SetError(errors.New("dialling /credentials/guard.sock: no such file or directory"))

	cookie := h.login(t)
	body := h.get(t, "/node", cookie).Body.String()
	lower := strings.ToLower(body)
	for _, expected := range []string{"guard", "node"} {
		if !strings.Contains(lower, expected) {
			t.Errorf("the degraded page does not mention %q: %s", expected, body)
		}
	}
	if strings.Contains(lower, "panic") || strings.Contains(lower, "no such file or directory\n") {
		t.Error("the page leaked a raw error rather than explaining the state")
	}
}

func TestWalletAllocationGoesThroughTheFormAndMovesTheCeiling(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	page := h.get(t, "/", cookie)
	token := csrfFrom(t, page.Body.String())
	form := url.Values{"sats": {"1000"}, "note": {"first allocation"}, "csrf_token": {token}}
	post := httptest.NewRequest(http.MethodPost, "/wallet/allocate", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, post)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("allocate = %d, want a redirect after the POST (%s)", rec.Code, rec.Body)
	}
	balance, err := h.store.BalanceMsat(t.Context())
	if err != nil {
		t.Fatalf("BalanceMsat: %v", err)
	}
	if balance != 1_000_000 {
		t.Errorf("balance = %d msat, want 1000000 — the form takes sats", balance)
	}
}

func TestTheSecurityPageShowsTheAuditTrail(t *testing.T) {
	h := newHarness(t)
	err := h.store.AppendAuditEvent(t.Context(), logging.AuditEvent{
		Event: logging.EventMacaroonBake, Severity: logging.SeverityInfo,
		Detail: `{"permissions":5}`, CreatedAt: authTime,
	})
	if err != nil {
		t.Fatalf("AppendAuditEvent: %v", err)
	}
	cookie := h.login(t)
	body := h.get(t, "/security", cookie).Body.String()
	if !strings.Contains(body, "macaroon.bake") {
		t.Errorf("the security page does not show the audit trail: %s", body)
	}
}

// The public group is reachable with no session at all — that is the point of
// it — and the admin group is not.
func TestThePublicGroupNeedsNoSession(t *testing.T) {
	h := newHarness(t)
	got := h.get(t, "/health", nil)
	if got.Code != http.StatusOK || got.Body.String() != "ok" {
		t.Errorf("/health unauthenticated = %d %q, want 200 \"ok\"", got.Code, got.Body)
	}
	if got := h.get(t, "/.well-known/lnurlp/bob", nil); got.Code == http.StatusSeeOther {
		t.Error("an LNURL request was redirected to /login; the public group has no auth")
	}
}

// The per-boot probe token reaches the wire on LNURL responses even before P2
// lands the real handler, so the self-probe can recognise this instance.
func TestLNURLResponsesCarryTheProbeToken(t *testing.T) {
	h := newHarness(t)
	got := h.get(t, "/.well-known/lnurlp/bob", nil)
	if got.Header().Get(api.ProbeHeader) != "probe-token" {
		t.Errorf("%s = %q, want the per-boot token", api.ProbeHeader, got.Header().Get(api.ProbeHeader))
	}
}

// The login page has to hand out a CSRF token before anyone is logged in. That
// token must not itself be a session: if merely fetching /login authenticated
// the caller, the password would be decorative.
func TestFetchingTheLoginPageDoesNotAuthenticate(t *testing.T) {
	h := newHarness(t)
	rec := h.get(t, "/login", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login = %d, want 200", rec.Code)
	}
	for _, cookie := range rec.Result().Cookies() {
		got := h.get(t, "/", cookie)
		if got.Code == http.StatusOK {
			t.Errorf("the cookie %q handed out by GET /login authenticated an admin page",
				cookie.Name)
		}
	}
}

// §9: CSRF on every mutating form — and login is a mutating form. Without it,
// a third-party page can log the operator into an account of its choosing.
func TestLoginItselfRequiresACSRFToken(t *testing.T) {
	h := newHarness(t)
	form := url.Values{"password": {"umbrel-derived-password"}}
	post := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, post)

	if rec.Code == http.StatusSeeOther {
		t.Fatal("a login POST with no CSRF token succeeded")
	}
	if sessionIssued(rec) {
		t.Error("a login POST with no CSRF token issued a session")
	}
}

// postForm submits an authenticated form and returns the response.
func (h *harness) postForm(t *testing.T, path string, cookie *http.Cookie, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	page := h.get(t, "/settings", cookie)
	values.Set("csrf_token", csrfFrom(t, page.Body.String()))
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)
	return rec
}

// Every field the Settings form renders must also be saved. A field that is
// displayed and then silently discarded is worse than a missing one: it looks
// like it worked.
func TestEverySettingsFieldRoundTrips(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	// The fields are read OFF THE RENDERED PAGE rather than listed here. A
	// hand-kept list is the shape the code's own comment warns about — "a key
	// in one list and not the other is a field that silently discards what the
	// operator typed" — and a hand-kept list in the test cannot catch it,
	// because it is the same hand keeping both.
	form := h.get(t, "/settings", cookie).Body.String()
	fields := formFieldNames(form)
	if len(fields) == 0 {
		t.Fatal("no named fields in the settings form; the test is asserting over nothing")
	}

	submitted := url.Values{}
	want := map[string]string{}
	for _, name := range fields {
		value := valueFor(name)
		submitted.Set(name, value)
		want[name] = value
	}
	if got := h.postForm(t, "/settings", cookie, submitted); got.Code != http.StatusSeeOther {
		t.Fatalf("saving settings = %d, want a redirect (%s)", got.Code, got.Body)
	}

	for key, value := range want {
		got, ok, err := h.store.Setting(t.Context(), key)
		if err != nil || !ok {
			t.Errorf("%s is on the form and was not saved at all (ok=%v err=%v)", key, ok, err)
			continue
		}
		if got != value {
			t.Errorf("%s = %q, want %q", key, got, value)
		}
	}

	// ...and the form shows them back.
	body := h.get(t, "/settings", cookie).Body.String()
	for key, value := range want {
		if !strings.Contains(body, value) {
			t.Errorf("the settings form does not show %s (%q) back", key, value)
		}
	}
}

// formFieldNames pulls the inputs out of the settings form ITSELF — the element
// posting to /settings — so the password and nostr-key forms elsewhere on the
// page, and the layout's own <meta name=…>, cannot leak in. Only csrf_token and
// credit_received are excluded by name, and both are genuinely in this form
// while not being settings rows.
func formFieldNames(page string) []string {
	const marker = `<form method="post" action="/settings">`
	start := strings.Index(page, marker)
	if start < 0 {
		return nil
	}
	body := page[start:]
	body = body[:strings.Index(body, "</form>")]

	notSettings := map[string]bool{"csrf_token": true, "credit_received": true}
	var out []string
	for _, tag := range strings.Split(body, "<")[1:] {
		if !strings.HasPrefix(tag, "input") && !strings.HasPrefix(tag, "select") &&
			!strings.HasPrefix(tag, "textarea") {
			continue
		}
		tag = tag[:strings.Index(tag, ">")]
		at := strings.Index(tag, `name="`)
		if at < 0 {
			continue
		}
		name := tag[at+len(`name="`):]
		name = name[:strings.Index(name, `"`)]
		if notSettings[name] || slices.Contains(out, name) {
			continue
		}
		out = append(out, name)
	}
	return out
}

// valueFor invents a value each field will accept: the numeric settings parse
// as integers, trusted_proxies must be a CIDR list or the save is refused, and
// log_level must be one the LevelVar understands.
func valueFor(name string) string {
	switch name {
	case api.SettingTrustedProxies:
		return "10.21.0.0/16"
	case api.SettingLogLevel:
		return "debug"
	case api.SettingPublicRateLimitMinute:
		return "7"
	case api.SettingPublicRateLimitHour:
		return "77"
	case api.SettingMaxFeePPM:
		return "25000"
	case api.SettingMaxFeeFloorMsat:
		return "5000"
	case api.SettingRelays:
		return "wss://relay.example"
	default:
		return "round-trip-" + name
	}
}

func TestChangingTheLogLevelAppliesWithoutARestart(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)
	if h.level.Level() != slog.LevelInfo {
		t.Fatalf("level starts at %v, want info", h.level.Level())
	}

	got := h.postForm(t, "/settings", cookie, url.Values{"log_level": {"debug"}})
	if got.Code != http.StatusSeeOther {
		t.Fatalf("saving = %d, want a redirect", got.Code)
	}
	if h.level.Level() != slog.LevelDebug {
		t.Errorf("the running level is %v after saving debug; §12 says it applies without a restart",
			h.level.Level())
	}
}

// §7 mirrors TRUSTED_PROXIES into settings.trusted_proxies. If the settings
// value does not change the decision, the field is decorative on a value that
// gates a security boundary.
func TestTheTrustedProxiesSettingChangesWhoIsBelieved(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	// The environment trusts nobody, so a forwarded header is ignored.
	if got := h.clientIPFor(t, "10.21.0.3:5000", "203.0.113.7"); got != "10.21.0.3" {
		t.Fatalf("client IP = %s before the setting, want the peer", got)
	}

	if got := h.postForm(t, "/settings", cookie, url.Values{"trusted_proxies": {"10.21.0.0/16"}}); got.Code != http.StatusSeeOther {
		t.Fatalf("saving = %d, want a redirect (%s)", got.Code, got.Body)
	}
	if got := h.clientIPFor(t, "10.21.0.3:5000", "203.0.113.7"); got != "203.0.113.7" {
		t.Errorf("client IP = %s after trusting 10.21.0.0/16, want the forwarded address — "+
			"the settings value did not reach the trust decision", got)
	}
}

// A CIDR list that does not parse must be refused, not stored: a silently
// ignored value leaves the operator believing they changed a boundary.
func TestAnUnparseableTrustedProxiesValueIsRefused(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)
	got := h.postForm(t, "/settings", cookie, url.Values{
		"domain": {"kept.example"}, "trusted_proxies": {"not-a-cidr"},
	})
	if got.Code != http.StatusSeeOther || !strings.Contains(got.Header().Get("Location"), "refused") {
		t.Errorf("saving a bad CIDR list = %d %q, want a refusal", got.Code, got.Header().Get("Location"))
	}
	if stored, ok, _ := h.store.Setting(t.Context(), "trusted_proxies"); ok && stored == "not-a-cidr" {
		t.Error("the unparseable value was stored anyway")
	}
	if stored, ok, _ := h.store.Setting(t.Context(), "domain"); ok && stored == "kept.example" {
		t.Error("the rest of the form was applied despite the refusal; the save is all or nothing")
	}
}

// Criterion 10: the degraded banner and the Security panel are two renderings
// of ONE report. Two independent "is this healthy" computations drift apart,
// and the failure mode is one page saying the node is reachable while another
// shows a re-link banner.
func TestTheBannerAndTheSecurityPanelCannotDisagree(t *testing.T) {
	h := newHarness(t)
	h.report = preflight.Report{
		Checks: []preflight.Check{
			{ID: "node.linked", Title: "Connected to your Lightning node", OK: false,
				Threat: "Server compromised, receive-only install", Detail: "the node rejected the macaroon"},
			{ID: "guard.reachable", Title: "The guard is answering", OK: true,
				Threat: "Server baking itself a broader macaroon"},
		},
		BlindSpots: preflight.BlindSpots,
	}
	cookie := h.login(t)

	banner := h.get(t, "/", cookie).Body.String()
	panel := h.get(t, "/security", cookie).Body.String()
	if !strings.Contains(banner, "the node rejected the macaroon") {
		t.Errorf("the degraded banner does not show the failed check: %s", banner)
	}
	if !strings.Contains(panel, "Connected to your Lightning node") {
		t.Error("the security panel does not show the failed check")
	}

	// Flip it: both must follow, because there is only one source.
	h.report.Checks[0].OK = true
	h.report.Checks[0].Detail = ""
	banner = h.get(t, "/", cookie).Body.String()
	panel = h.get(t, "/security", cookie).Body.String()
	if strings.Contains(banner, "the node rejected the macaroon") {
		t.Error("the banner still shows a check that now passes")
	}
	if !strings.Contains(panel, "Connected to your Lightning node") {
		t.Error("the panel stopped listing a check that passes; passing checks are still shown")
	}
}

// §11: the panel names its own blind spots, as a visible list.
func TestTheSecurityPanelNamesItsBlindSpots(t *testing.T) {
	h := newHarness(t)
	h.report = preflight.Report{BlindSpots: preflight.BlindSpots}
	cookie := h.login(t)
	panel := strings.ToLower(h.get(t, "/security", cookie).Body.String())

	for _, expected := range []string{"wallet password", "permissions", "other apps", "backups"} {
		if !strings.Contains(panel, expected) {
			t.Errorf("the security panel does not name the %q blind spot", expected)
		}
	}
	if !strings.Contains(panel, "manufactures confidence") {
		t.Error("the panel does not say why the limits are listed")
	}
}

// §11: every check maps to a named threat, and the page shows it — a tick with
// no threat behind it is the theatre this rule exists to prevent.
func TestTheSecurityPanelShowsTheThreatEachCheckMapsTo(t *testing.T) {
	h := newHarness(t)
	h.report = preflight.Report{
		Checks: []preflight.Check{{
			ID: "guard.reachable", Title: "The guard is answering", OK: true,
			Threat: "Server baking itself a broader macaroon",
		}},
		BlindSpots: preflight.BlindSpots,
	}
	cookie := h.login(t)
	panel := h.get(t, "/security", cookie).Body.String()
	if !strings.Contains(panel, "Server baking itself a broader macaroon") {
		t.Errorf("the panel shows a check without the threat it maps to: %s", panel)
	}
}

// §12: a security event is written to the durable trail as well as the log —
// "alongside the log line, never instead of it". Until this was wired, every
// audit= line went to the log only and the Security page's event list was
// empty in practice.
func TestSecurityEventsReachTheDurableTrail(t *testing.T) {
	h := newHarness(t)
	before, err := h.store.AuditEventCount(t.Context())
	if err != nil {
		t.Fatalf("AuditEventCount: %v", err)
	}
	if before != 0 {
		t.Fatalf("the trail already holds %d events", before)
	}

	cookie := h.login(t)
	events, err := h.store.AuditEvents(t.Context(), 10)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	var found bool
	for _, e := range events {
		if e.Event == logging.EventAuthOK {
			found = true
		}
	}
	if !found {
		t.Errorf("logging in wrote no auth.ok row; the trail holds %+v", events)
	}

	// ...and the Security page shows it, which is the point of writing it.
	page := h.get(t, "/security", cookie).Body.String()
	if !strings.Contains(page, "auth.ok") {
		t.Error("the security page does not show the login that just happened")
	}
}

// The report is one computation. The Security page renders the checks AND the
// degraded banner, so it is the page most able to ask twice.
func TestOnePageRenderComputesThePreflightReportOnce(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	h.reports = 0
	h.get(t, "/security", cookie)
	if h.reports != 1 {
		t.Errorf("rendering /security ran preflight %d times, want 1 — the banner and the panel "+
			"are two renderings of ONE report", h.reports)
	}
	h.reports = 0
	h.get(t, "/", cookie)
	if h.reports != 1 {
		t.Errorf("rendering / ran preflight %d times, want 1", h.reports)
	}
}

// browser is the cookie handling a real client does and curl does not — which
// is exactly why d46.17 reproduced in a browser and not in curl. It keeps the
// last Set-Cookie for each name and sends them all back, so a test can follow a
// login across several requests the way an operator does.
type browser struct {
	h       *harness
	cookies map[string]*http.Cookie
}

func (h *harness) browser() *browser {
	return &browser{h: h, cookies: map[string]*http.Cookie{}}
}

func (b *browser) do(t *testing.T, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	for _, c := range b.cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.h.handler.ServeHTTP(rec, r)
	for _, c := range rec.Result().Cookies() {
		b.cookies[c.Name] = c
	}
	return rec
}

func (b *browser) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	return b.do(t, httptest.NewRequest(http.MethodGet, path, nil))
}

// submitLogin posts the login form with a token the caller chose, so a test can
// submit one page's token against another page's cookie.
func (b *browser) submitLogin(t *testing.T, token, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"password": {password}, api.CSRFField: {token}}
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(t, r)
}

// audited reports whether an event of that name reached §12's durable trail.
func (h *harness) audited(t *testing.T, event string) bool {
	t.Helper()
	_, found := h.auditRow(t, event)
	return found
}

// auditRow is the most recent trail row for one event, so a test can assert what
// it SAYS and not only that it exists — §12's trail answers "changed to what?".
func (h *harness) auditRow(t *testing.T, event string) (logging.AuditEvent, bool) {
	t.Helper()
	events, err := h.store.AuditEvents(t.Context(), 50)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	for _, e := range events {
		if string(e.Event) == event {
			return e, true
		}
	}
	return logging.AuditEvent{}, false
}

func sessionIssued(rec *httptest.ResponseRecorder) bool { return sessionCookie(rec) != nil }

// sessionCookie is the session cookie a response sets, or nil. One definition
// of "which cookie is the session, and what counts as present" — the renewal
// tests ask the same question and had their own copies of the loop.
func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == api.SessionCookieName && c.Value != "" {
			return c
		}
	}
	return nil
}

// d46.17 defect 1: the wrong-password branch rendered PageData with no
// CSRFToken, so the retry form shipped value="" and every later submit from it
// was refused — INCLUDING one with the correct password, so the error the
// operator saw had nothing to do with what they had done wrong. One mistyped
// password wedged the page.
//
// Asserting the retry token is merely non-empty would not catch a regression
// that hands out a fresh token while rotating the cookie underneath it. The
// assertion has to be that the token works: post it with the CORRECT password
// and log in.
func TestARetryAfterAWrongPasswordCanStillLogIn(t *testing.T) {
	b := newHarness(t).browser()

	page := b.get(t, "/login")
	failed := b.submitLogin(t, csrfFrom(t, page.Body.String()), "not-the-password")
	if failed.Code != http.StatusOK {
		t.Fatalf("a wrong password answered %d, want 200 with the form re-rendered", failed.Code)
	}

	retry := b.submitLogin(t, csrfFrom(t, failed.Body.String()), "umbrel-derived-password")
	if retry.Code != http.StatusSeeOther {
		t.Fatalf("the correct password on the retry form answered %d %q, want 303 — "+
			"the retry form's token must be one the cookie accepts",
			retry.Code, retry.Body.String())
	}
	if !sessionIssued(retry) {
		t.Error("the retry redirected but issued no session")
	}
}

// d46.17 defect 2: StartLoginForm minted a NEW nonce and overwrote the cookie
// on every GET /login, so a second tab, a prefetch, or a redirect from /
// invalidated the token in the form already on screen. Measured on the box:
// three consecutive GETs, three different nonces.
//
// The nonce is stable while the cookie is valid, so the first page's token
// still logs in after the second page has been fetched.
func TestASecondLoginPageDoesNotInvalidateTheFirst(t *testing.T) {
	b := newHarness(t).browser()

	first := csrfFrom(t, b.get(t, "/login").Body.String())
	second := csrfFrom(t, b.get(t, "/login").Body.String())
	if first != second {
		t.Errorf("two GET /login handed out different tokens (%q then %q); "+
			"the second invalidates the form already on screen", first, second)
	}

	rec := b.submitLogin(t, first, "umbrel-derived-password")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("the FIRST page's token answered %d %q after a second GET /login, want 303",
			rec.Code, rec.Body.String())
	}
}

// d46.17 criterion 3. Every admin page carries a CSRF token and node state, and
// a cached admin page served after logout is a real leak on a shared browser.
// The login page was measured on the box with no cache directives at all, which
// is heuristically cacheable and is what bfcache reuses.
//
// Both halves are asserted: the public group must NOT get no-store, because
// LNURL responses are cacheable and want to be.
func TestTheAdminGroupIsUncacheableAndThePublicGroupIsNot(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	for _, path := range []string{"/", "/login", "/settings", "/security", "/node",
		"/setup", "/static/style.css"} {
		rec := h.get(t, path, cookie)
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("admin GET %s: Cache-Control = %q, want %q (%d)",
				path, got, "no-store", rec.Code)
		}
	}

	for _, path := range []string{"/health", "/.well-known/lnurlp/bob", "/lnurlp/bob"} {
		rec := h.get(t, path, nil)
		if got := rec.Header().Get("Cache-Control"); got != "" {
			t.Errorf("public GET %s: Cache-Control = %q; LNURL responses are cacheable "+
				"and want to be", path, got)
		}
	}
}

// d46.20 criterion 4, the server's half. The guard bakes a fresh credential in
// milliseconds; the reconnect loop may be part-way through a backoff of up to a
// minute. On the box that made a successful Re-link look like a failed one.
func TestRelinkAlsoStopsTheReconnectFromWaitingItOut(t *testing.T) {
	var retries int
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.RetryNow = func() { retries++ }
	})
	cookie := h.login(t)

	rec := h.postForm(t, "/node/relink", cookie, url.Values{})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /node/relink = %d, want 303", rec.Code)
	}
	if retries != 1 {
		t.Errorf("re-link asked for %d immediate retries, want 1 — otherwise the new "+
			"credential waits out a backoff of up to a minute", retries)
	}
}

// And it must not, when the guard refused: there is no new credential to try.
func TestAFailedRelinkDoesNotRestartTheReconnect(t *testing.T) {
	var retries int
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.RetryNow = func() { retries++ }
	})
	h.broker.SetError(errors.New("guard unreachable"))
	cookie := h.login(t)

	if rec := h.postForm(t, "/node/relink", cookie, url.Values{}); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /node/relink = %d, want 303", rec.Code)
	}
	if retries != 0 {
		t.Errorf("a refused re-link asked for %d retries, want 0", retries)
	}
}

// d46.23. On the box, moving the ceiling wrote txns and balance_entries and
// raised no audit event at all — the ledger recorded the amount and nothing
// recorded who, or from where. That is the half attribution needs, and it is
// the question the Security page exists to answer without an SSH session.
func TestMovingTheCeilingIsAttributedInTheTrail(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	if rec := h.postForm(t, "/wallet/allocate", cookie,
		url.Values{"sats": {"5000"}, "note": {"top up"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("allocate = %d %q", rec.Code, rec.Body)
	}
	if rec := h.postForm(t, "/wallet/deallocate", cookie,
		url.Values{"sats": {"2000"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("deallocate = %d %q", rec.Code, rec.Body)
	}

	events, err := h.store.AuditEvents(t.Context(), 50)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	found := map[logging.Event]logging.AuditEvent{}
	for _, e := range events {
		switch e.Event {
		case logging.EventWalletAllocate, logging.EventWalletDeallocate:
			found[e.Event] = e
		}
	}
	for _, want := range []struct {
		event logging.Event
		msat  string
	}{
		{logging.EventWalletAllocate, "5000000"},
		{logging.EventWalletDeallocate, "2000000"},
	} {
		row, ok := found[want.event]
		if !ok {
			t.Errorf("no %s row; the ceiling moved and nothing recorded it", want.event)
			continue
		}
		if !strings.Contains(row.Detail, want.msat) {
			t.Errorf("%s detail = %q, want the amount %s", want.event, row.Detail, want.msat)
		}
		if row.Remote == "" {
			t.Errorf("%s recorded no remote address; the ledger already has the amount, "+
				"and the address is the half it does not have", want.event)
		}
	}

	// A refused move is not a ceiling move, and must not be recorded as one.
	before := len(found)
	if rec := h.postForm(t, "/wallet/deallocate", cookie,
		url.Values{"sats": {"999999"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("an over-large deallocate = %d", rec.Code)
	}
	events, _ = h.store.AuditEvents(t.Context(), 50)
	var moves int
	for _, e := range events {
		if e.Event == logging.EventWalletAllocate || e.Event == logging.EventWalletDeallocate {
			moves++
		}
	}
	if moves != before {
		t.Errorf("the trail holds %d ceiling moves after a REFUSED one, want %d", moves, before)
	}
}

// d46.23's argument — the ledger records the amount, not who or from where —
// applies to every handler-raised event, not only the wallet's. "Who changed
// the admin password, and from where" is the same question, and it went
// unanswered until the remote attribute stopped being passed by hand.
func TestEveryHandlerRaisedEventCarriesTheCallersAddress(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	if rec := h.postForm(t, "/settings", cookie, url.Values{
		"domain": {"zap.example"}, "address_name": {"bob"},
	}); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /settings = %d %q", rec.Code, rec.Body)
	}
	if rec := h.postForm(t, "/wallet/allocate", cookie,
		url.Values{"sats": {"1000"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /wallet/allocate = %d", rec.Code)
	}

	events, err := h.store.AuditEvents(t.Context(), 100)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no audit rows at all")
	}
	var checked int
	for _, e := range events {
		switch e.Event {
		case logging.EventAuthOK, logging.EventSettingChange, logging.EventWalletAllocate:
			checked++
			if e.Remote == "" {
				t.Errorf("%s carries no remote address; attribution is the half the ledger "+
					"does not have", e.Event)
			}
		}
	}
	if checked < 3 {
		t.Errorf("only %d handler-raised events were checked, want at least 3 — the test "+
			"is asserting over an empty set", checked)
	}
}

// The audit row describes something that has ALREADY been committed, so a
// browser that goes away between the commit and the row must not be able to
// drop it. Otherwise a ceiling move lands in the ledger with nothing recording
// who made it — exactly the gap d46.23 exists to close, reopened by a
// disconnect.
//
// The window is narrow and cannot be hit by cancelling up front: that fails the
// wallet call too, so nothing commits and there is nothing to orphan. It has to
// be opened where it really is — after the ledger write returns.
func TestAnAuditRowSurvivesTheCallerHangingUpAfterTheLedgerWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.Wallet = hangUpWallet{Wallet: opts.Wallet, afterWrite: cancel}
	})
	cookie := h.login(t)

	page := h.get(t, "/settings", cookie)
	form := url.Values{"sats": {"4000"}, "csrf_token": {csrfFrom(t, page.Body.String())}}
	r := httptest.NewRequest(http.MethodPost, "/wallet/allocate", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	h.handler.ServeHTTP(httptest.NewRecorder(), r.WithContext(ctx))

	events, err := h.store.AuditEvents(context.Background(), 50)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	for _, e := range events {
		if e.Event == logging.EventWalletAllocate {
			return
		}
	}
	t.Error("no wallet.allocate row after the caller hung up; the ledger would hold a " +
		"ceiling move that nothing attributes")
}

// hangUpWallet commits, then the caller goes away — the one ordering that can
// leave an unattributed ledger entry.
type hangUpWallet struct {
	api.Wallet
	afterWrite func()
}

func (w hangUpWallet) Allocate(ctx context.Context, amountMsat int64, note string) error {
	err := w.Wallet.Allocate(ctx, amountMsat, note)
	w.afterWrite()
	return err
}

// o34.1 criterion 1: an operator can bring their own nostr identity, and the
// key never reaches a log or a page on the way in or out.
func TestImportingANostrIdentityReplacesTheAnnouncedPubkey(t *testing.T) {
	var logged bytes.Buffer
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.Log = logging.New(&logged, logging.NewLevelVar(slog.LevelDebug))
	})
	cookie := h.login(t)

	before, _, _ := h.store.Setting(t.Context(), api.SettingNostrPubkey)
	key := gonostr.GeneratePrivateKey()
	want, err := gonostr.GetPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}

	if rec := h.postForm(t, "/settings/nostr", cookie,
		url.Values{"nostr_key": {key}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /settings/nostr = %d %q", rec.Code, rec.Body)
	}
	got, ok, _ := h.store.Setting(t.Context(), api.SettingNostrPubkey)
	if !ok || got != want {
		t.Fatalf("announced pubkey = %q, want %q (was %q)", got, want, before)
	}

	// The page shows the public half and never the private one.
	page := h.get(t, "/settings", cookie).Body.String()
	if !strings.Contains(page, want) {
		t.Error("the settings page does not show the new public key")
	}
	if strings.Contains(page, key) {
		t.Error("the settings page rendered the PRIVATE key back")
	}
	if strings.Contains(logged.String(), key) {
		t.Errorf("the private key reached the log:\n%s", logged.String())
	}

	// A key that is not one is refused, and leaves the working identity alone.
	if rec := h.postForm(t, "/settings/nostr", cookie,
		url.Values{"nostr_key": {"nsec1definitelynot"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("a refused import = %d", rec.Code)
	}
	after, _, _ := h.store.Setting(t.Context(), api.SettingNostrPubkey)
	if after != want {
		t.Errorf("a refused import changed the identity to %q", after)
	}
}

// d46.26: the receive credential now expires, so the operator needs to be able
// to see when. The field was plumbed through five layers and rendered nowhere.
func TestTheNodePageShowsWhenTheReceiveCredentialExpires(t *testing.T) {
	expiry := authTime.Add(7 * 24 * time.Hour)
	h := newHarness(t)
	h.broker.Answer = lnd.BrokerStatus{ReceiveMacaroonPresent: true, ReceiveExpiry: expiry}
	cookie := h.login(t)

	page := h.get(t, "/node", cookie).Body.String()
	if !strings.Contains(page, expiry.UTC().Format("2006-01-02")) {
		t.Errorf("the Node page does not show the receive credential's expiry:\n%s", page)
	}
}

// Review L7. The admin group sent no browser-side hardening headers at all, so
// a rendered admin page could be framed, could have its URL leak in a
// Referer, and — with a CSP absent — would execute any script that reached the
// markup. The templates escape, so this is defence in depth rather than a
// live hole, but it is the layer that turns an escaping mistake from an account
// takeover into nothing.
//
// The split is asserted both ways, like no-store. The public group stays bare:
// its responses are JSON read by wallets, not documents rendered in a browser,
// and a CSP on them is a header nobody reads that the next person has to reason
// about.
func TestTheAdminGroupCarriesTheBrowserHardeningHeadersAndThePublicGroupDoesNot(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	want := []struct {
		header   string
		contains string
		why      string
	}{
		{"X-Content-Type-Options", "nosniff", "a mis-typed response must not be re-guessed as script"},
		{"Content-Security-Policy", "frame-ancestors 'none'", "the admin UI is never framed"},
		{"Content-Security-Policy", "default-src 'self'", "nothing on an admin page comes from off-box"},
		{"Referrer-Policy", "no-referrer", "admin paths must not leak in a Referer"},
	}
	for _, path := range []string{"/", "/login", "/settings", "/security", "/node",
		"/setup", "/static/style.css"} {
		rec := h.get(t, path, cookie)
		for _, w := range want {
			if got := rec.Header().Get(w.header); !strings.Contains(got, w.contains) {
				t.Errorf("admin GET %s: %s = %q, want it to contain %q (%s)",
					path, w.header, got, w.contains, w.why)
			}
		}
	}

	// Real public routes only. An unrouted path under a public prefix answers
	// through http.NotFound, which sets nosniff of its own accord — asserting
	// against that would be asserting net/http's behaviour, not ours.
	for _, path := range []string{"/health", "/.well-known/lnurlp/bob",
		"/lnurlp/bob/callback?amount=21000"} {
		rec := h.get(t, path, nil)
		for _, header := range []string{"X-Content-Type-Options", "Content-Security-Policy",
			"Referrer-Policy"} {
			if got := rec.Header().Get(header); got != "" {
				t.Errorf("public GET %s: %s = %q; the public group is JSON for wallets "+
					"and carries no browser policy", path, header, got)
			}
		}
	}
}
