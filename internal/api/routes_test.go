package api_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/api"
)

// Spec §3 and §11: a test must walk the public mux and assert its route set
// contains EXACTLY the LNURL paths and /health.
//
// Equality, not a subset. A subset check passes at precisely the moment it
// matters — when a new route silently joins the public surface.
// The three OPTIONS patterns are the CORS preflight (BrollyZap-z60), registered
// explicitly rather than intercepted in middleware precisely so they appear
// here. That this assertion had to be updated is the point of it: a method
// added to the anonymous surface is a change to that surface, and it should
// cost a line in the declared set rather than slipping in unenumerated.
func TestPublicRouteSetIsExactlyTheDeclaredPublicPatterns(t *testing.T) {
	want := []string{
		"/health",
		"GET /.well-known/lnurlp/{name}",
		"GET /lnurlp/{name}/callback",
		"OPTIONS /health",
		"OPTIONS /.well-known/lnurlp/{name}",
		"OPTIONS /lnurlp/{name}/callback",
	}
	got := publicGroup().Patterns()

	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("public route set = %v, want exactly %v (spec §3, §11)", got, want)
	}
	// And the declared list says the same thing, because Compose, the proxy
	// whitelist and this assertion must not be able to disagree.
	declared := slices.Clone(api.PublicPatterns)
	slices.Sort(declared)
	if !slices.Equal(declared, want) {
		t.Errorf("api.PublicPatterns = %v, want %v", declared, want)
	}
}

// PublicPaths is the ROUTING PREFIX list — what Compose sends to the public
// group and what the proxy whitelist mirrors. Every route actually served must
// fall under one of them, or a pattern is registered on a group nothing routes
// to, and the whitelist is describing a surface that is not the real one.
func TestEveryPublicPatternFallsUnderAWhitelistedPrefix(t *testing.T) {
	for _, pattern := range api.PublicPatterns {
		path := pattern
		if _, after, found := strings.Cut(pattern, " "); found {
			path = after
		}
		var covered bool
		for _, prefix := range api.PublicPaths {
			if strings.HasPrefix(path, strings.TrimSuffix(prefix, "/")) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("public route %q is under no PublicPaths prefix %v, so Compose never "+
				"routes to it and the proxy whitelist does not describe it", pattern, api.PublicPaths)
		}
	}

	// AND THE REVERSE, which CORS made load-bearing (BrollyZap-z60). Compose
	// hands whole PublicPaths PREFIXES to the public group, and the public group
	// now carries Access-Control-Allow-Origin — so a prefix with no route under
	// it is no longer merely dead config, it is an anonymous, CORS-carrying 404
	// subtree that the proxy whitelist also opens. Harmless today, because the
	// public group is built with no session manager at all; still, a prefix
	// should cost a route, so that growing the anonymous surface is a thing
	// someone has to do on purpose.
	for _, prefix := range api.PublicPaths {
		if !slices.ContainsFunc(api.PublicPatterns, func(pattern string) bool {
			path := pattern
			if _, after, found := strings.Cut(pattern, " "); found {
				path = after
			}
			return strings.HasPrefix(path, strings.TrimSuffix(prefix, "/"))
		}) {
			t.Errorf("PublicPaths opens %q to the anonymous group and no PublicPatterns route "+
				"is served under it; the prefix is a CORS-carrying 404 subtree", prefix)
		}
	}
}

// The composed root sends the public paths to the public group and everything
// else to the admin group. Two muxes, composed — never one mux with per-route
// middleware (§3, §16).
func TestTheRootComposesTwoMuxesRatherThanOne(t *testing.T) {
	root := composedRoot()

	cases := map[string]string{
		"/health":                        "public-health",
		"/.well-known/lnurlp/bob":        "public-lnurl",
		"/lnurlp/bob/callback":           "public-lnurl",
		"/":                              "admin",
		"/wallet":                        "admin",
		"/settings":                      "admin",
		"/.well-known/acme-challenge/xy": "admin",
	}
	for path, want := range cases {
		rec := httptest.NewRecorder()
		root.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if got := strings.TrimSpace(rec.Body.String()); got != want {
			t.Errorf("%s reached %q, want %q", path, got, want)
		}
	}
}

// A path that only looks public must not reach the public group. ServeMux
// cleans the path and redirects rather than dispatching, which is the answer we
// want — what matters is that no traversal lands on an unauthenticated handler.
func TestPathTraversalDoesNotReachThePublicGroup(t *testing.T) {
	root := composedRoot()

	for _, path := range []string{
		"/health/../wallet",
		"/lnurlp/../settings",
		"/.well-known/lnurlp/../../settings",
	} {
		rec := httptest.NewRecorder()
		root.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if strings.Contains(rec.Body.String(), "public-") {
			t.Errorf("%s reached the public group: %s", path, rec.Body.String())
		}
		if rec.Code == http.StatusOK {
			t.Errorf("%s returned 200 rather than a redirect to its cleaned path", path)
		}
	}
}

// Spec §3: /health returns 200 ok or 503 and nothing else — no version, no
// balance, no node state, no build info. It is reachable by anyone on the
// public internet, so the assertion is on the body, not just the status.
func TestHealthSaysOnlyOkOrUnavailable(t *testing.T) {
	healthy := true
	handler := api.HealthHandler(func() bool { return healthy })

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("healthy status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "ok" {
		t.Errorf("healthy body = %q, want exactly \"ok\"", body)
	}

	healthy = false
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("unhealthy status = %d, want 503", rec.Code)
	}
	if body := rec.Body.String(); body != "unavailable" {
		t.Errorf("unhealthy body = %q, want exactly \"unavailable\"", body)
	}
}

// Anything that leaks node or build state through /health is a finding: the
// endpoint is anonymous and public.
func TestHealthLeaksNothingAboutTheDeployment(t *testing.T) {
	handler := api.HealthHandler(func() bool { return true })
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	body := strings.ToLower(rec.Body.String())
	for _, leak := range []string{"version", "balance", "msat", "lnd", "node", "macaroon", "dev"} {
		if strings.Contains(body, leak) {
			t.Errorf("/health body %q mentions %q; it says ok or unavailable and nothing else (spec §3)",
				rec.Body.String(), leak)
		}
	}
	if len(rec.Header()) > 2 {
		t.Errorf("/health set headers %v; keep it to the content type", rec.Header())
	}
}

func marker(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(name))
	})
}

// publicGroup and adminGroup are the two halves as Compose sees them, wired to
// markers so a test can tell which one answered; composedRoot is the pair as
// the server serves them.
func publicGroup() *api.Routes {
	return api.NewPublicMux(marker("public-health"), marker("public-lnurl"), marker("public-lnurl"))
}

func adminGroup() *api.Routes {
	admin := api.NewAdminMux()
	admin.Handle("/", marker("admin"))
	return admin
}

func composedRoot() http.Handler { return api.Compose(publicGroup(), adminGroup()) }

// lnurlPaths are the two legs a browser wallet fetches. Both, always: a browser
// fails on the address document first, so a callback asserted on its own can
// regress unnoticed behind an address document that still works.
var lnurlPaths = []string{"/.well-known/lnurlp/bob", "/lnurlp/bob/callback"}

// browserRequest is a request as a browser wallet sends it — cross-origin, which
// is the only condition under which any of this matters.
func browserRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("Origin", "https://primal.net")
	return r
}

// The LNURL endpoints must be readable cross-origin, or no browser wallet can
// zap (BrollyZap-z60).
//
// Reported from Primal web and confirmed against the live box: both legs
// returned 200 with no Access-Control-Allow-Origin. A browser fails on the
// address document first, so the callback's failure is LATENT — asserting only
// the first would move the error rather than clear it, which is why both are
// here.
//
// "*" rather than an origin list: these endpoints are unauthenticated, carry no
// per-user data, and exist to be fetched by arbitrary wallets. There is nothing
// an allowlist could protect, and one would need updating for every new client.
func TestTheLNURLEndpointsAreReadableCrossOrigin(t *testing.T) {
	root := composedRoot()

	for _, path := range lnurlPaths {
		rec := httptest.NewRecorder()
		root.ServeHTTP(rec, browserRequest(http.MethodGet, path))

		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("%s sent Access-Control-Allow-Origin %q, want \"*\"; a browser wallet "+
				"cannot read this response at all", path, got)
		}
	}
}

// THE ADMIN GROUP MUST NOT GET IT. This is the assertion that matters.
//
// The admin surface is session-authenticated, and cross-origin readability
// there is an account-takeover vector in an app whose threat model already
// treats the server as the component under attack. The structure prevents it by
// construction — the middleware goes on the public group at the composition
// point — but "by construction" is a claim, and NewAdminMux takes everything
// not explicitly public, so a root-level wrapper added in a future "just add
// CORS globally" change would silently cover it. This is the regression that
// would otherwise creep back in.
func TestTheAdminGroupIsNotReadableCrossOrigin(t *testing.T) {
	root := composedRoot()

	// Not just the pages that exist. NewAdminMux takes EVERYTHING not explicitly
	// public — unknown paths included — so the sweep covers the near misses
	// that are the actual hazard: paths that look public and are not, and a
	// route nobody has written yet.
	//
	// The assertion keys off WHICH GROUP ANSWERED, not off whether the path is a
	// declared public route, because those are different questions. Compose
	// routes by the PublicPaths PREFIXES, so /lnurlp/bob — the callback path
	// minus /callback — reaches the public group and 404s there, carrying the
	// header. That is correct and harmless: the public group is constructed
	// without a session manager at all (see NewPublicMux), so a 404 from it
	// discloses nothing to anyone. What must never carry the header is a
	// response the ADMIN group produced.
	// EVERY path here must actually reach the admin group, and the test says so
	// rather than skipping quietly. An earlier version filtered on "did admin
	// answer?" and counted, which let four of its fourteen rows contribute
	// nothing: /health/../wallet, /.well-known/lnurlp and /lnurlp are 307
	// redirects that never reach a group at all, and they sat in the list under
	// a comment claiming one of them was a traversal onto an admin page. A row
	// that cannot fail is worse than a missing row, because it reads as cover.
	for _, path := range []string{
		"/", "/wallet", "/settings", "/login", "/connections", "/security",
		"/static/style.css",
		"/healthz",                       // not /health, so not public
		"/.well-known/acme-challenge/xy", // a well-known that is not ours
		"/a-route-nobody-has-written-yet",
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
			rec := httptest.NewRecorder()
			root.ServeHTTP(rec, browserRequest(method, path))

			if got := strings.TrimSpace(rec.Body.String()); got != "admin" {
				t.Errorf("%s %s was answered by %q, not the admin group; this row asserts "+
					"nothing about CORS while it sits in this list", method, path, got)
				continue
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("%s %s was answered by the ADMIN group and sent "+
					"Access-Control-Allow-Origin %q; that surface is session-authenticated "+
					"and must never be cross-origin readable", method, path, got)
			}
		}
	}

	// The near misses, kept but stated honestly: these do NOT reach the admin
	// group today, and the assertion is exactly that. /lnurlp/bob — the callback
	// path minus /callback — reaches the PUBLIC group and 404s there carrying the
	// header, which is correct and harmless: the public group is constructed with
	// no session manager at all (see NewPublicMux), so a 404 from it discloses
	// nothing. The rest are redirects. If any of them ever starts reaching admin,
	// the loop above is where it belongs.
	for _, path := range []string{
		"/health/../wallet",   // ServeMux cleans and redirects; it never dispatches
		"/.well-known/lnurlp", // the prefix without a name
		"/lnurlp",             // ditto
		"/lnurlp/bob",         // public group, 404
	} {
		rec := httptest.NewRecorder()
		root.ServeHTTP(rec, browserRequest(http.MethodGet, path))
		if strings.TrimSpace(rec.Body.String()) == "admin" {
			t.Errorf("%s now reaches the admin group; move it into the sweep above, where "+
				"its CORS header is asserted", path)
		}
	}
}

// The preflight advertises every method the public group actually registers.
//
// The Allow-Methods string and PublicPatterns are two statements of one fact,
// which is the shape adminHeaders' own doc comment names as the thing that
// drifts. The drift here is invisible from inside: register
// POST /lnurlp/{name}/callback one day, and the preflight keeps advertising
// GET, HEAD, OPTIONS — every browser wallet blocks the real request, and
// nothing goes red, because a test that spelled the literal out would move in
// lockstep with the bug. So this derives the expectation from the route set
// instead of restating it.
func TestThePreflightAdvertisesEveryMethodThePublicGroupServes(t *testing.T) {
	root := composedRoot()
	rec := httptest.NewRecorder()
	r := browserRequest(http.MethodOptions, lnurlPaths[0])
	r.Header.Set("Access-Control-Request-Method", "GET")
	root.ServeHTTP(rec, r)

	advertised := rec.Header().Get("Access-Control-Allow-Methods")
	if advertised == "" {
		t.Fatal("the preflight advertised no methods at all")
	}
	for _, pattern := range api.PublicPatterns {
		method, _, found := strings.Cut(pattern, " ")
		if !found {
			// A method-less pattern answers every method; it constrains nothing.
			continue
		}
		if !strings.Contains(advertised, method) {
			t.Errorf("the public group serves %q but the preflight advertises only %q, so a "+
				"browser blocks the real request before it is sent", pattern, advertised)
		}
	}
}

// A preflight must be answered, not refused.
//
// A plain GET with no custom headers is a simple request and does not preflight,
// so the header alone unblocks a wallet like Primal today. But OPTIONS returning
// 405 breaks any wallet that sets a custom header or uses an explicit CORS mode,
// and that is the second bug report waiting to happen.
func TestAPreflightOnTheLNURLEndpointsIsAnswered(t *testing.T) {
	root := composedRoot()

	for _, path := range lnurlPaths {
		rec := httptest.NewRecorder()
		r := browserRequest(http.MethodOptions, path)
		r.Header.Set("Access-Control-Request-Method", "GET")
		root.ServeHTTP(rec, r)

		if rec.Code != http.StatusNoContent {
			t.Errorf("OPTIONS %s answered %d, want %d; a 405 fails the preflight and the "+
				"wallet never sends the real request", path, rec.Code, http.StatusNoContent)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("the preflight for %s sent Access-Control-Allow-Origin %q, want \"*\"",
				path, got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "GET, HEAD, OPTIONS" {
			t.Errorf("the preflight for %s allowed methods %q, want \"GET, HEAD, OPTIONS\"",
				path, got)
		}
	}
}
