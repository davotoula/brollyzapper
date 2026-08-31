package api

import (
	"net/http"
	"slices"
)

// PublicPaths is the entire anonymous surface (spec §3): the LNURL endpoints
// and /health. Nothing else, ever.
//
// It is a list rather than a set of calls scattered through a constructor so
// the §11 route-set assertion can compare against it, and so the
// PROXY_AUTH_WHITELIST in §10 has one place to stay in sync with.
var PublicPaths = []string{
	"/health",
	"/.well-known/lnurlp/",
	"/lnurlp/",
}

// Routes is an http.ServeMux that remembers what was registered on it.
//
// The standard mux cannot be asked which patterns it holds, and §11 requires a
// test that walks the public group and asserts its route set EQUALS the list
// above. Without this the assertion could only ever be a subset check, which
// passes at exactly the moment it matters — when a new route silently joins the
// public surface.
type Routes struct {
	mux      *http.ServeMux
	patterns []string
}

// NewRoutes returns an empty route group.
func NewRoutes() *Routes {
	return &Routes{mux: http.NewServeMux()}
}

// Handle registers a pattern and records it.
func (r *Routes) Handle(pattern string, handler http.Handler) {
	r.patterns = append(r.patterns, pattern)
	r.mux.Handle(pattern, handler)
}

// HandleFunc registers a pattern and records it.
func (r *Routes) HandleFunc(pattern string, handler http.HandlerFunc) {
	r.Handle(pattern, handler)
}

// Patterns is everything registered on this group, in registration order.
func (r *Routes) Patterns() []string { return slices.Clone(r.patterns) }

func (r *Routes) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

// NewPublicMux builds the anonymous route group.
//
// It takes no session manager and no auth of any kind — deliberately. §11 wants
// the public group to have no auth path at all rather than auth that happens to
// pass, and a constructor that cannot be handed a session store is the version
// of that which cannot erode. An arch test asserts this file mentions no
// session or CSRF machinery.
func NewPublicMux(health, payRequest, callback http.Handler) *Routes {
	routes := NewRoutes()
	routes.Handle("/health", health)
	// Registered with their full patterns rather than behind a prefix, so every
	// public route is one Routes.Patterns() reports. A handler that mounted a
	// mux of its own under a prefix could add routes to the anonymous surface
	// that the §11 equality assertion would never see.
	routes.Handle("GET /.well-known/lnurlp/{name}", payRequest)
	routes.Handle("GET /lnurlp/{name}/callback", callback)
	// The preflight, registered EXPLICITLY rather than intercepted in
	// publicHeaders (BrollyZap-z60). Intercepting is the smaller diff, but it
	// adds a method to the anonymous surface that Patterns() never reports —
	// exactly the hole the comment above warns about for prefix-mounted
	// submuxes. These lines buy back the enumerability §11 is built around.
	//
	// EVERY public route, /health included. It would work without one — a
	// method-less pattern already answers OPTIONS rather than 405 — but that is
	// a mechanism detail, and leaving /health out would make the group's
	// preflight behaviour non-uniform on the strength of it: 200 with a body and
	// no Allow-Methods here, 204 with it there. publicHeaders takes the whole
	// group for the reason that applies unchanged: a rule with an exception is a
	// rule someone has to remember.
	routes.HandleFunc("OPTIONS /health", corsPreflight)
	routes.HandleFunc("OPTIONS /.well-known/lnurlp/{name}", corsPreflight)
	routes.HandleFunc("OPTIONS /lnurlp/{name}/callback", corsPreflight)
	return routes
}

// corsPreflight answers a CORS preflight for the public group.
//
// 204 and no body: there is nothing to say beyond the headers, and
// publicHeaders has already set the origin by the time this runs.
//
// HEAD is named alongside GET because net/http serves it from the GET handler,
// so a wallet that probes with HEAD is not being told something untrue. A test
// asserts this list covers every method PublicPatterns actually registers —
// otherwise this string and that route set are two statements of one fact, and
// the one that drifts is the one no browser can see going wrong.
func corsPreflight(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
	w.WriteHeader(http.StatusNoContent)
}

// PublicPatterns is the public group's registered route set, in full.
//
// PublicPaths above is the ROUTING PREFIX list — what Compose sends to this
// group and what the proxy whitelist mirrors. This is what is actually served
// under those prefixes. Both exist because they answer different questions, and
// a test asserts every pattern here falls under a prefix there.
var PublicPatterns = []string{
	"/health",
	"GET /.well-known/lnurlp/{name}",
	"GET /lnurlp/{name}/callback",
	"OPTIONS /health",
	"OPTIONS /.well-known/lnurlp/{name}",
	"OPTIONS /lnurlp/{name}/callback",
}

// NewAdminMux builds the authenticated route group. Everything that is not a
// public path lands here, including unknown paths, so a route added without
// thought is private by default rather than public by accident.
func NewAdminMux() *Routes { return NewRoutes() }

// Compose joins the two groups at the root.
//
// Two http.ServeMux instances composed, never one mux with per-route
// middleware (§3, §16): the split is what makes the public surface a thing you
// can enumerate and assert.
func Compose(public, admin *Routes) http.Handler {
	root := http.NewServeMux()
	// Named for the GROUPS, not for today's headers: the two lines are one
	// operation applied twice, and a local called after whichever header the
	// middleware happens to set first goes stale the moment it sets a second.
	publicGroup, adminGroup := publicHeaders(public), adminHeaders(admin)
	for _, pattern := range PublicPaths {
		root.Handle(pattern, publicGroup)
	}
	root.Handle("/", adminGroup)
	return boundBodies(root)
}

// boundBodies caps every request body, on BOTH groups.
//
// It wraps the composition point rather than sitting inside the form readers,
// for the reason adminHeaders gives below: a rule with an exception is a rule
// someone has to remember, and a cap installed per handler is a cap every
// future handler has to remember to install. This one covers all methods, all
// routes present and future, and any path that reads r.Body directly rather
// than through ParseForm — io.ReadAll, a JSON decoder, whatever P3 brings. An
// arch rule keeps readForm the only body reader in the package.
//
// The public group gets it too. Response POLICY is deliberately withheld from
// the public group (see adminHeaders); a body cap is not policy, it is a
// resource bound, and §11 treats the public group as the hostile surface. That
// the public routes are registered GET-only today is a property of the current
// handlers, not of the boundary.
//
// It is middleware and not an http.Server field because MaxBytesReader needs
// the ResponseWriter to mark the connection unusable once the limit is hit.
func boundBodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// adminHeaders sets every response policy the admin group gets, and applies to
// nothing else.
//
// The unit is the GROUP, not authentication: /login and /static/ live in this
// group unauthenticated, and they are covered too, because a rule with an
// exception is a rule someone has to remember. Applying it here, at the
// composition point that already knows which group is which, is what keeps the
// distinction from depending on each handler remembering.
//
// Cache-Control: no-store. Every admin page carries a one-time form token and
// live node state, and a cached admin page served after logout is a real leak
// on a shared browser — the login page was measured in production carrying no
// freshness information at all, which makes it heuristically cacheable and
// eligible for bfcache (d46.17). The header is set before delegating, so a
// handler that genuinely wants to be cached can still say so.
//
// The rest is review L7's browser hardening. The templates escape and there is
// no inline script or style anywhere in internal/web, so the CSP below costs
// nothing today and is what turns a future escaping mistake into a blocked
// load rather than an account takeover. frame-ancestors carries the
// clickjacking half; X-Frame-Options is not sent alongside it because every
// browser this app can be administered from honours the CSP directive, and two
// spellings of one rule is the "two statements of one fact" shape that drifts.
//
// The public group deliberately gets NONE of this: LNURL responses are
// cacheable and want to be, and they are JSON read by wallets rather than
// documents rendered in a browser, so a content policy on them is a header
// nobody reads that the next reader has to reason about.
func adminHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", adminCSP)
		next.ServeHTTP(w, r)
	})
}

// publicHeaders sets every response policy the PUBLIC group gets, and applies
// to nothing else. It is adminHeaders' mirror, at the same composition point.
//
// Only CORS, and only because a browser cannot read these responses without it
// (BrollyZap-z60). Reported from Primal web: every browser-based wallet was
// blocked, while native and mobile clients were unaffected — which is why it
// went unnoticed for so long.
//
// "*" IS CORRECT HERE, not a compromise. These endpoints are unauthenticated,
// carry no per-user data, and exist to be fetched by arbitrary wallets; there
// is nothing an origin allowlist could protect, and one would need editing for
// every new client. Access-Control-Allow-Credentials is deliberately absent —
// it is invalid alongside "*", and there is no cookie or credential on this
// surface to send.
//
// THE SCOPING IS THE SAFETY-CRITICAL PART, and it is why this wraps the group
// rather than the root. NewAdminMux takes everything not explicitly public, so
// a middleware installed on the root mux would silently make the
// session-authenticated surface cross-origin readable — an account-takeover
// vector in an app whose threat model already treats the server as the
// component under attack. The group is the unit; a test asserts the admin
// side stays bare.
//
// The whole group, /health included. adminHeaders' reasoning applies unchanged:
// a rule with an exception is a rule someone has to remember. /health gaining a
// CORS header is harmless, and the alternative is a carve-out the next reader
// has to reason about.
func publicHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(w, r)
	})
}

// adminCSP is the admin group's content policy.
//
// Everything the UI needs is served from this origin: one stylesheet, no
// scripts, no images, no fonts. So the policy says exactly that, and the
// directives that would otherwise fall back to default-src are named
// explicitly where saying nothing would be weaker — form-action and base-uri
// have no default-src fallback at all.
const adminCSP = "default-src 'self'; " +
	"script-src 'none'; " +
	"object-src 'none'; " +
	"img-src 'self' data:; " +
	"form-action 'self'; " +
	"base-uri 'none'; " +
	"frame-ancestors 'none'"
