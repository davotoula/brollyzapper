package api

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// redirectAtTheCall reads the target out of an http.Redirect call, when it is a
// literal there. Compiled once: the whole file turns on this pattern, and two
// copies is one of them being narrowed while the other is not.
var redirectAtTheCall = regexp.MustCompile(`http\.Redirect\(w, r, "([^"]*)"`)

// EVERY REDIRECT TARGET IN THIS PACKAGE MUST BE A PATH SOMETHING SERVES (`v7u`
// fix D).
//
// Found on the box. `assertPaymentOutcome` — `669`'s control, the supported way
// out of a stranded payment — redirected to `/wallet?flash=saved`, and there is
// no `/wallet` route: the wallet page is `GET /{$}`, and the allocate and
// deallocate handlers on that same page have always redirected to `/`. The write
// happens before the redirect, so pressing *It failed* APPLIED the assertion and
// then showed a 404 for it. An operator following the incident write-up had to
// be told the 404 was a success.
//
// The flash test beside this one checks the half after the `?`: every marker has
// a message. Nothing checked the half before it, so a marker with a message on a
// path with no route read as correct from both ends.
//
// A SOURCE SCAN AND THE REAL MUX, which is the seam this bead is about —
// `669`'s tests exercised the handler and the wallet, and there was no test in
// this package for the handler at all, so nothing ever followed the Location it
// writes. Asking `pages()` itself is what makes this a rule rather than a second
// hand-kept list of routes that can go stale the same way.
func TestEveryRedirectTargetIsAServedPath(t *testing.T) {
	targets, literal := redirectTargets(t)
	// Bounded on the CALLS, not the distinct paths: the package redirects from
	// about fifty sites to six pages, so a pattern that silently stopped matching
	// most of them would still leave a plausible-looking handful of targets.
	if literal < 40 {
		t.Fatalf("only %d literal redirect calls were found across %d files; this rule can "+
			"no longer see its subject", literal, len(sourceFiles(t)))
	}
	// Anti-vacuity with teeth: the two paths the scan MUST see. "/" is the one
	// the bug was about, and "/connections" is only reachable through the
	// non-literal `a.noop`/`a.done` fields, so its absence would mean the second
	// pattern below had stopped matching.
	for _, required := range []string{"/", "/connections"} {
		if !slices.Contains(targets, required) {
			t.Fatalf("the scan found no redirect to %q; it is reading %d files and its "+
				"patterns have drifted off the code", required, len(sourceFiles(t)))
		}
	}

	served := servedPaths(t)
	for _, target := range targets {
		if _, pattern := served.Handler(getRequest(target)); pattern == "" {
			t.Errorf("a handler redirects to %q and no route serves it — the write before the "+
				"redirect lands and the operator is shown a 404 for a success (`v7u`)", target)
		}
	}
}

// servedPaths is the authenticated route table PLUS the two paths registered
// beside it on the admin mux, as one oracle.
//
// The real `pages()`, called on a zero Server: it registers method values and
// touches no state, so this is the route table the process serves and not a copy
// of it. `/login` and `/static/` live on the admin mux that New builds around
// `pages()`, and they are read out of server.go rather than listed here for the
// same reason — a hand-kept list is what goes stale.
func servedPaths(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := pagesMux(t)
	beside := regexp.MustCompile(`admin\.Handle\("([^"]+)"`).
		FindAllStringSubmatch(readSource(t, "server.go"), -1)
	if len(beside) < 2 {
		t.Fatalf("found %d admin.Handle registrations in server.go, want at least the two "+
			"beside pages(); the oracle would refuse paths the server does serve", len(beside))
	}
	for _, match := range beside {
		if match[1] == "/" {
			// The catch-all that IS pages(), already in the mux above.
			continue
		}
		mux.Handle(match[1], http.NotFoundHandler())
	}
	return mux
}

// pagesMux is the authenticated route table as the process registers it.
func pagesMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux, ok := (&Server{}).pages().(*http.ServeMux)
	if !ok {
		t.Fatal("pages() no longer returns a *http.ServeMux, so this rule cannot ask it " +
			"what it serves")
	}
	return mux
}

// redirectTargets is every path this package redirects a browser to, and how
// many literal call sites it read them from.
//
// TWO PATTERNS, because there are two shapes and one of them has no literal at
// the call:
//
//   - the literal at the call — `http.Redirect(w, r, "/node?flash=…"`, which
//     also catches the concatenations that START with a literal, since the path
//     is always in the first part.
//   - any string literal that looks like a redirect target — which is how the
//     `done`/`noop` fields in pages_connections.go are seen, since those reach
//     `http.Redirect` as `a.done` and a scan of the call site finds nothing.
//
// A target that is neither — built from a variable with no literal anywhere —
// would be invisible here, which is what the guard below is for.
func redirectTargets(t *testing.T) ([]string, int) {
	t.Helper()
	looksLikeOne := regexp.MustCompile(`"(/[^"\s]*\?flash=[^"\s]*)"`)

	seen := map[string]bool{}
	var calls, literal int
	for _, name := range sourceFiles(t) {
		src := readSource(t, name)
		// Every call, literal target or not, so the patterns below can be checked
		// for coverage. A plain Count because every call site starts with the same
		// fixed prefix — a third regex here would be a third thing to keep in step.
		calls += strings.Count(src, "http.Redirect(w, r, ")
		for _, match := range redirectAtTheCall.FindAllStringSubmatch(src, -1) {
			literal++
			seen[routePath(match[1])] = true
		}
		for _, match := range looksLikeOne.FindAllStringSubmatch(src, -1) {
			seen[routePath(match[1])] = true
		}
	}

	// THE COVERAGE GUARD. Two calls redirect to a variable — pages_connections's
	// `a.done` and `a.noop` — and both variables are assigned literals the second
	// pattern sees. A THIRD such call would be a target this rule cannot read,
	// and it must stop the build rather than pass silently: a rule that
	// enumerates a set needs to know when the set stopped being complete.
	if indirect := calls - literal; indirect != 2 {
		t.Errorf("%d redirect targets in this package are not string literals at the call, "+
			"want the 2 known ones (pages_connections's done/noop).\n\nA new one is invisible "+
			"to this rule: give it a literal at the call, or teach the scan to read it",
			indirect)
	}

	return slices.Sorted(maps.Keys(seen)), literal
}

// routePath is the part a mux routes on: everything before the query.
func routePath(target string) string {
	p, _, _ := strings.Cut(target, "?")
	return p
}

// getRequest is the browser's follow-up to a 303: a GET at that path.
func getRequest(target string) *http.Request {
	return httptest.NewRequest(http.MethodGet, "http://brollyzap.local"+target, nil)
}

func sourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			out = append(out, name)
		}
	}
	return out
}

func readSource(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		t.Fatal(err)
	}
	return string(src)
}

// And the one redirect this bead was filed for, named after it.
//
// The structural rule above already covers it, and this is worth having beside
// it for two reasons. It NAMES the regression, so a future change that moves the
// wallet page fails with the incident in the failure message rather than as one
// line in a swept list. And it is scoped to this handler's own source, so it
// still bites if the general scan's patterns are ever narrowed.
//
// It reads the Locations out of pages_wallet.go rather than repeating them, for
// the reason the rule above gives: a hand-kept copy of a path is the thing that
// goes stale. It does not POST — driving the real handler needs a Server with a
// wallet, a session and a CSRF token, and what went wrong here was the target,
// not the write, which had already landed when the operator saw the 404.
func TestTheAssertionRedirectLandsOnAPage(t *testing.T) {
	pages := pagesMux(t)

	// THE HANDLER'S OWN BODY, bounded at both ends. pages_wallet.go holds the
	// allocate and deallocate handlers too, and they redirect with the same two
	// flash markers to the CORRECT path — so a scan of the whole file finds a
	// served target for every marker and passes while this handler is broken.
	// It did: the first cut of this test read the last match in the file and
	// stayed green under a plant that restored the bug.
	body := readSource(t, "pages_wallet.go")
	start := strings.Index(body, "func (s *Server) assertPaymentOutcome(")
	if start < 0 {
		t.Fatal("assertPaymentOutcome is gone from pages_wallet.go; this test asserts nothing")
	}
	end := strings.Index(body[start:], "\nfunc ")
	if end < 0 {
		t.Fatal("could not find the end of assertPaymentOutcome; an unbounded region would " +
			"scan the rest of the file, which is how this test passed on the wrong handler")
	}
	body = body[start : start+end]

	targets := redirectAtTheCall.FindAllStringSubmatch(body, -1)
	if len(targets) != 2 {
		t.Fatalf("assertPaymentOutcome has %d redirects, want the 2 it answers with — a "+
			"refused assertion and a saved one", len(targets))
	}
	for _, target := range targets {
		if _, pattern := pages.Handler(getRequest(routePath(target[1]))); pattern == "" {
			t.Errorf("the assertion redirects to %q, which no route serves — the assertion "+
				"APPLIES and the operator is shown a 404 (`v7u`, found on the box)", target[1])
		}
	}
}
