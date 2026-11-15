package api_test

import (
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// HEAD /login answers as GET does (as0.4; the reason is on the login handler).
// It runs through a real server because only the server drops a HEAD body:
// httptest.ResponseRecorder keeps whatever the handler wrote, and a monitor
// sees the server's response.
func TestHeadLoginAnswersAsGetDoes(t *testing.T) {
	srv := httptest.NewServer(newHarness(t).handler)
	defer srv.Close()

	do := func(method string) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+"/login", nil)
		if err != nil {
			t.Fatalf("building %s /login: %v", method, err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s /login: %v", method, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading the %s /login body: %v", method, err)
		}
		return resp, body
	}

	get, _ := do(http.MethodGet)
	head, body := do(http.MethodHead)
	if head.StatusCode != http.StatusOK || get.StatusCode != http.StatusOK {
		t.Fatalf("HEAD /login = %d, GET /login = %d, want both 200; a monitor sending HEAD "+
			"reports the app down", head.StatusCode, get.StatusCode)
	}
	if len(body) != 0 {
		t.Errorf("HEAD /login returned %d body bytes; the server drops the body", len(body))
	}

	// HEAD describes the GET response, so it carries every header GET does —
	// the admin group's hardening headers included, which
	// TestTheAdminGroupCarriesTheBrowserHardeningHeadersAndThePublicGroupDoesNot
	// pins on GET. Comparing against GET rather than a copied list means a header
	// added to the admin group later is covered here without touching this test.
	// Excluded are the ones that legitimately differ per response: the clock, the
	// length the server could only count for the GET, and a fresh login nonce.
	for _, hdr := range []http.Header{get.Header, head.Header} {
		for _, k := range []string{"Date", "Content-Length", "Set-Cookie"} {
			hdr.Del(k)
		}
	}
	if !maps.EqualFunc(get.Header, head.Header, slices.Equal) {
		t.Errorf("HEAD /login headers differ from GET's:\nHEAD %v\nGET  %v", head.Header, get.Header)
	}
	if csp := head.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("HEAD /login: Content-Security-Policy = %q, want the admin group's policy", csp)
	}

	// The methods refused before are still refused.
	for _, method := range []string{
		http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions,
	} {
		if resp, _ := do(method); resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s /login = %d, want 405", method, resp.StatusCode)
		}
	}
}
