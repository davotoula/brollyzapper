package api_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/api"
)

// Review L6. Both form-reading paths called ParseForm on an unbounded body, so
// an anonymous caller could make the process buffer as much as it cared to send
// — on /login, before authenticating, and on the admin group, before the CSRF
// token was even looked at.
//
// The order is the point on the authenticated path: the body cap has to fire
// BEFORE the CSRF check, because ParseForm is what reads the token, so a check
// placed after it is a check that has already read the whole body.
func TestAnOversizedFormIsRefusedBeforeItIsParsed(t *testing.T) {
	h := newHarness(t)
	oversized := strings.Repeat("x", api.MaxFormBytes+1)

	t.Run("login, unauthenticated", func(t *testing.T) {
		form := url.Values{"password": {oversized}}
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, r)

		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("POST /login with an oversized body = %d, want 413", rec.Code)
		}
		if sessionIssued(rec) {
			t.Error("an oversized login POST issued a session")
		}
	})

	t.Run("admin form, before the CSRF verdict", func(t *testing.T) {
		cookie := h.login(t)
		form := url.Values{"note": {oversized}}
		r := httptest.NewRequest(http.MethodPost, "/wallet/allocate", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, r)

		// 403 here would mean the CSRF check won the race — which it can only
		// do by having read the whole oversized body first.
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("POST /wallet/allocate with an oversized body = %d, want 413", rec.Code)
		}
	})

	// A form under the cap must be unaffected: a size limit that also rejects
	// ordinary submissions is an outage, not a control.
	t.Run("an ordinary form still works", func(t *testing.T) {
		cookie := h.login(t)
		if rec := h.postForm(t, "/settings", cookie, url.Values{
			"log_level": {"debug"},
		}); rec.Code >= http.StatusBadRequest {
			t.Errorf("an ordinary settings POST = %d; the cap rejects legitimate forms", rec.Code)
		}
	})
}

// The cap is installed by Compose, for every route, not by the form readers.
// That distinction is the whole point of moving it there — and it is invisible
// to the test above, which reaches the cap through readForm and would still
// pass if Compose did nothing.
//
// So: a handler that reads r.Body ITSELF, registered on a bare route with no
// form parsing anywhere in the chain. If the cap has slipped back down into
// readForm, this handler reads whatever the caller chose to send.
func TestComposeCapsBodiesForHandlersThatNeverParseAForm(t *testing.T) {
	var readErr error
	admin := api.NewAdminMux()
	admin.HandleFunc("/swallow", func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	})
	nothing := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	handler := api.Compose(api.NewPublicMux(nothing, nothing, nothing), admin)

	body := strings.NewReader(strings.Repeat("x", api.MaxFormBytes+1))
	r := httptest.NewRequest(http.MethodPost, "/swallow", body)
	handler.ServeHTTP(httptest.NewRecorder(), r)

	var tooLarge *http.MaxBytesError
	if !errors.As(readErr, &tooLarge) {
		t.Errorf("a handler reading r.Body directly got err=%v; the body cap is not "+
			"installed at the composition point, so it covers only the routes that "+
			"remembered to ask for it", readErr)
	}
}
