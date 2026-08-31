package api_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

// d46.28 criterion 1, review L1. Sessions are signed rather than stored, so
// there was nothing to delete: signing out cleared the cookie in the browser
// doing the clearing and nothing else. A copy taken from a machine the operator
// had walked away from kept working for the rest of the week — and on Umbrel
// SESSION_SECRET is derived deterministically per install, so not even
// restarting the app evicted it.
//
// The copy is the whole point of the test. Asserting that the signing-out
// browser is signed out would have passed before the fix.
func TestSigningOutRejectsACookieCopiedBeforehand(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)
	copied := *cookie

	if h.get(t, "/", &copied).Code != http.StatusOK {
		t.Fatal("the copied cookie did not work before sign-out; the test proves nothing")
	}

	if rec := h.postForm(t, "/logout", cookie, url.Values{}); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /logout = %d %q, want 303", rec.Code, rec.Body)
	}

	if rec := h.get(t, "/", &copied); rec.Code == http.StatusOK {
		t.Error("a cookie copied before sign-out still reached an admin page; " +
			"signing out has to end every session, not one browser's")
	}
}

// The durable half. The counter lives in settings because SESSION_SECRET is
// stable across restarts on Umbrel, so an in-memory-only counter would let
// every revoked session come back the next time the app started.
func TestTheRevocationSurvivesARestart(t *testing.T) {
	db := newTestStore(t)
	clock := func() time.Time { return authTime }
	build := func() *api.Auth {
		return newAuthOver(t, db, "umbrel-derived-password", testSessionSecret, clock)
	}

	before := build()
	rec := httptest.NewRecorder()
	before.StartSession(rec, httptest.NewRequest(http.MethodPost, "/login", nil))
	cookie := rec.Result().Cookies()[0]

	before.EndSession(httptest.NewRecorder())
	if err := before.EndEverySession(t.Context()); err != nil {
		t.Fatalf("EndEverySession: %v", err)
	}

	// Same database, same signing secret, a new process.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)
	if _, ok := build().Session(r); ok {
		t.Error("a session revoked before a restart authenticated after it; the counter " +
			"is not being persisted, and on Umbrel the signing secret is stable")
	}
}

// Changing the password is the other thing an operator does when they believe
// somebody else has a session. A new password that left the old sessions
// running answers that with a no.
func TestChangingThePasswordEndsEverySession(t *testing.T) {
	// No APP_PASSWORD: on Umbrel the password is managed there and cannot be
	// changed here at all (§9), so this is the off-Umbrel case.
	// No APP_PASSWORD is the variation this test turns on, so it is the one
	// argument spelled out rather than shared.
	auth := newAuthOver(t, newTestStore(t), "", testSessionSecret,
		func() time.Time { return authTime })
	current := auth.GeneratedPassword()

	rec := httptest.NewRecorder()
	auth.StartSession(rec, httptest.NewRequest(http.MethodPost, "/login", nil))
	cookie := rec.Result().Cookies()[0]

	if err := auth.ChangePassword(t.Context(), current, secret.New("a-much-longer-password")); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)
	if _, ok := auth.Session(r); ok {
		t.Error("a session issued under the old password still authenticated")
	}
}

// d46.28 criterion 2, ruled 22 Aug 2026: 24h sliding, adopted. A seven-day
// absolute lifetime with no idle timeout, on an app that can be made to spend,
// leaves a session left behind on a borrowed machine live for a week.
//
// Both halves are asserted. An idle window that also ended ACTIVE sessions
// would sign the operator out mid-afternoon, which is the failure that makes
// people turn timeouts off.
func TestASessionIdlePastTheWindowIsRejectedAndAnActiveOneIsNot(t *testing.T) {
	now := authTime
	auth := newAuthOver(t, newTestStore(t), "umbrel-derived-password", testSessionSecret,
		func() time.Time { return now })
	authenticated := auth.RequireSession(marker("served"))

	// use makes one authenticated request and returns the cookie the response
	// leaves the browser holding — which is how a sliding window actually
	// works: the deadline moves because the server re-issues.
	use := func(cookie *http.Cookie) (*http.Cookie, int) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(cookie)
		out := httptest.NewRecorder()
		authenticated.ServeHTTP(out, r)
		if renewed := sessionCookie(out); renewed != nil {
			return renewed, out.Code
		}
		return cookie, out.Code
	}

	start := httptest.NewRecorder()
	auth.StartSession(start, httptest.NewRequest(http.MethodPost, "/login", nil))
	cookie := start.Result().Cookies()[0]

	// Used daily for a fortnight's worth of ticks — except the absolute cap
	// stops it at seven days, which the next test covers. Three days here.
	for day := range 3 {
		now = now.Add(20 * time.Hour)
		var code int
		if cookie, code = use(cookie); code != http.StatusOK {
			t.Fatalf("day %d: an actively used session was refused (%d); a sliding "+
				"window must not end sessions that are in use", day+1, code)
		}
	}

	// Now leave it alone for longer than the window.
	now = now.Add(api.SessionIdleWindow + time.Minute)
	if _, code := use(cookie); code == http.StatusOK {
		t.Errorf("a session idle for %s still authenticated", api.SessionIdleWindow+time.Minute)
	}
}

// The absolute cap is the other bound, and a renewal must never be able to push
// a session past it: otherwise "24h sliding" quietly means "forever, as long as
// somebody keeps using it", which is exactly the property a stolen session has.
func TestNoAmountOfUseExtendsASessionPastItsAbsoluteLifetime(t *testing.T) {
	now := authTime
	auth := newAuthOver(t, newTestStore(t), "umbrel-derived-password", testSessionSecret,
		func() time.Time { return now })
	authenticated := auth.RequireSession(marker("served"))

	start := httptest.NewRecorder()
	auth.StartSession(start, httptest.NewRequest(http.MethodPost, "/login", nil))
	cookie := start.Result().Cookies()[0]

	lastGood := time.Duration(0)
	for elapsed := time.Duration(0); elapsed < 10*24*time.Hour; elapsed += 6 * time.Hour {
		now = authTime.Add(elapsed)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(cookie)
		out := httptest.NewRecorder()
		authenticated.ServeHTTP(out, r)
		if out.Code != http.StatusOK {
			break
		}
		lastGood = elapsed
		if renewed := sessionCookie(out); renewed != nil {
			cookie = renewed
		}
	}
	if lastGood >= api.SessionLifetime {
		t.Errorf("a continuously used session was still valid %s after sign-in; the "+
			"absolute lifetime is %s and a renewal must not move it",
			lastGood, api.SessionLifetime)
	}
	if lastGood < api.SessionLifetime-12*time.Hour {
		t.Errorf("a continuously used session died after only %s; the absolute "+
			"lifetime is %s", lastGood, api.SessionLifetime)
	}
}

// d46.28 criterion 3. Signing out now ends sessions the operator cannot see, so
// the page has to say so — a security property nobody is told about does not
// change what anybody does.
func TestSigningOutSaysThatEverySessionEnded(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	rec := h.postForm(t, "/logout", cookie, url.Values{})
	where := rec.Header().Get("Location")
	if where == "" {
		t.Fatalf("logout did not redirect: %d", rec.Code)
	}
	page := h.get(t, where, nil).Body.String()
	for _, phrase := range []string{"every session", "sign in again"} {
		if !strings.Contains(strings.ToLower(page), phrase) {
			t.Errorf("the page after sign-out does not say %q, so the operator is not "+
				"told that other devices were signed out too:\n%s", phrase, page)
		}
	}
}

// The counter must not be readable as a settings field or writable through the
// Settings form: an operator who could edit it could set it backwards and
// revive every session they had just ended.
func TestTheSessionGenerationIsNotASettingsFormField(t *testing.T) {
	h := newHarness(t, func(_ *api.ServerOptions, db *store.Store) {
		if err := db.SetSetting(t.Context(), api.SettingSessionGeneration, "5"); err != nil {
			t.Fatalf("seeding: %v", err)
		}
	})
	page := h.get(t, "/settings", h.login(t)).Body.String()
	if strings.Contains(page, api.SettingSessionGeneration) {
		t.Errorf("the Settings form carries %q", api.SettingSessionGeneration)
	}
}

// The sliding window re-issues the cookie, and a re-issue that minted a fresh
// nonce would rotate the CSRF token underneath every form already on screen —
// d46.17's defect, one layer down and arriving on a timer rather than on a
// second GET. The renewal carries the nonce across; this is what says so.
func TestARenewalKeepsTheCSRFTokenStable(t *testing.T) {
	now := authTime
	auth := newAuthOver(t, newTestStore(t), "umbrel-derived-password", testSessionSecret,
		func() time.Time { return now })

	start := httptest.NewRecorder()
	first := auth.StartSession(start, httptest.NewRequest(http.MethodPost, "/login", nil))
	cookie := start.Result().Cookies()[0]

	// Far enough in for the renewal condition to fire.
	now = now.Add(api.SessionIdleWindow - time.Hour)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)
	out := httptest.NewRecorder()
	auth.RequireSession(marker("served")).ServeHTTP(out, r)
	if out.Code != http.StatusOK {
		t.Fatalf("the session was refused before it could be renewed: %d", out.Code)
	}

	renewed := sessionCookie(out)
	if renewed == nil {
		t.Fatal("no cookie was re-issued, so the window did not slide at all")
	}
	if renewed.Value == cookie.Value {
		t.Fatal("the re-issued cookie is byte-identical, so the deadline did not move")
	}

	after := httptest.NewRequest(http.MethodGet, "/", nil)
	after.AddCookie(renewed)
	session, ok := auth.Session(after)
	if !ok {
		t.Fatal("the renewed cookie does not authenticate")
	}
	if session.CSRFToken != first.CSRFToken {
		t.Error("the renewal rotated the CSRF token, so every form already rendered " +
			"in the operator's browser is now wedged (d46.17)")
	}
}
