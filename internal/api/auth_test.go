package api_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

var authTime = time.Unix(1_700_000_000, 0).UTC()

func newAuth(t *testing.T, appPassword string) (*api.Auth, *store.Store) {
	t.Helper()
	return newAuthWithSecret(t, appPassword, "0123456789abcdef0123456789abcdef")
}

func newAuthWithSecret(t *testing.T, appPassword, sessionSecret string) (*api.Auth, *store.Store) {
	t.Helper()
	db := newTestStore(t)
	return newAuthOver(t, db, appPassword, sessionSecret, func() time.Time { return authTime }), db
}

// newAuthOver builds an Auth over a store the caller already has, on a clock
// the caller controls. The session tests need both: one rebuilds Auth over the
// same database to stand in for a restart, and the idle-window tests move time.
func newAuthOver(t *testing.T, db *store.Store, appPassword, sessionSecret string,
	now func() time.Time) *api.Auth {
	t.Helper()
	auth, err := api.NewAuth(t.Context(), db, api.AuthOptions{
		AppPassword:   secret.New(appPassword),
		SessionSecret: secret.New(sessionSecret),
		Now:           now,
	})
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	return auth
}

// testSessionSecret is the signing key every session test shares. Spelled once:
// a literal repeated across six constructions is six places to change.
const testSessionSecret = "0123456789abcdef0123456789abcdef"

// Spec §9: argon2id, and the hash must not be the password.
func TestPasswordsAreStoredAsArgon2idHashes(t *testing.T) {
	auth, db := newAuth(t, "umbrel-derived-password")
	stored, ok, err := db.Setting(t.Context(), api.SettingAdminPasswordHash)
	if err != nil || !ok {
		t.Fatalf("the password hash was not stored: ok=%v err=%v", ok, err)
	}
	if !strings.HasPrefix(stored, "$argon2id$") {
		t.Errorf("stored hash %q is not an argon2id PHC string", stored)
	}
	if strings.Contains(stored, "umbrel-derived-password") {
		t.Error("the stored hash contains the password")
	}
	if !auth.Verify(t.Context(), secret.New("umbrel-derived-password")) {
		t.Error("the correct password did not verify")
	}
	if auth.Verify(t.Context(), secret.New("wrong")) {
		t.Error("an incorrect password verified")
	}
}

// Spec §9: APP_PASSWORD seeds the stored hash ONLY when no hash exists yet.
func TestAppPasswordSeedsOnlyWhenNoHashExists(t *testing.T) {
	db := newTestStore(t)
	opts := api.AuthOptions{
		AppPassword:   secret.New("first-password-value"),
		SessionSecret: secret.New("0123456789abcdef0123456789abcdef"),
		Now:           func() time.Time { return authTime },
	}
	first, err := api.NewAuth(t.Context(), db, opts)
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	hashBefore, _, _ := db.Setting(t.Context(), api.SettingAdminPasswordHash)

	// A restart with a DIFFERENT APP_PASSWORD must not silently reseed: the
	// stored hash is the truth once it exists.
	opts.AppPassword = secret.New("second-password-value")
	second, err := api.NewAuth(t.Context(), db, opts)
	if err != nil {
		t.Fatalf("NewAuth on an existing install: %v", err)
	}
	hashAfter, _, _ := db.Setting(t.Context(), api.SettingAdminPasswordHash)
	if hashBefore != hashAfter {
		t.Error("a second start reseeded the password hash")
	}
	if !second.Verify(t.Context(), secret.New("first-password-value")) {
		t.Error("the original password stopped working after a restart")
	}
	_ = first
}

// Spec §9: when APP_PASSWORD is set, Settings offers no password change —
// otherwise umbrelOS would display a value that is silently wrong.
func TestPasswordIsUmbrelManagedWhenAppPasswordIsSet(t *testing.T) {
	auth, _ := newAuth(t, "umbrel-derived-password")
	if auth.PasswordChangeable() {
		t.Error("PasswordChangeable() = true with APP_PASSWORD set; umbrelOS would show a stale value")
	}
	err := auth.ChangePassword(t.Context(), secret.New("umbrel-derived-password"), secret.New("something-else"))
	if err == nil {
		t.Fatal("ChangePassword succeeded with APP_PASSWORD set")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "umbrel") {
		t.Errorf("error %q does not explain that the password is Umbrel-managed", err)
	}
}

// ...and off Umbrel, where the variable is absent, it IS changeable.
func TestPasswordIsChangeableOffUmbrel(t *testing.T) {
	auth, _ := newAuth(t, "")
	if !auth.PasswordChangeable() {
		t.Fatal("PasswordChangeable() = false with no APP_PASSWORD; off Umbrel this is the only layer")
	}
	generated := auth.GeneratedPassword()
	if generated.IsZero() {
		t.Fatal("no password was generated on first run")
	}
	if err := auth.ChangePassword(t.Context(), generated, secret.New("a-new-long-password")); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if auth.Verify(t.Context(), generated) {
		t.Error("the old password still verifies after a change")
	}
	if !auth.Verify(t.Context(), secret.New("a-new-long-password")) {
		t.Error("the new password does not verify")
	}
	if err := auth.ChangePassword(t.Context(), secret.New("wrong-old"), secret.New("another-password")); err == nil {
		t.Error("ChangePassword accepted a wrong current password")
	}
}

// Spec §9: first run generates a password and shows it IN THE BROWSER. A
// password that exists only in the logs fails this.
func TestGeneratedPasswordIsAvailableToRenderAndIsLongEnough(t *testing.T) {
	auth, _ := newAuth(t, "")
	generated := auth.GeneratedPassword()
	if generated.IsZero() {
		t.Fatal("first run generated no password")
	}
	if len(generated.Reveal()) < 16 {
		t.Errorf("generated password is %d characters, want at least 16", len(generated.Reveal()))
	}
	// It must not be rendered by a log line: the type refuses to serialise.
	if got := generated.String(); strings.Contains(got, generated.Reveal()) {
		t.Error("the generated password renders itself in string form")
	}
}

func TestSessionCookieRoundTrips(t *testing.T) {
	auth, _ := newAuth(t, "umbrel-derived-password")
	rec := httptest.NewRecorder()
	auth.StartSession(rec, httptest.NewRequest(http.MethodPost, "/login", nil))

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("StartSession set %d cookies, want 1", len(cookies))
	}
	cookie := cookies[0]
	if !cookie.HttpOnly {
		t.Error("the session cookie is not HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode && cookie.SameSite != http.SameSiteStrictMode {
		t.Error("the session cookie has no SameSite protection")
	}

	r := httptest.NewRequest(http.MethodGet, "/wallet", nil)
	r.AddCookie(cookie)
	session, ok := auth.Session(r)
	if !ok {
		t.Fatal("a freshly issued cookie did not authenticate")
	}
	if session.CSRFToken == "" {
		t.Error("the session carries no CSRF token")
	}
}

func TestATamperedOrExpiredSessionIsRejected(t *testing.T) {
	auth, _ := newAuth(t, "umbrel-derived-password")
	rec := httptest.NewRecorder()
	auth.StartSession(rec, httptest.NewRequest(http.MethodPost, "/login", nil))
	cookie := rec.Result().Cookies()[0]

	tampered := *cookie
	tampered.Value = cookie.Value[:len(cookie.Value)-2] + "xy"
	r := httptest.NewRequest(http.MethodGet, "/wallet", nil)
	r.AddCookie(&tampered)
	if _, ok := auth.Session(r); ok {
		t.Error("a tampered session cookie authenticated")
	}

	// A cookie signed with a different secret must not carry over. Umbrel
	// derives SESSION_SECRET deterministically per install, so the same secret
	// deliberately DOES survive a restart — it is a different secret, not a
	// different process, that must invalidate a session.
	other, _ := newAuthWithSecret(t, "other-password-value", "ffffffffffffffffffffffffffffffff")
	r = httptest.NewRequest(http.MethodGet, "/wallet", nil)
	r.AddCookie(cookie)
	if _, ok := other.Session(r); ok {
		t.Error("a session signed with a different SESSION_SECRET authenticated")
	}
}

// A session must not outlive its expiry.
func TestAnExpiredSessionIsRejected(t *testing.T) {
	auth, _ := newAuth(t, "umbrel-derived-password")
	rec := httptest.NewRecorder()
	auth.StartSession(rec, httptest.NewRequest(http.MethodPost, "/login", nil))
	cookie := rec.Result().Cookies()[0]

	// Same signing secret, a clock past the expiry stamped into the cookie.
	later, _ := api.NewAuth(t.Context(), newTestStore(t), api.AuthOptions{
		AppPassword:   secret.New("umbrel-derived-password"),
		SessionSecret: secret.New("0123456789abcdef0123456789abcdef"),
		Now:           func() time.Time { return authTime.Add(api.SessionLifetime + time.Minute) },
	})
	r := httptest.NewRequest(http.MethodGet, "/wallet", nil)
	r.AddCookie(cookie)
	if _, ok := later.Session(r); ok {
		t.Error("a session past its expiry still authenticated")
	}
}

// newTestStore opens a throwaway database. Every test in this package that
// needs one goes through here.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// Spec §9: CSRF token on every mutating form. A mutating POST without a valid
// token is rejected.
func TestMutatingRequestsRequireACSRFToken(t *testing.T) {
	auth, _ := newAuth(t, "umbrel-derived-password")
	rec := httptest.NewRecorder()
	auth.StartSession(rec, httptest.NewRequest(http.MethodPost, "/login", nil))
	cookie := rec.Result().Cookies()[0]

	authenticated := auth.RequireSession(marker("served"))

	post := func(token string) *httptest.ResponseRecorder {
		body := strings.NewReader("csrf_token=" + token + "&amount=1000")
		r := httptest.NewRequest(http.MethodPost, "/wallet/allocate", body)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(cookie)
		out := httptest.NewRecorder()
		authenticated.ServeHTTP(out, r)
		return out
	}

	r := httptest.NewRequest(http.MethodGet, "/wallet", nil)
	r.AddCookie(cookie)
	session, _ := auth.Session(r)

	if got := post(session.CSRFToken); got.Code != http.StatusOK {
		t.Errorf("a POST with a valid CSRF token = %d, want 200", got.Code)
	}
	if got := post(""); got.Code != http.StatusForbidden {
		t.Errorf("a POST with no CSRF token = %d, want 403", got.Code)
	}
	if got := post("not-the-token"); got.Code != http.StatusForbidden {
		t.Errorf("a POST with a wrong CSRF token = %d, want 403", got.Code)
	}
}

func TestUnauthenticatedAdminRequestsAreRefused(t *testing.T) {
	auth, _ := newAuth(t, "umbrel-derived-password")
	authenticated := auth.RequireSession(marker("served"))

	rec := httptest.NewRecorder()
	authenticated.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet", nil))
	if rec.Code == http.StatusOK {
		t.Errorf("an unauthenticated admin request was served: %d %s", rec.Code, rec.Body)
	}
	if rec.Body.String() == "served" {
		t.Error("the handler ran without a session")
	}
}
