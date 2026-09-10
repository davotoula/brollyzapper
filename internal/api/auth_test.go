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

// THE TWO FIXTURES ARE NAMED, because since `20i.5` the difference between them
// is a flag and not the presence of a password. Both deployments supply one;
// what differs is whether the PLATFORM owns it. A helper taking only a password
// could no longer express that, and the old one silently meant "managed" purely
// because a value was passed — which is the bug this bead removes.
const (
	umbrelPassword = "umbrel-derived-password"
	// plainPassword is the other half of the pair: a password the OPERATOR
	// chose, on a deployment nothing else is displaying it from. The two are
	// spelled together because since `20i.5` the difference between the
	// fixtures is the flag and not the password, and a reader comparing them
	// should see that.
	plainPassword = "the-operator-chose-this"
)

// newManagedAuth is the umbrelOS fixture: the platform supplied the password and
// displays it, so Settings must not offer a change.
func newManagedAuth(t *testing.T) (*api.Auth, *store.Store) {
	t.Helper()
	return newAuthWithSecret(t, umbrelPassword, true, testSessionSecret)
}

// newPlainAuth is the plain-Docker fixture: the operator put the password in
// .env themselves, nobody else is displaying it, and they may change it.
func newPlainAuth(t *testing.T, adminPassword string) (*api.Auth, *store.Store) {
	t.Helper()
	return newAuthWithSecret(t, adminPassword, false, testSessionSecret)
}

func newAuthWithSecret(t *testing.T, adminPassword string, managed bool,
	sessionSecret string) (*api.Auth, *store.Store) {
	t.Helper()
	db := newTestStore(t)
	return newAuthOver(t, db, adminPassword, managed, sessionSecret,
		func() time.Time { return authTime }), db
}

// newAuthOver builds an Auth over a store the caller already has, on a clock
// the caller controls. The session tests need both: one rebuilds Auth over the
// same database to stand in for a restart, and the idle-window tests move time.
func newAuthOver(t *testing.T, db *store.Store, adminPassword string, managed bool,
	sessionSecret string, now func() time.Time) *api.Auth {
	t.Helper()
	auth, err := api.NewAuth(t.Context(), db, api.AuthOptions{
		AdminPassword:   secret.New(adminPassword),
		PasswordManaged: managed,
		SessionSecret:   secret.New(sessionSecret),
		Now:             now,
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
	auth, db := newManagedAuth(t)
	stored, ok, err := db.Setting(t.Context(), api.SettingAdminPasswordHash)
	if err != nil || !ok {
		t.Fatalf("the password hash was not stored: ok=%v err=%v", ok, err)
	}
	if !strings.HasPrefix(stored, "$argon2id$") {
		t.Errorf("stored hash %q is not an argon2id PHC string", stored)
	}
	if strings.Contains(stored, umbrelPassword) {
		t.Error("the stored hash contains the password")
	}
	if !auth.Verify(t.Context(), secret.New(umbrelPassword)) {
		t.Error("the correct password did not verify")
	}
	if auth.Verify(t.Context(), secret.New("wrong")) {
		t.Error("an incorrect password verified")
	}
}

// Spec §9: APP_PASSWORD seeds the stored hash ONLY when no hash exists yet.
func TestAdminPasswordSeedsOnlyWhenNoHashExists(t *testing.T) {
	db := newTestStore(t)
	opts := api.AuthOptions{
		AdminPassword: secret.New("first-password-value"),
		SessionSecret: secret.New(testSessionSecret),
		Now:           func() time.Time { return authTime },
	}
	first, err := api.NewAuth(t.Context(), db, opts)
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	hashBefore, _, _ := db.Setting(t.Context(), api.SettingAdminPasswordHash)

	// A restart with a DIFFERENT APP_PASSWORD must not silently reseed: the
	// stored hash is the truth once it exists.
	opts.AdminPassword = secret.New("second-password-value")
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

// Spec §9: when the PLATFORM manages the password, Settings offers no change —
// otherwise umbrelOS would display a value that is silently wrong.
func TestPasswordIsManagedWhenTheDeploymentSaysSo(t *testing.T) {
	auth, _ := newManagedAuth(t)
	if auth.PasswordChangeable() {
		t.Error("PasswordChangeable() = true on the managed fixture; umbrelOS would show a stale value")
	}
	err := auth.ChangePassword(t.Context(), secret.New(umbrelPassword), secret.New("something-else"))
	if err == nil {
		t.Fatal("ChangePassword succeeded on the managed fixture")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "umbrel") {
		t.Errorf("error %q does not explain that the password is Umbrel-managed", err)
	}
}

// ...and off Umbrel it IS changeable — WITH A PASSWORD SET, which is the whole
// point of `20i.5`. This fixture is the one that used to be indistinguishable
// from the one above: both supply a password, and until the flag existed that
// was the only thing the app looked at, so this operator was refused a change
// on a credential nobody else was showing them.
func TestPasswordIsChangeableOffUmbrelEvenThoughOneWasSupplied(t *testing.T) {
	auth, _ := newPlainAuth(t, plainPassword)
	if !auth.PasswordChangeable() {
		t.Fatal("PasswordChangeable() = false on the plain fixture, which supplies a password " +
			"exactly as the managed one does; the flag is what must separate them")
	}
	if err := auth.ChangePassword(t.Context(), secret.New(plainPassword), secret.New("a-new-long-password")); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if auth.Verify(t.Context(), secret.New(plainPassword)) {
		t.Error("the old password still verifies after a change")
	}
	if !auth.Verify(t.Context(), secret.New("a-new-long-password")) {
		t.Error("the new password does not verify")
	}
	if err := auth.ChangePassword(t.Context(), secret.New("wrong-old-password"), secret.New("another-password")); err == nil {
		t.Error("ChangePassword accepted a wrong current password")
	}
}

// The password is no longer optional, and NewAuth is the second line of that
// defence: internal/config refuses first, but a caller that got past it must
// not end up with a random credential nobody can read (`20i.5`).
func TestNewAuthRefusesToSeedWithNoPassword(t *testing.T) {
	_, err := api.NewAuth(t.Context(), newTestStore(t), api.AuthOptions{
		SessionSecret: secret.New(testSessionSecret),
	})
	if err == nil {
		t.Fatal("NewAuth accepted an empty password on an empty store; it used to invent one " +
			"and render it on a page behind the login it would have opened")
	}
	if !strings.Contains(err.Error(), "ADMIN_PASSWORD") {
		t.Errorf("error %q does not name the variable the operator has to set", err)
	}
}

func TestSessionCookieRoundTrips(t *testing.T) {
	auth, _ := newManagedAuth(t)
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
	auth, _ := newManagedAuth(t)
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
	other, _ := newAuthWithSecret(t, "other-password-value", true, "ffffffffffffffffffffffffffffffff")
	r = httptest.NewRequest(http.MethodGet, "/wallet", nil)
	r.AddCookie(cookie)
	if _, ok := other.Session(r); ok {
		t.Error("a session signed with a different SESSION_SECRET authenticated")
	}
}

// A session must not outlive its expiry.
func TestAnExpiredSessionIsRejected(t *testing.T) {
	auth, _ := newManagedAuth(t)
	rec := httptest.NewRecorder()
	auth.StartSession(rec, httptest.NewRequest(http.MethodPost, "/login", nil))
	cookie := rec.Result().Cookies()[0]

	// Same signing secret, a clock past the expiry stamped into the cookie.
	later := newAuthOver(t, newTestStore(t), umbrelPassword, true, testSessionSecret,
		func() time.Time { return authTime.Add(api.SessionLifetime + time.Minute) })
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
	auth, _ := newManagedAuth(t)
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
	auth, _ := newManagedAuth(t)
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
