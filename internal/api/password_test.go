package api_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

// zu5.5 criterion 1, and coverage analysis §3.7.
//
// A verifier that returns true on a malformed stored hash and one that returns
// (false, err) differ by a character, and until this table nothing here would
// have noticed. Every row is a way the stored string can be wrong — truncation,
// a half-written setting, a hand-edited row, a future format change — and every
// one of them must be a refusal rather than an accident that lets anybody in.
//
// The assertion is deliberately BOTH halves. (false, nil) would be safe but
// silent; (true, err) would be a caller that checks only one of them letting a
// stranger through. Auth.Verify checks err == nil && matched, so a hash that
// returned true WITH an error would still be refused there — but VerifyPassword
// is exported and the next caller may not be so careful.
func TestAMalformedStoredHashIsAlwaysARefusalAndAlwaysAnError(t *testing.T) {
	// A real hash, so the rows below differ from it only in the way each names.
	good, err := api.HashPassword(secret.New("a-much-longer-password"))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	parts := strings.Split(good, "$")

	for _, tc := range []struct {
		name   string
		stored string
	}{
		{"empty", ""},
		{"not a PHC string at all", "hunter2"},
		{"too few fields", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA"},
		{"too many fields", good + "$extra"},
		{"a different algorithm", strings.Replace(good, "argon2id", "argon2i", 1)},
		{"bcrypt, which is a plausible thing to find in an old row",
			"$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"},
		{"unreadable parameters", parts[0] + "$argon2id$" + parts[2] + "$m=lots,t=3,p=2$" +
			parts[4] + "$" + parts[5]},
		{"parameters in the wrong order", parts[0] + "$argon2id$" + parts[2] +
			"$t=3,m=65536,p=2$" + parts[4] + "$" + parts[5]},
		{"an unreadable salt", parts[0] + "$argon2id$" + parts[2] + "$" + parts[3] +
			"$not!base64$" + parts[5]},
		{"an unreadable hash", parts[0] + "$argon2id$" + parts[2] + "$" + parts[3] +
			"$" + parts[4] + "$not!base64"},
		// These three make argon2 PANIC rather than return, which is how the
		// login handler came to answer a corrupted settings row with a 500 and
		// a stack trace. They are here as rows, not as a separate test, because
		// they are the same fact: the stored string is not a credential.
		{"an empty hash, so the comparison has nothing to compare",
			parts[0] + "$argon2id$" + parts[2] + "$" + parts[3] + "$" + parts[4] + "$"},
		{"an empty salt", parts[0] + "$argon2id$" + parts[2] + "$" + parts[3] + "$$" + parts[5]},
		{"zero iterations", parts[0] + "$argon2id$" + parts[2] + "$m=65536,t=0,p=2$" +
			parts[4] + "$" + parts[5]},
		{"zero threads", parts[0] + "$argon2id$" + parts[2] + "$m=65536,t=3,p=0$" +
			parts[4] + "$" + parts[5]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := api.VerifyPassword(tc.stored, secret.New("a-much-longer-password"))
			if matched {
				t.Error("a malformed stored hash ACCEPTED a password")
			}
			if err == nil {
				t.Error("no error; the caller cannot tell a wrong password from an " +
					"unreadable credential, and one of those needs an operator")
			}
		})
	}

	// The control. A table of refusals passes against a verifier that refuses
	// everything, which would lock the operator out of their own box.
	matched, err := api.VerifyPassword(good, secret.New("a-much-longer-password"))
	if err != nil || !matched {
		t.Fatalf("the correct password against a real hash = %v, %v; the rows above would "+
			"all pass against a verifier that refuses everything", matched, err)
	}
}

// zu5.5 criterion 2. The minimum is 12, asserted at 11 and at 12 — an off-by-one
// in that comparison is invisible to any test that only tries "short" and "long".
func TestTheNewPasswordMinimumIsTwelveCharacters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		accepted bool
	}{
		{"eleven characters", strings.Repeat("a", 11), false},
		{"exactly twelve", strings.Repeat("a", 12), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestStore(t)
			auth := newAuthOver(t, db, "", testSessionSecret, func() time.Time { return authTime })
			err := auth.ChangePassword(t.Context(), auth.GeneratedPassword(),
				secret.New(tc.password))
			if tc.accepted && err != nil {
				t.Errorf("a %d-character password was refused: %v", len(tc.password), err)
			}
			if !tc.accepted {
				if err == nil {
					t.Errorf("a %d-character password was accepted", len(tc.password))
				} else if !strings.Contains(err.Error(), "minimum is 12") {
					t.Errorf("the refusal does not say what the minimum is: %v", err)
				}
			}
		})
	}
}

// zu5.5 criterion 3. The change-password form, end to end, which nothing drove:
// the handler was 0% cross-package.
//
// The half that matters is the last one. Changing the password is one of the two
// things an operator does when they believe somebody else has a session, and a
// new password that left the old sessions running would answer the question they
// were asking with a no (d46.28).
func TestChangingThePasswordThroughTheFormEndsTheOtherSessions(t *testing.T) {
	var auth *api.Auth
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		// No APP_PASSWORD: on Umbrel the password is managed there and the form
		// refuses outright, which is the case below.
		auth = newAuthOver(t, db, "", testSessionSecret, func() time.Time { return authTime })
		opts.Auth = auth
	})
	const replacement = "a-much-longer-password"
	// The hash the harness seeded is already in the store, and NewAuth only
	// bootstraps when there is none — so the replacement Auth above inherits
	// that credential and simply stops treating it as Umbrel-managed, which is
	// exactly the off-Umbrel case this needs.
	const old = "umbrel-derived-password"

	operator := signIn(t, h, old)
	// A second signed-in session — the one the operator is worried about.
	stranger := signIn(t, h, old)
	if h.get(t, "/", stranger).Code != http.StatusOK {
		t.Fatal("the second session did not sign in, so ending it later would prove nothing")
	}

	rec := h.postForm(t, "/settings/password", operator, url.Values{
		"current": {old}, "new": {replacement},
	})
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "saved") {
		t.Fatalf("POST /settings/password = %d %q", rec.Code, rec.Header().Get("Location"))
	}

	if auth.Verify(t.Context(), secret.New(old)) {
		t.Error("the old password still works")
	}
	if !auth.Verify(t.Context(), secret.New(replacement)) {
		t.Error("the new password does not work")
	}
	if h.get(t, "/", stranger).Code == http.StatusOK {
		t.Error("a session issued under the old password survived the change; the operator " +
			"changed it precisely to end that session")
	}
}

// signIn logs a fresh session in with a password the test chose. h.login hard-
// codes the Umbrel one, and these tests need a second session and a generated
// password.
func signIn(t *testing.T, h *harness, password string) *http.Cookie {
	t.Helper()
	b := h.browser()
	rec := b.submitLogin(t, csrfFrom(t, b.get(t, "/login").Body.String()), password)
	cookie := sessionCookie(rec)
	if cookie == nil {
		t.Fatalf("signing in issued no session: %d %s", rec.Code, rec.Body)
	}
	return cookie
}

// The Umbrel branch: there the password comes from the platform, so the form
// must refuse rather than write a hash the platform will overwrite — and it must
// say WHY, or the operator retypes it and wonders.
func TestTheFormRefusesWhenUmbrelOwnsThePassword(t *testing.T) {
	h := newHarness(t) // the default harness sets APP_PASSWORD
	cookie := h.login(t)

	rec := h.postForm(t, "/settings/password", cookie, url.Values{
		"current": {"umbrel-derived-password"}, "new": {"a-much-longer-password"},
	})
	if !strings.Contains(rec.Header().Get("Location"), "refused") {
		t.Errorf("the form did not refuse: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if err := h.auth.ChangePassword(t.Context(), secret.New("umbrel-derived-password"),
		secret.New("a-much-longer-password")); err == nil {
		t.Error("the password was changeable after all")
	} else if !strings.Contains(err.Error(), "managed by Umbrel") {
		t.Errorf("the reason does not name Umbrel: %v", err)
	}
	// And the platform's password still works, which is the point of refusing.
	if !h.auth.Verify(t.Context(), secret.New("umbrel-derived-password")) {
		t.Error("the refused change altered the stored hash anyway")
	}
}

// zu5.5 criterion 4. probeNow, which nothing drove: it is the button on the
// Security page that asks §9's self-probe to run now rather than on the hour.
func TestTheProbeNowButtonAsksForAProbe(t *testing.T) {
	demand := make(chan struct{}, 1)
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.ProbeDemand = demand
	})
	cookie := h.login(t)

	rec := h.postForm(t, "/settings/probe", cookie, url.Values{})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /settings/probe = %d %q", rec.Code, rec.Body)
	}
	select {
	case <-demand:
	default:
		t.Error("the button redirected but asked for no probe; the operator is told " +
			"'saved' and nothing happens")
	}
}
