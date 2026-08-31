package api

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// SessionCookieName is the admin session cookie.
const SessionCookieName = "brollyzapper_session"

// LoginCookieName holds the pre-authentication CSRF nonce.
//
// It is a different cookie from the session on purpose. The login form needs a
// CSRF token before anyone is logged in, and issuing a real session to hand one
// out would mean that fetching the login page authenticated the caller — the
// password would be decorative.
const LoginCookieName = "brollyzapper_login"

// CSRFField is the form field every mutating admin form must carry (§9).
const CSRFField = "csrf_token"

// sessionCookieVersion prefixes the cookie so its shape can change without a
// stale cookie being misread as a valid one. Version 1 carried only an expiry
// and a nonce; version 2 adds the issue time, because a sliding idle window and
// an absolute lifetime are two deadlines and the cookie has to carry both.
const sessionCookieVersion = "2"

// Session is one logged-in admin session.
//
// It is signed rather than stored: the payload is an issue time, an idle
// deadline and a nonce, and the HMAC over those plus the current session
// generation is what makes it unforgeable AND revocable. That keeps per-session
// state out of a database whose backup is a user-visible artefact, while still
// letting one settings row end every session at once (d46.28).
type Session struct {
	ExpiresAt time.Time
	// CSRFToken is derived from the session nonce, so it needs no storage of
	// its own and cannot be replayed against a different session.
	CSRFToken string

	// issuedAt and nonce are what a renewal re-signs. The nonce is carried
	// across unchanged on purpose: it is what the CSRF token is derived from,
	// and rotating it under a rendered form wedges every copy of that form on
	// screen — the shape of d46.17, one layer down.
	issuedAt time.Time
	nonce    string
}

// StartSession issues a session cookie and returns the session it represents,
// so a caller that needs the CSRF token immediately — the login form — does not
// have to read its own Set-Cookie header back.
func (a *Auth) StartSession(w http.ResponseWriter, r *http.Request) Session {
	return a.issue(w, r, a.now(), secret.RandomToken(16))
}

// issue writes the cookie for a session that began at issuedAt.
//
// The cookie carries the IDLE deadline only. The absolute cap is enforced in
// Session() from issuedAt, which the cookie also carries and the MAC covers.
//
// Deliberately not the sooner of the two. Clamping the cookie's deadline to the
// absolute cap as well would put the same rule in two places, and the copy in
// Session() would then be unreachable — a live-looking check that can never
// fire, with a test that reads as though it exercised it while actually
// exercising the clamp. One deadline on the wire, both bounds checked in one
// place. The cost is that a browser may hold a cookie for up to an idle window
// past the absolute cap and be told to sign in when it presents it, which is
// the correct answer arriving from the server rather than from the browser.
func (a *Auth) issue(w http.ResponseWriter, r *http.Request, issuedAt time.Time, nonce string) Session {
	expires := a.now().Add(SessionIdleWindow)
	payload := strconv.FormatInt(issuedAt.Unix(), 10) + "." +
		strconv.FormatInt(expires.Unix(), 10) + "." + nonce

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionCookieVersion + "." + payload + "." + a.mac(a.bind(payload)),
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),
	})
	return Session{ExpiresAt: expires, CSRFToken: a.csrfToken(nonce), issuedAt: issuedAt, nonce: nonce}
}

// bind folds the current session generation into what the MAC covers.
//
// This is the whole of revocation: nothing stores which sessions exist, so
// there is nothing to delete — but a cookie signed under generation N stops
// verifying the moment the counter reaches N+1, and every cookie ever issued
// does so at once (d46.28).
func (a *Auth) bind(payload string) string {
	return payload + "." + strconv.FormatInt(a.generation.Load(), 10)
}

// LoginFormWindow is how long a rendered login form stays submittable. It is
// refreshed every time the form is rendered, so it bounds how long a form may
// sit unattended rather than how long the operator has to arrive.
const LoginFormWindow = 15 * time.Minute

// LoginForm returns the CSRF token the login form must echo back, REUSING the
// caller's nonce when they already have a valid one. It confers no authority of
// any kind.
//
// Reuse is the correctness half, not an optimisation (d46.17). Minting on every
// GET invalidated the token in every copy of the form already rendered, so a
// second tab, a prefetch, a redirect from / or a revalidating reload silently
// wedged the form on screen — and because the page carried no cache directives,
// the copy on screen could outlive several rotations. A CSRF nonce needs to be
// unpredictable and bound to the caller; it does not need to be fresh.
//
// The cookie is (re)issued either way, so the window tracks the last render.
func (a *Auth) LoginForm(w http.ResponseWriter, r *http.Request) string {
	nonce, ok := a.loginNonce(r)
	if !ok {
		nonce = secret.RandomToken(16)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     LoginCookieName,
		Value:    nonce + "." + a.mac("login:"+nonce),
		Path:     "/login",
		MaxAge:   int(LoginFormWindow.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),
	})
	return a.csrfToken(nonce)
}

// LoginFormToken returns the CSRF token the caller's login form should carry.
func (a *Auth) LoginFormToken(r *http.Request) (string, bool) {
	nonce, ok := a.loginNonce(r)
	if !ok {
		return "", false
	}
	return a.csrfToken(nonce), true
}

// csrfToken derives a form token from a nonce. Both cookies use it, and it is
// one function so the derivation cannot drift between the four sites that need
// it — a token derived one way and checked another is an unexplainable 403.
func (a *Auth) csrfToken(nonce string) string { return a.mac("csrf:" + nonce) }

// loginNonce returns the nonce in a present, well-formed, correctly signed
// login cookie.
func (a *Auth) loginNonce(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(LoginCookieName)
	if err != nil {
		return "", false
	}
	nonce, mac, found := strings.Cut(cookie.Value, ".")
	if !found || subtle.ConstantTimeCompare([]byte(a.mac("login:"+nonce)), []byte(mac)) != 1 {
		return "", false
	}
	return nonce, true
}

// EndSession clears the caller's own cookies, and nothing else.
//
// Signing out must ALSO end every other session (d46.28), but that is
// EndEverySession and the sign-out handler calls both. Two names for two
// effects: a single EndSession that quietly revoked globally would be a
// function whose name described half of what it did, and the next caller —
// "Disable sending", say — would get the other half without asking for it.
func (a *Auth) EndSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     LoginCookieName,
		Value:    "",
		Path:     "/login",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Session returns the caller's session, if the cookie is present, well-formed,
// correctly signed and unexpired.
func (a *Auth) Session(r *http.Request) (Session, bool) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return Session{}, false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 5 || parts[0] != sessionCookieVersion {
		return Session{}, false
	}
	payload := parts[1] + "." + parts[2] + "." + parts[3]
	// The generation is folded in here, so a bumped counter fails this compare
	// and every session ends at once.
	if subtle.ConstantTimeCompare([]byte(a.mac(a.bind(payload))), []byte(parts[4])) != 1 {
		return Session{}, false
	}
	issuedAt, ok := unixSeconds(parts[1])
	if !ok {
		return Session{}, false
	}
	expires, ok := unixSeconds(parts[2])
	if !ok {
		return Session{}, false
	}
	now := a.now()
	// Both deadlines are enforced HERE and only here: the sliding idle window
	// carried in the cookie, and the absolute lifetime measured from the
	// original sign-in. A renewal moves the first; nothing moves the second,
	// because issuedAt is carried across unchanged and the MAC covers it.
	if !now.Before(expires) || !now.Before(issuedAt.Add(SessionLifetime)) {
		return Session{}, false
	}
	return Session{
		ExpiresAt: expires,
		CSRFToken: a.csrfToken(parts[3]),
		issuedAt:  issuedAt,
		nonce:     parts[3],
	}, true
}

func unixSeconds(value string) (time.Time, bool) {
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0).UTC(), true
}

// RequireSession is the admin group's gate: a valid session, and on a mutating
// request a matching CSRF token.
//
// It exists only on the admin mux. The public group is built by a constructor
// that is not given an Auth at all, so there is no auth path there to skip
// rather than auth that happens to pass (§11).
func (a *Auth) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := a.Session(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// Slide the idle window. Only once the window is more than half spent:
		// renewing on every request would put a Set-Cookie on every admin
		// response for no benefit, and it would race the sign-out handler's own
		// cookie-clearing on the one request where that matters.
		if session.ExpiresAt.Sub(a.now()) < SessionIdleWindow/2 {
			a.issue(w, r, session.issuedAt, session.nonce)
		}
		if isMutating(r.Method) {
			// Before the comparison below, not after: ParseForm is what reads
			// the token out of the body, so the size cap has to be in place
			// first or it is bounding a read that already happened (L6).
			if !readForm(w, r) {
				return
			}
			supplied := r.PostFormValue(CSRFField)
			if subtle.ConstantTimeCompare([]byte(supplied), []byte(session.CSRFToken)) != 1 {
				http.Error(w, "missing or invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(contextWithSession(r.Context(), session)))
	})
}

func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// isHTTPS decides whether to mark the cookie Secure. Off Umbrel the app may
// legitimately be reached over plain HTTP on a LAN, where a Secure cookie would
// simply never be sent back.
func isHTTPS(r *http.Request) bool {
	return r != nil && (r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https")
}
