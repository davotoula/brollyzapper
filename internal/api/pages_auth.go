package api

import (
	"crypto/subtle"
	"log/slog"
	"net/http"

	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/web"
)

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderLogin(w, r, "")
	case http.MethodPost:
		s.attemptLogin(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) attemptLogin(w http.ResponseWriter, r *http.Request) {
	if !readForm(w, r) {
		return
	}
	// §9: CSRF on every mutating form, and login is one — without it a
	// third-party page can log the operator in at a moment of its choosing.
	expected, ok := s.Auth.LoginFormToken(r)
	if !ok || subtle.ConstantTimeCompare([]byte(expected), []byte(r.PostFormValue(CSRFField))) != 1 {
		s.auditRequest(r, slog.LevelWarn, "login rejected: missing or invalid CSRF token",
			logging.EventAuthFail)
		http.Error(w, "missing or invalid CSRF token", http.StatusForbidden)
		return
	}
	if !s.Auth.Verify(r.Context(), secret.New(r.PostFormValue("password"))) {
		s.auditRequest(r, slog.LevelWarn, "admin login failed", logging.EventAuthFail)
		s.renderLogin(w, r, "That password is not correct.")
		return
	}
	s.Auth.StartSession(w, r)
	s.auditRequest(r, slog.LevelInfo, "admin login", logging.EventAuthOK)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// renderLogin is the ONLY place the login page is built.
//
// Every other page goes through s.page(), which takes the CSRF token from the
// session; the login form has no session yet, so it was the one hand-built
// PageData literal in the codebase — and the wrong-password branch was written
// without a token, which wedged the page for the rest of its life (d46.17).
// One function now, so the two branches cannot disagree again.
//
// The token is a pre-authentication CSRF nonce, not a session: rendering this
// page must not admit the caller to anything.
func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, formError string) {
	token := s.Auth.LoginForm(w, r)
	s.render(w, "login", web.PageData{
		Title:     "Sign in",
		CSRFToken: token,
		Error:     formError,
		Flash:     flashFrom(r),
	})
}

// logout ends EVERY session, not just this browser's (d46.28).
//
// Clearing one cookie only ever signed out the browser doing the clearing,
// which is the place it was least likely to matter. The flash on the login page
// says so, because "signed out" that leaves a copied cookie working for another
// week is a promise the operator did not get.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.Auth.EndSession(w)
	if err := s.Auth.EndEverySession(r.Context()); err != nil {
		// The sessions are ended for this process either way; what failed is
		// that they stay ended across a restart. Worth a line in the trail, not
		// worth refusing to sign the operator out.
		s.Log.Error("could not persist the session revocation", "error", err.Error())
	}
	s.auditRequest(r, slog.LevelInfo, "admin logout: every session ended",
		logging.EventAuthOK)
	http.Redirect(w, r, "/login?flash=signed-out", http.StatusSeeOther)
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	data, values, _ := s.page(r.Context(), "Setup")
	domain, name := values.get(SettingDomain), values.get(SettingAddressName)
	data.Setup = web.SetupView{
		GeneratedPassword: s.Auth.GeneratedPassword(),
		PasswordManaged:   !s.Auth.PasswordChangeable(),
		AddressConfigured: domain != "" && name != "",
		LightningAddress:  lnurl.Identifier(name, domain),
	}
	s.render(w, "setup", data)
}
