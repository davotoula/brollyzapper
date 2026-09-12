package api_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/api"
)

// d46.29, the seam. The template test proves the layout renders the control
// when SignedIn is set; only a request through the server proves page() sets
// it from the session — and that renderLogin, which does not go through page(),
// leaves it unset.
//
// The last step submits the rendered form as a browser would: its own action,
// its own token. A control whose token did not match the session would render
// on every page and be refused on every click.
func TestTheSignOutControlRendersForASessionAndSignsOut(t *testing.T) {
	h := newHarness(t)

	if body := h.get(t, "/login", nil).Body.String(); strings.Contains(body, "/logout") {
		t.Errorf("GET /login without a session renders a sign-out control:\n%s", body)
	}

	cookie := h.login(t)
	body := h.get(t, "/", cookie).Body.String()
	const action = `<form method="post" action="/logout">`
	i := strings.Index(body, action)
	if i < 0 {
		t.Fatalf("GET / with a session renders no sign-out control:\n%s", body)
	}

	form := url.Values{api.CSRFField: {csrfFrom(t, body[i:])}}
	post := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, post)

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login?flash=signed-out" {
		t.Fatalf("submitting the rendered sign-out form = %d to %q, want 303 to /login?flash=signed-out",
			rec.Code, rec.Header().Get("Location"))
	}
	if h.get(t, "/", cookie).Code == http.StatusOK {
		t.Error("the session still reaches an admin page after the sign-out form was submitted")
	}
}
