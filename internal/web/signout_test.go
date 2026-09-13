package web_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/web"
)

// d46.29. POST /logout existed, ended every session, and nothing reached it: no
// template referenced the route, so the one action d46.28 built for an operator
// who suspects a ridden session could only be taken with a hand-crafted POST.
//
// The negative half is rendered WITH a CSRF token, because the login page
// carries one of its own. A control conditioned on the token would pass the
// positive half and put "Sign out" on the sign-in page.
func TestTheSignOutControlIsThereWhenSignedInAndNotOnTheLoginPage(t *testing.T) {
	r := newRenderer(t)
	const token = "the-session-token"

	var signedIn strings.Builder
	if err := r.Render(&signedIn, "node", web.PageData{Title: "Node", CSRFToken: token, SignedIn: true}); err != nil {
		t.Fatal(err)
	}
	// A POST form carrying the token, not a link: a GET that signs out is
	// prefetched, and this one would sign out every device on a hover.
	control := regexp.MustCompile(`<form method="post" action="/logout">\s*` +
		`<input type="hidden" name="csrf_token" value="` + token + `">\s*` +
		`<button type="submit">[^<]+</button>\s*</form>`)
	if !control.MatchString(signedIn.String()) {
		t.Errorf("a signed-in page has no sign-out form posting to /logout with the CSRF token:\n%s", signedIn.String())
	}

	var login strings.Builder
	if err := r.Render(&login, "login", web.PageData{Title: "Sign in", CSRFToken: token}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(login.String(), "/logout") {
		t.Errorf("the login page references /logout; there is nobody to sign out:\n%s", login.String())
	}
}
