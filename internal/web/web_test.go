package web_test

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/web"
)

// §9's seven pages, plus the login screen that guards them.
var pages = []string{"setup", "login", "wallet", "sending", "connections", "node", "security", "settings"}

func TestEveryPageRenders(t *testing.T) {
	renderer := newRenderer(t)
	for _, page := range pages {
		t.Run(page, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderer.Render(&buf, page, web.PageData{Title: page, CSRFToken: "t"}); err != nil {
				t.Fatalf("Render(%s): %v", page, err)
			}
			body := buf.String()
			if !strings.Contains(body, "<!doctype html>") {
				t.Errorf("%s did not render through the layout", page)
			}
			if strings.TrimSpace(body) == "" {
				t.Errorf("%s rendered nothing", page)
			}
		})
	}
}

func TestRenderingAnUnknownPageIsAnError(t *testing.T) {
	renderer := newRenderer(t)
	var buf bytes.Buffer
	if err := renderer.Render(&buf, "not-a-page", web.PageData{}); err == nil {
		t.Error("Render accepted a page that does not exist")
	}
}

// Spec §5 and §9: allocation is the concept most likely to be misread as a
// transfer, so the explanation goes ON THE PAGE, not in a tooltip.
func TestTheWalletPageExplainsThatAllocationMovesNoSats(t *testing.T) {
	renderer := newRenderer(t)
	var buf bytes.Buffer
	if err := renderer.Render(&buf, "wallet", web.PageData{Title: "Wallet"}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	body := strings.ToLower(buf.String())
	for _, phrase := range []string{"moves no sats", "spending authorisation"} {
		if !strings.Contains(body, phrase) {
			t.Errorf("the wallet page does not say %q; §5's explanation belongs on the page", phrase)
		}
	}
	if strings.Contains(body, "title=\"") {
		t.Error("the explanation appears to be in a tooltip; §9 says on the page")
	}
}

// P3 surface: stub honestly rather than half-building.
// §9 items 3 and 4 make two sentences REQUIREMENTS, and d24.5's ruling calls
// them deliverables rather than decoration. This is the assertion that they are
// on the pages and not merely in a constant.
//
// They exist because both pages ask an operator to grant something whose
// consequence is not obvious from the control: a checkbox that says "Pay
// invoices" does not say that ticking it lets an app spend without asking again,
// and a toggle called "Sending" does not say what the worst case is.
func TestThePagesStateWhatTheyGrantAndWhatItRisks(t *testing.T) {
	renderer := newRenderer(t)

	var sending bytes.Buffer
	if err := renderer.Render(&sending, "sending", web.PageData{
		Title:   "Sending",
		Sending: web.SendingView{ResidualRisk: web.ResidualRisk},
	}); err != nil {
		t.Fatalf("Render(sending): %v", err)
	}
	// §11's worst case, in full and unedited: a page that paraphrased it would
	// be a page that softened it. Compared against the ESCAPED form, because
	// html/template escapes the apostrophes — the assertion is that the page
	// carries this statement, not that it carries these bytes.
	if !strings.Contains(sending.String(), template.HTMLEscapeString(web.ResidualRisk)) {
		t.Error("the sending page does not carry §11's residual-risk statement")
	}
	for _, must := range []string{"rolling 24-hour limit", "revoke"} {
		if !strings.Contains(sending.String(), must) {
			t.Errorf("the sending page does not mention %q, which is what an operator is "+
				"deciding about", must)
		}
	}
	// AND IT NO LONGER CLAIMS THE OLD WORST CASE (tna.1). Until P4 this page
	// said an attacker "could spend up to your node's outbound channel balance",
	// which was true and is now not: the guard enforces a rolling cap inside
	// LND's request path. A page that overstates the risk is not the safe kind
	// of wrong — it is a page the operator learns to discount, and the same
	// panel is what tells them about the risks that ARE real.
	if strings.Contains(sending.String(), "outbound channel balance") {
		t.Error("the sending page still says a compromised server could spend the node's whole " +
			"outbound balance; the guard's rolling cap bounds it at one window")
	}

	var connections bytes.Buffer
	if err := renderer.Render(&connections, "connections", web.PageData{
		Title: "Connections",
		Connections: web.ConnectionsView{Groups: []web.PermissionOption{{
			Group:       "pay",
			Label:       "Pay invoices",
			Consequence: "Granting this is what lets this connection spend your sats.",
		}}},
	}); err != nil {
		t.Fatalf("Render(connections): %v", err)
	}
	if !strings.Contains(connections.String(),
		template.HTMLEscapeString("Granting this is what lets this connection spend your sats.")) {
		t.Error("the connections page does not state what granting the pay group does, which " +
			"§9 requires of the form itself")
	}
}

// Nothing rendered may carry a secret: every value that could is a
// secret.String, which refuses.
func TestTemplatesEscapeUserSuppliedValues(t *testing.T) {
	renderer := newRenderer(t)
	var buf bytes.Buffer
	data := web.PageData{Title: "Settings", Settings: web.SettingsView{Domain: `"><script>alert(1)</script>`}}
	if err := renderer.Render(&buf, "settings", data); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(buf.String(), "<script>alert(1)</script>") {
		t.Error("a user-supplied setting was rendered unescaped")
	}
}

// §9 criterion 7: first run generates a password and shows it IN THE BROWSER.
// The value is a secret.String, so the template has to reveal it deliberately —
// which is exactly the property that stops it reaching a log by accident.
func TestTheGeneratedPasswordIsRenderedOnceOnTheSetupPage(t *testing.T) {
	renderer := newRenderer(t)
	var buf bytes.Buffer
	data := web.PageData{Title: "Setup"}
	data.Setup.GeneratedPassword = secret.New("the-generated-password")
	if err := renderer.Render(&buf, "setup", data); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), "the-generated-password") {
		t.Errorf("the setup page does not show the generated password: %s", buf.String())
	}

	// With none generated — every start after the first — the block is absent.
	buf.Reset()
	if err := renderer.Render(&buf, "setup", web.PageData{Title: "Setup"}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(buf.String(), "[redacted]") {
		t.Error("the setup page rendered a redaction placeholder where no password exists")
	}
}

// shippedStatic is every file internal/web/static is meant to serve. It is a
// list rather than a pattern for the same reason the embed directive is: a
// pattern says what is allowed in, and a list says what is actually there.
var shippedStatic = []string{"style.css", "favicon.svg", "apple-touch-icon.png"}

// TestStaticServesExactlyTheNamedAssets pins what the embedded static directory
// ships. The directory holds the stylesheet's own Go tests beside the assets,
// and an embed pattern of `static/*` would put a _test.go into both binaries and
// hand it to anyone who asked StaticHandler for it.
//
// It walks the directory ON DISK and checks every entry against shippedStatic,
// so it fails in BOTH directions: a file the pattern silently picks up, and a
// named asset that stops being served. The version this replaced probed three
// fixed paths, which could only ever catch the second — a new .svg dropped into
// static/ would have been served with nothing to say so.
func TestStaticServesExactlyTheNamedAssets(t *testing.T) {
	shipped := make(map[string]bool, len(shippedStatic))
	for _, name := range shippedStatic {
		shipped[name] = true
	}

	entries, err := os.ReadDir("static")
	if err != nil {
		t.Fatalf("reading static/: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("static/ is empty, so this rule would pass vacuously")
	}

	h := web.StaticHandler()
	onDisk := make(map[string]bool, len(entries))

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		onDisk[name] = true

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/"+name, nil))
		served := rec.Code == http.StatusOK

		switch {
		case shipped[name] && !served:
			t.Errorf("static/%s is named as shipped but StaticHandler returned %d; "+
				"the embed pattern no longer covers it", name, rec.Code)
		case !shipped[name] && served:
			t.Errorf("static/%s is served but is not one of the named assets; "+
				"the embed pattern has widened", name)
		}
	}

	for _, name := range shippedStatic {
		if !onDisk[name] {
			t.Errorf("static/%s is named as shipped but is not in the directory; "+
				"assets/build_icons.py writes two of these three", name)
		}
	}

	// The directory listing is its own surface: a FileServer will happily render
	// one, and it is the reason the _test.go's absence from the embed matters
	// twice over.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/", nil))
	if strings.Contains(rec.Body.String(), "package static_test") {
		t.Error("the directory listing served the stylesheet's test source")
	}
}

// TestTheWalletSeparatesWaitingFromFailed pins the one piece of judgement the
// wallet makes about colour. `.state` renders for every state except settled,
// and those states are not one thing: open and pending are an invoice waiting,
// which is the system working, while expired and failed are the rung below on
// the spec's ladder. Painting all four with one colour would tell an operator
// their normal unpaid invoice had gone wrong.
//
// Asserted against the VALUE, not against rendered HTML: the classification is
// a Go decision and can be checked without a template in the way.
func TestTheWalletSeparatesWaitingFromFailed(t *testing.T) {
	for state, want := range map[string]string{
		"open":    web.StateClassWaiting,
		"pending": web.StateClassWaiting,
		"expired": web.StateClassBad,
		"failed":  web.StateClassBad,
		// Never rendered — the template omits the qualifier for settled — but
		// held anyway, so that a future caller of StateClass gets an answer
		// rather than an accident.
		"settled": web.StateClassWaiting,
	} {
		if got := (web.TxnRow{State: state}).StateClass(); got != want {
			t.Errorf("a %q transaction classifies as %q, want %q", state, got, want)
		}
	}
}

// TestTheWalletRendersTheStateClass is the other half: the value above has to
// reach the page as a class, and settled has to reach it as nothing at all.
func TestTheWalletRendersTheStateClass(t *testing.T) {
	render := func(t *testing.T, state string) string {
		t.Helper()
		var buf bytes.Buffer
		data := web.PageData{Title: "Wallet"}
		data.Wallet.Txns = []web.TxnRow{{Kind: "invoice_in", State: state, AmountMsat: 1000}}
		data.Wallet.Total = 1
		if err := newRenderer(t).Render(&buf, "wallet", data); err != nil {
			t.Fatalf("Render: %v", err)
		}
		return buf.String()
	}

	if out := render(t, "expired"); !strings.Contains(out, `class="state state-`+web.StateClassBad+`"`) {
		t.Error("an expired transaction does not carry its state class")
	}
	if out := render(t, "open"); !strings.Contains(out, `class="state state-`+web.StateClassWaiting+`"`) {
		t.Error("an open transaction does not carry its state class")
	}
	// settled renders no qualifier at all: the table says what a row is, and
	// "(settled)" on every ordinary line is noise.
	if out := render(t, "settled"); strings.Contains(out, `class="state`) {
		t.Error("a settled transaction rendered a state qualifier")
	}
}

func newRenderer(t *testing.T) *web.Renderer {
	t.Helper()
	renderer, err := web.New("test")
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	return renderer
}

// The operator can see which build they are running, on every page
// (BrollyZap-3wy).
//
// Answering "which version is this?" used to mean reading the container's logs
// or exec-ing into it — neither of which is available to someone holding a
// phone in front of the box, which is exactly when the question gets asked.
func TestEveryPageShowsTheRunningVersion(t *testing.T) {
	renderer, err := web.New("0.1.12")
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	for _, page := range pages {
		t.Run(page, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderer.Render(&buf, page, web.PageData{Title: page, CSRFToken: "t"}); err != nil {
				t.Fatalf("Render(%s): %v", page, err)
			}
			if !strings.Contains(buf.String(), "0.1.12") {
				t.Errorf("%s does not show the running version anywhere", page)
			}
		})
	}
}

// RENDER SETS IT, not the handler — the same rule, and the same reason, as Page
// and Content. The version is one fact about the process, so a handler that
// could pass it is a handler that can pass a different one; seven pages
// disagreeing about which build is running is worse than none of them saying.
func TestAHandlerCannotClaimADifferentVersion(t *testing.T) {
	renderer, err := web.New("0.1.12")
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	var buf bytes.Buffer
	if err := renderer.Render(&buf, "wallet", web.PageData{Version: "9.9.9-lies"}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(buf.String(), "9.9.9-lies") {
		t.Error("a handler's version reached the page; Render must set it")
	}
	if !strings.Contains(buf.String(), "0.1.12") {
		t.Error("the renderer's own version is not on the page")
	}
}

// doy.5: the payee reaches the page, and a row that has one still shows
// everything a row shows.
//
// The field existing on TxnRow proves nothing — a value the template never
// mentions is a field the operator never sees, and this page's history has
// shipped a blank column for exactly that reason before (d24.27's undated rows,
// where created_at was on the row and simply not emitted).
func TestTheWalletRendersAnOutgoingZapsPayee(t *testing.T) {
	var buf bytes.Buffer
	data := web.PageData{Title: "Wallet"}
	data.Wallet.Txns = []web.TxnRow{{
		Kind: "payment_out", State: "settled", AmountMsat: 21_000,
		Payee: "npub1abcdefg…xyz123", Comment: "thanks for the write-up",
	}}
	data.Wallet.Total = 1
	if err := newRenderer(t).Render(&buf, "wallet", data); err != nil {
		t.Fatalf("Render: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "npub1abcdefg…xyz123") {
		t.Errorf("the payee is not on the page:\n%s", out)
	}
	if !strings.Contains(out, "thanks for the write-up") {
		t.Error("the zap comment is not on the page")
	}
	// And no receipt state, which is the trap one layer up asserted here too:
	// the operator must not read "abandoned" on a zap they sent.
	if strings.Contains(out, "receipt ") {
		t.Errorf("an outgoing zap row carries receipt wording:\n%s", out)
	}
}
