package web_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/web"
)

// TestEveryPageRendersWithAFullFixture renders every page with every view
// populated, which TestEveryPageRenders does not: that one proves the templates
// parse and execute against near-empty data, and near-empty data never reaches
// a `range` body, a populated table row, or a health block. A field renamed out
// from under one of those fails here and nowhere else.
//
// It is also the palette's preview: set BROLLY_PREVIEW_DIR and it writes the
// pages out as standalone HTML, stylesheet beside them, so a wave can LOOK at
// what it changed in both themes. The two defects wave 36 shipped fixes for
// were both invisible to every assertion in this repo and visible in a browser
// in seconds.
func TestEveryPageRendersWithAFullFixture(t *testing.T) {
	dir := os.Getenv("BROLLY_PREVIEW_DIR")
	now := time.Now().UTC()
	r := newRenderer(t)

	writeAssets(t, dir)
	for _, page := range pages {
		var b strings.Builder
		data := fullFixture(now)
		if page == "wallet" {
			data.Degraded = []string{"No lightning address is configured yet."}
			data.Flash = "Settings saved."
		}
		if err := r.Render(&b, page, data); err != nil {
			t.Fatalf("%s: %v", page, err)
		}
		writePage(t, dir, page, b.String())
	}
	if dir != "" {
		t.Logf("wrote %d pages to %s", len(pages), dir)
	}
}

// galleryPages are the screens a stranger chooses the app by — the ones that
// go in the App Store submission (0vk.21). Setup and login are not among them:
// one is a page the operator sees once, the other is a password box.
var galleryPages = []string{"wallet", "sending", "connections", "node", "security", "settings"}

// TestTheGalleryFixtureShowsAHealthyInstall renders the store screenshots'
// source: a configured, working install with nothing wrong on any page.
//
// The full fixture above cannot be that, and must not become it — its job is to
// reach every branch, so it carries a degraded banner, an abandoned receipt, a
// failed payment and a blocked check on purpose. Screenshots taken from it show
// a reviewer an app that is not set up, which is the one thing a listing must
// not do. So the gallery is the full fixture with the unhappiness removed, and
// this test asserts the removal held: a rendered gallery page names no failure.
//
// Set BROLLY_GALLERY_DIR to write the pages out; the screenshots are taken from
// those, at 1440×900, which is what the gallery hosts today. Fixture data
// rather than a real box, deliberately: deterministic, re-generable when the UI
// changes, and none of the operator's own npubs or amounts in a public listing.
func TestTheGalleryFixtureShowsAHealthyInstall(t *testing.T) {
	dir := os.Getenv("BROLLY_GALLERY_DIR")
	now := time.Now().UTC()

	// The header prints the build version under the wordmark (3wy), so a
	// screenshot from the default test renderer says "test" in its top-left
	// corner. Whoever takes the store screenshots passes the version they are
	// shipping; nothing here hardcodes one, because a hardcoded one is stale by
	// the next release.
	version := os.Getenv("BROLLY_GALLERY_VERSION")
	if version == "" {
		version = "test"
	}
	r, err := web.New(version)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}

	// Phrases a healthy install's pages never say. Each is something the full
	// fixture DOES say, so an assertion that the gallery fixture omits them is
	// an assertion about the transform, not about the templates. Phrases, not
	// bare words: "unreachable" alone also matches the connections page's
	// standing hint that a single-relay pairing is unreachable when its relay
	// is — which is product copy, true on any install, and not a failure.
	unhappy := []string{
		"Not fully set up", "abandoned", "failed", "The node is unreachable", "Settings saved",
		// The 06v deployment-ceiling banner, and the pending ceremony: the first
		// is a contradiction under "Sending is on", the second reads as the app
		// waiting on the operator. Both were on the sending page before this list
		// named them, because the fixture predates the fields they key on.
		"does not permit sending", "Confirm this in a file only you can read",
	}

	writeAssets(t, dir)
	for _, page := range galleryPages {
		var b strings.Builder
		if err := r.Render(&b, page, galleryFixture(now)); err != nil {
			t.Fatalf("%s: %v", page, err)
		}
		html := b.String()
		for _, word := range unhappy {
			if strings.Contains(html, word) {
				t.Errorf("gallery %s page says %q; a store screenshot must not show a failure", page, word)
			}
		}
		writePage(t, dir, page, html)
	}

	// The one thing the gallery must show that the full fixture predates: an
	// outgoing zap that names who it paid (doy.5). If this stops rendering, the
	// screenshots quietly go back to showing unlabelled debits.
	var wallet strings.Builder
	if err := r.Render(&wallet, "wallet", galleryFixture(now)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(wallet.String(), galleryPayee) {
		t.Errorf("the gallery wallet page does not name the payee of the outgoing zap")
	}
}

// galleryPayee is the shortened npub the gallery's outgoing zap paid. A
// constant so the assertion above and the fixture cannot disagree about it.
const galleryPayee = "npub1s0…k3x"

// galleryFixture is the full fixture with every unhappy state removed and the
// operator's own name replaced by a neutral one. Derived, not copied: a field
// added to the full fixture reaches the gallery automatically, and only the
// subtractions below have to be maintained.
func galleryFixture(now time.Time) web.PageData {
	d := fullFixture(now)
	day := 24 * time.Hour

	// Wallet: published receipts only, and the outgoing zap carries its payee.
	d.Wallet.Txns = []web.TxnRow{
		{Kind: "zap", State: "settled", AmountMsat: 21_000, When: now.Add(-2 * time.Hour), Comment: "great post!", Receipt: "published", ReceiptID: "e3f1a9…"},
		{Kind: "payment_out", State: "settled", AmountMsat: 5_000, FeeMsat: 12, When: now.Add(-5 * time.Hour), Payee: galleryPayee, Comment: "thanks for the guide"},
		{Kind: "zap", State: "settled", AmountMsat: 1_000_000, When: now.Add(-1 * day), Comment: "onward", Receipt: "published", ReceiptID: "7bc04d…"},
		{Kind: "invoice_in", State: "open", AmountMsat: 50_000, When: now.Add(-3 * day)},
		{Kind: "zap", State: "settled", AmountMsat: 2_100, When: now.Add(-4 * day), Receipt: "published", ReceiptID: "a91e02…"},
	}

	// Sending: nothing in the way, and no ceremony mid-flight.
	d.Sending.Blocked = nil
	d.Sending.Authorisation = web.AuthorisationView{}

	// Connections: no refusal on record, both relays serving, and the revoked
	// pairing stays — revocation is a feature worth seeing, not a fault.
	c := &d.Connections.Connections[0]
	c.LastRefusal, c.LastRefusalAt = "", time.Time{}
	for i := range c.Health.Relays {
		c.Health.Relays[i].State = "serving"
		c.Health.Relays[i].FailedDials = 0
	}

	// Security: every check passes; the trail shows the app doing its job.
	for i := range d.Security.Checks {
		d.Security.Checks[i].OK = true
		d.Security.Checks[i].Detail, d.Security.Checks[i].Blocks = "", ""
	}

	return d
}

// fullFixture is every view populated, including the unhappy states — a
// refusal, an abandoned receipt, a failed payment, a blocked check. Its job is
// to reach every template branch. It is shared with the gallery fixture so the
// two cannot drift: the gallery is this, with the unhappiness taken out.
func fullFixture(now time.Time) web.PageData {
	d := web.PageData{}
	d.Wallet.BalanceMsat = 5_000_000
	d.Wallet.Total = 214
	d.Wallet.Txns = []web.TxnRow{
		{Kind: "zap", State: "settled", AmountMsat: 21_000, When: now, Comment: "great post!", Receipt: "published", ReceiptID: "e3f1a9…"},
		{Kind: "zap", State: "settled", AmountMsat: 1_000_000, When: now, Comment: "onward", Receipt: "pending"},
		{Kind: "zap", State: "settled", AmountMsat: 210_500, When: now, Receipt: "abandoned"},
		{Kind: "invoice_in", State: "open", AmountMsat: 50_000, When: now},
		{Kind: "invoice_in", State: "expired", AmountMsat: 3_000, When: now},
		{Kind: "payment_out", State: "failed", AmountMsat: 12_000, FeeMsat: 1_100, When: now, Note: "manual allocation"},
	}
	d.Sending.Enabled = true
	d.Sending.Ready = true
	d.Sending.Permitted = true
	// The post-06v half of the view. Permitted alone is the pre-06v gate; without
	// AllowedByDeployment the page prints "This deployment does not permit
	// sending" directly under "Sending is on", and without the caps the limit
	// inputs show 0. Both went unnoticed because nothing rendered this page to
	// a screen anyone looked at.
	d.Sending.AllowedByDeployment = true
	d.Sending.SpendCapMsat = 100_000_000
	d.Sending.PaymentCapMsat = 25_000_000
	d.Sending.Authorisation = web.AuthorisationView{
		Pending: true, Control: "payment_cap", Msat: 26_000_000,
		Change: "RAISE THE PER-PAYMENT LIMIT to 26000 sats.",
	}
	d.Sending.GuardReachable = true
	d.Sending.Expiry = now.Add(7 * 24 * time.Hour)
	d.Sending.PayingConnections = 1
	d.Sending.SpendUsedMsat = 21_000_000
	d.Sending.SpendLimitMsat = 100_000_000
	d.Sending.SpendWindowHours = 24
	d.Sending.ResidualRisk = "A compromised server can spend up to the ceiling above, within the window, and no more."
	d.Sending.Blocked = []web.SendingCheck{{Title: "The node is unreachable", Detail: "Sending is refused until it answers again."}}
	d.Connections.SendingEnabled = true
	d.Connections.DefaultBudgetSats = 10_000
	d.Connections.DefaultMaxPaymentSats = 1_000
	d.Connections.RelayPrefill = "wss://relay.damus.io"
	d.Connections.Groups = []web.PermissionOption{
		{Group: "info", Label: "See the balance", Consequence: "This app can read what the wallet holds.", Default: true},
		{Group: "pay", Label: "Pay invoices", Consequence: "This app can spend, up to the limits below, without asking you again."},
	}
	d.Connections.Connections = []web.ConnectionRow{{
		ID: 1, Name: "Amethyst", Relays: []string{"wss://relay.damus.io", "wss://nos.lol"},
		// Both units: the page renders the msat pair and the edit form echoes the
		// sats pair. Only the sats pair was set at first, and the connections
		// page previewed "up to 0.000 sats per day" for as long as nobody looked.
		CanPay: true, BudgetMsat: 10_000_000, MaxPaymentMsat: 1_000_000,
		BudgetSats: 10_000, MaxPaymentSats: 1_000, SpentMsat: 2_100_000,
		CreatedAt: now, LastUsedAt: now, Groups: d.Connections.Groups,
		LastRefusal: "over the budget for this connection", LastRefusalAt: now,
		Health: web.ConnectionHealthView{Known: true, Working: true, Relays: []web.RelayHealthView{
			{Relay: "wss://relay.damus.io", State: "serving", Since: now, Reconnects: 2},
			{Relay: "wss://nos.lol", State: "retrying", Since: now, FailedDials: 4},
		}},
	}, {
		ID: 2, Name: "Old phone", Revoked: true, Relays: []string{"wss://nos.lol"}, CreatedAt: now,
	}}
	d.Node.State = "serving"
	d.Node.LNDReachable = true
	d.Node.ReceiveMacaroonPresent = true
	d.Node.SpendMacaroonPresent = true
	d.Node.GuardReachable = true
	d.Node.ReceiveExpiry = now.Add(60 * 24 * time.Hour)
	d.Security.GuardRejections = 0
	d.Security.RejectionWindowHours = 24
	d.Security.Checks = []web.CheckRow{
		{Title: "admin.macaroon is not mounted into the server", OK: true, Threat: "A compromised server could spend the whole node."},
		{Title: "The advertised origin is https", OK: false, Threat: "A wallet would be handed a plaintext callback.", Detail: "Set a domain on Settings.", Blocks: "sending"},
	}
	d.Security.BlindSpots = []string{"This page cannot tell you whether your node's own backups work."}
	d.Security.Events = []web.AuditRow{
		{When: now.Format(time.RFC3339), Event: "login.success", Detail: "the operator signed in", Remote: "192.168.77.20"},
		{When: now.Format(time.RFC3339), Event: "relay.refuse", Severity: "warn", Detail: "over the per-sender limit", Remote: "203.0.113.9"},
	}
	d.Settings.Domain = "zap.example.com"
	d.Settings.AdvertisedOrigin = "https://zap.example.com"
	d.Settings.AddressName = "alice"
	d.Settings.LogLevel = "info"
	d.Settings.PublicRateLimitPerMinute = 20
	d.Settings.PublicRateLimitPerHour = 200
	d.Settings.MaxFeePPM = 3000
	d.Settings.MaxFeeFloorMsat = 10_000
	d.Settings.Relays = "wss://relay.damus.io\nwss://nos.lol"
	d.Setup.AddressConfigured = true
	d.Setup.LightningAddress = "alice@zap.example.com"
	d.CSRFToken = "preview"
	return d
}

// writeAssets copies every shipped static asset beside the preview pages, so a
// page opened from disk shows the header mark rather than a broken image — a
// preview whose header is broken misreports what the wave changed. A no-op when
// no directory is set, which is every run but a human's.
func writeAssets(t *testing.T, dir string) {
	t.Helper()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range shippedStatic {
		asset, err := os.ReadFile(filepath.Join("static", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), asset, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// writePage writes one rendered page as standalone HTML. Every /static/
// reference is rewritten so the file opens from disk or a static server without
// the app running. ReplaceAll over the prefix rather than one named href: the
// layout has four such references now, and a rewrite that names them
// individually goes stale silently — the page still opens, just missing
// whatever was added last.
func writePage(t *testing.T, dir, page, html string) {
	t.Helper()
	if dir == "" {
		return
	}
	out := strings.ReplaceAll(html, `"/static/`, `"`)
	if err := os.WriteFile(filepath.Join(dir, page+".html"), []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
}
