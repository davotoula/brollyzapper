package api_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/store"
)

// A connection created through the FORM with the pay group and blank limits is
// bounded (plk), because the defaults live in the store rather than in the page.
//
// The page is one caller. The regtest stack is another and d24.9's field trip
// will be a third, so a default that lived in the form is one the next caller
// would not get.
func TestCreatingAPayingConnectionThroughTheFormBoundsIt(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)

	rec := h.postForm(t, "/connections/create", cookie, url.Values{
		"name":       {"Amethyst on my phone"},
		"relays":     {"wss://relay.example"},
		"group_pay":  {"on"},
		"group_info": {"on"},
		// Blank limits: "you did not say", which is what plk answers.
		"budget_sats":      {""},
		"max_payment_sats": {""},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /connections/create = %d %q, want 303", rec.Code, rec.Body)
	}

	rows, err := h.store.AllNWCConnections(t.Context())
	if err != nil || len(rows) != 1 {
		t.Fatalf("connections = %d, err=%v", len(rows), err)
	}
	row := rows[0]
	if row.BudgetMsat == nil || row.MaxPaymentMsat == nil {
		t.Fatalf("a paying connection was created unbounded: budget=%v cap=%v",
			row.BudgetMsat, row.MaxPaymentMsat)
	}
	if *row.BudgetMsat != store.DefaultConnectionBudgetMsat {
		t.Errorf("budget = %d, want the default %d", *row.BudgetMsat,
			store.DefaultConnectionBudgetMsat)
	}
	if !h.audited(t, "connection.create") {
		t.Error("creating a connection wrote no audit event")
	}
}

// The unlimited box is an EXPLICIT act, and it is honoured.
//
// nil has to stay expressible — unlimited-within-the-ceiling is a legitimate
// choice — it must simply never be what a blank form produces.
func TestTheUnlimitedBoxIsHonoured(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)

	h.postForm(t, "/connections/create", cookie, url.Values{
		"name":      {"my own node's remote"},
		"relays":    {"wss://relay.example"},
		"group_pay": {"on"},
		"unlimited": {"on"},
	})

	rows, _ := h.store.AllNWCConnections(t.Context())
	if len(rows) != 1 {
		t.Fatalf("connections = %d, want 1", len(rows))
	}
	if rows[0].BudgetMsat != nil || rows[0].MaxPaymentMsat != nil {
		t.Error("the operator asked for no limits and got some anyway")
	}
}

// THE PAIRING URI IS RENDERED AND THE SECRET IS NOT IN THE QR.
//
// It is shown as text deliberately — an operator sometimes needs to copy it —
// and as a picture, which is what a phone reads. The picture is rectangles, so
// the secret is not in the page source twice.
func TestThePairingURIIsShownAsTextAndAsAQR(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	h.postForm(t, "/connections/create", cookie, url.Values{
		"name":       {"a wallet"},
		"relays":     {"wss://relay.example"},
		"group_info": {"on"},
	})
	rows, _ := h.store.AllNWCConnections(t.Context())
	if len(rows) != 1 {
		t.Fatalf("connections = %d, want 1", len(rows))
	}

	body := h.get(t, "/connections?show=1", cookie).Body.String()

	// Matched from "walletconnect://" rather than the whole scheme, because
	// html/template renders the URI's "+" as &#43; — correct escaping, which a
	// browser displays as "+", so an operator copying the text gets the right
	// thing. Asserting on the raw bytes would be asserting that the page does
	// NOT escape, which is the opposite of what is wanted.
	if !strings.Contains(body, "walletconnect://"+rows[0].ServicePubkey) {
		t.Error("the pairing URI is not on the page as text")
	}
	if !strings.Contains(body, "nostr&#43;walletconnect") {
		t.Error("the URI's scheme is missing or unescaped; a browser needs the escaped form " +
			"to display nostr+walletconnect")
	}
	if !strings.Contains(body, "<svg ") {
		t.Error("the pairing QR is not on the page")
	}
	// The QR is markup, not a fetch: no data: URI, no <img>, nothing external.
	if strings.Contains(body, "data:image") {
		t.Error("the QR was rendered as a data: URI; ADR 0002 rules it inline")
	}
}

// A connection NOT asked for is not rendered with its secret.
//
// The list shows every pairing; the URI is built only for the row the operator
// asked to see. A page that rendered all of them would put every secret on
// screen for the sake of the one being looked at.
func TestOtherConnectionsSecretsAreNotOnThePage(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	for _, name := range []string{"first", "second"} {
		h.postForm(t, "/connections/create", cookie, url.Values{
			"name": {name}, "relays": {"wss://relay.example"}, "group_info": {"on"},
		})
	}
	rows, _ := h.store.AllNWCConnections(t.Context())
	if len(rows) != 2 {
		t.Fatalf("connections = %d, want 2", len(rows))
	}

	// Ask for one of them by id.
	body := h.get(t, "/connections?show=1", cookie).Body.String()

	var shown, hidden store.NWCConnection
	for _, row := range rows {
		if row.ID == 1 {
			shown = row
		} else {
			hidden = row
		}
	}
	if !strings.Contains(body, shown.ClientSecret.Reveal()) {
		t.Error("the connection the operator asked to see has no pairing secret on the page")
	}
	if strings.Contains(body, hidden.ClientSecret.Reveal()) {
		t.Error("another connection's pairing secret is on the page; only the one asked for " +
			"is rendered")
	}
}

// Revoking is audited and signals the service (uhg): a revocation that waited
// for a restart would be a revocation that did nothing.
func TestRevokingAConnectionAuditsAndSignals(t *testing.T) {
	demand := make(chan struct{}, 1)
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
		opts.NWCDemand = demand
	})
	cookie := h.login(t)
	h.postForm(t, "/connections/create", cookie, url.Values{
		"name": {"a wallet"}, "relays": {"wss://relay.example"}, "group_info": {"on"},
	})
	// Drain the create's signal so the revoke's is the one observed.
	select {
	case <-demand:
	default:
	}

	h.postForm(t, "/connections/revoke", cookie, url.Values{"id": {"1"}})

	rows, _ := h.store.AllNWCConnections(t.Context())
	if len(rows) != 1 || !rows[0].Revoked {
		t.Fatalf("the connection was not revoked: %+v", rows)
	}
	select {
	case <-demand:
	default:
		t.Error("revoking did not signal the NWC service, so the connection would keep " +
			"answering until the next restart")
	}
	if !h.audited(t, "connection.revoke") {
		t.Error("revoking a connection wrote no audit event")
	}
}

// A limit field that was typed WRONGLY is refused, not silently defaulted.
//
// Blank means "you did not say" and takes plk's default. "-5", "twenty" and a
// number larger than every sat that will ever exist are all something else: the
// operator said something and it did not parse. The first version answered all
// four with the default, so a deliberate 500 sat cap with a stray keystroke in
// it became a 25 000 sat one — silently, and in the direction that spends more.
func TestAMistypedLimitIsRefusedRatherThanDefaulted(t *testing.T) {
	for _, typed := range []string{"twenty", "-5", "0", "1 000", "2100000000000001"} {
		t.Run(typed, func(t *testing.T) {
			h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
				opts.Connections = db
			})
			cookie := h.login(t)

			rec := h.postForm(t, "/connections/create", cookie, url.Values{
				"name":             {"Amethyst on my phone"},
				"relays":           {"wss://relay.example"},
				"group_pay":        {"on"},
				"max_payment_sats": {typed},
			})
			if got := rec.Header().Get("Location"); !strings.Contains(got, "flash=bad_amount") {
				t.Errorf("a cap of %q redirected to %q, want flash=bad_amount", typed, got)
			}
			rows, err := h.store.AllNWCConnections(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 0 {
				t.Errorf("a cap of %q created a connection anyway (%d rows); the operator's "+
					"limit was not what they typed and they were not told", typed, len(rows))
			}
		})
	}
}

// A relay address that is not one is refused at the form.
//
// Stored, it fails at pairing time — where the operator has a QR code, a phone,
// and no way to tell a typo from a relay that happens to be down.
func TestARelayThatIsNotARelayIsRefused(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)

	rec := h.postForm(t, "/connections/create", cookie, url.Values{
		"name":   {"Amethyst on my phone"},
		"relays": {"relay.example"}, // no scheme
	})
	if got := rec.Header().Get("Location"); !strings.Contains(got, "flash=bad_relay") {
		t.Errorf("a schemeless relay redirected to %q, want flash=bad_relay", got)
	}
}

// Both switches must survive a server wired without a connections store, and
// must say so rather than crash.
//
// newHarness supplies one, so nothing exercised the branch that answers when
// it is absent — and the branch is load-bearing: s.Connections is an INTERFACE,
// so anything that reaches through it before the nil check panics rather than
// redirects. Collapsing the two handlers into one ceremony made that a single
// place to get wrong, which is worth a single place to assert.
func TestTheConnectionSwitchesRefuseWithNoStoreRatherThanPanicking(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.Connections = nil
	})
	cookie := h.login(t)

	for _, path := range []string{"/connections/revoke", "/connections/resume"} {
		rec := h.postForm(t, path, cookie, url.Values{"id": {"1"}})
		if rec.Code != http.StatusSeeOther {
			t.Errorf("%s answered %d with no connections store, want a redirect", path, rec.Code)
		}
		if got := rec.Header().Get("Location"); got != "/connections?flash=refused" {
			t.Errorf("%s redirected to %q, want the refusal flash", path, got)
		}
	}
}

// Nothing changed means nothing is claimed: no §12 row, and no nudge.
//
// An audit entry for a revoke that revoked nothing, or a resume that resumed
// nothing, is an answer to a question nobody can check — and a nudge for it
// wakes the subscriber to re-read a table that did not move. The rule is now
// stated once in connectionAction, so it is asserted once here, on both
// switches and on an id that does not exist.
func TestASwitchThatChangesNothingWritesNoTrailAndSendsNoNudge(t *testing.T) {
	demand := make(chan struct{}, 1)
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
		opts.NWCDemand = demand
	})
	cookie := h.login(t)

	for _, c := range []struct{ path, flash, event string }{
		{"/connections/revoke", "nothing_to_revoke", "connection.revoke"},
		{"/connections/resume", "nothing_to_resume", "connection.resume"},
	} {
		rec := h.postForm(t, c.path, cookie, url.Values{"id": {"4242"}})
		if got := rec.Header().Get("Location"); got != "/connections?flash="+c.flash {
			t.Errorf("%s on an absent connection redirected to %q, want the %q flash",
				c.path, got, c.flash)
		}
		if h.audited(t, c.event) {
			t.Errorf("%s wrote a %s row for a connection that does not exist", c.path, c.event)
		}
		select {
		case <-demand:
			t.Errorf("%s woke the NWC service for a change that did not happen", c.path)
		default:
		}
	}
}
