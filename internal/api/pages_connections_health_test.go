package api_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/nwc"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

// d24.21: the Connections page says which pairings are working, and — for one
// that is not — since when, and which kind of broken it is.
//
// The 0.1.10 trip is the requirement: for thirteen minutes the app was
// unreachable for every paired wallet, the log said nothing, and the operator
// established it by reading nwc_handled_requests out of SQLite. This page is
// where they already look.
//
// BOTH ROWS are asserted, and that is deliberate. A page that always said the
// same thing would satisfy a substring match whichever thing it said; a pair —
// one healthy connection, one failing, on one field — cannot be satisfied by a
// constant.
func TestTheConnectionsPageSaysWhichPairingsAreReachable(t *testing.T) {
	var health map[int64]nwc.ConnectionHealth
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
		opts.NWCHealth = healthFunc(func() map[int64]nwc.ConnectionHealth { return health })
	})
	cookie := h.login(t)
	working := aPairing(t, h, "working phone", "wss://relay.good")
	failing := aPairing(t, h, "the phone in the kitchen", "wss://relay.bad")
	failingSince := time.Date(2026, 8, 25, 10, 54, 48, 0, time.UTC)
	health = map[int64]nwc.ConnectionHealth{
		working.ID: {Relays: []nwc.RelayHealth{
			{Relay: "wss://relay.good", State: nwc.HealthServing, Since: failingSince}}},
		failing.ID: {Relays: []nwc.RelayHealth{
			{Relay: "wss://relay.bad", State: nwc.HealthRetrying, Since: failingSince,
				FailedDials: 156}}},
	}

	body := h.body(t, "/connections", cookie)
	workingRow, failingRow := sectionFor(t, body, "working phone"),
		sectionFor(t, body, "the phone in the kitchen")

	if !strings.Contains(workingRow, "Working") {
		t.Errorf("the reachable pairing does not say so:\n%s", workingRow)
	}
	if strings.Contains(workingRow, "Not working") {
		t.Errorf("the reachable pairing is reported as broken:\n%s", workingRow)
	}
	if !strings.Contains(failingRow, "Not working") {
		t.Errorf("the pairing that cannot reach its relay reads as fine — which is exactly the "+
			"state the operator spent thirteen minutes in:\n%s", failingRow)
	}
	// SINCE WHEN. "It is broken" without a time cannot be told from "it has
	// always been like this".
	if !strings.Contains(failingRow, "10:54") {
		t.Errorf("the failing pairing does not say since when:\n%s", failingRow)
	}
	// WHICH KIND of broken, in wording UNIQUE to this branch, plus the wording of
	// the other branch being ABSENT. The first version asserted that the row
	// contained "relay" — which the row's own Relay field satisfies whatever the
	// session line says, so planting the unusable wording into the retrying
	// branch passed every test in this file. The operator would have been told to
	// delete a working pairing and re-pair their phone to cure a relay outage
	// that heals itself (found by review, by planting exactly that).
	if !strings.Contains(failingRow, "start working on its own") {
		t.Errorf("the failing pairing does not say the relay is the reason and that it will "+
			"recover unaided:\n%s", failingRow)
	}
	if strings.Contains(failingRow, "pair this app again") {
		t.Errorf("a pairing whose relay is merely down tells the operator to re-pair; that is "+
			"the other state's remedy, and following it destroys a working pairing:\n%s",
			failingRow)
	}
	// The reconnect count is what makes a flapping relay visible; the failing row
	// carries the failed-dial count for the same reason.
	if !strings.Contains(failingRow, "156") {
		t.Errorf("the failing pairing does not say how many attempts have failed:\n%s", failingRow)
	}
}

// A row that no relay can fix says something DIFFERENT from one whose relay is
// down, because the operator's next move differs: one is waiting, the other is
// re-pairing.
func TestAnUnusableRowReadsDifferentlyFromAnUnreachableRelay(t *testing.T) {
	var health map[int64]nwc.ConnectionHealth
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
		opts.NWCHealth = healthFunc(func() map[int64]nwc.ConnectionHealth { return health })
	})
	cookie := h.login(t)
	broken := aPairing(t, h, "a pairing with a broken row", "wss://relay.good")
	health = map[int64]nwc.ConnectionHealth{
		broken.ID: {State: nwc.HealthUnusable, Since: time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC)},
	}

	row := sectionFor(t, h.body(t, "/connections", cookie), "a pairing with a broken row")
	if !strings.Contains(row, "Not working") {
		t.Errorf("an unusable pairing reads as fine:\n%s", row)
	}
	if !strings.Contains(row, "pair this app again") {
		t.Errorf("an unusable row does not tell the operator what to do about it; waiting will "+
			"not fix it and the page must not imply it might:\n%s", row)
	}
	// The other half of the pair: this row must NOT promise the recovery the
	// retrying one promises.
	if strings.Contains(row, "start working on its own") {
		t.Errorf("a row no relay can fix says it will recover by itself:\n%s", row)
	}
}

// With no service attached — before the first reload, or in a build without one
// — the page says it does not know, rather than claiming either answer.
//
// The state is in memory (see nwc.Service.Health), so this is the honest reading
// for the seconds after a restart. "Working" would be a claim about a socket
// nobody has opened yet.
func TestAPairingWithNoKnownStateSaysSo(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	aPairing(t, h, "a pairing nobody has tried", "wss://relay.good")

	row := sectionFor(t, h.body(t, "/connections", cookie), "a pairing nobody has tried")
	if !strings.Contains(row, "not known yet") {
		t.Errorf("a pairing the service has not reached yet does not say so:\n%s", row)
	}
	if strings.Contains(row, "Working") {
		t.Errorf("a pairing nobody has tried is reported as working:\n%s", row)
	}
}

// Ruling B on the page: the last refusal, beside the budget the operator is
// already reading.
//
// d24.22 is why it has to be here at all — Amethyst swallows QUOTA_EXCEEDED, so
// the user is told nothing and the operator is the only possible explainer. The
// page already shows the STANDING budget state ("up to X per day, Y used"); what
// was missing was any record that a refusal HAPPENED.
func TestTheConnectionsPageShowsTheLastRefusal(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	refused := aPairing(t, h, "the phone that hit its cap", "wss://relay.good")
	aPairing(t, h, "the phone that never has", "wss://relay.good")
	at := time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC)
	// The CODE and the SENTENCE the service composed. Rendering one sentence per
	// code was wrong for five of RESTRICTED's six meanings, which is why the
	// message is stored at all.
	if err := h.store.RecordNWCRefusal(t.Context(), refused.ID, "QUOTA_EXCEEDED",
		"this payment would exceed the connection's budget for this period", at); err != nil {
		t.Fatal(err)
	}

	body := h.body(t, "/connections", cookie)
	refusedRow := sectionFor(t, body, "the phone that hit its cap")
	neverRow := sectionFor(t, body, "the phone that never has")

	if !strings.Contains(refusedRow, "14:32") {
		t.Errorf("the refusal's time is not on the page; \"my zap did not work\" cannot be "+
			"linked to \"this connection hit its cap at 14:32\":\n%s", refusedRow)
	}
	// The SERVICE'S OWN SENTENCE, not one re-derived from the code. The page
	// renders what the app was actually told.
	// No apostrophe in the needle: html/template renders one as &#39;, and an
	// assertion that contains it fails against a page that is perfectly correct.
	if !strings.Contains(refusedRow, "budget for this period") {
		t.Errorf("the refusal is not explained in the words the service used:\n%s", refusedRow)
	}
	if strings.Contains(refusedRow, "QUOTA_EXCEEDED") {
		t.Errorf("the page shows the operator a NIP-47 protocol word:\n%s", refusedRow)
	}
	if strings.Contains(neverRow, "Last refused") {
		t.Errorf("a connection that was never refused claims it was:\n%s", neverRow)
	}
}

// healthFunc lets a test stand in for the running service. The seam is
// consumer-declared in internal/api, so this is one function and no fake type.
type healthFunc func() map[int64]nwc.ConnectionHealth

func (f healthFunc) Health() map[int64]nwc.ConnectionHealth { return f() }

func aPairing(t *testing.T, h *harness, name string, relays ...string) store.NWCConnection {
	t.Helper()
	if len(relays) == 0 {
		relays = []string{"wss://relay.good"}
	}
	row, err := h.store.CreateNWCConnection(t.Context(), store.NWCConnection{
		Name:           name,
		ServicePrivkey: secret.New("aa"),
		ServicePubkey:  name + "-service-pub",
		ClientPubkey:   name + "-client-pub",
		ClientSecret:   secret.New("bb"),
		Relays:         relays,
		Permissions:    store.DefaultPermissions(),
		CreatedAt:      time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC),
	}, store.DefaultLimits)
	if err != nil {
		t.Fatalf("CreateNWCConnection: %v", err)
	}
	return row
}

// sectionFor is one connection's block of the page. Asserting against the whole
// body would let one row's state satisfy an assertion about another's, which is
// the shape that makes a two-row test prove nothing.
func sectionFor(t *testing.T, body, name string) string {
	t.Helper()
	start := strings.Index(body, name)
	if start < 0 {
		t.Fatalf("the page has no connection called %q:\n%s", name, body)
	}
	rest := body[start:]
	// Bounded at BOTH ends of the list, not just between rows. The last row
	// otherwise runs into the create form, which says "relay" several times and
	// offers every configured one — so an assertion about this row's reason
	// would be satisfied by a form nobody filled in.
	end, found := len(rest), false
	for _, boundary := range []string{`<section class="connection`, "<h2>Add a connection</h2>"} {
		if i := strings.Index(rest, boundary); i > 0 && i < end {
			end, found = i, true
		}
	}
	if !found {
		// Both anchors are markup this page always emits, so neither matching
		// means the markup moved — and a section that silently ran to the end of
		// the body would swallow the create form, weakening every negative
		// assertion above it without failing anything (found by review).
		t.Fatalf("neither section boundary was found after %q; the page's markup has changed "+
			"and this helper is now returning the rest of the document", name)
	}
	return rest[:end]
}

func (h *harness) body(t *testing.T, path string, cookie *http.Cookie) string {
	t.Helper()
	rec := h.get(t, path, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, rec.Code)
	}
	return rec.Body.String()
}

// A refusal recorded with no message of its own still says something useful.
//
// The fallback path: a row written before the message column existed, or any
// future caller that records a code alone. It must not render a blank line or
// the raw protocol word.
func TestARefusalWithNoMessageFallsBackToTheCode(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	refused := aPairing(t, h, "an upgraded pairing", "wss://relay.good")
	at := time.Date(2026, 8, 25, 14, 32, 0, 0, time.UTC)
	if err := h.store.RecordNWCRefusal(t.Context(), refused.ID, "QUOTA_EXCEEDED", "", at); err != nil {
		t.Fatal(err)
	}

	row := sectionFor(t, h.body(t, "/connections", cookie), "an upgraded pairing")
	if !strings.Contains(row, "spending limit") {
		t.Errorf("a refusal with no stored message renders nothing an operator can act on:\n%s", row)
	}
}

// d24.18 criterion 11: the page does not claim a resilience a migrated pairing
// does not have.
//
// A pairing carrying one relay after the migration is exactly as fragile as it
// was yesterday, and the operator will only re-pair if the page says so. This is
// spike item (c)'s "a form that lies", one layer down — and the honesty has a
// second half the brief could not have known: NIP-47 says the URI's relay
// parameter "may be more than one", and Amethyst's parser keeps
// `getQueryParameter("relay")?.firstOrNull()` and discards the rest. So even a
// three-relay pairing gains nothing with a client that reads only the first, and
// the page says that too rather than promising failover the wallet will not use.
//
// BOTH ROWS are asserted, on wording unique to each, with a negative assertion
// that the single-relay row does not carry the multi-relay sentence. Wave 28's
// page tests could not fail for exactly this reason: `Contains(row, "relay")` was
// satisfied by the row's own Relay field and by the fixture's name, so a fixture
// name with no "relay" in it is part of the test.
func TestThePageDoesNotPromiseFailoverAPairingDoesNotHave(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	aPairing(t, h, "the phone in the kitchen", "wss://one.example")
	aPairing(t, h, "the tablet upstairs", "wss://first.example", "wss://second.example")

	body := h.body(t, "/connections", cookie)
	migrated := sectionFor(t, body, "the phone in the kitchen")
	paired := sectionFor(t, body, "the tablet upstairs")

	// The migrated one says it depends on one relay, and what to do about it.
	if !strings.Contains(migrated, "unreachable whenever that relay") {
		t.Errorf("a one-relay pairing does not say it is only as good as that relay:\n%s",
			migrated)
	}
	if !strings.Contains(migrated, "pairing the app again") {
		t.Errorf("a one-relay pairing does not say what would give it more; re-pairing is the "+
			"operator action that unlocks this, and silently better-for-new-pairings-only is "+
			"the shape nobody discovers:\n%s", migrated)
	}
	// And it does NOT carry the multi-relay sentence.
	if strings.Contains(migrated, "keeps working while any one of them does") {
		t.Errorf("a one-relay pairing claims the resilience of a list:\n%s", migrated)
	}

	// The multi-relay one says what it has — and is honest that a client which
	// reads only the first relay uses only the first.
	if !strings.Contains(paired, "keeps working while any one of them does") {
		t.Errorf("a multi-relay pairing does not say so:\n%s", paired)
	}
	// THE WHOLE CLAUSE, not just the URL. The URL alone appears in the plain
	// comma-separated relay list two lines up, so the assertion was satisfied
	// whatever the sentence about it said — deleting the clause left this test
	// green (found by review).
	if !strings.Contains(paired, "uses wss://first.example and nothing else") {
		t.Errorf("the multi-relay pairing does not name the relay a single-relay client "+
			"would use:\n%s", paired)
	}
}

// Spike item (c): the create form offers the operator's first few relays rather
// than one, and says the first one matters most.
//
// It ships in this commit and not earlier: a list of which only the first entry
// could ever be used would have been a control implying a resilience the pairing
// URI had no way to express.
func TestTheCreateFormOffersSeveralRelaysAndSaysTheFirstMattersMost(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
		opts.Settings = db
	})
	// BEFORE the login, which renders a page and fills the settings cache: the
	// snapshot has a TTL, so a setting written after it is not what the next page
	// reads.
	if err := h.store.SetSetting(t.Context(), api.SettingRelays,
		"wss://nos.lol\nwss://relay.damus.io\nwss://relay.primal.net\nwss://relay.nostr.band"); err != nil {
		t.Fatal(err)
	}
	cookie := h.login(t)

	body := h.body(t, "/connections", cookie)
	form := body[strings.Index(body, "<h2>Add a connection</h2>"):]

	// IN ORDER, which the same test's last assertion calls load-bearing: a
	// prefill that reversed after the cap would satisfy a presence check and put
	// the relay an operator trusts least at the front, where a single-relay client
	// would use it (found by review).
	offered := "wss://nos.lol\nwss://relay.damus.io\nwss://relay.primal.net"
	if !strings.Contains(form, offered) {
		t.Errorf("the create form does not offer the operator's first three relays in their "+
			"own order:\n%s", form)
	}
	// CAPPED, and at the same number a row may hold: a form that offered four
	// would be refused by the handler that reads it.
	if strings.Contains(form, "wss://relay.nostr.band") {
		t.Errorf("the create form offers a fourth relay; a pairing may name %d:\n%s",
			nostr.MaxPairingRelays, form)
	}
	if !strings.Contains(form, "first one matters most") {
		t.Errorf("the form does not say the order is load-bearing, which it is: a client that "+
			"reads only the first relay from the pairing code uses exactly that one:\n%s", form)
	}
}
