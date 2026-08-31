package api_test

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/store"
)

// An operator can LOWER a live connection's limit, and the app stays paired
// (d24.17).
//
// Step 6 of the 0.1.9 field trip, which could not be run: there was no update
// route, and `budget_sats` was read only inside createConnection. The only way
// to tighten a limit was to revoke the pairing and re-pair the phone — which
// inverts the incentive exactly when an operator is worried, because tightening
// a limit is the cheapest safety action available and it was the most expensive
// one to take.
func TestAnOperatorCanTightenALiveConnectionsLimits(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	h.postForm(t, "/connections/create", cookie, url.Values{
		"name":             {"Amethyst on my phone"},
		"relays":           {"wss://relay.example"},
		"group_pay":        {"on"},
		"group_balance":    {"on"},
		"budget_sats":      {"100000"},
		"max_payment_sats": {"25000"},
	})
	before := onlyConnection(t, h)

	rec := h.postForm(t, "/connections/update", cookie, url.Values{
		"id":               {itoa(before.ID)},
		"group_pay":        {"on"},
		"group_balance":    {"on"},
		"budget_sats":      {"500"},
		"max_payment_sats": {"100"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /connections/update = %d %q, want 303", rec.Code, rec.Body)
	}

	after := onlyConnection(t, h)
	if after.BudgetMsat == nil || *after.BudgetMsat != 500_000 {
		t.Errorf("budget = %v, want 500000 msat", after.BudgetMsat)
	}
	if after.MaxPaymentMsat == nil || *after.MaxPaymentMsat != 100_000 {
		t.Errorf("per-payment cap = %v, want 100000 msat", after.MaxPaymentMsat)
	}
	// The pairing is untouched: same keys, same relays, same secret. That is the
	// whole point — a limit change must not cost a re-pair, and since d24.18 the
	// relay LIST is part of what a re-pair would be needed to change.
	if after.ServicePubkey != before.ServicePubkey ||
		after.ClientSecret.Reveal() != before.ClientSecret.Reveal() ||
		!slices.Equal(after.Relays, before.Relays) {
		t.Error("the update changed the pairing; the operator would have to set the app up again")
	}
	if !h.audited(t, "connection.update") {
		t.Error("changing a connection's spending authority wrote no audit event (§12)")
	}
}

// The running service is TOLD, so the next payment sees the new limit without a
// restart (d24.17, uhg).
//
// uhg's reload-on-limit-change path was tested code with NO production caller —
// the shape this project treats as rot. This is the caller.
func TestChangingALimitNudgesTheRunningService(t *testing.T) {
	demand := make(chan struct{}, 1)
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
		opts.NWCDemand = demand
	})
	cookie := h.login(t)
	h.postForm(t, "/connections/create", cookie, url.Values{
		"name": {"Amethyst"}, "relays": {"wss://relay.example"}, "group_pay": {"on"},
	})
	<-demand // the create's own nudge

	h.postForm(t, "/connections/update", cookie, url.Values{
		"id": {itoa(onlyConnection(t, h).ID)}, "group_pay": {"on"}, "budget_sats": {"500"},
	})

	select {
	case <-demand:
	default:
		t.Error("the running service was not told; the change would land in the database and " +
			"the next payment would still be measured against the old limit until a restart — " +
			"which is the failure uhg was reframed around")
	}
}

// Removing `pay` from a LIVE connection is the same operator move as lowering a
// budget, and it works the same way.
func TestAnOperatorCanTakeThePayGroupBack(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	h.postForm(t, "/connections/create", cookie, url.Values{
		"name": {"Amethyst"}, "relays": {"wss://relay.example"},
		"group_pay": {"on"}, "group_balance": {"on"},
	})

	h.postForm(t, "/connections/update", cookie, url.Values{
		"id": {itoa(onlyConnection(t, h).ID)}, "group_balance": {"on"},
	})

	after := onlyConnection(t, h)
	if slices.Contains(after.Permissions, store.PermissionPay) {
		t.Error("the pay group survived being unticked; an operator cannot take spend " +
			"authority back without revoking the pairing")
	}
	if !slices.Contains(after.Permissions, store.PermissionBalance) {
		t.Errorf("the groups that were left ticked did not survive: %v", after.Permissions)
	}
}

// Changing a budget does NOT reset the window.
//
// An operator lowering a limit must never accidentally hand the connection a
// fresh period's worth of spending — that would make the cheapest safety action
// briefly INCREASE what a worried operator's app can spend, which is the exact
// opposite of why they reached for it.
func TestChangingABudgetKeepsTheWindowAndWhatWasSpent(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	h.postForm(t, "/connections/create", cookie, url.Values{
		"name": {"Amethyst"}, "relays": {"wss://relay.example"}, "group_pay": {"on"},
	})
	created := onlyConnection(t, h)
	// A window that is UNMISTAKABLY not "now plus a day". Both the created and
	// the recomputed window land in the same Unix second when a test runs in
	// under a second, so an assertion against the row as created could not tell
	// a kept window from a fresh one — it went green against a planted reset,
	// which is the whole reason plants are run.
	window := created.CreatedAt.Add(3 * time.Hour).UTC().Truncate(time.Second)
	if _, err := h.store.SetNWCConnectionLimits(t.Context(), created.ID, created.Permissions,
		created.BudgetMsat, store.BudgetDaily, window, created.MaxPaymentMsat); err != nil {
		t.Fatal(err)
	}
	created = onlyConnection(t, h)
	if _, err := h.store.ReserveNWCBudget(t.Context(), created.ID, 40_000,
		created.CreatedAt, created.BudgetRenewsAt); err != nil {
		t.Fatal(err)
	}

	h.postForm(t, "/connections/update", cookie, url.Values{
		"id": {itoa(created.ID)}, "group_pay": {"on"}, "budget_sats": {"500"},
	})

	after := onlyConnection(t, h)
	if !after.BudgetRenewsAt.Equal(created.BudgetRenewsAt) {
		t.Errorf("the window moved from %v to %v; lowering a limit would briefly INCREASE what "+
			"this app can spend", created.BudgetRenewsAt, after.BudgetRenewsAt)
	}
	if after.BudgetUsedMsat != 40_000 {
		t.Errorf("spent = %d msat, want the 40000 already spent — a lower budget changes what "+
			"happens next, not what happened", after.BudgetUsedMsat)
	}
}

// A REVOKED connection cannot be edited, and the page says so rather than
// claiming a change.
func TestARevokedConnectionCannotBeUpdated(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	h.postForm(t, "/connections/create", cookie, url.Values{
		"name": {"Amethyst"}, "relays": {"wss://relay.example"}, "group_pay": {"on"},
	})
	id := onlyConnection(t, h).ID
	h.postForm(t, "/connections/revoke", cookie, url.Values{"id": {itoa(id)}})

	rec := h.postForm(t, "/connections/update", cookie, url.Values{
		"id": {itoa(id)}, "group_pay": {"on"}, "budget_sats": {"500"},
	})

	if got := rec.Header().Get("Location"); !strings.Contains(got, "flash=nothing_to_update") {
		t.Errorf("updating a revoked connection redirected to %q, want flash=nothing_to_update", got)
	}
	if h.audited(t, "connection.update") {
		t.Error("an audit row claims a change that never happened (§12)")
	}
}

// A mistyped limit on the UPDATE form is refused too, not silently defaulted.
//
// The same reading as the create form, through one function — two readings of
// one form is how "unlimited" comes to mean different things on two pages.
func TestAMistypedLimitOnTheUpdateFormIsRefused(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	h.postForm(t, "/connections/create", cookie, url.Values{
		"name": {"Amethyst"}, "relays": {"wss://relay.example"}, "group_pay": {"on"},
	})
	id := onlyConnection(t, h).ID

	rec := h.postForm(t, "/connections/update", cookie, url.Values{
		"id": {itoa(id)}, "group_pay": {"on"}, "budget_sats": {"twenty"},
	})

	if got := rec.Header().Get("Location"); !strings.Contains(got, "flash=bad_amount") {
		t.Errorf("a mistyped budget redirected to %q, want flash=bad_amount", got)
	}
	if got := onlyConnection(t, h); got.BudgetMsat == nil ||
		*got.BudgetMsat != store.DefaultConnectionBudgetMsat {
		t.Errorf("the budget moved to %v on a refused update", got.BudgetMsat)
	}
}

func onlyConnection(t *testing.T, h *harness) store.NWCConnection {
	t.Helper()
	rows, err := h.store.AllNWCConnections(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d connections, want 1", len(rows))
	}
	return rows[0]
}

func itoa(id int64) string { return strconv.FormatInt(id, 10) }

// "No limits" ticked TOGETHER with a typed limit is refused, not resolved.
//
// The hole review found, and the update form is where it bit. `connectionRow`
// pre-ticked the No-limits box from `BudgetMsat == nil`, and every connection
// WITHOUT the pay group has nil limits — the defaults are only applied to one
// that can spend. So an operator opening the edit form on a receive-only
// pairing, ticking "Pay invoices" and typing 5000 sats/day got an UNBOUNDED
// paying connection, a green "Saved. This connection's new limits are in force
// now", and an audit row saying the limits were changed. That is exactly the
// state plk exists to make unreachable, reached through the control whose whole
// justification is that tightening should be cheap.
func TestTickingNoLimitsWhileTypingALimitIsRefused(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	h.postForm(t, "/connections/create", cookie, url.Values{
		"name": {"Amethyst"}, "relays": {"wss://relay.example"},
		"group_balance": {"on"},
	})
	id := onlyConnection(t, h).ID

	rec := h.postForm(t, "/connections/update", cookie, url.Values{
		"id": {itoa(id)}, "group_pay": {"on"}, "group_balance": {"on"},
		"budget_sats": {"5000"}, "max_payment_sats": {"1000"},
		"unlimited": {"on"},
	})

	if got := rec.Header().Get("Location"); !strings.Contains(got, "flash=conflicting_limits") {
		t.Errorf("a contradictory form redirected to %q, want flash=conflicting_limits", got)
	}
	after := onlyConnection(t, h)
	if slices.Contains(after.Permissions, store.PermissionPay) {
		t.Error("a form that contradicted itself granted the pay group anyway")
	}
	if h.audited(t, "connection.update") {
		t.Error("an audit row claims limits were changed by a form that was refused (§12)")
	}
}

// A connection that CANNOT pay does not open its edit form asking for unbounded
// spend.
//
// Its limits are nil because limits are meaningless on it, not because an
// operator chose none — and pre-ticking "No limits" from the nil alone is what
// made the hole above reachable in one click.
func TestAReceiveOnlyConnectionDoesNotRenderAsUnlimited(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	h.postForm(t, "/connections/create", cookie, url.Values{
		"name": {"Amethyst"}, "relays": {"wss://relay.example"}, "group_balance": {"on"},
	})

	page := h.get(t, "/connections", cookie).Body.String()
	form := page[strings.Index(page, `action="/connections/update"`):]
	if i := strings.Index(form, `name="unlimited"`); i >= 0 {
		box := form[i:min(i+80, len(form))]
		if strings.Contains(box, "checked") {
			t.Errorf("the edit form for a receive-only pairing opens with No limits ticked:\n%s", box)
		}
	}
}

// The audit row states the limits that were STORED, not the ones that were
// posted (§12).
//
// Blank fields become plk's defaults inside the store, so auditing the request
// recorded budget_msat=0 and max_payment_msat=0 for a connection that was in
// fact bounded at 100 000 000 / 25 000 000 — and 0 is what everything else here
// reads as "no limit". §12's trail exists to answer "when did this app's limit
// change, and to what?", and it was answering with the operator's blanks. Found
// by review.
func TestTheUpdateAuditRowStatesTheStoredLimits(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	h.postForm(t, "/connections/create", cookie, url.Values{
		"name": {"Amethyst"}, "relays": {"wss://relay.example"}, "group_balance": {"on"},
	})

	// The pay group granted with both limit boxes left blank: plk fills them in.
	h.postForm(t, "/connections/update", cookie, url.Values{
		"id": {itoa(onlyConnection(t, h).ID)}, "group_pay": {"on"},
	})

	detail := auditDetail(t, h, "connection.update")
	if !strings.Contains(detail, `"budget_msat":100000000`) {
		t.Errorf("the trail records %s; want the STORED 100000000 msat, not the blank the "+
			"operator posted — 0 reads as \"no limit\" everywhere else here", detail)
	}
	if !strings.Contains(detail, `"max_payment_msat":25000000`) {
		t.Errorf("the trail records %s; want the STORED per-payment cap", detail)
	}
}

// auditDetail is the detail JSON of the most recent row for one event.
func auditDetail(t *testing.T, h *harness, event string) string {
	t.Helper()
	row, found := h.auditRow(t, event)
	if !found {
		t.Fatalf("no %s audit row", event)
	}
	return row.Detail
}

// And a box that was typed in WRONGLY beside a ticked "No limits" is refused
// too.
//
// The check reads whether the field is non-empty, not whether it parsed: a box
// holding "twenty" is a box the operator typed in, and letting the unlimited box
// win over a typo is the same silent win one step further along.
func TestTickingNoLimitsBesideAMistypedLimitIsRefused(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Connections = db
	})
	cookie := h.login(t)
	h.postForm(t, "/connections/create", cookie, url.Values{
		"name": {"Amethyst"}, "relays": {"wss://relay.example"}, "group_balance": {"on"},
	})

	rec := h.postForm(t, "/connections/update", cookie, url.Values{
		"id": {itoa(onlyConnection(t, h).ID)}, "group_pay": {"on"},
		"budget_sats": {"twenty"}, "unlimited": {"on"},
	})

	if got := rec.Header().Get("Location"); !strings.Contains(got, "flash=conflicting_limits") {
		t.Errorf("redirected to %q, want flash=conflicting_limits", got)
	}
	if after := onlyConnection(t, h); slices.Contains(after.Permissions, store.PermissionPay) {
		t.Error("a contradictory form granted unbounded pay anyway")
	}
}
