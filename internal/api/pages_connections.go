package api

import (
	gonostr "github.com/nbd-wtf/go-nostr"

	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/nwc"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/web"
	"slices"
)

// permissionOptions is §8's permission groups as the create form offers them.
//
// The CONSEQUENCE text is a §9 requirement rather than help text: the page must
// state that granting `pay` is what lets this connection spend. The others carry
// one too so the list reads as one thing and the pay line does not look like a
// warning bolted onto an otherwise plain form — a warning that stands out
// because it is the only sentence is a warning people learn to skip.
var permissionOptions = []web.PermissionOption{
	{Group: store.PermissionInfo, Label: "Read node information",
		Consequence: "Lets this app see your node's alias, network and block height.", Default: true},
	{Group: store.PermissionBalance, Label: "Read the balance",
		Consequence: "Lets this app see the wallet balance you have allocated here — never your node's.", Default: true},
	{Group: store.PermissionInvoice, Label: "Create invoices",
		Consequence: "Lets this app ask your node for invoices to be paid.", Default: true},
	{Group: store.PermissionLookup, Label: "Look up invoices",
		Consequence: "Lets this app check whether an invoice has been paid.", Default: true},
	{Group: store.PermissionHistory, Label: "Read transaction history",
		Consequence: "Lets this app list payments in and out.", Default: true},
	{Group: store.PermissionPay, Label: "Pay invoices",
		Consequence: "Granting this is what lets this connection spend your sats. " +
			"It can pay up to the limits you set below, without asking you again.",
		Default: false},
}

func (s *Server) connectionsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data, values, _ := s.page(ctx, "Connections")
	view := web.ConnectionsView{
		Groups:                permissionOptions,
		DefaultBudgetSats:     store.DefaultConnectionBudgetMsat / 1000,
		DefaultMaxPaymentSats: store.DefaultConnectionMaxPaymentMsat / 1000,
		SendingEnabled:        values.get(nwc.SettingSendEnabled) == "true",
		RelayPrefill:          relayPrefill(nostr.ParseRelays(values.get(SettingRelays))),
	}
	// Nil-tolerant, like every other optional seam here: a build without a
	// connection store renders the page and its form rather than panicking, and
	// §11's posture is degraded over dead.
	if s.Connections != nil {
		rows, err := s.Connections.AllNWCConnections(ctx)
		if err != nil {
			data.Error = "The connections could not be read."
			s.Log.Error("reading NWC connections", "error", err.Error())
		}
		// Read ONCE for the whole page rather than per row: it is a snapshot of
		// state several goroutines write, and taking it per row would let two
		// rows of one page disagree about a moment.
		//
		// Nil-tolerant like every other optional seam here (§11: degraded over
		// dead). No service means nobody knows, which the row renders as "not
		// known yet" rather than as either answer.
		var health map[int64]nwc.ConnectionHealth
		if s.NWCHealth != nil {
			health = s.NWCHealth.Health()
		}
		show := r.URL.Query().Get("show")
		for _, row := range rows {
			connection := s.connectionRow(row, show)
			connection.Health = healthView(health, row)
			view.Connections = append(view.Connections, connection)
		}
	}
	data.Connections = view
	data.Flash = flashFrom(r)
	s.render(w, "connections", data)
}

// relayPrefill is what the create form starts with: the first few of the
// operator's own relays, one per line (spike item (c) of d24.20).
//
// The form used to prefill ONE — `index . 0` — and that was right while a pairing
// could only carry one: a list of which only the first entry could ever be used
// would have been a control implying a resilience the build did not have. d24.18
// is what makes it true, which is why the two ship together.
//
// The ORDER is the operator's own list's, unchanged, and it matters twice over:
// nostr.DefaultRelays leads with nos.lol because entry zero is what a stock
// pairing lands on, and a client that reads only the first relay from the pairing
// code uses exactly that one.
//
// A PREFILL and not a policy — the operator can type anything they like over it,
// including one relay, which is what an operator pairing an app they know reads
// only the first would sensibly do.
func relayPrefill(operator []string) string {
	if len(operator) > nostr.MaxPairingRelays {
		operator = operator[:nostr.MaxPairingRelays]
	}
	return strings.Join(operator, "\n")
}

// connectionRow renders one pairing. The URI is built only for the row the
// operator asked to see: it carries the secret, and a page that rendered every
// one of them would put every pairing on screen at once for the sake of the one
// being looked at.
func (s *Server) connectionRow(row store.NWCConnection, show string) web.ConnectionRow {
	out := web.ConnectionRow{
		ID:           row.ID,
		Name:         row.Name,
		Relays:       row.Relays,
		CanPay:       row.CanPay(),
		Revoked:      row.Revoked,
		PausedReason: row.PausedReason,
		PausedAt:     row.PausedAt,
		SpentMsat:    row.BudgetUsedMsat,
		CreatedAt:    row.CreatedAt,
		LastUsedAt:   row.LastUsedAt,
	}
	if row.BudgetMsat != nil {
		out.BudgetMsat = *row.BudgetMsat
	} else if row.CanPay() {
		// Only a connection that CAN spend is "unlimited"; one that cannot has
		// nil limits because limits would be meaningless on it, not because an
		// operator chose none. Pre-ticking the edit form's No-limits box from
		// the nil alone is how a receive-only pairing's edit form came to open
		// already asking for unbounded spend (found by review).
		out.Unlimited = true
	}
	if row.MaxPaymentMsat != nil {
		out.MaxPaymentMsat = *row.MaxPaymentMsat
	}
	out.BudgetSats, out.MaxPaymentSats = out.BudgetMsat/1000, out.MaxPaymentMsat/1000
	out.LastRefusal, out.LastRefusalAt = refusalSentence(row), row.LastRefusalAt
	// The edit form's boxes start where this connection actually is (d24.17). An
	// update form that opened with the DEFAULTS ticked would turn "lower my
	// budget" into "silently re-grant every permission", which is the opposite
	// of what an operator reaching for this control is trying to do.
	out.Groups = make([]web.PermissionOption, 0, len(permissionOptions))
	for _, option := range permissionOptions {
		option.Default = slices.Contains(row.Permissions, option.Group)
		out.Groups = append(out.Groups, option)
	}
	// A REVOKED connection never gets a pairing code, whatever the URL asks for.
	// Its secret is of no use to anyone now, and rendering it is a secret on
	// screen for nothing (found by review).
	if !row.Revoked && show == strconv.FormatInt(row.ID, 10) {
		out.ShowPairing = true
		out.Pairing = pairing(row)
	}
	return out
}

// healthView turns the service's state into the sentence the page states.
//
// A REVOKED pairing gets nothing: it is not being served and never will be
// again, so "not working" would read as a fault rather than as the operator's
// own decision, which the row already says in its own words.
func healthView(health map[int64]nwc.ConnectionHealth, row store.NWCConnection) web.ConnectionHealthView {
	if row.Revoked {
		return web.ConnectionHealthView{}
	}
	state, known := health[row.ID]
	if !known {
		return web.ConnectionHealthView{}
	}
	// IN THE PAIRING'S OWN ORDER. The registry records relays as their sessions
	// first reported, which is whichever dial finished first — and this page says,
	// two lines further up, that the first relay is the one a single-relay client
	// uses. The two must not disagree.
	state = state.Order(row.Relays)
	view := web.ConnectionHealthView{Known: true, Working: state.Working(), Since: state.Since}
	if state.State == nwc.HealthUnusable {
		view.Unusable = true
		return view
	}
	for _, relay := range state.Relays {
		view.Relays = append(view.Relays, web.RelayHealthView{
			Relay:       relay.Relay,
			State:       string(relay.State),
			Since:       relay.Since,
			FailedDials: relay.FailedDials,
			Reconnects:  relay.Reconnects,
		})
	}
	return view
}

// refusalSentence is what this pairing was last told, in the words the service
// used when it told them.
//
// THE STORED MESSAGE FIRST, and that ordering is a review finding rather than a
// preference. The service composes a differentiated sentence per refusal — §8's
// ruling 2 — and RESTRICTED alone has six of them: a permission this pairing
// does not hold, sending being off, no spend credential, spending held, a Tier-2
// check failing, a freeze at dispatch. Rendering one sentence per CODE was
// therefore wrong five times out of six, and wrong in the direction that costs
// the most: on a stock receive-only install the likely case is "sending is off",
// and the page said "this pairing is not allowed to do that" — sending the
// operator to permission boxes that were already correct, directly underneath
// this page's own banner explaining that sending is off.
//
// refusalWords remains the fallback, for a row written before the message column
// existed and for any future path that records a code alone.
func refusalSentence(row store.NWCConnection) string {
	if strings.TrimSpace(row.LastRefusalMessage) != "" {
		return row.LastRefusalMessage
	}
	return refusalWords(row.LastRefusalCode)
}

// refusalWords says what a NIP-47 error code means to the person who has to act
// on it, for a refusal that carries no message of its own.
//
// The CODE is a protocol word, and §9's posture is that a page states
// consequences rather than vocabulary. An operator reading "QUOTA_EXCEEDED"
// beside a budget has to guess whether it was their limit or their node; the
// sentence says which — and for RESTRICTED, which has six meanings, it says as
// much as a code alone honestly can.
//
// An unrecognised code is shown as itself rather than dropped: it came from this
// build's own answer, and a page that silently rendered nothing for it would
// hide the one refusal nobody anticipated.
func refusalWords(code string) string {
	switch code {
	case "":
		return ""
	case nwc.CodeQuotaExceeded:
		return "it reached its spending limit"
	case nwc.CodeInsufficientBalance:
		return "the wallet balance you allocated here was not enough"
	case nwc.CodeRestricted:
		return "it was refused — either a permission this pairing does not hold, or sending " +
			"being off or held on this node"
	case nwc.CodeUnauthorized:
		return "it is not authorised for this connection"
	case nwc.CodePaymentFailed:
		return "the payment failed at your node"
	default:
		return code
	}
}

// pairing builds §8's URI and its picture.
//
// Assembled here and nowhere else, so there is one place that knows the secret
// goes into a query parameter — and one place to look when asking whether it can
// escape. It is never logged, never returned in an error, and never audited: the
// audit row for a connection carries its id and name (§12).
func pairing(row store.NWCConnection) web.PairingView {
	// ONE `relay` PARAMETER PER RELAY, which is what NIP-47 says: "URL of the
	// relay where the wallet service is connected and will be listening for
	// events. May be more than one."
	//
	// THE ORDER IS LOAD-BEARING, and measurably so. Amethyst's parser takes
	// `url.getQueryParameter("relay")?.firstOrNull()` and discards the rest
	// (quartz/.../Nip47WalletConnect.kt, read 25 Aug 2026), so a client that
	// implements only the first pairs on exactly the relay at the front of this
	// URI and gains nothing from the others. The first entry is therefore the one
	// a single-relay client depends on entirely — the same lesson
	// nostr.DefaultRelays' own ordering comment records, one layer along.
	var params []string
	for _, relay := range row.Relays {
		params = append(params, "relay="+url.QueryEscape(relay))
	}
	params = append(params, "secret="+row.ClientSecret.Reveal())
	uri := fmt.Sprintf("nostr+walletconnect://%s?%s", row.ServicePubkey, strings.Join(params, "&"))
	return web.PairingView{URI: uri, QR: web.QRCode(uri)}
}

// createConnection is §9 item 4's create form.
func (s *Server) createConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if s.Connections == nil {
		http.Redirect(w, r, "/connections?flash=refused", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		http.Redirect(w, r, "/connections?flash=name_required", http.StatusSeeOther)
		return
	}
	// A LIST since d24.18, one per line, in the order the operator wrote them —
	// which is the order the pairing URI will carry them in, and a client that
	// implements only the first will use exactly the first.
	relays := postedRelays(r)
	if len(relays) == 0 {
		http.Redirect(w, r, "/connections?flash=relay_required", http.StatusSeeOther)
		return
	}
	if len(relays) > nostr.MaxPairingRelays {
		http.Redirect(w, r, "/connections?flash=too_many_relays", http.StatusSeeOther)
		return
	}
	// Checked here rather than discovered later. A typo'd relay stores fine and
	// then fails at pairing time, where the operator has a QR code, a phone, and
	// no way to tell a bad address from a relay that happens to be down.
	//
	// ALL of them, and one bad address refuses the form rather than being
	// dropped: a pairing silently created with two of the three relays the
	// operator typed is one whose URI does not say what they think it says.
	for _, relay := range relays {
		if !nostr.IsRelayURL(relay) {
			http.Redirect(w, r, "/connections?flash=bad_relay", http.StatusSeeOther)
			return
		}
	}

	groups := postedGroups(r)

	// Two keypairs, and neither is the server's own: §8 gives every connection
	// its own service key so an observer cannot link the operator's apps to each
	// other on the relay. Minted rather than derived, through the one function
	// that hands back a private half — see nostr.NewPairingKey for why that is a
	// constructor and not an accessor.
	servicePriv, servicePub, err := nostr.NewPairingKey()
	if err != nil {
		s.Log.Error("generating a connection service key", "error", err.Error())
		http.Redirect(w, r, "/connections?flash=refused", http.StatusSeeOther)
		return
	}
	clientPriv, clientPub, err := nostr.NewPairingKey()
	if err != nil {
		s.Log.Error("generating a connection client key", "error", err.Error())
		http.Redirect(w, r, "/connections?flash=refused", http.StatusSeeOther)
		return
	}

	row := store.NWCConnection{
		Name:           name,
		ServicePrivkey: secret.New(servicePriv),
		ServicePubkey:  servicePub,
		ClientPubkey:   clientPub,
		ClientSecret:   secret.New(clientPriv),
		Relays:         relays,
		Permissions:    groups,
		CreatedAt:      time.Now(),
	}
	// plk: a connection that may pay is bounded unless the operator says
	// otherwise IN SO MANY WORDS. Blank fields are "you did not say" and get the
	// defaults; the unlimited box is the explicit act. The SAME reading as the
	// update form's, through one function, because two readings of one form is
	// how "unlimited" comes to mean different things on two pages.
	budget, perPayment, limits, ok := postedLimits(w, r)
	if !ok {
		return
	}
	if budget != nil {
		row.BudgetMsat = budget
		row.BudgetPeriod = store.BudgetDaily
	}
	row.MaxPaymentMsat = perPayment

	created, err := s.Connections.CreateNWCConnection(ctx, row, limits)
	if err != nil {
		// Deliberately not %w into the flash or the log line: the row carries
		// two secrets, and an error string built from it is the easiest way for
		// one to reach a log (§11, §12).
		s.Log.Error("creating an NWC connection", "name", name, "error", err.Error())
		http.Redirect(w, r, "/connections?flash=refused", http.StatusSeeOther)
		return
	}
	s.auditRequest(r, slog.LevelInfo, "an NWC connection was created",
		logging.EventConnectionCreate,
		slog.Int64("connection", created.ID), slog.String("name", created.Name),
		slog.Bool("can_pay", created.CanPay()))
	// uhg: the service picks it up without a restart.
	nudge(s.NWCDemand)
	http.Redirect(w, r, "/connections?flash=created&show="+strconv.FormatInt(created.ID, 10),
		http.StatusSeeOther)
}

// updateConnection is §9 item 4's UPDATE control (d24.17).
//
// It exists because the 0.1.9 field trip could not run its step 6: there was no
// update route, and an operator's only way to lower a limit was to revoke the
// pairing and re-pair the phone. That inverts the incentive exactly when someone
// is worried — tightening a limit is the cheapest safety action available and it
// was the most expensive one to take.
//
// SCOPE, and the line is the ruling's: budget, per-payment cap, and the
// permission GROUPS. Removing `pay` from a live connection is the same operator
// move as lowering a budget, so it belongs on the same form. The relay and the
// keys are NOT editable — changing either is a new pairing, and pretending
// otherwise would leave a wallet app holding a URI that no longer works while
// the page said the connection was fine.
func (s *Server) updateConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "that is not a connection", http.StatusBadRequest)
		return
	}
	if s.Connections == nil {
		http.Redirect(w, r, "/connections?flash=refused", http.StatusSeeOther)
		return
	}

	groups := postedGroups(r)
	budget, perPayment, limits, ok := postedLimits(w, r)
	if !ok {
		return
	}

	stored, changed, err := s.Connections.UpdateNWCConnectionLimits(ctx, id, groups,
		budget, perPayment, limits, time.Now())
	if err != nil {
		s.Log.Error("updating an NWC connection", "connection", id, "error", err.Error())
		http.Redirect(w, r, "/connections?flash=refused", http.StatusSeeOther)
		return
	}
	if !changed {
		// No such connection, or a revoked one. Nothing changed, so nothing is
		// claimed — the same rule the revoke path learned (§12).
		http.Redirect(w, r, "/connections?flash=nothing_to_update", http.StatusSeeOther)
		return
	}
	// The STORED limits, not the posted ones. Blank fields become plk's defaults
	// inside the store, so auditing the request would record 0 — which
	// limitOrZero's own contract reads as "no limit" — for a connection that was
	// in fact bounded (found by review). §12's trail has to answer "changed to
	// what?" with what is now true.
	s.auditRequest(r, slog.LevelWarn, "an NWC connection's limits were changed",
		logging.EventConnectionUpdate, slog.Int64("connection", id),
		slog.Bool("can_pay", stored.CanPay()),
		slog.Int64("budget_msat", limitOrZero(stored.BudgetMsat)),
		slog.Int64("max_payment_msat", limitOrZero(stored.MaxPaymentMsat)))
	// uhg's THIRD reload path, and until now it had no production caller: the
	// running service re-reads the row and the NEXT payment is measured against
	// the new limit, with no restart. That is the failure uhg was reframed
	// around — an operator who lowers a limit and sees no effect — and it was
	// unreachable because the change could not be made at all.
	nudge(s.NWCDemand)
	http.Redirect(w, r, "/connections?flash=updated", http.StatusSeeOther)
}

// limitOrZero renders a nullable limit for the audit row. Zero means "no limit",
// which is what nil means everywhere else here.
func limitOrZero(limit *int64) int64 {
	if limit == nil {
		return 0
	}
	return *limit
}

// postedRelays reads the relay box: one per line, in the operator's order, with
// blanks dropped.
//
// nostr.ParseRelays is deliberately NOT used, and the difference is the whole
// point of this function existing. That one silently discards anything that is
// not a relay URL and falls back to DefaultRelays when nothing survives — right
// for a settings field the operator can re-read, and catastrophic here: it would
// turn a typo into a pairing on the OPERATOR'S OWN relays, which is precisely
// the co-publication §8 forbids and the arch rule guards. This one keeps what was
// typed so the validation above can refuse it.
func postedRelays(r *http.Request) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.FieldsFunc(r.PostFormValue("relays"), func(c rune) bool {
		return c == '\n' || c == '\r' || c == ',' || c == ' ' || c == '\t'
	}) {
		trimmed := strings.TrimSpace(line)
		// NORMALISED for the comparison and stored as typed. `wss://a` and
		// `wss://a/` are one relay, and a pairing that named both would hold two
		// sockets to it and key its sessions on one — which the service refuses
		// outright, so an operator who pasted the same address twice would get a
		// pairing that cannot be served rather than a tidy list.
		key := gonostr.NormalizeURL(trimmed)
		if trimmed == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, trimmed)
	}
	return out
}

// postedGroups reads the permission checkboxes.
func postedGroups(r *http.Request) []string {
	var groups []string
	for _, option := range permissionOptions {
		if r.PostFormValue("group_"+option.Group) != "" {
			groups = append(groups, option.Group)
		}
	}
	return groups
}

// postedLimits reads the two limit fields and the unlimited box, redirecting and
// reporting false when one of them was typed wrongly.
//
// Shared by create and update because they are one decision made twice, and plk
// applies to both: blank means "you did not say" and gets the defaults, the
// unlimited box is the explicit act, and anything else is refused rather than
// silently defaulted.
func postedLimits(w http.ResponseWriter, r *http.Request) (budget, perPayment *int64,
	limits store.LimitPolicy, ok bool) {
	rawBudget := strings.TrimSpace(r.PostFormValue("budget_sats"))
	rawCap := strings.TrimSpace(r.PostFormValue("max_payment_sats"))
	budget, budgetErr := limitMsat(rawBudget)
	perPayment, capErr := limitMsat(rawCap)

	if r.PostFormValue("unlimited") != "" {
		// TICKED TOGETHER WITH A TYPED LIMIT, THE FORM CONTRADICTS ITSELF, AND
		// IT IS REFUSED RATHER THAN RESOLVED.
		//
		// Letting the box win was a real hole found by review, and the update
		// form is where it bit: the edit form pre-ticks "No limits" from the
		// row, every connection WITHOUT the pay group has nil limits (defaults
		// are only applied to one that can spend), so an operator granting `pay`
		// on an existing pairing and typing 5000 sats got an UNBOUNDED paying
		// connection, a green "Saved" and an audit row saying the limits were
		// changed. That is precisely the state plk exists to make unreachable,
		// reached through the control whose justification is that tightening
		// should be cheap.
		//
		// Refusing beats picking a winner because both readings are defensible
		// and only the operator knows which they meant.
		// NON-EMPTY, not "parsed to a limit". A box holding "twenty" is a box the
		// operator typed in, and reading only the parsed value would let the
		// unlimited box quietly win over a typo — the same silent-win this whole
		// branch exists to stop, one step further along.
		if rawBudget != "" || rawCap != "" {
			http.Redirect(w, r, "/connections?flash=conflicting_limits", http.StatusSeeOther)
			return nil, nil, store.DefaultLimits, false
		}
		return nil, nil, store.NoLimits, true
	}
	if budgetErr != nil || capErr != nil {
		http.Redirect(w, r, "/connections?flash=bad_amount", http.StatusSeeOther)
		return nil, nil, store.DefaultLimits, false
	}
	return budget, perPayment, store.DefaultLimits, true
}

// connectionAction is the ceremony both of the operator's switches perform,
// said ONCE: parse the id, refuse if the store is absent, apply, and — only if
// something actually changed — write the §12 row and wake the subscriber.
//
// The rule worth keeping in one place is the middle one. Nothing changed means
// nothing is claimed: no audit row and no nudge, because §12's trail answers
// "what happened to this connection" and an entry for an id that never existed
// is an answer to a question nobody can check. Written twice, it is a rule that
// can come to differ between the switch that ends a pairing and the switch that
// restores one.
type connectionAction struct {
	// apply reports whether it changed anything, which is what decides the rest.
	apply func(context.Context, int64) (bool, error)
	verb  string // for the error log: "revoking", "resuming"
	event logging.Event
	msg   string
	// done and noop are whole redirect targets rather than bare markers, so the
	// literal "?flash=<marker>" still appears in this file — flash_test.go
	// scans the source for exactly that, and a marker assembled by concatenation
	// is one it cannot see.
	done string // where to go when something changed
	noop string // where to go when nothing did
}

func (s *Server) connectionAction(w http.ResponseWriter, r *http.Request, a connectionAction) {
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "that is not a connection", http.StatusBadRequest)
		return
	}
	if s.Connections == nil {
		http.Redirect(w, r, "/connections?flash=refused", http.StatusSeeOther)
		return
	}
	changed, err := a.apply(r.Context(), id)
	if err != nil {
		s.Log.Error(a.verb+" an NWC connection", "connection", id, "error", err.Error())
		http.Redirect(w, r, "/connections?flash=refused", http.StatusSeeOther)
		return
	}
	if !changed {
		http.Redirect(w, r, a.noop, http.StatusSeeOther)
		return
	}
	s.auditRequest(r, slog.LevelWarn, a.msg, a.event, slog.Int64("connection", id))
	// The subscription moves now, not at the next restart (uhg): a revocation
	// that waited for one would be a revocation that did nothing, and a resume
	// that waited would leave the operator's fix looking broken.
	nudge(s.NWCDemand)
	http.Redirect(w, r, a.done, http.StatusSeeOther)
}

// revokeConnection stops a pairing working.
func (s *Server) revokeConnection(w http.ResponseWriter, r *http.Request) {
	s.connectionAction(w, r, connectionAction{
		// A closure, not a method value: s.Connections is an interface, and
		// binding a method value off a nil one panics — before the nil check
		// inside connectionAction has had a chance to answer the request.
		apply: func(ctx context.Context, id int64) (bool, error) {
			return s.Connections.RevokeNWCConnection(ctx, id)
		},
		verb:  "revoking",
		event: logging.EventConnectionRevoke,
		msg:   "an NWC connection was revoked",
		done:  "/connections?flash=revoked",
		noop:  "/connections?flash=nothing_to_revoke", // absent, or already revoked
	})
}

// errNotAnAmount is what a limit field that was filled in wrongly produces.
var errNotAnAmount = errors.New("that is not an amount of sats")

// limitMsat reads a limit field: nil when blank, an amount in msat when given,
// and an error when the operator typed something that is not one.
//
// The three cases are kept APART, which the first version did not do: blank,
// "-5" and "twenty" all fell to the same "not given" branch and were answered
// with plk's default. An operator who deliberately typed a small cap and made a
// typo got a 25 000 sat one instead, silently — the opposite of what they asked
// for, in the direction that spends more. Found by review.
func limitMsat(raw string) (*int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	sats, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || sats <= 0 {
		return nil, errNotAnAmount
	}
	// int64 msat holds 9.2e15 — more than the 2.1e15 msat that will ever exist —
	// so the multiplication cannot overflow for any sats value ParseInt accepted
	// that is also a plausible amount. Guarded anyway: ParseInt accepts up to
	// 9.2e18, and *1000 on that wraps to a negative limit, which reads as
	// "no limit at all" everywhere downstream.
	if sats > maxLimitSats {
		return nil, errNotAnAmount
	}
	msat := sats * 1000
	return &msat, nil
}

// maxLimitSats is more sats than exist (21e6 BTC = 2.1e15 sats); a limit above
// it is a typo, and accepting it risks the msat multiplication wrapping.
const maxLimitSats int64 = 2_100_000_000_000_000

// resumeConnection is the operator saying the app that owns this pairing is
// fixed (`xmc` Fix C, Ruling A).
//
// PAUSE IS UNDONE, NOT REVOKE. The app paused this pairing because its requests
// kept crashing the handler; the client was buggy rather than hostile, so the
// way back must not cost the operator a re-pairing. This clears the pause and
// the panic count together — the count is what makes the next single panic
// harmless rather than instantly fatal, and clearing it is the operator
// asserting that something changed.
func (s *Server) resumeConnection(w http.ResponseWriter, r *http.Request) {
	s.connectionAction(w, r, connectionAction{
		apply: func(ctx context.Context, id int64) (bool, error) {
			return s.Connections.ResumeNWCConnection(ctx, id)
		},
		verb: "resuming",
		// Its own event rather than connection.update: the trail has to be able
		// to answer "the app paused this, and then who un-paused it".
		event: logging.EventConnectionResume,
		msg: "an operator re-enabled an NWC connection the app had paused after " +
			"repeated panics",
		done: "/connections?flash=resumed",
		noop: "/connections?flash=nothing_to_resume", // nothing was paused
	})
}
