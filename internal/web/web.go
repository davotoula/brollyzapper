// Package web embeds the admin UI templates and static assets and renders them
// (spec §3, §9). Server-rendered Go templates: no SPA, no npm, no build step.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// The static patterns are named by extension, not `static/*`: internal/web/static
// holds the stylesheet's own tests as well as the assets, and `static/*` would
// embed a _test.go into both binaries and serve it from StaticHandler. What ships
// is named.
//
// Naming three extensions is weaker than naming one, and the extension list is
// no longer the whole control: *.svg and *.png would each pick up a second file
// dropped into the directory. TestStaticServesExactlyTheNamedAssets is what
// closes that — it walks static/ on disk and fails on anything served that is
// not one of the three assets by name. Widen this line and that test goes red.
//
//go:embed templates/*.html static/*.css static/*.svg static/*.png
var assets embed.FS

// PageData is everything a template may read. It is one type rather than one
// per page so a handler cannot accidentally hand a template a value it should
// not have — there is nothing in here that a secret could be assigned to.
type PageData struct {
	Title string
	// Page is the template name Render was called with, so the nav can mark the
	// current entry. Handlers never set it; Render does, for the same reason it
	// sets Content — a handler that had to name its own page could name the
	// wrong one.
	Page string
	// Version is the build this process is running. Handlers never set it;
	// Render does, for Page's reason — one process has one version, and a
	// handler that could pass it could pass a different one.
	Version   string
	CSRFToken string
	// Flash is a one-shot message: the outcome of the last form submission.
	Flash string
	Error string
	// Degraded names the dependencies that are missing, so the UI can say which
	// one rather than simply looking broken (§11).
	Degraded []string

	// Content is the rendered page, injected into the layout. Handlers never
	// set it; Render does.
	Content template.HTML

	Setup       SetupView
	Wallet      WalletView
	Node        NodeView
	Security    SecurityView
	Settings    SettingsView
	Sending     SendingView
	Connections ConnectionsView
}

// ResidualRisk is §11's worst case, in the operator's language.
//
// A DELIVERABLE rather than help text (§9 item 3, and the d24.5 ruling): the page
// must state what enabling grants and what the residual risk is, and §11's own
// text is written for someone reading a threat model. This says the same thing to
// someone deciding whether to click a button.
//
// AMENDED FOR P4 (tna.1, 26 Aug 2026), and the amendment is the point. It used
// to say "the attacker could spend up to your node's outbound channel balance",
// because before this wave that was true: the working ceiling was bookkeeping
// the app applied to itself. The guard now enforces a rolling 24 h cap inside
// LND's request path, so the honest worst case is one window's cap — and the
// sentence has to move with the code, or the page tells the operator their risk
// is larger than it is and they discount the whole panel.
//
// It still names the two limits SEPARATELY, because they are different things:
// the ceiling is the app's own bookkeeping and a compromised server ignores it;
// the guard's cap is the one a compromised server cannot reach. §11's own text
// is written for someone reading a threat model; this says the same thing to
// someone deciding whether to click a button.
//
// The exact figures are NOT baked in here: the page renders them from Status,
// which is the guard's number and not the server's copy of it.
const ResidualRisk = "Enabling sending bakes a second macaroon that can pay Lightning invoices " +
	"from your node. It is separately revocable, locked to this container's IP address, and " +
	"expires on its own — and it is still the real risk in this app. If this server were " +
	"compromised, the attacker could spend up to the guard's rolling 24-hour limit, shown " +
	"below: that limit is enforced by your node, which asks the guard before every payment " +
	"this app makes, and the guard reads it from a setting this part of the app cannot write. " +
	"The spending ceiling you set here is a different thing — bookkeeping the app applies to " +
	"itself, which an attacker who took the app over would simply ignore. Sending cannot touch " +
	"your on-chain funds, cannot open or close channels, and cannot mint itself a wider " +
	"macaroon — the guard holds that key, in a container with no network listener of any kind. " +
	"You can revoke sending from this page at any time, and your node stops honouring the " +
	"macaroon immediately."

// SendingView drives §9 item 3's Sending page.
type SendingView struct {
	// Enabled is the operator's intent, and Ready is whether a spend credential
	// exists to act on it. They are separate because they can disagree: a guard
	// that could not bake leaves the intent unwritten, and a revoked credential
	// leaves the intent standing with nothing behind it.
	Enabled bool
	Ready   bool
	// Expiry is when the spend macaroon stops working, zero when there is none.
	Expiry time.Time
	// Blocked is every Tier-2 check that currently takes sending away, in the
	// operator's words (§11). Non-empty means the ladder is refusing payments
	// right now, whatever the toggle says.
	Blocked []SendingCheck
	// GuardReachable is whether the guard answered. Enabling needs it, and a
	// page that offered the button anyway would be offering a half-toggle.
	GuardReachable bool
	// Permitted is whether the guard will mint spend authority if asked (tna.4,
	// `06v`): the deployment ceiling AND the operator's stored latch.
	//
	// It comes from the GUARD via Status and never from the server's own
	// environment: two sources for one fact is how a page comes to promise
	// something the enforcement refuses.
	Permitted bool
	// AllowedByDeployment is GUARD_ALLOW_SENDING alone, and it is the off-state
	// with NO in-app remedy (`06v`, Ruling 4).
	//
	// THREE off-states now, and each needs its own sentence:
	//
	//	Enabled=false, Permitted=true      one click, and the ceremony
	//	AllowedByDeployment=false          nothing in this app will ever change it
	//	GuardReachable=false               the guard is down; nothing is known
	//
	// tna.4's rule that the page must not offer a control that cannot work
	// applies to all three, and the reason is unchanged: a button that fails
	// teaches an operator the app is broken rather than that it is locked.
	AllowedByDeployment bool
	// Authorisation is the outstanding one-time grant, if any. Its presence is
	// what turns the Enable button into the code form.
	Authorisation AuthorisationView
	// SpendCapMsat and PaymentCapMsat are §6's two caps as the operator has them
	// now, for the controls that change them. SpendCapMsat is the same number as
	// SpendLimitMsat below and is carried separately because that one comes from
	// §11's report and is absent on a receive-only install, while the CONTROL has
	// to show a value whether or not sending is on.
	SpendCapMsat   int64
	PaymentCapMsat int64
	// PayingConnections is how many pairings hold the pay group, so "disable
	// sending" can say what it will do to them.
	PayingConnections int
	// SpendUsedMsat and SpendLimitMsat are §6's rolling window as the GUARD sees
	// it, and SpendWindowHours is how long that window is. A zero limit means
	// the report carried no window at all — sending is off — and the page says
	// nothing rather than claiming a cap of nothing (tna.2).
	//
	// From the guard through §11's report, like every other verdict on this
	// page: the server's own idea of what it has spent is the number a
	// compromised server rewrites. Integer msat, never a formatted string and
	// never a float (§4) — the division into sats happens in the template and
	// nowhere else.
	SpendWindowView
	// ResidualRisk is §11's worst case in the operator's words — a deliverable,
	// not decoration.
	ResidualRisk string
}

// SpendWindowView is the guard's rolling cap as both pages show it.
//
// EMBEDDED in SendingView and SecurityView rather than declared in each. It was
// declared twice and mapped twice, from one preflight.SpendWindow, by two
// handlers doing the identical three lines — so a fourth field, or a change to
// how the hours are derived, was four edits with nothing to make the fourth
// happen. Embedding keeps every template path working: .Sending.SpendUsedMsat
// still resolves, through promotion.
//
// Integer msat and whole hours: the sats division happens in the template and
// nowhere else (§4), and the template must not do arithmetic on a duration.
//
// The zero value is ABSENT, which is what a receive-only install has — the page
// then says nothing rather than "0 of 0". preflight.spendWindow already returns
// nil for a limit of zero or less, so absent and "a cap of zero" arrive here as
// the same thing by its decision, not by this type losing one.
type SpendWindowView struct {
	SpendUsedMsat    int64
	SpendLimitMsat   int64
	SpendWindowHours int
}

// SendingCheck is one Tier-2 row as the Sending page shows it.
type SendingCheck struct {
	Title  string
	Detail string
}

// AuthorisationView is the pending ceremony, as the page shows it (`06v`).
//
// EVERY FIELD HERE CAME FROM THE GUARD. The page composes none of it, and in
// particular it does not compose Change: the operator's only trustworthy account
// of what they are confirming is one this container did not write, and the
// authoritative copy is the file itself. This is the page's echo of it, shown so
// the operator can check the two agree before typing anything.
//
// THERE IS NO CODE FIELD, and there must never be. The server relays a code it
// cannot read; a field for it here would put the secret in the container the
// ceremony exists to keep out, and the template would render it.
type AuthorisationView struct {
	Pending bool
	// Control is WHICH control the pending grant is for, so the code form posts
	// to the handler that can redeem it. A single form pointed at the sending
	// handler would take a code issued for a cap raise and offer it against a
	// change the operator never asked for — which the guard refuses, correctly,
	// leaving the operator with a code that works and a page that cannot use it.
	Control string
	// Msat is the pending value, for the hidden field that re-submits it.
	Msat int64
	// Change is the guard's own sentence about what is being authorised.
	Change string
	// ExpiresAt is when the code stops working, and it is the ARBITER: a
	// relative figure rendered server-side is already stale when the page is
	// read, so the instant has to stay.
	ExpiresAt time.Time
	// MinutesLeftAtRender is how long was left WHEN THE PAGE WAS BUILT, so the
	// operator does not have to know their offset from UTC and do arithmetic
	// inside a ten-minute window (BrollyZap-5z4). The name says "at render"
	// because that is the only moment it is true: a figure computed server-side
	// is already ageing when the page is read, which is why ExpiresAt stays as
	// the arbiter and the template phrases this one against page load. A whole
	// number rather than a
	// Duration because the template must not do arithmetic — the same rule
	// RejectionWindowHours follows — and it is phrased against page load in the
	// template, which is the honest thing to say about a number that ages.
	//
	// Rounded UP, so a code with seconds left says "1 minute" rather than "0",
	// which would read as dead on one that still works.
	MinutesLeftAtRender int
	// Location is where the DEPLOYMENT says the file will be found, in words a
	// person can follow. §19 forbids the generic app assuming a deployment path,
	// so this arrives from the guard and is rendered as given — there is no
	// umbrelOS route anywhere in this package or in the templates.
	Location string
}

// ConnectionsView drives §9 item 4's Connections page.
type ConnectionsView struct {
	Connections []ConnectionRow
	// Groups are the permission groups the create form offers, in §8's order.
	Groups []PermissionOption
	// DefaultBudgetSats and DefaultMaxPaymentSats prefill the form with plk's
	// bounds, so a connection that may pay is bounded unless the operator
	// deliberately removes the limit.
	DefaultBudgetSats     int64
	DefaultMaxPaymentSats int64
	// SendingEnabled is whether a granted pay group can do anything yet. The
	// form says so rather than granting a capability that silently does nothing.
	SendingEnabled bool
	// RelayPrefill is what the create form starts with: the first few of the
	// operator's own relays, one per line (d24.18, spike item (c)).
	//
	// The operator's full list is no longer carried separately: the datalist that
	// offered it is gone — a text box holding several relays cannot be filled
	// from a picker one value at a time — so a Relays field beside this one would
	// be read by nothing and would describe a control the page does not have.
	//
	// A LIST rather than one value, and only since a pairing can carry a list —
	// doing it earlier would have been a form that lies, offering a resilience
	// the pairing URI had no way to express.
	RelayPrefill string
}

// PermissionOption is one tickable permission group.
type PermissionOption struct {
	Group string
	Label string
	// Consequence is shown beside the box. §9 requires the pay group to state
	// that granting it is what lets this connection spend; the others say what
	// they allow so the list reads consistently.
	Consequence string
	Default     bool
}

// ConnectionRow is one pairing in the list.
//
// Amounts stay MSAT here and are divided by the `sats` template function, which
// is the only place money is divided (§4) and the only one that renders the
// remainder §9 requires. Dividing in the handler dropped it.
type ConnectionRow struct {
	ID   int64
	Name string
	// Relays are the pairing's own, in the order its URI names them (d24.18).
	// The FIRST is the one a client that implements only one will use, which is
	// why the page shows them in order rather than sorted.
	Relays []string
	CanPay bool
	// Revoked rows are shown, marked, and without a pairing code: the operator
	// needs to see that the one they revoked is gone rather than wondering
	// whether the click worked.
	Revoked bool
	// Paused is the APP having stopped serving this pairing after its requests
	// repeatedly crashed the handler (`xmc` Fix C), with the reason in the
	// operator's words and when it happened.
	//
	// A THIRD state beside live and revoked, and it is not either of them: the
	// operator did not do this, and it is undone with one click rather than by
	// re-pairing a phone. The Connections page already answers "why is this
	// pairing not working" — relay health, the last refusal — and this is
	// another answer to the same question, in the same place.
	PausedReason   string
	PausedAt       time.Time
	BudgetMsat     int64
	Unlimited      bool
	MaxPaymentMsat int64
	SpentMsat      int64
	CreatedAt      time.Time
	LastUsedAt     time.Time
	ShowPairing    bool
	Pairing        PairingView
	// Groups is this connection's permission options with Default set to what it
	// ACTUALLY holds, so the edit form opens where the connection is (d24.17).
	// An update form pre-ticked with the creation defaults would turn "lower my
	// budget" into "silently re-grant every permission".
	Groups []PermissionOption
	// BudgetSats and MaxPaymentSats are the same limits in the unit the form
	// speaks, so the template does no arithmetic.
	BudgetSats     int64
	MaxPaymentSats int64
	// Health is whether this pairing can currently reach its relay (d24.21).
	Health ConnectionHealthView
	// LastRefusal is the last thing this pairing was told no about, and when
	// (d24.21, ruling B). Empty when it never has been.
	LastRefusal   string
	LastRefusalAt time.Time
}

// Paused reports whether the app has stopped serving this pairing. DERIVED from
// the reason, exactly as store.NWCConnection does it: a bool beside the string
// would be two sources for one fact, and a template calls a zero-argument method
// the same way it reads a field.
func (r ConnectionRow) Paused() bool { return r.PausedReason != "" }

// ConnectionHealthView is one pairing's relay session as the page states it.
//
// The state's NAME is rendered, never the underlying error: an operator's next
// move is "wait" or "pair it again", and a dial error's text distinguishes
// neither. It is also the only thing here that cannot leak — see §12 on what a
// connection's fields are allowed to reach a page as.
//
// One value rather than a bool per state, matching TxnRow and NodeView: three
// bools is eight representable combinations for four meanings, and two of them
// contradict each other.
type ConnectionHealthView struct {
	// Known is false when nothing has an opinion — no service attached, or the
	// seconds after a restart before the first reload. The page says so rather
	// than picking an answer.
	Known bool
	// Working is whether ANY of this pairing's relays currently holds a
	// subscription, which is the operator's question: a client publishes its
	// request to one relay from the same list, so one up means some client can
	// reach us and none up means none can.
	Working bool
	// Unusable distinguishes "no relay will fix this row" from "the relays are
	// down", because waiting helps with one and not the other. When it is set
	// there are no relay entries: nothing is dialling.
	Unusable bool
	// Since is when an unusable row became unusable.
	Since time.Time
	// Relays is one entry per relay, in the pairing's own order.
	Relays []RelayHealthView
}

// RelayHealthView is one relay session of one pairing, as the page states it.
type RelayHealthView struct {
	Relay string
	// State is "serving", "retrying" — the two a relay session can be in.
	State       string
	Since       time.Time
	FailedDials int
	// Reconnects is how many times this relay has come back since the service
	// started. It is what makes a flapping relay visible: one that accepts and
	// drops every few seconds reads as "working" at every moment the operator
	// looks, and this is the only field that survives the flapping.
	Reconnects int
}

// PairingView is the URI as text and as a picture.
//
// The URI carries client_secret, which is the point — a pairing that did not
// would pair nothing. It is rendered and never logged: §12's redaction covers
// store.NWCConnection, and this type exists only inside a template's reach.
type PairingView struct {
	URI string
	// QR is the same URI as inline SVG. The markup contains rectangles and no
	// text, so the secret is not in the page source (ADR 0002).
	QR template.HTML
}

// SetupView drives the first-run page.
type SetupView struct {
	// GeneratedPassword is shown once, in the browser. §9: a password that
	// exists only in the logs is a failure — and §12 means it must be unable to
	// reach a log at all, so the template reveals it explicitly.
	GeneratedPassword secret.String
	PasswordManaged   bool
	AddressConfigured bool
	LightningAddress  string
}

// LogValue keeps the one-time password out of a log line (§12). The template
// reveals it deliberately; nothing else should be able to.
func (v SetupView) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("password_managed", v.PasswordManaged),
		slog.Bool("address_configured", v.AddressConfigured),
	)
}

// WalletView drives the wallet page.
type WalletView struct {
	BalanceMsat    int64
	CreditReceived bool
	// Txns is the most recent transactions, newest first (§9 item 2). Total is
	// how many exist, so the page can say "showing 100 of 2,314" rather than
	// implying the list is everything.
	Txns  []TxnRow
	Total int64
	// HistoryError replaces the table when the history cannot be read. A
	// page-level banner is the wrong place for it: the section would still
	// print "No transactions yet.", which is a different claim and a false one.
	HistoryError string
	// Unresolvable is every pending payment the RESOLVER has given up on, which
	// the operator may close and nobody else may (`669`). Empty on a healthy
	// install, and the section does not render at all.
	Unresolvable      []UnresolvableRow
	UnresolvableError string
}

// UnresolvableRow is one payment awaiting an operator's decision, with
// everything they need to check it AT THE NODE first (`669`).
//
// §6: only they can say whether this settled. Asking someone to assert that
// without showing them what to look up produces a guess, and a guess here is a
// wrong ledger rather than an unknown one — so the hash, the amount and the
// moment it was dispatched all travel to the page.
type UnresolvableRow struct {
	ID          int64
	PaymentHash string
	// AmountMsat is the whole reservation — amount plus the fee reserve — which
	// is what returns to the ceiling if the operator says it failed.
	AmountMsat int64
	// Reason is the resolver's own words for why it gave up.
	Reason string
	When   string
	// DispatchedAt is empty when the payment was never handed to the node.
	DispatchedAt string
}

// TxnRow is one line of the transaction history, already rendered into the
// words the page shows.
//
// The decisions live here rather than in the template: a template that computed
// a receipt's status would be logic nothing can test directly, and this is the
// kind of thing that quietly starts saying "pending" forever.
type TxnRow struct {
	Kind       string
	State      string
	AmountMsat int64
	FeeMsat    int64
	// Note is the operator's own reason for an allocation; Comment is the
	// sender's words on a zap (LUD-12). Kept apart because they are different
	// people talking.
	Note    string
	Comment string
	// Payee is who an OUTGOING zap paid, as a shortened npub, and empty for
	// every other row (doy.5).
	//
	// A NIP-57 invoice has no memo to lift, so before this the operator's own
	// history showed a column of unlabelled debits while every incoming row
	// carried its zap comment. The identity comes from the zap request the
	// paired client sent with the payment, and it is the `p` TAG rather than the
	// event's pubkey: outbound the signer is the payer.
	//
	// An npub and not a name. Resolving a kind 0 profile would be a new outbound
	// path from the server container, at page-render time, against relays chosen
	// by whoever the operator paid.
	//
	// WHAT MAKES IT TRUE rather than merely displayed: since y09 a row carries an
	// event only when it hashes to the invoice that was paid. The reasoning is at
	// nwc.Service.outgoingMetadata; what matters here is that without it this
	// cell would render whichever payee the paying app chose to name.
	Payee string
	When  time.Time
	// Receipt is the zap receipt's state in one word, empty for anything that
	// is not a zap. See the constants below.
	Receipt string
	// ReceiptID is the published event id, truncated per §12's correlation
	// rule. Empty unless Receipt is "published".
	ReceiptID string
}

// Zap receipt states, as the Wallet page words them.
const (
	ReceiptPublished = "published"
	ReceiptPending   = "pending"
	ReceiptAbandoned = "abandoned"
)

// Transaction state classes, as the Wallet page colours them.
//
// The state vocabulary is open, pending, settled, expired and failed, and the
// page renders a qualifier for every one of them except settled — so the hook
// is not one meaning but two. An invoice that is open or pending is waiting,
// which is the system working and needs no attention; expired and failed are
// the rung below. Colouring all four alike would tell an operator their normal
// unpaid invoice had gone wrong.
const (
	StateClassWaiting = "waiting"
	StateClassBad     = "bad"
)

// StateClass is which of the two above this row is, so the decision lives here
// rather than in the template — the same reason Receipt arrives as a word and
// not as a computation (see TxnRow's own doc).
//
// The state strings are the store's, which declares them as SQL literals and
// not as constants; they are repeated here because this is the layer that has
// an opinion about them. Anything not known to be a failure reads as waiting:
// a state added upstream and rendered before anyone revisits this is better
// quiet than alarming.
func (t TxnRow) StateClass() string {
	switch t.State {
	case "expired", "failed":
		return StateClassBad
	default:
		return StateClassWaiting
	}
}

// NodeView drives the node page.
type NodeView struct {
	State                  string
	LNDReachable           bool
	ReceiveMacaroonPresent bool
	SpendMacaroonPresent   bool
	ReceiveExpiry          time.Time
	GuardReachable         bool
	GuardError             string
}

// SecurityView drives the security page.
type SecurityView struct {
	// Checks is §11's preflight, shown with the threat each maps to.
	Checks []CheckRow
	// BlindSpots is what this page cannot tell you. §11: a checklist of green
	// ticks that bounds nothing manufactures confidence, so the limits are on
	// the page, not in a footnote.
	BlindSpots []string
	Events     []AuditRow
	// GuardRejections is the one signal that means a bug or a compromise in
	// progress, so it renders as a banner rather than a row (§9, §12).
	//
	// It is a RATE, and the two fields travel together for that reason: a count
	// without the period it covers is the number this replaced, where the
	// denominator was "the last 200 audit rows" and twelve could mean a minute
	// or a month. The page states the window beside the number (tna.2).
	GuardRejections int
	// RejectionWindowHours is the period GuardRejections covers. Whole hours,
	// because the template must not do arithmetic on a duration.
	RejectionWindowHours int
	// The spend window, as a MEASUREMENT beside the checks rather than as one of
	// them (tna.2, Ruling A). There is no level at which "you have used X of Y"
	// becomes unsafe, and a Check would have to invent one.
	//
	SpendWindowView
}

// CheckRow is one preflight check as the page shows it.
type CheckRow struct {
	Title  string
	OK     bool
	Threat string
	Detail string
	Blocks string
}

// AuditRow is one line of the §12 trail.
type AuditRow struct {
	When     string
	Event    string
	Severity string
	Detail   string
	Remote   string
}

// SettingsView drives the settings page.
type SettingsView struct {
	Domain string
	// AdvertisedOrigin is what wallets will actually be handed — the whole
	// origin, not its parts. Shown beside the field because the domain is
	// stored bare and the scheme is a separate row, so without this the
	// operator has to remember which one they last pasted (vz1.7). The 0.1.7
	// box advertised http for an https address for exactly that reason.
	//
	// WHOLE, because the first version of this carried the scheme alone and let
	// the template concatenate it with the raw domain row. On a box configured
	// before o34.13 that row still holds "http://192.168.77.42:3033", so the
	// hint rendered "http://http://192.168.77.42:3033" — the page saying
	// something the callback never would, which is the one thing this field
	// exists to prevent.
	AdvertisedOrigin string
	AddressName      string
	LogLevel         string
	TrustedProxies   string
	// The rate-limit pair governs the PUBLIC callback only. The admin group's
	// limits are constants in internal/api and deliberately have no field
	// here: a form that let an operator raise their own login brute-force
	// ceiling would be a footgun with a label on it (d46.27).
	PublicRateLimitPerMinute int64
	PublicRateLimitPerHour   int64
	MaxFeePPM                int64
	MaxFeeFloorMsat          int64
	// Relays is the operator's relay list, one per line.
	Relays string
	// NostrPubkey is the identity announced in every LNURL response. The
	// PUBLIC half only — there is nothing on this page a private key could be
	// assigned to, deliberately (§12).
	NostrPubkey        string
	CreditReceived     bool
	PasswordChangeable bool
	ProbeOK            bool
	ProbeReason        string
	ProbeAt            string
}

// Renderer renders the embedded templates.
type Renderer struct {
	templates *template.Template
	version   string
}

// New parses every template once, at startup, so a broken one fails loudly
// there rather than on the page that happens to use it.
func New(version string) (*Renderer, error) {
	t, err := template.New("").Funcs(funcs()).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("web: parsing templates: %w", err)
	}
	return &Renderer{templates: t, version: version}, nil
}

// Render writes one page, wrapped in the layout.
func (r *Renderer) Render(w io.Writer, page string, data PageData) error {
	if r.templates.Lookup(page+".html") == nil {
		return fmt.Errorf("web: no such page %q", page)
	}
	if data.Title == "" {
		data.Title = page
	}
	data.Page = page
	data.Version = r.version
	// The page is rendered first and injected, because a Go template cannot
	// dispatch to a template chosen at runtime.
	var body strings.Builder
	if err := r.templates.ExecuteTemplate(&body, page+".html", data); err != nil {
		return fmt.Errorf("web: rendering %s: %w", page, err)
	}
	data.Content = template.HTML(body.String()) //nolint:gosec // produced by our own templates, already escaped
	return r.templates.ExecuteTemplate(w, "layout.html", data)
}

// StaticHandler serves the embedded stylesheet.
func StaticHandler() http.Handler {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		// Unreachable: the directory is embedded at build time.
		return http.NotFoundHandler()
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}

func funcs() template.FuncMap {
	return template.FuncMap{
		// sats renders msat as sats for display. Money is msat everywhere else
		// (§4); this is the only place it is divided, and only for humans.
		"sats": func(msat int64) string {
			return fmt.Sprintf("%d.%03d", msat/1000, abs(msat%1000))
		},
		// One timestamp format in the product. node.html already renders
		// "2006-01-02 15:04 UTC"; the history had its own pre-rendered string
		// that silently dropped the zone, on the page where an operator
		// correlates rows against a sender saying "I paid at 14:02".
		"when": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
		// satsPlain is sats for a FORM FIELD rather than for prose: whole sats,
		// no decimals, so the number an operator sees in the box is the number
		// they can type back. `sats` renders "100000.000", which posted back
		// would not parse as an integer — the field and the sentence beside it
		// need different renderings of the same msat, and this is the field's.
		//
		// A cap that does not divide evenly ROUNDS DOWN, which is the safe
		// direction: re-submitting the form without touching it can only tighten
		// the limit, never loosen it past what the operator set.
		"satsPlain": func(msat int64) string { return strconv.FormatInt(msat/1000, 10) },
		"list":      func(items ...string) []string { return items },
	}
}

func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
