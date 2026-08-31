// Package preflight is §11's startup and runtime security checks: the one
// computation of "is this instance healthy", shared by the admin UI's degraded
// banner and its Security panel.
//
// It is one computation on purpose. Two independent answers drift apart, and
// the failure mode is an operator reading that the node is reachable on one
// page while another renders a re-link banner.
package preflight

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/lnd"
)

// Capability is what a failed check takes away. §11's Tier 2 blocks the
// dangerous capability, never the process — blocking startup mostly hides the
// problem.
type Capability string

const (
	// BlocksNothing: the check reports, or repaired itself.
	BlocksNothing Capability = ""
	// BlocksSending: outbound payments are refused.
	BlocksSending Capability = "sending"
	// BlocksAddress: the lightning address is unreachable; receiving by
	// invoice is unaffected.
	BlocksAddress Capability = "lightning address"
	// BlocksReceiving exists to be asserted against. Nothing in Tier 2 may
	// produce it: §11 is explicit that receiving continues.
	BlocksReceiving Capability = "receiving"
)

// Check IDs, stable so the page and the tests can name one.
const (
	CheckAdminMacaroon    = "admin.macaroon.unreachable"
	CheckNodeLinked       = "node.linked"
	CheckGuardReachable   = "guard.reachable"
	CheckSpendCaveats     = "spend.caveats"
	CheckSpendIPMatches   = "spend.ipaddr"
	CheckSpendExpiry      = "spend.expiry"
	CheckSpendRootKey     = "spend.rootkey"
	CheckSpendGuardCaveat = "spend.guard_caveat"
	CheckGuardMiddleware  = "guard.middleware"
	CheckReconciliation   = "wallet.reconciliation"
	CheckUnresolvedSpend  = "wallet.unresolved_payments"
	CheckLightningAddress = "address.reachable"
	CheckDataDirMode      = "datadir.mode"
)

// TierOneChecks is the whole of Tier 1. §11: exactly one condition, and it
// stays that way — anything else that seems startup-worthy belongs in Tier 2,
// because §19 requires degraded states rather than crash loops.
var TierOneChecks = []string{CheckAdminMacaroon}

// BlindSpots are the things this panel cannot tell the operator, stated on the
// page. §11: a checklist of green ticks that bounds nothing is worse than no
// checklist, because it manufactures confidence.
var BlindSpots = []string{
	"Whether LND's wallet password is Umbrel's default. No RPC exposes it, and probing " +
		"would be reckless on a node holding real funds.",
	"File permissions inside LND's data directory. BrollyZapper deliberately does not " +
		"mount it, and checking would mean reintroducing the hole that closed.",
	"Whether other apps on this machine hold admin-level macaroons. Not visible, and not " +
		"BrollyZapper's business.",
	"Whether your backups actually run.",
}

// sharedAdminBucket is the blind spot d46.19 adds when no proxy is trusted.
//
// It is a blind spot rather than a failed check because nothing in this process
// can see whether there IS a proxy in front of it. With none, the admin
// limiter's per-client-address bucket is genuinely per client; behind one with
// TRUSTED_PROXIES unset, every request arrives from the proxy and the whole
// machine shares a single 30-a-minute bucket. Both are consistent with what we
// can observe, so the panel says what it cannot tell rather than guessing.
//
// It does not fail startup: §19 is degraded over dead, and an operator locked
// out of a working app because a variable was unset would be the worse outcome
// by a distance. The Umbrel package sets TRUSTED_PROXIES; this is the
// off-Umbrel deployment §19 requires to work.
const sharedAdminBucket = "Whether you are behind a proxy. " + SharedAdminBucket

// SharedAdminBucket is the operator-facing explanation of the shared sign-in
// bucket, exported because the admin 429 body says the same thing (d46.19).
//
// One sentence, one place: the Security panel and the refusal an operator
// actually hits are the same claim, and two copies of an explanation drift
// until they contradict each other in front of somebody who is already locked
// out.
const SharedAdminBucket = "No trusted proxy is configured, so if there is one, every sign-in " +
	"looks like it comes from the proxy and the sign-in rate limit is shared across the whole " +
	"machine rather than being yours alone. Set TRUSTED_PROXIES, or add the proxy's range " +
	"under Trusted proxies in Settings."

// blindSpots is the standing list plus anything this deployment adds.
func blindSpots(in Inputs) []string {
	if in.ProxiesDeclared != nil && in.ProxiesDeclared() {
		return BlindSpots
	}
	// A fresh slice: appending to the package-level one would mutate it for
	// every later caller, and the second call would carry two copies.
	out := make([]string, 0, len(BlindSpots)+1)
	return append(append(out, BlindSpots...), sharedAdminBucket)
}

// Check is one evaluated control.
type Check struct {
	ID    string
	Title string
	// Threat is the entry in §11's threat model this maps to. Every check has
	// one, or it is deleted rather than kept for completeness.
	Threat string
	OK     bool
	Detail string
	Blocks Capability
}

// Report is the whole answer.
type Report struct {
	Checks     []Check
	BlindSpots []string
	// Spend is §6's rolling cap as the GUARD holds it (tna.2). Nil when sending
	// is off — see SpendWindow.
	Spend *SpendWindow
	// Rejections is how many operations the guard refused RECENTLY (tna.2). Nil
	// when the trail could not be read; zero-with-a-window is a real answer and
	// says so.
	Rejections *RejectionBurst
}

// SpendWindow is a MEASUREMENT, not a verdict, and that is why it is a field
// here rather than a Check.
//
// A Check answers "is this safe, and what does it take away". "You have used
// 12 000 of 100 000 msat this window" has no failure state: turning it red
// would need an invented threshold — at what percentage? — which is a policy
// decision nobody has made, and the page would then imply that crossing it is
// unsafe.
//
// INTEGER MSAT, never a formatted string and never a float (§4). Formatting
// belongs in the template, and this is the structural half of that rule: if the
// data cannot carry a rounded string, the page cannot lie by rounding.
type SpendWindow struct {
	UsedMsat  int64
	LimitMsat int64
	// Period is how long the window rolls over, so the page can state it rather
	// than the reader assuming a day.
	Period time.Duration
}

// RejectionBurst is the §12 signal that means a bug in the wallet ceiling or a
// compromise in progress.
//
// WINDOW-SCOPED, because a burst is about RATE. The count it replaced was
// "guard.reject rows among the last 200 audit events", which is neither a rate
// nor a total: twelve of the last two hundred events could span a minute or a
// month, and the two mean opposite things. A denominator of "the last 200 rows"
// answers a question nobody asked.
type RejectionBurst struct {
	Count int
	// Within is the period Count covers. It travels WITH the number so the page
	// cannot state one and mean another.
	Within time.Duration
}

// RejectionWindow is the period a burst is measured over.
//
// The same 24 hours as §6's spend window, deliberately: the two numbers sit on
// the same page and an operator reading "3 rejections" beside "12 000 of 100 000
// msat" should not have to work out that they cover different spans. Short
// enough to still mean "recently", long enough that an operator who looks the
// next morning still sees last night's burst.
const RejectionWindow = 24 * time.Hour

// Failed is every check that did not pass.
func (r Report) Failed() []Check {
	var out []Check
	for _, c := range r.Checks {
		if !c.OK {
			out = append(out, c)
		}
	}
	return out
}

// BlockedBy is every failed check that takes the capability away.
//
// The predicate lives HERE rather than in each caller: §8's pay ladder needs the
// same question answered twice — whether to refuse, and which controls to name
// in the log — and a caller walking Failed() itself would be a second statement
// of what "this capability is blocked" means.
func (r Report) BlockedBy(capability Capability) []Check {
	var out []Check
	for _, c := range r.Failed() {
		if c.Blocks == capability {
			out = append(out, c)
		}
	}
	return out
}

// Blocked reports whether any failed check takes the capability away.
func (r Report) Blocked(capability Capability) bool {
	return len(r.BlockedBy(capability)) > 0
}

// Finding is a Tier-1 result: a packaging defect that stops the process.
type Finding struct {
	ID     string
	Detail string
}

// adminMacaroonName is the file whose reachability from the server means §3's
// credential inversion has been undone.
const adminMacaroonName = "admin.macaroon"

// AdminMacaroonExposure is Tier 1, and the only member of it.
//
// The server must not be able to read admin.macaroon. If it can, it can bake
// itself an unencumbered credential and every other control is decorative —
// so this exits the process rather than degrading, because a UI cannot usefully
// report it: the UI running at all is the problem.
//
// It cannot prove a negative. A mount at an unexpected path is invisible to it,
// which is why the compose lint is the primary control and this is the backstop.
func AdminMacaroonExposure(env config.Lookup, dirs ...string) *Finding {
	if env != nil {
		if value, ok := env("LND_ADMIN_MACAROON"); ok && value != "" {
			return &Finding{
				ID: CheckAdminMacaroon,
				Detail: fmt.Sprintf("LND_ADMIN_MACAROON is set to %q in the server's environment. "+
					"Only the guard may hold the admin macaroon. This is a packaging defect, "+
					"not a user condition: remove that variable from the server service.", value),
			}
		}
	}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if found := findAdminMacaroon(dir); found != "" {
			return &Finding{
				ID: CheckAdminMacaroon,
				Detail: fmt.Sprintf("a readable %s exists at %s, which the server can reach. "+
					"Only the guard may hold it. This is a packaging defect, not a user "+
					"condition: remove that mount from the server service.", adminMacaroonName, found),
			}
		}
	}
	return nil
}

// findAdminMacaroon walks dir for a readable admin.macaroon and returns where
// it found one.
func findAdminMacaroon(dir string) string {
	var found string
	// An unreadable tree is not a finding: what matters is whether the server
	// can READ one, and a walk error means it cannot.
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != adminMacaroonName {
			return nil //nolint:nilerr // an unreadable entry is not an exposure
		}
		file, openErr := os.Open(path)
		if openErr != nil {
			return nil
		}
		_ = file.Close()
		found = path
		return filepath.SkipAll
	})
	return found
}

// Inputs are the live values Tier 2 reads. Every one is a function so the
// report is computed fresh, not cached into staleness.
type Inputs struct {
	NodeState func() lnd.State
	// BrokerStatus is called ONCE per Run, by askBroker, and the answer is
	// shared by the three consumers that need it. Fresh per report, not per
	// reader — see brokerState.
	BrokerStatus func(ctx context.Context) (lnd.BrokerStatus, error)
	// SpendMacaroon returns the serialised spend macaroon, if one has been
	// baked. Absent is not a failure: receive-only is the default (§6).
	SpendMacaroon func() ([]byte, bool)
	// ServerIP is this container's address, which the spend macaroon's ipaddr
	// caveat must match.
	ServerIP netip.Addr
	DataDir  string
	// Domain reports the configured domain, whether the last self-probe
	// succeeded, and why not (§9).
	Domain func(ctx context.Context) (domain string, probeOK bool, reason string)
	// Shortfall reports a reconciliation deficit and the likeliest reason for
	// it (§5). The cause travels with the number because a number on its own
	// sends the operator to the wrong place.
	Shortfall func(ctx context.Context) (shortfallMsat int64, cause string, present bool)
	// UnresolvedPayments reports how many payments a previous run left in
	// flight (§5's second freeze, u0u).
	//
	// A SEPARATE input from Shortfall, and its own row below, for the reason
	// the two errors are siblings: the remedies differ. A shortfall may need an
	// operator's adjustment; this one needs nobody and clears itself when the
	// node answers. Folding it into the shortfall row would tell the operator
	// to go and correct a deficit that does not exist.
	UnresolvedPayments func(ctx context.Context) (int, error)
	// Repair is told what was silently fixed, so the caller can log it at WARN
	// with an audit attribute (§11, §12).
	Repair func(what string)
	// GuardRejections counts guard.reject events at or after `since` (tna.2).
	//
	// From the AUDIT TRAIL, never a second counter: the guard already relays
	// these events to the server, which writes them to §12's trail, and a second
	// store would be two statements of one fact. The window is this package's,
	// so the page and the report cannot disagree about what "recently" means.
	GuardRejections func(ctx context.Context, since time.Time) (int, error)
	// ProxiesDeclared reports whether any trusted proxy is configured (§7).
	// It feeds a blind spot rather than a check: nothing here can tell whether
	// this deployment is behind a proxy at all, so the honest statement is
	// "we cannot verify this", not a tick or a cross (d46.19).
	ProxiesDeclared func() bool
	Now             func() time.Time
}

// Run evaluates every Tier-2 check.
//
// Nothing here blocks startup and nothing blocks receiving: a zap arriving is
// never the dangerous operation.
func Run(ctx context.Context, in Inputs) Report {
	if in.Now == nil {
		in.Now = time.Now
	}
	broker := askBroker(ctx, in)
	report := Report{BlindSpots: blindSpots(in)}
	report.Checks = append(report.Checks,
		nodeCheck(in),
		guardCheck(broker),
		addressCheck(ctx, in),
		reconciliationCheck(ctx, in),
		unresolvedPaymentsCheck(ctx, in),
		dataDirCheck(in),
	)
	report.Checks = append(report.Checks, spendChecks(in, broker)...)
	report.Spend = spendWindow(broker)
	report.Rejections = rejectionBurst(ctx, in)
	return report
}

// brokerState is the guard's answer to "what do you hold", asked ONCE per report.
//
// Three consumers need it — the reachability row, the spend rows and the
// rolling window — and each used to ask for itself. cmd/brollyzapper wires the
// pay ladder's copy to the raw socket rather than the cache, and the ladder
// consults a report before every payment (d24.6), so that was three unix round
// trips per payment. The worse half is that three answers can disagree: a
// report claiming the guard is reachable, its macaroon absent and its window
// open is not a snapshot of anything. Asked once, it is.
type brokerState struct {
	status lnd.BrokerStatus
	err    error
	// wired records whether an Inputs.BrokerStatus was supplied at all, which
	// is not the same as one that answered — see answered.
	wired bool
}

// answered reports that the guard was asked AND replied.
//
// "We could not ask" is deliberately not "it said no": since d24.6 the rootKey
// row refuses payments, so collapsing a transient RPC error into a revocation
// would turn it into a spend refusal diagnosing the wrong repair. Callers that
// need to tell the two apart read err; the reachability row is the one that
// reports it.
func (b brokerState) answered() bool { return b.wired && b.err == nil }

// askBroker puts the question, once, for Run.
func askBroker(ctx context.Context, in Inputs) brokerState {
	if in.BrokerStatus == nil {
		return brokerState{}
	}
	status, err := in.BrokerStatus(ctx)
	return brokerState{status: status, err: err, wired: true}
}

// spendWindow is the guard's rolling cap, or NIL when sending is off.
//
// ABSENT, not zeroed, and the difference is the whole reason this returns a
// pointer. "0 of 0 msat" reads as either "you have spent your entire budget" or
// "you have no budget at all", and both are wrong on a receive-only install —
// which is the default. A nil field renders as nothing; a zero value renders as
// a claim.
func spendWindow(broker brokerState) *SpendWindow {
	if !broker.answered() || !broker.status.SpendMacaroonPresent || broker.status.SpendLimitMsat <= 0 {
		return nil
	}
	return &SpendWindow{
		UsedMsat:  broker.status.SpendUsedMsat,
		LimitMsat: broker.status.SpendLimitMsat,
		Period:    SpendWindowPeriod,
	}
}

// SpendWindowPeriod is how long §6's cap rolls over. It is the guard's number;
// this is the server's name for it, so the page can say "in any 24 hours"
// without a second constant deciding what that means.
const SpendWindowPeriod = 24 * time.Hour

// rejectionBurst counts recent guard refusals, or reports nothing when the trail
// could not be read.
//
// NIL rather than zero on an error, for the same reason as spendWindow: "no
// rejections in the last 24 hours" is reassurance, and a database that would not
// answer must not be able to produce it.
func rejectionBurst(ctx context.Context, in Inputs) *RejectionBurst {
	if in.GuardRejections == nil {
		return nil
	}
	count, err := in.GuardRejections(ctx, in.Now().Add(-RejectionWindow))
	if err != nil {
		return nil
	}
	return &RejectionBurst{Count: count, Within: RejectionWindow}
}

func nodeCheck(in Inputs) Check {
	c := Check{
		ID:     CheckNodeLinked,
		Title:  "Connected to your Lightning node",
		Threat: "Server compromised, receive-only install — the baked macaroon is what bounds it, and an unlinked node means there is no baked macaroon in play.",
		OK:     true,
		Blocks: BlocksNothing,
	}
	if in.NodeState == nil {
		return c
	}
	switch state := in.NodeState(); state {
	case lnd.StateReady:
	case lnd.StateNotLinked:
		c.OK, c.Detail = false, "No credentials for your Lightning node yet — the guard writes them once it can reach LND."
	case lnd.StateRelink:
		c.OK, c.Detail = false, "Your node rejected the macaroon. It has most likely been rotated; the guard is being asked for a new one."
	default:
		c.OK, c.Detail = false, "Connecting to your Lightning node."
	}
	return c
}

func guardCheck(broker brokerState) Check {
	c := Check{
		ID:     CheckGuardReachable,
		Title:  "The guard is answering",
		Threat: "Server baking itself a broader macaroon — the guard is the container boundary that prevents it, and an unreachable guard means no macaroon can be baked or revoked.",
		OK:     true,
		Blocks: BlocksSending,
	}
	if !broker.wired {
		return c
	}
	if broker.err != nil {
		c.OK = false
		c.Detail = "The guard is not answering on its socket, so macaroons cannot be baked, checked or revoked."
	}
	return c
}

// spendChecks are §11's spend-macaroon rows. With no spend macaroon baked —
// the receive-only default — they pass: there is nothing unconstrained.
func spendChecks(in Inputs, broker brokerState) []Check {
	caveats := Check{
		ID:     CheckSpendCaveats,
		Title:  "The spend macaroon carries its caveats",
		Threat: "Database or credential volume stolen from a backup — the IP lock and timeout are what make a stolen copy inert, and a macaroon missing them is unconstrained.",
		OK:     true, Blocks: BlocksSending,
	}
	ipMatch := Check{
		ID:     CheckSpendIPMatches,
		Title:  "The spend macaroon is locked to this container",
		Threat: "Spend macaroon exfiltrated — an ipaddr caveat for the wrong address locks it to somewhere else, which is the §10 static-IP misconfiguration showing up as an authentication failure days later.",
		OK:     true, Blocks: BlocksSending,
	}
	expiry := Check{
		ID:     CheckSpendExpiry,
		Title:  "The spend macaroon has not expired",
		Threat: "Spend macaroon exfiltrated — the timeout is the mitigation, and an expired one simply stops working. Receiving is unaffected.",
		OK:     true, Blocks: BlocksSending,
	}
	rootKey := Check{
		ID:     CheckSpendRootKey,
		Title:  "The node still honours the spend root key",
		Threat: "Spend macaroon exfiltrated — RevokeSpend deletes the root key node-side, so a key the node no longer lists means sending was already revoked.",
		OK:     true, Blocks: BlocksSending,
	}
	// §11's Tier 2, from P4. TWO ROWS, and Wave 31 shipped them as one — which
	// was wrong for the reason tna.4 had already established about the two
	// sending off-states: TWO REMEDIES MEANS TWO ROWS. A macaroon with no
	// `lnd-custom brollyguard` caveat is fixed by turning sending off and on
	// again, here, in ten seconds; a guard that will not register is fixed by
	// checking a setting on the NODE, or by waiting for the retry. One row shows
	// one Detail, so when both fail the operator is told one cause and goes
	// looking for one thing.
	//
	// They also fail for OPPOSITE reasons, which is the sharper half: the first
	// means payments go through and are not counted; the second means payments
	// do not happen at all. Folding "the cap is not applying" together with
	// "sending is broken" loses the distinction that decides what to do next.
	guardCaveat := Check{
		ID:     CheckSpendGuardCaveat,
		Title:  "Payments this app makes go through the guard",
		Threat: "Server compromised with sending enabled — the working ceiling is the server's own check and a compromised server skips it. The guard's rolling cap is enforced inside LND's request path, and it applies only to a macaroon carrying the caveat that routes it there.",
		OK:     true, Blocks: BlocksSending,
	}
	middleware := Check{
		ID:     CheckGuardMiddleware,
		Title:  "The guard is registered with your node",
		Threat: "Guard down with sending enabled — LND rejects a custom caveat with no middleware behind it, so the spend macaroon stops working entirely. That is the fail-closed direction, and it is a state the page must name rather than leave as an unexplained payment failure.",
		OK:     true, Blocks: BlocksSending,
	}

	// The set, named ONCE. It was written out four times, and this wave split a
	// row in two and had to edit every copy: a seventh row that reaches five
	// sites but not the sixth drops silently from whichever return path was
	// missed, and the receive-only path below is the one no test exercises with
	// a macaroon present.
	rows := []*Check{&caveats, &ipMatch, &expiry, &rootKey, &guardCaveat, &middleware}
	all := func() []Check {
		out := make([]Check, 0, len(rows))
		for _, c := range rows {
			out = append(out, *c)
		}
		return out
	}

	if in.SpendMacaroon == nil {
		return all()
	}
	raw, present := in.SpendMacaroon()
	if !present {
		// Receive-only is the default and not a defect (§6).
		for _, c := range rows {
			c.Detail = "Sending is not enabled, so there is no spend macaroon to check."
		}
		return all()
	}
	if !lnd.HasGuardCaveat(raw) {
		guardCaveat.OK = false
		guardCaveat.Detail = "this macaroon was baked before the guard enforced the spend limit, " +
			"so payments made with it are not counted against it; turning sending off and on " +
			"again bakes one that is"
	}

	// lnd.RequireHardening is the one statement of the policy: the guard bakes
	// to it and this verifies against it, so a change to what a hardened
	// credential must carry cannot leave a second copy behind that quietly
	// stops requiring something (§6, d46.26).
	if err := lnd.RequireHardening(raw); err != nil {
		caveats.OK, caveats.Detail = false, err.Error()
	}
	if locked, ok := lnd.CaveatValue(raw, lnd.CaveatIPAddr); ok {
		if in.ServerIP.IsValid() && locked != in.ServerIP.String() {
			ipMatch.OK = false
			ipMatch.Detail = fmt.Sprintf("the macaroon is locked to %s but this container is %s; "+
				"the static IP in the package and the caveat disagree", locked, in.ServerIP)
		}
	} else {
		ipMatch.OK, ipMatch.Detail = false, "the macaroon carries no ipaddr caveat"
	}
	if when, ok := lnd.Expiry(raw); ok {
		if !in.Now().Before(when) {
			expiry.OK = false
			expiry.Detail = fmt.Sprintf("the macaroon expired at %s; receiving continues, "+
				"and re-enabling sending bakes a fresh one", when.Format(time.RFC3339))
		}
	} else {
		expiry.OK, expiry.Detail = false, "the macaroon carries no time-before caveat"
	}
	// CHECKED as well as not-listed. A node that could not be asked has not said
	// anything about this key, and since d24.6 this row refuses payments — so
	// treating "we could not ask" as "already revoked" would turn a transient RPC
	// error into a spend refusal with a diagnosis pointing at the wrong repair.
	// An unreachable node has its own row (guard.reachable, node.linked), which
	// is where that belongs.
	if status := broker.status; broker.answered() && status.SpendMacaroonPresent {
		switch {
		case !status.SpendRootKeyRecorded:
			// A spend macaroon on disk that the guard has no root key for.
			// It baked none, or baked one and revoked it — which is what a
			// stale copy put back by hand looks like, and what a stolen one
			// looks like too. Since d24.6 this refuses payments, which is
			// the right answer for both.
			rootKey.OK = false
			rootKey.Detail = "the guard holds no root key for this macaroon, so it was " +
				"either never baked here or has already been revoked"
		case status.SpendRootKeyChecked && !status.SpendRootKeyListed:
			rootKey.OK = false
			rootKey.Detail = "the node no longer lists this macaroon's root key, so it has already been revoked"
		}
		// The OTHER cause of a failing spend-cap row (tna.1), and it is not
		// "the cap is unenforced" — it is "the macaroon does not work". LND
		// rejects a custom caveat with no middleware behind it, so sending
		// is already broken and this row's job is to name the reason rather
		// than leave an unexplained payment failure. Only when the caveat
		// itself checked out, so the more specific diagnosis wins.
		if !status.MiddlewareRegistered {
			middleware.OK = false
			middleware.Detail = "the guard is not registered with your node as an RPC " +
				"middleware, so your node will refuse this macaroon outright until it is; " +
				"the guard retries on its own, and rpcmiddleware.enable must be set on the node"
		}
	}
	return all()
}

func addressCheck(ctx context.Context, in Inputs) Check {
	c := Check{
		ID:     CheckLightningAddress,
		Title:  "Your lightning address reaches this instance",
		Threat: "Not a security threat but a silent failure: a domain pointing at something else breaks receipt verification with no visible error. Receiving by invoice is unaffected.",
		OK:     true, Blocks: BlocksAddress,
	}
	if in.Domain == nil {
		return c
	}
	domain, probeOK, reason := in.Domain(ctx)
	switch {
	case domain == "":
		c.OK = false
		c.Detail = "No public domain configured, so there is no lightning address yet. " +
			"Nostr Wallet Connect works without one."
	case !probeOK:
		c.OK, c.Detail = false, reason
	}
	return c
}

func reconciliationCheck(ctx context.Context, in Inputs) Check {
	c := Check{
		ID:     CheckReconciliation,
		Title:  "The wallet ceiling is within the node's balance",
		Threat: "Hostile or buggy NWC client, and operator over-allocation — §5 freezes spending on a shortfall rather than recomputing the ceiling.",
		OK:     true, Blocks: BlocksSending,
	}
	if in.Shortfall == nil {
		return c
	}
	if shortfall, cause, present := in.Shortfall(ctx); present {
		c.OK = false
		c.Detail = fmt.Sprintf("the wallet believes it may spend %d msat more than the node can "+
			"send, so spending is frozen. %s. Correct it with an adjustment on the wallet page — "+
			"the balance is never rewritten silently", shortfall, cause)
	}
	return c
}

// unresolvedPaymentsCheck is §5's second freeze, made visible (1xp).
//
// Without a row of its own the dashboard stays GREEN while every payment is
// refused: an unresolved reservation REDUCES the wallet's spendable, so
// reconciliation sees no shortfall and has nothing to report. §11 argues that a
// checklist of green ticks which bounds nothing is worse than no checklist, and
// an operator whose payments are being turned down with no indication anywhere
// is exactly that.
//
// The detail says what clears it, because nothing here is for the operator to
// do — a degraded row that implies action where none is possible sends them
// looking for a setting that does not exist.
func unresolvedPaymentsCheck(ctx context.Context, in Inputs) Check {
	c := Check{
		ID:     CheckUnresolvedSpend,
		Title:  "No payments are waiting to be resolved",
		Threat: "A crash mid-payment — §6 forbids reversing a reservation whose fate is unknown, so the ceiling holds it until the node says what happened.",
		OK:     true, Blocks: BlocksSending,
	}
	if in.UnresolvedPayments == nil {
		return c
	}
	count, err := in.UnresolvedPayments(ctx)
	if err != nil {
		// Unknown is not "fine". The freeze may well be up; saying so beats a
		// green tick this check cannot stand behind.
		c.OK = false
		c.Detail = "could not tell whether any payments are unresolved, so this cannot be " +
			"confirmed: " + err.Error()
		return c
	}
	if count > 0 {
		c.OK = false
		c.Detail = fmt.Sprintf("%d payment(s) from a previous run have not been resolved against "+
			"the node yet, so spending is held. Usually nothing to do: this clears itself as "+
			"soon as the node answers, and reconciliation keeps asking. The exception is a "+
			"payment the log names as DISPATCHED with no record at the node — that one does "+
			"not clear itself and needs you (§6)", count)
	}
	return c
}

// dataDirCheck closes the hole rather than only reporting it. §11: chmod it,
// and log at WARN with an audit attribute.
func dataDirCheck(in Inputs) Check {
	c := Check{
		ID:     CheckDataDirMode,
		Title:  "The data directory is private",
		Threat: "Database or credential volume stolen — §4 stores the zap-receipt signing key and the NWC secrets unencrypted, and the mitigation is filesystem-level.",
		OK:     true, Blocks: BlocksNothing,
	}
	if in.DataDir == "" {
		return c
	}
	info, err := os.Stat(in.DataDir)
	if err != nil {
		c.OK, c.Detail = false, fmt.Sprintf("cannot read %s: %v", in.DataDir, err)
		return c
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		c.OK = false
		c.Detail = fmt.Sprintf("%s was mode %o and has been tightened to 700", in.DataDir, mode)
		if err := os.Chmod(in.DataDir, 0o700); err != nil {
			c.Detail = fmt.Sprintf("%s is mode %o and could not be tightened: %v", in.DataDir, mode, err)
		} else if in.Repair != nil {
			in.Repair(c.Detail)
		}
	}
	return c
}

// LocalAddress is this container's own address, for the ipaddr-caveat check.
//
// It is discovered rather than configured on purpose: the point of the check is
// to compare the caveat against where this process ACTUALLY is. Comparing it to
// a configured value would agree with itself when the static IP in the package
// is the thing that is wrong.
func LocalAddress() (netip.Addr, bool) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return netip.Addr{}, false
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			addr := prefix.Addr().Unmap()
			if addr.Is4() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
				return addr, true
			}
		}
	}
	return netip.Addr{}, false
}
