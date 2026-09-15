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
	"github.com/davotoula/brollyzapper/internal/guard"
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
	// BlocksRelink: the Node page's Re-link is withdrawn, and POST /node/relink
	// refuses (`20i.11`). Set only when a re-bake provably cannot help — the
	// node refusing the credential for the ADDRESS it sees, which a fresh
	// credential carries unchanged.
	BlocksRelink Capability = "re-link"
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
	// `0vk.11`: the four rows the receive credential shares with the spend one.
	CheckReceiveCaveats   = "receive.caveats"
	CheckReceiveIPMatches = "receive.ipaddr"
	CheckReceiveExpiry    = "receive.expiry"
	CheckReceiveRootKey   = "receive.rootkey"
	CheckGuardMiddleware  = "guard.middleware"
	CheckReconciliation   = "wallet.reconciliation"
	CheckUnresolvedSpend  = "wallet.unresolved_payments"
	CheckLightningAddress = "address.reachable"
	CheckDataDirMode      = "datadir.mode"
	// `20i.11`: the two operator hints that used to reach one surface each.
	CheckCertificateName   = "lnd.certificate_name"
	CheckCredentialAddress = "node.credential_address"
	// `20i.21`: the server's own credential, put to the node.
	CheckServerCredential = "node.server_credential"
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

// State is a check's verdict: it passed, it failed, or nothing could evaluate it
// (as0.11).
//
// A TYPE, because "not checked" used to be a fail that blocked nothing, told
// apart from a real fail-that-blocks-nothing by its Detail beginning "Not
// checked —". The Security page's cell knew only pass and FAIL, the banner
// listed it as a failure, and the tests found it by grepping for the wording:
// three consumers of one convention, and none of them could be told by the
// compiler.
//
// THE ZERO VALUE IS NOT CHECKED. A row that nobody gave a verdict is exactly
// that, so every constructor states Pass explicitly, and a row built and
// forgotten reads "not checked" rather than a tick or a cross it never earned.
type State int

const (
	// NotChecked: the question could not be put — no accessor wired, no
	// credential where one is expected, a guard or node that did not answer.
	// Not a pass, and not a finding: it takes nothing away whatever Blocks
	// names, because the row that knows WHY (guard.reachable, node.linked) is
	// the one that fails.
	NotChecked State = iota
	// Pass: the control was evaluated and holds.
	Pass
	// Fail: the control was evaluated and does not hold. Only this takes
	// Blocks away.
	Fail
)

func (s State) String() string {
	switch s {
	case NotChecked:
		return "not checked"
	case Pass:
		return "pass"
	case Fail:
		return "fail"
	}
	return fmt.Sprintf("State(%d)", int(s))
}

// Check is one evaluated control.
type Check struct {
	ID    string
	Title string
	// Threat is the entry in §11's threat model this maps to. Every check has
	// one, or it is deleted rather than kept for completeness.
	Threat string
	State  State
	Detail string
	// Blocks is what this control takes away WHEN IT FAILS. It describes the
	// control rather than the verdict, so a passing or not-checked row keeps it
	// and still takes nothing: BlockedBy reads State first.
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
	// MismatchedAddress is the address the credential is locked to, set ONLY
	// when the credential-address check failed (`20i.11`). The Node page's
	// explanation needs the value, and it travels with the verdict so no page
	// can name an address for a refusal that is not happening.
	MismatchedAddress string
	// ServerCredential is the last answer the server's own credential got from
	// the node, with its time (`20i.21`). Nil when no probe is wired; a zero At
	// means not asked yet. A MEASUREMENT beside its check, like Spend: the Node
	// page states it as "yes/no, as of", and the check is the verdict on it.
	ServerCredential *ProbeResult
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

// Failed is every check that was evaluated and did not hold. A not-checked row
// is not among them (as0.11): it is not news about the install, only about what
// this report could see.
func (r Report) Failed() []Check {
	var out []Check
	for _, c := range r.Checks {
		if c.State == Fail {
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
	// ReceiveMacaroon returns the serialised receive macaroon (`0vk.11`). Absent
	// is NOT the default here: it is an install the guard has not linked yet, and
	// its rows say not checked rather than pass.
	ReceiveMacaroon func() ([]byte, bool)
	// ServerIP is this container's address, which both macaroons' ipaddr caveats
	// must match. Invalid is "could not discover it", and those rows say not
	// checked.
	ServerIP netip.Addr
	DataDir  string
	// Domain reports the configured domain, whether the last self-probe
	// succeeded, and why not (§9).
	Domain func(ctx context.Context) (domain string, probeOK bool, reason string)
	// Shortfall reports a reconciliation deficit and the likeliest reason for
	// it (§5). The cause travels with the number because a number on its own
	// sends the operator to the wrong place.
	// An error is "could not tell whether spending is frozen", which the row
	// reports as not checked — never as no shortfall.
	Shortfall func(ctx context.Context) (shortfallMsat int64, cause string, present bool, err error)
	// LastReconciliation is when the last reconciliation check finished and what
	// it returned; a zero time is none yet (d46.25).
	//
	// Beside Shortfall because Shortfall is the WALLET's frozen state, which a
	// check that could not run leaves untouched: on its own it renders the
	// previous verdict under a tick for as long as the node stays away. Wired
	// with Shortfall: the row treats a Shortfall with no LastReconciliation as
	// never checked, never as fresh.
	LastReconciliation func() (at time.Time, err error)
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
	// CertificateName reports whether LND's certificate names the address the
	// server dials: nil, or the typed mismatch (`20i.11`). The same decision
	// lnd.Client makes before it dials, read here for the panel. A POINTER, not
	// an error, so a passing certificate cannot arrive as a non-nil interface.
	CertificateName func() *lnd.CertificateNameError
	// ServerCredential is the server's own credential's last answer from the
	// node — a CredentialProbe's Result, which never waits on the node and asks
	// it at most once per ServerCredentialInterval (`20i.21`).
	ServerCredential func() ProbeResult
	Now              func() time.Time
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
	state := nodeState(in)
	mismatch, mismatchedAddress := credentialAddressCheck(state, broker)
	report.MismatchedAddress = mismatchedAddress
	serverCredential, probed := serverCredentialCheck(in)
	report.ServerCredential = probed
	report.Checks = append(report.Checks,
		nodeCheck(state, mismatchedAddress != ""),
		mismatch,
		certificateNameCheck(in, state),
		serverCredential,
		guardCheck(broker),
		addressCheck(ctx, in),
		reconciliationCheck(ctx, in),
		unresolvedPaymentsCheck(ctx, in),
		dataDirCheck(in),
	)
	report.Checks = append(report.Checks, credentialChecks(receiveCredential, read(in.ReceiveMacaroon), in, broker)...)
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

// nodeState is the connection state, read ONCE per report: three checks
// consult it, and three reads could straddle a transition and describe a
// connection that was never in any one state. The empty state means no
// NodeState was wired, which the rows that need the node's answer say as not
// checked (as0.11).
func nodeState(in Inputs) lnd.State {
	if in.NodeState == nil {
		return ""
	}
	return in.NodeState()
}

func nodeCheck(state lnd.State, addressRefused bool) Check {
	c := Check{
		ID:     CheckNodeLinked,
		Title:  "Connected to your Lightning node",
		Threat: "Server compromised, receive-only install — the baked macaroon is what bounds it, and an unlinked node means there is no baked macaroon in play.",
		State:  Pass,
		Blocks: BlocksNothing,
	}
	switch state {
	case "":
		notChecked(&c, unwired)
	case lnd.StateReady:
	case lnd.StateNotLinked:
		c.State, c.Detail = Fail, "No credentials for your Lightning node yet — the guard writes them once it can reach LND."
	case lnd.StateRelink:
		// IT NAMES A CAUSE ONLY WHEN ONE WAS COMPUTED. Before `20i.3` this said
		// the macaroon "has most likely been rotated", which is exactly wrong
		// for a node refusing the credential for the ADDRESS it observes — the
		// same state. `20i.3` stopped it guessing; `20i.11` gave it the answer,
		// from the same check the Node page reads, so the two cannot differ.
		if addressRefused {
			c.State, c.Detail = Fail, "Your node is refusing the app's credential for the address it sees the connection arrive from, so re-linking will not help. The Node page says what to fix."
			break
		}
		c.State, c.Detail = Fail, "Your node rejected the macaroon. A rotation is the usual cause and the guard repairs it by itself; if this persists, the Node page says what else it can be."
	default:
		c.State, c.Detail = Fail, "Connecting to your Lightning node."
	}
	return c
}

// credentialAddressCheck is `20i.3`'s condition, computed once for both pages.
//
// TWO FACTS, AND NEITHER IS ENOUGH ALONE. The guard's kind means "a re-bake
// would change nothing" — equally true of an operator who pressed Re-link twice
// on a healthy install inside MinBakeInterval, and measuring that is what caught
// the first version: a working deployment was told its address was wrong, with
// its only recovery button removed, until the next renewal days later. The other
// half is the node ACTUALLY rejecting the credential, which the guard never
// observes and the server does. Together they are the condition; apart they are
// a guess.
//
// It returns the address with the verdict, and only with it.
func credentialAddressCheck(state lnd.State, broker brokerState) (Check, string) {
	c := Check{
		ID:     CheckCredentialAddress,
		Title:  "Your node accepts the app's credential from this container's address",
		Threat: "Credential exfiltrated — the ipaddr caveat is what makes a stolen copy useless elsewhere, and the same lock refuses this container when the address it connects from is not the one the credential names.",
		State:  Pass,
		Blocks: BlocksRelink,
	}
	// NOT CHECKED only when the node's refusal is possible and the guard's half
	// could not be read (as0.11). A node that is not refusing the credential is an
	// answer on its own, whatever the guard says.
	switch {
	case state == "" || !broker.wired:
		notChecked(&c, unwired)
		return c, ""
	case state == lnd.StateRelink && broker.err != nil:
		notChecked(&c, guardDown)
		return c, ""
	}
	address := broker.status.CredentialAddress
	// The address is part of the condition, not decoration: with none, the Node
	// page has nothing to explain and keeps its Re-link button, and a verdict that
	// still blocked re-linking would have the handler refuse the button it shows.
	// The guard relays the address it locks credentials to, so an empty one means
	// no lock is configured — a state in which it refuses to bake at all.
	if !broker.answered() || broker.status.RefusalKind != guard.KindAddressMismatch ||
		state != lnd.StateRelink || address == "" {
		return c, ""
	}
	c.State = Fail
	c.Detail = fmt.Sprintf("The credential is locked to %s and your node sees this app's connection "+
		"arrive from a different address. Re-linking will not change this — a fresh credential "+
		"carries the same address. Fix the address or the network, then restart the guard.", address)
	return c, address
}

// certificateNameCheck puts `20i.3`'s certificate hint where an operator reads
// it (`20i.11`); it used to reach only the logs.
//
// NOT READ WHILE THE NODE IS READY. A connection the node accepted has passed
// gRPC's own verification of this certificate against this address, so the
// question is answered — and this report is built before every payment as well
// as per render, which is no place for a file read and an x509 parse that can
// only agree.
//
// THE DETAIL IS THE APP'S. It names the edit and the address the app dials, and
// never the names inside the certificate — Error() carries those, for the log.
func certificateNameCheck(in Inputs, state lnd.State) Check {
	c := Check{
		ID:     CheckCertificateName,
		Title:  "Your node's certificate names the address this app dials",
		Threat: "Not a security threat but a silent failure: gRPC refuses a certificate that does not name the dial address, so the app never connects, and the handshake error names TLS rather than the two-line fix.",
		State:  Pass,
		Blocks: BlocksNothing,
	}
	if state == lnd.StateReady {
		return c
	}
	if in.CertificateName == nil {
		notChecked(&c, unwired)
		return c
	}
	mismatch := in.CertificateName()
	if mismatch == nil {
		return c
	}
	c.State = Fail
	c.Detail = fmt.Sprintf("Your node's certificate does not name %s, the address this app dials. "+
		"Add %s to lnd.conf, delete tls.cert and tls.key so LND regenerates them, restart LND, "+
		"then restart the guard.", mismatch.Dialled, mismatch.Directive())
	return c
}

func guardCheck(broker brokerState) Check {
	c := Check{
		ID:     CheckGuardReachable,
		Title:  "The guard is answering",
		Threat: "Server baking itself a broader macaroon — the guard is the container boundary that prevents it, and an unreachable guard means no macaroon can be baked or revoked.",
		State:  Pass,
		Blocks: BlocksSending,
	}
	if !broker.wired {
		notChecked(&c, unwired)
		return c
	}
	if broker.err != nil {
		c.State = Fail
		c.Detail = "The guard is not answering on its socket, so macaroons cannot be baked, checked or revoked."
	}
	return c
}

// credentialKind is what differs between §11's rows for the two credentials
// (`0vk.11`). Four rows apply to both — caveats present, locked to this
// container, not expired, root key still listed — and they were written for the
// spend credential alone, which most installs never bake, while the receive
// credential, which `d46.26` gave the same caveats and its own root key and
// whose failure stops the app receiving, had none.
//
// THE EVALUATION IS SHARED; the words and what a failure takes away are not.
type credentialKind struct {
	ids [4]string // caveats, ipaddr, expiry, rootkey
	// titles and threats, in the same order. Each threat names the §11
	// threat-model row it maps to.
	titles, threats [4]string
	// blocks is what a FINDING takes away. Not-checked states block nothing,
	// whatever this says.
	blocks Capability
	// absent is the detail when there is no such credential on disk, and
	// absentIsAPass whether that is the expected state (receive-only) or a
	// question nobody could answer (no receive credential yet), which is said as
	// not checked.
	absent        string
	absentIsAPass bool
	// expired is the consequence clause of an expired credential's detail.
	expired string
	// rootKey reads the guard's answer about this credential's root key.
	rootKey func(lnd.BrokerStatus) rootKeyAnswer
	// requiresRecord is whether the guard holding no root key for a credential on
	// disk is a finding. For spend it is (a stale or stolen copy, d24.6); a
	// receive credential with none is one the guard re-bakes on its own (d46.26),
	// and Status carries no such field for it.
	requiresRecord bool
	// revoked is the detail when the node was asked and no longer lists the key.
	revoked string
}

var spendCredential = credentialKind{
	ids: [4]string{CheckSpendCaveats, CheckSpendIPMatches, CheckSpendExpiry, CheckSpendRootKey},
	titles: [4]string{
		"The spend macaroon carries its caveats",
		"The spend macaroon is locked to this container",
		"The spend macaroon has not expired",
		"The node still honours the spend root key",
	},
	threats: [4]string{
		"A macaroon copy stolen by any other route — the IP lock and timeout are what make a stolen copy inert, and a spend macaroon missing them is unconstrained.",
		"A macaroon copy stolen by any other route — an ipaddr caveat for the wrong address locks it to somewhere else, which is the §10 static-IP misconfiguration showing up as an authentication failure days later. Read from the file, so the row names both addresses before a payment is attempted; node.credential_address is the node's own refusal, after.",
		"A macaroon copy stolen by any other route — the timeout is the mitigation, and an expired spend macaroon simply stops working. Receiving is unaffected.",
		"Spend macaroon exfiltrated — RevokeSpend deletes the root key node-side, so a key the node no longer lists means sending was already revoked.",
	},
	blocks:        BlocksSending,
	absent:        "Sending is not enabled, so there is no spend macaroon to check.",
	absentIsAPass: true,
	expired:       "receiving continues, and re-enabling sending bakes a fresh one",
	rootKey: func(s lnd.BrokerStatus) rootKeyAnswer {
		return rootKeyAnswer{s.SpendMacaroonPresent, s.SpendRootKeyRecorded, s.SpendRootKeyChecked, s.SpendRootKeyListed}
	},
	requiresRecord: true,
	revoked:        "the node no longer lists this macaroon's root key, so it has already been revoked",
}

// receiveCredential's rows block NOTHING, and that is §11 rather than an
// oversight. BlocksReceiving exists to be asserted against: Tier 2 never takes
// receiving away. A receive credential that fails these is one the NODE refuses,
// or will — the app withholds nothing — so the detail says what stops working and
// the pay ladder, which reads BlockedBy(BlocksSending), is not handed a reason to
// refuse a payment the spend credential can make.
var receiveCredential = credentialKind{
	ids: [4]string{CheckReceiveCaveats, CheckReceiveIPMatches, CheckReceiveExpiry, CheckReceiveRootKey},
	titles: [4]string{
		"The receive macaroon carries its caveats",
		"The receive macaroon is locked to this container",
		"The receive macaroon has not expired",
		"The node still honours the receive root key",
	},
	threats: [4]string{
		"Receive macaroon exfiltrated — a stolen copy streams every invoice on the node, memos and preimages included; the IP lock and timeout are what make it inert, and one missing them is not.",
		"Receive macaroon exfiltrated — the ipaddr caveat makes a stolen copy useless elsewhere, and the same lock refuses this container when the address in the caveat is another. Read from the file, so the row names both addresses before the node is asked; node.credential_address is the node's own refusal, after, and only once the guard has declined to re-bake.",
		"Receive macaroon exfiltrated — time-before stops a stolen copy within a week. An expired one is refused by the node, so the app stops receiving until the guard renews it, which it does before expiry on its own.",
		"Receive macaroon exfiltrated — Re-link revokes its own root key without touching any other app, so a key the node no longer lists means this credential no longer works.",
	},
	blocks:  BlocksNothing,
	absent:  "There is no receive macaroon yet; the guard writes it once it can reach your node.",
	expired: "your node refuses it, so the app cannot receive until the guard bakes a fresh one",
	rootKey: func(s lnd.BrokerStatus) rootKeyAnswer {
		return rootKeyAnswer{present: s.ReceiveMacaroonPresent, checked: s.ReceiveRootKeyChecked,
			listed: s.ReceiveRootKeyListed}
	},
	revoked: "the node no longer lists this macaroon's root key, so it was revoked or the node's " +
		"macaroons were rotated; the app cannot receive with it, and the guard re-links when it notices",
}

// credentialChecks evaluates kind's four rows against the credential read by
// macaroon.
//
// NOT CHECKED IS NOT A PASS (d46.25). Every row that could not be evaluated —
// no credential to read where one is expected, no address to compare with, a
// guard that did not answer, a node the guard could not ask — says so, is not OK,
// and blocks nothing: the row that knows WHY (node.linked, guard.reachable) is
// the one that blocks.
func credentialChecks(kind credentialKind, cred credentialRead, in Inputs, broker brokerState) []Check {
	rows := make([]Check, 4)
	for i := range rows {
		rows[i] = Check{ID: kind.ids[i], Title: kind.titles[i], Threat: kind.threats[i], State: Pass, Blocks: kind.blocks}
	}
	caveats, ipMatch, expiry, rootKey := &rows[0], &rows[1], &rows[2], &rows[3]

	if !cred.wired {
		for i := range rows {
			notChecked(&rows[i], unwired)
		}
		return rows
	}
	raw := cred.raw
	if !cred.present {
		for i := range rows {
			if kind.absentIsAPass {
				rows[i].Detail = kind.absent
			} else {
				notChecked(&rows[i], kind.absent)
			}
		}
		return rows
	}

	// lnd.RequireHardening is the one statement of the policy: the guard bakes
	// to it and this verifies against it, so a change to what a hardened
	// credential must carry cannot leave a second copy behind that quietly
	// stops requiring something (§6, d46.26).
	if err := lnd.RequireHardening(raw); err != nil {
		caveats.State, caveats.Detail = Fail, err.Error()
	}
	switch locked, ok := lnd.CaveatValue(raw, lnd.CaveatIPAddr); {
	case !ok:
		ipMatch.State, ipMatch.Detail = Fail, "the macaroon carries no ipaddr caveat"
	case !in.ServerIP.IsValid():
		notChecked(ipMatch, fmt.Sprintf("The macaroon is locked to %s, and this container's own "+
			"address could not be discovered to compare it with.", locked))
	case locked != in.ServerIP.String():
		ipMatch.State = Fail
		ipMatch.Detail = fmt.Sprintf("the macaroon is locked to %s but this container is %s; "+
			"the static IP in the package and the caveat disagree", locked, in.ServerIP)
	}
	if when, ok := lnd.Expiry(raw); ok {
		if !in.Now().Before(when) {
			expiry.State = Fail
			expiry.Detail = fmt.Sprintf("the macaroon expired at %s; %s", when.Format(time.RFC3339), kind.expired)
		}
	} else {
		expiry.State, expiry.Detail = Fail, "the macaroon carries no time-before caveat"
	}

	// CHECKED as well as not-listed. A node that could not be asked has not said
	// anything about this key, and since d24.6 the spend row refuses payments — so
	// treating "we could not ask" as "already revoked" would turn a transient RPC
	// error into a spend refusal with a diagnosis pointing at the wrong repair.
	if broker.wired && broker.err != nil {
		notChecked(rootKey, guardDown)
		return rows
	}
	if !broker.wired {
		notChecked(rootKey, unwired)
		return rows
	}
	answer := kind.rootKey(broker.status)
	switch {
	case !answer.present:
		// The server reads a credential the guard does not report: the two are
		// looking at different files, or the guard's view is a moment behind.
		// Neither is an answer about the key.
		notChecked(rootKey, "The guard does not report this macaroon, so it has not said which root key it was baked under.")
	case kind.requiresRecord && !answer.recorded:
		// A spend macaroon on disk that the guard has no root key for. It baked
		// none, or baked one and revoked it — which is what a stale copy put back
		// by hand looks like, and what a stolen one looks like too. Since d24.6
		// this refuses payments, which is the right answer for both.
		rootKey.State = Fail
		rootKey.Detail = "the guard holds no root key for this macaroon, so it was " +
			"either never baked here or has already been revoked"
	case !answer.checked:
		// Including a guard too old to send the receive fields, which decode false.
		notChecked(rootKey, "The guard has not confirmed with your node which root keys it still lists.")
	case !answer.listed:
		rootKey.State, rootKey.Detail = Fail, kind.revoked
	}
	return rows
}

// rootKeyAnswer is the guard's Status about one credential's root key: whether
// the guard reports the credential, holds a root key id for it, asked the node,
// and was told the node still lists it.
type rootKeyAnswer struct{ present, recorded, checked, listed bool }

// credentialRead is one credential file, read ONCE per report: wired is whether
// an accessor was supplied at all, present whether it found a credential.
type credentialRead struct {
	raw            []byte
	present, wired bool
}

// read reads a credential through its accessor, once.
func read(macaroon func() ([]byte, bool)) credentialRead {
	if macaroon == nil {
		return credentialRead{}
	}
	raw, present := macaroon()
	return credentialRead{raw: raw, present: present, wired: true}
}

// guardDown is why a row the guard answers was not checked when it did not.
const guardDown = "The guard is not answering, so it could not be asked."

// unwired is why a row whose Inputs accessor was never supplied was not checked
// (as0.11). Production supplies every one, and cmd/brollyzapper's test holds it
// to that, so an operator should never read this; a test fixture that forgot an
// accessor does, instead of a tick nobody earned.
const unwired = "Nothing in this build is wired to evaluate it."

// notChecked is d46.25's state, typed since as0.11: not a pass, and not a finding
// either. Why stays in Detail; the page's verdict cell says the state, so the
// sentence does not.
func notChecked(c *Check, why string) {
	c.State, c.Detail = NotChecked, why
}

// spendChecks are §11's spend-macaroon rows: the four shared with the receive
// credential, and two of its own. With no spend macaroon baked — the
// receive-only default — they pass: there is nothing unconstrained.
func spendChecks(in Inputs, broker brokerState) []Check {
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
		State:  Pass, Blocks: BlocksSending,
	}
	middleware := Check{
		ID:     CheckGuardMiddleware,
		Title:  "The guard is registered with your node",
		Threat: "Guard down with sending enabled — LND rejects a custom caveat with no middleware behind it, so the spend macaroon stops working entirely. That is the fail-closed direction, and it is a state the page must name rather than leave as an unexplained payment failure.",
		State:  Pass, Blocks: BlocksSending,
	}
	// The set, named ONCE: the shared four, then these two, on every return path.
	// A row that reaches some paths and not others drops silently from whichever
	// was missed, and the receive-only path is the one no test exercises with a
	// macaroon present.
	//
	// The file is read ONCE and handed to the shared four, so one report cannot
	// describe two different spend macaroons if the guard bakes between reads.
	cred := read(in.SpendMacaroon)
	rows := func() []Check {
		return append(credentialChecks(spendCredential, cred, in, broker), guardCaveat, middleware)
	}

	if !cred.wired {
		notChecked(&guardCaveat, unwired)
		notChecked(&middleware, unwired)
		return rows()
	}
	if !cred.present {
		guardCaveat.Detail, middleware.Detail = spendCredential.absent, spendCredential.absent
		return rows()
	}
	if !lnd.HasGuardCaveat(cred.raw) {
		guardCaveat.State = Fail
		guardCaveat.Detail = "this macaroon was baked before the guard enforced the spend limit, " +
			"so payments made with it are not counted against it; turning sending off and on " +
			"again bakes one that is"
	}
	switch {
	case !broker.wired:
		notChecked(&middleware, unwired)
	case broker.err != nil:
		// NOT CHECKED IS NOT A PASS (d46.25, 0vk.1 F5). Built passing and flipped
		// only on a finding, this row used to render "The guard is registered with
		// your node" with a tick having asked nobody. guard.reachable is the row
		// that knows why, and it blocks.
		notChecked(&middleware, guardDown)
	}
	// The OTHER cause of a failing spend-cap row (tna.1), and it is not "the cap
	// is unenforced" — it is "the macaroon does not work". LND rejects a custom
	// caveat with no middleware behind it, so sending is already broken and this
	// row's job is to name the reason rather than leave an unexplained payment
	// failure.
	if broker.answered() && broker.status.SpendMacaroonPresent && !broker.status.MiddlewareRegistered {
		middleware.State = Fail
		middleware.Detail = "the guard is not registered with your node as an RPC " +
			"middleware, so your node will refuse this macaroon outright until it is; " +
			"the guard retries on its own, and rpcmiddleware.enable must be set on the node"
	}
	return rows()
}

func addressCheck(ctx context.Context, in Inputs) Check {
	c := Check{
		ID:     CheckLightningAddress,
		Title:  "Your lightning address reaches this instance",
		Threat: "Not a security threat but a silent failure: a domain pointing at something else breaks receipt verification with no visible error. Receiving by invoice is unaffected.",
		State:  Pass, Blocks: BlocksAddress,
	}
	if in.Domain == nil {
		notChecked(&c, unwired)
		return c
	}
	domain, probeOK, reason := in.Domain(ctx)
	switch {
	case domain == "":
		c.State = Fail
		c.Detail = "No public domain configured, so there is no lightning address yet. " +
			"Nostr Wallet Connect works without one."
	case !probeOK:
		c.State, c.Detail = Fail, reason
	}
	return c
}

// reconciliationCheck is §5's freeze, and when it was last looked at (d46.25).
//
// THE VERDICT IS THE WALLET'S; THE FRESHNESS IS THE RECONCILER'S. A frozen
// shortfall is real whether or not the last check ran — the wallet refuses on
// it — so it blocks sending in every case and the detail says how current it is.
// No shortfall is only a pass when a check actually ran and succeeded: before
// the first one, or after one that failed, nothing has compared the ceiling with
// the node since, and the tick that used to stand there was the confidence §11
// calls worse than no checklist.
//
// A FAILED CHECK BLOCKS NOTHING by itself (delegated, d46.25). §5's freeze is the
// wallet's decision and this row reports it; it does not make one. Refusing to
// send because LND did not answer a balance read would be an outage caused by
// the check, which Check's own comment already rules out, and the payment that
// needs LND will fail at LND regardless.
func reconciliationCheck(ctx context.Context, in Inputs) Check {
	c := Check{
		ID:     CheckReconciliation,
		Title:  "The wallet ceiling is within the node's balance",
		Threat: "Hostile or buggy NWC client, and operator over-allocation — §5 freezes spending on a shortfall rather than recomputing the ceiling.",
		State:  Pass, Blocks: BlocksSending,
	}
	if in.Shortfall == nil {
		notChecked(&c, unwired)
		return c
	}
	// Read before the shortfall, so a check finishing between the two reads makes
	// the freshness older than the verdict, never newer. Unwired is never-checked,
	// not fresh: a report with no way to say when must not be able to say "now".
	var at time.Time
	var checkErr error
	if in.LastReconciliation != nil {
		at, checkErr = in.LastReconciliation()
	}
	shortfall, cause, present, readErr := in.Shortfall(ctx)
	if readErr != nil {
		// The FREEZE could not be read, and a node check however recent says
		// nothing about it (go-review). Not a pass; not a finding either — the
		// pay ladder reads the wallet itself and refuses on the same error.
		notChecked(&c, "Could not read whether spending is frozen: "+readErr.Error())
		return c
	}
	failed := ""
	if !at.IsZero() && checkErr != nil {
		failed = fmt.Sprintf("The last check failed at %s: %v", clock(at), checkErr)
	}

	if present {
		c.State = Fail
		c.Detail = fmt.Sprintf("the wallet believes it may spend %d msat more than the node can "+
			"send, so spending is frozen. %s. Correct it with an adjustment on the wallet page — "+
			"the balance is never rewritten silently", shortfall, cause)
		switch {
		case at.IsZero():
			c.Detail += ". Not re-checked since the app started; the freeze stands until a check clears it."
		case failed != "":
			c.Detail += ". " + failed + "; the freeze stands until a check succeeds."
		default:
			c.Detail += ". This is the verdict as of " + clock(at) + "."
		}
		return c
	}
	switch {
	case at.IsZero():
		notChecked(&c, "Reconciliation runs when the app starts and every five minutes, and none has "+
			"finished yet. No shortfall is recorded, so spending is not frozen.")
	case failed != "":
		// NOT CHECKED, not a fail (as0.11, delegated): nothing has compared the
		// ceiling with the node since, which is exactly what the state means. The
		// row that knows WHY the node did not answer is node.linked, in the banner;
		// as a fail, one outage would be said there twice.
		notChecked(&c, failed+". The last verdict stands: no shortfall recorded, so spending is not "+
			"frozen — but nothing has compared the ceiling with the node since.")
	default:
		c.Detail = "Within the node's balance, as of " + clock(at) + "."
	}
	return c
}

// clock is how this package states a time on the panel. The Node page's template
// spells the same format itself (node.html's "as of"); change both together.
func clock(at time.Time) string { return at.UTC().Format("15:04:05 UTC") }

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
		State:  Pass, Blocks: BlocksSending,
	}
	if in.UnresolvedPayments == nil {
		notChecked(&c, unwired)
		return c
	}
	count, err := in.UnresolvedPayments(ctx)
	if err != nil {
		// Unknown is not "fine". The freeze may well be up; saying so beats a
		// green tick this check cannot stand behind.
		c.State = Fail
		c.Detail = "could not tell whether any payments are unresolved, so this cannot be " +
			"confirmed: " + err.Error()
		return c
	}
	if count > 0 {
		c.State = Fail
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
		State:  Pass, Blocks: BlocksNothing,
	}
	if in.DataDir == "" {
		notChecked(&c, unwired)
		return c
	}
	info, err := os.Stat(in.DataDir)
	if err != nil {
		c.State, c.Detail = Fail, fmt.Sprintf("cannot read %s: %v", in.DataDir, err)
		return c
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		c.State = Fail
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
