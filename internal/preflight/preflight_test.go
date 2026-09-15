package preflight_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/preflight"
)

func env(m map[string]string) config.Lookup {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// §11 Tier 1, condition one of four: the variable in the server's environment.
func TestTierOneFiresOnTheAdminMacaroonVariable(t *testing.T) {
	finding := preflight.AdminMacaroonExposure(env(map[string]string{
		"LND_ADMIN_MACAROON": "/lnd/admin.macaroon",
	}))
	if finding == nil {
		t.Fatal("Tier 1 passed with LND_ADMIN_MACAROON set in the server's environment")
	}
	if !strings.Contains(finding.Detail, "LND_ADMIN_MACAROON") {
		t.Errorf("the finding does not name the variable: %s", finding.Detail)
	}
	if !strings.Contains(strings.ToLower(finding.Detail), "packaging") {
		t.Errorf("the finding does not say this is a packaging defect: %s", finding.Detail)
	}
}

// Conditions two, three and four: a readable admin.macaroon under any of the
// three directories the server can see. Each tested independently.
func TestTierOneFiresOnAnAdminMacaroonUnderEachSearchedDirectory(t *testing.T) {
	for _, where := range []string{"lnd", "credentials", "data"} {
		t.Run(where, func(t *testing.T) {
			root := t.TempDir()
			dirs := map[string]string{}
			for _, name := range []string{"lnd", "credentials", "data"} {
				dir := filepath.Join(root, name)
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				dirs[name] = dir
			}
			// The macaroon is nested, because a mount can land anywhere below.
			nested := filepath.Join(dirs[where], "chain", "bitcoin")
			if err := os.MkdirAll(nested, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(nested, "admin.macaroon"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}

			finding := preflight.AdminMacaroonExposure(env(nil), dirs["lnd"], dirs["credentials"], dirs["data"])
			if finding == nil {
				t.Fatalf("Tier 1 passed with a readable admin.macaroon under %s", where)
			}
			if !strings.Contains(finding.Detail, dirs[where]) {
				t.Errorf("the finding does not name where it found it: %s", finding.Detail)
			}
		})
	}
}

func TestTierOnePassesOnACorrectlyPackagedServer(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"credentials", "data"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The receive macaroon is fine — it is admin that must be unreachable.
	if err := os.WriteFile(filepath.Join(root, "credentials", "recv.macaroon"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory that does not exist at all is not a finding either.
	if got := preflight.AdminMacaroonExposure(env(nil),
		filepath.Join(root, "lnd"), filepath.Join(root, "credentials"), filepath.Join(root, "data")); got != nil {
		t.Errorf("Tier 1 fired on a correctly packaged server: %+v", got)
	}
}

// §11: Tier 1 is exactly one check. Anything else that "should stop startup"
// belongs in Tier 2, because §19 requires degraded states rather than crash
// loops.
func TestTierOneIsExactlyOneCheck(t *testing.T) {
	if got := preflight.TierOneChecks; len(got) != 1 {
		t.Errorf("Tier 1 has %d checks (%v), want exactly 1 (spec §11)", len(got), got)
	}
}

func inputs(t *testing.T) preflight.Inputs {
	t.Helper()
	// store.Open creates the data directory 0700; t.TempDir does not, so the
	// fixture matches production rather than tripping the mode check.
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatalf("securing the fixture data dir: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	// EVERY ROW-BEARING ACCESSOR WIRED, and healthy (as0.11): an unwired one reads
	// not checked, so a fixture that left one out would not be a healthy install.
	// TestAHealthyFixtureHasEveryRowPassing holds it to that.
	return preflight.Inputs{
		NodeState: func() lnd.State { return lnd.StateReady },
		BrokerStatus: func(context.Context) (lnd.BrokerStatus, error) {
			return lnd.BrokerStatus{LNDReachable: true, ReceiveMacaroonPresent: true,
				ReceiveRootKeyChecked: true, ReceiveRootKeyListed: true}, nil
		},
		SpendMacaroon: func() ([]byte, bool) { return nil, false },
		// A healthy receive credential, as the guard bakes it (§6, d46.26).
		ReceiveMacaroon: func() ([]byte, bool) {
			return lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2026-12-01T00:00:00Z"), true
		},
		ServerIP: netip.MustParseAddr("10.21.0.17"),
		DataDir:  dataDir,
		Domain:   func(context.Context) (string, bool, string) { return "zap.example", true, "" },
		Shortfall: func(context.Context) (int64, string, bool, error) {
			return 0, "", false, nil
		},
		LastReconciliation: func() (time.Time, error) { return now, nil },
		UnresolvedPayments: func(context.Context) (int, error) { return 0, nil },
		CertificateName:    func() *lnd.CertificateNameError { return nil },
		ServerCredential:   func() preflight.ProbeResult { return preflight.ProbeResult{At: now} },
		Now:                func() time.Time { return now },
	}
}

func check(t *testing.T, report preflight.Report, id string) preflight.Check {
	t.Helper()
	for _, c := range report.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check with id %q; the report has %v", id, ids(report))
	return preflight.Check{}
}

// blocking reports whether the row with id is among what the report says takes
// capability away — the pay ladder's question, asked of one row.
func blocking(report preflight.Report, capability preflight.Capability, id string) bool {
	return slices.ContainsFunc(report.BlockedBy(capability), func(c preflight.Check) bool { return c.ID == id })
}

func ids(report preflight.Report) []string {
	var out []string
	for _, c := range report.Checks {
		out = append(out, c.ID)
	}
	return out
}

// §11's Tier-2 table, row by row. Each blocks a capability, never startup.
func TestTierTwoBlocksSendingWhenTheSpendMacaroonIsUnconstrained(t *testing.T) {
	in := inputs(t)
	in.SpendMacaroon = func() ([]byte, bool) { return lndtest.Macaroon(t), true }

	report := preflight.Run(t.Context(), in)
	got := check(t, report, preflight.CheckSpendCaveats)
	if got.State != preflight.Fail {
		t.Error("a spend macaroon with no caveats passed the caveat check")
	}
	if got.Blocks != preflight.BlocksSending {
		t.Errorf("the finding blocks %q, want sending", got.Blocks)
	}
	if !report.Blocked(preflight.BlocksSending) {
		t.Error("the report does not block sending")
	}
	if report.Blocked(preflight.BlocksReceiving) {
		t.Error("receiving was blocked; §11 says Tier 2 never blocks receiving")
	}
}

func TestTierTwoBlocksSendingWhenTheIPLockIsForAnotherContainer(t *testing.T) {
	in := inputs(t)
	in.SpendMacaroon = func() ([]byte, bool) {
		return lndtest.Macaroon(t, "ipaddr 10.21.0.99", "time-before 2026-12-01T00:00:00Z"), true
	}
	report := preflight.Run(t.Context(), in)
	got := check(t, report, preflight.CheckSpendIPMatches)
	if got.State != preflight.Fail {
		t.Error("an ipaddr caveat for another address passed")
	}
	if !strings.Contains(got.Detail, "10.21.0.99") || !strings.Contains(got.Detail, "10.21.0.17") {
		t.Errorf("the detail does not name both addresses, so the operator cannot act: %s", got.Detail)
	}
}

func TestTierTwoBlocksSendingWhenTheSpendMacaroonHasExpired(t *testing.T) {
	in := inputs(t)
	in.SpendMacaroon = func() ([]byte, bool) {
		return lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2020-01-01T00:00:00Z"), true
	}
	report := preflight.Run(t.Context(), in)
	if got := check(t, report, preflight.CheckSpendExpiry); got.State != preflight.Fail {
		t.Error("an expired spend macaroon passed the expiry check")
	}
	// §11: receiving continues.
	if report.Blocked(preflight.BlocksReceiving) {
		t.Error("an expired spend macaroon blocked receiving; zaps must still arrive")
	}
}

func TestTierTwoBlocksSendingWhenTheRootKeyIsAlreadyRevoked(t *testing.T) {
	in := inputs(t)
	in.SpendMacaroon = func() ([]byte, bool) {
		return lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2026-12-01T00:00:00Z"), true
	}
	in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
		// Checked AND not listed: the node was asked and said no. "Could not
		// ask" is a different answer and must not refuse a payment (d24.6).
		return lnd.BrokerStatus{LNDReachable: true, SpendMacaroonPresent: true,
			SpendRootKeyRecorded: true, SpendRootKeyChecked: true, SpendRootKeyListed: false}, nil
	}
	report := preflight.Run(t.Context(), in)
	if got := check(t, report, preflight.CheckSpendRootKey); got.State != preflight.Fail {
		t.Error("a spend root key the node no longer lists passed")
	}
}

func TestTierTwoBlocksSendingWhenTheGuardIsUnreachable(t *testing.T) {
	in := inputs(t)
	in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
		return lnd.BrokerStatus{}, errors.New("dialling /credentials/guard.sock: no such file")
	}
	report := preflight.Run(t.Context(), in)
	got := check(t, report, preflight.CheckGuardReachable)
	if got.State != preflight.Fail {
		t.Error("an unreachable guard passed")
	}
	if got.Blocks != preflight.BlocksSending {
		t.Errorf("an unreachable guard blocks %q, want sending", got.Blocks)
	}
}

func TestTierTwoFlagsTheLightningAddressWhenTheProbeFails(t *testing.T) {
	in := inputs(t)
	in.Domain = func(context.Context) (string, bool, string) {
		return "zap.example", false, "zap.example answered without this instance's token"
	}
	report := preflight.Run(t.Context(), in)
	got := check(t, report, preflight.CheckLightningAddress)
	if got.State != preflight.Fail {
		t.Error("a failing self-probe passed")
	}
	if got.Blocks != preflight.BlocksAddress {
		t.Errorf("a failing probe blocks %q, want the lightning address only", got.Blocks)
	}
	if !strings.Contains(got.Detail, "without this instance's token") {
		t.Errorf("the probe result is not shown: %s", got.Detail)
	}
	if report.Blocked(preflight.BlocksReceiving) || report.Blocked(preflight.BlocksSending) {
		t.Error("an unreachable address blocked more than the address")
	}
}

func TestTierTwoFlagsAReconciliationShortfall(t *testing.T) {
	in := inputs(t)
	in.Shortfall = func(context.Context) (int64, string, bool, error) {
		return 25_000, "another app on this node may have spent", true, nil
	}
	report := preflight.Run(t.Context(), in)
	got := check(t, report, preflight.CheckReconciliation)
	if got.State != preflight.Fail {
		t.Error("a reconciliation shortfall passed")
	}
	if got.Blocks != preflight.BlocksSending {
		t.Errorf("a shortfall blocks %q, want sending frozen (§5)", got.Blocks)
	}
	// Criterion 4: the amount AND the likely cause.
	if !strings.Contains(got.Detail, "25000") {
		t.Errorf("the detail does not carry the amount: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "another app on this node may have spent") {
		t.Errorf("the detail does not carry the likely cause: %s", got.Detail)
	}
}

// §11: chmod it, and log at WARN with an audit attribute.
func TestTierTwoTightensAWideDataDirectory(t *testing.T) {
	in := inputs(t)
	if err := os.Chmod(in.DataDir, 0o755); err != nil {
		t.Fatalf("widening the data dir: %v", err)
	}
	var repaired []string
	in.Repair = func(what string) { repaired = append(repaired, what) }

	report := preflight.Run(t.Context(), in)
	got := check(t, report, preflight.CheckDataDirMode)
	if got.State != preflight.Fail {
		t.Error("a world-readable data directory passed")
	}
	info, err := os.Stat(in.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("the data directory is still %o; §11 says chmod it", info.Mode().Perm())
	}
	if len(repaired) == 0 {
		t.Error("the repair was not reported, so nothing can log it with audit=")
	}
	// It blocks nothing: the hole is closed by the time anyone reads the page.
	if got.Blocks != preflight.BlocksNothing {
		t.Errorf("tightening the data dir blocked %q, want nothing", got.Blocks)
	}
}

func TestAHealthyInstanceHasNoFailedChecks(t *testing.T) {
	report := preflight.Run(t.Context(), inputs(t))
	if failed := report.Failed(); len(failed) != 0 {
		t.Errorf("a healthy instance reported %d failures: %+v", len(failed), failed)
	}
	if report.Blocked(preflight.BlocksSending) || report.Blocked(preflight.BlocksAddress) {
		t.Error("a healthy instance blocked a capability")
	}
}

// as0.11: the fixture every other test starts from is a healthy install, row by
// row. Failed() being empty is not that — a not-checked row is not a failure —
// so this asserts Pass on each, which is what makes "one accessor nil turns
// exactly these rows not checked" below mean anything.
func TestAHealthyFixtureHasEveryRowPassing(t *testing.T) {
	for _, c := range preflight.Run(t.Context(), inputs(t)).Checks {
		if c.State != preflight.Pass {
			t.Errorf("%s is %v on the healthy fixture: %q", c.ID, c.State, c.Detail)
		}
	}
}

// as0.11 criterion 7: an Inputs with nothing wired evaluates nothing. Every row
// says not checked, and none is a pass, a fail or a reason to refuse a payment.
// Before this bead nine of them rendered a tick over a question nobody put.
func TestAnUnwiredReportChecksNothing(t *testing.T) {
	report := preflight.Run(t.Context(), preflight.Inputs{})
	if len(report.Checks) == 0 {
		t.Fatal("an unwired report has no rows at all; the panel is a fixed list")
	}
	for _, c := range report.Checks {
		if c.State != preflight.NotChecked {
			t.Errorf("%s is %v with nothing wired: %q", c.ID, c.State, c.Detail)
		}
	}
	for _, capability := range []preflight.Capability{preflight.BlocksSending, preflight.BlocksAddress,
		preflight.BlocksRelink, preflight.BlocksReceiving} {
		if report.Blocked(capability) {
			t.Errorf("an unwired report blocks %q: %v", capability, report.BlockedBy(capability))
		}
	}
}

// as0.11 criterion 7, one accessor at a time: the healthy fixture with a single
// Inputs field left out turns EXACTLY the rows that read it not checked, and
// nothing else moves. The table is the inventory; a field missing from it is a
// field whose absence nobody decided about, and the reflection below names it.
func TestEachUnwiredAccessorLeavesExactlyItsRowsNotChecked(t *testing.T) {
	spend := func() ([]byte, bool) {
		return lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2026-12-01T00:00:00Z", lnd.GuardCaveat("n")), true
	}
	spendStatus := func(context.Context) (lnd.BrokerStatus, error) {
		return lnd.BrokerStatus{LNDReachable: true, ReceiveMacaroonPresent: true, ReceiveRootKeyChecked: true,
			ReceiveRootKeyListed: true, SpendMacaroonPresent: true, SpendRootKeyRecorded: true,
			SpendRootKeyChecked: true, SpendRootKeyListed: true, MiddlewareRegistered: true}, nil
	}
	spendRows := []string{preflight.CheckSpendCaveats, preflight.CheckSpendIPMatches, preflight.CheckSpendExpiry,
		preflight.CheckSpendRootKey, preflight.CheckSpendGuardCaveat, preflight.CheckGuardMiddleware}
	receiveRows := []string{preflight.CheckReceiveCaveats, preflight.CheckReceiveIPMatches,
		preflight.CheckReceiveExpiry, preflight.CheckReceiveRootKey}
	for _, tc := range []struct {
		field string
		unset func(*preflight.Inputs)
		// withSpend puts a spend macaroon on disk first, so the rows that read the
		// guard about it have something to be asked about.
		withSpend bool
		want      []string
	}{
		{"NodeState", func(in *preflight.Inputs) { in.NodeState = nil }, false,
			// The certificate row is read only while the node is not Ready, and with
			// no state that is not known; the address row needs the node's refusal.
			[]string{preflight.CheckNodeLinked, preflight.CheckCredentialAddress}},
		{"BrokerStatus", func(in *preflight.Inputs) { in.BrokerStatus = nil }, true,
			[]string{preflight.CheckGuardReachable, preflight.CheckCredentialAddress,
				preflight.CheckReceiveRootKey, preflight.CheckSpendRootKey, preflight.CheckGuardMiddleware}},
		{"SpendMacaroon", func(in *preflight.Inputs) { in.SpendMacaroon = nil }, true, spendRows},
		{"ReceiveMacaroon", func(in *preflight.Inputs) { in.ReceiveMacaroon = nil }, false, receiveRows},
		{"ServerIP", func(in *preflight.Inputs) { in.ServerIP = netip.Addr{} }, true,
			[]string{preflight.CheckReceiveIPMatches, preflight.CheckSpendIPMatches}},
		{"DataDir", func(in *preflight.Inputs) { in.DataDir = "" }, false, []string{preflight.CheckDataDirMode}},
		{"Domain", func(in *preflight.Inputs) { in.Domain = nil }, false, []string{preflight.CheckLightningAddress}},
		{"Shortfall", func(in *preflight.Inputs) { in.Shortfall = nil }, false, []string{preflight.CheckReconciliation}},
		// Wired with Shortfall; without it the row has no time, so never checked.
		{"LastReconciliation", func(in *preflight.Inputs) { in.LastReconciliation = nil }, false,
			[]string{preflight.CheckReconciliation}},
		{"UnresolvedPayments", func(in *preflight.Inputs) { in.UnresolvedPayments = nil }, false,
			[]string{preflight.CheckUnresolvedSpend}},
		// Not read while the node is Ready — gRPC has answered it — so on the
		// healthy fixture its absence moves nothing. The node-not-Ready half is
		// TestTheCertificateRowIsNotCheckedWithNoAccessor.
		{"CertificateName", func(in *preflight.Inputs) { in.CertificateName = nil }, false, nil},
		{"ServerCredential", func(in *preflight.Inputs) { in.ServerCredential = nil }, false,
			[]string{preflight.CheckServerCredential}},
		// No row reads these. Repair is told about a chmod that happens anyway;
		// GuardRejections and ProxiesDeclared feed a measurement and a blind spot,
		// each of which already says nothing rather than something when absent;
		// Now defaults to the clock.
		{"Repair", func(in *preflight.Inputs) { in.Repair = nil }, false, nil},
		{"GuardRejections", func(in *preflight.Inputs) { in.GuardRejections = nil }, false, nil},
		{"ProxiesDeclared", func(in *preflight.Inputs) { in.ProxiesDeclared = nil }, false, nil},
		{"Now", func(in *preflight.Inputs) { in.Now = nil }, false, nil},
	} {
		t.Run(tc.field, func(t *testing.T) {
			in := inputs(t)
			if tc.withSpend {
				in.SpendMacaroon, in.BrokerStatus = spend, spendStatus
			}
			tc.unset(&in)
			for _, c := range preflight.Run(t.Context(), in).Checks {
				want := preflight.Pass
				if slices.Contains(tc.want, c.ID) {
					want = preflight.NotChecked
				}
				if c.State != want {
					t.Errorf("%s is %v with %s unset, want %v: %q", c.ID, c.State, tc.field, want, c.Detail)
				}
			}
		})
	}
	t.Run("the table names every Inputs field", func(t *testing.T) {
		var named []string
		for _, f := range reflect.VisibleFields(reflect.TypeFor[preflight.Inputs]()) {
			named = append(named, f.Name)
		}
		// Kept in step by hand, deliberately: a new field is a new decision about
		// what its absence renders, and this is where that decision is written.
		inventory := []string{"NodeState", "BrokerStatus", "SpendMacaroon", "ReceiveMacaroon", "ServerIP",
			"DataDir", "Domain", "Shortfall", "LastReconciliation", "UnresolvedPayments", "Repair",
			"GuardRejections", "ProxiesDeclared", "CertificateName", "ServerCredential", "Now"}
		if !slices.Equal(named, inventory) {
			t.Errorf("preflight.Inputs has fields %v; the inventory above covers %v", named, inventory)
		}
	})
}

// The certificate row's own unwired half: a node that is not Ready has not
// answered the question, so with no way to read the certificate the row cannot.
func TestTheCertificateRowIsNotCheckedWithNoAccessor(t *testing.T) {
	in := inputs(t)
	in.NodeState = func() lnd.State { return lnd.StateConnecting }
	in.CertificateName = nil
	if got := check(t, preflight.Run(t.Context(), in), preflight.CheckCertificateName); got.State != preflight.NotChecked {
		t.Errorf("the certificate row with no accessor on a connecting node is %v: %q", got.State, got.Detail)
	}
}

// as0.11 criterion 5: BlockedBy is the pay ladder's seam, and the third state
// must not move it. A not-checked row takes nothing away WHATEVER its Blocks
// says — the table gives one Blocks=sending on purpose, because a not-checked
// row keeps the capability its control would take on a failure.
func TestBlockedByAnswersOnlyForFailures(t *testing.T) {
	report := preflight.Report{Checks: []preflight.Check{
		{ID: "pass", State: preflight.Pass, Blocks: preflight.BlocksSending},
		{ID: "fail-blocking", State: preflight.Fail, Blocks: preflight.BlocksSending},
		{ID: "fail-nonblocking", State: preflight.Fail, Blocks: preflight.BlocksNothing},
		{ID: "not-checked", State: preflight.NotChecked, Blocks: preflight.BlocksSending},
		{ID: "not-checked-nonblocking", State: preflight.NotChecked, Blocks: preflight.BlocksNothing},
	}}
	for _, tc := range []struct {
		capability preflight.Capability
		want       []string
	}{
		{preflight.BlocksSending, []string{"fail-blocking"}},
		{preflight.BlocksNothing, []string{"fail-nonblocking"}},
		{preflight.BlocksAddress, nil},
		{preflight.BlocksReceiving, nil},
	} {
		var got []string
		for _, c := range report.BlockedBy(tc.capability) {
			got = append(got, c.ID)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("BlockedBy(%q) = %v, want %v", tc.capability, got, tc.want)
		}
		if blocked := report.Blocked(tc.capability); blocked != (len(tc.want) > 0) {
			t.Errorf("Blocked(%q) = %v, want %v", tc.capability, blocked, len(tc.want) > 0)
		}
	}
	var failed []string
	for _, c := range report.Failed() {
		failed = append(failed, c.ID)
	}
	if want := []string{"fail-blocking", "fail-nonblocking"}; !slices.Equal(failed, want) {
		t.Errorf("Failed() = %v, want %v; a not-checked row is not a failure", failed, want)
	}
}

// §11: every check maps to a named threat in the model, or it is deleted.
// Checks that exist to look thorough are how a security page becomes theatre.
func TestEveryCheckNamesTheThreatItMapsTo(t *testing.T) {
	report := preflight.Run(t.Context(), inputs(t))
	if len(report.Checks) == 0 {
		t.Fatal("the report has no checks at all")
	}
	for _, c := range report.Checks {
		if strings.TrimSpace(c.Threat) == "" {
			t.Errorf("check %q names no threat; §11 says delete it rather than keep it", c.ID)
		}
		if strings.TrimSpace(c.Title) == "" {
			t.Errorf("check %q has no title to show an operator", c.ID)
		}
	}
}

// §11: a checklist of green ticks that bounds nothing is worse than no
// checklist, because it manufactures confidence.
func TestTheReportNamesItsOwnBlindSpots(t *testing.T) {
	in := inputs(t)
	in.ProxiesDeclared = func() bool { return true }
	report := preflight.Run(t.Context(), in)
	if len(report.BlindSpots) != 4 {
		t.Errorf("the report names %d blind spots, want the four from §11", len(report.BlindSpots))
	}
	joined := strings.ToLower(strings.Join(report.BlindSpots, " | "))
	for _, expected := range []string{"wallet password", "permissions", "other apps", "backup"} {
		if !strings.Contains(joined, expected) {
			t.Errorf("the blind spots do not mention %q: %v", expected, report.BlindSpots)
		}
	}
}

// d46.19. With no trusted proxy configured, nothing in this process can tell
// whether it is behind one — and if it is, the admin limiter's
// per-client-address bucket is really one bucket for the whole machine. That
// belongs on the not-checked list rather than as a tick or a cross: both
// readings are consistent with everything observable from in here, and §11 is
// explicit that a green tick bounding nothing is worse than no tick.
//
// The negative half matters as much. A blind spot that is always listed is not
// a diagnosis, and an operator who HAS set TRUSTED_PROXIES must not be told to
// go and check it.
func TestTheSharedAdminBucketIsABlindSpotOnlyWhenNoProxyIsTrusted(t *testing.T) {
	for declared, wantListed := range map[bool]bool{false: true, true: false} {
		in := inputs(t)
		in.ProxiesDeclared = func() bool { return declared }
		report := preflight.Run(t.Context(), in)

		joined := strings.Join(report.BlindSpots, " | ")
		if listed := strings.Contains(joined, "TRUSTED_PROXIES"); listed != wantListed {
			t.Errorf("with proxies declared=%v the shared-bucket blind spot listed=%v, want %v:\n%s",
				declared, listed, wantListed, joined)
		}
		// Nothing about this may become a check, let alone a failing one:
		// receiving must never be blocked by it (§11).
		for _, c := range report.Failed() {
			if strings.Contains(c.Detail, "TRUSTED_PROXIES") {
				t.Errorf("the shared bucket became a FAILED check (%s); it is unknowable "+
					"from in here, which is what the blind-spot list is for", c.ID)
			}
		}
	}
}

// A second Run must not see the first Run's extra blind spot. Appending to the
// package-level slice would grow it once per render, which looks fine in a test
// that runs one report and shows the operator the same line four times after an
// afternoon of page loads.
func TestBlindSpotsDoNotAccumulateAcrossReports(t *testing.T) {
	in := inputs(t)
	in.ProxiesDeclared = func() bool { return false }
	first := len(preflight.Run(t.Context(), in).BlindSpots)
	for range 5 {
		preflight.Run(t.Context(), in)
	}
	if got := len(preflight.Run(t.Context(), in).BlindSpots); got != first {
		t.Errorf("after six reports the blind-spot list is %d long, was %d", got, first)
	}
	if got := len(preflight.BlindSpots); got != 4 {
		t.Errorf("the package-level list grew to %d; a report mutated it", got)
	}
}

// The node's own state is part of the same computation, so the degraded banner
// and the security panel cannot disagree about whether the node is reachable.
func TestNodeStateIsPartOfTheSameReport(t *testing.T) {
	for state, want := range map[lnd.State]preflight.State{
		lnd.StateReady:      preflight.Pass,
		lnd.StateNotLinked:  preflight.Fail,
		lnd.StateRelink:     preflight.Fail,
		lnd.StateConnecting: preflight.Fail,
	} {
		in := inputs(t)
		in.NodeState = func() lnd.State { return state }
		report := preflight.Run(t.Context(), in)
		if got := check(t, report, preflight.CheckNodeLinked); got.State != want {
			t.Errorf("node state %q gave %v, want %v", state, got.State, want)
		}
	}
}

func TestCheckIDsAreUnique(t *testing.T) {
	report := preflight.Run(t.Context(), inputs(t))
	seen := map[string]bool{}
	for _, c := range report.Checks {
		if seen[c.ID] {
			t.Errorf("duplicate check id %q", c.ID)
		}
		seen[c.ID] = true
	}
	if !slices.IsSorted(ids(report)) {
		t.Log("checks are not in id order; that is fine, but the page order should be deliberate")
	}
}

// The ipaddr check compares the caveat against where this process actually is,
// so the address has to be discovered rather than configured — a configured
// value would agree with itself when the package's static IP is the thing that
// is wrong.
func TestLocalAddressFindsANonLoopbackAddress(t *testing.T) {
	addr, ok := preflight.LocalAddress()
	if !ok {
		t.Skip("no non-loopback IPv4 interface on this machine")
	}
	if addr.IsLoopback() || !addr.Is4() {
		t.Errorf("LocalAddress = %v, want a non-loopback IPv4 address", addr)
	}
}

// 1xp: §5's second freeze gets a row of its OWN, distinct from the shortfall.
//
// Without it the dashboard stays green while every payment is refused — an
// unresolved reservation reduces the wallet's spendable, so reconciliation sees
// no deficit and reports nothing. §11: a checklist of green ticks that bounds
// nothing is worse than no checklist.
//
// The pairing is the test. Asserting only that a row appears would pass against
// a row wired to the shortfall input, which is exactly the mistake to make here:
// the two are adjacent, both about spending, and one is a deficit the operator
// must correct while the other needs nobody at all.
func TestUnresolvedPaymentsGetTheirOwnDegradedRow(t *testing.T) {
	in := inputs(t)
	in.UnresolvedPayments = func(context.Context) (int, error) { return 2, nil }

	report := preflight.Run(t.Context(), in)
	row := check(t, report, preflight.CheckUnresolvedSpend)
	if row.State != preflight.Fail {
		t.Fatal("two unresolved payments and the row is green; spending is held and the " +
			"operator has no way to know why")
	}
	if !strings.Contains(row.Detail, "clears itself") {
		t.Errorf("detail = %q, want it to say nothing needs doing — a degraded row that "+
			"implies action where none is possible sends the operator hunting for a setting "+
			"that does not exist", row.Detail)
	}
	// And it is NOT the reconciliation row: no shortfall was reported, so that
	// one must still be green.
	if shortfall := check(t, report, preflight.CheckReconciliation); shortfall.State != preflight.Pass {
		t.Errorf("the reconciliation row went red for an unresolved payment (%q); it reports a "+
			"deficit, and there is none — the operator would go looking for money that is "+
			"not missing", shortfall.Detail)
	}

	// It clears when they resolve, with no operator action.
	in.UnresolvedPayments = func(context.Context) (int, error) { return 0, nil }
	if row := check(t, preflight.Run(t.Context(), in), preflight.CheckUnresolvedSpend); row.State != preflight.Pass {
		t.Errorf("the row stayed red after the payments resolved: %q", row.Detail)
	}
}

// "Cannot tell" is not "fine". The freeze may well be up, and a green tick this
// check cannot stand behind is the thing §11 objects to.
func TestAnUnreadableUnresolvedCountIsNotGreen(t *testing.T) {
	in := inputs(t)
	in.UnresolvedPayments = func(context.Context) (int, error) {
		return 0, errors.New("the database is locked")
	}
	if row := check(t, preflight.Run(t.Context(), in), preflight.CheckUnresolvedSpend); row.State != preflight.Fail {
		t.Error("an unreadable count reported a green tick")
	}
}

// "We could not ask the node" is not "the node has revoked this key".
//
// Since d24.6 this row refuses payments, so the difference is the difference
// between a transient RPC error and a spend refusal whose diagnosis points the
// operator at the wrong repair. An unreachable node has its own rows.
func TestAnUnaskedNodeDoesNotMeanARevokedRootKey(t *testing.T) {
	in := inputs(t)
	in.SpendMacaroon = func() ([]byte, bool) {
		return lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2026-12-01T00:00:00Z"), true
	}
	in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
		// Reachable, but ListMacaroonIDs failed — so nothing was learned about
		// the key.
		return lnd.BrokerStatus{LNDReachable: true, SpendMacaroonPresent: true,
			SpendRootKeyRecorded: true, SpendRootKeyChecked: false, SpendRootKeyListed: false}, nil
	}

	report := preflight.Run(t.Context(), in)

	got := check(t, report, preflight.CheckSpendRootKey)
	if blocking(report, preflight.BlocksSending, got.ID) || strings.Contains(got.Detail, "revoked") {
		t.Errorf("a node that could not be asked was reported as having revoked the key: "+
			"%q (%v) — since d24.6 that refuses the payment too", got.Detail, got.State)
	}
	// And not a pass either (d46.25): nothing was learned about the key.
	if got.State != preflight.NotChecked {
		t.Errorf("an unasked node rendered the root-key row %v %q; not checked is not a pass",
			got.State, got.Detail)
	}
}

// A spend macaroon the guard has no root key for blocks sending.
//
// It was never baked here, or was baked and revoked — which is what a stale copy
// put back by hand looks like, and what a stolen one looks like. The regtest arc
// produces exactly this state, and an earlier version of the "could not ask"
// fix let it through: the guard forgets the id at revoke, so requiring CHECKED
// alone silently stopped detecting the case the arc exists for.
func TestASpendMacaroonWithNoRootKeyBehindItBlocksSending(t *testing.T) {
	in := inputs(t)
	in.SpendMacaroon = func() ([]byte, bool) {
		return lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2026-12-01T00:00:00Z"), true
	}
	in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
		return lnd.BrokerStatus{LNDReachable: true, SpendMacaroonPresent: true,
			SpendRootKeyRecorded: false}, nil
	}

	report := preflight.Run(t.Context(), in)

	got := check(t, report, preflight.CheckSpendRootKey)
	if got.State != preflight.Fail {
		t.Error("a spend macaroon with no root key behind it passed; it was either never " +
			"baked here or has already been revoked")
	}
	// THE ROW ITSELF blocks, and says why: the fixture's missing guard caveat
	// blocks sending on its own, so the report-level check alone could not tell.
	if !blocking(report, preflight.BlocksSending, got.ID) || !strings.Contains(got.Detail, "no root key") {
		t.Errorf("the root-key row blocks %q with %q; want sending, naming the missing root key",
			got.Blocks, got.Detail)
	}
	if !report.Blocked(preflight.BlocksSending) {
		t.Error("sending was not blocked")
	}
}

// §11's Tier-2 rows from P4 (tna.1). Two conditions, one row, opposite causes.
//
// A spend macaroon with no `lnd-custom brollyguard` caveat is one LND honours
// WITHOUT consulting the guard, so the rolling cap does not apply to it. This is
// the state an upgraded install is in before the credential is re-baked, and it
// is the exact case §11's table added a row for.
func TestTierTwoBlocksSendingWhenTheSpendMacaroonPredatesTheGuardsEnforcement(t *testing.T) {
	in := inputs(t)
	in.SpendMacaroon = func() ([]byte, bool) {
		return lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2033-01-01T00:00:00Z"), true
	}
	in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
		return lnd.BrokerStatus{LNDReachable: true, SpendMacaroonPresent: true,
			SpendRootKeyRecorded: true, SpendRootKeyChecked: true, SpendRootKeyListed: true,
			MiddlewareRegistered: true}, nil
	}

	report := preflight.Run(t.Context(), in)

	got := check(t, report, preflight.CheckSpendGuardCaveat)
	if got.State != preflight.Fail {
		t.Error("a spend macaroon with no guard caveat passed its row; payments made with it " +
			"reach the node without the guard ever being asked")
	}
	// And the OTHER row is unaffected: the guard is registered, and telling the
	// operator otherwise would send them to check a setting on their node when
	// the fix is two clicks on this page (tna.2, Ruling C).
	if other := check(t, report, preflight.CheckGuardMiddleware); other.State != preflight.Pass {
		t.Errorf("the middleware row failed too (%q); two remedies means two rows, and a "+
			"credential problem must not read as a node problem", other.Detail)
	}
	if got.Blocks != preflight.BlocksSending {
		t.Errorf("the finding blocks %q, want sending", got.Blocks)
	}
	if report.Blocked(preflight.BlocksReceiving) {
		t.Error("receiving was blocked; §11 says Tier 2 never blocks receiving")
	}
}

// And the other cause: the macaroon is right, the guard is not registered.
//
// This one is not "the cap is unenforced" — it is "the macaroon does not work".
// LND rejects a custom caveat with no middleware behind it, so sending is
// already broken and the row's job is to name the reason rather than leave the
// operator with an unexplained payment failure.
func TestTierTwoBlocksSendingWhenTheGuardIsNotRegisteredAsAMiddleware(t *testing.T) {
	in := inputs(t)
	in.SpendMacaroon = func() ([]byte, bool) {
		return lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2033-01-01T00:00:00Z",
			lnd.GuardCaveat("nonce")), true
	}
	in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
		return lnd.BrokerStatus{LNDReachable: true, SpendMacaroonPresent: true,
			SpendRootKeyRecorded: true, SpendRootKeyChecked: true, SpendRootKeyListed: true,
			MiddlewareRegistered: false}, nil
	}

	report := preflight.Run(t.Context(), in)

	got := check(t, report, preflight.CheckGuardMiddleware)
	if got.State != preflight.Fail {
		t.Error("the check passed while the guard was not registered; the node refuses this " +
			"macaroon outright until it is")
	}
	if other := check(t, report, preflight.CheckSpendGuardCaveat); other.State != preflight.Pass {
		t.Errorf("the caveat row failed too (%q); the macaroon is correctly baked, and telling "+
			"the operator to re-bake it would be the wrong repair", other.Detail)
	}
	if !strings.Contains(got.Detail, "rpcmiddleware") {
		t.Errorf("the detail %q does not name the node setting an operator would have to "+
			"check", got.Detail)
	}
	// INDEPENDENTLY blocks sending, which is the half a row's own OK does not
	// say: a Check that fails while blocking nothing is a cross on a page that
	// changes nothing about what the app will do.
	if got.Blocks != preflight.BlocksSending {
		t.Errorf("the finding blocks %q, want sending", got.Blocks)
	}
	if !report.Blocked(preflight.BlocksSending) {
		t.Error("the report does not block sending while the node is refusing every payment " +
			"made with this macaroon")
	}
	if report.Blocked(preflight.BlocksReceiving) {
		t.Error("receiving was blocked; §11 says Tier 2 never blocks receiving")
	}
}

// With both halves in place the row passes, which is what makes the two above
// mean anything.
func TestTheSpendCapRowPassesWhenTheCaveatAndTheMiddlewareAgree(t *testing.T) {
	in := inputs(t)
	in.SpendMacaroon = func() ([]byte, bool) {
		return lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2033-01-01T00:00:00Z",
			lnd.GuardCaveat("nonce")), true
	}
	in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
		return lnd.BrokerStatus{LNDReachable: true, SpendMacaroonPresent: true,
			SpendRootKeyRecorded: true, SpendRootKeyChecked: true, SpendRootKeyListed: true,
			MiddlewareRegistered: true}, nil
	}

	report := preflight.Run(t.Context(), in)

	for _, id := range []string{preflight.CheckSpendGuardCaveat, preflight.CheckGuardMiddleware} {
		if got := check(t, report, id); got.State != preflight.Pass {
			t.Errorf("a correctly baked macaroon with a registered middleware failed %s: %q",
				id, got.Detail)
		}
	}
	if report.Blocked(preflight.BlocksSending) {
		t.Errorf("sending is blocked on a healthy install: %v", report.BlockedBy(preflight.BlocksSending))
	}
}

// The spend-cap row exists even on an install with no spend macaroon.
//
// §11's panel is a fixed list: a row that VANISHES on some installs is worse
// than a row that fails, because the operator cannot tell "not applicable" from
// "this build does not check that". Removing it from both early returns was
// green until this test existed.
func TestTheSpendCapRowIsPresentOnAReceiveOnlyInstall(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spend func() ([]byte, bool)
		want  preflight.State
	}{
		{"no spend macaroon", func() ([]byte, bool) { return nil, false }, preflight.Pass},
		// as0.11: with no accessor nothing was read, which is not the receive-only
		// pass — but the rows are still there.
		{"no accessor at all", nil, preflight.NotChecked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := inputs(t)
			in.SpendMacaroon = tc.spend

			report := preflight.Run(t.Context(), in)

			for _, id := range []string{preflight.CheckSpendGuardCaveat, preflight.CheckGuardMiddleware} {
				if got := check(t, report, id); got.State != tc.want {
					t.Errorf("%s is %v, want %v: %q", id, got.State, tc.want, got.Detail)
				}
			}
			if report.Blocked(preflight.BlocksSending) {
				t.Errorf("sending is blocked with nothing to send with: %v",
					report.BlockedBy(preflight.BlocksSending))
			}
		})
	}
}

// tna.2 criterion 3: the spend window is a MEASUREMENT with typed integer msat,
// and it is ABSENT when sending is off.
//
// The absence case is the one a zero value silently gets wrong: "0 of 0 msat"
// reads as either "you have spent your whole budget" or "you have no budget",
// and both are wrong on a receive-only install — which is the default.
func TestTheSpendWindowIsCarriedAsMsatAndIsAbsentWhenSendingIsOff(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status lnd.BrokerStatus
		want   *preflight.SpendWindow
	}{
		{"sending on", lnd.BrokerStatus{
			LNDReachable: true, SpendMacaroonPresent: true,
			SpendUsedMsat: 12_000, SpendLimitMsat: 100_000,
		}, &preflight.SpendWindow{UsedMsat: 12_000, LimitMsat: 100_000, Period: 24 * time.Hour}},
		{"no spend macaroon", lnd.BrokerStatus{LNDReachable: true, SpendLimitMsat: 100_000}, nil},
		{"no limit configured", lnd.BrokerStatus{
			LNDReachable: true, SpendMacaroonPresent: true, SpendUsedMsat: 12_000,
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := inputs(t)
			in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) { return tc.status, nil }

			got := preflight.Run(t.Context(), in).Spend

			switch {
			case tc.want == nil && got != nil:
				t.Errorf("the report carries a window (%+v) with sending off; the page would "+
					"state a cap this install does not have", got)
			case tc.want != nil && got == nil:
				t.Error("the report carries no window while sending is on")
			case tc.want != nil && *got != *tc.want:
				t.Errorf("the window is %+v, want %+v", *got, *tc.want)
			}
		})
	}
	// And a guard that cannot be reached says nothing rather than zero: an
	// unreachable guard has its own row, and a window of 0 of 0 would be this
	// page inventing a fact from a failed call.
	in := inputs(t)
	in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
		return lnd.BrokerStatus{}, errors.New("guard unreachable")
	}
	if got := preflight.Run(t.Context(), in).Spend; got != nil {
		t.Errorf("an unreachable guard produced a window: %+v", got)
	}
}

// tna.2 criterion 4: the rejection signal is a RATE, not a tally.
//
// THIS IS WHAT PROVES IT. The same rejections, asked about over two different
// spans, must give two different answers — which is exactly what the count it
// replaced could not do: "guard.reject rows among the last 200 audit events" has
// no denominator in time at all, so twelve of them could span a minute or a
// month and the page said the same thing either way.
func TestTheRejectionCountIsScopedToAWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	// Three rejections: one an hour ago, one a day and an hour ago, one a week
	// ago. A window of 24 hours must see exactly the first.
	at := []time.Time{
		now.Add(-time.Hour),
		now.Add(-25 * time.Hour),
		now.Add(-7 * 24 * time.Hour),
	}
	var asked time.Time
	in := inputs(t)
	in.Now = func() time.Time { return now }
	in.GuardRejections = func(_ context.Context, since time.Time) (int, error) {
		asked = since
		count := 0
		for _, when := range at {
			if !when.Before(since) {
				count++
			}
		}
		return count, nil
	}

	burst := preflight.Run(t.Context(), in).Rejections

	if burst == nil {
		t.Fatal("the report carries no rejection count")
	}
	if burst.Within != preflight.RejectionWindow {
		t.Errorf("the burst covers %v, want %v — the period travels WITH the number so the "+
			"page cannot state one and mean another", burst.Within, preflight.RejectionWindow)
	}
	if burst.Count != 1 {
		t.Errorf("the burst counts %d rejections in %v, want 1; the other two are older than "+
			"the window and a tally would have counted them", burst.Count, burst.Within)
	}
	if want := now.Add(-preflight.RejectionWindow); !asked.Equal(want) {
		t.Errorf("the report asked for events since %v, want %v", asked, want)
	}

	// The SAME rejections over a wider window give a different answer. That is
	// the difference between a rate and a tally, and it is the assertion the old
	// count could not have passed.
	wider := 0
	for _, when := range at {
		if !when.Before(now.Add(-8 * 24 * time.Hour)) {
			wider++
		}
	}
	if wider == burst.Count {
		t.Fatalf("the fixture is wrong: a wider window sees %d, the same as the narrow one — "+
			"this test would prove nothing", wider)
	}
}

// A trail that cannot be read reports NOTHING, not zero.
//
// "No rejections in the last 24 hours" is reassurance, and a database that would
// not answer must not be able to produce it.
func TestAnUnreadableTrailDoesNotReportZeroRejections(t *testing.T) {
	in := inputs(t)
	in.GuardRejections = func(context.Context, time.Time) (int, error) {
		return 0, errors.New("the trail is unreadable")
	}
	if got := preflight.Run(t.Context(), in).Rejections; got != nil {
		t.Errorf("an unreadable trail reported %+v; the operator would read that as calm", got)
	}
}

// One report asks the guard exactly once.
//
// Three consumers need the guard's status — the reachability row, the spend
// rows and the rolling window — and each used to call Inputs.BrokerStatus for
// itself. cmd/brollyzapper wires the pay ladder's copy to the raw socket rather
// than the cached one, and the ladder builds a report before every payment
// (d24.6), so that was three unix round trips per payment. The cost is the
// smaller half: three answers can disagree, and a report claiming the guard is
// reachable, its macaroon absent and its window open is not a snapshot of
// anything.
//
// Asserted with a spend macaroon present, because that is the arm where all
// three consumers actually read the status.
func TestOneReportAsksTheGuardOnce(t *testing.T) {
	in := inputs(t)
	var calls int
	in.SpendMacaroon = func() ([]byte, bool) {
		return lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2026-12-01T00:00:00Z"), true
	}
	in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
		calls++
		return lnd.BrokerStatus{
			LNDReachable: true, SpendMacaroonPresent: true, SpendRootKeyRecorded: true,
			MiddlewareRegistered: true, SpendLimitMsat: 100_000_000, SpendUsedMsat: 1_000,
		}, nil
	}

	report := preflight.Run(t.Context(), in)

	if calls != 1 {
		t.Errorf("one report dialled the guard %d times, want 1; every extra call is a unix "+
			"round trip on the pay ladder and another chance for one report to disagree "+
			"with itself", calls)
	}
	// And the answer still reached all three consumers.
	if report.Spend == nil {
		t.Error("the rolling window is absent, so the shared status did not reach spendWindow")
	}
	if check(t, report, preflight.CheckGuardReachable).State != preflight.Pass {
		t.Error("the reachability row failed against a guard that answered")
	}
}

// d46.25 (0vk.1 F5): a guard that did not answer has not said anything about
// the spend credential, and a row built OK and flipped only on a positive
// finding renders a tick over a question nobody asked. "The guard is registered
// with your node", with a tick, beside a guard that is not answering.
func TestSpendRowsTheGuardMustAnswerAreNotAPassWhenItDoesNot(t *testing.T) {
	in := inputs(t)
	in.SpendMacaroon = func() ([]byte, bool) {
		return lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2033-01-01T00:00:00Z",
			lnd.GuardCaveat("nonce")), true
	}
	in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
		return lnd.BrokerStatus{}, errors.New("dialling /credentials/guard.sock: connection refused")
	}

	report := preflight.Run(t.Context(), in)

	for _, id := range []string{preflight.CheckGuardMiddleware, preflight.CheckSpendRootKey} {
		got := check(t, report, id)
		if got.State != preflight.NotChecked {
			t.Errorf("%s is %v with a guard that did not answer; nobody was asked", id, got.State)
		}
		// Not checked is not a finding: the row that knows WHY is guard.reachable,
		// and it is the one that blocks.
		if blocking(report, preflight.BlocksSending, id) {
			t.Errorf("%s blocks sending while unchecked; guard.reachable is the row that blocks", id)
		}
	}
	// guard_caveat is read from the FILE, which needs no guard, so it still has
	// an answer — and a correctly baked macaroon passes it.
	if got := check(t, report, preflight.CheckSpendGuardCaveat); got.State != preflight.Pass {
		t.Errorf("the guard caveat row failed on a macaroon that carries the caveat: %q", got.Detail)
	}
	if check(t, report, preflight.CheckGuardReachable).State != preflight.Fail {
		t.Error("the fixture is wrong: guard.reachable passed")
	}

	// The broker answering: unchanged from before this bead.
	in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
		return lnd.BrokerStatus{LNDReachable: true, SpendMacaroonPresent: true,
			SpendRootKeyRecorded: true, SpendRootKeyChecked: true, SpendRootKeyListed: true,
			MiddlewareRegistered: true}, nil
	}
	report = preflight.Run(t.Context(), in)
	for _, id := range []string{preflight.CheckGuardMiddleware, preflight.CheckSpendRootKey,
		preflight.CheckSpendGuardCaveat} {
		if got := check(t, report, id); got.State != preflight.Pass {
			t.Errorf("%s failed against a guard that answered healthy: %q", id, got.Detail)
		}
	}
}

// d46.25: the reconciliation row's four states. The seam test in internal/api
// drives the failure through a real reconciler; this pins each state's verdict
// and what it blocks, which the page alone cannot show.
func TestTheReconciliationRowSaysHowCurrentItsVerdictIs(t *testing.T) {
	checkedAt := time.Date(2026, 9, 15, 8, 46, 0, 0, time.UTC)
	down := errors.New("recon: reading the node's balance: connection refused")
	for _, tc := range []struct {
		name       string
		at         time.Time
		err        error
		readErr    error
		frozen     bool
		want       preflight.State
		wantDetail []string
	}{
		{"never checked", time.Time{}, nil, nil, false, preflight.NotChecked,
			[]string{"none has finished yet", "not frozen"}},
		{"checked and healthy", checkedAt, nil, nil, false, preflight.Pass,
			[]string{"as of 08:46:00 UTC"}},
		// as0.11, delegated: NOT CHECKED rather than a fail. Nothing has compared
		// the ceiling with the node since, which is what the state means, and the
		// row that knows why the node did not answer is the one in the banner.
		{"last check failed", checkedAt, down, nil, false, preflight.NotChecked,
			[]string{"failed at 08:46:00 UTC", "connection refused", "last verdict stands", "not frozen"}},
		// A freeze is the wallet's and stands whatever the freshness: it blocks.
		{"frozen, last check failed", checkedAt, down, nil, true, preflight.Fail,
			[]string{"25000", "failed at 08:46:00 UTC", "connection refused", "freeze stands"}},
		{"frozen, never re-checked", time.Time{}, nil, nil, true, preflight.Fail,
			[]string{"25000", "Not re-checked"}},
		{"frozen, checked", checkedAt, nil, nil, true, preflight.Fail,
			[]string{"25000", "as of 08:46:00 UTC"}},
		// go-review: the freeze itself could not be read. A fresh node check says
		// nothing about it, so this is not a pass "as of" that check.
		{"freeze state unreadable", checkedAt, nil, errors.New("database is locked"), false,
			preflight.NotChecked, []string{"database is locked"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := inputs(t)
			in.Shortfall = func(context.Context) (int64, string, bool, error) {
				return 25_000, "a force close", tc.frozen, tc.readErr
			}
			in.LastReconciliation = func() (time.Time, error) { return tc.at, tc.err }

			report := preflight.Run(t.Context(), in)
			got := check(t, report, preflight.CheckReconciliation)

			// Only a fail blocks, and every fail here is the freeze, which blocks sending.
			wantBlocks := tc.want == preflight.Fail
			if got.State != tc.want || blocking(report, preflight.BlocksSending, got.ID) != wantBlocks {
				t.Errorf("%v, blocks sending %v; want %v, %v (%q)", got.State,
					blocking(report, preflight.BlocksSending, got.ID), tc.want, wantBlocks, got.Detail)
			}
			for _, want := range tc.wantDetail {
				if !strings.Contains(got.Detail, want) {
					t.Errorf("the detail does not say %q: %q", want, got.Detail)
				}
			}
		})
	}
}

// `0vk.11` criterion 5: the panel carries four rows for the receive credential
// and six for the spend one — by id, so a row that drops from one return path is
// named rather than counted.
func TestTheReportCarriesFourReceiveRowsAndSixSpendRows(t *testing.T) {
	want := map[string][]string{
		"receive.": {preflight.CheckReceiveCaveats, preflight.CheckReceiveIPMatches,
			preflight.CheckReceiveExpiry, preflight.CheckReceiveRootKey},
		"spend.": {preflight.CheckSpendCaveats, preflight.CheckSpendIPMatches, preflight.CheckSpendExpiry,
			preflight.CheckSpendRootKey, preflight.CheckSpendGuardCaveat, preflight.CheckGuardMiddleware},
	}
	receiveMacaroon := func() ([]byte, bool) {
		return lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2026-12-01T00:00:00Z"), true
	}
	spendMacaroon := func() ([]byte, bool) {
		return lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2026-12-01T00:00:00Z", lnd.GuardCaveat("n")), true
	}
	absent := func() ([]byte, bool) { return nil, false }
	// Every return path: both present, neither, and the guard not answering.
	for _, tc := range []struct {
		name           string
		receive, spend func() ([]byte, bool)
		guardDown      bool
	}{
		{"both present", receiveMacaroon, spendMacaroon, false},
		{"neither present", absent, absent, false},
		{"guard not answering", receiveMacaroon, spendMacaroon, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := inputs(t)
			in.ReceiveMacaroon, in.SpendMacaroon = tc.receive, tc.spend
			if tc.guardDown {
				in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
					return lnd.BrokerStatus{}, errors.New("guard unreachable")
				}
			}
			report := preflight.Run(t.Context(), in)
			var receive, spend []string
			for _, id := range ids(report) {
				switch {
				case strings.HasPrefix(id, "receive."):
					receive = append(receive, id)
				case strings.HasPrefix(id, "spend.") || id == preflight.CheckGuardMiddleware:
					spend = append(spend, id)
				}
			}
			if !slices.Equal(receive, want["receive."]) {
				t.Errorf("receive rows = %v, want %v", receive, want["receive."])
			}
			if !slices.Equal(spend, want["spend."]) {
				t.Errorf("spend rows = %v, want %v", spend, want["spend."])
			}
			for _, c := range report.Checks {
				if strings.HasPrefix(c.ID, "receive.") && c.Blocks != preflight.BlocksNothing {
					t.Errorf("%s blocks %q; Tier 2 never takes receiving away, and nothing a "+
						"receive row finds is a reason to refuse a payment (§11)", c.ID, c.Blocks)
				}
			}
			if report.Blocked(preflight.BlocksReceiving) {
				t.Error("receiving was blocked; §11 says Tier 2 never blocks receiving")
			}
		})
	}
}

// `0vk.11` criterion 6: each receive row fails on its own condition and names it,
// and a guard that did not check says not checked rather than pass.
func TestEachReceiveRowFailsOnItsOwnCondition(t *testing.T) {
	for _, tc := range []struct {
		name     string
		macaroon []string
		status   *lnd.BrokerStatus
		row      string
		want     []string
		checked  bool // false: the row must say it was not checked
	}{
		{"locked to another address", []string{"ipaddr 10.21.0.99", "time-before 2026-12-01T00:00:00Z"},
			nil, preflight.CheckReceiveIPMatches, []string{"10.21.0.99", "10.21.0.17"}, true},
		{"expired", []string{"ipaddr 10.21.0.17", "time-before 2020-01-01T00:00:00Z"},
			nil, preflight.CheckReceiveExpiry, []string{"expired", "cannot receive"}, true},
		{"unconstrained", nil, nil, preflight.CheckReceiveCaveats, []string{"time-before"}, true},
		{"root key no longer listed", []string{"ipaddr 10.21.0.17", "time-before 2026-12-01T00:00:00Z"},
			&lnd.BrokerStatus{LNDReachable: true, ReceiveMacaroonPresent: true,
				ReceiveRootKeyChecked: true, ReceiveRootKeyListed: false},
			preflight.CheckReceiveRootKey, []string{"no longer lists"}, true},
		// Criterion 7's page half: a guard that predates the fields sends neither,
		// and both decode false.
		{"guard did not check", []string{"ipaddr 10.21.0.17", "time-before 2026-12-01T00:00:00Z"},
			&lnd.BrokerStatus{LNDReachable: true, ReceiveMacaroonPresent: true},
			preflight.CheckReceiveRootKey, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := inputs(t)
			in.ReceiveMacaroon = func() ([]byte, bool) { return lndtest.Macaroon(t, tc.macaroon...), true }
			if tc.status != nil {
				status := *tc.status
				in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) { return status, nil }
			}

			report := preflight.Run(t.Context(), in)

			got := check(t, report, tc.row)
			want := preflight.Fail
			if !tc.checked {
				want = preflight.NotChecked
			}
			if got.State != want {
				t.Fatalf("%s is %v, want %v (%q)", tc.row, got.State, want, got.Detail)
			}
			for _, want := range tc.want {
				if !strings.Contains(got.Detail, want) {
					t.Errorf("%s detail does not name %q: %q", tc.row, want, got.Detail)
				}
			}
			// Only the row under test fails among the receive four — except for the
			// unconstrained credential, whose missing caveats are also the other two
			// rows' conditions.
			for _, c := range report.Failed() {
				if tc.macaroon != nil && strings.HasPrefix(c.ID, "receive.") && c.ID != tc.row {
					t.Errorf("%s failed too (%q); each row is its own condition", c.ID, c.Detail)
				}
			}
		})
	}
}

// Not checked is not a pass, for the receive rows that cannot be evaluated: no
// credential on disk yet, no address to compare with, no guard to ask.
func TestReceiveRowsThatCannotBeEvaluatedAreNotAPass(t *testing.T) {
	t.Run("no receive macaroon yet", func(t *testing.T) {
		in := inputs(t)
		in.ReceiveMacaroon = func() ([]byte, bool) { return nil, false }
		for _, id := range []string{preflight.CheckReceiveCaveats, preflight.CheckReceiveIPMatches,
			preflight.CheckReceiveExpiry, preflight.CheckReceiveRootKey} {
			if got := check(t, preflight.Run(t.Context(), in), id); got.State != preflight.NotChecked {
				t.Errorf("%s with no receive macaroon: %v %q", id, got.State, got.Detail)
			}
		}
	})
	t.Run("own address unknown", func(t *testing.T) {
		in := inputs(t)
		in.ServerIP = netip.Addr{}
		for _, id := range []string{preflight.CheckReceiveIPMatches, preflight.CheckSpendIPMatches} {
			if id == preflight.CheckSpendIPMatches {
				in.SpendMacaroon = func() ([]byte, bool) {
					return lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2026-12-01T00:00:00Z"), true
				}
			}
			report := preflight.Run(t.Context(), in)
			got := check(t, report, id)
			if got.State != preflight.NotChecked || blocking(report, preflight.BlocksSending, id) {
				t.Errorf("%s with no discovered address: %v, blocks sending %v, %q", id, got.State,
					blocking(report, preflight.BlocksSending, id), got.Detail)
			}
		}
	})
	t.Run("guard not answering", func(t *testing.T) {
		in := inputs(t)
		in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
			return lnd.BrokerStatus{}, errors.New("guard unreachable")
		}
		got := check(t, preflight.Run(t.Context(), in), preflight.CheckReceiveRootKey)
		if got.State != preflight.NotChecked {
			t.Errorf("the receive root-key row with no guard: %v %q", got.State, got.Detail)
		}
	})
}
