package guard_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// Spec §6: the socket API is exactly this list, and the narrowness IS the
// boundary. A seventh must fail here rather than being reviewed into existence.
//
// IT WAS FOUR UNTIL `06v`. Re-aimed rather than relaxed: what the count was
// standing in for is "no operation lets the server obtain something it may not
// have", and that property is asserted by name in
// TestTheGuardRequestCarriesNothingButTheOperation below. The two operations
// that joined are the OPERATOR's ceremony — ask for an authorisation, redeem one
// — and they exist because `06v` established there is no operator surface on
// umbrelOS at all: no settings key in any of 391 app manifests, and `exports.sh`
// is package content an update overwrites. Adding them was the alternative to
// shipping an app whose Sending page named a setting that did not exist.
func TestTheSocketAPIIsExactlyTheseOperations(t *testing.T) {
	want := []string{"status", "bake_receive", "bake_spend", "revoke_spend",
		"request_authorisation", "apply_change"}
	var got []string
	for _, op := range guard.Ops {
		got = append(got, string(op))
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		t.Errorf("guard.Ops = %v, want %v (spec §6)", got, want)
	}

	g, _ := newGuard(t, lndtest.Start(t))
	for _, op := range guard.Ops {
		if resp := g.Handle(t.Context(), guard.Request{Op: op}); strings.Contains(resp.Error, "unknown operation") {
			t.Errorf("operation %q is in Ops but the guard does not implement it", op)
		}
	}
	resp := g.Handle(t.Context(), guard.Request{Op: guard.Op("bake_anything")})
	if !strings.Contains(resp.Error, "unknown operation") {
		t.Errorf("an operation outside the list was accepted: %+v", resp)
	}
}

// Spec §6, `wxz`, re-aimed by `06v`: NO FIELD OF Request GRANTS ANYTHING.
//
// This was "exactly one field, Op", and the count was standing in for the
// property. `06v` had to add two fields, so the property is now asserted
// directly — by an allow-list of the exact field set, so a third arrives as a
// failure here rather than as a review someone waves through.
//
// WHY THE TWO NEW FIELDS ARE NOT WHAT d46.8 REFUSED. That bead asked for the
// request types to have no field for a permission list rather than for a
// supplied one to be rejected — "a validation check is a rule someone can
// remove; an absent field is not". It is about fields that let the server OBTAIN
// something:
//
//   - Change names one of THREE compiled-in controls and a value. It cannot name
//     a fourth, and it does not say which DIRECTION it moves; the guard computes
//     that against its own stored state, because the direction is exactly what a
//     compromised server would lie about.
//   - Code is checked against a secret in a volume the server has no mount for.
//     Supplying it is relaying, not asserting.
//
// A field saying "this is a tightening", or naming a control by free-form
// string, or carrying the authorisation itself, WOULD be the widening d46.8
// refused — and would fail the allow-list here.
func TestNoFieldOfTheGuardRequestGrantsAnything(t *testing.T) {
	want := map[string]string{
		"Op":     "guard.Op",
		"Change": "*guard.Change",
		"Code":   "string",
	}
	typ := reflect.TypeOf(guard.Request{})
	got := map[string]string{}
	for i := range typ.NumField() {
		got[typ.Field(i).Name] = typ.Field(i).Type.String()
	}
	if !maps.Equal(got, want) {
		t.Errorf("guard.Request carries %v, want exactly %v.\n"+
			"A field here is a PARAMETER the server supplies, and the server is the container "+
			"§11 assumes may be compromised. A root key id would turn RevokeSpend into "+
			"DeleteMacaroonID pointed at any app's key on the box; a permission list would turn "+
			"bake into arbitrary-bake; a direction flag would let a compromised server call "+
			"every one of its own changes a tightening. §11's threat table states this "+
			"narrowness as a mitigation, so widening the type makes that row false. If the "+
			"guard genuinely needs to be told something new, that is a spec change to §6 and a "+
			"new bounded operation (d46.8, `06v`).", got, want)
	}

	// And the same scan the count used to make redundant: nothing named like a
	// capability, on Request or on the Change it now carries.
	forbidden := []string{"permission", "uri", "caveat", "rootkey", "root_key", "id", "entity",
		"action", "macaroon", "authoris", "tighten", "loosen"}
	for _, typ := range []reflect.Type{typ, reflect.TypeOf(guard.Change{})} {
		for i := range typ.NumField() {
			name := strings.ToLower(typ.Field(i).Name)
			for _, bad := range forbidden {
				if strings.Contains(name, bad) {
					t.Errorf("%s.%s looks like a caller-supplied capability or a "+
						"caller-supplied DIRECTION (spec §6, `06v`)",
						typ.Name(), typ.Field(i).Name)
				}
			}
		}
	}
}

// `06v`: the operator controls are a CLOSED SET of three, and the closedness is
// what stops OpApplyChange being a general "write into the guard's state" call
// wearing a safe name.
//
// A fourth control is a design change: it is one more thing an operator can be
// asked to authorise, and one more sentence the guard has to be able to write
// truthfully into the file they read.
func TestTheOperatorControlsAreExactlyThree(t *testing.T) {
	want := []string{"sending", "spend_cap", "payment_cap"}
	var got []string
	for _, c := range guard.Controls {
		got = append(got, string(c))
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("guard.Controls = %v, want %v (`06v`)", got, want)
	}

	// And a control outside the set is refused rather than silently ignored —
	// which would be a change the operator was told happened and did not.
	g, _ := newGuard(t, lndtest.Start(t))
	resp := g.Handle(t.Context(), guard.Request{
		Op:     guard.OpApplyChange,
		Change: &guard.Change{Control: guard.Control("everything"), On: true},
	})
	if resp.Error == "" {
		t.Error("apply_change accepted a control this guard does not have")
	}
}

// Spec §6: five URI-scoped permissions, never entity:action. `invoices:write`
// alone grants every invoice-mutating RPC; five explicit URIs grant five
// methods.
func TestBakeReceiveAsksForExactlyTheFiveReceivePermissions(t *testing.T) {
	node := lndtest.Start(t)
	g, _ := newGuard(t, node)

	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}
	requests := node.BakeRequests()
	if len(requests) != 1 {
		t.Fatalf("the node saw %d bake requests, want 1", len(requests))
	}
	want := []string{
		"/lnrpc.Lightning/GetInfo",
		"/lnrpc.Lightning/AddInvoice",
		"/lnrpc.Lightning/LookupInvoice",
		"/lnrpc.Lightning/SubscribeInvoices",
		"/lnrpc.Lightning/ChannelBalance",
	}
	var got []string
	for _, permission := range requests[0].Permissions {
		if permission.Entity != "uri" {
			t.Errorf("permission %+v uses entity %q, want uri — entity:action grants far too much (spec §6)",
				permission, permission.Entity)
		}
		got = append(got, permission.Action)
	}
	if !slices.Equal(got, want) {
		t.Errorf("baked permissions = %v, want exactly %v", got, want)
	}
}

func TestBakeReceiveWritesTheMacaroonIntoTheCredentialVolume(t *testing.T) {
	node := lndtest.Start(t)
	baked := lndtest.Macaroon(t)
	node.SetBakedMacaroon(baked)
	g, credentials := newGuard(t, node)

	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}
	written, err := os.ReadFile(filepath.Join(credentials, lnd.ReceiveMacaroon))
	if err != nil {
		t.Fatalf("reading the baked macaroon: %v", err)
	}
	// NOT the bytes the node returned: LND's BakeMacaroon takes permissions and
	// nothing else, so the constraints are added client-side afterwards (§6).
	// What must hold is that the written credential is the node's macaroon plus
	// this build's policy.
	if string(written) == string(baked) {
		t.Error("recv.macaroon is the node's macaroon unchanged; no caveat was added, and a " +
			"stolen copy would work from anywhere, for ever (d46.26)")
	}
	if err := lnd.RequireHardening(written); err != nil {
		t.Errorf("the written receive macaroon is not hardened: %v", err)
	}
	if got, ok := lnd.CaveatValue(written, lnd.CaveatIPAddr); !ok || got != "10.21.0.17" {
		t.Errorf("ipaddr caveat = %q (present %v), want the server's address", got, ok)
	}
	if _, ok := lnd.Expiry(written); !ok {
		t.Error("the written receive macaroon carries no readable expiry")
	}
	info, err := os.Stat(filepath.Join(credentials, lnd.ReceiveMacaroon))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("recv.macaroon mode = %o, want 600", got)
	}
}

// Spec §6, d24.1: every operation in the list is REAL — none is a stub that
// answers "not enabled" — and one outside it is still a design change.
//
// The two `06v` added are driven with the change they need. An operation that
// requires an argument is exercised WITH one here rather than skipped, because
// the point of this test is that the list and the implementation agree, and a
// skipped entry is exactly how they come to disagree.
func TestEveryOperationInTheListIsImplemented(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuardFull(t, node, d, guard.Options{}, netip.MustParseAddr("10.21.0.17"), true)
	permitSending(t, g, d)

	// A loosening the guard will grant, so request_authorisation has something
	// to do; apply_change then redeems it.
	raise := guard.Change{Control: guard.ControlSpendCap, Msat: config.DefaultMaxSpendMsat * 2}
	for _, op := range guard.Ops {
		req := guard.Request{Op: op}
		switch op {
		case guard.OpRequestAuthorisation:
			req.Change = &raise
		case guard.OpApplyChange:
			req.Change = &raise
			req.Code = readAuthorisationCode(t, d)
		}
		if resp := g.Handle(t.Context(), req); resp.Error != "" {
			t.Errorf("%s: %s", op, resp.Error)
		}
	}
	resp := g.Handle(t.Context(), guard.Request{Op: "bake_anything"})
	if resp.Error == "" {
		t.Error("an operation outside the list was accepted")
	}
}

// Spec §6: the guard re-copies tls.cert on every start, which is how a
// regenerated certificate reaches the server.
func TestStartCopiesTheCertificateIntoTheCredentialVolume(t *testing.T) {
	node := lndtest.Start(t)
	g, credentials := newGuard(t, node)

	if err := g.CopyCertificate(); err != nil {
		t.Fatalf("CopyCertificate: %v", err)
	}
	copied, err := os.ReadFile(filepath.Join(credentials, lnd.CertFile))
	if err != nil {
		t.Fatalf("reading the copied certificate: %v", err)
	}
	if string(copied) != string(node.CertPEM()) {
		t.Error("the certificate in the credential volume is not the one the guard mounts")
	}
}

func TestStatusReportsCredentialPresenceAndReachability(t *testing.T) {
	node := lndtest.Start(t)
	g, _ := newGuard(t, node)

	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.ReceiveMacaroonPresent {
		t.Error("Status reports a receive macaroon before one was baked")
	}
	if !status.LNDReachable {
		t.Error("Status reports the node unreachable, but the fake node answered")
	}

	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("BakeReceive: %v", err)
	}
	status, err = g.Status(t.Context())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.ReceiveMacaroonPresent {
		t.Error("Status does not report the receive macaroon that was just baked")
	}
	if status.SpendMacaroonPresent {
		t.Error("Status reports a spend macaroon; sending is not enabled until P3")
	}

	// A node that stops answering must show as unreachable, not as an error the
	// server has to interpret.
	node.SetReject(true)
	status, err = g.Status(t.Context())
	if err != nil {
		t.Fatalf("Status with a rejecting node: %v", err)
	}
	if status.LNDReachable {
		t.Error("Status reports the node reachable while it rejects every call")
	}
}

// Spec §6, box-verified: a missing bind-mount source makes Docker create a
// DIRECTORY at the host path and the container dies at exit 127, leaving a
// directory that must be rm -rf'd. A named preflight failure is the difference
// between an operator knowing what to delete and not.
func TestPreflightNamesADirectoryWhereAFileShouldBe(t *testing.T) {
	dir := t.TempDir()
	mountPath := filepath.Join(dir, "admin.macaroon")
	if err := os.MkdirAll(mountPath, 0o700); err != nil {
		t.Fatalf("creating the directory Docker would have created: %v", err)
	}

	err := guard.PreflightMounts(mountPath)
	if err == nil {
		t.Fatal("PreflightMounts accepted a directory where the macaroon should be")
	}
	if !errors.Is(err, guard.ErrMountIsDirectory) {
		t.Errorf("error = %v, want ErrMountIsDirectory", err)
	}
	if !strings.Contains(err.Error(), mountPath) {
		t.Errorf("error %q does not name the path the operator has to remove", err)
	}
}

func TestPreflightAcceptsRegularFilesAndReportsMissingOnes(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "tls.cert")
	lndtest.WriteFile(t, present, []byte("cert"))
	if err := guard.PreflightMounts(present); err != nil {
		t.Errorf("PreflightMounts on a regular file = %v, want nil", err)
	}

	missing := filepath.Join(dir, "admin.macaroon")
	err := guard.PreflightMounts(missing)
	if err == nil {
		t.Fatal("PreflightMounts accepted a mount source that does not exist")
	}
	if errors.Is(err, guard.ErrMountIsDirectory) {
		t.Error("a missing file was reported as a directory")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error %q does not name the missing path", err)
	}
}

// Spec §6, box-verified: rotate by rename, never rm-then-write. The window
// between the two is what kills the container.
func TestCredentialWritesReplaceAtomicallyAndLeaveNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "recv.macaroon")

	if err := guard.WriteCredential(target, []byte("first"), 0o600); err != nil {
		t.Fatalf("WriteCredential: %v", err)
	}
	if err := guard.WriteCredential(target, []byte("second"), 0o600); err != nil {
		t.Fatalf("WriteCredential over an existing file: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("content = %q, want the replacement", got)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading dir: %v", err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only the target — the temp file must be renamed, not left", names)
	}
}

// Spec §6: three consecutive auth failures within 30 s mean the node's
// macaroons were rotated. The clock is injected; no test waits 30 seconds.
func TestRotationIsDetectedAfterThreeConsecutiveRejectedProbes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	detector := guard.NewRotationDetector(func() time.Time { return now }, 30*time.Second, 3)

	if detector.ProbeFailed() || detector.ProbeFailed() {
		t.Fatal("rotation was declared before the third rejected probe")
	}
	if !detector.ProbeFailed() {
		t.Error("three consecutive rejected probes did not declare rotation")
	}
}

// as0.8: a caller cannot push the guard toward its own exit.
//
// Re-link has no rate limit, and clicking it is exactly what an operator does
// while the node is rejecting. Before this, one bake attempt on a WARM guard
// produced two detector samples — measured — so two clicks inside the window
// exited the guard with the probe loop contributing nothing.
func TestOnlyTheGuardsOwnProbesAdvanceTheRun(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	detector := guard.NewRotationDetector(func() time.Time { return now }, 30*time.Second, 3)

	for range 20 {
		detector.Rejected()
	}
	if !detector.Armed() {
		t.Error("a rejection did not arm the probe loop")
	}
	if detector.ProbeFailed() || detector.ProbeFailed() {
		t.Error("observations from elsewhere counted toward the threshold; twenty of them " +
			"should leave the run at zero, so two probes must not be enough")
	}
}

func TestASuccessBetweenProbesMeansTheyAreNotConsecutive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	detector := guard.NewRotationDetector(func() time.Time { return now }, 30*time.Second, 3)

	detector.ProbeFailed()
	detector.ProbeFailed()
	detector.Success()
	if detector.Armed() {
		t.Error("a success left the probe loop armed")
	}
	if detector.ProbeFailed() || detector.ProbeFailed() {
		t.Fatal("a success did not reset the run of probes")
	}
	if !detector.ProbeFailed() {
		t.Error("three probes after the reset did not declare rotation")
	}
}

// The gap rule, and it is the other half of CONSECUTIVE.
//
// A probe that took longer than the window — a loaded node, a stalled TLS
// handshake — is not adjacent to the one before the trouble started, and
// counting it as such would let a run span any amount of wall time.
func TestProbesFurtherApartThanTheWindowAreNotAConsecutiveRun(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	detector := guard.NewRotationDetector(func() time.Time { return now }, 30*time.Second, 3)

	detector.ProbeFailed()
	detector.ProbeFailed()
	now = now.Add(31 * time.Second)
	if detector.ProbeFailed() {
		t.Error("probes 31 s apart were treated as a consecutive run inside a 30 s window")
	}
}

// Spec §6: the guard's bounded exit is the one sanctioned exit in the codebase,
// because it is the only way to re-resolve a rename-replaced bind mount.
func TestRepeatedAuthFailuresEndTheProcessWithTheRotationError(t *testing.T) {
	node := lndtest.Start(t)
	node.SetReject(true)
	// The probe loop has its own timer, so this hook sees the exit delay and
	// nothing else — which is what lets the assertion below be exact.
	slept := make(chan time.Duration, 4)
	g, _ := newGuardWithOptions(t, node, guard.Options{
		ProbeInterval: time.Millisecond,
		Sleep: func(_ context.Context, d time.Duration) error {
			select {
			case slept <- d:
			default:
			}
			return nil
		},
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx, socketPath(t)) }()

	// Three rejected bakes is what a rotated node looks like from here.
	for range 3 {
		_ = g.Handle(ctx, guard.Request{Op: guard.OpBakeReceive})
	}

	select {
	case err := <-done:
		if !errors.Is(err, guard.ErrMacaroonRotated) {
			t.Fatalf("Serve = %v, want ErrMacaroonRotated", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the guard did not exit after three consecutive auth failures")
	}
	select {
	case d := <-slept:
		if d != guard.RotationExitDelay {
			t.Errorf("slept %v before exiting, want %v", d, guard.RotationExitDelay)
		}
	default:
		t.Error("the guard exited without the settling delay that lets restart: on-failure work")
	}
}

// as0.7: the guard re-bakes after its own restart, without being asked.
//
// It exits SO THAT the restart re-resolves the bind mount and it can re-link.
// Before this it came back and logged "receive macaroon already present and
// within policy" — about a credential baked under a root key the node forgot in
// the rotation the guard had just finished declaring — and recovery waited 39
// seconds for the SERVER to ask. Measured on regtest.
func TestARestartRebakesWhenTheNodeNoLongerListsTheRootKey(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	first := openGuard(t, node, d, guard.Options{})
	if err := first.BakeReceive(t.Context()); err != nil {
		t.Fatalf("the first bake: %v", err)
	}
	before := node.ListedRootKeyIDs()
	if len(before) != 1 {
		t.Fatalf("the node lists %v after one bake, want exactly one root key", before)
	}
	baked := credentialBytes(t, d.credentials)

	// The rotation: the node forgets every key it had. The credential on disk
	// is untouched, present, hardened and unexpired — everything the old check
	// looked at.
	if _, err := node.DeleteRootKeyForTest(before[0]); err != nil {
		t.Fatalf("forgetting the root key: %v", err)
	}

	// The restart. A second guard over the SAME volumes is what that is.
	restarted := openGuard(t, node, d, guard.Options{})
	if err := restarted.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon after the restart: %v", err)
	}
	if got := credentialBytes(t, d.credentials); string(got) == string(baked) {
		t.Error("the guard came back and kept a credential baked under a root key the node " +
			"has forgotten; it exited in order to re-link and then did not")
	}
	if after := node.ListedRootKeyIDs(); len(after) != 1 || after[0] == before[0] {
		t.Errorf("the node lists %v after the restart, want one NEW root key (was %v)",
			after, before)
	}
}

// The guard-rail, and it matters more than the fix.
//
// A node whose answer we cannot get must not count as "not listed". Treating
// unknown as rotated would re-bake on every transient outage, and each bake is
// a root key on the operator's node plus two audit rows — the storm Wave 9's
// circuit-breaker exists to prevent.
//
// Two shapes of "cannot tell", and they are genuinely different: a node that
// REFUSES (Unauthenticated — which is also the rotation signal) and a node that
// does not answer at all (Unavailable — the case where observe's IsAuthFailure
// filter is the entire guard-rail). The first version of this test only had the
// former, under a name that claimed the latter.
func TestANodeThatCannotAnswerIsNotTreatedAsARotation(t *testing.T) {
	for name, refuse := range map[string]func(*lndtest.Node){
		"a node that refuses":         func(n *lndtest.Node) { n.SetReject(true) },
		"a node that does not answer": func(n *lndtest.Node) { n.SetRejectWith(status.Error(codes.Unavailable, "node is down")) },
	} {
		t.Run(name, func(t *testing.T) {
			unreachableNodeIsNotARotation(t, refuse)
		})
	}
}

func unreachableNodeIsNotARotation(t *testing.T, refuse func(*lndtest.Node)) {
	t.Helper()
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuard(t, node, d, guard.Options{})
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("the first bake: %v", err)
	}
	baked := credentialBytes(t, d.credentials)

	// The node stops being able to answer. It has NOT forgotten anything.
	refuse(node)
	restarted := openGuard(t, node, d, guard.Options{})
	err := restarted.EnsureReceiveMacaroon(t.Context())

	// The RETURN VALUE is the assertion, not the file. Deciding "rotated" here
	// leads to a bake ATTEMPT, and against an unreachable node that attempt
	// fails — leaving the credential on disk unchanged either way. Planted
	// exactly that (unknown treated as rotated) and the file-only version
	// reported a pass. Leaving the credential alone is a success; trying and
	// failing is not.
	if err != nil {
		t.Errorf("EnsureReceiveMacaroon = %v while the node was unreachable; unknown is not "+
			"rotated, and attempting a bake on every blip is a root-key storm on the "+
			"operator's node", err)
	}
	if got := credentialBytes(t, d.credentials); string(got) != string(baked) {
		t.Error("the credential changed while the node could not answer")
	}
}

// Criterion 3's control: a node that still lists the key must not provoke a bake.
func TestARestartKeepsACredentialTheNodeStillHonours(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuard(t, node, d, guard.Options{})
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("the first bake: %v", err)
	}
	baked := credentialBytes(t, d.credentials)

	restarted := openGuard(t, node, d, guard.Options{})
	if err := restarted.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon: %v", err)
	}
	if got := credentialBytes(t, d.credentials); string(got) != string(baked) {
		t.Error("the guard re-baked a credential the node still honours; that is a new root " +
			"key and two audit rows for nothing, on every restart")
	}
}

// credentialBytes is the receive macaroon currently on the credential volume.
func credentialBytes(t *testing.T, credentials string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(credentials, "recv.macaroon"))
	if err != nil {
		t.Fatalf("reading the receive macaroon: %v", err)
	}
	return raw
}

// as0.8, at the guard rather than the detector: no amount of calling in can
// push the guard toward its own exit.
//
// The detector-level test above proves Rejected() does not advance the run. It
// does NOT prove observe() calls Rejected() rather than ProbeFailed() — planted
// exactly that and the detector test still passed. This is the wiring, and it is
// the regression that actually happened: a WARM guard produced two detector
// samples per bake attempt, so two Re-link clicks inside the window exited it.
// POST /node/relink has no rate limit, and clicking it is precisely what an
// operator does while the node is rejecting.
func TestCallingTheGuardRepeatedlyCannotMakeItExit(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	g := openGuard(t, node, d, guard.Options{
		// The probe loop must not rescue the assertion by tripping on its own:
		// an interval longer than the test means every sample here is external.
		ProbeInterval: time.Hour,
	})
	// WARM — it has baked before, which is the production shape and the one
	// where the extra sample appeared.
	if err := g.BakeReceive(t.Context()); err != nil {
		t.Fatalf("warming the guard: %v", err)
	}
	node.SetReject(true)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx, socketPath(t)) }()

	// Ten times the threshold, as fast as they can be made.
	for range 10 * guard.DefaultRotationThreshold {
		_ = g.Handle(ctx, guard.Request{Op: guard.OpBakeReceive})
		if _, err := g.Status(ctx); err != nil {
			t.Fatalf("Status: %v", err)
		}
	}

	select {
	case err := <-done:
		t.Fatalf("the guard exited (%v) because it was called %d times; only its own probes "+
			"may advance the run, or an operator clicking Re-link can restart the guard",
			err, 10*guard.DefaultRotationThreshold)
	case <-time.After(time.Second):
	}
}

// as0.8: the guard reaches the conclusion from its OWN observations.
//
// This is the unit form of the criterion that matters. Measured on regtest,
// nothing in an unattended deployment produces three auth failures inside the
// thirty-second window: the server's re-bake ask is capped at one a minute, its
// guard poll at one per five minutes, the guard's renewal check hourly. Seven
// failures arrived over 4m37s and no window held more than two, so the detector
// never fired and the app could not receive until a human refreshed a page.
//
// So the test gives the guard EXACTLY ONE external rejection and then never
// touches it again. If it exits, the second and third samples were its own.
func TestOneRejectionIsEnoughForTheGuardToDetectRotationOnItsOwn(t *testing.T) {
	node := lndtest.Start(t)
	node.SetReject(true)
	g, _ := newGuardWithOptions(t, node, guard.Options{
		// Instant, so the probe loop's interval and the settling delay do not
		// make this test wait thirty seconds to learn something about ordering.
		// The loop has its own timer now, so this is what drives it; the Sleep
		// hook is the exit delay alone.
		ProbeInterval: 5 * time.Millisecond,
		Sleep:         func(context.Context, time.Duration) error { return nil },
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx, socketPath(t)) }()

	// ONE. Not three. This is the whole point.
	_ = g.Handle(ctx, guard.Request{Op: guard.OpBakeReceive})

	select {
	case err := <-done:
		if !errors.Is(err, guard.ErrMacaroonRotated) {
			t.Fatalf("Serve = %v, want ErrMacaroonRotated", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("one rejection did not lead to a rotation exit: the guard is still waiting " +
			"for someone else to call it, which is what as0.8 is about")
	}
}

// The control for the test above, and the property §6 now rests on.
//
// The old window protected against a slow trickle of unrelated failures by
// demanding density. The probe loop protects against it by demanding
// CONTINUITY: a transient failure is followed by a successful probe ten seconds
// later, which ends the loop. Without this, a guard that probes on its own
// clock would turn every momentary blip into a rotation — and each rotation is
// an exit, a restart, and a fresh root key on the operator's node.
func TestATransientFailureEndsTheProbeLoopInsteadOfTrippingIt(t *testing.T) {
	node := lndtest.Start(t)
	node.SetReject(true)
	g, _ := newGuardWithOptions(t, node, guard.Options{
		// The loop has its own timer now, so this is what drives it; the Sleep
		// hook is the exit delay alone.
		ProbeInterval: 5 * time.Millisecond,
		Sleep:         func(context.Context, time.Duration) error { return nil },
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx, socketPath(t)) }()

	// A TRICKLE: fail, recover, fail, recover — five times, which is well past
	// the threshold in total and never once reaches it consecutively. This is
	// §6's "a slow trickle of unrelated failures over hours must still not be
	// read as rotation", compressed.
	//
	// Alternating rather than one-blip-then-healthy on purpose: with a single
	// failure, BOTH the run being cleared and the loop stopping prevent a trip,
	// so the test passes whichever one is broken. Planted exactly that and it
	// reported a pass. Alternating leaves only the cleared run.
	for range 5 {
		node.SetReject(true)
		_ = g.Handle(ctx, guard.Request{Op: guard.OpBakeReceive})
		node.SetReject(false)
		if _, err := g.Status(ctx); err != nil {
			t.Fatalf("Status while the node is healthy: %v", err)
		}
		select {
		case err := <-done:
			t.Fatalf("the guard exited with %v after failures the node recovered from "+
				"between; a trickle is not a rotation", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// The socket is the whole interface. This drives it end to end, which is also
// the test that the server-side client satisfies lnd.CredentialBroker.
func TestTheSocketClientDrivesTheRealAPI(t *testing.T) {
	node := lndtest.Start(t)
	g, _ := newGuard(t, node)
	ctx := t.Context()
	client := serveGuard(t, g)
	var _ lnd.CredentialBroker = client

	if err := client.RequestReceiveBake(ctx); err != nil {
		t.Fatalf("RequestReceiveBake over the socket: %v", err)
	}
	if len(node.BakeRequests()) != 1 {
		t.Errorf("the node saw %d bakes, want 1", len(node.BakeRequests()))
	}
	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status over the socket: %v", err)
	}
	if !status.ReceiveMacaroonPresent || !status.LNDReachable {
		t.Errorf("status over the socket = %+v, want the baked macaroon and a reachable node", status)
	}
}

// --- helpers ---------------------------------------------------------------

// newGuard builds a guard against node and returns it with its credential
// volume, which several tests then read.
func newGuard(t *testing.T, node *lndtest.Node) (*guard.Guard, string) {
	t.Helper()
	return newGuardWithOptions(t, node, guard.Options{})
}

func newGuardWithOptions(t *testing.T, node *lndtest.Node, opts guard.Options) (*guard.Guard, string) {
	t.Helper()
	d := guardDirs(t, node)
	return openGuard(t, node, d, opts), d.credentials
}

// dirs is one guard's volumes, kept separate from the guard itself so a test
// can build a SECOND guard over the same ones — which is what a restart is.
type dirs struct {
	credentials, data, cert, admin string
}

func guardDirs(t *testing.T, node *lndtest.Node) dirs {
	t.Helper()
	root := t.TempDir()
	d := dirs{
		credentials: filepath.Join(root, "credentials"),
		data:        filepath.Join(root, "guard-data"),
		cert:        filepath.Join(root, "tls.cert"),
		admin:       filepath.Join(root, "admin.macaroon"),
	}
	if err := os.MkdirAll(d.credentials, 0o700); err != nil {
		t.Fatalf("creating credential dir: %v", err)
	}
	node.WriteMounts(t, d.cert, d.admin)
	return d
}

func openGuard(t *testing.T, node *lndtest.Node, d dirs, opts guard.Options) *guard.Guard {
	t.Helper()
	return openGuardAt(t, node, d, opts, netip.MustParseAddr("10.21.0.17"))
}

// newGuardWithoutSending is a guard on which the operator has not enabled
// sending, which is the DEFAULT and the state every install starts in (tna.4,
// `06v`). The deployment ceiling is on; the operator's LATCH is off, which since
// `06v` is what makes a fresh install receive-only.
func newGuardWithoutSending(t *testing.T, node *lndtest.Node) (*guard.Guard, string) {
	t.Helper()
	d := guardDirs(t, node)
	return openGuardWithSending(t, node, d, false), d.credentials
}

// openGuardWithSending builds a guard over existing volumes with the operator's
// gate in a named position, so a test can restart one with sending permitted or
// not.
//
// PERMITTING IT RUNS THE REAL CEREMONY (`06v`), rather than writing the latch
// into the state file behind the guard's back. Two reasons, and the second is
// the one that matters: a harness that wrote the JSON would hold a second copy
// of the state format, and — since almost every spend test comes through here —
// the ceremony would be exercised only by the tests that are about it. This way
// every test that needs sending on drives the operator's actual path to it.
func openGuardWithSending(t *testing.T, node *lndtest.Node, d dirs, permit bool) *guard.Guard {
	t.Helper()
	g := openGuardFull(t, node, d, guard.Options{}, netip.MustParseAddr("10.21.0.17"), true)
	if permit {
		permitSending(t, g, d)
	}
	return g
}

// openGuardUnpermitted is a guard on which the operator has NOT enabled sending
// — a fresh install — with the caps configured.
//
// It is the shape every ceremony test needs, and it is a separate constructor
// rather than a flag because the difference matters: openGuardWithCaps performs
// the ceremony, so a test using it to check that turning sending on needs one
// would find the latch already thrown and pass for the wrong reason.
func openGuardUnpermitted(t *testing.T, node *lndtest.Node, d dirs, limits caps) *guard.Guard {
	t.Helper()
	return openGuardFull(t, node, d, guard.Options{},
		netip.MustParseAddr("10.21.0.17"), true, limits)
}

// openGuardWithDeploymentCeiling builds a guard with GUARD_ALLOW_SENDING itself
// in a named position — the one control `06v` left in the environment, and the
// one no in-app action can lift.
func openGuardWithDeploymentCeiling(t *testing.T, node *lndtest.Node, d dirs, allow bool) *guard.Guard {
	t.Helper()
	return openGuardFull(t, node, d, guard.Options{}, netip.MustParseAddr("10.21.0.17"), allow)
}

// permitSending performs the operator's ceremony: ask for an authorisation, read
// the code out of the guard's own file, and redeem it.
//
// It reads the file rather than being handed the code, because there is no other
// way to get one — RequestAuthorisation deliberately returns no code, and the
// server may never learn one. That constraint is the whole design, and a test
// helper that could shortcut it would be evidence the constraint had a hole.
//
// IDEMPOTENT, because a test that restarts a guard over the same volumes comes
// back to a latch that is already on — and asking for an authorisation to
// perform a change that is not a loosening is refused, by design (Ruling 1). The
// production shape is the same: the ceremony authorises the TRANSITION, so there
// is nothing to authorise when the transition has happened.
func permitSending(t *testing.T, g *guard.Guard, d dirs) {
	t.Helper()
	if status, err := g.Status(t.Context()); err == nil && status.SendingLatched {
		return
	}
	change := guard.Change{Control: guard.ControlSending, On: true}
	if err := g.RequestAuthorisation(t.Context(), change); err != nil {
		t.Fatalf("requesting an authorisation to enable sending: %v", err)
	}
	if err := g.ApplyChange(t.Context(), change, readAuthorisationCode(t, d)); err != nil {
		t.Fatalf("redeeming the authorisation to enable sending: %v", err)
	}
}

// readAuthorisationCode lifts the code out of the file the guard wrote for the
// operator, through the one statement of that file's format.
func readAuthorisationCode(t *testing.T, d dirs) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(d.data, "authorisation.txt"))
	if err != nil {
		t.Fatalf("reading the authorisation file the operator is meant to read: %v", err)
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if _, code, ok := strings.Cut(line, guard.AuthorisationCodeLine); ok {
			return strings.TrimSpace(code)
		}
	}
	t.Fatalf("the authorisation file carries no %q line; an operator has nothing to type:\n%s",
		guard.AuthorisationCodeLine, raw)
	return ""
}

// openGuardAt is openGuard with the server address as a parameter, so the one
// test that needs a guard with NO address to lock to does not have to
// re-implement this constructor — and so a new required config.Guard field is
// added in one place rather than two.
func openGuardAt(t *testing.T, node *lndtest.Node, d dirs, opts guard.Options,
	serverIP netip.Addr) *guard.Guard {
	t.Helper()
	// PERMITTED for every test that does not say otherwise. A fresh install is
	// receive-only — that is tna.4, and since `06v` the latch is what makes it
	// so — and the tests that are about the gate name it; the rest are about
	// what happens once an operator has permitted sending, and would otherwise
	// all be testing the refusal.
	g := openGuardFull(t, node, d, opts, serverIP, true)
	permitSending(t, g, d)
	return g
}

// caps are §6's two spend limits, zero meaning "not configured" (tna.1).
type caps struct{ window, payment int64 }

// openGuardWithCaps builds a guard with the hard cap configured and the gate
// on, which is the shape every middleware test needs.
func openGuardWithCaps(t *testing.T, node *lndtest.Node, d dirs, limits caps) *guard.Guard {
	t.Helper()
	g := openGuardFull(t, node, d, guard.Options{},
		netip.MustParseAddr("10.21.0.17"), true, limits)
	permitSending(t, g, d)
	return g
}

func openGuardFull(t *testing.T, node *lndtest.Node, d dirs, opts guard.Options,
	serverIP netip.Addr, allowSending bool, limits ...caps) *guard.Guard {
	t.Helper()
	var limit caps
	if len(limits) == 1 {
		limit = limits[0]
	}
	if opts.Log == nil {
		opts.Log = logging.New(io.Discard, logging.NewLevelVar(slog.LevelDebug))
	}
	if opts.Sleep == nil {
		opts.Sleep = func(context.Context, time.Duration) error { return nil }
	}
	g, err := guard.New(&config.Guard{
		LNDAddress:           node.Address(),
		LNDCertFile:          d.cert,
		LNDAdminMacaroonFile: d.admin,
		CredentialsDir:       d.credentials,
		DataDir:              d.data,
		ServerIP:             serverIP,
		AllowSending:         allowSending,
		MaxSpendMsat:         limit.window,
		MaxPaymentMsat:       limit.payment,
	}, opts)
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

// assertHardened is §6's policy, checked once and used by both credentials.
//
// It was written out twice — once per credential — and had already drifted in
// the copying: one spelled the expiry check `expiry.Before(time.Now())` and the
// other `got <= 0`. Adding a fourth allowed condition to §6 would have meant
// finding two allow-lists, and missing one leaves a test that passes while
// asserting less. That is the same failure mode as the two caveat lists §6
// collapsed into one function.
func assertHardened(t *testing.T, raw []byte, kind string) {
	t.Helper()
	if err := lnd.RequireHardening(raw); err != nil {
		t.Fatalf("the %s macaroon is not hardened: %v", kind, err)
	}
	present, err := lnd.Caveats(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing beyond the policy either. A caveat nobody intended is as much a
	// defect as a missing one — it would be a constraint nobody wrote down.
	allowed := []string{lnd.CaveatIPAddr, lnd.CaveatIPRange, lnd.CaveatTimeBefore}
	if kind == "spend" {
		allowed = append(allowed, lnd.CaveatLNDCustom)
	}
	for _, caveat := range present {
		condition, _, _ := strings.Cut(caveat, " ")
		if !slices.Contains(allowed, condition) {
			t.Errorf("unexpected caveat %q on the %s macaroon", caveat, kind)
		}
	}
	// And P4's caveat is on the spend credential and ONLY on it (tna.1). The
	// negative half is the sharp one: a custom caveat fails closed, so a receive
	// macaroon carrying it would stop zap receiving dead every time the guard
	// restarted — the app's whole purpose, taken down by a spend control.
	if got, want := lnd.HasGuardCaveat(raw), kind == "spend"; got != want {
		t.Errorf("the %s macaroon carries the %s caveat = %v, want %v",
			kind, lnd.GuardCaveatName, got, want)
	}
	expiry, ok := lnd.Expiry(raw)
	if !ok {
		t.Fatalf("the %s macaroon carries no readable expiry", kind)
	}
	if left := time.Until(expiry); left > guard.CredentialLifetime || left <= 0 {
		t.Errorf("the %s macaroon expires in %v, want within the %v lifetime",
			kind, left, guard.CredentialLifetime)
	}
}

// socketPath keeps the unix socket short enough for sun_path.
func socketPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(lndtest.ShortDir(t), "g.sock")
}

// §11: after every bake, parse the macaroon and assert the caveats are
// genuinely present rather than trusting the bake applied them. The failure
// this prevents is a credential that constrains nothing while every indicator
// reads green.
func TestBakeRejectsAMacaroonThatIsNotOne(t *testing.T) {
	node := lndtest.Start(t)
	node.SetBakedMacaroon([]byte("this is not a macaroon"))
	g, credentials := newGuard(t, node)

	err := g.BakeReceive(t.Context())
	if err == nil {
		t.Fatal("BakeReceive accepted bytes that are not a macaroon")
	}
	if _, statErr := os.Stat(filepath.Join(credentials, lnd.ReceiveMacaroon)); statErr == nil {
		t.Error("the unusable macaroon was written to the credential volume anyway")
	}
}

// The spend macaroon's caveats are what make an exfiltrated copy inert (§6).
// P3 bakes it; the verification it will use is built and tested now, because
// the check is only worth having if it can fail.
func TestSpendCaveatsAreVerifiedBeforeAMacaroonIsAccepted(t *testing.T) {
	full := lndtest.Macaroon(t, "ipaddr 10.21.0.17", "time-before 2026-09-01T00:00:00Z")
	if err := guard.VerifyBaked("spend", false, full); err != nil {
		t.Errorf("a correctly baked spend macaroon was rejected: %v", err)
	}

	stripped := lndtest.Macaroon(t)
	err := guard.VerifyBaked("spend", false, stripped)
	if err == nil {
		t.Fatal("a spend macaroon with every caveat stripped was accepted")
	}
	for _, condition := range []string{lnd.CaveatIPAddr, lnd.CaveatTimeBefore} {
		if !strings.Contains(err.Error(), condition) {
			t.Errorf("error %q does not name the missing %s caveat", err, condition)
		}
	}

	// Half-constrained is still unconstrained enough to matter: an IP lock with
	// no expiry never stops being valid.
	half := lndtest.Macaroon(t, "ipaddr 10.21.0.17")
	if err := guard.VerifyBaked("spend", false, half); err == nil {
		t.Error("a spend macaroon with no time-before caveat was accepted")
	}
}
