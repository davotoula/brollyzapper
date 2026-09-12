// This file is the lint that keeps the STACK reproducible, as lint_test.go
// keeps it generic. Both exist for the same reason: a claim nobody checks
// decays, and regtest is not in CI (BrollyZap-zu5.7), so a stack that stops
// working is invisible until someone runs it by hand.
//
// BrollyZap-qnz is what these two rules are made of. nwc.sh could not get past
// section 1: get_balance timed out after 20s, on the branch and on main alike,
// with no commit in this repo to blame.
//
// The cause was the relay's LMDB living on a macOS bind mount. strfry's writer
// commits, and its reqMonitor threads read new events back through a long-lived
// mmap that, across virtiofs, never observes the write. So the relay accepted
// the subscription, answered EOSE, accepted every published event with OK true,
// stored them, returned them to a FRESH query — and pushed nothing to the
// subscription already open. Every visible signal said healthy.
//
// Measured before either rule below was written, six filter shapes per cell
// (the app's kinds+#p, kinds only, authors only, a regular kind 1, and the
// 13194 info event):
//
//	strfry 1.1.0, NIP-42 on,  named volume   all six delivered
//	strfry 1.1.1, NIP-42 on,  named volume   all six delivered
//	strfry 1.1.2, NIP-42 on,  named volume   all six delivered
//	strfry 1.1.0, NIP-42 on,  bind mount     none delivered
//	strfry 1.1.1, NIP-42 on,  bind mount     none delivered
//	strfry 1.1.2, NIP-42 off, bind mount     none delivered
//
// The storage is the whole variable. The version and the auth setting each
// looked like the cause when tested against only one storage kind, and were
// not — which is the other reason this file exists.
package regtest

import (
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The relay databases must be named volumes, never host binds.
//
// This is the second time virtiofs has cost this stack real time in the same
// way: the credentials volume is named because the guard's chmod on a unix
// socket inside a macOS bind mount fails with EINVAL. Both are the same lesson —
// a bind mount on macOS is not a filesystem, and anything doing more than
// reading and writing whole files will find out.
//
// Nothing needs the relay DB on the host. It is scratch, and `docker compose
// down -v` clears it either way.
func TestRelayDatabasesAreNamedVolumes(t *testing.T) {
	c, _ := load(t)
	relays := []string{"relay", "relay2"}
	for _, name := range relays {
		svc, ok := c.Services[name]
		if !ok {
			t.Fatalf("service %q is missing from %s", name, composePath)
		}
		found := false
		for _, v := range svc.Volumes {
			source, dest, ok := strings.Cut(v, ":")
			if !ok || !strings.HasPrefix(dest, "/app/strfry-db") {
				continue
			}
			found = true
			// A named volume is a bare name; a bind is a path.
			if strings.ContainsAny(source, "/.") {
				t.Errorf("service %q mounts its LMDB from %q, a host bind. On macOS "+
					"strfry then stops delivering live events to open subscriptions "+
					"while looking entirely healthy (BrollyZap-qnz) — use a named "+
					"volume", name, source)
			}
		}
		if !found {
			t.Errorf("service %q mounts nothing at /app/strfry-db; if the path moved, "+
				"this rule needs rewriting rather than deleting", name)
		}
	}
}

// Every image in this stack is pinned by digest. The relay was the one that was
// not — it read `dockurr/strfry:latest`, which moved from 1.1.0 to 1.1.1 on
// 21 Jul 2026 while this repo stood still.
//
// That tag move was NOT the qnz failure; the storage above was, and it fails on
// every version tested. The rule is here on its own merits: a floating tag in a
// stack that otherwise pins everything is worse than one that pins nothing,
// because the pinning creates a reasonable belief that the stack is
// reproducible — and a whole session went into ruling the relay version in and
// then back out precisely because it could have changed under us.
// A version tag AND a full digest. umbrel/lint_test.go refuses a bare repo and
// a :latest tag for the same reason this file gives at the top: the digest says
// what ran, and the tag is how a human reading the file knows WHICH VERSION that
// was without resolving it. A reference with a digest and no tag pulls correctly
// and tells the next reader nothing.
var pinnedImageRE = regexp.MustCompile(`^[^:@[:space:]]+:[^:@[:space:]]+@sha256:[0-9a-f]{64}$`)

func TestEveryImageInTheStackIsPinnedByDigest(t *testing.T) {
	c, _ := load(t)
	for _, name := range serviceNames(c) {
		image := c.Services[name].Image
		if image == "" {
			// Absence belongs to TestTheStackActuallyNamesImages, which reports it
			// once per service. Named rather than "the control below", so renaming
			// that test breaks this reference instead of silently orphaning it.
			continue
		}
		// THE DIGEST'S SHAPE, NOT THE PREFIX. strings.Contains(image, "@sha256:")
		// was satisfied by the marker alone: a digest shortened by one hex digit
		// passed, and so would `@sha256:` with nothing after it. Measured — the
		// brief for BrollyZap-20i.16 named that plant expecting it to be red, and
		// on main it was green. Docker would reject such a reference at pull
		// time, which is exactly the failure this rule exists to catch BEFORE
		// anyone pulls.
		if !pinnedImageRE.MatchString(image) {
			t.Errorf("service %q pins %q; every image here must carry a version tag AND a "+
				"full @sha256: digest of 64 lowercase hex, or this stack's behaviour changes "+
				"with no commit to point at (BrollyZap-qnz)", name, image)
		}
	}
}

// The control for the test above, and the reason it is no longer a line scan.
//
// It was strings.Count(raw, "image:") >= 6 over the whole file, comments
// included — so the check whose ONLY job is to prove the rule above is not
// vacuous was itself satisfiable by prose. Verified by plant (BrollyZap-20i.16):
// rename every real image: key to imaged: and append six comment lines reading
// "# image: a comment", and BOTH tests pass having looked at nothing. The rule
// above had the same shape, scanning raw lines for an image: prefix while the
// parsed services sat in scope.
//
// Reading the struct is stronger in three ways — and not shorter, which the
// first version of this comment claimed: the control below went from five lines
// to about twenty. It
// resolves the `<<: *lnd-common` merge key, so lnd and lnd-payer are two
// services carrying an image rather than one anchor line the scan counted once.
// It ignores x-lnd-common, which is an extension field and not a service, where
// the line scan counted its image: as a seventh. And ABSENCE BECOMES VISIBLE: a
// service with no image at all is something a raw scan cannot see, because
// there is no line there to match.
//
// EVERY SERVICE HAS ONE. The brief that asked for this expected init to be the
// exception; it is not, it runs the lnd image to drive lncli. So there is no
// image-less allowance — and the stack's membership is the list below rather
// than a sentence, because a sentence naming eight services is a claim that goes
// stale the first time a ninth arrives and nothing notices.
//
// THE LIST REPLACES A FLOOR. `len(names) < 6` would have passed a stack that
// gained a service, lost one, or renamed one, all of which change what the
// digest rule above is asserting over. What would change this list: a service
// added to or removed from the stack, which is a change worth a reader's
// attention and now costs one line here.
var stackServices = []string{
	"bitcoind", "brollyzapper", "guard", "init", "lnd", "lnd-payer", "relay", "relay2",
}

func TestTheStackActuallyNamesImages(t *testing.T) {
	c, _ := load(t)
	names := serviceNames(c)
	if !slices.Equal(names, stackServices) {
		t.Errorf("%s defines services %s, and this file expects %s; the digest rule above "+
			"asserts over whatever is here, so a change to the membership is a change to "+
			"what it checks", composePath, strings.Join(names, ", "),
			strings.Join(stackServices, ", "))
	}
	for _, name := range names {
		if c.Services[name].Image == "" {
			t.Errorf("service %q declares no image; every service in this stack runs one, so "+
				"this is either a service that should say why it is different or a mount "+
				"that lost its image line — and the digest rule above cannot see the "+
				"difference", name)
		}
	}
}

// serviceNames is the stack's services in a stable order, so a failure names the
// same service every run and two failures read in the same order.
func serviceNames(c compose) []string {
	return slices.Sorted(maps.Keys(c.Services))
}

// TestPinnedImageREAcceptsOnlyATagAndAFullDigest is what makes the rule above
// survive a revert.
//
// Both halves of BrollyZap-20i.16 were revertible-without-red when they landed:
// `strings.Contains(image, "@sha256:")` passes every case below except the bare
// tag, and the stack's own compose exercises none of them because it is
// correct. A rule whose only input is a file that satisfies it has been written,
// not tested.
func TestPinnedImageREAcceptsOnlyATagAndAFullDigest(t *testing.T) {
	const digest = "@sha256:e81d238db13507f6ef24c49d47cd0b0ea58ff207961f10581fa2a7c901054df4"
	for _, tc := range []struct {
		image string
		want  bool
		why   string
	}{
		{"dockurr/strfry:1.1.2" + digest, true, "the shape the stack uses"},
		{"ghcr.io/davotoula/brollyzapper:0.1.16" + digest, true, "a registry-qualified name"},
		{"dockurr/strfry:1.1.2", false, "a tag alone is what BrollyZap-qnz was"},
		{"dockurr/strfry" + digest, false, "a digest with no tag says nothing about which version"},
		{"dockurr/strfry:1.1.2@sha256:", false, "the marker with no digest after it"},
		{"dockurr/strfry:1.1.2" + digest[:len(digest)-1], false, "one hex digit short"},
		{"dockurr/strfry:1.1.2" + digest + "0", false, "one hex digit long"},
		{"dockurr/strfry:1.1.2" + strings.ToUpper(digest[8:]), false, "uppercase hex: no registry emits it"},
		{"dockurr/strfry:1.1.2" + digest + " ", false, "trailing space"},
		{"dockurr/strfry:latest" + digest, true, "a moving tag is still pinned by its digest"},
	} {
		if got := pinnedImageRE.MatchString(tc.image); got != tc.want {
			t.Errorf("pinnedImageRE.MatchString(%q) = %v, want %v — %s", tc.image, got, tc.want, tc.why)
		}
	}
}
