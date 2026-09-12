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
	"regexp"
	"sort"
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
func TestEveryImageInTheStackIsPinnedByDigest(t *testing.T) {
	c, _ := load(t)
	for _, name := range serviceNames(c) {
		image := c.Services[name].Image
		if image == "" {
			continue // reported by the control below, which is where absence belongs
		}
		// THE DIGEST'S SHAPE, NOT THE PREFIX. strings.Contains(image, "@sha256:")
		// was satisfied by the marker alone: a digest shortened by one hex digit
		// passed, and so would `@sha256:` with nothing after it. Measured — the
		// brief for BrollyZap-20i.16 named that plant expecting it to be red, and
		// on main it was green. Docker would reject such a reference at pull
		// time, which is exactly the failure this rule exists to catch BEFORE
		// anyone pulls.
		if !digestRE.MatchString(image) {
			t.Errorf("service %q pins %q without a full @sha256: digest (64 lowercase hex); "+
				"every image here must carry one, or this stack's behaviour changes with no "+
				"commit to point at (BrollyZap-qnz)", name, image)
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
// Reading the struct is less code and strictly stronger in three ways. It
// resolves the `<<: *lnd-common` merge key, so lnd and lnd-payer are two
// services carrying an image rather than one anchor line the scan counted once.
// It ignores x-lnd-common, which is an extension field and not a service, where
// the line scan counted its image: as a seventh. And ABSENCE BECOMES VISIBLE: a
// service with no image at all is something a raw scan cannot see, because
// there is no line there to match.
//
// EVERY SERVICE HAS ONE, measured 12 Sep 2026 — bitcoind, lnd, lnd-payer,
// relay, relay2, init, guard, brollyzapper. The brief that asked for this
// expected init to be the exception; it is not, it runs the lnd image to drive
// lncli. So there is no image-less allowance here, and a service that gains one
// has to say so in this list rather than by passing quietly.
func TestTheStackActuallyNamesImages(t *testing.T) {
	c, _ := load(t)
	names := serviceNames(c)
	if len(names) < 6 {
		t.Errorf("%s defines %d services (%s); too few for "+
			"TestEveryImageInTheStackIsPinnedByDigest to mean anything",
			composePath, len(names), strings.Join(names, ", "))
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

var digestRE = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// serviceNames is the stack's services in a stable order, so a failure names the
// same service every run and two failures read in the same order.
func serviceNames(c compose) []string {
	names := make([]string, 0, len(c.Services))
	for name := range c.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
