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
	_, raw := load(t)
	for i, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "image:") {
			continue
		}
		image := strings.TrimSpace(strings.TrimPrefix(trimmed, "image:"))
		if !strings.Contains(image, "@sha256:") {
			t.Errorf("%s:%d pins %q by tag alone; every image here must carry an "+
				"@sha256: digest, or this stack's behaviour changes with no commit to "+
				"point at (BrollyZap-qnz)", composePath, i+1, image)
		}
	}
}

// The control for the test above: a compose file naming no images would pass it
// having checked nothing.
func TestTheStackActuallyNamesImages(t *testing.T) {
	_, raw := load(t)
	if n := strings.Count(raw, "image:"); n < 6 {
		t.Errorf("%s names %d images; too few for TestEveryImageInTheStackIsPinnedByDigest "+
			"to mean anything", composePath, n)
	}
}
