package api

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Every flash marker a handler redirects with must have a message, and every
// message must belong to a marker some handler redirects with.
//
// Found by review, and it is the shape this repo keeps rediscovering: d24.5's
// two pages arrived with eight markers and NONE of them rendered. The template
// says {{if .Flash}}, so an untranslated marker is not a blank line — it is no
// line at all, and the page silently says nothing happened. The two the Sending
// page exists to report, "the guard would not bake" and "the macaroon was not
// revoked", were both in that set.
//
// THE REVERSE DIRECTION was missing until a later review, and two messages had
// already arrived through the gap: "authorisation_failed" and "cap_refused",
// neither reachable from any handler, the second a second wording for a case
// "code_refused" already covered. Operator-facing copy nobody can trigger is
// worse than none — it gets read, maintained and translated as though it were
// real, and it makes the set of things the app can actually say unknowable.
//
// This test is INTERNAL to the package so one scan can check both directions
// against flashMessages itself. Source-scanning rather than a hand-kept list,
// because a hand-kept list is the thing that went out of date.
func TestEveryFlashMarkerHasAMessageAndEveryMessageAMarker(t *testing.T) {
	marker := regexp.MustCompile(`\?flash=([a-z_-]+)`)
	found := map[string][]string{}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range marker.FindAllStringSubmatch(string(src), -1) {
			found[match[1]] = append(found[match[1]], entry.Name())
		}
	}

	if len(found) == 0 {
		t.Fatal("no flash markers were found at all; this rule can no longer see its subject")
	}
	for name, files := range found {
		if FlashMessage(name) == "" {
			t.Errorf("%s redirects with ?flash=%s and nothing translates it, so the page "+
				"renders no message at all", strings.Join(files, ", "), name)
		}
	}
	// The other direction. A marker assembled by concatenation — "?flash="+x —
	// is invisible to the scan above, so a message reported here is either dead
	// or reached by a redirect this rule cannot see; both want fixing, and the
	// second is fixed by spelling the whole target out at the redirect.
	unreachable := make([]string, 0)
	for name := range flashMessages {
		if found[name] == nil {
			unreachable = append(unreachable, name)
		}
	}
	slices.Sort(unreachable)
	for _, name := range unreachable {
		t.Errorf("flashMessages has %q and no handler redirects with it; it is either dead "+
			"copy or reached by a marker built from a variable, which this rule cannot see", name)
	}
}
