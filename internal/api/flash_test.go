package api

import (
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/guard"
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

	// The ceremony's refusal markers, which the scan cannot see because since
	// `0vk.53` moveGuardControl redirects with "?flash="+refusalFlash(...) — a
	// cap-pair refusal and a bad code are two different things to say, and the
	// guard's own sentence may not be either of them.
	//
	// Read out of the producing code, not re-listed: capPairFlashes is the map
	// the handler indexes, and the fallback is whatever refusalFlash returns for
	// an error carrying no kind, so a renamed marker or a changed default is
	// still seen here. Same departure as settingsForm below, same reason.
	//
	// ABOVE THE FORWARD LOOP, unlike settingsForm's, so BOTH directions cover
	// these: a marker here with no message renders nothing at all, and that is
	// the failure this whole rule exists for. settingsForm can sit below because
	// TestEveryValidatedFieldCanSayWhyItRefused covers its forward direction;
	// nothing else covers this one.
	for _, marker := range capPairFlashes {
		found[marker] = append(found[marker], "capPairFlashes")
	}
	fallback := refusalFlash(nil, "")
	found[fallback] = append(found[fallback], "refusalFlash")
	for name, files := range found {
		if FlashMessage(name) == "" {
			t.Errorf("%s redirects with ?flash=%s and nothing translates it, so the page "+
				"renders no message at all", strings.Join(files, ", "), name)
		}
	}
	// The settings form's refusal markers, which the scan cannot see because
	// saveSettings redirects with "?flash="+field.refused (0vk.38).
	//
	// THE NOTE BELOW SAYS TO SPELL THE TARGET OUT INSTEAD, and this is a
	// deliberate departure from it, so here is the reason. That advice was
	// written against a marker built from an ARBITRARY variable, which nothing
	// can enumerate. settingsForm is a typed list, so this rule can read the
	// markers straight out of the structure that produces them — which is a
	// stronger guarantee than the regex gives, not a weaker one, because it
	// cannot drift from the redirect the way a literal in a second place can.
	// Spelling it out would mean a per-key switch at the redirect site, which is
	// the shape 0vk.38's brief asked the validator design to avoid.
	for _, field := range settingsForm {
		if field.refused != "" {
			found[field.refused] = append(found[field.refused], "settingsForm")
		}
	}

	// The other direction. A marker assembled by concatenation — "?flash="+x —
	// is invisible to the scan above, so a message reported here is either dead
	// or reached by a redirect this rule cannot see; both want fixing, and the
	// second is fixed by spelling the whole target out at the redirect, or — when
	// the markers live in a list something can range over — by adding that list
	// to the scan as settingsForm is added above.
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

// The companion to the rule above, and settingField's doc names it: a field that
// can refuse must be able to SAY it refused.
//
// A validator with no marker redirects to "/settings?flash=" — no message at
// all, because the template says {{if .Flash}} — so the page silently claims
// nothing happened while the save was thrown away. That is the same failure the
// rule above exists to prevent, arriving from the other direction.
//
// ITS OWN TEST BECAUSE ITS OWN NAME WAS CITED. settingField's doc promised
// TestEveryValidatedFieldCanSayWhyItRefused and the check was an unnamed pair of
// loops inside the rule above, so a reader grepping for the guarantee would have
// found nothing and concluded it had been dropped. Found by review.
func TestEveryValidatedFieldCanSayWhyItRefused(t *testing.T) {
	for _, field := range settingsForm {
		if field.validate != nil && field.refused == "" {
			t.Errorf("settingsForm's %q validates but names no flash marker, so a refusal "+
				"would redirect with an empty one and the page would say nothing", field.key)
		}
		if field.validate == nil && field.refused != "" {
			t.Errorf("settingsForm's %q names the flash marker %q but validates nothing, so "+
				"that copy can never be reached", field.key, field.refused)
		}
	}
}

// levelOption no longer depends on this order, and that is deliberate — review
// found that taking the last match made a lower level appended at the END render
// for a higher process, silently. The TEMPLATE still displays the options in
// table order, though, and an operator reading a select that runs
// debug/error/info/warn would reasonably think it was broken.
//
// So the order is still a real requirement; it is just no longer load-bearing
// for correctness, and this is what holds it.
func TestTheLogLevelOptionsAscend(t *testing.T) {
	for i := 1; i < len(logLevelOptions); i++ {
		if logLevelOptions[i].Level <= logLevelOptions[i-1].Level {
			t.Errorf("logLevelOptions[%d] (%s, %v) does not sit above [%d] (%s, %v); the "+
				"select would show them out of order", i, logLevelOptions[i].Name,
				logLevelOptions[i].Level, i-1, logLevelOptions[i-1].Name,
				logLevelOptions[i-1].Level)
		}
	}
	// And the case the fix was made for: a level appended out of order must not
	// change what an INFO process renders.
	if got := levelOption(slog.LevelInfo); got != "info" {
		t.Errorf("levelOption(INFO) = %q, want \"info\"", got)
	}
}

// The page's cap-pair copy and the guard's remedy name the same limit to move
// (`0vk.53`).
//
// TWO AUTHORS, ONE INSTRUCTION. The guard decides WHAT the refusal is and writes
// a sentence for a log and an audit trail; this package writes what the operator
// reads on the page. That split is the whole design — no guard-supplied text
// reaches the URL — and its one hazard is that the two can drift into naming
// DIFFERENT controls, which is worse than the silence 0vk.53 replaced: an
// operator lowering the 24-hour limit who is told to raise it has been sent to
// undo the tightening they came to make. `8vj` priced that on the box.
//
// SO THE REMEDY CLAUSE IS SHARED VERBATIM and this holds it. It is not relayed
// text: it is this package's own copy, checked against the guard's rather than
// taken from it, in exactly the way internal/arch's
// TestTheCapPairRemediesReadTheSameEverywhere holds the Sending hint, MANUAL.html
// and OPERATING.md to the same phrase (`6zd`). This is the after-refusal surface
// those three do not cover.
//
// READ OUT OF THE GUARD'S SOURCE, because the alternative is a third copy of the
// phrase in this file — and a rule that carries its own copy of the thing whose
// copies are the problem checks nothing.
func TestTheCapPairFlashNamesTheSameLimitAsTheGuardsRemedy(t *testing.T) {
	remedies := guardCapPairRemedies(t)
	controls := map[string]guard.Control{
		"ControlSpendCap":   guard.ControlSpendCap,
		"ControlPaymentCap": guard.ControlPaymentCap,
	}
	if len(capPairFlashes) != len(controls) {
		t.Fatalf("capPairFlashes covers %d controls and this rule knows %d; a cap control "+
			"without a message of its own falls back to the ceremony's code message, which "+
			"is what 0vk.53 removed", len(capPairFlashes), len(controls))
	}

	for name, control := range controls {
		remedy, ok := remedies[name]
		if !ok {
			t.Fatalf("the guard's checkCapPair names no remedy for %s; this rule reads them "+
				"out of internal/guard/operator.go and cannot check copy against a remedy it "+
				"failed to find", name)
		}
		flash := FlashMessage(capPairFlashes[control])
		if flash == "" {
			t.Errorf("%s's cap-pair refusal renders no message at all", name)
			continue
		}
		if !strings.Contains(flash, remedy) {
			t.Errorf("the page tells an operator editing %s:\n  %s\nand the guard refuses "+
				"them with %q. Two wordings for one action are two instructions", name, flash,
				remedy)
		}
		for other, otherRemedy := range remedies {
			if other != name && strings.Contains(flash, otherRemedy) {
				t.Errorf("the page tells an operator editing %s to %q, which is the guard's "+
					"remedy for the OTHER direction — the control they are already editing "+
					"(`8vj`)", name, otherRemedy)
			}
		}
		// A cap-pair refusal involves no code in either direction: lowering the
		// 24-hour limit is a tightening, and the raising case is refused before a
		// code is ever issued (`pou`). Saying one was not accepted is wrong about
		// what happened and points at a remedy that cannot work.
		if strings.Contains(flash, "code was not accepted") {
			t.Errorf("%s's cap-pair message still speaks of a code:\n  %s", name, flash)
		}
	}
}

// guardCapPairRemedies reads checkCapPair's per-control remedies out of the
// guard's source, keyed by the control constant each `case` names.
//
// KEYED BY THE CASE, not by position. The order of two literals in a file is not
// a fact about which control each answers, and a rule that assumed it would go
// on passing after a swap — which is precisely the drift it is here to catch.
func guardCapPairRemedies(t *testing.T) map[string]string {
	t.Helper()
	source, err := os.ReadFile(filepath.Clean("../guard/operator.go"))
	if err != nil {
		t.Fatalf("reading the guard: %v", err)
	}
	// NARROWED TO checkCapPair FIRST, and the first attempt is why: operator.go
	// switches on Control in six places, so a `case ControlX:` scan over the
	// whole file paired the FIRST control label in the file with the first remedy
	// literal four hundred lines below it — two matches, both mis-keyed, and the
	// count check above was satisfied.
	body := capPairBody(t, string(source))
	// Non-greedy to the first remedy after each case label, so the two cases
	// cannot borrow each other's string.
	pattern := regexp.MustCompile(`(?s)case (Control\w+):.*?remedy = "([^"]+)"`)
	matches := pattern.FindAllStringSubmatch(body, -1)
	// ANTI-VACUITY. If checkCapPair is ever rewritten so the remedies are not
	// per-case `remedy = "..."` literals, this finds nothing and the copy below
	// "agrees" with an empty set.
	if len(matches) != 2 {
		t.Fatalf("found %d per-control cap-pair remedies in internal/guard/operator.go, want 2",
			len(matches))
	}
	remedies := map[string]string{}
	for _, m := range matches {
		remedies[m[1]] = m[2]
	}
	if len(remedies) != 2 || matches[0][2] == matches[1][2] {
		t.Fatalf("the guard's two cap-pair remedies are %q; two identical remedies would let "+
			"any page copy satisfy both directions", remedies)
	}
	return remedies
}

// capPairBody is checkCapPair's source, from its signature to the closing brace
// in the first column.
func capPairBody(t *testing.T, source string) string {
	t.Helper()
	const signature = "func (g *Guard) checkCapPair("
	start := strings.Index(source, signature)
	if start < 0 {
		t.Fatalf("internal/guard/operator.go no longer declares %s; the rule that reads its "+
			"remedies has lost its subject", signature)
	}
	end := strings.Index(source[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("checkCapPair's body has no closing brace this rule can find")
	}
	return source[start : start+end]
}
