package api

import (
	"log/slog"
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

// Every cap control this route may move has a cap-pair message of its own
// (`0vk.53`).
//
// ANCHORED TO capControls, the production list, not to a second copy of it here:
// a third cap control added there and nowhere else would fall through
// refusalFlash to code_refused, and its operator would be told a code was not
// accepted for a refusal that involves no code — which is the exact defect this
// bead exists to remove, arriving again by way of a list that was extended in
// one place.
//
// WHAT THE MESSAGES SAY is not checked here. internal/arch's
// TestTheCapPairRemediesReadTheSameEverywhere holds this copy to the guard's own
// remedy, alongside the Sending hint, MANUAL.html and OPERATING.md; and
// TestACapPairRefusalTellsTheOperatorWhichLimitToMove drives the real handler to
// prove which control gets which message.
func TestEveryCapControlHasACapPairMessage(t *testing.T) {
	if len(capControls) == 0 {
		t.Fatal("capControls is empty; this rule can no longer see its subject")
	}
	for _, control := range capControls {
		marker, ok := capPairFlashes[control]
		if !ok {
			t.Errorf("the caps route may move %q and capPairFlashes has no message for it, "+
				"so its cap-pair refusal falls back to the ceremony's code message", control)
			continue
		}
		if FlashMessage(marker) == "" {
			t.Errorf("%q's cap-pair marker %q translates to nothing", control, marker)
		}
	}
}
