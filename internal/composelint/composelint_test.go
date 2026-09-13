package composelint_test

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/composelint"
)

// The three compose files this package reads for the lints, from here.
var realComposeFiles = []string{
	"../../deploy/docker-compose.yml",
	"../../umbrel/brollyzapper/docker-compose.yml",
	"../../regtest/docker-compose.yml",
}

// COMMENTS ARE PLACED ON THEIR LINES, and every whole-line comment in the three
// real files is found. yaml.v3 records comments on nodes without line numbers,
// so Comments places them; a comment it dropped would be a marker deploy's
// INTERIM check could never see, which is the silent direction.
//
// This test reads the files' text itself — it is checking the reader against
// the thing the reader exists to stop the lints from reading.
func TestCommentsFindEveryWholeLineCommentOnItsLine(t *testing.T) {
	for _, path := range realComposeFiles {
		t.Run(path, func(t *testing.T) {
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var want []composelint.Comment
			for i, line := range strings.Split(string(src), "\n") {
				if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "#") {
					want = append(want, composelint.Comment{Text: trimmed, Line: i + 1})
				}
			}
			if len(want) < 10 {
				t.Fatalf("found %d whole-line comments in %s; every one of these files explains "+
					"itself at length, so this is reading the wrong thing", len(want), path)
			}
			got := composelint.Load(t, path, nil).Comments()
			for _, w := range want {
				if !slices.Contains(got, w) {
					t.Errorf("%s:%d: comment %q was not recovered on its line", path, w.Line, w.Text)
				}
			}
		})
	}
}

// A `#` inside a quoted value is part of the value, and a trailing comment is a
// comment on the line it trails.
func TestCommentsAreOnlyWhatTheParserCallsAComment(t *testing.T) {
	doc := composelint.Parse(t, "fixture", []byte(
		"services:\n"+
			"  s:\n"+
			"    # above the environment\n"+
			"    environment:\n"+
			"      A: \"x # not a comment\"  # a trailing one\n"+
			"      B: \"# nor this\"\n"), nil)
	want := []composelint.Comment{
		{Text: "# above the environment", Line: 3},
		{Text: "# a trailing one", Line: 5},
	}
	if got := doc.Comments(); !slices.Equal(got, want) {
		t.Errorf("Comments() = %+v, want %+v", got, want)
	}
	for _, s := range doc.Scalars() {
		if s.Value == "x # not a comment" && s.Line != 5 {
			t.Errorf("the quoted value is on line %d, want 5", s.Line)
		}
	}
}

// What sits between two keys is the entries between them, never comments or
// blanks — and the lines say which came first.
func TestKeysBetweenIsEntriesInDocumentOrder(t *testing.T) {
	doc := composelint.Parse(t, "fixture", []byte(
		"services:\n"+
			"  server:\n"+
			"    environment:\n"+
			"      ADMIN_PASSWORD: $APP_PASSWORD\n"+
			"      # the platform owns it\n"+
			"\n"+
			"      OTHER: x\n"+
			"      ADMIN_PASSWORD_MANAGED: \"true\"\n"), nil)

	got, err := doc.KeysBetween([]string{"services", "server", "environment"}, "ADMIN_PASSWORD", "ADMIN_PASSWORD_MANAGED")
	if err != nil {
		t.Fatal(err)
	}
	want := composelint.Between{First: 4, Second: 8, Entries: []composelint.Scalar{{Value: "OTHER: x", Line: 7}}}
	if got.First != want.First || got.Second != want.Second || !slices.Equal(got.Entries, want.Entries) {
		t.Errorf("KeysBetween = %+v, want %+v", got, want)
	}

	reversed, err := doc.KeysBetween([]string{"services", "server", "environment"}, "ADMIN_PASSWORD_MANAGED", "OTHER")
	if err != nil {
		t.Fatal(err)
	}
	if reversed.First < reversed.Second || len(reversed.Entries) != 0 {
		t.Errorf("keys in the wrong order = %+v, want the first line after the second and nothing between", reversed)
	}

	if _, err := doc.KeysBetween([]string{"services", "server", "environment"}, "ADMIN_PASSWORD", "MISSING"); err == nil {
		t.Error("a key that is not there was not an error")
	}
}

// A folded double-quoted scalar is one value, and an anchor name is reported.
func TestScalarsFoldAndAnchorsAreSeen(t *testing.T) {
	doc := composelint.Parse(t, "fixture", []byte(
		"services:\n  s:\n    environment: &ENV_anchor\n      A: \"${LND_D\\\n        IR}\"\n"), nil)
	if !doc.InterpolatedNames()["LND_DIR"] {
		t.Errorf("a folded scalar was not read as one interpolation: %v", doc.InterpolatedNames())
	}
	if anchors := doc.Anchors(); len(anchors) != 1 || anchors[0].Name != "ENV_anchor" {
		t.Errorf("Anchors() = %v, want ENV_anchor", anchors)
	}
}

// The key and the comment block above it.
func TestKeyCarriesTheCommentAboveIt(t *testing.T) {
	doc := composelint.Parse(t, "fixture", []byte(
		"services:\n  guard:\n    # runs as 65532 by default\n    user: \"1000:1000\"\n"), nil)
	key, ok := doc.Key("services", "guard", "user")
	if !ok || key.Line != 4 || !strings.Contains(key.Comment, "65532") {
		t.Errorf("Key = %+v, %v; want line 4 carrying the comment above it", key, ok)
	}
	if _, ok := doc.Key("services", "server", "user"); ok {
		t.Error("a key under a service that does not exist was found")
	}
}
