package logging_test

import (
	"strings"
	"testing"
)

// The rule above, run against violations rather than against the tree.
//
// WHY THIS FILE EXISTS. CLAUDE.md: "Verify a structural rule by planting a
// violation. A rule that has only ever passed has been written, not tested. This
// has caught its own author three times." internal/arch spells the same
// discipline as a scanner plus a Test wrapper that runs it clean and then
// catches. The first version of the completeness rule had no such seam — its
// plants were edits made by hand, run once, reverted, and leaving nothing that
// could be re-run after a refactor. These are those plants, kept.
//
// Each case names the branch it exercises. A case that stops matching is a branch
// that has stopped firing.
func TestTheCompletenessRuleDetectsItsOwnViolations(t *testing.T) {
	// The three shapes a bearer's field can take, plus the primitive itself.
	const bearers = `package web

import "github.com/davotoula/brollyzapper/internal/secret"

type SetupView struct {
	Name  string
	Token secret.String
}

type Held struct {
	Token *secret.String
}

type Many struct {
	Tokens []secret.String
}

type Keyed struct {
	Tokens map[string]secret.String
}

type KeyedBySecret struct {
	Seen map[secret.String]bool
}

type Plain struct {
	Name string
}
`
	found, _ := secretBearingTypes(t, []moduleFile{planted("internal/web", "internal/web/web.go", bearers)})
	names := make([]string, len(found))
	for i, b := range found {
		names[i] = b.name
	}
	if got := strings.Join(names, ","); got != "web.Held,web.Keyed,web.KeyedBySecret,web.Many,web.SetupView" {
		t.Errorf("the walk found %q; it must see a secret.String behind a pointer, a slice, "+
			"a map value and a map key, and must not invent a bearer out of web.Plain", got)
	}
	if len(found) > 0 && found[0].line == 0 {
		t.Error("a bearer was reported at line 0, which is the fabricated position the " +
			"hand-seeded secret.String entry used to carry")
	}

	// secret.String is matched by name, being the one bearer with no such field.
	primitive, _ := secretBearingTypes(t, []moduleFile{planted("internal/secret",
		"internal/secret/secret.go", "package secret\n\ntype String struct {\n\tv string\n}\n")})
	if len(primitive) != 1 || primitive[0].name != "secret.String" {
		t.Errorf("the walk did not find secret.String itself: %v", primitive)
	}

	// A test file is not source: a fixture in a _test.go is not a bearer.
	if in, _ := secretBearingTypes(t, []moduleFile{planted("internal/web",
		"internal/web/web_test.go", bearers)}); len(in) != 0 {
		t.Errorf("the walk read a _test.go file and found %v; test fixtures are not the "+
			"module's types", in)
	}

	// The four spellings that left BOTH this rule and internal/arch green on
	// 2026-09-05, each with no LogValue anywhere. Every one of them is an
	// ordinary thing to write.
	for _, c := range []struct{ name, src, want string }{{
		name: "the package imported under an alias",
		src: "package store\n\nimport sec \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Pairing struct {\n\tToken sec.String\n}\n",
		want: "store.Pairing",
	}, {
		name: "the package dot-imported",
		src: "package store\n\nimport . \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Pairing struct {\n\tToken String\n}\n",
		want: "store.Pairing",
	}, {
		name: "a map value",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Pairing struct {\n\tTokens map[string]secret.String\n}\n",
		want: "store.Pairing",
	}, {
		name: "a bare String outside package secret is not one",
		src:  "package store\n\ntype Pairing struct {\n\tToken String\n}\n",
		want: "",
	}, {
		name: "the package imported for side effects only",
		src: "package store\n\nimport _ \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Pairing struct {\n\tToken String\n}\n",
		want: "",
	}} {
		t.Run(c.name, func(t *testing.T) {
			got, _ := secretBearingTypes(t, []moduleFile{planted("internal/store",
				"internal/store/nwc.go", c.src)})
			names := make([]string, len(got))
			for i, b := range got {
				names[i] = b.name
			}
			if strings.Join(names, ",") != c.want {
				t.Errorf("the walk found %v, want %q", names, c.want)
			}
		})
	}

	// A second name for secret.String is refused rather than followed. See
	// aliasesASecret for why forbidding beats resolving.
	for _, c := range []struct{ name, src, want string }{{
		name: "an alias for secret.String",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Token = secret.String\n",
		want: "declares Token as another name for secret.String",
	}, {
		name: "a redefinition of secret.String",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Token secret.String\n",
		want: "declares Token as another name for secret.String",
	}, {
		name: "an alias for something else",
		src:  "package store\n\ntype Token = string\n",
		want: "",
	}, {
		name: "a struct is not an alias",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Token struct {\n\tv secret.String\n}\n",
		want: "",
	}} {
		t.Run(c.name, func(t *testing.T) {
			_, aliases := secretBearingTypes(t, []moduleFile{planted("internal/store",
				"internal/store/nwc.go", c.src)})
			got := strings.Join(aliases, "\n")
			switch {
			case c.want == "" && got != "":
				t.Errorf("reported an alias where there is none:\n%s", got)
			case c.want != "" && !strings.Contains(got, c.want):
				t.Errorf("did not report %q; it said %q", c.want, got)
			}
		})
	}

	txn := secretBearer{name: "store.Txn", dir: "internal/store", file: "internal/store/invoices.go", line: 486}
	beside := redactionMarker{name: "store.Txn", dir: "internal/store", file: "internal/store/txn_redaction_test.go", line: 21}

	for _, c := range []struct {
		name     string
		bearers  []secretBearer
		markers  []redactionMarker
		table    map[string]subject
		wantOne  string
		wantNone bool
	}{{
		name: "a bearer in neither place", bearers: []secretBearer{txn},
		wantOne: "store.Txn carries a secret",
	}, {
		name: "a bearer in the table", bearers: []secretBearer{txn},
		table: map[string]subject{"store.Txn": {}}, wantNone: true,
	}, {
		name: "a bearer with a marker beside it", bearers: []secretBearer{txn},
		markers: []redactionMarker{beside}, wantNone: true,
	}, {
		name: "a marker for a type that carries no secret", markers: []redactionMarker{beside},
		bearers: []secretBearer{{name: "store.Other", dir: "internal/store", file: "x.go"}},
		wantOne: "the marker is stale",
	}, {
		name: "a marker in another package", bearers: []secretBearer{txn},
		markers: []redactionMarker{{name: "store.Txn", dir: "internal/logging",
			file: "internal/logging/logging_test.go", line: 9}},
		wantOne: "must live beside the type it covers",
	}, {
		name: "a table entry covering nothing", bearers: []secretBearer{txn},
		table:   map[string]subject{"store.Txn": {}, "store.Gone": {}},
		wantOne: "store.Gone, which carries no secret",
	}, {
		name: "one qualified name, two packages",
		bearers: []secretBearer{
			{name: "main.Creds", dir: "cmd/brollyguard", file: "cmd/brollyguard/main.go"},
			{name: "main.Creds", dir: "cmd/brollyzapper", file: "cmd/brollyzapper/main.go"},
		},
		table:   map[string]subject{"main.Creds": {}},
		wantOne: "cannot tell them apart",
	}} {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(checkRedactionCoverage(c.bearers, c.markers, c.table), "\n")
			switch {
			case c.wantNone && got != "":
				t.Errorf("the rule reported a problem where there is none:\n%s", got)
			case !c.wantNone && !strings.Contains(got, c.wantOne):
				t.Errorf("the rule did not report %q; it said:\n%s", c.wantOne, got)
			}
		})
	}

	// Placement: a marker only claims coverage from a test function's doc comment.
	for _, c := range []struct{ name, rel, src, want string }{{
		name: "in a test's doc comment", rel: "internal/store/txn_redaction_test.go",
		src: "package store_test\n\n//redaction:covers store.Txn\nfunc TestATxn(t *testing.T) {}\n",
	}, {
		name: "in a function body", rel: "internal/store/txn_redaction_test.go",
		src:  "package store_test\n\nfunc TestATxn(t *testing.T) {\n\t//redaction:covers store.Txn\n}\n",
		want: "outside the doc comment",
	}, {
		name: "on a function that is not a test", rel: "internal/store/txn_redaction_test.go",
		src:  "package store_test\n\n//redaction:covers store.Txn\nfunc helper() {}\n",
		want: "outside the doc comment",
	}, {
		name: "in a file that is not a test", rel: "internal/store/invoices.go",
		src:  "package store\n\n//redaction:covers store.Txn\nfunc Thing() {}\n",
		want: "outside the doc comment",
	}, {
		name: "mentioned in prose rather than claimed", rel: "internal/store/txn_redaction_test.go",
		src: "package store_test\n\n// A test carries a //redaction:covers marker.\n" +
			"func TestATxn(t *testing.T) {}\n",
	}} {
		t.Run(c.name, func(t *testing.T) {
			markers, misplaced := redactionMarkers(t, []moduleFile{planted("internal/store", c.rel, c.src)})
			got := strings.Join(misplaced, "\n")
			switch {
			case c.want == "" && got != "":
				t.Errorf("reported a misplaced marker where there is none:\n%s", got)
			case c.want != "" && !strings.Contains(got, c.want):
				t.Errorf("did not report %q; it said %q", c.want, got)
			case c.want == "" && c.name == "in a test's doc comment" && len(markers) != 1:
				t.Errorf("the marker was not collected: %v", markers)
			case c.want == "" && c.name != "in a test's doc comment" && len(markers) != 0:
				t.Errorf("prose mentioning the marker was collected as a claim: %v", markers)
			}
		})
	}
}

// planted synthesises a file for the scanners, in the shape moduleGoFiles yields.
// Nothing reads it from disk — the parsers take the source directly — so the path
// need only be distinctive.
func planted(dir, rel, src string) moduleFile {
	return moduleFile{rel: rel, dir: dir, path: rel, src: []byte(src)}
}
