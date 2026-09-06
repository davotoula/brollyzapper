package logging_test

import (
	"fmt"
	"go/ast"
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
	found, _, _ := secretBearingTypes(t, []moduleFile{planted("internal/web", "internal/web/web.go", bearers)})
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
	primitive, _, _ := secretBearingTypes(t, []moduleFile{planted("internal/secret",
		"internal/secret/secret.go", "package secret\n\ntype String struct {\n\tv string\n}\n")})
	if len(primitive) != 1 || primitive[0].name != "secret.String" {
		t.Errorf("the walk did not find secret.String itself: %v", primitive)
	}

	// A test file is not source: a fixture in a _test.go is not a bearer.
	if in, _, _ := secretBearingTypes(t, []moduleFile{planted("internal/web",
		"internal/web/web_test.go", bearers)}); len(in) != 0 {
		t.Errorf("the walk read a _test.go file and found %v; test fixtures are not the "+
			"module's types", in)
	}

	// Spellings that left BOTH this rule and internal/arch green with no LogValue
	// anywhere, plus two controls that must NOT be read as bearers. Every one is an
	// ordinary thing to write.
	//
	// DELIBERATELY NOT COUNTED HERE. The enumeration is split three ways — the
	// pointer and the slice are in the fixture above, the alias and the
	// redefinition in the loop below, the rest here — so a number in this comment
	// is a fourth statement of a list and goes stale on any edit to any of them. It
	// already had: the header said "four" while the loop held three of them. The
	// authoritative list is the first bullet on secretBearingTypes.
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
		// Ported from internal/arch, where the go-review pass on 0vk.46 planted it
		// and watched a secret-bearing struct with no LogValue pass clean. The
		// parens are not a container; they are spelling, and gofmt keeps them.
		name: "a parenthesised type, which is spelling and not a container",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Pairing struct {\n\tToken (secret.String)\n}\n",
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
	}, {
		// THE GENERIC FIELD, which until 0vk.49 had no plant in either copy: the
		// module has no generic-typed struct field, so deleting the
		// IndexExpr/IndexListExpr case was invisible to the entire gate. Excluded
		// rather than unwrapped because `type Box[T any] struct{ n int }` never
		// stores its T — see isSecretString. With the collector asserted above,
		// this row now fails if that case is removed.
		name: "a generic field is a boundary, not a bearer",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Box[T any] struct{ n int }\n\n" +
			"type Pairing struct {\n\tOne Box[secret.String]\n}\n",
		want: "",
	}, {
		// THE BOUNDARY THE PAREN CASE MUST NOT CROSS. Parens unwrap SPELLING, and
		// the shapes deliberately excluded stay excluded when they are wrapped in
		// them — a parenthesised channel is still a channel. Kept because the
		// go-review pass had to establish it by hand, and a property established by
		// hand is one nobody can re-establish after a refactor.
		name: "a parenthesised chan is still a chan",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Pairing struct {\n\tToken (chan secret.String)\n}\n",
		want: "",
	}, {
		name: "a parenthesised func is still a func",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Pairing struct {\n\tToken (func() secret.String)\n}\n",
		want: "",
	}, {
		// THE ANONYMOUS NESTED STRUCT (0vk.48), reported against its CONTAINER.
		// The inner struct has no TypeSpec, so the walk never visits it and it has
		// no name to report; Pairing is the type that needs the LogValue.
		name: "an anonymous nested struct, reported against its container",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Pairing struct {\n\tName  string\n\tInner struct{ Token secret.String }\n}\n",
		want: "store.Pairing",
	}, {
		// Two levels, because RECURSION is the claim: a case that looked one field
		// deep would satisfy the plant above and miss this one.
		name: "an anonymous nested struct two levels down",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Pairing struct {\n\tInner struct {\n\t\tDeeper struct{ Token secret.String }\n\t}\n}\n",
		want: "store.Pairing",
	}, {
		// THE CONTROL, and the reason the case is not merely symmetry with the
		// containers: a nested struct holding no secret must not make its container
		// a bearer. `case *ast.StructType: return true` would pass both plants above
		// and fail this one.
		name: "an anonymous nested struct holding no secret is not one",
		src:  "package store\n\ntype Pairing struct {\n\tInner struct{ Count int }\n}\n",
		want: "",
	}, {
		// An INTERFACE field is excluded on a different reason from chan and func —
		// it renders its dynamic value, not an address — and is planted so that
		// reason is tested rather than merely written. See isSecretString.
		name: "an interface field is not a bearer",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Pairing struct {\n\tAny any\n\tRdr interface{ Read() secret.String }\n}\n",
		want: "",
	}, {
		// THE BOUNDARY COMPOSES THROUGH THE NESTING. A nested struct whose only
		// secret sits behind a channel is still not a bearer, for the same reason a
		// parenthesised chan is still a chan — otherwise the nested case would have
		// quietly widened the chan exclusion.
		name: "a nested struct holding only a chan is still not a bearer",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Pairing struct {\n\tInner struct{ C chan secret.String }\n}\n",
		want: "",
	}, {
		// And the containers compose with it in the other direction: a nested
		// struct reached through a pointer, a slice or a map value is still reached.
		name: "a nested struct behind a pointer, a slice and a map value",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Pairing struct {\n\tOne   *struct{ Token secret.String }\n" +
			"\tMany  []struct{ Token secret.String }\n" +
			"\tKeyed map[string]struct{ Token secret.String }\n}\n",
		want: "store.Pairing",
	}, {
		// And it composes with the containers rather than shadowing them: parens
		// around a pointer, and parens around parens, are both still the secret.
		name: "a parenthesised pointer, and parens around parens",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Pairing struct {\n\tOne (*secret.String)\n\tTwo ((secret.String))\n}\n",
		want: "store.Pairing",
	}} {
		t.Run(c.name, func(t *testing.T) {
			got, _, unrecognised := secretBearingTypes(t, []moduleFile{planted("internal/store",
				"internal/store/nwc.go", c.src)})
			names := make([]string, len(got))
			for i, b := range got {
				names[i] = b.name
			}
			if strings.Join(names, ",") != c.want {
				t.Errorf("the walk found %v, want %q", names, c.want)
			}
			// EVERY ROW ASSERTS THIS, and it is what makes the exclusion cases
			// guarded at all. Discarding the third value was measured on 6 Sep to
			// leave chan, func and interface deletable from isSecretString with
			// this whole test still green: a collected-but-dropped node looks
			// exactly like a field that is not a bearer. The rows below that
			// expect `want: ""` are the exclusions, so a deleted case turns them
			// red here rather than relying on the module happening to contain a
			// field of that shape.
			if len(unrecognised) != 0 {
				t.Errorf("the walk did not recognise a node it is supposed to have a case "+
					"for; an exclusion has probably been deleted from isSecretString:\n%s",
					strings.Join(unrecognised, "\n"))
			}
		})
	}

	// A second name for secret.String is refused rather than followed. See
	// namesASecret for why forbidding beats resolving.
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
		// A NAMED CONTAINER OF AN ANONYMOUS STRUCT IS NOT A SECOND NAME. 0vk.48
		// taught isSecretString to see into an anonymous struct, and namesASecret
		// reuses it, so without containsAnonymousStruct these three reported "gives
		// secret.String a second name" — false about a named slice or map type,
		// which drops nothing and names nothing. Measured against main, which
		// reported nothing for all three; a wrong diagnostic is worse than the gap.
		name: "a named slice of an anonymous struct is not a second name",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type T []struct{ Token secret.String }\n",
		want: "",
	}, {
		name: "a named map keyed by an anonymous struct is not a second name",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type T map[struct{ Token secret.String }]bool\n",
		want: "",
	}, {
		name: "a named map valued by an anonymous struct is not a second name",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type T map[string]struct{ Token secret.String }\n",
		want: "",
	}, {
		// AND THE SHAPES THAT MUST KEEP REPORTING, so the narrowing above did not
		// quietly turn the rule off. A named CONTAINER of secrets is reported, and
		// since 0vk.50 with a message that is true of one: T is not a second name,
		// and its elements keep every redaction they had.
		name: "a named slice of secret.String is a container, not a second name",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type T []secret.String\n",
		want: "T is a named container of secret.String",
	}, {
		// The pointer form, which reported the same wrong thing and is the same
		// answer. Added by 0vk.50; before it, both said "another name for
		// secret.String … also drops LogValue, String, GoString and MarshalJSON",
		// every clause of which is false of a named pointer type.
		name: "a named pointer to secret.String is a container too",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type T *secret.String\n",
		want: "T is a named container of secret.String",
	}, {
		// And the identity shapes are UNCHANGED, which is the half a rewording can
		// break silently: an alias and a redefinition really are second names.
		name: "an alias is still a second name",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type T = secret.String\n",
		want: "declares T as another name for secret.String",
	}, {
		name: "a redefinition is still a second name",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type T secret.String\n",
		want: "declares T as another name for secret.String",
	}, {
		// Parenthesised identity is identity: the parens are spelling, as
		// isSecretString has said since g5n.
		name: "a parenthesised alias is still a second name",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type T = (secret.String)\n",
		want: "declares T as another name for secret.String",
	}, {
		name: "a struct is not an alias",
		src: "package store\n\nimport \"github.com/davotoula/brollyzapper/internal/secret\"\n\n" +
			"type Token struct {\n\tv secret.String\n}\n",
		want: "",
	}} {
		t.Run(c.name, func(t *testing.T) {
			_, aliases, unrecognised := secretBearingTypes(t, []moduleFile{planted("internal/store",
				"internal/store/nwc.go", c.src)})
			if len(unrecognised) != 0 {
				t.Errorf("the walk did not recognise a node it has a case for:\n%s",
					strings.Join(unrecognised, "\n"))
			}
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

// The fail-closed default, pinned (0vk.49).
//
// AN UNRECOGNISED NODE CANNOT BE WRITTEN IN REAL SOURCE — that is the whole point
// of the rule, and it is what makes this plant awkward. Every ast.Expr a field
// type can actually be now has a case. So the node is SYNTHESISED rather than
// parsed: handed straight to the predicate, it exercises the same default branch
// that a Go version with a new type-expression node would reach, without pretending
// to be Go anybody can write today.
//
// The other half — that the exclusion cases are what stand between the tree and
// this message — is pinned by the tables in
// TestTheCompletenessRuleDetectsItsOwnViolations, every row of which now asserts
// that the walk recognised everything it was handed. AN EARLIER VERSION OF THIS
// COMMENT CLAIMED THOSE ROWS ALREADY DID THAT AND THEY DID NOT: they discarded
// the collector, so all four exclusions could be deleted from isSecretString with
// the whole plant file green, and the only thing that noticed was the module-wide
// test — which noticed only because the tree happens to contain chan and func
// fields today. Source coincidence is not a plant. Measured, and fixed, 6 Sep.
func TestAnUnrecognisedNodeIsReportedAndNotDiagnosed(t *testing.T) {
	names := map[string]bool{"secret": true}

	for _, node := range []ast.Expr{&ast.BadExpr{}, &ast.Ellipsis{}} {
		t.Run(fmt.Sprintf("%T", node), func(t *testing.T) {
			unknown := &unknownNodes{}
			if isSecretString(node, names, unknown) {
				t.Error("an unrecognised node was answered TRUE. That is the `default: return " +
					"true` the bead's design constraint rules out: it reports the field as " +
					"holding a secret, which is a confident wrong diagnosis")
			}
			if len(unknown.nodes) != 1 {
				t.Fatalf("the node was not collected (%d collected); it was answered `not a "+
					"secret` silently, which is the fail-OPEN behaviour this bead removed",
					len(unknown.nodes))
			}

			// The message is the other half of the constraint: it must ask for a
			// decision, and must not allege a leak.
			msg := unrecognisedNode("internal/store/nwc.go", 42, unknown.nodes[0])
			for _, want := range []string{"unrecognised type expression", fmt.Sprintf("%T", node),
				"internal/store/nwc.go:42", "NOT a report of a leak"} {
				if !strings.Contains(msg, want) {
					t.Errorf("the message does not contain %q:\n%s", want, msg)
				}
			}
			for _, never := range []string{"holds a secret.String", "carries a secret but",
				"second name"} {
				if strings.Contains(msg, never) {
					t.Errorf("the message says %q, which is a diagnosis this rule cannot "+
						"honestly make about a node kind it does not know:\n%s", never, msg)
				}
			}
		})
	}

	// Criterion 3: an unrecognised node in a TypeSpec is NEITHER a second name for
	// secret.String NOR a container of one. It falls out of the answers rather
	// than needing a guard, and it is planted because the day someone changes
	// those answers is the day namesASecret starts making a claim about a node
	// kind nobody has ever seen — and since 0vk.50 there are two claims it could
	// make, so both are pinned.
	unknown := &unknownNodes{}
	ts := &ast.TypeSpec{Name: ast.NewIdent("T"), Type: &ast.BadExpr{}}
	if got := namesASecret(ts, names, unknown); got != namesNoSecret {
		t.Errorf("an unrecognised node was classified %v; it is neither a second name for "+
			"secret.String nor a container of one", got)
	}
	if len(unknown.nodes) != 1 {
		t.Errorf("namesASecret dropped the collector, so a new node kind first met in a "+
			"TypeSpec would go unreported (%d collected)", len(unknown.nodes))
	}
}
