// Package composelint is the one compose reader the three deployment lints
// share — deploy/, umbrel/ and regtest/ — and it deliberately hands out no text.
//
// WHY A READER AND NOT A STRING. Every defect the 20i epic closed in those lints
// was a raw-text scan standing beside a struct the test had already parsed:
// 20i.6, 20i.12, 20i.13, 20i.15, 20i.16, 20i.19 and 20i.20, several introduced
// inside the fix for the one before, because each loader returned `(struct,
// raw)` and the string was in scope. A comment satisfied a Contains; a `#` inside
// a quoted value hid a name; a folded scalar split a variable across two lines
// no line scan could rejoin. So this package reads the file, keeps the parsed
// yaml.Node document, and answers questions ABOUT it — scalars with their lines,
// interpolations, defaults, a key's comment, what sits between two keys. A caller
// that wants "the file as lines" cannot have it (BrollyZap-20i.18).
//
// IT OWNS NO ASSERTIONS. Each lint keeps its own struct, its own tests and its
// own messages. The three structs differ on purpose — a field a lint does not
// read is the vacuity risk this family hunts — so there is no shared Compose
// type either. The primitives return errors rather than failing the test, so the
// sentence an operator reads when one fails stays in the lint that owns it.
//
// Test support in non-test files, like internal/lnd/lndtest: it takes a
// testing.TB and is imported only by _test.go files.
package composelint

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Document is one parsed compose file. It holds the node tree and the comments,
// and no copy of the text.
type Document struct {
	path     string
	root     *yaml.Node
	comments []Comment
}

// Scalar is one scalar value in the document — keys included — and the line it
// starts on. yaml folds a `\`-continued double-quoted scalar back into one Value,
// which is exactly what a per-line scan cannot do.
type Scalar struct {
	Value string
	Line  int
}

// Anchor is an anchor name and the line of the node carrying it. An anchor name
// is not a scalar Value, so a check that forbids a name has to be shown these as
// well: `environment: &NETWORK_IP_anchor` put a forbidden name in deploy's
// template past a scalar-only scan (brief E).
type Anchor struct {
	Name string
	Line int
}

// Comment is one line of a YAML comment, `#` included, and the line it is on.
type Comment struct {
	Text string
	Line int
}

// Load reads path, decodes it into into (a pointer to the caller's own struct,
// or nil), and keeps the document. Any failure fails the test: a lint that cannot
// read its file has nothing to assert.
func Load(t testing.TB, path string, into any) *Document {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return Parse(t, path, src, into)
}

// Parse is Load for a document the test already holds — a table row's fixture.
// path only labels messages.
func Parse(t testing.TB, path string, src []byte, into any) *Document {
	t.Helper()
	if into != nil {
		if err := yaml.Unmarshal(src, into); err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
	}
	var root yaml.Node
	if err := yaml.Unmarshal(src, &root); err != nil {
		t.Fatalf("parsing %s as a document: %v", path, err)
	}
	return &Document{path: path, root: &root, comments: locateComments(&root, src)}
}

// Path is the file this document was read from.
func (d *Document) Path() string { return d.path }

// Scalars is every scalar in the document, keys included, in document order.
//
// An alias node carries no Content, only a pointer this does not follow, so a
// recursive alias terminates — and nothing is missed, since the anchor's own
// definition is a scalar elsewhere in the same tree.
func (d *Document) Scalars() []Scalar {
	var out []Scalar
	walk(d.root, func(n *yaml.Node) {
		if n.Kind == yaml.ScalarNode {
			out = append(out, Scalar{Value: n.Value, Line: n.Line})
		}
	})
	return out
}

// Anchors is every anchor name in the document. Anchors sit on mappings and
// sequences as readily as on scalars, so every node is asked.
func (d *Document) Anchors() []Anchor {
	var out []Anchor
	walk(d.root, func(n *yaml.Node) {
		if n.Anchor != "" {
			out = append(out, Anchor{Name: n.Anchor, Line: n.Line})
		}
	})
	return out
}

// Comments is every comment line in the document, in file order.
//
// FOR A CHECK WHOSE SUBJECT IS A COMMENT, and only that: deploy's INTERIM-note
// check reads markers that live in prose by design. Everything that asks what a
// file SETS reads Scalars, which no comment can reach.
func (d *Document) Comments() []Comment { return slices.Clone(d.comments) }

func walk(n *yaml.Node, visit func(*yaml.Node)) {
	visit(n)
	for _, child := range n.Content {
		walk(child, visit)
	}
}

// unescapedScalars is every scalar's value with compose's `$$` escape removed.
//
// `$$` IS A LITERAL `$`, never an interpolation, and Go's regexp has no
// lookbehind to say so. Removing the pairs first is exact rather than
// approximate: `$$NAME` becomes `NAME` and matches nothing, while `$$$NAME`
// becomes `$NAME` — which is what compose does with it too, a literal dollar
// followed by a real interpolation. Measured: without this, `$$NOT_REAL_VAR`
// demanded an assignment for a name compose never reads (brief E).
func (d *Document) unescapedScalars() []Scalar {
	scalars := d.Scalars()
	for i := range scalars {
		scalars[i].Value = strings.ReplaceAll(scalars[i].Value, "$$", "")
	}
	return scalars
}

// Interpolation is one variable reference and the scalar it is in.
type Interpolation struct {
	Name   string
	Scalar Scalar
}

// Interpolations is every variable the document reads, in either spelling —
// `${NAME}`, `${NAME:-default}` and bare `$NAME` — with the scalar each is in.
//
// BOTH SPELLINGS, because a brace-only pattern never collected `$LND_DIR`
// (BrollyZap-20i.19), and the Umbrel package writes bare interpolations on its
// most copy-pasted line.
func (d *Document) Interpolations() []Interpolation {
	var out []Interpolation
	for _, scalar := range d.unescapedScalars() {
		for _, m := range interpolationRE.FindAllStringSubmatch(scalar.Value, -1) {
			out = append(out, Interpolation{Name: m[1], Scalar: scalar})
		}
	}
	return out
}

// InterpolatedNames is the set of names Interpolations finds.
func (d *Document) InterpolatedNames() map[string]bool {
	out := map[string]bool{}
	for _, i := range d.Interpolations() {
		out[i.Name] = true
	}
	return out
}

// Defaults is every default the document gives a variable, by name, one entry
// per occurrence — so a template that disagrees with itself is visible to the
// caller rather than resolved here.
//
// `:-` and `-` both count; `:?` and `?` are an error message, never a value.
func (d *Document) Defaults() map[string][]string {
	out := map[string][]string{}
	for _, scalar := range d.unescapedScalars() {
		for _, m := range defaultRE.FindAllStringSubmatch(scalar.Value, -1) {
			out[m[1]] = append(out[m[1]], m[2])
		}
	}
	return out
}

var (
	// ${NAME}, ${NAME:-default} and bare $NAME alike; only the name is captured.
	interpolationRE = regexp.MustCompile(`\$\{?([A-Z_][A-Z0-9_]*)`)
	// ${NAME:-default} and ${NAME-default}: m[1] the name, m[2] the default. A
	// nested ${A:-${B}} is not read correctly — the default stops at the first
	// `}` — and no template here has one; the parser tables say so.
	defaultRE = regexp.MustCompile(`\$\{([A-Z_][A-Z0-9_]*):?-([^}]*)\}`)
)
