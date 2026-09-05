package logging_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// The redaction table is hand-kept, and nothing used to check it covered every
// secret-bearing type (BrollyZap-0vk.36).
//
// The arch rule TestEverySecretBearingStructRedactsItself fires on a type that
// holds a secret.String and declares NO LogValue. It never fires on a type that
// declares one and is simply absent from the table — so a type could redact
// itself badly and nothing rendered it. nwc.PayResult and api.Auth were both in
// that blind spot, and the table's own comment named this bead as its exit.
//
// This is the same shape as TestEveryDeclaredEventIsInTheVocabulary further up
// logging_test.go, and for the same reason: the table is a second statement of a
// list the source already contains, and a second statement can be incomplete in
// the same way twice. So the list is read out of the source rather than restated.
//
// THE TREE HAS TWO CONVENTIONS AND BOTH STAY ALLOWED. A type is covered by an
// entry in the redaction table, or by a rendered-record test beside the type —
// store.Txn, lnd.PaymentResult, config.Server and api.Auth take the second, and
// that is not the worse answer: the test lives next to the LogValue it
// constrains, so the person editing the method is the person who sees it fail,
// and an INTERNAL test there can read back a secret that has no accessor, which
// this package's external test cannot.
func TestEverySecretBearingTypeIsCoveredByOneOfTheTwoConventions(t *testing.T) {
	bearers := secretBearingTypes(t)
	if len(bearers) == 0 {
		t.Fatal("found no secret-bearing types in the module; this rule is reading the wrong thing")
	}
	markers := redactionMarkers(t)

	inTable := map[string]bool{}
	for name := range redactionSubjects(t) {
		inTable[name] = true
	}

	byName := map[string]secretBearer{}
	for _, b := range bearers {
		byName[b.name] = b
	}

	for _, b := range bearers {
		if inTable[b.name] {
			continue
		}
		// Same directory as the type, deliberately: "beside the type" is the
		// whole claim the second convention makes, and a marker in some other
		// package would be making a claim it cannot keep.
		if slices.ContainsFunc(markers, func(m redactionMarker) bool {
			return m.name == b.name && m.dir == b.dir
		}) {
			continue
		}
		t.Errorf("%s carries a secret (%s:%d) but nothing renders it: it is not in the "+
			"redaction table in logging_test.go, and no test in %s carries "+
			"`//redaction:covers %s`. Add one or the other — §12 wants what the LogValue "+
			"emits asserted, not only that it exists",
			b.name, b.file, b.line, b.dir, b.name)
	}

	// A marker naming a type that is not secret-bearing is stale: the type was
	// renamed, deleted, or stopped holding a secret, and the test beside it is
	// now guarding nothing while still reporting coverage.
	for _, m := range markers {
		b, ok := byName[m.name]
		switch {
		case !ok:
			t.Errorf("%s:%d claims to cover %s, but no type of that name carries a "+
				"secret; the marker is stale", m.file, m.line, m.name)
		case b.dir != m.dir:
			t.Errorf("%s:%d claims to cover %s, but that type is declared in %s; a "+
				"rendered-record test must live beside the type it covers",
				m.file, m.line, m.name, b.dir)
		}
	}

	// The mirror of the walk: an entry for a type that no longer holds a secret
	// is dead weight, and it reads as coverage.
	for name := range inTable {
		if _, ok := byName[name]; !ok {
			t.Errorf("the redaction table has an entry for %s, which carries no secret; "+
				"it is covering nothing", name)
		}
	}
}

// secretBearer is one type the module declares that holds a secret.
type secretBearer struct {
	name string // package-qualified, as the table and the markers spell it
	dir  string // module-relative directory of the declaration
	file string
	line int
}

// redactionMarker is one `//redaction:covers <pkg>.<Type>` claim.
type redactionMarker struct {
	name string
	dir  string
	file string
	line int
}

// markerPrefix is the directive a per-type rendered-record test carries.
//
// A MARKER AND NOT A NAMING CONVENTION. A convention like "a test whose name
// contains the type name" is already satisfied, in internal/store, by
// TestTxnsHonoursEveryFilter — which puts nothing through a log. The check would
// have reported coverage that does not exist, which is the failure being fixed
// rather than a fix for it. A marker is a deliberate claim, and it is checkable
// in both directions: it must name a type that really carries a secret, and it
// must sit beside that type.
//
// A registry the per-type tests call at runtime was considered and cannot work:
// `go test ./...` runs each package in its own process, so nothing internal/store
// registers is visible to a test in internal/logging.
//
// A filename list was the one answer ruled out in advance, being the same
// hand-kept second statement this rule exists to remove.
const markerPrefix = "//redaction:covers "

// secretBearingTypes reads every struct with a secret.String field out of the
// module's non-test source.
//
// NO SKIP LIST, unlike the arch rule this mirrors: a directory a rule refuses to
// look in is a place a secret-bearing type can sit unrendered.
//
// NOT TRANSITIVE, which is the same line internal/arch draws: a struct holding a
// store.NWCConnection is not reported here. Drawing it elsewhere would mean this
// rule and the arch rule disagreed about what a secret-bearing type is, and the
// table would have to answer to two definitions.
//
// It is stricter than the arch rule in one respect, deliberately: it walks with
// ast.Inspect rather than over top-level declarations, so a struct declared
// INSIDE a function is seen too. The arch rule misses those, and a local struct
// holding a secret is exactly as loggable as a package-level one. The remedy if
// this ever fires on one is to hoist the type, not to narrow the walk.
func secretBearingTypes(t *testing.T) []secretBearer {
	t.Helper()
	var found []secretBearer
	fset := token.NewFileSet()
	for _, f := range moduleGoFiles(t) {
		if strings.HasSuffix(f.rel, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f.path, f.src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", f.rel, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			bearer := secretBearer{
				name: file.Name.Name + "." + ts.Name.Name,
				dir:  f.dir,
				file: f.rel,
				line: fset.Position(ts.Pos()).Line,
			}
			// secret.String is the thing every other bearer holds, and the
			// table's first entry. The field walk below cannot find it — its own
			// field is a plain string — so it is matched by name, HERE rather
			// than seeded by hand above, which would have put a made-up file and
			// line in the failure message. Measured: it said secret.go:0.
			if bearer.name == "secret.String" {
				found = append(found, bearer)
				return true
			}
			for _, field := range st.Fields.List {
				sel, ok := field.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "String" {
					continue
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "secret" {
					continue
				}
				found = append(found, bearer)
				return true
			}
			return true
		})
	}
	slices.SortFunc(found, func(a, b secretBearer) int { return strings.Compare(a.name, b.name) })
	// Two packages may share a name — this tree has five called `main` — and the
	// table and the markers spell a type as `pkg.Type`, which cannot tell them
	// apart. Deduplicating quietly would drop one of the two and report the
	// survivor as covered. Reported instead, because the fix is a decision (a
	// rename, or a qualifier scheme) and not something a rule should take.
	for i := 1; i < len(found); i++ {
		if found[i].name == found[i-1].name {
			t.Errorf("%s is declared in both %s and %s; the redaction table spells types as "+
				"pkg.Type and cannot tell them apart, so one of the two would be reported as "+
				"covered by the other's entry", found[i].name, found[i-1].file, found[i].file)
		}
	}
	return found
}

// redactionMarkers reads every per-type coverage claim out of the module's test
// source. The marker must be in the doc comment of a `func Test...`, so it is
// attached to something that runs.
func redactionMarkers(t *testing.T) []redactionMarker {
	t.Helper()
	var found []redactionMarker
	fset := token.NewFileSet()
	for _, f := range moduleGoFiles(t) {
		if !strings.HasSuffix(f.rel, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f.path, f.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parsing %s: %v", f.rel, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Doc == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			for _, c := range fn.Doc.List {
				name, ok := strings.CutPrefix(c.Text, markerPrefix)
				if !ok {
					continue
				}
				found = append(found, redactionMarker{
					name: strings.TrimSpace(name),
					dir:  f.dir,
					file: f.rel,
					line: fset.Position(c.Pos()).Line,
				})
			}
		}
	}
	// A marker outside a test function's doc comment is a claim nothing runs, and
	// it would report coverage silently. Cheap to catch: count the marker LINES in
	// the bytes and compare with what the AST attached.
	//
	// Line-anchored, not a plain Contains: this rule's own source spells the
	// marker three times — in the const, in a doc comment and inside a failure
	// message — and a substring count made the rule fail on itself. A marker in
	// use starts its line; prose that mentions one does not.
	//
	// A near-miss ("// redaction:covers X", with a space) is invisible to both
	// halves and stays so. It does not go unreported: the type it meant to cover
	// is then uncovered, and the failure above names the directory and the exact
	// text to write.
	var inBytes int
	for _, f := range moduleGoFiles(t) {
		for _, line := range strings.Split(string(f.src), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), markerPrefix) {
				inBytes++
			}
		}
	}
	if inBytes != len(found) {
		t.Errorf("the module has %d %q lines but only %d sit in the doc comment of a "+
			"test function; a marker anywhere else claims coverage nothing runs",
			inBytes, strings.TrimSuffix(markerPrefix, " "), len(found))
	}
	return found
}

type moduleFile struct {
	rel, dir, path string
	src            []byte
}

// neverWalked are directories with no source of ours in them.
var neverWalked = []string{".git", ".beads", "vendor", "testdata", "node_modules"}

var moduleGoFilesOnce = sync.OnceValues(readModuleGoFiles)

// moduleGoFiles returns every Go file in the module, tests included.
func moduleGoFiles(t *testing.T) []moduleFile {
	t.Helper()
	files, err := moduleGoFilesOnce()
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
	return files
}

func readModuleGoFiles() ([]moduleFile, error) {
	root, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			return nil, fmt.Errorf("no go.mod found above the test's working directory")
		}
		root = parent
	}
	var out []moduleFile
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if slices.Contains(neverWalked, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		out = append(out, moduleFile{rel: rel, dir: filepath.ToSlash(filepath.Dir(rel)), path: path, src: src})
		return nil
	})
	return out, err
}
