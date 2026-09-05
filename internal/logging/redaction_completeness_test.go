package logging_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
// itself badly and nothing rendered it. Measured on 2026-09-05: with
// `session_secret` added to api.Auth.LogValue in plain text and this bead's
// api.Auth test taken out of the tree, `go test ./...` was green everywhere
// except this rule. Both arch rules passed.
//
// This is the same shape as TestEveryDeclaredEventIsInTheVocabulary further up
// logging_test.go, and for the same reason: the table is a second statement of a
// list the source already contains, and a second statement can be incomplete in
// the same way twice. So the list is read out of the source rather than restated.
//
// THE TREE HAS TWO CONVENTIONS AND BOTH STAY ALLOWED. A type is covered by an
// entry in the redaction table, or by a rendered-record test beside the type
// carrying a //redaction:covers marker. store.Txn, lnd.PaymentResult and api.Auth
// take the second, and it is not the worse answer: the test lives next to the
// LogValue it constrains, so the person editing the method is the person who sees
// it fail, and an INTERNAL test there can read back a secret that has no
// accessor, which this package's external test cannot. config.Server has both —
// its table entry is what satisfies this rule, and its marker records that the
// per-type test beside it (0vk.33) is a real second home rather than a duplicate
// to be deleted.
func TestEverySecretBearingTypeIsCoveredByOneOfTheTwoConventions(t *testing.T) {
	files := moduleGoFiles(t)
	bearers, aliases := secretBearingTypes(t, files)
	if len(bearers) == 0 {
		t.Fatal("found no secret-bearing types in the module; this rule is reading the wrong thing")
	}
	for _, p := range aliases {
		t.Error(p)
	}
	markers, misplaced := redactionMarkers(t, files)
	for _, p := range misplaced {
		t.Error(p)
	}
	for _, p := range checkRedactionCoverage(bearers, markers, redactionSubjects(t)) {
		t.Error(p)
	}
}

// checkRedactionCoverage is the rule itself, separated from the walk so it can be
// handed planted inputs.
//
// SEPARATED FOR EXACTLY THAT REASON. internal/arch splits every rule into a
// scanner and a Test wrapper that runs it twice — clean over the real tree, then
// over a planted violation — because a rule that has only ever passed has been
// written, not tested, and this tree has caught itself three times. The first
// version of this file had no such seam: its plants were run by hand, left no
// trace, and could not be re-run after a refactor.
func checkRedactionCoverage(bearers []secretBearer, markers []redactionMarker,
	table map[string]subject) []string {
	var found []string
	byName := map[string]secretBearer{}
	for _, b := range bearers {
		// Two packages may share a name — this tree has five called `main` — and
		// the table and the markers spell a type as `pkg.Type`, which cannot tell
		// them apart. Deduplicating quietly would drop one of the two and report
		// the survivor as covered. Reported instead, because the fix is a decision
		// (a rename, or a qualifier scheme) and not something a rule should take.
		if prior, ok := byName[b.name]; ok {
			found = append(found, fmt.Sprintf("%s is declared in both %s and %s; the "+
				"redaction table spells types as pkg.Type and cannot tell them apart, so "+
				"one of the two would be reported as covered by the other's entry",
				b.name, prior.file, b.file))
			continue
		}
		byName[b.name] = b
	}

	for _, b := range bearers {
		if _, ok := table[b.name]; ok {
			continue
		}
		// Same directory as the type, deliberately: "beside the type" is the whole
		// claim the second convention makes, and a marker in some other package
		// would be making a claim it cannot keep. Directory and not file, which is
		// the line internal/arch already drew on the neighbouring rule: requiring
		// the same file would fail a type whose LogValue moves to a methods.go.
		if slices.ContainsFunc(markers, func(m redactionMarker) bool {
			return m.name == b.name && m.dir == b.dir
		}) {
			continue
		}
		found = append(found, fmt.Sprintf("%s carries a secret (%s:%d) but nothing renders "+
			"it: it is not in the redaction table in logging_test.go, and no test in %s "+
			"carries `%s%s`. Add one or the other — §12 wants what the LogValue emits "+
			"asserted, not only that it exists",
			b.name, b.file, b.line, b.dir, markerPrefix, b.name))
	}

	// A marker naming a type that is not secret-bearing is stale: the type was
	// renamed, deleted, or stopped carrying a secret, and the test beside it is now
	// guarding nothing while still reporting coverage.
	for _, m := range markers {
		b, ok := byName[m.name]
		switch {
		case !ok:
			found = append(found, fmt.Sprintf("%s:%d claims to cover %s, but no type of "+
				"that name carries a secret; the marker is stale", m.file, m.line, m.name))
		case b.dir != m.dir:
			found = append(found, fmt.Sprintf("%s:%d claims to cover %s, but that type is "+
				"declared in %s; a rendered-record test must live beside the type it covers",
				m.file, m.line, m.name, b.dir))
		}
	}

	// The mirror of the walk: an entry for a type that no longer carries a secret
	// is dead weight, and it reads as coverage.
	for name := range table {
		if _, ok := byName[name]; !ok {
			found = append(found, fmt.Sprintf("the redaction table has an entry for %s, "+
				"which carries no secret; it is covering nothing", name))
		}
	}
	slices.Sort(found)
	return found
}

// secretBearer is one type the module declares that carries a secret.
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

// secretBearingTypes reads every type carrying a secret out of the module's
// non-test source: secret.String itself, and every struct with a field of that
// type.
//
// WHERE IT AGREES WITH internal/arch's checkSecretBearingStructsRedact, and where
// it does not. Both walk the module's non-test source for `secret.String` fields,
// and neither is transitive — a struct holding a store.NWCConnection is not a
// bearer to either. Three deliberate differences, listed because two rules that
// believe they agree while quietly not agreeing is how the next blind spot gets
// made:
//
//   - NO SKIP LIST. checkSecretBearingStructsRedact skips internal/secret (its
//     sibling checkSecretBearingFields skips internal/lnd/lnrpc and lndtest as
//     well). A directory a rule refuses to look in is a place a type can sit
//     unrendered, and internal/secret is where secret.String itself lives.
//
//   - ast.Inspect, not top-level declarations. arch reads file.Decls, so a struct
//     declared INSIDE a function is invisible to it. A local struct holding a
//     secret is exactly as loggable as a package-level one. The remedy if this
//     fires on one is to hoist the type, not to narrow the walk.
//
//   - HOW THE FIELD IS SPELLED does not matter. arch compares the field's
//     rendered type against the literal string "secret.String", so four ordinary
//     spellings evade it — and evade its LogValue requirement too, which is the
//     more serious half. All four were planted on 2026-09-05 and left BOTH rules
//     green with no LogValue anywhere:
//
//     Token map[string]secret.String   arch's typeString renders no map
//     Token sec.String                 `import sec ".../internal/secret"`
//     Token String                     `import . ".../internal/secret"`
//     type Token = secret.String       an alias, then a Token field
//
//     So this walk resolves the import rather than assuming the identifier
//     `secret` (secretNames), unwraps pointers, slices, arrays and maps
//     (holdsASecret), and refuses aliases and redefinitions outright rather than
//     chasing them through the package (aliasesASecret) — a rule can forbid a
//     shape more cheaply and more reliably than it can resolve one.
//
//     internal/arch still has all four holes; this rule does not close them
//     there, and BrollyZap-0vk.46 tracks that.
func secretBearingTypes(t *testing.T, files []moduleFile) ([]secretBearer, []string) {
	t.Helper()
	var found []secretBearer
	var aliases []string
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f.rel, "_test.go") {
			continue
		}
		// SkipObjectResolution: neither this walk nor redactionMarkers reads
		// *ast.Object or File.Unresolved, and resolving costs about a third of
		// each pass over a tree this size.
		file, err := parser.ParseFile(fset, f.path, f.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", f.rel, err)
		}
		names := secretNames(file)
		ast.Inspect(file, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			at := fset.Position(ts.Pos())
			if aliasesASecret(ts, names) {
				aliases = append(aliases, fmt.Sprintf("%s:%d declares %s as another name for "+
					"secret.String. Spell the type out: this rule and internal/arch both match "+
					"the field's SOURCE, so a field typed %s is invisible to the requirement "+
					"that its struct redact itself and to the requirement that something "+
					"render it", f.rel, at.Line, ts.Name.Name, ts.Name.Name))
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			// secret.String is the thing every other bearer holds, and the table's
			// first entry. The field scan cannot find it — its own field is a plain
			// string — so it is matched by name HERE rather than seeded into the
			// results, which would have put a made-up file and line in the failure
			// message. Measured: it said secret.go:0.
			name := file.Name.Name + "." + ts.Name.Name
			if name != "secret.String" && !holdsASecret(st, names) {
				return true
			}
			found = append(found, secretBearer{
				name: name,
				dir:  f.dir,
				file: f.rel,
				line: at.Line,
			})
			return true
		})
	}
	slices.SortFunc(found, func(a, b secretBearer) int { return strings.Compare(a.name, b.name) })
	return found, aliases
}

// secretNames returns the identifiers that mean secret.String in this file: the
// name internal/secret is imported under, "." when it is dot-imported, and the
// bare "String" inside package secret itself.
//
// RESOLVED AND NOT ASSUMED. internal/arch matches the rendered type against the
// literal "secret.String", so `import sec ".../internal/secret"` defeats it. That
// nothing in the tree does this today is not a guarantee — it is one line-length
// decision away, and the failure is silent in both directions.
func secretNames(file *ast.File) map[string]bool {
	names := map[string]bool{}
	if file.Name.Name == "secret" {
		names["."] = true // a bare String, inside the package that declares it
	}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || !strings.HasSuffix(path, "/internal/secret") {
			continue
		}
		switch {
		case spec.Name == nil:
			names["secret"] = true
		case spec.Name.Name == "_":
			// Imported for side effects; nothing in this file names the type.
		default:
			names[spec.Name.Name] = true // an alias, or "." for a dot-import
		}
	}
	return names
}

// aliasesASecret reports whether ts gives secret.String a second name, by alias
// (`type T = secret.String`) or by redefinition (`type T secret.String`).
//
// FORBIDDEN RATHER THAN RESOLVED. Following the second name to the fields typed
// with it means resolving types across a package, which is go/types and a much
// larger rule. Refusing the shape costs four lines and cannot be got wrong.
// Redefinition is included because it is the worse of the two: a defined type
// over secret.String does NOT inherit String, GoString, LogValue or MarshalJSON,
// so it is a secret that has lost every one of its redactions.
func aliasesASecret(ts *ast.TypeSpec, names map[string]bool) bool {
	if _, isStruct := ts.Type.(*ast.StructType); isStruct {
		return false
	}
	return isSecretString(ts.Type, names)
}

// holdsASecret reports whether any of st's fields is a secret.String, however it
// is spelled and however it is wrapped. See the third bullet on
// secretBearingTypes for the four spellings that used to get through.
func holdsASecret(st *ast.StructType, names map[string]bool) bool {
	return slices.ContainsFunc(st.Fields.List, func(field *ast.Field) bool {
		return isSecretString(field.Type, names)
	})
}

// isSecretString reports whether expr denotes a secret.String, through any number
// of pointers, slices, arrays and maps. Map KEYS are unwrapped as well as values:
// a secret is no less exposed for being on the left of the colon, and the cost of
// checking is one recursive call.
func isSecretString(expr ast.Expr, names map[string]bool) bool {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return isSecretString(t.X, names)
	case *ast.ArrayType:
		return isSecretString(t.Elt, names)
	case *ast.MapType:
		return isSecretString(t.Key, names) || isSecretString(t.Value, names)
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		return ok && names[pkg.Name] && t.Sel.Name == "String"
	case *ast.Ident:
		// A bare String: either the package was dot-imported, or this file IS
		// package secret.
		return names["."] && t.Name == "String"
	default:
		return false
	}
}

// redactionMarkers reads every per-type coverage claim out of the module's
// source, and returns alongside it the claims that are in no position to be one.
//
// A marker is only a claim if something runs it, so it must sit in the doc
// comment of a `func Test...` in a _test.go file. Anywhere else — a function
// body, a floating comment, a non-test file — it reads as coverage and is not.
// Those are reported rather than ignored, WITH THE FILE AND LINE: the first
// version counted marker lines in the raw bytes and compared totals, which meant
// a second walk of the module, a "must start its line" workaround so the rule did
// not fire on its own source, and a failure message that sent the reader hunting
// for which of five markers was the wrong one.
func redactionMarkers(t *testing.T, files []moduleFile) ([]redactionMarker, []string) {
	t.Helper()
	var found []redactionMarker
	var misplaced []string
	fset := token.NewFileSet()
	for _, f := range files {
		file, err := parser.ParseFile(fset, f.path, f.src, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", f.rel, err)
		}
		// The doc comments of this file's test functions, as position ranges. A
		// marker comment inside one of them is attached to something that runs.
		type span struct{ from, to token.Pos }
		var docs []span
		if strings.HasSuffix(f.rel, "_test.go") {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if ok && fn.Doc != nil && strings.HasPrefix(fn.Name.Name, "Test") {
					docs = append(docs, span{fn.Doc.Pos(), fn.Doc.End()})
				}
			}
		}
		for _, group := range file.Comments {
			for _, c := range group.List {
				name, ok := strings.CutPrefix(c.Text, markerPrefix)
				if !ok {
					continue
				}
				at := fset.Position(c.Pos())
				if !slices.ContainsFunc(docs, func(s span) bool {
					return c.Pos() >= s.from && c.Pos() < s.to
				}) {
					misplaced = append(misplaced, fmt.Sprintf("%s:%d has a %q marker outside "+
						"the doc comment of a test function, where it claims coverage nothing "+
						"runs", f.rel, at.Line, strings.TrimSuffix(markerPrefix, " ")))
					continue
				}
				found = append(found, redactionMarker{
					name: strings.TrimSpace(name),
					dir:  f.dir,
					file: f.rel,
					line: at.Line,
				})
			}
		}
	}
	return found, misplaced
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
