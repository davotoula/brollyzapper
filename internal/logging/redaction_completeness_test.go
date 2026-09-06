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
	bearers, aliases, unrecognised := secretBearingTypes(t, files)
	if len(bearers) == 0 {
		t.Fatal("found no secret-bearing types in the module; this rule is reading the wrong thing")
	}
	for _, p := range aliases {
		t.Error(p)
	}
	// Reported on its own, never folded into the alias or the bearer messages: an
	// unrecognised node is a request for a decision and not an allegation of a
	// leak (0vk.49).
	for _, p := range unrecognised {
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
// bearer to either. The list below is kept because two rules that believe they
// agree while quietly not agreeing is how the next blind spot gets made; 0vk.46
// closed the three differences that were holes, and what is left is either
// deliberate or narrower than it was:
//
//   - HOW THE FIELD IS SPELLED no longer separates them. Until 0vk.46,
//     checkSecretBearingStructsRedact compared the field's rendered type against
//     the literal "secret.String", and SIX ordinary spellings evaded it — and
//     evaded its LogValue requirement too, which is the more serious half. All
//     six were planted and left it green with no LogValue anywhere:
//
//     Token sec.String                 `import sec ".../internal/secret"`
//     Token String                     `import . ".../internal/secret"`
//     Token map[string]secret.String   its typeString rendered no map
//     type Token = secret.String       an alias, then a Token field
//     Token *secret.String             rendered "*secret.String"
//     Tokens []secret.String           rendered "[]secret.String"
//
//     0vk.46 ported this walk's predicate over — resolve the import rather than
//     assume the identifier `secret` (secretNames), unwrap pointers, slices,
//     arrays and maps including KEYS (holdsASecret), and refuse aliases and
//     redefinitions outright rather than chase them (aliasesASecret). Both rules
//     now agree on every one of those shapes, and both keep permanent plants for
//     them. A SEVENTH spelling — `Token (secret.String)`, where the parens are
//     not a container but spelling — evaded both, was closed in arch by 0vk.46
//     and here by g5n. An EIGHTH — `Inner struct{ Token secret.String }`, which
//     has no TypeSpec of its own so neither walk ever visited it — evaded both
//     until 0vk.48 closed it in the two copies together.
//
//     AND WITH THAT THE FAMILY IS CLOSED — but NOT for the reason first given.
//     The 6 Sep ruling closed it on a promise to stop looking, which is the
//     weakest kind of closure and would have been broken by the ninth spelling
//     exactly as the eight before it were. 0vk.49 closed it on a MECHANISM
//     instead: isSecretString now enumerates what it excludes and REPORTS a node
//     kind it has never seen, so a ninth spelling announces itself the first time
//     anyone writes it rather than being answered "not a secret" in silence. The
//     exclusions and their reasons are cases on that function; read them there,
//     not here, because a second statement of them is what this bullet is warning
//     about.
//
//     The code is duplicated rather than shared, because this file is
//     `package logging_test` and a test file cannot be imported; if a third rule
//     ever wants the predicate, that is the moment to give it a real home.
//
//   - THE SKIP LIST IS SHORTER. checkSecretBearingStructsRedact skipped
//     internal/secret and no longer does (0vk.46 checked that it protected
//     nothing: the package declares one type whose field is a plain string). Its
//     sibling checkSecretBearingFields still skips internal/lnd/lnrpc and
//     lndtest. A directory a rule refuses to look in is a place a type can sit
//     unrendered, so this walk still has no skip list at all.
//
//   - BOTH NOW SEE LOCAL TYPES, by the same method. arch read file.Decls until
//     0vk.46; it now walks the whole file and subtracts the package-level
//     declarations, so a struct inside a plain function, inside a method, inside
//     a package-level func literal, and a function-local ALIAS are all seen. An
//     earlier version of this branch walked only function BODIES, and review
//     measured that it still missed the last two.
//
//     arch reports such a type with a DIFFERENT message from this one's advice,
//     because the remedy differs: Go does not allow a method on a type declared
//     in a function body, so there the fix is to hoist the type rather than to
//     give it a LogValue.
func secretBearingTypes(t *testing.T, files []moduleFile) (
	bearers []secretBearer, aliases, unrecognised []string) {
	t.Helper()
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
		// One collector per FILE, drained below, so a reported node can be given
		// the filename and line the predicate itself has no way to know.
		unknown := &unknownNodes{}
		ast.Inspect(file, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			at := fset.Position(ts.Pos())
			if aliasesASecret(ts, names, unknown) {
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
			if name != "secret.String" && !holdsASecret(st, names, unknown) {
				return true
			}
			bearers = append(bearers, secretBearer{
				name: name,
				dir:  f.dir,
				file: f.rel,
				line: at.Line,
			})
			return true
		})
		for _, expr := range unknown.nodes {
			unrecognised = append(unrecognised,
				unrecognisedNode(f.rel, fset.Position(expr.Pos()).Line, expr))
		}
	}
	slices.SortFunc(bearers, func(a, b secretBearer) int { return strings.Compare(a.name, b.name) })
	return bearers, aliases, unrecognised
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
// AN UNRECOGNISED NODE IS NOT A SECOND NAME, and that falls out of the bool
// answer rather than needing a guard: isSecretString collects the node and still
// returns false, so `type T <something nobody has taught the switch>` is reported
// as unrecognised by the walk and never as an alias. The collector is threaded
// through rather than dropped because a TypeSpec is exactly as good a place to
// meet a new node kind as a field is (0vk.49).
func aliasesASecret(ts *ast.TypeSpec, names map[string]bool, unknown *unknownNodes) bool {
	if containsAnonymousStruct(ts.Type) {
		return false
	}
	return isSecretString(ts.Type, names, unknown)
}

// containsAnonymousStruct reports whether expr has an anonymous struct type
// anywhere inside it.
//
// IT EXISTS TO KEEP aliasesASecret ASKING ITS OWN QUESTION. That rule is about
// IDENTITY — "is this a second NAME for secret.String" — and it answers it by
// reusing isSecretString, which is about CONTAINMENT. The two agreed until
// 0vk.48 taught isSecretString to see into an anonymous struct: after that,
// `type T []struct{ Token secret.String }` made isSecretString true, and
// aliasesASecret reported "T gives secret.String a second name; a redefinition
// also drops LogValue, String, GoString and MarshalJSON" — every clause of which
// is false about a named slice type, which drops nothing and is not a second
// name for anything. Measured before and after: main reported nothing for that
// shape, this branch reported the wrong thing, which is worse than the gap.
//
// A struct is never a second name for secret.String — it is a different type
// that happens to hold one — so this refuses the whole family and leaves
// aliasesASecret exactly as it behaved before 0vk.48. It subsumes the bare
// `ts.Type.(*ast.StructType)` check it replaces, a bare struct containing itself.
//
// The BROADER conflation is older than this bead and is left alone: `type T
// []secret.String` and `type T *secret.String` are reported as second names
// today and are not ones either. That is BrollyZap-0vk.50.
//
// ONE CONSEQUENCE FOR 0vk.49'S GUARANTEE, measured and filed as BrollyZap-0vk.51.
// Refusing here happens BEFORE isSecretString is called, and the walk then falls
// through because ts.Type is not a *ast.StructType — so for `type T
// []struct{...}` and `type T map[string]struct{...}` the inner struct's fields
// are never handed to the predicate at all, and a node kind first written in
// there is never collected. With the ChanType case removed, a plain `type T
// struct{ C chan secret.String }` reports one unrecognised node and the named
// slice reports none. Collecting is not diagnosing, so it is fixable without
// changing what is reported — but it is held behind 0vk.50, which owns whether
// this family is reported at all and would move the same guard.
func containsAnonymousStruct(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if _, ok := n.(*ast.StructType); ok {
			found = true
		}
		return !found
	})
	return found
}

// holdsASecret reports whether any of st's fields is a secret.String, however it
// is spelled and however it is wrapped. See the FIRST bullet on
// secretBearingTypes for the seven spellings that used to get through.
//
// EVERY FIELD IS VISITED, where this used to be a slices.ContainsFunc that stopped
// at the first true one. Under 0vk.49 the walk is also collecting unrecognised
// nodes, and short-circuiting would skip the fields after a secret — so a struct
// with one known secret and one node kind nobody has taught this predicate would
// report the first and stay silent about the second.
func holdsASecret(st *ast.StructType, names map[string]bool, unknown *unknownNodes) bool {
	secret := false
	for _, field := range st.Fields.List {
		if isSecretString(field.Type, names, unknown) {
			secret = true
		}
	}
	return secret
}

// unknownNodes collects the type expressions isSecretString did not recognise.
//
// A COLLECTOR, chosen over the two other shapes the brief offered.
//
// A t.Fatalf from the predicate is cheapest and is ruled out by criterion 1: the
// rule has to be PROVED to report an unrecognised node, and a Fatalf cannot be
// planted — it ends the test rather than returning a message a plant can assert.
// It would also put a *testing.T inside a pure predicate, in a package whose whole
// design is scanners that RETURN problems and Test wrappers that assert them.
//
// A third outcome is pure and is rejected on WEIGHT, not on impossibility — an
// earlier draft of this comment said a map with an unrecognised key and a secret
// value "has no single right pair to return", which is true of
// (bool, ast.Expr) and false of (bool, []ast.Expr), where the combination is
// plainly concatenation. The honest reason is that threading a returned slice
// through six recursion sites IS this collector, hand-written, with a join
// allocation at every site. Same conclusion; the reader who spots the difference
// should not be left thinking the choice rested on a mistake.
//
// It holds ast.Expr rather than a formatted string because the predicate has no
// FileSet and no filename; the caller resolves the position, which is the only
// place that can.
type unknownNodes struct{ nodes []ast.Expr }

// unrecognisedNode is what the walk reports for one. It says UNRECOGNISED and
// never that a secret was found — see the fail-closed paragraph on
// isSecretString for why that distinction is the whole bead.
func unrecognisedNode(file string, line int, expr ast.Expr) string {
	return fmt.Sprintf("%s:%d: unrecognised type expression %T. isSecretString has never "+
		"been taught this node kind, so it cannot say whether the field carries a secret — "+
		"this is a request for a decision, NOT a report of a leak. Add a case that unwraps "+
		"it, or an exclusion case with its reason beside chan and interface (0vk.49)",
		file, line, expr)
}

// isSecretString reports whether expr denotes a secret.String, through any number
// of pointers, slices, arrays, maps, parentheses and anonymous nested structs.
// Map KEYS are unwrapped as well as values: a secret is no less exposed for being
// on the left of the colon.
//
// IT FAILS CLOSED (0vk.49, David's ruling of 6 Sep 2026). Every node kind this
// predicate accepts or refuses is an explicit case carrying its own reason, and a
// node kind it has never seen is REPORTED — file, line and %T — rather than
// silently answered "not a secret".
//
// THAT IS WHY THE SPELLING FAMILY IS CLOSED, and it is a better reason than the
// one that stood here before. Four beads walked it: 0vk.36 wrote this predicate,
// 0vk.46 ported it to internal/arch and added map keys and local types, g5n closed
// the parenthesised type, 0vk.48 the anonymous nested struct. Every one was the
// same event with a different node kind — an ordinary Go spelling reached
// `default: return false`, the CONTAINER stopped being a bearer, and the whole
// tree stayed green. The missing case differed each time; the mechanism never did.
// So the family does not close because anyone promised to stop looking. It closes
// because the fifth spelling now announces itself.
//
// FAILING CLOSED IS NOT `default: return true`, and that distinction is the whole
// bead. Answering true would report an unrecognised node as "holds a secret.String
// and implements no LogValue" — a confident and wrong diagnosis, which is a cost
// 0vk.48 paid once already. The bool answer therefore stays false and the node is
// collected instead, so the walk can ask for a decision rather than allege a leak.
//
// Resolving what an identifier DENOTES — an alias, a named type from another
// package, a type parameter — is still go/types and still a different decision. An
// unrecognised node is a shape this switch has never been taught, not a name whose
// meaning has to be looked up.
func isSecretString(expr ast.Expr, names map[string]bool, unknown *unknownNodes) bool {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return isSecretString(t.X, names, unknown)
	case *ast.ArrayType:
		return isSecretString(t.Elt, names, unknown)
	case *ast.MapType:
		// BOTH HALVES, NEVER SHORT-CIRCUITED. `||` would stop at a secret key and
		// never look at the value, so an unrecognised node on the right would go
		// uncollected in exactly the struct someone is already being told about.
		// Under a fail-closed rule an unvisited node is the thing to avoid.
		key := isSecretString(t.Key, names, unknown)
		value := isSecretString(t.Value, names, unknown)
		return key || value
	case *ast.ParenExpr:
		// `Token (secret.String)` is legal Go and IS a secret.String — the parens
		// are not a container, they are spelling, and gofmt keeps them. Found by
		// the go-review pass on 0vk.46, which planted it in internal/arch and
		// watched a secret-bearing struct with no LogValue pass clean; this copy
		// carried the same hole for a day longer (g5n).
		return isSecretString(t.X, names, unknown)
	case *ast.StructType:
		// An ANONYMOUS NESTED STRUCT — `Inner struct{ Token secret.String }` —
		// has no TypeSpec of its own, so neither walk ever visits it and the
		// CONTAINER escaped the LogValue requirement entirely (0vk.48). Mutual
		// recursion with holdsASecret closes it at any depth.
		//
		// Reported against the CONTAINER, per David's ruling of 6 Sep: the inner
		// struct has no name to report, and the container is the type that needs
		// the LogValue. A nested struct inside a function-local type therefore
		// keeps that walk's own message, whose remedy is to hoist.
		return holdsASecret(t, names, unknown)
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		if !ok {
			// The one refusal left inside this switch that was silent, and under a
			// rule whose whole claim is that none of them are. A qualified type
			// name is always ident.Name in legal Go — `pkg.Pair[T]` arrives as an
			// IndexExpr, not as a nested selector — so this is unreachable today.
			// "Unreachable today" is exactly what the four beads before this one
			// were each told about the case they were missing.
			unknown.nodes = append(unknown.nodes, expr)
			return false
		}
		return names[pkg.Name] && t.Sel.Name == "String"
	case *ast.Ident:
		// A bare String: either the package was dot-imported, or this file IS
		// package secret.
		return names["."] && t.Name == "String"

	// THE EXCLUSIONS. Each is a deliberate answer with its own reason, and the
	// reasons differ — they look alike and are not, which is why they are separate
	// cases and not one. Before 0vk.49 these lived in prose above the switch while
	// the code said nothing, which is two statements of one list.
	case *ast.ChanType, *ast.FuncType:
		// Both render as an ADDRESS under %v and under slog.Any (measured), so
		// unlike a slice or a map they cannot spill what they hold. The containers
		// above are unwrapped precisely because they DO print their elements.
		return false
	case *ast.InterfaceType:
		// NOT for the reason above, though it is easy to file it there: an
		// interface renders its dynamic value, not an address. It is out because
		// what it holds is a runtime fact, which no syntax check can see at any
		// depth. Measured: an `any` holding a secret.String still prints
		// `[redacted]`, every rendering path on the type being overridden, and what
		// survives is a plain string that CAME from a secret — dataflow, and these
		// tests' own job. An earlier draft said interfaces render as an address.
		// They do not.
		return false
	case *ast.IndexExpr, *ast.IndexListExpr:
		// `Token Box[secret.String]`, and `pkg.Pair[string, secret.String]` for the
		// list form. Excluded because unwrapping the type ARGUMENT is not sound:
		// `type Box[T any] struct{ n int }` never stores its T, so this would
		// report a struct holding no secret at all. internal/arch's typeString
		// already learned these two nodes for generic RECEIVERS, which makes it
		// easy to assume field types followed; they did not.
		return false

	default:
		unknown.nodes = append(unknown.nodes, expr)
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
