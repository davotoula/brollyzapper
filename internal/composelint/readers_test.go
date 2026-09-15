package composelint

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// NOTHING IN A LINT READS A COMPOSE FILE'S TEXT (BrollyZap-20i.24). This package
// took the raw string out of the three lint loaders (20i.18); what held that
// afterwards was a grep run once, with three routes back open. Parse taking bytes
// is closed at the compiler — it is unexported. The other two — a lint calling
// os.ReadFile on a compose path, or umbrel's readPackageFile, which returns any
// package file as a string — are what this scanner refuses.
//
// It lives here and not in internal/arch because arch reads non-test files only,
// and every lint is a _test.go.
//
// WHAT IT JUDGES: a path argument's string literals and the constants it names —
// alone, concatenated, or inside a call such as filepath.Join — and it refuses one
// that names a compose file. WHAT IT DOES NOT: a path computed at run time. That is
// not called clean; it is listed, every run, as the inventory a reviewer reads
// (TestNoLintReadsComposeText logs it). What would reopen it: a lint reading a
// file through a function this does not know — fs.ReadFile, io.ReadAll over an
// os.DirFS — in which case add it to fileReaders and a row to the catches table.

// lintDirs are the three directories whose tests are the lints, from here.
var lintDirs = []string{"../../deploy", "../../umbrel", "../../regtest"}

// skippedDirs are never walked by either rule. data/ is regtest's gitignored
// runtime state of a stack (bitcoind, LND) — never source, and thousands of files.
var skippedDirs = []string{"data", "testdata", "vendor"}

// fileReaders is every call that turns a path into content, by the name it is
// called under and the index of its path argument. An "os." name matches the os
// package under whatever name a file imports it as.
var fileReaders = map[string]int{
	"os.ReadFile":     0,
	"os.Open":         0,
	"os.OpenFile":     0,
	"readPackageFile": 1, // umbrel/lint_test.go: (t, name)
}

// isComposeName reports whether a path names a compose file. BY NAME, because a
// name is all a scanner of source has; TestEveryComposeFileIsNamedAsOne is what
// makes the name a fact rather than a habit.
func isComposeName(p string) bool {
	base := strings.ToLower(path.Base(filepath.ToSlash(p)))
	ext := path.Ext(base)
	return (ext == ".yml" || ext == ".yaml") && strings.Contains(base, "compose")
}

// readCall is one call in fileReaders, as found.
type readCall struct {
	At    string // file:line
	Call  string // the call as written
	Kind  string // literal, const, or computed
	Names []string
}

// sourceFile is one Go file's name and content: the scanner's input, so a
// synthetic file can prove each refusal without touching the tree.
type sourceFile struct {
	Name string
	Src  string
}

// scanReads parses one package's files and returns every file-reading call, and
// the ones that name a compose file. Constants resolve across the package's files
// and within the function a call sits in.
func scanReads(t *testing.T, pkg []sourceFile) (refused, all []readCall) {
	t.Helper()
	fset := token.NewFileSet()
	var files []*ast.File
	for _, f := range pkg {
		file, err := parser.ParseFile(fset, f.Name, f.Src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", f.Name, err)
		}
		files = append(files, file)
	}
	pkgConsts := map[string]ast.Expr{}
	for _, file := range files {
		for _, decl := range file.Decls {
			if gen, ok := decl.(*ast.GenDecl); ok {
				collectConsts(gen, pkgConsts)
			}
		}
	}
	for _, file := range files {
		osNames := importNames(file, "os")
		// Every declaration, not only functions: a read in a package-level
		// `var x = func() {…}` is a read too. A function's own constants are in
		// scope inside it; anywhere else, the package's.
		for _, decl := range file.Decls {
			consts := pkgConsts
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				consts = localConsts(fn.Body, pkgConsts)
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				argAt, known := fileReaders[callName(call, osNames)]
				if !known || argAt >= len(call.Args) {
					return true
				}
				arg := call.Args[argAt]
				rc := readCall{
					At:    fset.Position(call.Pos()).String(),
					Call:  types.ExprString(call),
					Kind:  "computed",
					Names: stringParts(arg, consts),
				}
				if _, ok := stringValue(arg, consts, 0); ok {
					rc.Kind = "const"
					if _, lit := arg.(*ast.BasicLit); lit {
						rc.Kind = "literal"
					}
				}
				all = append(all, rc)
				if slices.ContainsFunc(rc.Names, isComposeName) {
					refused = append(refused, rc)
				}
				return true
			})
		}
	}
	return refused, all
}

// callName is "os.ReadFile" for a call through the os package under any of its
// import names, the bare name for a plain function, and "" otherwise.
func callName(call *ast.CallExpr, osNames []string) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		if x, ok := fun.X.(*ast.Ident); ok && slices.Contains(osNames, x.Name) {
			return "os." + fun.Sel.Name
		}
	}
	return ""
}

// importNames is every name a file refers to the package at importPath by.
func importNames(file *ast.File, importPath string) []string {
	var out []string
	for _, imp := range file.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p != importPath {
			continue
		}
		if imp.Name != nil {
			out = append(out, imp.Name.Name)
		} else {
			out = append(out, path.Base(importPath))
		}
	}
	return out
}

func collectConsts(gen *ast.GenDecl, into map[string]ast.Expr) {
	if gen.Tok != token.CONST {
		return
	}
	for _, spec := range gen.Specs {
		vs := spec.(*ast.ValueSpec)
		for i, name := range vs.Names {
			if i < len(vs.Values) {
				into[name.Name] = vs.Values[i]
			}
		}
	}
}

// localConsts is the package's constants with a function's own on top. A local
// constant shadows a package one of the same name, as it does in Go; a local
// VARIABLE that shadows a constant is not modelled, and can only make this
// judge a computed path as the constant — a false red, never a false green.
func localConsts(body *ast.BlockStmt, pkg map[string]ast.Expr) map[string]ast.Expr {
	out := maps.Clone(pkg)
	ast.Inspect(body, func(n ast.Node) bool {
		if decl, ok := n.(*ast.DeclStmt); ok {
			if gen, ok := decl.Decl.(*ast.GenDecl); ok {
				collectConsts(gen, out)
			}
		}
		return true
	})
	return out
}

// stringValue is the value of a constant string expression — a literal, a named
// constant, or a concatenation of them — and whether it is one. Call it with depth
// 0.
//
// THE DEPTH BOUND IS NOT DECORATION. localConsts lays a function's constants over
// the package's by name, so `const dir = dir + "/x"` — legal Go, the right-hand
// dir being the package's — resolves here to itself. The bound turns that into
// "not a constant" (listed as computed) instead of a hang.
func stringValue(e ast.Expr, consts map[string]ast.Expr, depth int) (string, bool) {
	if depth > 16 {
		return "", false
	}
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(e.Value)
		return v, err == nil
	case *ast.Ident:
		if def, ok := consts[e.Name]; ok {
			return stringValue(def, consts, depth+1)
		}
	case *ast.ParenExpr:
		return stringValue(e.X, consts, depth+1)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		l, lok := stringValue(e.X, consts, depth+1)
		r, rok := stringValue(e.Y, consts, depth+1)
		return l + r, lok && rok
	}
	return "", false
}

// stringParts is every constant string inside a computed expression —
// filepath.Join(dir, "docker-compose.yml") has one — so a path assembled at run
// time from a compose file's name is judged by that name.
func stringParts(e ast.Expr, consts map[string]ast.Expr) []string {
	var out []string
	ast.Inspect(e, func(n ast.Node) bool {
		expr, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		if v, ok := stringValue(expr, consts, 0); ok {
			out = append(out, v)
			return false
		}
		return true
	})
	return out
}

// lintPackages is every _test.go under the three lint directories, grouped by
// the directory — the package — it is in.
func lintPackages(t *testing.T) map[string][]sourceFile {
	t.Helper()
	pkgs := map[string][]sourceFile{}
	for _, dir := range lintDirs {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if slices.Contains(skippedDirs, d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel := strings.TrimPrefix(filepath.ToSlash(p), "../../")
			pkgs[path.Dir(rel)] = append(pkgs[path.Dir(rel)], sourceFile{Name: rel, Src: string(src)})
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}
	return pkgs
}

func TestNoLintReadsComposeText(t *testing.T) {
	pkgs := lintPackages(t)
	var scanned []string
	for _, files := range pkgs {
		for _, f := range files {
			scanned = append(scanned, f.Name)
		}
	}
	slices.Sort(scanned)
	// A scanner that found nothing to read passes having judged nothing.
	for _, dir := range []string{"deploy", "umbrel", "regtest"} {
		if len(pkgs[dir]) == 0 {
			t.Fatalf("found no _test.go in %s (scanned %v); this rule would pass having read nothing", dir, scanned)
		}
	}
	t.Logf("scanned %d files: %s", len(scanned), strings.Join(scanned, ", "))

	for _, dir := range slices.Sorted(maps.Keys(pkgs)) {
		refused, all := scanReads(t, pkgs[dir])
		for _, rc := range refused {
			t.Errorf("%s: %s reads a compose file's text (%q); read it through composelint.Load "+
				"and ask the document — the raw string is what every 20i defect was built on "+
				"(BrollyZap-20i.18, 20i.24)", rc.At, rc.Call, rc.Names)
		}
		for _, rc := range all {
			t.Logf("read: %s  %s  [%s] %q", rc.At, rc.Call, rc.Kind, rc.Names)
		}
	}
}

// TestEveryComposeFileIsNamedAsOne is the premise isComposeName stands on. A
// compose file named stack.yml would be read past the rule above without a word,
// so every YAML file in the lint directories with a top-level services: mapping —
// what makes a file a compose file — must carry "compose" in its name.
func TestEveryComposeFileIsNamedAsOne(t *testing.T) {
	composeFiles := 0
	for _, dir := range lintDirs {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if slices.Contains(skippedDirs, d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if ext := filepath.Ext(p); ext != ".yml" && ext != ".yaml" {
				return nil
			}
			src, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			var top map[string]yaml.Node
			if err := yaml.Unmarshal(src, &top); err != nil {
				t.Errorf("%s is not a YAML mapping: %v", p, err)
				return nil
			}
			if _, ok := top["services"]; !ok {
				return nil
			}
			composeFiles++
			if !isComposeName(p) {
				t.Errorf("%s is a compose file (it has services:) but its name does not say so; "+
					"TestNoLintReadsComposeText judges by name and would not see it read", p)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}
	// deploy's, umbrel's, and regtest's canonical file and build override.
	if composeFiles < 4 {
		t.Fatalf("found %d compose files; there are at least four, so this read the wrong thing", composeFiles)
	}
}

// TestTheComposeReadRuleCatches plants each route in a synthetic package. A rule
// that has only ever passed has been written, not tested.
func TestTheComposeReadRuleCatches(t *testing.T) {
	const header = "package lint\n\nimport (\n\t\"os\"\n\tfsos \"os\"\n\t\"path/filepath\"\n\t\"testing\"\n)\n\n" +
		"func readPackageFile(t *testing.T, name string) string { return \"\" }\n\n"
	for _, tc := range []struct {
		name     string
		body     string
		extra    string // a second file in the same package
		refused  string // the call the refusal must name, or "" for clean
		computed bool   // listed as computed
	}{
		{name: "a literal", body: `os.ReadFile("docker-compose.yml")`, refused: `os.ReadFile("docker-compose.yml")`},
		{name: "readPackageFile", body: `readPackageFile(t, "docker-compose.yml")`, refused: `readPackageFile(t, "docker-compose.yml")`},
		{name: "a local const", body: "const p = \"../regtest/docker-compose.yaml\"\n\tos.ReadFile(p)", refused: `os.ReadFile(p)`},
		{name: "a const in another file of the package", body: `os.Open(stack)`,
			extra: "package lint\n\nconst stack = \"docker-compose.build.yml\"\n", refused: `os.Open(stack)`},
		{name: "a concatenation of consts", body: "const dir = \"../deploy/\"\n\tos.ReadFile(dir + \"docker-compose.yml\")", refused: `os.ReadFile(dir + "docker-compose.yml")`},
		{name: "a literal inside a Join", body: `os.ReadFile(filepath.Join(t.TempDir(), "docker-compose.yml"))`,
			refused: `os.ReadFile(filepath.Join(t.TempDir(), "docker-compose.yml"))`, computed: true},
		{name: "os under another import name", body: `fsos.OpenFile("compose.yaml", 0, 0)`, refused: `fsos.OpenFile("compose.yaml", 0, 0)`},
		{name: "a read outside any function", body: `_ = 0`,
			extra: "package lint\n\nimport \"os\"\n\nvar read = func() { os.ReadFile(\"docker-compose.yml\") }\n", refused: `os.ReadFile("docker-compose.yml")`},
		{name: "a local const defined from the package const it shadows terminates, listed", body: "const dir = dir + \"/x\"\n\tos.ReadFile(dir)",
			extra: "package lint\n\nconst dir = \"../deploy\"\n", computed: true},
		{name: "a script is not compose", body: `os.ReadFile("exports.sh")`},
		{name: "the Umbrel manifest is YAML and not compose", body: "const name = \"umbrel-app.yml\"\n\treadPackageFile(t, name)"},
		{name: "a variable is listed, not judged", body: `name := t.Name()` + "\n\tos.ReadFile(name)", computed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := []sourceFile{{Name: "synthetic_test.go", Src: header + "func TestX(t *testing.T) {\n\t" + tc.body + "\n\t_ = filepath.Join\n\t_ = fsos.Open\n}\n"}}
			if tc.extra != "" {
				pkg = append(pkg, sourceFile{Name: "extra_test.go", Src: tc.extra})
			}
			refused, all := scanReads(t, pkg)
			if len(all) != 1 {
				t.Fatalf("found %d reads, want the one planted: %+v", len(all), all)
			}
			if got := all[0].Kind == "computed"; got != tc.computed {
				t.Errorf("kind = %s, want computed=%v", all[0].Kind, tc.computed)
			}
			switch {
			case tc.refused == "" && len(refused) != 0:
				t.Errorf("refused %+v; it names no compose file", refused)
			case tc.refused != "" && (len(refused) != 1 || refused[0].Call != tc.refused):
				t.Errorf("refused %+v, want exactly %s", refused, tc.refused)
			}
		})
	}
}
