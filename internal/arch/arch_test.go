// Package arch holds the structural invariants of the repository: the spec §3
// package layout, the rules that keep the layers honest, and — since the CI
// workflow is the only gate before MVP — the rule that keeps the enforcement
// itself honest. It contains test files only; no production code lives here.
package arch

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/template/parse"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// specPackages is the package layout of spec §3, including the amendments
// recorded in that section.
var specPackages = []string{
	"cmd/brollyzapper",
	"cmd/brollyguard",
	"internal/guard",
	"internal/config",
	"internal/secret",
	"internal/logging",
	"internal/buildinfo",
	"internal/cliboot",
	"internal/preflight",
	"internal/store",
	"internal/lnd",
	"internal/wallet",
	"internal/recon",
	"internal/nostr",
	"internal/lnurl",
	"internal/zap",
	"internal/nwc",
	"internal/api",
	"internal/web",
}

// ---------------------------------------------------------------------------
// Shared source walking. Every rule below reads the same tree, so it is walked
// and parsed once per test binary rather than once per rule.
// ---------------------------------------------------------------------------

// neverScanned are directories no rule ever looks inside.
var neverScanned = []string{".git", ".beads", "vendor", "testdata", "node_modules"}

// problem is one rule violation, as a scanner reports it.
//
// The rules used to call t.Errorf where they found something, which made every
// one of them untestable: the only way to know a rule still WORKED was to edit
// the tree by hand, watch it go red, and revert. Nothing recorded that the plant
// had happened, so a rule refactored into uselessness passed exactly as quietly
// as it had before — and arch_test.go already documents one that "passed while
// the violation was in the tree" (zu5.6, coverage analysis §4.2).
//
// A scanner takes its input and returns these instead. The Test wrapper runs it
// twice: once over the real tree, asserting nothing is found, and once over a
// synthetic file that breaks the rule on purpose, asserting it IS found. The
// manual plant, made permanent.
type problem struct {
	file string
	line int // 1-indexed; 0 when the finding is about a file or package as a whole
	msg  string
}

func (p problem) String() string {
	if p.line == 0 {
		return p.file + ": " + p.msg
	}
	return fmt.Sprintf("%s:%d: %s", p.file, p.line, p.msg)
}

// clean asserts a scanner found nothing in the real tree.
func clean(t *testing.T, found []problem) {
	t.Helper()
	for _, p := range found {
		t.Error(p)
	}
}

// catches asserts the scanner found the planted violation and said something
// recognisable about it.
//
// The message is checked, not just the count: a rule that fires with the wrong
// explanation sends the next person to the wrong place, and a rule that fires
// for an unrelated reason would otherwise look like it was working.
func catches(t *testing.T, found []problem, want string) {
	t.Helper()
	if len(found) == 0 {
		t.Fatalf("the planted violation was NOT detected; this rule can no longer fail, "+
			"which means it has been written rather than tested (wanted a message naming %q)",
			want)
	}
	for _, p := range found {
		if strings.Contains(p.msg, want) {
			return
		}
	}
	t.Errorf("the violation was detected but no message names %q; found %v", want, found)
}

// planted builds a synthetic Go file for a rule to find its violation in.
//
// The path is a label — codeLines parses from src — so this never touches the
// disk and cannot be mistaken for part of the tree.
func planted(dir, body string) sourceFile {
	rel := dir + "/planted_violation.go"
	return sourceFile{rel: rel, dir: dir, path: rel, src: []byte(body)}
}

// sourceFile is one non-test Go file of the module.
type sourceFile struct {
	rel  string // module-relative, slash-separated
	dir  string // module-relative directory
	path string // absolute
	src  []byte
}

// pkg is one Go package in the module, keyed by its module-relative directory.
type pkg struct {
	dir     string
	docs    string   // package doc comment, concatenated across files
	imports []string // direct imports of non-test files
}

// findModuleRoot walks up from the working directory to the directory holding
// go.mod.
func findModuleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found above %s", dir)
		}
		dir = parent
	}
}

var (
	moduleRootOnce  = sync.OnceValues(findModuleRoot)
	sourceFilesOnce = sync.OnceValues(readSourceFiles)
	packagesOnce    = sync.OnceValues(loadPackages)
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := moduleRootOnce()
	if err != nil {
		t.Fatalf("locating module root: %v", err)
	}
	return root
}

// readSourceFiles reads every non-test Go file in the module.
func readSourceFiles() ([]sourceFile, error) {
	root, err := moduleRootOnce()
	if err != nil {
		return nil, err
	}
	var out []sourceFile
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if slices.Contains(neverScanned, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
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
		out = append(out, sourceFile{rel: rel, dir: filepath.ToSlash(filepath.Dir(rel)), path: path, src: src})
		return nil
	})
	return out, err
}

// codeLines returns f's lines with every comment blanked out, line numbers and
// column offsets preserved.
//
// Several rules read code and must not fire on prose that merely mentions the
// thing they forbid — a §12 comment explaining why a ceiling move needs an audit
// event tripped the balance rule, and a comment naming ".SubscribeInvoices("
// would break a rule that counts call sites.
//
// It blanks comment BYTE RANGES rather than cutting at the first "//", because
// cutting is wrong twice over: it truncates at a "//" inside a string literal
// (this tree has "https://" in internal/api/probe.go), silently hiding anything
// after it on that line, and it does not remove block comments at all. A rule
// that can be evaded by writing the violation after a URL is worse than one
// that occasionally fires on prose.
//
// MEMOIZED, and keyed on the SOURCE rather than the path. Two dozen rules each
// walk the tree, so the same ~130 files were parsed some twenty times over —
// about 0.6s of the package's runtime, doubled by the -race pass. The key
// cannot be f.path: planted() synthesises files with a fake path and reuses
// that one path for a different body in every rule that plants, so a
// path-keyed memo hands the second plant the first one's code and the rule
// stops detecting its own violation. Content is the thing being parsed, so
// content is the key.
//
// The returned slice is shared between callers. No rule mutates it; one that
// needs to must copy first.
func codeLines(t *testing.T, f sourceFile) []string {
	t.Helper()
	if cached, ok := codeLineCache.Load(string(f.src)); ok {
		return cached.([]string)
	}
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, f.path, f.src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", f.rel, err)
	}
	blanked := []byte(string(f.src))
	base := fset.File(parsed.Pos()).Base()
	for _, group := range parsed.Comments {
		for i := int(group.Pos()) - base; i < int(group.End())-base && i < len(blanked); i++ {
			if blanked[i] != '\n' {
				blanked[i] = ' '
			}
		}
	}
	lines := strings.Split(string(blanked), "\n")
	codeLineCache.Store(string(f.src), lines)
	return lines
}

// codeLineCache backs codeLines. Keyed by source text; see the note there on
// why the path will not do.
var codeLineCache sync.Map

// sourceFiles returns every non-test Go file outside skipDirs, which are named
// by module-relative directory prefix.
func sourceFiles(t *testing.T, skipDirs ...string) []sourceFile {
	t.Helper()
	all, err := sourceFilesOnce()
	if err != nil {
		t.Fatalf("walking module: %v", err)
	}
	if len(skipDirs) == 0 {
		return all
	}
	var out []sourceFile
	for _, f := range all {
		if !slices.ContainsFunc(skipDirs, func(skip string) bool {
			return f.dir == skip || strings.HasPrefix(f.dir, skip+"/")
		}) {
			out = append(out, f)
		}
	}
	return out
}

// loadPackages groups the module's non-test files by directory, recording each
// package's doc comment and direct imports.
func loadPackages() (map[string]*pkg, error) {
	files, err := sourceFilesOnce()
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	pkgs := map[string]*pkg{}
	for _, file := range files {
		f, err := parser.ParseFile(fset, file.path, file.src, parser.ParseComments|parser.ImportsOnly)
		if err != nil {
			return nil, err
		}
		p := pkgs[file.dir]
		if p == nil {
			p = &pkg{dir: file.dir}
			pkgs[file.dir] = p
		}
		if f.Doc != nil {
			p.docs += f.Doc.Text()
		}
		for _, spec := range f.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return nil, err
			}
			p.imports = append(p.imports, path)
		}
	}
	return pkgs, nil
}

func packages(t *testing.T) map[string]*pkg {
	t.Helper()
	pkgs, err := packagesOnce()
	if err != nil {
		t.Fatalf("parsing module: %v", err)
	}
	return pkgs
}

// ---------------------------------------------------------------------------
// The rules.
// ---------------------------------------------------------------------------

// vz1.2: a settings-key string literal is spelled out in exactly one package.
//
// The same family as the fee rule, generalised. internal/api/settings.go states
// the principle in prose — "the package that computes with a value owns the name
// of the row it comes from" — and follows it for three keys while `domain` and
// `address_name` were independent literals in two packages each.
//
// The failure is silent and fails OPEN. A mistyped read returns "", and for
// domain_insecure "" means secure, which advertises an https callback for a box
// that only answers plain HTTP. Nothing errors, nothing logs, and the two
// packages simply disagree about which row they are talking about.
//
// Only Setting* constants are considered, so an ordinary string that happens to
// match a row name is not a violation.
func checkSettingsKeyLiterals(t *testing.T, files []sourceFile) []problem {
	declaration := regexp.MustCompile(`\bSetting\w*\s*=\s*"([^"]+)"`)
	spelledIn := map[string]map[string]int{} // key -> dir -> line
	for _, f := range files {
		for i, line := range codeLines(t, f) {
			m := declaration.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if spelledIn[m[1]] == nil {
				spelledIn[m[1]] = map[string]int{}
			}
			spelledIn[m[1]][f.dir] = i + 1
		}
	}
	var found []problem
	for key, dirs := range spelledIn {
		if len(dirs) < 2 {
			continue
		}
		for _, dir := range slices.Sorted(maps.Keys(dirs)) {
			found = append(found, problem{dir, dirs[dir], fmt.Sprintf(
				"spells out the settings key %q, which %d packages declare; the package that "+
					"COMPUTES with a row owns its name and the others alias that constant — "+
					"two literals for one row is how a save and a read back become different "+
					"strings, silently (vz1.2)", key, len(dirs))})
		}
	}
	return found
}

func TestASettingsKeyLiteralExistsInOnePackage(t *testing.T) {
	clean(t, checkSettingsKeyLiterals(t, sourceFiles(t)))
	catches(t, checkSettingsKeyLiterals(t, []sourceFile{
		planted("internal/api", "package api\n\nconst SettingDomain = \"domain\"\n"),
		planted("internal/lnurl", "package lnurl\n\nconst SettingDomain = \"domain\"\n"),
	}), "owns its name")
	// One package declaring it is the healthy case, and must not fire.
	clean(t, checkSettingsKeyLiterals(t, []sourceFile{
		planted("internal/lnurl", "package lnurl\n\nconst SettingDomain = \"domain\"\n"),
	}))
}

func checkSpecPackageLayout(pkgs map[string]*pkg) []problem {
	var found []problem
	for _, want := range specPackages {
		p, ok := pkgs[want]
		if !ok {
			found = append(found, problem{want, 0, "spec §3 package does not exist"})
			continue
		}
		if strings.TrimSpace(p.docs) == "" {
			found = append(found, problem{want, 0,
				"has no package doc comment naming its responsibility"})
		}
	}
	return found
}

func TestSpecPackageLayoutExists(t *testing.T) {
	clean(t, checkSpecPackageLayout(packages(t)))
	catches(t, checkSpecPackageLayout(map[string]*pkg{
		specPackages[0]: {dir: specPackages[0], docs: ""},
	}), "no package doc comment")
}

func checkNetHTTPImporters(pkgs map[string]*pkg) []problem {
	// Spec §3: "Everything below api/web must be usable without an HTTP server."
	allowed := map[string]bool{
		"internal/api":     true,
		"internal/web":     true,
		"cmd/brollyzapper": true,
	}
	var found []problem
	for dir, p := range pkgs {
		if allowed[dir] {
			continue
		}
		for _, imp := range p.imports {
			if isPackage(imp, "net/http") {
				found = append(found, problem{dir, 0, fmt.Sprintf(
					"imports %q; only %s may (spec §3)",
					imp, strings.Join(slices.Sorted(maps.Keys(allowed)), ", "))})
			}
		}
	}
	return found
}

func TestOnlyAPIWebAndCmdImportNetHTTP(t *testing.T) {
	clean(t, checkNetHTTPImporters(packages(t)))
	catches(t, checkNetHTTPImporters(map[string]*pkg{
		"internal/store": {dir: "internal/store", imports: []string{"net/http"}},
	}), "cmd/brollyzapper, internal/api")
}

// The guard has no listeners (§16) and never reads the server's database (§12,
// §16: "the guard writes to nothing the server owns", "do not let the guard
// read the server's database for the spend counter"). Both are the same kind of
// rule, so they are one table rather than one test each.
func checkGuardImports(pkgs map[string]*pkg) []problem {
	forbidden := map[string]string{
		"net/http":           "the guard has no listeners (spec §16)",
		"internal/store":     "the guard keeps its own store and never reads the server's (spec §12, §16)",
		"database/sql":       "the guard has no database of the server's kind (spec §16)",
		"modernc.org/sqlite": "the guard has no database of the server's kind (spec §16)",
	}
	var found []problem
	for _, dir := range []string{"internal/guard", "cmd/brollyguard"} {
		p, ok := pkgs[dir]
		if !ok {
			found = append(found, problem{dir, 0, "guard package does not exist"})
			continue
		}
		for _, imp := range p.imports {
			for banned, why := range forbidden {
				if isPackage(imp, banned) || isPackage(imp, "github.com/davotoula/brollyzapper/"+banned) {
					found = append(found, problem{dir, 0,
						fmt.Sprintf("imports %q: %s", imp, why)})
				}
			}
		}
	}
	return found
}

func TestGuardImportsNothingItMustNotSee(t *testing.T) {
	clean(t, checkGuardImports(packages(t)))
	catches(t, checkGuardImports(map[string]*pkg{
		"internal/guard":  {dir: "internal/guard", imports: []string{"net/http"}},
		"cmd/brollyguard": {dir: "cmd/brollyguard"},
	}), "no listeners")
}

// Spec §3 and §6: the guard listens on a unix domain socket in the shared
// volume and nowhere else. The import ban above stops net/http; this stops the
// other way in, a raw TCP listener.
func checkGuardListensOnNoNetworkSocket(t *testing.T, files []sourceFile) []problem {
	networks := []string{`"tcp"`, `"tcp4"`, `"tcp6"`, `"udp"`, `"udp4"`, `"udp6"`}
	var found []problem
	for _, f := range files {
		if f.dir != "internal/guard" && f.dir != "cmd/brollyguard" {
			continue
		}
		for i, line := range codeLines(t, f) {
			for _, network := range networks {
				if strings.Contains(line, network) {
					found = append(found, problem{f.rel, i + 1, fmt.Sprintf(
						"names the %s network; the guard has a unix socket and nothing "+
							"else (spec §3, §6)", network)})
				}
			}
		}
	}
	return found
}

func TestTheGuardListensOnNoNetworkSocket(t *testing.T) {
	clean(t, checkGuardListensOnNoNetworkSocket(t, sourceFiles(t)))
	catches(t, checkGuardListensOnNoNetworkSocket(t, []sourceFile{planted("internal/guard", `package guard

func listen() {
	l, _ := net.Listen("tcp", ":9000")
	_ = l
}
`)}), "unix socket and nothing else")
}

// Spec §6, box-verified: every write into the credential volume goes through
// WriteCredential, which writes a temp file in the same directory and renames
// over the target. A single rm-then-write anywhere reopens the window where a
// missing mount source makes Docker create a directory and kill the container.
func checkWriteCredentialIsTheOnlyWriter(t *testing.T, files []sourceFile) []problem {
	writers := []string{"os.WriteFile(", "os.Create(", "os.OpenFile("}
	var found []problem
	for _, f := range files {
		if f.dir != "internal/guard" || strings.HasSuffix(f.rel, "/write.go") {
			continue
		}
		for i, line := range codeLines(t, f) {
			for _, writer := range writers {
				if strings.Contains(line, writer) {
					found = append(found, problem{f.rel, i + 1, fmt.Sprintf(
						"calls %s; credential writes go through WriteCredential so they "+
							"replace by rename (spec §6)", writer)})
				}
			}
		}
	}
	return found
}

func TestWriteCredentialIsTheOnlyWriterInTheGuard(t *testing.T) {
	clean(t, checkWriteCredentialIsTheOnlyWriter(t, sourceFiles(t)))
	catches(t, checkWriteCredentialIsTheOnlyWriter(t, []sourceFile{planted("internal/guard", `package guard

func save() {
	os.WriteFile("/creds/recv.macaroon", nil, 0o600)
}
`)}), "replace by rename")
}

// isPackage reports whether imported is want or a subpackage of it.
func isPackage(imported, want string) bool {
	return imported == want || strings.HasPrefix(imported, want+"/")
}

// goModSource returns go.mod's bytes.
//
// Two rules read it. The LND rule below scans the RAW text, comments included,
// so this deliberately returns bytes rather than a parsed model.
func goModSource(t *testing.T) []byte {
	t.Helper()
	gomod, err := os.ReadFile(filepath.Join(moduleRoot(t), "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	return gomod
}

func checkLNDModuleDependency(src []byte) []problem {
	// ADR 0001: the LND protos are vendored and the stubs generated into this
	// module. Importing github.com/lightningnetwork/lnd would drag in ~170
	// modules and force this module onto lnd's forked google.golang.org/protobuf.
	var found []problem
	for i, line := range strings.Split(string(src), "\n") {
		if strings.Contains(line, "github.com/lightningnetwork/lnd") {
			found = append(found, problem{"go.mod", i + 1, fmt.Sprintf(
				"depends on the lnd module: %q (it drags in cgo, which CGO_ENABLED=0 forbids)",
				strings.TrimSpace(line))})
		}
	}
	return found
}

func TestGoModDoesNotDependOnTheLNDModule(t *testing.T) {
	clean(t, checkLNDModuleDependency(goModSource(t)))
	catches(t, checkLNDModuleDependency([]byte(`module x

require github.com/lightningnetwork/lnd v0.18.0
`)), "depends on the lnd module")
}

// The go-nostr fork, named exactly (bead bym).
//
// go-nostr v0.52.3's Relay.close() cancels the connection context and then reads
// a field the writer goroutine nils on that same cancellation — a nil-pointer
// dereference inside the library, in a process that handles payments. The fork
// carries that fix and nothing else. Full reasoning: spec §1, "go-nostr is now a
// pinned fork, and upstream is gone".
//
// The version is the EXACT string, not a shape. A rule that only checked the
// shape would pass unchanged after `go get github.com/davotoula/go-nostr@<any
// other commit>` — which rewrites go.mod and go.sum together and silently
// changes what `go build` compiles. Bumping the pin should cost a test edit,
// because the exit here is a migration (BrollyZap-o34.18), not a stream of bumps.
const (
	upstreamGoNostr  = "github.com/nbd-wtf/go-nostr"
	forkedGoNostr    = "github.com/davotoula/go-nostr"
	forkedGoNostrPin = "v0.52.4-0.20260824010951-b11ed5448845"

	// goNostrGoModHash is UPSTREAM v0.52.3's own go.mod hash, and the fork's must
	// still equal it. It is the one fact about the fork's CONTENTS that can be
	// checked offline: a matching hash proves the fork changed no module path, no
	// Go floor, and — the point — added no dependency of its own, which is the
	// shape a "one-line fix" fork goes bad in.
	goNostrGoModHash = "h1:4avYoc9mDGZ9wHsvCOhHH9vPzKucCfuYBtJUSpHTfNk="
)

// go.mod carries exactly one replace, and it is the fork at the pinned commit.
//
// A replace silently swaps what the compiler sees, so it is the line in go.mod a
// reader most needs to be able to trust. Parsed with modfile rather than scanned:
// this package already deleted a hand-rolled scanner for the same reason (see
// workflow_test.go), and a rule that mis-parses does not error, it passes
// vacuously.
// 0vk.39: the `go` directive's minor tracks the `toolchain` line's.
//
// WHY THE LANGUAGE VERSION IS LOAD-BEARING HERE, which is not obvious. Under
// GOTOOLCHAIN=local — which both Dockerfiles set, so the image's own Go compiles
// and the digest pin actually determines the compiler — a `toolchain` line is
// INERT. Only the `go` directive can refuse a Go older than it asks for.
// Measured: `go 1.27.0` on a base shipping go1.26.8 fails with "go.mod requires
// go >= 1.27.0 (running go 1.26.8; GOTOOLCHAIN=local)", while `go 1.25.0` on the
// same base builds silently.
//
// That refusal is the ONLY guard on the publish path. publish.yml builds and
// pushes the images without running the gate at all — no `needs:`, no make
// target from it, not even a setup-go — so `make toolchain-floor` never sees a
// release. The `go` directive does, because it is enforced inside the build.
//
// HERE RATHER THAN IN THAT SCRIPT, deliberately. This is a pure go.mod-internal
// invariant needing no network, and the script needs the registry. Left there it
// would evaporate during a Docker Hub outage — exit 2, could-not-check — taking
// the publish path's only guard with it. A guard that is absent exactly when the
// network is having a bad day is not one. The script keeps the half that
// genuinely needs the wire: floor == the Go the digest ships.
//
// MINOR, not patch: the `go` directive names a language version and has no
// business tracking a patch release. The toolchain line pins the patch.
func checkLanguageVersionTracksToolchain(src []byte) []problem {
	parsed, err := modfile.Parse("go.mod", src, nil)
	if err != nil {
		return []problem{{"go.mod", 0, "does not parse: " + err.Error()}}
	}
	if parsed.Go == nil {
		return []problem{{"go.mod", 0, "has no `go` directive"}}
	}
	if parsed.Toolchain == nil {
		return []problem{{"go.mod", 0, "has no `toolchain` line, so the floor is unstated"}}
	}
	lang := goMinor(parsed.Go.Version)
	tool := goMinor(strings.TrimPrefix(parsed.Toolchain.Name, "go"))
	if lang != tool {
		return []problem{{"go.mod", 0, fmt.Sprintf(
			"`go %s` and `toolchain %s` name different minors (%s vs %s); under "+
				"GOTOOLCHAIN=local only the `go` directive can refuse a base image older "+
				"than the language version, and it is the only guard on the publish path",
			parsed.Go.Version, parsed.Toolchain.Name, lang, tool)}}
	}
	return nil
}

// goMinor takes major.minor off a Go version, tolerating a bare "1.27".
func goMinor(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return version
	}
	return parts[0] + "." + parts[1]
}

func TestTheLanguageVersionTracksTheToolchain(t *testing.T) {
	clean(t, checkLanguageVersionTracksToolchain(goModSource(t)))

	// The decay case, and the reason this is a rule rather than a comment: the
	// next base-image bump moves the toolchain line — scripts/toolchain_floor.py
	// forces that — and leaving the language version behind puts the build
	// quietly back to where it was before 0vk.39, with nothing to say so.
	catches(t, checkLanguageVersionTracksToolchain(
		[]byte("module m\n\ngo 1.25.0\n\ntoolchain go1.27.1\n")), "different minors")
	// And the other direction, which would pass a rule written as "the go
	// directive is not behind": both stated, still disagreeing.
	catches(t, checkLanguageVersionTracksToolchain(
		[]byte("module m\n\ngo 1.28.0\n\ntoolchain go1.27.1\n")), "different minors")
	catches(t, checkLanguageVersionTracksToolchain(
		[]byte("module m\n\ngo 1.27.0\n")), "no `toolchain` line")
}

func checkGoNostrReplace(src []byte) []problem {
	parsed, err := modfile.Parse("go.mod", src, nil)
	if err != nil {
		return []problem{{"go.mod", 0, "does not parse: " + err.Error()}}
	}
	if len(parsed.Replace) != 1 {
		// Named, not printed as []*Replace: %v on a slice of pointers prints
		// addresses, and a failure message nobody can read is a rule that fires
		// and still leaves the reader to go and look.
		var lines []string
		for _, r := range parsed.Replace {
			lines = append(lines, fmt.Sprintf("go.mod:%d %s => %s %s",
				r.Syntax.Start.Line, r.Old.Path, r.New.Path, r.New.Version))
		}
		return []problem{{"go.mod", 0, fmt.Sprintf(
			"carries %d replace directives, want exactly 1 (the %s fork):\n\t%s",
			len(parsed.Replace), forkedGoNostr, strings.Join(lines, "\n\t"))}}
	}
	got := parsed.Replace[0]
	line := got.Syntax.Start.Line
	var found []problem
	if got.Old.Path != upstreamGoNostr {
		found = append(found, problem{"go.mod", line, fmt.Sprintf(
			"replaces %q; the only module this repository replaces is %q",
			got.Old.Path, upstreamGoNostr)})
	}
	if got.New.Path != forkedGoNostr {
		found = append(found, problem{"go.mod", line, fmt.Sprintf(
			"replaces with %q, want %q — a replace pointing anywhere else is an "+
				"unreviewed substitution of a dependency", got.New.Path, forkedGoNostr)})
	}
	if got.New.Version != forkedGoNostrPin {
		found = append(found, problem{"go.mod", line, fmt.Sprintf(
			"pins %s at %q, want %q. Changing the pin changes what go build compiles; "+
				"update this constant in the same commit so the change is reviewed",
			got.New.Path, got.New.Version, forkedGoNostrPin)})
	}
	// Criterion in its own right, and it is what makes the constant above safe to
	// read as a commit: a tag or a branch would satisfy the equality check too.
	if !module.IsPseudoVersion(got.New.Version) {
		found = append(found, problem{"go.mod", line, fmt.Sprintf(
			"pins %s at %q, which is not a pseudo-version. A branch or a tag can be moved "+
				"by whoever owns the fork; a commit hash names bytes that cannot change",
			got.New.Path, got.New.Version)})
	}
	return found
}

func TestGoModReplacesOnlyTheGoNostrForkAndPinsItByCommit(t *testing.T) {
	clean(t, checkGoNostrReplace(goModSource(t)))

	catches(t, checkGoNostrReplace([]byte("module x\n\ngo 1.25\n")),
		"want exactly 1")
	catches(t, checkGoNostrReplace([]byte("module x\n\ngo 1.25\n\nreplace "+
		upstreamGoNostr+" => "+forkedGoNostr+" v9.9.9\n")),
		"not a pseudo-version")
	catches(t, checkGoNostrReplace([]byte("module x\n\ngo 1.25\n\nreplace "+
		"example.com/other => example.com/fork "+forkedGoNostrPin+"\n")),
		"the only module this repository replaces")
}

// The fork's go.mod is byte-identical to upstream's, so it added no dependency.
//
// The replace rule above guards WHICH commit is pinned. This guards what that
// commit may contain — the half that actually carries supply-chain risk — as far
// as anything offline can: go.sum records a hash of the module's own go.mod, and
// upstream v0.52.3's is a constant. If the fork ever gains a require, changes its
// module path, or raises its Go floor, that hash moves and this fails.
func checkGoNostrForkGoModHash(gosum []byte) []problem {
	want := forkedGoNostr + " " + forkedGoNostrPin + "/go.mod "
	for _, line := range strings.Split(string(gosum), "\n") {
		if hash, ok := strings.CutPrefix(line, want); ok {
			if hash != goNostrGoModHash {
				return []problem{{"go.sum", 0, fmt.Sprintf(
					"the fork's go.mod hashes to %s, upstream v0.52.3's to %s — the fork has "+
						"changed its own go.mod, so it is no longer only the close() fix",
					hash, goNostrGoModHash)}}
			}
			return nil
		}
	}
	return []problem{{"go.sum", 0, fmt.Sprintf(
		"has no %q line; this rule asserts nothing, which is worse than failing", want)}}
}

func TestTheGoNostrForkAddsNoDependencyOfItsOwn(t *testing.T) {
	gosum, err := os.ReadFile(filepath.Join(moduleRoot(t), "go.sum"))
	if err != nil {
		t.Fatalf("reading go.sum: %v", err)
	}
	clean(t, checkGoNostrForkGoModHash(gosum))

	// Both ways it can rot: the fork grows a dependency of its own...
	catches(t, checkGoNostrForkGoModHash([]byte(
		forkedGoNostr+" "+forkedGoNostrPin+"/go.mod h1:something-else=\n")),
		"changed its own go.mod")
	// ...and the line disappearing entirely, which would otherwise make the
	// rule pass by having nothing to check.
	catches(t, checkGoNostrForkGoModHash([]byte("example.com/x v1.0.0/go.mod h1:abc=\n")),
		"asserts nothing")
}

// Spec §12: logs go to stdout only, and the app must not manage log files or
// rotation itself. That is enforced by centralising logger construction: only
// internal/logging builds a handler, and it writes to an io.Writer its caller
// supplies — the binaries supply os.Stdout and nothing else opens a file.
func checkLoggerConstruction(t *testing.T, files []sourceFile) []problem {
	constructors := []string{"slog.New(", "slog.NewJSONHandler(", "slog.NewTextHandler("}
	var found []problem
	for _, f := range files {
		for i, line := range codeLines(t, f) {
			for _, c := range constructors {
				if strings.Contains(line, c) {
					found = append(found, problem{f.rel, i + 1, fmt.Sprintf(
						"calls %s; only internal/logging may build a logger (spec §12)", c)})
				}
			}
		}
	}
	return found
}

func TestOnlyTheLoggingPackageConstructsALogger(t *testing.T) {
	clean(t, checkLoggerConstruction(t, sourceFiles(t, "internal/logging")))
	catches(t, checkLoggerConstruction(t, []sourceFile{planted("internal/api", `package api

import "log/slog"

var private = slog.New(slog.NewJSONHandler(nil, nil))
`)}), "only internal/logging may build a logger")
}

// vz1.3: nothing under internal/ reads slog's default logger except
// internal/logging, which owns the one sanctioned reader.
//
// Several components take a *slog.Logger and fall back when a caller passes
// nil. Until this rule that fallback was slog.Default() written out six times,
// and slog's own default is plain text on stderr, deaf to LOG_LEVEL — §12 says
// JSON on stdout. Wave 16 shipped exactly that in the relay pool, and NO UNIT
// TEST COULD HAVE CAUGHT IT: every test passes its own logger in, so the
// fallback is the one line the suite never exercises. It was found by reading
// the regtest stack's output.
//
// cliboot.Start now calls slog.SetDefault at boot, which makes the fallback
// correct wherever it is taken. This is the other half: one reader, so a new
// package cannot quietly acquire a private one and no test will notice.
//
// slog.SetDefault is a different string and deliberately not matched — setting
// the default is the fix, not the problem.
func checkDefaultLoggerReaders(t *testing.T, files []sourceFile) []problem {
	var found []problem
	for _, f := range files {
		if !strings.HasPrefix(f.rel, "internal/") {
			continue
		}
		for i, line := range codeLines(t, f) {
			if strings.Contains(line, "slog.Default()") {
				found = append(found, problem{f.rel, i + 1,
					"falls back to slog's default logger; call logging.Default() " +
						"so there is one reader, and see why in its doc (§12, vz1.3)"})
			}
		}
	}
	return found
}

func TestOnlyTheLoggingPackageReadsTheDefaultLogger(t *testing.T) {
	clean(t, checkDefaultLoggerReaders(t, sourceFiles(t, "internal/logging")))
	catches(t, checkDefaultLoggerReaders(t, []sourceFile{planted("internal/nostr", `package nostr

func fallback() {
	opts.Log = slog.Default()
}
`)}), "one reader")
}

// Spec §3 and §5: only wallet.Spender may consult or mutate the balance.
// internal/store owns the SQL and internal/wallet is the seam; everything else
// goes through Spender or not at all.
func checkBalanceReach(t *testing.T, files []sourceFile) []problem {
	// ".BalanceMsat(" is a call, not a mention: a view struct may legitimately
	// have a field of that name holding a number the wallet already handed it.
	reaching := []string{".BalanceMsat(", "balance_entries"}
	// codeLines, not the raw source: this rule fired on a §12 comment explaining
	// why a ceiling move needs an audit event, and prose about a rule is not a
	// breach of it. A rule that punishes explanation teaches people to stop
	// explaining.
	var found []problem
	for _, f := range files {
		for i, line := range codeLines(t, f) {
			for _, r := range reaching {
				if strings.Contains(line, r) {
					found = append(found, problem{f.rel, i + 1, fmt.Sprintf(
						"reaches %s; nothing outside internal/wallet may consult or mutate "+
							"the balance — go through wallet.Spender (spec §3, §5, §16)", r)})
				}
			}
		}
	}
	return found
}

func TestOnlyTheWalletReachesTheBalance(t *testing.T) {
	clean(t, checkBalanceReach(t, sourceFiles(t, "internal/store", "internal/wallet")))
	catches(t, checkBalanceReach(t, []sourceFile{planted("internal/api", `package api

func peek() {
	n, _ := db.BalanceMsat(ctx)
	_ = n
}
`)}), "go through wallet.Spender")
}

// Spec §5 invariant 3: balance_entries is append-only. No row is ever updated
// or deleted; a correction is a new adjustment txn with a note. The history of
// how the balance reached its current value is the audit trail, and an UPDATE
// erases it.
func checkBalanceEntriesAppendOnly(t *testing.T, files []sourceFile) []problem {
	mutating := regexp.MustCompile(`(?is)(update|delete\s+from)\s+balance_entries`)
	var found []problem
	for _, f := range files {
		// Code, not prose: a comment saying "we never UPDATE balance_entries"
		// states the rule and would otherwise break it.
		if match := mutating.FindString(strings.Join(codeLines(t, f), "\n")); match != "" {
			found = append(found, problem{f.rel, 0, fmt.Sprintf(
				"contains %q; balance_entries is append-only and a correction is a new "+
					"adjustment entry, never an edit (spec §5)",
				strings.Join(strings.Fields(match), " "))})
		}
	}
	return found
}

func TestBalanceEntriesAreAppendOnly(t *testing.T) {
	clean(t, checkBalanceEntriesAppendOnly(t, sourceFiles(t)))
	catches(t, checkBalanceEntriesAppendOnly(t, []sourceFile{planted("internal/store", `package store

const fix = `+"`"+`UPDATE balance_entries SET amount_msat = 0`+"`"+`
`)}), "append-only")
}

// Spec §12, and `t0b`: every writer to the durable trail is CLASSIFIED, and a
// new one cannot be added without saying which it is.
//
// THE RULE HAD AN EXEMPTION NOBODY DECIDED. Measured at `c1e3fa2`: two writers
// bounded their remote-triggerable events by the hour and two did not — abandoned
// zap receipts and the guard's rejections — and the second pair had no bound
// because nothing said the rule was general, not because anyone judged them safe.
// Both were driven by strangers, and both EVICT: §12's trail trims to 10 000 rows
// and the guard's ring holds 32, so an unbounded writer lets somebody who is not
// the operator flush `macaroon.bake` — the row most needed after an incident.
//
// So the next writer gets classified rather than assumed. A file that records
// security events must appear below with either a bound or a stated reason a
// stranger cannot drive it.
type auditWriter struct {
	file string
	// bounded says this file's remote-triggerable events go through a
	// logging.RefusalBudget. The rule checks that the file actually references
	// one, so the classification cannot be aspirational.
	bounded bool
	// why is the reason an unbounded writer is safe. Required when !bounded, and
	// it is prose on purpose: the judgement is what a later reader needs.
	why string
}

var auditWriters = []auditWriter{
	{file: "internal/nostr/pool.go", bounded: true},
	// Every audit write in internal/nwc goes through auditBounded here, so this
	// one entry covers three events. connection.refuse is d24.14's capability
	// boundary on the refusals budget; nwc.panic and connection.pause are
	// `xmc`'s, on a separate panics budget so that a flood of refusals from one
	// paired client cannot spend the allowance that would have recorded the
	// first panic.
	{file: "internal/nwc/outcome.go", bounded: true},
	{file: "internal/zap/publish.go", bounded: true},
	{file: "internal/guard/spend.go", bounded: true},
	{file: "internal/guard/spendcap.go", bounded: true},
	// `06v`'s ceremony, on its OWN budget rather than the refusals one: every
	// event here is server-drivable at will — ask for an authorisation, offer a
	// wrong code, lower a cap by one msat — and a flood of those must not spend
	// the allowance that would have recorded the guard.reject for the bake the
	// same server then attempted.
	{file: "internal/guard/operator.go", bounded: true},
	{file: "internal/guard/guard.go", why: "bakes and rotations. A bake is caused by the " +
		"operator enabling sending, by the renewal tick, or by the node rejecting a credential " +
		"— none of which a stranger can drive faster than the guard's own MinBakeInterval and " +
		"wouldRepeatItself allow. That refusal is itself audited and bounded in spend.go."},
	{file: "internal/api/server.go", why: "sign-ins, setting changes and connection lifecycle, " +
		"all behind the admin session. The one unauthenticated path — a failed sign-in — is " +
		"rate-limited per client by §7's admin limiter before it reaches here."},
	{file: "internal/wallet/wallet.go", why: "one event, and it is the app auditing an " +
		"adjustment it made to ITSELF: a payment whose route cost more than was reserved. " +
		"A remote party can ask for a payment, but not for LND to exceed the fee_limit_msat " +
		"it was given — so the rate is the node's own defect rate, which is zero on a healthy " +
		"install and a thing to go and look at when it is not."},
	{file: "internal/recon/recon.go", why: "the reconciler's own schedule. It runs on a ticker " +
		"the operator's configuration sets and records at most one shortfall per pass; nothing " +
		"a remote party sends changes how often it runs."},
	{file: "cmd/brollyzapper/main.go", why: "startup and the domain self-probe. The first runs " +
		"once per process; the second is on the app's own timer, and its result is recorded " +
		"whether it succeeded or failed, so a stranger who breaks the probe changes the row's " +
		"content and not its rate."},
}

func checkAuditWritersAreClassified(t *testing.T, files []sourceFile) []problem {
	// Both mechanisms: the server's Auditor and the guard's own relayed ring
	// (§16 gives the guard no database, so it cannot use the Auditor).
	writes := regexp.MustCompile(`\.Record\(|g\.audit\(`)
	declared := map[string]auditWriter{}
	for _, w := range auditWriters {
		declared[w.file] = w
	}
	// PER PACKAGE, not per file: a budget is a field on the type that does the
	// writing, and the write itself is usually a few files away from where the
	// bound is held. internal/guard keeps its budget on the Guard and consults
	// it from two files; internal/nwc holds it on the Service.
	bounded := map[string]bool{}
	for _, f := range files {
		if strings.Contains(string(f.src), "RefusalBudget") {
			bounded[f.dir] = true
		}
	}
	var found []problem
	for _, f := range files {
		body := strings.Join(codeLines(t, f), "\n")
		// The definitions themselves are not writers.
		if f.dir == "internal/logging" || !writes.MatchString(body) {
			continue
		}
		w, ok := declared[f.rel]
		switch {
		case !ok:
			found = append(found, problem{f.rel, 0,
				"writes to §12's durable trail and is not classified in auditWriters. Say " +
					"whether its events are BOUNDED (a logging.RefusalBudget) or why a " +
					"stranger cannot drive them — the trail is a fixed ring, and an " +
					"unbounded remote-triggerable writer evicts macaroon.bake (t0b)"})
		case w.bounded && !bounded[f.dir]:
			found = append(found, problem{f.rel, 0,
				"is classified as bounded and references no logging.RefusalBudget; the " +
					"classification is aspirational"})
		case !w.bounded && strings.TrimSpace(w.why) == "":
			found = append(found, problem{f.rel, 0,
				"is classified as unbounded with no reason given"})
		}
	}
	return found
}

func TestEveryAuditWriterIsClassified(t *testing.T) {
	files := sourceFiles(t)
	clean(t, checkAuditWritersAreClassified(t, files))

	// EVERY DECLARED FILE MUST STILL WRITE. Without this the table is a list of
	// exemptions that outlive their files: rename a writer and its entry keeps
	// covering a path that no longer exists, while the renamed one is unclassified
	// — which is precisely how the audit rule's predecessor came to exempt a whole
	// package and left every guard event log-only for three waves.
	writes := regexp.MustCompile(`\.Record\(|g\.audit\(`)
	for _, w := range auditWriters {
		i := slices.IndexFunc(files, func(f sourceFile) bool { return f.rel == w.file })
		if i < 0 {
			t.Errorf("%s is classified as an audit writer and does not exist", w.file)
			continue
		}
		if !writes.MatchString(strings.Join(codeLines(t, files[i]), "\n")) {
			t.Errorf("%s is classified as an audit writer and writes no audit events; the "+
				"classification is covering nothing, and whatever replaced it is unclassified",
				w.file)
		}
	}

	// A new writer, unclassified.
	catches(t, checkAuditWritersAreClassified(t, []sourceFile{planted("internal/relay", `package relay

func shout(ctx context.Context) {
	_ = auditor.Record(ctx, slog.LevelWarn, "something", logging.EventGuardReject)
}
`)}), "not classified")
}

// §14 forbids `rpcmiddleware.addmandatory` BY NAME, and this is that rule.
//
// It looks like the stronger setting and is the dangerous one: with it, LND
// blocks EVERY RPC when the named middleware is absent — so a guard that died
// would take down every other app on the node, not just this one. The property
// P4 actually wants is already there without it: a macaroon carrying a custom
// caveat with no middleware registered is rejected on its own, and nothing else
// is touched.
//
// Checked across the whole tree, not just Go: the place it would plausibly be
// added is a compose file's LND command line, which is exactly where regtest's
// `--rpcmiddleware.enable` lives.
func checkNoMandatoryMiddleware(t *testing.T, files []sourceFile) []problem {
	var found []problem
	for _, f := range files {
		// CODE, NOT PROSE — the same trap the balance-entries rule sets and
		// steps over. Both internal/lnd/middleware.go and the regtest compose
		// file explain in a COMMENT why this flag is not used, and a rule that
		// matched those would fire on the very writing that keeps it true.
		if strings.Contains(withoutComments(t, f), "addmandatory") {
			found = append(found, problem{f.rel, 0,
				"mentions rpcmiddleware.addmandatory; §14 forbids it by name — it blocks ALL " +
					"RPC on the node when the middleware is absent, so a guard that died would " +
					"take every other app down with it. The per-caveat fail-closed behaviour " +
					"is already the property we want."})
		}
	}
	return found
}

func TestTheMandatoryMiddlewareFlagIsNeverUsed(t *testing.T) {
	clean(t, checkNoMandatoryMiddleware(t, append(sourceFiles(t), deploymentFiles(t)...)))
	catches(t, checkNoMandatoryMiddleware(t, []sourceFile{{
		rel: "regtest/docker-compose.yml",
		src: []byte("      - --rpcmiddleware.addmandatory=brollyguard\n"),
	}}), "forbids it by name")
}

// withoutComments is codeLines for Go and a `#`-stripper for everything else,
// which here means YAML.
func withoutComments(t *testing.T, f sourceFile) string {
	t.Helper()
	if strings.HasSuffix(f.rel, ".go") {
		return strings.Join(codeLines(t, f), "\n")
	}
	var out []string
	for _, line := range strings.Split(string(f.src), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// deploymentFiles are the compose files, which sourceFiles does not walk — it
// reads Go only. They are where an LND command line lives, so they are where a
// rule about an LND flag has to look.
func deploymentFiles(t *testing.T) []sourceFile {
	t.Helper()
	root := moduleRoot(t)
	var out []sourceFile
	for _, rel := range []string{
		"regtest/docker-compose.yml",
		"regtest/docker-compose.build.yml",
		"umbrel/brollyzapper/docker-compose.yml",
	} {
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		out = append(out, sourceFile{rel: rel, dir: path.Dir(rel), path: rel, src: src})
	}
	return out
}

// BrollyZap-dsi: nothing DELETES an NWC connection, and revocation is an UPDATE.
//
// This is a FINDING RECORDED, not safety machinery. Migration 0012 refused to
// commit against a database holding rows whose connection was gone, and the
// obvious repair — ON DELETE CASCADE on the two child tables — would have meant
// another table rebuild, the exact operation that caused the outage, to guard a
// path that does not exist: `foreign_keys(1)` has been in the DSN since Wave 1,
// so a delete that orphaned children would have FAILED rather than succeeded
// quietly, and revocation is `UPDATE nwc_connections SET revoked = 1`.
//
// Dead safety machinery reads to the next person as though the hazard is live.
// So instead the absence is pinned here: if someone adds a delete, the orphan
// question is raised at that moment — with `txns.nwc_connection_id` and
// `nwc_handled_requests.connection_id` to answer for — rather than at a future
// migration, on an operator's box, as a server that will not start.
func checkNWCConnectionsAreNeverDeleted(t *testing.T, files []sourceFile) []problem {
	deleting := regexp.MustCompile(`(?is)delete\s+from\s+nwc_connections`)
	var found []problem
	for _, f := range files {
		// Code and SQL, not prose: a comment saying "we never delete a
		// connection" states the rule and would otherwise break it.
		if match := deleting.FindString(strings.Join(codeLines(t, f), "\n")); match != "" {
			found = append(found, problem{f.rel, 0, fmt.Sprintf(
				"contains %q; revoking a pairing is an UPDATE, and deleting one would orphan "+
					"its txns and nwc_handled_requests rows — which is what stopped the server "+
					"starting in BrollyZap-dsi. If this is deliberate, decide what happens to "+
					"the children first (payments are never deleted).",
				strings.Join(strings.Fields(match), " "))})
		}
	}
	return found
}

func TestNWCConnectionsAreRevokedAndNeverDeleted(t *testing.T) {
	clean(t, checkNWCConnectionsAreNeverDeleted(t, sourceFiles(t)))
	catches(t, checkNWCConnectionsAreNeverDeleted(t, []sourceFile{planted("internal/store", `package store

const gone = `+"`"+`DELETE FROM nwc_connections WHERE id = ?`+"`"+`
`)}), "orphan")
}

// Spec §5: max_fee is ONE number. Reserve, the §8 budget check and
// SendPaymentV2's fee_limit_msat must all see the same value, so the settings
// that define it are readable in exactly one package. A second computation
// elsewhere would need these keys.
func checkFeeComputation(t *testing.T, files []sourceFile) []problem {
	feeSettings := []string{"max_fee_floor_msat", "max_fee_ppm"}
	// Comments are stripped first: the rule is about code that READS these
	// keys, and prose explaining why a neighbouring value is not settings-backed
	// is not a second fee computation. Same treatment as the public-mux and
	// auditor rules.
	var found []problem
	for _, f := range files {
		for i, line := range codeLines(t, f) {
			for _, key := range feeSettings {
				if strings.Contains(line, key) {
					found = append(found, problem{f.rel, i + 1, fmt.Sprintf(
						"reads %s; max_fee is computed once, in internal/wallet (spec §5)", key)})
				}
			}
		}
	}
	return found
}

func TestOnlyTheWalletComputesTheFee(t *testing.T) {
	clean(t, checkFeeComputation(t, sourceFiles(t, "internal/wallet")))
	catches(t, checkFeeComputation(t, []sourceFile{planted("internal/api", `package api

const key = "max_fee_ppm"
`)}), "computed once")
}

// Spec §12: redaction is structural, not disciplinary. Every field that holds a
// secret is typed secret.String, which is the only type in the tree that can
// refuse to serialise itself. A field named like a secret but typed as a plain
// string is exactly the regression this catches.
func checkSecretBearingFields(t *testing.T, files []sourceFile) []problem {
	// Names that mean "this holds a secret".
	secretish := []string{"password", "secret", "privkey", "privatekey", "preimage", "macaroon"}
	// ...unless the field is a location rather than the value itself.
	locationSuffixes := []string{"file", "path", "dir", "socket"}
	// Only these types can carry the value at all. A bool saying a macaroon
	// exists, or a time saying when it expires, is not the macaroon.
	carriers := []string{"string", "[]byte", "[]string"}

	fset := token.NewFileSet()
	// lnrpc is generated from LND's protos, secret is where the type is
	// defined, and lndtest is a fake node whose whole job is letting a test
	// inspect the credentials it was sent.
	var found []problem
	for _, file := range files {
		f, err := parser.ParseFile(fset, file.path, file.src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", file.rel, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			for _, field := range st.Fields.List {
				for _, name := range field.Names {
					lower := strings.ToLower(name.Name)
					isSecret := slices.ContainsFunc(secretish, func(s string) bool { return strings.Contains(lower, s) })
					isLocation := slices.ContainsFunc(locationSuffixes, func(s string) bool { return strings.HasSuffix(lower, s) })
					fieldType := typeString(field.Type)
					if !isSecret || isLocation || !slices.Contains(carriers, fieldType) {
						continue
					}
					if fieldType != "secret.String" {
						found = append(found, problem{file.rel, fset.Position(name.Pos()).Line,
							fmt.Sprintf("field %s is typed %s; a secret-bearing field must be "+
								"secret.String so it cannot serialise itself (spec §12)",
								name.Name, fieldType)})
					}
				}
			}
			return true
		})
	}
	return found
}

func TestSecretBearingFieldsUseTheRedactingType(t *testing.T) {
	clean(t, checkSecretBearingFields(t, sourceFiles(t,
		"internal/lnd/lnrpc", "internal/lnd/lndtest", "internal/secret")))
	catches(t, checkSecretBearingFields(t, []sourceFile{planted("internal/api", `package api

type creds struct {
	AdminPassword string
	MacaroonPath  string
	HasMacaroon   bool
}
`)}), "must be secret.String")
}

// §12: a struct that HOLDS a secret must be able to redact itself.
//
// The rule above makes the field a secret.String, which stops the secret from
// being printed. This is the other half, and §12 states it as a requirement
// rather than a suggestion — "every type holding a secret must implement
// slog.LogValuer" — because slog.Any on such a struct otherwise emits every
// OTHER field in full. store.NWCConnection was the first violation, and §12 uses
// that very type as its worked example.
//
// A rule and not a review note because the trigger is adding a field, which is
// the least conspicuous edit there is.
func TestEverySecretBearingStructRedactsItself(t *testing.T) {
	clean(t, checkSecretBearingStructsRedact(t, sourceFiles(t, "internal/secret")))
	catches(t, checkSecretBearingStructsRedact(t, []sourceFile{planted("internal/store", `package store

type pairing struct {
	Name   string
	Secret secret.String
}
`)}), "implements no LogValue")
}

// checkSecretBearingStructsRedact finds structs with a secret.String field and
// asserts the same package declares LogValue on that type.
//
// Package-scoped rather than file-scoped: Go allows the method anywhere in the
// package, and requiring the same file would fail a type whose methods live in a
// methods.go, which is a style this tree uses elsewhere.
func checkSecretBearingStructsRedact(t *testing.T, files []sourceFile) []problem {
	type decl struct {
		file string
		line int
	}
	bearers := map[string]map[string]decl{} // dir -> type -> where
	redacts := map[string]map[string]bool{} // dir -> type

	fset := token.NewFileSet()
	for _, f := range files {
		file, err := parser.ParseFile(fset, f.path, f.src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", f.rel, err)
		}
		for _, d := range file.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					for _, field := range st.Fields.List {
						if typeString(field.Type) != "secret.String" {
							continue
						}
						if bearers[f.dir] == nil {
							bearers[f.dir] = map[string]decl{}
						}
						bearers[f.dir][ts.Name.Name] = decl{f.rel, fset.Position(ts.Pos()).Line}
					}
				}
			case *ast.FuncDecl:
				if d.Name.Name != "LogValue" || d.Recv == nil || len(d.Recv.List) != 1 {
					continue
				}
				name := strings.TrimPrefix(typeString(d.Recv.List[0].Type), "*")
				if redacts[f.dir] == nil {
					redacts[f.dir] = map[string]bool{}
				}
				redacts[f.dir][name] = true
			}
		}
	}

	var found []problem
	for dir, types := range bearers {
		for name, at := range types {
			if redacts[dir][name] {
				continue
			}
			found = append(found, problem{at.file, at.line, fmt.Sprintf(
				"%s holds a secret.String and implements no LogValue; §12 requires the type "+
					"to redact itself, or slog.Any on it emits every other field in full",
				name)})
		}
	}
	slices.SortFunc(found, func(a, b problem) int { return strings.Compare(a.String(), b.String()) })
	return found
}

// typeString renders a field's type well enough to compare against
// "secret.String"; anything more exotic is reported as-is and fails.
func typeString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return typeString(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + typeString(t.X)
	case *ast.ArrayType:
		return "[]" + typeString(t.Elt)
	default:
		return fmt.Sprintf("%T", expr)
	}
}

// Spec §11, criterion 4: the public group must have no auth path at all —
// not auth that happens to pass, but no session lookup on that mux. The file
// that builds it mentions no auth machinery, and its constructor takes no Auth,
// so there is nothing there to conditionally skip.
// publicSurface is every file that builds or serves the public group. The list is hand-kept
// and each entry is checked to exist, because the previous version named ONE
// file — and when P2 added a second public-surface file, the rule went on
// reporting healthy while covering half of what it claimed. A rule that
// narrows silently is worse than one that was never written.
var publicSurface = []string{"internal/api/routes.go", "internal/api/lnurl.go"}

func checkPublicMuxAuth(t *testing.T, files []sourceFile) []problem {
	authMachinery := []string{"Auth", "Session", "CSRF", "csrf", "session", "Password"}

	var found []problem
	for _, f := range files {
		if !slices.Contains(publicSurface, f.rel) {
			continue
		}
		for i, line := range codeLines(t, f) {
			for _, token := range authMachinery {
				if strings.Contains(line, token) {
					found = append(found, problem{f.rel, i + 1, fmt.Sprintf(
						"mentions %q; the public group is built with no auth of any kind, "+
							"and a conditional skip is what erodes (spec §11)", token)})
				}
			}
		}
	}
	return found
}

func TestThePublicMuxHasNoAuthPath(t *testing.T) {
	files := sourceFiles(t)
	clean(t, checkPublicMuxAuth(t, files))

	// Each named file must exist, or the rule narrows in silence.
	for _, want := range publicSurface {
		if !slices.ContainsFunc(files, func(f sourceFile) bool { return f.rel == want }) {
			t.Fatalf("%s is named as public surface and does not exist; the rule is covering "+
				"less than it claims", want)
		}
	}

	// Planted into a file the rule actually watches — a violation anywhere else
	// is not what this rule is about.
	catches(t, checkPublicMuxAuth(t, []sourceFile{{
		rel: "internal/api/routes.go", dir: "internal/api", path: "internal/api/routes.go",
		src: []byte(`package api

func public() {
	if !Session(r) {
		return
	}
}
`),
	}}), "no auth of any kind")
}

// Spec §11: the public group's route set is asserted by equality, so no handler
// on it may mount a mux of its own.
//
// api.Routes exists because "the standard mux cannot be asked which patterns it
// holds". A bare http.NewServeMux behind one of the public prefixes would put
// routes on the anonymous surface that the equality assertion cannot see — which
// is exactly what the first version of the LNURL handler did.
const publicHandlers = "internal/api/lnurl.go"

func checkPublicHandlerMux(t *testing.T, files []sourceFile) []problem {
	var found []problem
	for _, f := range files {
		if f.rel != publicHandlers {
			continue
		}
		for i, line := range codeLines(t, f) {
			if strings.Contains(line, "NewServeMux(") {
				found = append(found, problem{f.rel, i + 1,
					"builds a mux behind a public route; register the patterns on api.Routes " +
						"so the §11 equality assertion counts them"})
			}
		}
	}
	return found
}

func TestNoPublicHandlerMountsAMuxOfItsOwn(t *testing.T) {
	files := sourceFiles(t)
	clean(t, checkPublicHandlerMux(t, files))
	if !slices.ContainsFunc(files, func(f sourceFile) bool { return f.rel == publicHandlers }) {
		t.Fatalf("%s does not exist; the rule is not running", publicHandlers)
	}
	catches(t, checkPublicHandlerMux(t, []sourceFile{{
		rel: publicHandlers, dir: "internal/api", path: publicHandlers,
		src: []byte(`package api

var m = http.NewServeMux()
`),
	}}), "register the patterns on api.Routes")
}

// Spec §12: a security event is written to the log AND to the durable trail —
// "alongside the log line, never instead of it", because log rotation must not
// be able to erase the answer to "when did sending get enabled, and by whom?".
//
// Building the audit attribute by hand writes only the line. So only
// internal/logging may do it, and everything else goes through logging.Auditor,
// which writes both.
//
// The guard cannot use the Auditor — §16 gives it no mount for the server's
// database and must not — so it has exactly one sanctioned way of its own,
// Guard.audit in internal/guard/audit.go, which writes the line AND the durable
// copy the server collects over the socket (§12, d46.18). The exemption is that
// ONE FILE and not the package: a guard component that reaches for
// logging.Audit directly is precisely how audit_events came to hold no
// macaroon.bake on a box where the guard had plainly logged one.
const guardsOwnAuditor = "internal/guard/audit.go"

func checkAuditAttributeBuilders(t *testing.T, files []sourceFile) []problem {
	var found []problem
	for _, f := range files {
		if f.rel == guardsOwnAuditor {
			continue
		}
		for i, line := range codeLines(t, f) {
			if !strings.Contains(line, "logging.Audit(") {
				continue
			}
			where := "use logging.Auditor (spec §12)"
			if f.dir == "internal/guard" || f.dir == "cmd/brollyguard" {
				where = "use Guard.audit, or the event reaches no durable trail (spec §12, §16)"
			}
			found = append(found, problem{f.rel, i + 1,
				"builds an audit attribute directly, which writes the log line and not the " +
					"durable trail; " + where})
		}
	}
	return found
}

func TestOnlyTheAuditorWritesSecurityEvents(t *testing.T) {
	files := sourceFiles(t, "internal/logging")
	clean(t, checkAuditAttributeBuilders(t, files))

	// The exemption has to name a file that exists, or the rule quietly stops
	// covering the one package it was written for.
	var exempt int
	for _, f := range files {
		if f.rel == guardsOwnAuditor {
			exempt++
		}
	}
	if exempt != 1 {
		t.Fatalf("found %d files named %s; the exemption names a file that does not exist",
			exempt, guardsOwnAuditor)
	}

	catches(t, checkAuditAttributeBuilders(t, []sourceFile{planted("internal/api", `package api

func note() {
	log.Warn("something", logging.Audit(logging.EventAuthFail))
}
`)}), "durable trail")
}

// CORS is set only by the public group's own middleware (BrollyZap-z60).
//
// The header itself is unremarkable — the LNURL endpoints are unauthenticated
// and meant to be fetched by any wallet. The SCOPE is the safety-critical part.
// api.NewAdminMux takes everything not explicitly public, including unknown
// paths, so an Access-Control-Allow-Origin reachable from the admin group makes
// a session-authenticated surface cross-origin readable — an account-takeover
// vector in an app whose threat model already treats the server as the
// component under attack.
//
// PER FUNCTION rather than per file, and that distinction is the whole rule.
// routes.go owns BOTH halves: publicHeaders and adminHeaders sit forty lines
// apart in it. A file-level exemption would therefore bless the one edit most
// likely to happen — someone told "we need a CORS header" opens routes.go,
// finds adminHeaders' four h.Set calls, and adds a fifth. That is the shape
// this repository has already been bitten by, and the relays rule below says so
// in the same words.
//
// CASE-INSENSITIVE, because http.Header.Set canonicalises: a lowercase
// "access-control-allow-origin" is byte-identical on the wire and is exactly
// what a paste from a curl trace, a devtools "copy as", or the bug report that
// prompted this fix would carry.
const corsSetters = "internal/api/routes.go"

// corsAllowed are the only functions that may name a CORS header: the public
// group's middleware and the preflight it answers with.
var corsAllowed = []string{"publicHeaders", "corsPreflight"}

func checkCORSSites(t *testing.T, files []sourceFile) []problem {
	var found []problem
	for _, f := range files {
		lines := codeLines(t, f)
		var allowed []fn
		if f.rel == corsSetters {
			for _, candidate := range functions(t, f) {
				if slices.Contains(corsAllowed, candidate.name) {
					allowed = append(allowed, candidate)
				}
			}
		}
		for i, line := range lines {
			if !strings.Contains(strings.ToLower(line), "access-control-") {
				continue
			}
			number := i + 1
			if slices.ContainsFunc(allowed, func(a fn) bool {
				return number >= a.from && number <= a.to
			}) {
				continue
			}
			found = append(found, problem{f.rel, number,
				"names a CORS header outside " + strings.Join(corsAllowed, "/") + "; " +
					"cross-origin readability is decided for the PUBLIC GROUP at the " +
					"composition point, and a header set anywhere else can land on the " +
					"session-authenticated admin surface"})
		}
	}
	return found
}

func TestOnlyThePublicGroupsMiddlewareSetsCORS(t *testing.T) {
	files := sourceFiles(t)
	clean(t, checkCORSSites(t, files))

	// The exemption must name functions that exist, in a file that exists, or
	// the rule quietly stops covering the two functions it was written for.
	var host *sourceFile
	for _, f := range files {
		if f.rel == corsSetters {
			host = &f
			break
		}
	}
	if host == nil {
		t.Fatalf("%s does not exist; the rule is not running", corsSetters)
	}
	for _, want := range corsAllowed {
		if !slices.ContainsFunc(functions(t, *host), func(a fn) bool { return a.name == want }) {
			t.Errorf("%s exempts %s, which %s does not declare", corsSetters, want, corsSetters)
		}
	}

	// THE PLANT THAT MATTERS: the header added to the ADMIN group's middleware,
	// in the very file the rule exempts. A file-scoped rule would pass this.
	catches(t, checkCORSSites(t, []sourceFile{{
		rel: corsSetters, dir: "internal/api", path: corsSetters, src: []byte(`package api

func publicHeaders(next http.Handler) http.Handler { return next }

func corsPreflight(w http.ResponseWriter, _ *http.Request) {}

func adminHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(w, r)
	})
}
`)}}), "admin surface")

	// And the lowercase spelling, which Header.Set canonicalises for you.
	catches(t, checkCORSSites(t, []sourceFile{planted("internal/api", `package api

func serveWallet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("access-control-allow-origin", "*")
}
`)}), "admin surface")
}

// Spec §11 and §16: verify TLS properly, and note that the prior art §1 names
// dials with InsecureSkipVerify. Making the string unbuildable is cheaper than
// hoping it never gets pasted in.
func checkTLSVerification(files []sourceFile) []problem {
	var found []problem
	for _, f := range files {
		for i, line := range strings.Split(string(f.src), "\n") {
			if strings.Contains(line, "InsecureSkipVerify") {
				found = append(found, problem{f.rel, i + 1,
					"mentions InsecureSkipVerify; TLS is verified against the " +
						"credential volume's tls.cert, always (spec §11, §16)"})
			}
		}
	}
	return found
}

func TestNothingSkipsTLSVerification(t *testing.T) {
	clean(t, checkTLSVerification(sourceFiles(t, "internal/lnd/lnrpc")))
	// Raw source, not code lines: this rule reads the bytes on purpose, so even
	// a mention in a comment counts.
	catches(t, checkTLSVerification([]sourceFile{planted("internal/lnd", `package lnd

var conf = &tls.Config{InsecureSkipVerify: true}
`)}), "InsecureSkipVerify")
}

// Spec §11: the server must never crash-loop. Umbrel's rules require an app to
// surface setup, retrying and degraded states instead — so the packages below
// api/web have no business terminating the process at all. The guard's bounded
// exit for macaroon rotation lives in cmd/brollyguard, which is why only
// internal/ is scanned.
func checkProcessTermination(t *testing.T, files []sourceFile) []problem {
	terminators := []string{"log.Fatal", "os.Exit(", "panic("}
	var found []problem
	for _, f := range files {
		if !strings.HasPrefix(f.dir, "internal/") {
			continue
		}
		// codeLines, not the raw source: this rule used to read comments too,
		// so a comment EXPLAINING why panic is unavailable here tripped it.
		// That is the same defect the balance rule had in wave 6, fixed there
		// and not propagated — a rule that cannot be written about is a rule
		// whose reasoning has to live somewhere else.
		for i, line := range codeLines(t, f) {
			for _, term := range terminators {
				if strings.Contains(line, term) {
					found = append(found, problem{f.rel, i + 1, fmt.Sprintf(
						"calls %s; failures below api/web become a state and a retry, "+
							"never an exit (spec §6, §11)", term)})
				}
			}
		}
	}
	return found
}

func TestNoInternalPackageTerminatesTheProcess(t *testing.T) {
	clean(t, checkProcessTermination(t, sourceFiles(t, "internal/lnd/lnrpc")))
	catches(t, checkProcessTermination(t, []sourceFile{planted("internal/store", `package store

func open() {
	if err != nil {
		os.Exit(1)
	}
}
`)}), "never an exit")
}

// Spec §6: subscribe ONCE to the invoice stream for the process lifetime. A
// second call site would double-deliver every settlement and race the resume
// point, and the runtime guard in RunInvoiceStream cannot see a caller that
// bypasses it.
// checkInvoiceSubscriptionSites reports every call site. "Exactly one" is the
// caller's assertion, because the count it wants differs between the real tree
// (one) and a planted file (two).
func checkInvoiceSubscriptionSites(t *testing.T, files []sourceFile) []problem {
	var found []problem
	for _, f := range files {
		for i, line := range codeLines(t, f) {
			if strings.Contains(line, ".SubscribeInvoices(") {
				found = append(found, problem{f.rel, i + 1,
					"subscribes to invoices; there is exactly one such call site (spec §6)"})
			}
		}
	}
	return found
}

func TestExactlyOneInvoiceSubscriptionCallSite(t *testing.T) {
	real := checkInvoiceSubscriptionSites(t, sourceFiles(t, "internal/lnd/lnrpc"))
	if len(real) != 1 {
		t.Errorf("found %d SubscribeInvoices call sites (%v), want exactly 1 (spec §6)",
			len(real), real)
	}
	// A second one is the violation: two subscriptions mean two streams and two
	// resume points over one settle_index.
	catches(t, checkInvoiceSubscriptionSites(t, []sourceFile{planted("internal/api", `package api

func watch() {
	s, _ := client.SubscribeInvoices(ctx, nil)
	_ = s
}
`)}), "exactly one such call site")
}

// 1yp and nok: NOTHING calls go-nostr's publish fan-out any more, and the door
// stays shut.
//
// SimplePool.PublishMany dials-and-sends as one unit per URL, and both of this
// wave's findings walked through that round trip. It re-checks IsConnected
// through EnsureRelay and re-dials a dropped socket under a hardcoded fifteen
// seconds off the POOL's context — bounded by neither connectBudget nor the
// caller's — under a fifty-bucket hash lock held across the connect. And by
// answering only with a URL and an error it gave this app no way to ask the
// question nok turns on: the library returns a NIL error when the connection
// dies before the OK, so a relay that took the frame and vanished read as
// accepted, and internal/zap recorded a receipt for it.
//
// Pool.dial now hands back the *Relay it stored and publishOne sends on that
// handle. The rule is here rather than as a comment because the fan-out is
// still exported, still the obvious thing to reach for, and re-adding it would
// reopen both findings silently — every test in this package would stay green.
//
// The AUTH-REQUIRED RETRY the fan-out offers is not a reason to go back, and
// internal/nostr's publishOne carries that argument — the only WithAuthHandler
// in this tree is the planted violation in
// TestTheRelayPoolIsBuiltWithTheDialAddressCheck, below.
func checkPublishFanOutSites(t *testing.T, files []sourceFile) []problem {
	var found []problem
	for _, f := range files {
		for i, line := range codeLines(t, f) {
			if strings.Contains(line, ".PublishMany(") {
				found = append(found, problem{f.rel, i + 1,
					"calls go-nostr's publish fan-out; publishing goes through the *Relay " +
						"Pool.dial holds, so a dropped socket cannot be silently re-dialled " +
						"for fifteen seconds nor read as an acknowledgement (1yp, nok)"})
			}
		}
	}
	return found
}

// The companion, and the one that actually holds the door shut.
//
// PublishMany IS EnsureRelay plus relay.Publish. Forbidding the fan-out alone
// leaves the hazard reachable one line lower down: `relay, _ := pool.EnsureRelay(
// url); relay.Publish(ctx, event)` re-dials a dropped socket under the library's
// hardcoded fifteen seconds off the POOL's context, holds the fifty-bucket hash
// lock across that connect, and — without publishOne's IsConnected check — reads
// a socket that died before its OK as an acknowledgement. Both findings, reopened
// by a caller who never typed PublishMany, with every test in this package green.
// The gap was found by review; the first version of the rule above had it.
//
// NOTHING CALLS IT AT ALL, as of du9.1, and the last caller left for a reason
// this rule now also carries. Pool.Subscribe used to take its relay from
// EnsureRelay — a subscription waits on no OK, so nok did not reach it, and a
// fifteen-second dial for a socket held open for the life of a pairing looked
// like a different trade. What it could not survive was the STORE: EnsureRelay
// writes the map with a plain Store under a fifty-bucket hash lock, Pool.dial
// writes it with an atomic Compute, and neither serialises against the other. A
// subscribe and a publish dialling one URL at once therefore ended with two live
// sockets and one map entry, and the unmapped one was a websocket plus its ping
// and read goroutines that nothing could ever close — every teardown here walks
// the map. Both doors go through Pool.dial now, so the torn store has no path.
func checkEnsureRelaySites(t *testing.T, files []sourceFile) []problem {
	var found []problem
	for _, file := range files {
		for i, line := range codeLines(t, file) {
			if strings.Contains(line, ".EnsureRelay(") {
				found = append(found, problem{file.rel, i + 1,
					"calls EnsureRelay; every relay this app opens comes from Pool.dial, " +
						"so a dropped socket cannot be silently re-dialled for fifteen " +
						"seconds nor read as an acknowledgement, and one URL cannot end " +
						"up with two live sockets (1yp, nok, du9.1)"})
			}
		}
	}
	return found
}

func TestNothingCallsEnsureRelay(t *testing.T) {
	clean(t, checkEnsureRelaySites(t, sourceFiles(t, "internal/lnd/lnrpc")))

	// A publish path that reaches for it directly, which is what the fan-out
	// rule above does not see.
	catches(t, checkEnsureRelaySites(t, []sourceFile{planted("internal/nostr", `package nostr

func send() {
	relay, _ := p.pool.EnsureRelay(url)
	_ = relay.Publish(ctx, event)
}
`)}), "calls EnsureRelay")
	// And the subscription that was its one legitimate caller until du9.1.
	//
	// It takes the same branch through the scanner as the plant above — this is a
	// per-line text match, so the two differ only in identifier names — and it is
	// here as a RATCHET rather than as coverage. The rule this replaced permitted
	// exactly this shape, and the argument for permitting it (a subscription
	// waits on no OK, so nok does not reach it) survives the reason it was
	// withdrawn (the torn store does). A future author re-narrowing the rule to
	// "no publish may call it" has to delete a failing plant to do it.
	catches(t, checkEnsureRelaySites(t, []sourceFile{planted("internal/nostr", `package nostr

func watch() {
	relay, _ := p.pool.EnsureRelay(normalised)
	_, _ = relay.Subscribe(ctx, filters)
}
`)}), "calls EnsureRelay")
}

func TestNothingCallsTheLibraryPublishFanOut(t *testing.T) {
	clean(t, checkPublishFanOutSites(t, sourceFiles(t, "internal/lnd/lnrpc")))

	catches(t, checkPublishFanOutSites(t, []sourceFile{planted("internal/nostr", `package nostr

func send() {
	for r := range p.pool.PublishMany(ctx, []string{url}, event) {
		_ = r
	}
}
`)}), "publish fan-out")
}

// `xmc` Fix B: there is exactly ONE recover() in this tree, and it is the NWC
// dispatch goroutine's.
//
// WHY IT EXISTS AT ALL. On 2026-08-26 one authorized client sent a request the
// handler could not survive, fifteen times in seven minutes, and each panic took
// the whole process — LNURL, zap receipts and the admin UI — down with it. The
// NWC service shares a process with all of them, so one paired app's malformed
// request was a full outage. Containing it there costs one dropped request.
//
// WHY EXACTLY ONE. Before this there were none anywhere in cmd/ or internal/,
// and the go-nostr fork's own first commit leaned on that fact. A recover is a
// decision that a particular goroutine's death is survivable, and it is only
// true where somebody has thought about what is left behind: here, a request
// that was never claimed and is now audited as dropped. Spread to a second site
// it becomes a general safety net, and the next one will be in a path where
// dying was the correct answer — a half-written balance, an unreleased lock, a
// credential half-rotated.
//
// PARSED, NOT SCANNED. The first version matched the text "recover()" per line,
// and a second FULLY WORKING recover written `recover( /* … */ )` compiled,
// survived gofmt, and left the rule reporting one site — measured, not supposed.
// A rule guarding the one place this codebase is allowed to survive a panic must
// not be defeatable by a comment. Wave 37 made the same change to
// checkPaymentCallSites and the guard's request-shape check, for the same reason.
//
// It does NOT additionally require the call to sit inside a deferred function
// LITERAL, which would be the tighter invariant. `defer s.containPanic(...)`
// defers a method, and the recover is at the top of that method's body — legal,
// and the shape this codebase actually uses — so such a rule would fail the one
// call site it exists to bless.
//
// It reports every site; "exactly one, and it is that one" is the caller's
// assertion, because the count differs between the real tree and a planted file.
func checkRecoverCallSites(t *testing.T, files []sourceFile) []problem {
	fset := token.NewFileSet()
	var found []problem
	for _, f := range files {
		parsed, err := parser.ParseFile(fset, f.path, f.src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", f.rel, err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if name, ok := call.Fun.(*ast.Ident); !ok || name.Name != "recover" {
				return true
			}
			found = append(found, problem{f.rel, fset.Position(call.Pos()).Line,
				"calls recover(); there is exactly one in this tree, in internal/nwc's " +
					"dispatch goroutine, and a second is a general panic handler by " +
					"another name (`xmc`)"})
			return true
		})
	}
	return found
}

func TestExactlyOneRecoverCallSite(t *testing.T) {
	real := checkRecoverCallSites(t, sourceFiles(t, "internal/lnd/lnrpc"))
	if len(real) != 1 || real[0].file != "internal/nwc/run.go" {
		t.Errorf("found %d recover() call sites (%v), want exactly 1 in internal/nwc/run.go. "+
			"A panic is the right answer almost everywhere in this process; the one place it "+
			"is not is a request from a paired client, which must not be able to take the "+
			"whole app down (`xmc`)", len(real), real)
	}
	// The plant is the form that DEFEATED the previous version: a comment inside
	// the parens. A synthetic case written in the friendliest possible shape
	// proves only that the scanner catches cooperative violations.
	catches(t, checkRecoverCallSites(t, []sourceFile{planted("internal/api", `package api

func serve() {
	defer func() {
		if r := recover( /* still a recover */ ); r != nil {
			log.Println("contained", r)
		}
	}()
	handle()
}
`)}), "exactly one in this tree")
}

// Spec §1 and o34.1 criterion 5: go-nostr supplies the nostr primitives, and
// BrollyZapper implements none of them again.
//
// §1 surveyed the libraries and settled this: go-nostr has events, relays,
// NIP-04 and NIP-44, and no nip47 or nip57 — those two are ours. The failure
// this guards is a hand-rolled schnorr, bech32 or event serialiser appearing
// beside a library that already has one, which is how a signature bug gets in.
// ADR 0001's no-new-runtime-dependency stance is the other half: nostr
// primitives come from go-nostr or from the standard library, and from nowhere
// else.
func checkNostrPrimitives(pkgs map[string]*pkg) []problem {
	const module = "github.com/davotoula/brollyzapper/"
	var found []problem
	p, ok := pkgs["internal/nostr"]
	if !ok {
		return []problem{{"internal/nostr", 0, "package does not exist"}}
	}
	for _, imp := range p.imports {
		switch {
		case !strings.Contains(imp, "."):
			continue // standard library
		case strings.HasPrefix(imp, module):
			continue // our own packages
		case strings.HasPrefix(imp, "github.com/nbd-wtf/go-nostr"):
			continue
		default:
			found = append(found, problem{"internal/nostr", 0, fmt.Sprintf(
				"imports %q; nostr primitives come from go-nostr or the standard library "+
					"(spec §1, ADR 0001)", imp)})
		}
	}
	return found
}

func TestNostrPrimitivesComeFromGoNostr(t *testing.T) {
	clean(t, checkNostrPrimitives(packages(t)))
	catches(t, checkNostrPrimitives(map[string]*pkg{
		"internal/nostr": {dir: "internal/nostr",
			imports: []string{"github.com/some/other/nostr"}},
	}), "come from go-nostr")
}

// Spec §3 and o34.1: ONE relay pool for the process lifetime, the same rule as
// the single invoice subscription.
//
// go-nostr's pool reopens and de-duplicates connections, so a second one means
// two sets of sockets to the same relays and two answers to "did this publish"
// — and §7's 24-hour retry is driven by that answer.
// checkRelayPoolConstruction reports every pool construction, ours and
// go-nostr's, and flags any of the latter outside internal/nostr. The counts are
// the caller's assertion, for the same reason as the invoice stream.
func checkRelayPoolConstruction(t *testing.T, files []sourceFile) (ours, theirs []problem) {
	for _, f := range files {
		for i, line := range codeLines(t, f) {
			if strings.Contains(line, "NewSimplePool(") {
				msg := "builds go-nostr's pool"
				if !strings.HasPrefix(f.rel, "internal/nostr/") {
					msg = "builds go-nostr's pool directly; go through internal/nostr so " +
						"there is one place that owns the connections (spec §3)"
				}
				theirs = append(theirs, problem{f.rel, i + 1, msg})
			}
			if strings.Contains(line, "nostr.NewPool(") {
				ours = append(ours, problem{f.rel, i + 1, "constructs the relay pool"})
			}
		}
	}
	return ours, theirs
}

func TestExactlyOneRelayPoolConstructionSite(t *testing.T) {
	ours, theirs := checkRelayPoolConstruction(t, sourceFiles(t))
	if len(ours) != 1 {
		t.Errorf("found %d nostr.NewPool call sites (%v), want exactly 1 (spec §3, o34.1)",
			len(ours), ours)
	}
	if len(theirs) != 1 {
		t.Errorf("found %d go-nostr pool constructions (%v), want exactly 1", len(theirs), theirs)
	}
	for _, p := range theirs {
		if strings.Contains(p.msg, "directly") {
			t.Error(p)
		}
	}

	_, elsewhere := checkRelayPoolConstruction(t, []sourceFile{planted("internal/api", `package api

func second() {
	p := gonostr.NewSimplePool(ctx)
	_ = p
}
`)})
	catches(t, elsewhere, "one place that owns the connections")
}

// vz1.4: the pool is built WITH the dial-time address check, and there is no
// other door onto a relay.
//
// The check is an option. A pool constructed without it connects exactly as
// before and every test in internal/nostr that is not about the dial still
// passes — which is how a security control disappears quietly. The wiring is
// therefore the assertion, not the check's own behaviour, which dialable_test
// covers.
//
// The second half matters as much: gonostr.NewRelay and gonostr.RelayConnect
// build a relay outside the pool, so they carry none of the pool's options and
// their connections would be vetted by nothing.
//
// AMENDED 2026-09-03 (du9). They are no longer forbidden outright; they must
// carry the check themselves. §7's connect budget requires this app to dial a
// relay itself — the library's fifteen-second connect timeout hangs off the
// POOL's context, where no caller can reach it — and SimplePool.relayOptions is
// unexported, so the dialler has to pass WithDialAddressCheck by hand. The rule
// therefore asks the question it always meant to ask, of all three doors: does
// THIS construction carry the check. A NewRelay without it still fails, which is
// the case the flat ban was standing in for.
//
// Through the AST, like checkSecretBearingFields, and NOT by scanning text. The
// real construction spans two lines, so a line-based rule would be satisfied by
// moving the option down one; the first version of this counted parens instead,
// which handles that but miscounts a paren inside a string literal — codeLines
// blanks comments, not strings. A parser sees neither lines nor literals.
func checkDialAddressCheckWiring(t *testing.T, files []sourceFile) []problem {
	// Building a relay outside the pool: it gets none of the pool's options, so
	// it must be given the dial-time check itself.
	bypasses := []string{"gonostr.NewRelay", "gonostr.RelayConnect"}

	fset := token.NewFileSet()
	var found []problem
	for _, file := range files {
		f, err := parser.ParseFile(fset, file.path, file.src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", file.rel, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := typeString(call.Fun)
			line := fset.Position(call.Pos()).Line
			if slices.Contains(bypasses, callee) && !mentions(call, "WithDialAddressCheck") {
				found = append(found, problem{file.rel, line, "calls " + callee +
					" without WithDialAddressCheck; a relay built outside the pool carries " +
					"none of its options, so this one connects to whatever it resolves to " +
					"(vz1.4, amended by du9)"})
			}
			if callee == "gonostr.NewSimplePool" && !mentions(call, "WithDialAddressCheck") {
				found = append(found, problem{file.rel, line,
					"builds the relay pool without WithDialAddressCheck; the dial-time " +
						"address check is an option, so a pool without it connects as before " +
						"and refuses nothing (vz1.4)"})
			}
			return true
		})
	}
	return found
}

// mentions reports whether name appears anywhere inside a call's own subtree —
// however deeply nested in the option arguments, and across as many lines as the
// author cares to spread it over.
func mentions(call *ast.CallExpr, name string) bool {
	seen := false
	ast.Inspect(call, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			seen = true
		}
		return !seen
	})
	return seen
}

func TestTheRelayPoolIsBuiltWithTheDialAddressCheck(t *testing.T) {
	clean(t, checkDialAddressCheckWiring(t, sourceFiles(t)))

	catches(t, checkDialAddressCheckWiring(t, []sourceFile{planted("internal/nostr", `package nostr

func build() {
	p := gonostr.NewSimplePool(ctx,
		gonostr.WithRelayOptions(gonostr.WithAuthHandler(nil)))
	_ = p
}
`)}), "connects as before")

	catches(t, checkDialAddressCheckWiring(t, []sourceFile{planted("internal/api", `package api

func direct() {
	r, _ := gonostr.RelayConnect(ctx, "wss://relay.example")
	_ = r
}
`)}), "outside the pool")

	// du9: the same, for the door this app now uses itself. A relay built by
	// hand WITHOUT the check is the violation; one built WITH it is the shipped
	// shape of Pool.dial and must stay clean.
	catches(t, checkDialAddressCheckWiring(t, []sourceFile{planted("internal/nostr", `package nostr

func dial() {
	r := gonostr.NewRelay(context.Background(), url)
	_ = r
}
`)}), "outside the pool")

	clean(t, checkDialAddressCheckWiring(t, []sourceFile{planted("internal/nostr", `package nostr

func dial() {
	r := gonostr.NewRelay(context.Background(), url,
		gonostr.WithDialAddressCheck(p.checkDialAddress))
	_ = r
}
`)}))

	// No false positive on the shapes a real author writes: the option spread
	// over several lines, and a string literal carrying an unbalanced paren —
	// the two cases the text-scanning version of this rule got wrong.
	clean(t, checkDialAddressCheckWiring(t, []sourceFile{planted("internal/nostr", `package nostr

func build() {
	p := gonostr.NewSimplePool(
		ctx,
		gonostr.WithRelayOptions(
			gonostr.WithDialAddressCheck(check),
		),
	)
	_ = p
}
`)}))
	clean(t, checkDialAddressCheckWiring(t, []sourceFile{planted("internal/nostr", `package nostr

func build() {
	p := gonostr.NewSimplePool(ctx, label("a relay :-) ("),
		gonostr.WithRelayOptions(gonostr.WithDialAddressCheck(check)))
	_ = p
}
`)}))
}

// §5, d24.2: the store's spend methods are reachable only through the wallet.
//
// This is the rule the ceiling actually rests on. internal/wallet.Reserve is
// where THREE separate protections live — the reconciliation freeze, the
// positive-amount checks, and (from d24.2) the requirement that every outbound
// payment carry its payment hash — and every one of them is bypassed by calling
// store.ReserveSpend directly. The store cannot enforce them: it has no view of
// recon and its payment_hash column is nullable.
//
// So "the wallet is the only caller" was true, and nothing made it stay true.
// TestOnlyTheWalletReachesTheBalance is the neighbouring rule and matches only
// .BalanceMsat( and balance_entries, which leaves this door open.
// storeBindingNames are the identifiers anything in the tree binds to a
// *store.Store — `db` in cmd/brollyzapper, a field of that name on a service.
//
// It is what lets the rule below name METHODS rather than raw strings: the wallet
// deliberately re-words most of what it wraps (Unresolvable, AssertOutcome,
// MarkUnresolvable), but NoteResolveAttempt and ClearResolveAttempts it passes
// through under the same names — so `purse.NoteResolveAttempt(ctx, id)` at
// cmd/brollyzapper/payments.go:475 is the sanctioned path and
// `db.NoteResolveAttempt(...)` two lines away would not be. A rule matching the
// method name alone cannot tell those apart and would fail on correct code.
//
// Over-approximate on purpose: ANY identifier ever bound to a *store.Store
// counts, everywhere. A variable that merely shares the name is a false
// positive in the direction of asking a person to look.
func storeBindingNames(t *testing.T, files []sourceFile) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	fset := token.NewFileSet()
	note := func(fieldNames []*ast.Ident, typ ast.Expr) {
		if typeString(typ) != "*store.Store" {
			return
		}
		for _, n := range fieldNames {
			names[n.Name] = true
		}
	}
	for _, file := range files {
		f, err := parser.ParseFile(fset, file.path, file.src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", file.rel, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch decl := n.(type) {
			case *ast.Field: // struct fields and function parameters
				note(decl.Names, decl.Type)
			case *ast.ValueSpec: // var and const declarations
				note(decl.Names, decl.Type)
			}
			return true
		})
	}
	return names
}

// checkSpendMethodCallSites reports the store's money methods being called
// outside internal/store and internal/wallet.
//
// This is the rule the ceiling actually rests on. internal/wallet.Reserve is
// where THREE separate protections live — the reconciliation freeze, the
// positive-amount checks, and (from d24.2) the requirement that every outbound
// payment carry its payment hash — and every one of them is bypassed by calling
// store.ReserveSpend directly. The store cannot enforce them: it has no view of
// recon and its payment_hash column is nullable.
//
// WHAT BELONGS ON THIS LIST, because a by-name list goes stale by construction
// and the next person adding a method is the one who has to know: a store method
// that MOVES MONEY OR CLOSES A RESERVATION, plus the two that are confined for a
// different reason — HasUnresolvedPaymentsBefore is the freeze's own query
// (u0u), and UnresolvablePayments decides which rows an operator may close,
// which is a wallet decision and not a second reader's.
//
// `669` (wave 34) added five and none was listed until `b9k`; `0vk.1` planted a
// compiling call to store.AssertPaymentOutcome — a write to balance_entries on a
// human's assertion — in internal/api and all 41 rules passed. Deriving this list
// from the store's SQL instead was tried and rejected: it MISSES the methods that
// write through a helper, ReserveSpend and AdjustBalance among them, which is
// incomplete in the direction that looks complete. What the derivation is good
// for is a lower bound that fails — see TestEveryStoreMoneyWriterIsClassified,
// and `b9k` for the measurements.
// spendMethods is the list itself, at package scope so the test can plant EVERY
// entry rather than sampling one: a list is exactly the thing that goes stale,
// and a synthetic case covering two of ten would not have caught `b9k` either.
var spendMethods = []string{
	// Moves money.
	"ReserveSpend", "SettleSpend", "ReverseSpend", "MarkSpendDispatched",
	"AssertPaymentOutcome", "AdjustBalance", "CreditSettledInvoice",
	// Decides a reservation's disposition.
	"MarkPaymentUnresolvable", "NoteResolveAttempt", "ClearResolveAttempts",
	"ClearSpendDispatched",
	// Confined for the reasons above rather than because they write.
	"HasUnresolvedPaymentsBefore", "UnresolvablePayments",
}

// exemptStoreWriters write one of the money tables and are deliberately NOT
// confined to the wallet. Each entry is a decision, and the reason is the entry.
var exemptStoreWriters = map[string]string{
	"RecordZapReceipt": "writes a receipt's event id onto a txn row and moves no money; " +
		"internal/zap owns receipt publication and is the only caller",
}

// storeWriters derives, from the store's own SQL, the exported *Store methods
// whose body writes one of the money tables.
//
// A LOWER BOUND and not the whole set: a method that writes through a helper —
// ReserveSpend and AdjustBalance both do — has no INSERT of its own to find.
// That is why this does not replace the hand-kept list. What it does is make the
// list's staleness FAIL rather than sit there: a future wave adding a method
// with inline SQL, which is how `669` added five, cannot leave it unclassified.
func storeWriters(t *testing.T, files []sourceFile) map[string]string {
	t.Helper()
	writes := regexp.MustCompile(`(?is)(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+` + "`?" + `(txns|balance_entries)\b`)
	out := map[string]string{}
	fset := token.NewFileSet()
	for _, file := range files {
		if file.dir != "internal/store" {
			continue
		}
		parsed, err := parser.ParseFile(fset, file.path, file.src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", file.rel, err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil || !fn.Name.IsExported() {
				continue
			}
			if typeString(fn.Recv.List[0].Type) != "*Store" {
				continue
			}
			start := fset.Position(fn.Body.Pos()).Offset
			end := fset.Position(fn.Body.End()).Offset
			if writes.MatchString(string(file.src[start:end])) {
				out[fn.Name.Name] = file.rel
			}
		}
	}
	return out
}

func checkSpendMethodCallSites(t *testing.T, files []sourceFile) []problem {
	allowed := []string{"internal/store", "internal/wallet"}
	stores := storeBindingNames(t, files)

	fset := token.NewFileSet()
	var found []problem
	for _, f := range files {
		if slices.Contains(allowed, f.dir) {
			continue
		}
		parsed, err := parser.ParseFile(fset, f.path, f.src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", f.rel, err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !slices.Contains(spendMethods, sel.Sel.Name) {
				return true
			}
			// `db.X()` or `s.db.X()` — the receiver's own last name is what
			// says whether this is the store.
			receiver := ""
			switch x := sel.X.(type) {
			case *ast.Ident:
				receiver = x.Name
			case *ast.SelectorExpr:
				receiver = x.Sel.Name
			}
			if !stores[receiver] {
				return true
			}
			found = append(found, problem{f.rel, fset.Position(call.Pos()).Line,
				"calls " + sel.Sel.Name + " on the store directly; the ceiling's protections — " +
					"the two spending freezes and the payment-hash requirement — live in " +
					"internal/wallet, and the store cannot enforce them (spec §5)"})
			return true
		})
	}
	return found
}

// §5, `b9k`: every store method that writes money is CLASSIFIED — confined to
// the wallet, or exempt with a reason.
//
// This is the half of `b9k` that closes the class rather than the instance.
// Wave 34's `669` added five methods on the money path and none reached the
// confined list; nothing failed, because a hand-kept list cannot notice what is
// missing from it. The list is still hand-kept — see storeWriters for why a
// derivation cannot replace it — but a method that writes txns or
// balance_entries in its own SQL now has to be put in one of the two buckets
// before the gate is green.
func TestEveryStoreMoneyWriterIsClassified(t *testing.T) {
	writers := storeWriters(t, sourceFiles(t))
	if len(writers) == 0 {
		t.Fatal("no store writers were found; this rule would pass vacuously")
	}
	for method, file := range writers {
		if slices.Contains(spendMethods, method) || exemptStoreWriters[method] != "" {
			continue
		}
		t.Errorf("%s: %s writes a money table and is neither confined to internal/wallet "+
			"(spendMethods) nor exempt with a reason (exemptStoreWriters). §5 makes the wallet "+
			"the one place the ceiling's protections live; a new writer is a decision about "+
			"that, not an oversight to leave for the next reader", file, method)
	}
	// An exemption for a method that no longer exists is a decision nobody made
	// about code nobody has.
	for method := range exemptStoreWriters {
		if _, ok := writers[method]; !ok {
			t.Errorf("exemptStoreWriters names %s, which writes no money table any more; "+
				"delete the exemption with the code", method)
		}
	}

	// Planted: `669` again — a new method with inline SQL, classified nowhere.
	planted := storeWriters(t, []sourceFile{planted("internal/store", `package store

func (s *Store) CreditSomethingNew(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "UPDATE balance_entries SET amount_msat = 1")
	return err
}
`)})
	if _, found := planted["CreditSomethingNew"]; !found {
		t.Error("the derivation did not see a method writing balance_entries in its own SQL, " +
			"so the classification above is checking nothing")
	}
}

func TestOnlyTheWalletMovesAReservation(t *testing.T) {
	clean(t, checkSpendMethodCallSites(t, sourceFiles(t)))

	// The plant DECLARES its store, because that is what the rule keys on: a
	// method name alone cannot be the test, since the wallet passes two of these
	// through under the same names.
	catches(t, checkSpendMethodCallSites(t, []sourceFile{planted("cmd/brollyzapper", `package main

type app struct {
	db *store.Store
}

func pay(a *app) {
	id, _ := a.db.ReserveSpend(ctx, 1000, 10, "", "ref")
	_ = id
}
`)}), "cannot enforce them")

	// EVERY entry, not a sample. `b9k` was five names missing from a list, so a
	// synthetic case that plants two of them proves the rule works for two.
	for _, method := range spendMethods {
		catches(t, checkSpendMethodCallSites(t, []sourceFile{planted("internal/api", `package api

func reach(db *store.Store) {
	_ = db.`+method+`(ctx)
}
`)}), method)
	}

	// AND THE NEGATIVE HALF, which is why this rule reads the receiver. The
	// wallet re-words most of what it wraps but passes NoteResolveAttempt and
	// ClearResolveAttempts through under the same names, so the sanctioned call
	// at cmd/brollyzapper/payments.go:475 looks identical to a forbidden one. A
	// rule that matched the name alone would fail on correct code.
	clean(t, checkSpendMethodCallSites(t, []sourceFile{planted("cmd/brollyzapper", `package main

func resolve(purse wallet.Spender, id wallet.ReservationID) error {
	_, err := purse.NoteResolveAttempt(ctx, id)
	return err
}
`)}))
}

// §5, §6, d24.2: there is exactly ONE place a payment is sent, and exactly two
// places a reservation is reversed.
//
// Neither proves the sequence Reserve-then-Send — that is not checkable at this
// level, and a rule that half-checked it would buy false confidence. What they
// do is reduce the proof to reading one function, which is what these rules are
// for. The reversal count is the sharper of the two: §6 says a
// reserved-but-unresolved payment must never be silently reversed, and a THIRD
// Reverse call site is precisely the edit that would do it.
// importedPackages are the identifiers this file's imports bind, so a call on
// one can be told from a method call on a value of ours.
func importedPackages(f *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, spec := range f.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := path[strings.LastIndex(path, "/")+1:]
		if spec.Name != nil {
			name = spec.Name.Name
		}
		out[name] = true
	}
	return out
}

// checkPaymentCallSites finds every place a payment is sent and every place a
// reservation is reversed.
//
// PARSED, NOT SCANNED (`7sp`). This read lines and skipped any containing
// "func ", to avoid counting a declaration as a call. That also skipped a call
// inside a ONE-LINE BODY, and `0vk.1` measured what it cost: appending
//
//	func plantedOneLiner() error { return notPendingIsFine(purse.Reverse(ctx, id)) }
//
// to cmd/brollyzapper/payments.go compiled, and the rule passed — a third
// reversal site, the exact edit §6 forbids, uncounted by the rule that exists to
// see it. The repository had already ruled on this shape one day earlier, when
// wave 36's template rule stopped scraping templates with a regex: a parser
// tells a *ast.CallExpr from a *ast.FuncDecl by construction, so the problem
// stops existing rather than being narrowed by a third string test.
//
// A call on an imported PACKAGE is not one of ours — slices.Reverse is the
// collision that matters, and it takes a slice rather than a reservation. The
// tree calls neither today; the exclusion is what lets it, without the rule
// quietly counting it as a reversal.
func checkPaymentCallSites(t *testing.T, files []sourceFile) (sends, reverses []problem) {
	fset := token.NewFileSet()
	for _, file := range files {
		f, err := parser.ParseFile(fset, file.path, file.src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", file.rel, err)
		}
		packages := importedPackages(f)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if receiver, ok := sel.X.(*ast.Ident); ok && packages[receiver.Name] {
				return true
			}
			line := fset.Position(call.Pos()).Line
			switch sel.Sel.Name {
			case "SendPayment":
				sends = append(sends, problem{file.rel, line, "sends a payment"})
			case "Reverse":
				reverses = append(reverses, problem{file.rel, line, "reverses a reservation"})
			}
			return true
		})
	}
	return sends, reverses
}

func TestThePaymentAndReversalCallSitesArePinned(t *testing.T) {
	sends, reverses := checkPaymentCallSites(t, sourceFiles(t))

	if len(sends) != 1 || sends[0].file != "cmd/brollyzapper/payments.go" {
		t.Errorf("found %d SendPayment call sites (%v), want exactly 1 in "+
			"cmd/brollyzapper/payments.go — every payment goes through payInvoice, which is "+
			"what reserves first (spec §5)", len(sends), sends)
	}
	// Both in payments.go: the live path's FAILED arm, and the resolver's
	// not-found arm. A third is a new answer to "when may we reverse", which is
	// the question §6 answers.
	if len(reverses) != 2 {
		t.Errorf("found %d Reverse call sites (%v), want exactly 2 — a reserved-but-unresolved "+
			"payment must never be silently reversed (spec §6), so a new one is a deliberate "+
			"act that needs its reasoning written down", len(reverses), reverses)
	}
	for _, r := range reverses {
		if r.file != "cmd/brollyzapper/payments.go" {
			t.Error(r)
		}
	}

	// THE SYNTHETIC VIOLATION (0vk.1, Ruling C). This rule reached the security
	// pass as the one rule of the forty-one with no planted case: it counts, and
	// a counting rule that has only ever counted the right number has been
	// written rather than tested. The third reversal is the exact edit §6
	// forbids, and the second send is the one that would put a payment outside
	// payInvoice's reserve-first path.
	//
	// Verified against the REAL tree first, before being written down here: a
	// third `purse.Reverse(ctx, id)` compiled into cmd/brollyzapper/payments.go
	// makes the assertion above fail naming all three sites.
	//
	// THE PLANT CARRIES THE SHAPES THE SCANNER USED TO GET WRONG (`7sp`): a
	// method DECLARATION named Reverse, which must not count; a call in a
	// one-line body, which the string scanner could not see; and slices.Reverse,
	// which is a package function and not a reservation. Three reversals, one
	// declaration, one slice.
	sends, reverses = checkPaymentCallSites(t, []sourceFile{planted("cmd/brollyzapper", `package main

import "slices"

func pay() {
	result, _ := node.SendPayment(ctx, p.bolt11, p.maxFeeMsat)
	_ = result
}

func alsoPay() {
	result, _ := node.SendPayment(ctx, other.bolt11, other.maxFeeMsat)
	_ = result
}

// A DECLARATION, not a call. The rule must not count this, and the string
// scanner this replaced could only avoid counting it by skipping every line
// containing "func " — which is what made a one-line call invisible.
func (w *Wallet) Reverse(ctx context.Context, id ReservationID) error {
	return nil
}

// A ONE-LINE BODY: the shape 7sp measured escaping the old scanner entirely.
func reverseOne() error { return notPendingIsFine(purse.Reverse(ctx, id)) }

// And one on an imported package, which reverses a slice and not a reservation.
func unrelated() {
	slices.Reverse(names)
}

func reverseTwo() error {
	return notPendingIsFine(purse.Reverse(ctx, id))
}

func reverseThree() error {
	return notPendingIsFine(purse.Reverse(ctx, id))
}
`)})
	if len(sends) != 2 {
		t.Errorf("the scanner found %d SendPayment sites in the planted file, want 2; it can no "+
			"longer see a payment being sent, so the count above proves nothing", len(sends))
	}
	if len(reverses) != 3 {
		t.Errorf("the scanner found %d Reverse sites in the planted file, want 3; it can no "+
			"longer see a reservation being reversed, so the count above proves nothing",
			len(reverses))
	}
}

// §6, d24.1: the two RPCs that mint and destroy credentials are reachable only
// from the guard, and every bake asks for URI-SCOPED permissions.
//
// internal/lnd/macaroons.go already says "Only the guard may call this" in
// prose. This wave added a second call site to each, which is the moment to
// make the claim a build failure rather than a sentence.
//
// The URI half is §6's sharpest rule about the credentials themselves:
// `offchain:write` would additionally grant SendToRouteV2 — arbitrary
// self-constructed routes, a probing and draining primitive — plus
// SendPaymentSync and DeleteAllPayments. It is defended today by a unit test on
// the SPEND list, which a third credential would not inherit; this defends the
// call site, so a permission built by hand is caught wherever it appears.
func checkCredentialMintingCallSites(t *testing.T, files []sourceFile) []problem {
	// Reachable only from the guard. lndtest is the fake node — it IMPLEMENTS
	// these RPCs rather than calling them — and internal/lnd is where the client
	// method is defined.
	allowed := []string{"internal/guard", "internal/lnd", "internal/lnd/lndtest"}

	fset := token.NewFileSet()
	var found []problem
	for _, file := range files {
		f, err := parser.ParseFile(fset, file.path, file.src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", file.rel, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := typeString(call.Fun)
			line := fset.Position(call.Pos()).Line
			if !strings.HasSuffix(callee, ".BakeMacaroon") && !strings.HasSuffix(callee, ".DeleteMacaroonID") {
				return true
			}
			if !slices.Contains(allowed, file.dir) {
				found = append(found, problem{file.rel, line, "calls " + callee +
					"; minting and destroying credentials needs admin.macaroon, which only the " +
					"guard holds (spec §3, §6)"})
			}
			if strings.HasSuffix(callee, ".BakeMacaroon") && file.dir == "internal/guard" &&
				!mentions(call, "URIPermissions") {
				found = append(found, problem{file.rel, line,
					"bakes without lnd.URIPermissions; an entity:action pair grants a whole " +
						"family of methods — offchain:write alone adds SendToRouteV2, " +
						"SendPaymentSync and DeleteAllPayments (spec §6)"})
			}
			return true
		})
	}
	return found
}

func TestOnlyTheGuardMintsCredentialsAndOnlyByURI(t *testing.T) {
	// lnrpc is generated from LND's vendored protos: it DECLARES these RPCs and
	// the client/server plumbing for them. It is not a caller, and it is not
	// ours to police — the gate excludes it from gofmt for the same reason.
	clean(t, checkCredentialMintingCallSites(t, sourceFiles(t, "internal/lnd/lnrpc")))

	catches(t, checkCredentialMintingCallSites(t, []sourceFile{planted("internal/api", `package api

func mint() {
	m, _ := node.BakeMacaroon(ctx, lnd.URIPermissions(perms), 1)
	_ = m
}
`)}), "only the guard holds")

	catches(t, checkCredentialMintingCallSites(t, []sourceFile{planted("internal/guard", `package guard

func bake() {
	m, _ := g.node.BakeMacaroon(ctx, []*lnrpc.MacaroonPermission{{Entity: "offchain", Action: "write"}}, 1)
	_ = m
}
`)}), "entity:action pair")
}

// §6, d24.1: nothing under regtest/ speaks the socket API in its own words.
//
// regtest/tools/guardctl exists to drive the guard from the stack, and it goes
// through guard.SocketClient — the SERVER's own side of the wire — so what it
// exercises is production's vocabulary. The failure mode this guards is a tool
// that grows its own `-op` flag and starts constructing requests: the moment
// that happens, "the request carries the operation and nothing else" is being
// tested by something that no longer shares the constraint.
func checkRegtestSpeaksNoRawProtocol(t *testing.T, files []sourceFile) []problem {
	var found []problem
	for _, file := range files {
		if !strings.HasPrefix(file.rel, "regtest/") {
			continue
		}
		for i, line := range codeLines(t, file) {
			if strings.Contains(line, "guard.Request{") || strings.Contains(line, "guard.Op") {
				found = append(found, problem{file.rel, i + 1,
					"builds the guard's wire protocol directly; regtest tooling must go through " +
						"guard.SocketClient so it exercises the server's own side of the socket " +
						"and cannot widen the four-operation API (spec §6)"})
			}
		}
	}
	return found
}

func TestRegtestToolingDoesNotSpeakTheSocketProtocolDirectly(t *testing.T) {
	clean(t, checkRegtestSpeaksNoRawProtocol(t, sourceFiles(t)))

	catches(t, checkRegtestSpeaksNoRawProtocol(t, []sourceFile{planted("regtest/tools/guardctl", `package main

func send(op string) {
	req := guard.Request{Op: guard.Op(op)}
	_ = req
}
`)}), "four-operation API")
}

// vz1.4: regtest tooling that lives in the MAIN module imports nothing but the
// standard library and this module.
//
// regtest/tools/mactool is in the main module deliberately — it works through
// internal/lnd's own caveat encoder, the one the guard bakes real credentials
// with, so that a defect in production's path is a defect it finds. A copy in a
// separate module would prove nothing about production. regtest/tools/zaptool is
// a separate module for the opposite reason: it needs third-party libraries.
//
// That split is safe only while the main-module tools stay dependency-free. One
// third-party import in one of them enters go.mod, ships in `go mod tidy`, and
// joins make vuln's reachable set — for a tool that is never built into either
// binary. Today it is true by accident; this is what makes it a rule.
func checkRegtestToolImports(t *testing.T, files []sourceFile) []problem {
	const module = "github.com/davotoula/brollyzapper/"
	root := moduleRoot(t)

	var found []problem
	for _, file := range files {
		if !strings.HasPrefix(file.rel, "regtest/") || inNestedModule(root, file.dir) {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file.path, file.src, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", file.rel, err)
		}
		for _, spec := range f.Imports {
			imp := strings.Trim(spec.Path.Value, `"`)
			if !strings.Contains(imp, ".") || strings.HasPrefix(imp, module) {
				continue // standard library, or this module
			}
			found = append(found, problem{file.rel, fset.Position(spec.Pos()).Line,
				"imports " + imp + "; regtest tooling in the MAIN module must import only " +
					"the standard library and this module, or it adds a dependency to " +
					"go.mod — and to make vuln's reachable set — for a tool neither binary " +
					"ships. A tool that needs a third-party library belongs in its own " +
					"module, as regtest/tools/zaptool does"})
		}
	}
	return found
}

// inNestedModule reports whether a directory belongs to a module of its own
// rather than to this one.
//
// The walk collects every Go file under the tree, nested modules included, so
// "is this file in MY module" has to be asked rather than assumed. Asked this
// way rather than by naming zaptool: adding a second separate-module tool is
// then automatically out of scope, and moving one INTO the main module puts it
// in scope, which is the actual rule.
func inNestedModule(root, dir string) bool {
	for d := dir; d != "." && d != "/" && d != ""; d = path.Dir(d) {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(d), "go.mod")); err == nil {
			return true
		}
	}
	return false
}

func TestRegtestToolingInTheMainModuleHasNoThirdPartyImports(t *testing.T) {
	clean(t, checkRegtestToolImports(t, sourceFiles(t)))

	catches(t, checkRegtestToolImports(t, []sourceFile{planted("regtest/tools/mactool", `package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func main() { fmt.Println(cobra.Command{}) }
`)}), "belongs in its own module")
}

// z9k/zu5.1: the relay allow-list has exactly ONE definition, and it lives in
// internal/nostr.
//
// reservedPrefixes' contents ARE the security property. The table has already
// been wrong twice — the Wave 8 version checked only the scheme, and the first
// Wave 12 version was missing 100.64.0.0/10, which is CGNAT and therefore every
// Tailscale address — and both times a human re-reading the code is what found
// it, not the suite. reserved_test.go now pins the contents. This pins the
// UNIQUENESS, which is the half a table test cannot cover: a second copy
// somewhere else would pass every test it had and drift on the first tightening.
//
// A rule rather than a comment because internal/nostr/dialable.go says exactly
// this in prose, and "the comment had outrun the code for three waves" is the
// recorded history of the very function it replaced.
//
// internal/preflight is allowed one classification: it is looking for the BOX's
// own LAN address to show the operator, so it wants private ranges rather than
// refusing them — the opposite question, asked of ourselves rather than of a
// stranger's input.
func checkRelayAllowListDefinitions(t *testing.T, files []sourceFile) []problem {
	classifiers := []string{
		"netip.MustParsePrefix(", "IsGlobalUnicast(", "IsLinkLocalUnicast(", "IsPrivate(",
	}
	allowed := map[string]string{
		"internal/nostr/dialable.go":      "the allow-list itself",
		"internal/preflight/preflight.go": "finds the box's own LAN address, the opposite question",
	}
	var found []problem
	for _, f := range files {
		if _, ok := allowed[f.rel]; ok {
			continue
		}
		for i, line := range codeLines(t, f) {
			for _, c := range classifiers {
				if strings.Contains(line, c) {
					found = append(found, problem{f.rel, i + 1, fmt.Sprintf(
						"classifies an IP address with %s; the allow-list a stranger's relay "+
							"is checked against lives in internal/nostr/dialable.go and there "+
							"must be exactly one of it (z9k, zu5.1)", c)})
				}
			}
		}
	}
	return found
}

func TestTheRelayAllowListHasOneDefinition(t *testing.T) {
	clean(t, checkRelayAllowListDefinitions(t, sourceFiles(t)))
	catches(t, checkRelayAllowListDefinitions(t, []sourceFile{planted("internal/lnurl", `package lnurl

var second = netip.MustParsePrefix("100.64.0.0/10")
`)}), "exactly one of it")
}

// Spec §6 (o34.10): exactly one call site may conclude that the node rejected
// our credential, and it is the invoice stream.
//
// The stream qualifies because it carries no caller input and runs for the
// process lifetime: nothing a stranger sends can make it fail, and it notices a
// bad credential within one backoff whether or not anyone is looking. A
// per-request call does not qualify — AddInvoice sits behind the PUBLIC LNURL
// callback and LND reports most handler errors as codes.Unknown, so acting on
// one lets an unauthenticated caller drive the credential broker one
// BakeMacaroon RPC and one macaroon.bake row at a time.
//
// A rule rather than a convention because the next per-request RPC is P3's
// SendPaymentV2, whose ordinary failures — no route, expired invoice,
// insufficient balance — are the archetype of the mistake.
func checkCredentialRejectionSites(t *testing.T, files []sourceFile) (all, offending []problem) {
	for _, f := range files {
		for i, line := range codeLines(t, f) {
			if !strings.Contains(line, "observeStream(") || strings.Contains(line, "func (c *Client)") {
				continue
			}
			p := problem{f.rel, i + 1,
				"concludes the credential was rejected; only the invoice stream may, because " +
					"it is the one LND path no caller can influence (spec §6, o34.10)"}
			all = append(all, p)
			if f.rel != "internal/lnd/stream.go" {
				offending = append(offending, p)
			}
		}
	}
	return all, offending
}

func TestOnlyTheInvoiceStreamConcludesTheCredentialWasRejected(t *testing.T) {
	all, offending := checkCredentialRejectionSites(t, sourceFiles(t))
	if len(all) == 0 {
		t.Fatal("no observeStream call sites at all; the rule is not running")
	}
	clean(t, offending)

	_, elsewhere := checkCredentialRejectionSites(t, []sourceFile{planted("internal/api", `package api

func mint() {
	c.observeStream(err)
}
`)})
	catches(t, elsewhere, "only the invoice stream may")
}

// Spec §3: the dependency runs guard -> lnd, never the other way. internal/lnd
// says what it needs from the guard as a consumer-defined interface
// (CredentialBroker) and cmd/brollyzapper wires the real one in — the same
// shape internal/logging uses for AuditSink.
func checkBackwardsImports(pkgs map[string]*pkg) []problem {
	backwards := map[string]string{
		"internal/lnd":     "internal/guard",
		"internal/logging": "internal/store",
	}
	var found []problem
	for consumer, supplier := range backwards {
		p, ok := pkgs[consumer]
		if !ok {
			found = append(found, problem{consumer, 0, "package does not exist"})
			continue
		}
		for _, imp := range p.imports {
			if isPackage(imp, "github.com/davotoula/brollyzapper/"+supplier) {
				found = append(found, problem{consumer, 0, fmt.Sprintf(
					"imports %s; declare what you need as an interface and let cmd/ wire "+
						"the implementation in (spec §3)", supplier)})
			}
		}
	}
	return found
}

func TestConsumersDeclareTheirOwnInterfacesRatherThanImportingBackwards(t *testing.T) {
	clean(t, checkBackwardsImports(packages(t)))
	catches(t, checkBackwardsImports(map[string]*pkg{
		"internal/lnd": {dir: "internal/lnd",
			imports: []string{"github.com/davotoula/brollyzapper/internal/guard"}},
		"internal/logging": {dir: "internal/logging"},
	}), "declare what you need as an interface")
}

// Review, wave 10. The request-body cap is installed once, by boundBodies at
// the composition point, so that it covers every route rather than every route
// that remembered. That only holds if nothing else reads a request body its own
// way: a bare r.ParseForm(), or an io.ReadAll(r.Body) in a future handler,
// reads whatever the caller chose to send.
//
// readForm is the one sanctioned reader — it classifies 413 against 400 — and
// probe.go's io.ReadAll is on a RESPONSE body, ours, already bounded by its own
// LimitReader.
func checkRequestBodyReaders(t *testing.T, files []sourceFile) []problem {
	readers := []string{"r.ParseForm()", "req.ParseForm()", "ParseMultipartForm(",
		"io.ReadAll(r.Body)", "io.ReadAll(req.Body)"}
	var found []problem
	for _, f := range files {
		if f.dir != "internal/api" || strings.HasSuffix(f.rel, "/form.go") {
			continue
		}
		for i, line := range codeLines(t, f) {
			for _, reader := range readers {
				if strings.Contains(line, reader) {
					found = append(found, problem{f.rel, i + 1, fmt.Sprintf(
						"reads the request body with %s; go through readForm, which is what "+
							"draws the 413-versus-400 line, and note that the cap itself is "+
							"installed for every route by boundBodies (review L6)", reader)})
				}
			}
		}
	}
	return found
}

func TestOnlyReadFormReadsARequestBody(t *testing.T) {
	clean(t, checkRequestBodyReaders(t, sourceFiles(t, "internal/lnd/lnrpc")))
	catches(t, checkRequestBodyReaders(t, []sourceFile{planted("internal/api", `package api

func handle(r *http.Request) {
	r.ParseForm()
}
`)}), "go through readForm")
}

// n7v. lnurl.VerifiedZapRequest is what carries §11's "the signature is checked
// before anything is minted" across the api→lnurl seam, and it carries it as
// proof rather than as a claim: the interface has an unexported method, the
// only implementation is unexported, and the only constructor runs after both
// checks have passed.
//
// The type system already refuses a composite literal or an outside
// implementation — those are build failures, not test failures. What the type
// system cannot see is a SECOND call to the constructor, from somewhere that
// has not verified anything, which would turn the proof back into a label. That
// is what this rule is for.
const zapConstructor = "newVerifiedZapRequest("

// sharedZapCheck is the helper both zap-request paths verify through since
// doy.4, and a CALL to it stands for the two checks it makes.
//
// Without this the rule would read the last CheckSignature/CheckID lines in the
// file, which now sit inside that helper at the TOP of zaprequest.go — above
// every constructor call by construction, so the ordering assertion would be
// satisfied by where the text happens to live rather than by anything true.
const sharedZapCheck = "checkSignedZapRequest("

// checkVerifiedZapRequestConstructor reports the three ways the proof can stop
// being one: an exported constructor, a second call site, or a call that runs
// above the checks it claims to certify.
//
// The call sites are returned too, because "exactly one" is a count the caller
// asserts — the real tree wants one and a planted file wants to see a second.
func checkVerifiedZapRequestConstructor(t *testing.T, files []sourceFile) (calls, found []problem) {
	for _, f := range files {
		lines := codeLines(t, f)
		var callLine, signature, id int
		for i, line := range lines {
			switch {
			case strings.Contains(line, "CheckSignature()"):
				signature = i + 1
			case strings.Contains(line, "CheckID()"):
				id = i + 1
			case strings.Contains(line, sharedZapCheck) &&
				!strings.HasPrefix(strings.TrimSpace(line), "func "+sharedZapCheck):
				signature, id = i+1, i+1
			}
			if strings.Contains(line, "func NewVerifiedZapRequest") {
				found = append(found, problem{f.rel, i + 1,
					"exports a VerifiedZapRequest constructor; the guarantee is that one " +
						"cannot be made outside internal/lnurl"})
			}
			if !strings.Contains(line, zapConstructor) {
				continue
			}
			// The declaration itself, and ONLY it. Skipping every line that
			// begins with "func" was the first attempt, and a planted second
			// call site written as a one-line function slipped straight
			// through it — the rule passed while the violation was in the tree.
			if strings.HasPrefix(strings.TrimSpace(line), "func "+zapConstructor) {
				continue
			}
			calls = append(calls, problem{f.rel, i + 1, "constructs a VerifiedZapRequest"})
			callLine = i + 1
		}
		// Ordering is only meaningful in the file that does both.
		if callLine > 0 && signature > 0 && id > 0 && (callLine < signature || callLine < id) {
			found = append(found, problem{f.rel, callLine, fmt.Sprintf(
				"constructs a VerifiedZapRequest above CheckSignature (line %d) or CheckID "+
					"(line %d); the value would claim a verification that had not happened",
				signature, id)})
		}
	}
	return calls, found
}

// An NWC request is proved before it is read, the same way a zap request is.
//
// §8's durable replay cache is keyed on the event id and the response's e-tag
// carries it, so the id has to be the one the signature covers. go-nostr does
// not give that for free: CheckSignature recomputes the id from the body and
// never compares the ID FIELD, so an event whose id has been rewritten still
// verifies and is still dispatched to a subscription. Whoever last touched the
// event chooses that field — including the relay, the party the cache exists to
// defend against.
//
// A rule rather than a comment because of what arrives next: d24.4 puts
// pay_invoice behind this key, and §8's whole argument for a durable cache is
// that a re-delivered pay_invoice pays twice. The check has to still be there,
// and still be ABOVE the read, when that lands.
func TestAnNWCRequestIsProvedBeforeItIsRead(t *testing.T) {
	files := sourceFiles(t, "")
	// The handler must be FOUND, or every assertion below is about an empty
	// scan. A rule whose subject has been renamed out from under it passes
	// exactly as quietly as one that holds — which is the shape this package's
	// own doc comment records having shipped once.
	if handlers := nwcHandlers(t, files); handlers != 1 {
		t.Fatalf("found %d NWC request handlers, want exactly 1; the rule below is scoped by "+
			"the declaration text and can no longer see its subject", handlers)
	}
	clean(t, checkNWCRequestProof(t, files))

	// One plant per way the proof can rot: dropped, and hoisted below the read.
	catches(t, checkNWCRequestProof(t, []sourceFile{planted("internal/nwc", `package nwc

func (s *Service) handle(ctx context.Context, conn *connection, event *gonostr.Event) (Response, bool) {
	if ok, _ := event.CheckSignature(); !ok {
		return Response{}, false
	}
	s.store.RecordNWCHandled(ctx, event.ID, "")
	return Response{}, true
}
`)}), "does not check the event id")

	catches(t, checkNWCRequestProof(t, []sourceFile{planted("internal/nwc", `package nwc

func (s *Service) handle(ctx context.Context, conn *connection, event *gonostr.Event) (Response, bool) {
	plaintext, err := conn.identity.Decrypt(scheme, event.PubKey, event.Content)
	if !event.CheckID() {
		return Response{}, false
	}
	if ok, _ := event.CheckSignature(); !ok {
		return Response{}, false
	}
	return s.respond(ctx, conn, event, scheme, s.dispatch(ctx, conn, req), true)
}
`)}), "reads the request above")
}

// nwcHandlers counts the declarations checkNWCRequestProof scopes itself by.
func nwcHandlers(t *testing.T, files []sourceFile) int {
	var n int
	for _, f := range files {
		if f.dir != "internal/nwc" {
			continue
		}
		for _, line := range codeLines(t, f) {
			if strings.HasPrefix(strings.TrimSpace(line), "func (s *Service) handle(") {
				n++
			}
		}
	}
	return n
}

// checkNWCRequestProof finds the handler and asserts both checks run above the
// first use of anything the event carries.
//
// Scoped to the function body rather than to the file: the checks are only
// meaningful relative to the read they guard, and a rule that merely asserted
// both strings exist somewhere in the package would pass with them in a helper
// nobody calls.
func checkNWCRequestProof(t *testing.T, files []sourceFile) []problem {
	const handler = "func (s *Service) handle("
	var found []problem
	for _, f := range files {
		if f.dir != "internal/nwc" {
			continue
		}
		lines := codeLines(t, f)
		start := -1
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), handler) {
				start = i
				break
			}
		}
		if start < 0 {
			continue
		}
		var id, signature, read int
		for i := start; i < len(lines); i++ {
			line := lines[i]
			if i > start && strings.HasPrefix(line, "}") {
				break
			}
			switch {
			case strings.Contains(line, "CheckID()"):
				id = i + 1
			case strings.Contains(line, "CheckSignature()"):
				signature = i + 1
			case read == 0 && (strings.Contains(line, "event.ID") ||
				strings.Contains(line, "event.Content") ||
				strings.Contains(line, "event.Tags") ||
				strings.Contains(line, "event.CreatedAt")):
				read = i + 1
			}
		}
		switch {
		case id == 0:
			found = append(found, problem{f.rel, start + 1,
				"handles an NWC request but does not check the event id; the replay cache " +
					"is keyed on a field the signature does not cover"})
		case signature == 0:
			found = append(found, problem{f.rel, start + 1,
				"handles an NWC request but does not check the signature"})
		case read > 0 && (read < id || read < signature):
			found = append(found, problem{f.rel, read,
				fmt.Sprintf("reads the request above CheckID (line %d) or CheckSignature "+
					"(line %d); the proof would be certifying a read that already happened",
					id, signature)})
		}
	}
	return found
}

func TestTheVerifiedZapRequestConstructorRunsOnlyAfterTheChecks(t *testing.T) {
	files := sourceFiles(t, "internal/lnd/lnrpc")
	calls, found := checkVerifiedZapRequestConstructor(t, files)
	clean(t, found)
	if len(calls) != 1 {
		t.Fatalf("%s is called from %d places: %v\n\tExactly one, at the end of "+
			"ParseZapRequest. A second call from anywhere that has not checked the "+
			"signature makes the type a label rather than a proof.",
			zapConstructor, len(calls), calls)
	}
	// Both checks must be present somewhere, or the constructor below them
	// would be certifying nothing.
	var signature, id bool
	for _, f := range files {
		for _, line := range codeLines(t, f) {
			signature = signature || strings.Contains(line, "CheckSignature()")
			id = id || strings.Contains(line, "CheckID()")
		}
	}
	if !signature || !id {
		t.Fatal("the tree no longer checks both the signature and the id")
	}

	// Three plants, one per way the proof can rot.
	_, exported := checkVerifiedZapRequestConstructor(t, []sourceFile{planted("internal/lnurl", `package lnurl

func NewVerifiedZapRequest(r *ZapRequest) VerifiedZapRequest { return nil }
`)})
	catches(t, exported, "cannot be made outside internal/lnurl")

	second, _ := checkVerifiedZapRequestConstructor(t, []sourceFile{planted("internal/lnurl", `package lnurl

func shortcut(r *ZapRequest) VerifiedZapRequest { return newVerifiedZapRequest(r) }
`)})
	if len(second) != 1 {
		t.Errorf("a second call site was not counted: %v", second)
	}

	_, hoisted := checkVerifiedZapRequestConstructor(t, []sourceFile{planted("internal/lnurl", `package lnurl

func parse(e *Event) VerifiedZapRequest {
	v := newVerifiedZapRequest(r)
	if !e.CheckSignature() {
		return nil
	}
	if !e.CheckID() {
		return nil
	}
	return v
}
`)})
	catches(t, hoisted, "verification that had not happened")

	// And the fourth, which only exists since the checks moved into a shared
	// helper: a constructor hoisted above the CALL to that helper. Without the
	// sharedZapCheck arm this file is green — the helper's own CheckSignature
	// line is at the top of zaprequest.go, so it precedes everything.
	_, aboveHelper := checkVerifiedZapRequestConstructor(t, []sourceFile{planted("internal/lnurl", `package lnurl

func parse(e *Event) VerifiedZapRequest {
	v := newVerifiedZapRequest(r)
	if err := checkSignedZapRequest(e); err != nil {
		return nil
	}
	return v
}
`)})
	catches(t, aboveHelper, "verification that had not happened")

	// And the DECLARATION of that helper is not a call to it — the exclusion in
	// the arm above, pinned rather than merely argued in a comment. Without it
	// this file reports a violation that is not one: the declaration below the
	// constructor would be read as the check happening after it.
	_, declarationOnly := checkVerifiedZapRequestConstructor(t, []sourceFile{planted("internal/lnurl", `package lnurl

func parse(r *ZapRequest) VerifiedZapRequest {
	return newVerifiedZapRequest(r)
}

func checkSignedZapRequest(e *Event) error {
	return nil
}
`)})
	clean(t, declarationOnly)
}

// d24.18 condition (ii): nothing derived from the OPERATOR'S relays may reach the
// NWC seams.
//
// §8's rule is that a pairing is served on the relays its own URI named, and
// never on default_relays — because the kind 13194 info event is UNENCRYPTED and
// carries a connection's service pubkey and capabilities, so announcing it beside
// the operator's own zap receipts links every pairing to that operator from one
// IP, defeating the per-connection service key without any key being reused.
//
// THE OLD GUARANTEE WAS NARROWER THAN IT READ. PublishTo took one relay URL, and
// that was described as structural — but it constrains the ARITY of a call, not
// the PROVENANCE of its argument, and
//
//	for _, r := range nostr.DefaultRelays { p.PublishTo(ctx, ev, r) }
//
// satisfied it in four lines. This rule is the half that was missing, and with
// nostr.ConnectionRelays — which the seam now takes, and which a bare []string
// cannot become by accident — the pair is stronger than what it replaced.
//
// PER FUNCTION rather than per file, deliberately. A file-level rule would fire
// on internal/nostr/pool.go, which declares DefaultRelays and defines the publish
// seam a hundred lines apart, and would therefore need that file exempted — and
// an exemption on the very file that owns both halves is the shape this
// repository has been bitten by (the audit rule exempted a whole package and that
// is what let every guard event be log-only for three waves). A function that
// mentions both is a function doing the thing the rule forbids.
//
// WHAT IT CANNOT CATCH, stated rather than left to be discovered. A rule whose
// limits are unwritten gets trusted past them:
//
//   - provenance crossing a function boundary — a helper that returns
//     DefaultRelays, called by a function that reaches a seam;
//   - a package-level `var` or `const` holding the operator's list, since this
//     reads function BODIES only;
//   - a package-level func literal, which is not a FuncDecl;
//   - any spelling of the operator's list other than the three literals below —
//     a struct field or an accessor is invisible.
//
// It is a tripwire on the obvious mistake, not a proof. The type the seam takes
// is the other half: a bare []string cannot reach it by accident, so the
// dangerous version has to be written deliberately, and this catches the
// deliberate version written in one place.
func checkOperatorRelaysReachNoPairing(t *testing.T, files []sourceFile) []problem {
	// The operator's own list, in every spelling it has: the constant, its alias
	// in internal/api, the parser that reads the setting, and the default set.
	operatorSources := []string{"DefaultRelays", "SettingRelays", "ParseRelays("}
	// The seams a pairing's relays reach: the constructor of the type the publish
	// seam takes, the publish seam itself, the subscribe call — and the ROW
	// WRITE, which is the one that matters most and which the first version of
	// this rule did not guard.
	//
	// Found by review, by planting the realistic mistake: replace
	// createConnection's empty-relay-box redirect with
	// `relays = nostr.ParseRelays(values.get(SettingRelays))`, and an operator who
	// leaves the box blank silently gets a pairing on their own zap-receipt
	// relays. Every downstream seam is then legitimately serving "the pairing's
	// own list", so a rule that watches only publish and subscribe sees nothing
	// wrong for the rest of that pairing's life.
	pairingSeams := []string{"PairingRelays(", "PublishToConnection(", ".Subscribe(",
		"CreateNWCConnection("}
	var found []problem
	for _, f := range files {
		lines := codeLines(t, f)
		for _, fn := range functions(t, f) {
			var source, seam string
			var sourceLine int
			for i := fn.from; i <= fn.to && i <= len(lines); i++ {
				for _, want := range operatorSources {
					if strings.Contains(lines[i-1], want) && source == "" {
						source, sourceLine = want, i
					}
				}
				for _, want := range pairingSeams {
					if strings.Contains(lines[i-1], want) && seam == "" {
						seam = want
					}
				}
			}
			if source != "" && seam != "" {
				found = append(found, problem{f.rel, sourceLine, fmt.Sprintf(
					"%s reaches %s in the same function as %s; a pairing is served on the "+
						"relays its own URI named, never on the operator's (§8, d24.18)",
					fn.name, seam, source)})
			}
		}
	}
	return found
}

func TestTheOperatorsRelaysNeverReachAPairing(t *testing.T) {
	clean(t, checkOperatorRelaysReachNoPairing(t, sourceFiles(t)))

	// TWO LINES APART, in one function. The first version of this planted file put
	// the source and the seam on ONE line, which cannot tell a per-function rule
	// from a per-line one — and per-function is the property the doc above argues
	// for at length (found by review).
	catches(t, checkOperatorRelaysReachNoPairing(t, []sourceFile{planted("internal/nwc", `
package nwc

import "github.com/davotoula/brollyzapper/internal/nostr"

func announceEverywhere(p *nostr.Pool, event any) {
	operators := nostr.DefaultRelays
	relays := nostr.PairingRelays(operators)
	_ = relays
}
`)}), "never on the operator's")

	// And the ROW WRITE, which is the seam that puts the operator's relays into a
	// pairing for good.
	catches(t, checkOperatorRelaysReachNoPairing(t, []sourceFile{planted("internal/api", `
package api

import "github.com/davotoula/brollyzapper/internal/nostr"

func createConnection(s *Server, values settingsSnapshot) {
	relays := nostr.ParseRelays(values.get(SettingRelays))
	_, _ = s.Connections.CreateNWCConnection(nil, store.NWCConnection{Relays: relays}, 0)
}
`)}), "never on the operator's")

	// THE LIMIT, recorded rather than assumed: provenance that crosses a function
	// boundary is NOT caught. This asserts `clean` on a violation, which looks
	// backwards and is not — it is the rule's own boundary written down, so the
	// next person reads it here instead of discovering it with a plant.
	clean(t, checkOperatorRelaysReachNoPairing(t, []sourceFile{planted("internal/nwc", `
package nwc

import "github.com/davotoula/brollyzapper/internal/nostr"

func operatorList() []string { return nostr.DefaultRelays }

func announceEverywhere(p *nostr.Pool, event any) {
	relays := nostr.PairingRelays(operatorList())
	_ = relays
}
`)}))
}

// fn is one function's line span, for a rule that reasons about what a single
// function does rather than what a file mentions.
type fn struct {
	name     string
	from, to int
}

// functions returns every function and method in a file, by line span.
func functions(t *testing.T, f sourceFile) []fn {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, f.path, f.src, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", f.rel, err)
	}
	var out []fn
	for _, decl := range parsed.Decls {
		decl, ok := decl.(*ast.FuncDecl)
		if !ok || decl.Body == nil {
			continue
		}
		out = append(out, fn{
			name: decl.Name.Name,
			from: fset.Position(decl.Pos()).Line,
			to:   fset.Position(decl.End()).Line,
		})
	}
	return out
}

// classAction marks where a template action stood in a flattened template, with
// the field it reads between the sentinels: `receipt-{{.Receipt}}` flattens to
// "receipt-\x00Receipt\x00". A byte no template can contain, so a class name
// cannot collide with it.
const classSentinel = "\x00"

// flattenTemplate renders a template's TEXT with every action replaced by a
// marker, using html/template's own parser.
//
// The first version of this scraped the raw file with regexps and needed a
// special case per template idiom: one to strip {{if}}/{{else}}/{{end}} out of
// a class list, and one to notice that `class="([^"]*)"` stops reading at the
// first quote INSIDE an action, which made a quoted argument look like six
// missing classes. Both disappear here — a parser knows where an action begins
// and ends, so quotes inside one never reach the text, and both arms of a
// conditional are walked, which is what "this class list can render either of
// these" actually means. A `with`, a `range` or a pipeline needs no new case.
func flattenTemplate(t *testing.T, name, body string) string {
	t.Helper()
	tree := parse.New(name)
	// The rule reads structure, not semantics: it must not need the template
	// FuncMap, which lives in internal/web and which internal/arch deliberately
	// does not import.
	tree.Mode = parse.SkipFuncCheck
	if _, err := tree.Parse(body, "", "", map[string]*parse.Tree{}); err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	var b strings.Builder
	var walk func(parse.Node)
	// The two arms of a conditional are alternatives, not neighbours: walked
	// end to end they would splice `{{if}}state-bad{{else}}state-waiting{{end}}`
	// into the single class "state-badstate-waiting". A space is what says
	// "either of these".
	branch := func(list, elseList parse.Node) {
		b.WriteString(" ")
		walk(list)
		b.WriteString(" ")
		walk(elseList)
		b.WriteString(" ")
	}
	walk = func(n parse.Node) {
		switch n := n.(type) {
		case nil:
			return
		case *parse.ListNode:
			// A branch with no {{else}} carries a TYPED nil here, which the
			// case above does not catch: the interface is not nil, its pointer
			// is.
			if n == nil {
				return
			}
			for _, child := range n.Nodes {
				walk(child)
			}
		case *parse.TextNode:
			b.WriteString(string(n.Text))
		case *parse.ActionNode:
			b.WriteString(classSentinel + actionField(n.Pipe) + classSentinel)
		case *parse.IfNode:
			branch(n.List, n.ElseList)
		case *parse.RangeNode:
			branch(n.List, n.ElseList)
		case *parse.WithNode:
			branch(n.List, n.ElseList)
		}
	}
	walk(tree.Root)
	return b.String()
}

// actionField is the last field name an action reads, or "" when it reads none.
// `{{.Receipt}}` gives Receipt; `{{.StateClass}}` gives StateClass; `{{sats
// .AmountMsat}}` gives AmountMsat, which names no class vocabulary and is
// reported as such if it ever appears inside a class attribute.
func actionField(pipe *parse.PipeNode) string {
	if pipe == nil {
		return ""
	}
	for _, cmd := range pipe.Cmds {
		for _, arg := range cmd.Args {
			switch a := arg.(type) {
			case *parse.FieldNode:
				if len(a.Ident) > 0 {
					return a.Ident[len(a.Ident)-1]
				}
			case *parse.VariableNode:
				if len(a.Ident) > 1 {
					return a.Ident[len(a.Ident)-1]
				}
			}
		}
	}
	return ""
}

// webConstants returns internal/web's exported string constants by name.
//
// This is what a dynamic class draws on. `receipt-{{.Receipt}}` renders one of
// the Receipt* constants, so the vocabulary is DERIVED rather than restated
// here: a state added to that const block and rendered by the template would
// otherwise never be required to have a colour, which is the drift this whole
// rule exists to catch, in the one place the rule needed outside knowledge.
func webConstants(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range sourceFiles(t) {
		if f.dir != "internal/web" {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), f.rel, f.src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", f.rel, err)
		}
		for _, decl := range parsed.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range value.Names {
					if i >= len(value.Values) {
						continue
					}
					lit, ok := value.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					unquoted, err := strconv.Unquote(lit.Value)
					if err != nil {
						continue
					}
					out[name.Name] = unquoted
				}
			}
		}
	}
	return out
}

// checkTemplateClassesAreStyled reports classes used by a renderer and never
// defined, and classes defined and never used.
//
// WHY THIS RULE EXISTS. The stylesheet stopped following the templates: by
// 2026-08-26, 13 of 26 class hooks had accumulated across six waves with
// nothing noticing, including `degraded` — the banner a half-configured install
// shows first, which had no styling at all.
//
// `renderers` is every source that emits a class attribute, not only the .html
// files: internal/web/qr.go writes `class="qr"` into an SVG it builds in Go,
// and a rule that read templates alone would report the one styled hook nobody
// renders from a template as dead and invite its deletion. HTML values arrive
// already flattened by flattenTemplate; Go values arrive as source.
//
// `consts` is internal/web's string constants, which is where a dynamic class
// gets its vocabulary. Taking both as arguments rather than reading the disk is
// what lets the test run this against planted inputs (zu5.6).
func checkTemplateClassesAreStyled(t *testing.T, renderers map[string]string, css string, consts map[string]string) []problem {
	t.Helper()
	classAttr := regexp.MustCompile(`class="([^"]*)"`)
	// Comments first: this stylesheet cites source files, and `Color.kt` or
	// `…-design.md` reads as a class selector to anything scanning raw text. A
	// rule that invents classes is worse than no rule, because the list it
	// prints is the specification for the next person's work.
	bare := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(css, " ")
	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`\.([a-zA-Z][\w-]*)`).FindAllStringSubmatch(bare, -1) {
		defined[m[1]] = true
	}
	var found []problem
	used := map[string]string{} // class -> the renderer that uses it
	for name, body := range renderers {
		for _, m := range classAttr.FindAllStringSubmatch(body, -1) {
			for _, tok := range strings.Fields(m[1]) {
				prefix, field, dynamic := strings.Cut(tok, classSentinel)
				if !dynamic {
					used[tok] = name
					continue
				}
				field = strings.TrimSuffix(field, classSentinel)
				values := vocabularyFor(consts, field)
				if len(values) == 0 {
					found = append(found, problem{file: name, msg: fmt.Sprintf(
						"class %q is built from .%s, and internal/web declares no %s* string "+
							"constants naming what it can render as, so nothing can check that "+
							"each of them is styled", dynamicClass(tok), field, field)})
					continue
				}
				for _, v := range values {
					used[prefix+v] = name
				}
			}
		}
	}
	for class, where := range used {
		if !defined[class] {
			found = append(found, problem{file: where, msg: fmt.Sprintf(
				"class %q is used by a template and defined nowhere in the stylesheet", class)})
		}
	}
	for class := range defined {
		if _, ok := used[class]; !ok {
			found = append(found, problem{file: "internal/web/static/style.css", msg: fmt.Sprintf(
				"class %q is defined in the stylesheet and used by no template", class)})
		}
	}
	// slices, not sort: arch_test.go already imports slices and not sort, and a
	// new import is one more way for a planted violation to fail to compile.
	slices.SortFunc(found, func(a, b problem) int { return strings.Compare(a.msg, b.msg) })
	return found
}

// vocabularyFor is the values of the constants whose name begins with field —
// Receipt gives published, pending and abandoned.
func vocabularyFor(consts map[string]string, field string) []string {
	if field == "" {
		return nil
	}
	var out []string
	for name, value := range consts {
		if strings.HasPrefix(name, field) && value != "" {
			out = append(out, value)
		}
	}
	slices.Sort(out)
	return out
}

// dynamicClass renders a dynamic class token readably, with the sentinels back as the
// action they stand for.
func dynamicClass(tok string) string {
	prefix, field, _ := strings.Cut(tok, classSentinel)
	return prefix + "{{." + strings.TrimSuffix(field, classSentinel) + "}}"
}

// templateFiles are the admin UI's HTML templates, which sourceFiles does not
// walk — it reads Go only. They are where a class attribute lives, so they are
// where a rule about a class hook has to look. Same reason deploymentFiles
// exists for the compose files.
func templateFiles(t *testing.T) []sourceFile {
	t.Helper()
	root := moduleRoot(t)
	const dir = "internal/web/templates"
	entries, err := os.ReadDir(filepath.Join(root, dir))
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var out []sourceFile
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".html" {
			continue
		}
		rel := path.Join(dir, e.Name())
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		out = append(out, sourceFile{rel: rel, dir: dir, path: filepath.Join(root, rel), src: src})
	}
	return out
}

func TestEveryTemplateClassIsStyled(t *testing.T) {
	renderers := map[string]string{}
	for _, f := range templateFiles(t) {
		renderers[f.rel] = flattenTemplate(t, f.rel, string(f.src))
	}
	// The Go half comes from the shared, cached walk every other rule uses, so
	// the paths a finding names read like every other rule's finding.
	for _, f := range sourceFiles(t) {
		if f.dir == "internal/web" {
			renderers[f.rel] = string(f.src)
		}
	}
	if len(renderers) == 0 {
		t.Fatal("no renderers were read; this rule would pass vacuously")
	}
	css, err := os.ReadFile(filepath.Join(moduleRoot(t), "internal/web/static/style.css"))
	if err != nil {
		t.Fatal(err)
	}
	consts := webConstants(t)
	if consts["ReceiptPublished"] == "" {
		t.Fatal("internal/web's constants were not read; the dynamic-class half of this rule " +
			"would pass vacuously")
	}

	clean(t, checkTemplateClassesAreStyled(t, renderers, string(css), consts))

	planted := func(t *testing.T, body string) map[string]string {
		t.Helper()
		return map[string]string{"planted.html": flattenTemplate(t, "planted.html", body)}
	}

	// A class a template asks for and the stylesheet never answers.
	catches(t, checkTemplateClassesAreStyled(t,
		planted(t, `<p class="ghost">x</p>`),
		`.real { color: red; }`, consts), "defined nowhere in the stylesheet")

	// And the reverse: a rule nobody renders any more, which is how a
	// stylesheet accumulates dead weight that reads as intentional.
	catches(t, checkTemplateClassesAreStyled(t,
		planted(t, `<p class="real">x</p>`),
		`.real { color: red; } .orphan { color: blue; }`, consts), "used by no template")

	// A dynamic class whose vocabulary grew: the const block gains a state, the
	// stylesheet does not, and the rule has to notice without being told the
	// list. This is the case the first version of this rule could not fail,
	// because it carried the three receipt states as a literal.
	grown := map[string]string{"ReceiptPublished": "published", "ReceiptDisputed": "disputed"}
	catches(t, checkTemplateClassesAreStyled(t,
		planted(t, `<p class="receipt-{{.Receipt}}">x</p>`),
		`.receipt-published { color: red; }`, grown), `class "receipt-disputed" is used`)

	// And a dynamic class reading a field that names no vocabulary at all: the
	// rule must say so rather than silently checking nothing.
	catches(t, checkTemplateClassesAreStyled(t,
		planted(t, `<p class="thing-{{.Nothing}}">x</p>`),
		`.thing-one { color: red; }`, consts), "declares no Nothing* string constants")

	// Both arms of a conditional class list are used, whatever the condition is
	// spelled like — including one with a quoted argument, which is what the
	// regex this replaced could not read.
	clean(t, checkTemplateClassesAreStyled(t,
		planted(t, `<p class="state {{if eq .State "expired"}}state-bad{{else}}state-waiting{{end}}">x</p>`),
		`.state {} .state-bad {} .state-waiting {}`, consts))
}

// `06v`, Ruling 1: THE MONOTONIC DECISION IS MADE IN THE GUARD AND NOWHERE ELSE,
// and the operator controls are WRITTEN at exactly one site.
//
// Tightening a guard control — turning sending off, lowering a cap — needs no
// authorisation; loosening one does. Which of those a change IS gets decided by
// comparing it against the guard's own stored state, in State.loosens, and
// applied by State.apply. Two rules, one reason.
//
// THE FAILURE THE FIRST HALF PREVENTS IS THE WHOLE CEREMONY BECOMING ADVISORY.
// If the server decided which changes were loosenings, a compromised server
// would call every one of its own a tightening and never be asked for a code.
// The design brief states it in those words: "The server must not be the thing
// that decides which is which — that decision is exactly what a compromised
// server would lie about."
//
// THE SECOND HALF IS WHERE THE FIRST WOULD LEAK. A direction check is only worth
// anything if every write goes past it, and the second write site is the one
// that will not: `clearSpendState` genuinely has to drop the latch — "off must
// latch off" — and doing that with a bare assignment rather than through apply
// is how a third site later drops it without the check. So the assignment lives
// in apply, and everything else states a Change.
//
// It is written as ONE SITE rather than as "not in internal/api" because the
// second copy that matters need not be in the server: a helper in
// internal/preflight or internal/web that re-derived the direction to decide
// what to render would be the same defect one page away, and would drift from
// this one the first time the rule changed.
func checkOperatorControlsHaveOneDecisionSite(t *testing.T, files []sourceFile) []problem {
	const site = "internal/guard/operator.go"
	// The direction check, and the write. Both by name: this is a rule about two
	// specific functions, and a fuzzy match for "compares a cap against
	// something" flags every legitimate reader of a limit in the tree — which is
	// how a rule becomes a thing people add exemptions to.
	decides := regexp.MustCompile(`\bloosens\s*\(`)
	writes := regexp.MustCompile(`\.(SendingLatch|MaxSpendMsat|MaxPaymentMsat)\s*=[^=]`)

	var found []problem
	for _, f := range files {
		for i, line := range codeLines(t, f) {
			if decides.MatchString(line) && f.dir != "internal/guard" {
				found = append(found, problem{f.rel, i + 1,
					"decides whether a change to a guard control is a LOOSENING. That " +
						"decision lives in State.loosens and nowhere else: a compromised " +
						"server that decided it would call every one of its own changes a " +
						"tightening, and the authorisation ceremony would be advisory " +
						"(`06v`, Ruling 1)"})
			}
			// The write check is scoped to the guard: MaxPaymentMsat is also a
			// per-connection field in internal/store and internal/api, and a
			// rule that flagged those would be a rule people learn to ignore.
			// What it is really about is a second writer INSIDE the guard, which
			// is where one would plausibly appear.
			if writes.MatchString(line) && f.dir == "internal/guard" && f.rel != site {
				found = append(found, problem{f.rel, i + 1,
					"assigns an operator control directly. Every write goes through " +
						"State.apply, which is the only thing the direction check in " +
						"State.loosens sits in front of — a second assignment is a control " +
						"that can be moved without one (`06v`, Ruling 1)"})
			}
		}
	}
	return found
}

func TestTheOperatorControlsHaveOneDecisionSite(t *testing.T) {
	clean(t, checkOperatorControlsHaveOneDecisionSite(t, sourceFiles(t)))

	// The plausible mistake, not vandalism: a page deciding whether to show the
	// code box by asking the guard's own predicate, reached by exporting it —
	// which is how a "small refactor" would actually produce this.
	catches(t, checkOperatorControlsHaveOneDecisionSite(t, []sourceFile{planted("internal/web", `package web

func showCodeBox(st guard.State, c guard.Change) bool {
	return st.loosens(c)
}
`)}), "and nowhere else")

	// And the write, in the place it would really happen: another guard file
	// that has a good reason to drop the latch and takes the short way.
	catches(t, checkOperatorControlsHaveOneDecisionSite(t, []sourceFile{planted("internal/guard", `package guard

func (g *Guard) forget() error {
	return g.state.update(func(st *State) {
		st.SendingLatch = false
	})
}
`)}), "goes through State.apply")
}

// §19, and `06v`'s copy defect: THE GENERIC APP NAMES NO DEPLOYMENT ROUTE.
//
// "Do not assume deployment-specific app IDs, data paths, or container names" is
// §19's rule, and `06v` is what happens when the app's own copy breaks it in the
// other direction: the Sending page told the operator to change a setting "in
// this app's settings", a place umbrelOS does not have, and an operator who
// followed it concluded the app was broken. That one line is why `06v` was P1.
//
// THE REPAIR IS NOT TO HARDCODE THE REAL ROUTE INSTEAD. That would satisfy the
// operator and fail the rule — the same app has to run on a plain Docker host,
// where `/Apps/brollyzapper/...` means nothing. The deployment supplies the
// sentence (GUARD_AUTHORISATION_LOCATION), the guard relays it, and the page
// renders what it is given.
//
// SCANNED IN THE TEMPLATES AS WELL AS THE GO, and that is the half that matters:
// the sentence naming a place that does not exist lived in sending.html, and no
// rule looked there. In Go it reads code only — a comment explaining why a
// deployment mechanism exists is exactly the reasoning this codebase wants, and
// a rule that punished it would be a rule against writing things down.
func checkNoDeploymentRouteInTheApp(t *testing.T, files []sourceFile, gocode bool) []problem {
	// The two umbrelOS routes, and the sentence `06v` was filed on. `/Apps/` is
	// the Files app's mapping and `app-data/` is umbreld's own directory; the
	// third is not a path at all, which is the point — a route that does not
	// exist fails this rule exactly as a route that only exists on Umbrel does.
	route := regexp.MustCompile(`/Apps/|app-data/|this app's settings`)

	var found []problem
	for _, f := range files {
		// The package is where knowing this is the job, and internal/arch names
		// the rule and therefore names the strings.
		if strings.HasPrefix(f.dir, "umbrel") || f.dir == "internal/arch" {
			continue
		}
		lines := strings.Split(string(f.src), "\n")
		if gocode {
			lines = codeLines(t, f)
		}
		for i, line := range lines {
			if route.MatchString(line) {
				found = append(found, problem{f.rel, i + 1,
					"names a deployment-specific route, or one that does not exist. §19 " +
						"forbids the generic app assuming deployment-specific data paths — " +
						"the same binary has to run on a plain Docker host. The deployment " +
						"supplies this string through GUARD_AUTHORISATION_LOCATION and the " +
						"guard relays it (`06v`)"})
			}
		}
	}
	return found
}

func TestTheGenericAppNamesNoDeploymentRoute(t *testing.T) {
	clean(t, checkNoDeploymentRouteInTheApp(t, sourceFiles(t), true))
	clean(t, checkNoDeploymentRouteInTheApp(t, templateFiles(t), false))

	// The plausible mistake: someone "fixes" the copy by writing the real route
	// into the page, which works on Umbrel and is a lie everywhere else.
	catches(t, checkNoDeploymentRouteInTheApp(t, []sourceFile{{
		rel: "internal/web/templates/sending.html", dir: "internal/web/templates",
		src: []byte(`<p>Open Files and go to /Apps/brollyzapper/data/guard/authorisation.txt</p>`),
	}}, false), "deployment-specific data paths")

	// And the original defect itself, so the exact sentence `06v` was filed on
	// can never come back.
	catches(t, checkNoDeploymentRouteInTheApp(t, []sourceFile{{
		rel: "internal/web/templates/sending.html", dir: "internal/web/templates",
		src: []byte(`<p>Set GUARD_ALLOW_SENDING to true in this app's settings.</p>`),
	}}, false), "one that does not exist")
}

// `06v`: `internal/api` may name the guard's OPERATOR VOCABULARY and nothing
// else.
//
// The read half of the guard seam is laundered: `guard.Status` is converted to
// `lnd.BrokerStatus` inside `guard/client.go`, so `internal/api` learns what the
// guard knows without importing it. The write half could not be, without either
// duplicating a closed set of three controls in a second package — the drift §6
// spent d46.26 removing — or adding an adapter in `cmd/` whose only job is to
// rename three constants. So `internal/api` imports `internal/guard`, and this
// rule is the price of that decision.
//
// WHAT IT CLOSES, concretely. The import puts the whole of `internal/guard` in
// `internal/api`'s cone: `Guard`, `State`, `SocketClient`, `WriteCredential`,
// the root-key machinery. And `checkOperatorControlsHaveOneDecisionSite` scopes
// its write check to `f.dir == "internal/guard"` on purpose, because
// `MaxPaymentMsat` is also a per-connection field in this package — so
// `st.SendingLatch = true` on a `guard.State` inside `internal/api` was both
// reachable and unflagged. Found by review.
//
// The allow-list is the operator vocabulary and the two errors a handler must be
// able to name. Anything else is a handler reaching past the socket, which is
// the one thing the two-container split exists to prevent.
func checkAPINamesOnlyTheGuardsVocabulary(t *testing.T, files []sourceFile) []problem {
	allowed := map[string]bool{
		"Change": true, "Control": true,
		"ControlSending": true, "ControlSpendCap": true, "ControlPaymentCap": true,
		"Controls": true,
	}
	reference := regexp.MustCompile(`\bguard\.([A-Z]\w*)`)

	var found []problem
	for _, f := range files {
		if f.dir != "internal/api" {
			continue
		}
		for i, line := range codeLines(t, f) {
			for _, match := range reference.FindAllStringSubmatch(line, -1) {
				if allowed[match[1]] {
					continue
				}
				found = append(found, problem{f.rel, i + 1, fmt.Sprintf(
					"names guard.%s. internal/api may name the guard's OPERATOR VOCABULARY "+
						"only — Change, Control and the three controls — because that is the "+
						"one thing it could not learn through lnd.BrokerStatus without a "+
						"second copy of a closed set. Everything else in that package is "+
						"reachable only through the socket, which is what the two-container "+
						"split is for: a handler holding a guard.State could write the "+
						"operator's latch without going past State.apply's direction check "+
						"(§3, §6, `06v`)", match[1])})
			}
		}
	}
	return found
}

func TestTheAPINamesOnlyTheGuardsOperatorVocabulary(t *testing.T) {
	clean(t, checkAPINamesOnlyTheGuardsVocabulary(t, sourceFiles(t)))

	// The plausible mistake, and the exact one the review named: a handler that
	// has the import anyway reaches for the state type to answer a question
	// locally.
	catches(t, checkAPINamesOnlyTheGuardsVocabulary(t, []sourceFile{planted("internal/api", `package api

func latched(st guard.State) bool {
	return st.SendingLatch
}
`)}), "OPERATOR VOCABULARY")

	// And the one that would actually be tempting: constructing the client here
	// rather than taking the consumer-defined interface.
	catches(t, checkAPINamesOnlyTheGuardsVocabulary(t, []sourceFile{planted("internal/api", `package api

func broker(path string) *guard.SocketClient {
	return guard.NewSocketClient(path, nil)
}
`)}), "reachable only through the socket")
}
