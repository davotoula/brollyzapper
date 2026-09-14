package arch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The CI workflow is the only gate before MVP, and it is a file nothing else
// validates: a syntax error or a renamed job means it silently stops running.
func TestTheCIWorkflowParsesAndRunsTheWholeGate(t *testing.T) {
	path := filepath.Join(moduleRoot(t), ".github", "workflows", "ci.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var workflow struct {
		Name string `yaml:"name"`
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
				Uses string `yaml:"uses"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatalf("%s is not valid YAML: %v", path, err)
	}
	if len(workflow.Jobs) == 0 {
		t.Fatal("the workflow declares no jobs")
	}

	var script strings.Builder
	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			script.WriteString(step.Run)
			script.WriteString("\n")
		}
	}
	all := script.String()

	clean(t, checkGateScript(all, string(raw)))

	// A `make X` in the workflow is only as good as the target behind it: a
	// target that ran nothing would satisfy the string check above while
	// enforcing nothing — the "test that cannot fail" shape this project has
	// already met twice.
	//
	// So expand each one with `make -n`, which prints the recipe without
	// running it: no network, no side effects, and it asserts what the target
	// DOES rather than what the Makefile looks like. An earlier version
	// string-cut the Makefile on "\nvuln:", which was both fragile and applied
	// to one target while `make cross` beside it got only the string check.
	for _, anchor := range []struct{ target, must string }{
		{"vuln", "govulncheck ./..."},
		// zu5.12. The regtest tool modules, which `./...` never reaches. The flags
		// are spelled in the recipe so they can be asserted here: without -scan
		// module it is a different scan, without -format json no finding list.
		{"vuln", "scripts/vuln_tools.py"},
		{"vuln", "govulncheck -scan module -format json"},
		{"cross", "GOOS="},
		// 0vk.39. Its own wave's check was the one gate command with nothing
		// asserting it was still wired up — found by the simplify pass.
		{"toolchain-floor", "scripts/toolchain_floor.py"},
		// zu5.11. The exclusion is asserted as well as the run: a recipe that
		// linted the generated stubs would go red on code that is not ours.
		{"staticcheck", "grep -Ev '/internal/lnd/lnrpc(/|$)'"},
	} {
		recipe := expandTarget(t, anchor.target)
		if !strings.Contains(recipe, anchor.must) {
			t.Errorf("`make %s` does not run %q; CI calls it, so an empty target would "+
				"make the whole check vacuous. Recipe:\n%s", anchor.target, anchor.must, recipe)
		}
		if strings.Contains(recipe, "@latest") {
			t.Errorf("`make %s` installs a tool @latest, which makes the gate's verdict "+
				"a function of the day it ran", anchor.target)
		}
	}

	// The planted half: a gate missing a command, and a workflow that has
	// acquired a secret.
	catches(t, checkGateScript("go build ./...\n", ""), "never runs")
	catches(t, checkGateScript(all, "env:\n  TOKEN: ${{ secrets.GH_TOKEN }}\n"),
		"references a secret")
}

// zu5.12: scripts/vuln_tools.py's verdict, against a scanner whose output is
// fixed, so the set difference and the three exits stay proven after the plants
// that first proved them are reverted. The anchors above say the script is WIRED;
// this says it still DECIDES. A copy of the script runs in a throwaway tree with
// its own two modules and accepted list, so the real list is never the fixture and
// the script needs no override that could double as an off switch.
func TestTheToolModuleVulnVerdict(t *testing.T) {
	script, err := os.ReadFile(filepath.Join(moduleRoot(t), "scripts", "vuln_tools.py"))
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	config := `{"config":{"scan_level":"module"}}` + "\n"
	finding := func(id string) string {
		return `{"finding":{"osv":"` + id + `","trace":[{"module":"golang.org/x/crypto"}]}}` + "\n"
	}
	for _, c := range []struct {
		name       string
		out        map[string]string // module -> the scanner's stdout
		exitOf     string            // a module whose scanner exits 1
		wantExit   int
		wantOutput []string
	}{
		{"the accepted finding alone is green, and says so",
			map[string]string{"a": config + finding("GO-1") + finding("GO-1"), "b": config}, "", 0, []string{"GO-1 in golang.org/x/crypto accepted — planted reason"}},
		{"a new finding is red, named with its module",
			map[string]string{"a": config + finding("GO-1") + finding("GO-2"), "b": config}, "", 1, []string{
				"a: GO-2 in golang.org/x/crypto is NEW",
				// On its own, not only via the case above: the accepted ID stays accepted.
				"GO-1 in golang.org/x/crypto accepted"}},
		{"an acceptance the scan no longer finds is red",
			map[string]string{"a": config, "b": config}, "", 1, []string{"GO-1 is accepted in regtest/tools/vuln-accepted.txt but the scan no longer finds it"}},
		{"a scanner that printed nothing could not check",
			map[string]string{"a": "", "b": config}, "", 2, []string{"COULD NOT CHECK — regtest/tools/a: expected one module-level scan"}},
		{"a scanner that failed could not check",
			map[string]string{"a": config + finding("GO-1"), "b": config}, "b", 2, []string{"COULD NOT CHECK — regtest/tools/b: govulncheck exited 1"}},
		{"reshaped JSON could not check rather than reading as a finding",
			map[string]string{"a": config + `{"finding":{}}` + "\n", "b": config}, "", 2, []string{"COULD NOT CHECK — KeyError"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tree := t.TempDir()
			write := func(rel, body string, mode os.FileMode) {
				path := filepath.Join(tree, rel)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			write("scripts/vuln_tools.py", string(script), 0o644)
			// Trailing slash deliberately: it must match the module the glob found.
			write("regtest/tools/vuln-accepted.txt", "regtest/tools/a/ GO-1 planted reason\n", 0o644)
			for module, out := range c.out {
				write("regtest/tools/"+module+"/go.mod", "module "+module+"\n", 0o644)
				write("regtest/tools/"+module+"/scan.out", out, 0o644)
			}
			if c.exitOf != "" {
				write("regtest/tools/"+c.exitOf+"/scan.exit", "1", 0o644)
			}
			// The fake runs in each module directory, as govulncheck does.
			write("fakescan", "#!/bin/sh\ncat scan.out\n[ -f scan.exit ] && echo 'creating client: planted' >&2 && exit 1\nexit 0\n", 0o755)

			cmd := exec.Command("python3", "scripts/vuln_tools.py", filepath.Join(tree, "fakescan"), "-scan", "module", "-format", "json")
			cmd.Dir = tree
			out, err := cmd.CombinedOutput()
			exit := 0
			if exitErr, ok := err.(*exec.ExitError); ok {
				exit = exitErr.ExitCode()
			} else if err != nil {
				t.Fatalf("running the script: %v", err)
			}
			if exit != c.wantExit {
				t.Errorf("exit %d, want %d; got:\n%s", exit, c.wantExit, out)
			}
			for _, want := range c.wantOutput {
				if !strings.Contains(string(out), want) {
					t.Errorf("output does not contain %q; got:\n%s", want, out)
				}
			}
		})
	}
}

// checkGateScript is every assertion about what the workflow RUNS, over the
// concatenated run: blocks and the raw file.
func checkGateScript(all, raw string) []problem {
	var found []problem
	// Every command in the local gate, and the arch tests with them: a CI that
	// skips internal/arch enforces nothing (spec §3, §5, §12, §16).
	for _, command := range []string{
		"gofmt -l .", "go build ./...", "go vet ./...", "go test ./...",
		"go test -race ./...", "make cross", "go mod tidy -diff", "make vuln",
		"make fuzz", "make toolchain-floor", "make staticcheck",
	} {
		if !strings.Contains(all, command) {
			found = append(found, problem{"ci.yml", 0, fmt.Sprintf(
				"never runs %q; the local gate and CI must mean the same thing", command)})
		}
	}
	if !strings.Contains(all, "internal/lnd/lnrpc") {
		found = append(found, problem{"ci.yml", 0,
			"the gofmt step does not exclude the generated protobuf stubs"})
	}
	// d46.1 acceptance 6 in its corrected form. The inverted form reports on the
	// container's configuration rather than on the presence of a shell, and CI
	// is the configured case.
	if !strings.Contains(all, "--entrypoint") {
		found = append(found, problem{"ci.yml", 0,
			"the shell assertion does not override the entrypoint, so it proves nothing"})
	}
	for _, inverted := range []string{"docker run --rm brollyzapper-$img:ci /bin/sh", "run <img> /bin/sh"} {
		if strings.Contains(all, inverted) {
			found = append(found, problem{"ci.yml", 0,
				fmt.Sprintf("uses the inverted shell assertion %q", inverted)})
		}
	}
	// Criterion 5: no secrets today, and one appearing is a design change.
	if strings.Contains(raw, "${{ secrets.") {
		found = append(found, problem{"ci.yml", 0,
			"references a secret; it needs none, and one appearing is worth escalating"})
	}
	return found
}

// expandTarget returns what `make <target>` would run, without running it.
func expandTarget(t *testing.T, target string) string {
	t.Helper()
	cmd := exec.Command("make", "-n", target)
	cmd.Dir = moduleRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n %s: %v\n%s", target, err, out)
	}
	if strings.TrimSpace(string(out)) == "" {
		t.Fatalf("`make %s` expands to nothing at all", target)
	}
	return string(out)
}

// workflow is the shape every rule in this file reads.
type workflow struct {
	Name string         `yaml:"name"`
	Jobs map[string]job `yaml:"jobs"`
}

// job and step are named rather than anonymous so a test can build one. The
// scanners take their input (zu5.6), and a synthetic workflow is how each rule
// proves it can still fail.
type job struct {
	Steps []step `yaml:"steps"`
}

type step struct {
	Name string `yaml:"name"`
	Run  string `yaml:"run"`
	Uses string `yaml:"uses"`
}

// workflowFiles is every GitHub Actions workflow in the repo, parsed, plus its
// raw text for the rules that legitimately need it.
//
// PARSED, not scanned line by line. An earlier version of the rules below
// hand-rolled `uses:` detection and a `run:` block-scalar state machine, which
// was both more code and strictly weaker than the parser already imported here:
// a literal "uses:" inside a run script or a comment matched, and a `run: |`
// block followed by a same-indent key mis-tracked. yaml.v3 is already a
// dependency; there was never a reason to reimplement it (review, wave 10).
//
// The rules apply to every workflow rather than to ci.yml alone: publish.yml is
// the one that holds a token and pushes images, so it is where a supply-chain
// rule matters most, and it was the file that had the injection (review L12).
func workflowFiles(t *testing.T) (map[string]workflow, map[string]string) {
	t.Helper()
	dir := filepath.Join(moduleRoot(t), ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	parsed, raws := map[string]workflow{}, map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		var w workflow
		if err := yaml.Unmarshal(raw, &w); err != nil {
			t.Fatalf("%s is not valid YAML: %v", e.Name(), err)
		}
		if len(w.Jobs) == 0 {
			t.Fatalf("%s declares no jobs; every rule here would pass vacuously", e.Name())
		}
		parsed[e.Name()], raws[e.Name()] = w, string(raw)
	}
	if len(parsed) == 0 {
		t.Fatal("no workflows found; these rules would pass vacuously")
	}
	return parsed, raws
}

// stepLabel names a step for a failure message, since a parsed step has no line
// number. The job and step names locate it more usefully than a line does.
func stepLabel(file, job, name string) string {
	if name == "" {
		name = "(unnamed step)"
	}
	return fmt.Sprintf("%s / job %s / %q", file, job, name)
}

// A tag is a mutable pointer. `actions/checkout@v4` is whatever that repo's
// owner — or anyone who compromises it — decides v4 means at the moment our job
// starts, and our job runs with a token that can push images. A commit SHA is
// the only form of `uses:` that names a fixed thing (review L12).
//
// The trailing `# vX.Y.Z` comment is required too: without it the file becomes
// forty hex characters nobody can review or update.
func checkActionsPinned(parsed map[string]workflow, raws map[string]string) []problem {
	// yaml strips the trailing "# v7.0.1" comment, so the SHA is checked here
	// and the presence of a version comment is checked against the raw text.
	pinned := regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)
	var found []problem
	for name, w := range parsed {
		for job, j := range w.Jobs {
			for _, step := range j.Steps {
				if step.Uses == "" {
					continue
				}
				if !pinned.MatchString(step.Uses) {
					found = append(found, problem{stepLabel(name, job, step.Name), 0,
						fmt.Sprintf("%q is not pinned to a commit SHA; a tag is a mutable "+
							"pointer, and these jobs hold a token that can push images",
							step.Uses)})
					continue
				}
				// Forty hex characters nobody can review or update is its own
				// problem, so the version has to stay written beside them.
				if !regexp.MustCompile(regexp.QuoteMeta(step.Uses) + `\s+#\s*v\d`).
					MatchString(raws[name]) {
					found = append(found, problem{stepLabel(name, job, step.Name), 0,
						fmt.Sprintf("%q carries no trailing version comment (# vX.Y.Z)",
							step.Uses)})
				}
			}
		}
	}
	return found
}

func TestEveryActionIsPinnedByCommitSHA(t *testing.T) {
	parsed, raws := workflowFiles(t)
	clean(t, checkActionsPinned(parsed, raws))
	catches(t, checkActionsPinned(
		map[string]workflow{"planted.yml": {Jobs: map[string]job{"gate": {Steps: []step{
			{Name: "checkout", Uses: "actions/checkout@v4"},
		}}}}},
		map[string]string{"planted.yml": "uses: actions/checkout@v4\n"}),
		"not pinned to a commit SHA")
}

// Review L12. publish.yml wrote ${{ inputs.version }} straight into a `run:`
// script — including into the step whose whole job was to validate it, so the
// validation ran only after the shell had already expanded whatever was typed.
// Actions substitutes the expression textually before the shell sees it, so
// anything a dispatcher can type is code.
//
// Only a dispatcher can reach it here and the repo has one, which is why this
// is low rather than critical. It is the pattern that is wrong, not the
// exposure — and the fix, `env:` indirection, costs a line.
func checkUntrustedInterpolation(parsed map[string]workflow) []problem {
	// github.event.* and inputs.* are the attacker-influenced halves of the
	// context. github.repository_owner and github.sha are not, and are used.
	untrusted := regexp.MustCompile(`\$\{\{\s*(inputs|github\.event)\b`)
	var found []problem
	for name, w := range parsed {
		for job, j := range w.Jobs {
			for _, step := range j.Steps {
				for _, line := range strings.Split(step.Run, "\n") {
					if !untrusted.MatchString(line) {
						continue
					}
					found = append(found, problem{stepLabel(name, job, step.Name), 0,
						fmt.Sprintf("a run: block interpolates untrusted context: %s — pass "+
							"it through env:, because Actions substitutes the expression "+
							"before the shell parses the line, so this is code, not data",
							strings.TrimSpace(line))})
				}
			}
		}
	}
	return found
}

func TestNoWorkflowInterpolatesInputIntoARunBlock(t *testing.T) {
	parsed, _ := workflowFiles(t)
	clean(t, checkUntrustedInterpolation(parsed))
	catches(t, checkUntrustedInterpolation(
		map[string]workflow{"planted.yml": {Jobs: map[string]job{"publish": {Steps: []step{
			{Name: "tag", Run: "echo ${{ inputs.version }}"},
		}}}}}),
		"interpolates untrusted context")
}

// Base images are pinned by digest for the same reason actions are pinned by
// SHA: `golang:1.26-alpine` is a mutable pointer, and it is the layer the two
// binaries are compiled by.
//
// The cost is real and deliberate: a pinned base stops receiving upstream
// patches until someone bumps it, which is what govulncheck in the gate is for
// on the Go side and what the refresh note in each Dockerfile is for on the
// image side. An unreviewed patch arriving silently is the worse of the two.
func checkBaseImagesPinned(files map[string]string) []problem {
	var found []problem
	for name, raw := range files {
		// `FROM x AS build` referred to later by name is a stage, not a registry
		// pull, and has no digest to pin. Known by the names earlier lines
		// declared, not by shape: "no slash and no colon" also describes
		// `FROM alpine`, an unpinned pull of latest (0vk.58 go-review).
		stages := map[string]bool{"scratch": true}
		for i, line := range strings.Split(raw, "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
				continue
			}
			fields = fields[1:]
			if strings.HasPrefix(fields[0], "--platform=") && len(fields) > 1 {
				fields = fields[1:]
			}
			image := fields[0]
			if !stages[strings.ToLower(image)] && !strings.Contains(image, "@sha256:") {
				found = append(found, problem{name, i + 1,
					fmt.Sprintf("%q is pinned by tag, not by digest", image)})
			}
			// Declared after the check: a stage can only be named by a later line.
			if len(fields) >= 3 && strings.EqualFold(fields[1], "AS") {
				stages[strings.ToLower(fields[2])] = true
			}
		}
	}
	return found
}

func TestTheBaseImagesArePinnedByDigest(t *testing.T) {
	// Every Dockerfile in the tree, not a list of where they are today: the
	// shipped images and the regtest tool images alike (0vk.58). Nothing about a
	// tool ships, but it is still a registry pull that Scorecard's
	// Pinned-Dependencies reads, and a weekly scanner is a slow way to learn a
	// pin was dropped — or that a new Dockerfile never had one.
	root := moduleRoot(t)
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if slices.Contains(neverScanned, d.Name()) {
				return filepath.SkipDir
			}
			// Two things a walk sees that git does not, either of which would make
			// the verdict depend on which checkout ran it: the main tree's
			// gitignored /docs and /.claude, which a worktree does not have, and a
			// nested worktree or clone (a directory holding a .git FILE or dir),
			// whose Dockerfiles are another branch's.
			if path != root {
				if rel, _ := filepath.Rel(root, path); rel == "docs" || rel == ".claude" {
					return filepath.SkipDir
				}
				if _, err := os.Lstat(filepath.Join(path, ".git")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if d.Name() != "Dockerfile" && !strings.HasPrefix(d.Name(), "Dockerfile.") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s for Dockerfiles: %v", root, err)
	}
	// The walk must have found the ones that exist, or a broken walk reads as a
	// clean tree.
	for _, want := range []string{"Dockerfile.server", "Dockerfile.guard", "regtest/tools/sqlite/Dockerfile"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("the Dockerfile walk did not find %s (found %d files)", want, len(files))
		}
	}
	clean(t, checkBaseImagesPinned(files))

	catches(t, checkBaseImagesPinned(map[string]string{
		"Dockerfile.planted": "FROM golang:1.26-alpine AS build\n",
	}), "pinned by tag, not by digest")
	// And a build STAGE is not a registry pull, so it must not be flagged.
	clean(t, checkBaseImagesPinned(map[string]string{
		"Dockerfile.planted": "FROM golang@sha256:" + strings.Repeat("0", 64) +
			" AS build\nFROM --platform=$BUILDPLATFORM build\nFROM scratch\n",
	}))
	// A bare image name is a pull of latest, not a stage, unless a line above
	// declared it — the shape "no slash, no colon" used to let this through.
	catches(t, checkBaseImagesPinned(map[string]string{
		"Dockerfile.planted": "FROM alpine\n",
	}), `"alpine" is pinned by tag`)
	// A stage is only a stage after its AS line, not before.
	catches(t, checkBaseImagesPinned(map[string]string{
		"Dockerfile.planted": "FROM build\nFROM golang@sha256:" + strings.Repeat("0", 64) + " AS build\n",
	}), `"build" is pinned by tag`)
}
