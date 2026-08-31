package arch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	for target, must := range map[string]string{
		"vuln":  "govulncheck ./...",
		"cross": "GOOS=",
	} {
		recipe := expandTarget(t, target)
		if !strings.Contains(recipe, must) {
			t.Errorf("`make %s` does not run %q; CI calls it, so an empty target would "+
				"make the whole check vacuous. Recipe:\n%s", target, must, recipe)
		}
		if strings.Contains(recipe, "@latest") {
			t.Errorf("`make %s` installs a tool @latest, which makes the gate's verdict "+
				"a function of the day it ran", target)
		}
	}

	// The planted half: a gate missing a command, and a workflow that has
	// acquired a secret.
	catches(t, checkGateScript("go build ./...\n", ""), "never runs")
	catches(t, checkGateScript(all, "env:\n  TOKEN: ${{ secrets.GH_TOKEN }}\n"),
		"references a secret")
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
		"make fuzz",
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
		for i, line := range strings.Split(raw, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "FROM ") {
				continue
			}
			// `FROM x AS build` referred to later by name is a stage, not a
			// registry pull, and has no digest to pin.
			image := strings.Fields(strings.TrimSpace(line))[1]
			if strings.HasPrefix(image, "--platform=") {
				image = strings.Fields(strings.TrimSpace(line))[2]
			}
			if !strings.Contains(image, "/") && !strings.Contains(image, ":") {
				continue
			}
			if !strings.Contains(image, "@sha256:") {
				found = append(found, problem{name, i + 1,
					fmt.Sprintf("%q is pinned by tag, not by digest", image)})
			}
		}
	}
	return found
}

func TestTheBaseImagesArePinnedByDigest(t *testing.T) {
	root := moduleRoot(t)
	names, err := filepath.Glob(filepath.Join(root, "Dockerfile.*"))
	if err != nil || len(names) == 0 {
		t.Fatalf("finding Dockerfiles in %s: %v", root, err)
	}
	files := map[string]string{}
	for _, path := range names {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		files[filepath.Base(path)] = string(raw)
	}
	clean(t, checkBaseImagesPinned(files))

	catches(t, checkBaseImagesPinned(map[string]string{
		"Dockerfile.planted": "FROM golang:1.26-alpine AS build\n",
	}), "pinned by tag, not by digest")
	// And a build STAGE is not a registry pull, so it must not be flagged.
	clean(t, checkBaseImagesPinned(map[string]string{
		"Dockerfile.planted": "FROM build\n",
	}))
}
