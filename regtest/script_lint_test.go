package regtest

// This file is stack_lint_test.go's sibling for the SCRIPTS: the compose file
// pins every image the stack runs by digest, and this keeps the images the
// scripts `docker run` from quietly not being part of that promise (0vk.59).
//
// They were not. 0vk.58 pinned tools/sqlite/Dockerfile — the one alpine line
// Scorecard reads — while the scripts pulled `alpine:3.20` by mutable tag
// thirteen times, so the score said pinned and every regtest run fetched
// whatever 3.20 meant that day, on a release already past end of life.

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// toolDockerfile is the one statement of the tool image's reference. Dependabot
// maintains it (its docker entry for that directory, 0vk.58), and every script's
// TOOL_IMAGE default is read from it at run time, so a bump moves the scripts in
// the same PR and the tree never states the digest twice.
const toolDockerfile = "tools/sqlite/Dockerfile"

// fromReference is the image a Dockerfile's FIRST `FROM` line names — the same
// line the scripts' awk reads. A second FROM would be a build stage the scripts
// have no use for; the first is the base.
func fromReference(src string) string {
	for line := range strings.Lines(src) {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "FROM" {
			return fields[1]
		}
	}
	return ""
}

// logicalLine is a script line with its backslash continuations joined, and the
// number of the physical line it starts on.
type logicalLine struct {
	line int
	text string
}

// joinContinuations joins `\`-continued lines. Four of nwc.sh's thirteen sites
// put the image on the line AFTER `docker run … \`, so a per-line scan over
// lines containing `docker run` reads a line with no image on it and passes.
func joinContinuations(src string) []logicalLine {
	var out []logicalLine
	var cur strings.Builder
	start := 0
	sc := bufio.NewScanner(strings.NewReader(src))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for n := 1; sc.Scan(); n++ {
		text := sc.Text()
		if cur.Len() == 0 {
			start = n
		}
		if body, ok := strings.CutSuffix(text, `\`); ok {
			cur.WriteString(body + " ")
			continue
		}
		cur.WriteString(text)
		out = append(out, logicalLine{start, cur.String()})
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, logicalLine{start, cur.String()})
	}
	return out
}

// shellWords splits the way the shell would for this purpose: whitespace outside
// quotes, quotes kept out of the word. It stops at the first `)`, `;`, `|` or
// `&` outside quotes, which is where a `docker run` inside $(…) or a pipeline
// ends. Not a shell parser, and it does not need to be: the question is only
// which word is the image.
func shellWords(s string) []string {
	var words []string
	var cur strings.Builder
	var quote rune
	inWord := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, inWord = r, true
		case r == ' ' || r == '\t':
			if inWord {
				words, inWord = append(words, cur.String()), false
				cur.Reset()
			}
		case strings.ContainsRune(");|&", r):
			if inWord {
				words = append(words, cur.String())
			}
			return words
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}

// dockerRunBooleans are the `docker run` flags these scripts use that take no
// value. Any other flag without `=` is assumed to take the next word, so an
// unknown boolean flag makes the COMMAND read as the image — which fails this
// rule loudly, naming the word, rather than passing.
var dockerRunBooleans = []string{"--rm", "-i", "-t", "-it", "-d", "--init", "--read-only"}

// runImage is the image word of the `docker run` in text, or "" if there is none.
func runImage(text string) (string, bool) {
	_, after, ok := strings.Cut(text, "docker run ")
	if !ok {
		return "", false
	}
	words := shellWords(after)
	for i := 0; i < len(words); i++ {
		w := words[i]
		if !strings.HasPrefix(w, "-") {
			return w, true
		}
		if !strings.Contains(w, "=") && !slices.Contains(dockerRunBooleans, w) {
			i++ // the flag's value
		}
	}
	return "", true
}

// acceptableImage: a variable (whose value is some other rule's business — the
// TOOL_IMAGE default below, the compose lint for the stack's), a locally built
// brollyregtest-* image, or a reference pinned by tag and digest.
func acceptableImage(image string) bool {
	switch {
	case strings.HasPrefix(image, "$"):
		return true
	case strings.HasPrefix(image, "brollyregtest-") && !strings.ContainsAny(image, ":/@"):
		return true
	}
	return pinnedImage(image)
}

func checkScriptImages(scripts map[string]string) []string {
	var found []string
	for _, name := range slices.Sorted(maps.Keys(scripts)) {
		for _, l := range joinContinuations(scripts[name]) {
			if strings.HasPrefix(strings.TrimSpace(l.text), "#") {
				continue
			}
			image, isRun := runImage(l.text)
			if !isRun || acceptableImage(image) {
				continue
			}
			found = append(found, fmt.Sprintf("%s:%d: `docker run` names image %q; use \"$TOOL_IMAGE\" "+
				"(read from %s), another variable, a brollyregtest-* image, or a tag@sha256 pin — "+
				"a bare tag is whatever it means the day the script runs", name, l.line, image, toolDockerfile))
		}
	}
	return found
}

// checkToolImageDefault runs a script's TOOL_IMAGE definition — the assignment
// and the guard after it, nothing else — in dir with TOOL_IMAGE unset, and
// requires it to print the Dockerfile's FROM reference. Executed, not matched as
// text: the assertion is what the default RESOLVES to, which a string compare
// against one blessed spelling of the awk would not prove.
func checkToolImageDefault(name, src, dir, want string) []string {
	if !strings.Contains(src, "$TOOL_IMAGE") {
		return nil
	}
	var def []string
	for line := range strings.Lines(src) {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "TOOL_IMAGE=") || strings.HasPrefix(t, `[ -n "$TOOL_IMAGE" ]`) {
			def = append(def, t)
		}
	}
	if len(def) != 2 {
		return []string{fmt.Sprintf("%s: uses $TOOL_IMAGE, so it must define it with one TOOL_IMAGE= "+
			"line and one [ -n \"$TOOL_IMAGE\" ] guard; found %d such lines", name, len(def))}
	}
	cmd := exec.Command("bash", "-c", "set -euo pipefail\n"+strings.Join(def, "\n")+"\nprintf %s \"$TOOL_IMAGE\"")
	cmd.Dir = dir
	cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "TOOL_IMAGE=") })
	out, err := cmd.CombinedOutput()
	if err != nil {
		return []string{fmt.Sprintf("%s: its TOOL_IMAGE definition does not resolve (%v): %s", name, err, out)}
	}
	if got := string(out); got != want {
		return []string{fmt.Sprintf("%s: TOOL_IMAGE defaults to %q, not %s's FROM reference %q; "+
			"read it from the Dockerfile so the digest is stated once", name, got, toolDockerfile, want)}
	}
	return nil
}

func realScripts(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob("*.sh")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no regtest/*.sh found (%v); these rules would pass having read nothing", err)
	}
	scripts := map[string]string{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		scripts[p] = string(raw)
	}
	return scripts
}

func toolFrom(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(toolDockerfile)
	if err != nil {
		t.Fatal(err)
	}
	ref := fromReference(string(raw))
	if !pinnedImage(ref) {
		t.Fatalf("%s's FROM reference %q is not tag@sha256-pinned; every script's TOOL_IMAGE "+
			"inherits whatever it names", toolDockerfile, ref)
	}
	return ref
}

func TestEveryScriptImageIsPinned(t *testing.T) {
	scripts := realScripts(t)
	for _, p := range checkScriptImages(scripts) {
		t.Error(p)
	}
	// The control: a rule over files with no `docker run` in them agrees with
	// everything. These scripts run images in thirty-odd places today.
	runs := 0
	for _, src := range scripts {
		for _, l := range joinContinuations(src) {
			if _, ok := runImage(l.text); ok {
				runs++
			}
		}
	}
	if runs < 10 {
		t.Errorf("found only %d `docker run` sites across regtest/*.sh; the rule above is "+
			"asserting over almost nothing", runs)
	}

	const pinned = "alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
	for _, tc := range []struct {
		src  string
		want string // "" means clean
	}{
		{`cred_stat() { docker run --rm -v brollyregtest_credentials:/c "$TOOL_IMAGE" stat /c/x; }`, ""},
		{`docker run --rm -i "$TOOL_IMAGE" sha256sum`, ""},
		{`docker run --rm -v "$DBVOL:/data" brollyregtest-sqlite /data/db.sqlite`, ""},
		{"docker run --rm " + pinned + " uname -m", ""},
		{`case "$(docker run --rm "$TOOL_IMAGE" uname -m)" in`, ""},
		// Criterion 3: the site this bead removed, put back.
		{`cred_stat()  { docker run --rm -v brollyregtest_credentials:/c alpine:3.20 stat -c '%s' "/c/$1"; }`,
			`planted.sh:1: ` + "`docker run`" + ` names image "alpine:3.20"`},
		// Criterion 4: the image on a continuation line — the plant that proves the join.
		{"x=1\ndocker run --rm -v \"$WORK:/w\" \\\n  alpine:3.20 /w/nwctool \"$@\"",
			`planted.sh:2: ` + "`docker run`" + ` names image "alpine:3.20"`},
		{`docker run --rm --net="container:$srv" alpine:3.20 netstat -tn`, `names image "alpine:3.20"`},
		{"docker run --rm alpine" + pinned[len("alpine:3.24"):] + " uname -m", `names image "alpine@sha256:`},
		// An unknown boolean flag reads the command as the image: loud, not silent.
		{`docker run --rm --privileged "$TOOL_IMAGE" uname -m`, `names image "uname"`},
	} {
		found := checkScriptImages(map[string]string{"planted.sh": tc.src})
		switch {
		case tc.want == "" && len(found) != 0:
			t.Errorf("clean case flagged:\n%s\n→ %v", tc.src, found)
		case tc.want != "" && (len(found) == 0 || !strings.Contains(found[0], tc.want)):
			t.Errorf("planted case not caught as %q:\n%s\n→ %v", tc.want, tc.src, found)
		}
	}
}

func TestEveryToolImageDefaultIsTheDockerfilesFrom(t *testing.T) {
	want := toolFrom(t)
	scripts := realScripts(t)
	users := 0
	for _, name := range slices.Sorted(maps.Keys(scripts)) {
		if strings.Contains(scripts[name], "$TOOL_IMAGE") {
			users++
		}
		for _, p := range checkToolImageDefault(name, scripts[name], ".", want) {
			t.Error(p)
		}
	}
	// Six scripts carry the definition today; a derivation nobody uses is not
	// the thing this asserts over.
	if users < 6 {
		t.Errorf("only %d scripts use $TOOL_IMAGE; expected the six that run a tool image", users)
	}

	const guard = `[ -n "$TOOL_IMAGE" ] || { echo "FAIL could not read the tool image" >&2; exit 1; }`
	derive := func(path string) string {
		return `TOOL_IMAGE="${TOOL_IMAGE:-$(awk '$1 == "FROM" { print $2; exit }' ` + path + ` 2>/dev/null || true)}"`
	}
	use := "\ndocker run --rm \"$TOOL_IMAGE\" uname -m\n"
	for _, tc := range []struct {
		src, want string
	}{
		{derive(toolDockerfile) + "\n" + guard + use, ""},
		// Criterion 5: a default that is not the Dockerfile's.
		{`TOOL_IMAGE="${TOOL_IMAGE:-alpine:3.24}"` + "\n" + guard + use, `TOOL_IMAGE defaults to "alpine:3.24"`},
		{derive("tools/nope/Dockerfile") + "\n" + guard + use, "does not resolve"},
		{derive(toolDockerfile) + use, "found 1 such lines"},
	} {
		found := checkToolImageDefault("planted.sh", tc.src, ".", want)
		switch {
		case tc.want == "" && len(found) != 0:
			t.Errorf("clean case flagged:\n%s\n→ %v", tc.src, found)
		case tc.want != "" && (len(found) == 0 || !strings.Contains(found[0], tc.want)):
			t.Errorf("planted case not caught as %q:\n%s\n→ %v", tc.want, tc.src, found)
		}
	}
}
