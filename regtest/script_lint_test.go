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
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// toolDockerfile is the one statement of the tool image's reference. Dependabot
// maintains it (its docker entry for that directory, 0vk.58), and every script's
// TOOL_IMAGE default is read from it at run time, so a bump moves the scripts in
// the same PR and no script states the digest (this file's plants read it from
// the Dockerfile too).
const toolDockerfile = "tools/sqlite/Dockerfile"

// fromReference is the image a Dockerfile's FIRST `FROM` line names — the same
// line the scripts' awk reads. The Dockerfile is single-stage; a second stage or
// a `FROM --platform=` would change what both read, and toolFrom's pin check
// fails loudly when it does.
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

// joinContinuations joins `\`-continued lines. Three of nwc.sh's eight sites put
// the image on the line AFTER `docker run … \`, so a per-line scan over lines
// containing `docker run` reads a line with no image on it and passes.
func joinContinuations(src string) []logicalLine {
	var out []logicalLine
	var cur strings.Builder
	start := 0
	for i, text := range strings.Split(src, "\n") {
		if cur.Len() == 0 {
			start = i + 1
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

// dockerRunRE finds each `docker run` on a line, however spaced, and the
// `docker container run` spelling of it (0vk.59 go-review: a literal
// "docker run " missed both, and a second run after `;` on the same line).
var dockerRunRE = regexp.MustCompile(`\bdocker\s+(?:container\s+)?run\s`)

// stripComment drops a `#` comment that starts a word outside quotes, so a
// comment mentioning `docker run` is not read as one. `${#x}` and `a#b` are not
// comments: the `#` does not start a word.
func stripComment(text string) string {
	var quote rune
	prev := ' '
	for i, r := range text {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '#' && (prev == ' ' || prev == '\t'):
			return text[:i]
		}
		prev = r
	}
	return text
}

// runImages is the image word of every `docker run` in text; "" for a run whose
// flags have nothing after them, which acceptableImage then refuses.
func runImages(text string) []string {
	var images []string
	for _, loc := range dockerRunRE.FindAllStringIndex(text, -1) {
		images = append(images, runImage(text[loc[1]:]))
	}
	return images
}

// runImage is the image word of the arguments after one `docker run`.
func runImage(after string) string {
	words := shellWords(after)
	for i := 0; i < len(words); i++ {
		w := words[i]
		if !strings.HasPrefix(w, "-") {
			return w
		}
		if !strings.Contains(w, "=") && !slices.Contains(dockerRunBooleans, w) {
			i++ // the flag's value
		}
	}
	return ""
}

// acceptableImage: a variable, a locally built brollyregtest-* image, or a
// reference pinned by tag and digest.
//
// A VARIABLE IS TRUSTED HERE, and that is a known blind spot, not an oversight:
// only $TOOL_IMAGE's value is checked (checkToolImageDefault). $SQLITE_IMAGE is
// a brollyregtest-* name; $LND_IMAGE defaults to a tag with no digest in cap.sh,
// spend.sh and ipaddr.sh, which this bead did not take on — its report says so.
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
			for _, image := range runImages(stripComment(l.text)) {
				if acceptableImage(image) {
					continue
				}
				found = append(found, fmt.Sprintf("%s:%d: `docker run` names image %q; use \"$TOOL_IMAGE\" "+
					"(read from %s), another variable, a brollyregtest-* image, or a tag@sha256 pin — "+
					"a bare tag is whatever was pulled first, and on a fresh runner whatever it means "+
					"that day", name, l.line, image, toolDockerfile))
			}
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

// scriptsWith is the sorted names of the scripts whose text contains marker.
func scriptsWith(scripts map[string]string, marker string) []string {
	var names []string
	for _, name := range slices.Sorted(maps.Keys(scripts)) {
		if strings.Contains(scripts[name], marker) {
			names = append(names, name)
		}
	}
	return names
}

// The controls, as lists rather than floors — stack_lint_test.go's ruling for
// its services, for the same reason: a count passes a set that gained one and
// lost another. What would change them: a script that starts or stops running
// a container, which is a change worth a reader's attention.
var (
	dockerRunScripts = []string{"authorise.sh", "cap.sh", "e2e.sh", "ipaddr.sh", "nwc.sh", "rotation.sh", "spend.sh"}
	toolImageScripts = []string{"authorise.sh", "cap.sh", "e2e.sh", "nwc.sh", "rotation.sh", "spend.sh"}
)

type plant struct{ src, want string } // want "" means clean

func assertPlants(t *testing.T, check func(src string) []string, plants []plant) {
	t.Helper()
	for _, tc := range plants {
		found := check(tc.src)
		switch {
		case tc.want == "" && len(found) != 0:
			t.Errorf("clean case flagged:\n%s\n→ %v", tc.src, found)
		case tc.want != "" && (len(found) == 0 || !strings.Contains(found[0], tc.want)):
			t.Errorf("planted case not caught as %q:\n%s\n→ %v", tc.want, tc.src, found)
		}
	}
}

func TestEveryScriptImageIsPinned(t *testing.T) {
	scripts := realScripts(t)
	for _, p := range checkScriptImages(scripts) {
		t.Error(p)
	}
	var running []string
	for _, name := range slices.Sorted(maps.Keys(scripts)) {
		if dockerRunRE.MatchString(scripts[name]) {
			running = append(running, name)
		}
	}
	if got := running; !slices.Equal(got, dockerRunScripts) {
		t.Errorf("scripts running a container are %v, and this file expects %v; the rule above "+
			"asserts over whatever is there", got, dockerRunScripts)
	}

	pinned := toolFrom(t) // read, not restated: the plants must not be a second statement of the digest
	digestOnly := "alpine" + pinned[strings.Index(pinned, "@"):]
	assertPlants(t, func(src string) []string {
		return checkScriptImages(map[string]string{"planted.sh": src})
	}, []plant{
		{`cred_stat() { docker run --rm -v brollyregtest_credentials:/c "$TOOL_IMAGE" stat /c/x; }`, ""},
		{`docker run --rm -i "$TOOL_IMAGE" sha256sum`, ""},
		{`docker run --rm -v "$DBVOL:/data" brollyregtest-sqlite /data/db.sqlite`, ""},
		{"docker run --rm " + pinned + " uname -m", ""},
		{`case "$(docker run --rm "$TOOL_IMAGE" uname -m)" in`, ""},
		// Criterion 3: the site this bead removed, put back.
		{`cred_stat()  { docker run --rm -v brollyregtest_credentials:/c alpine:3.20 stat -c '%s' "/c/$1"; }`,
			"planted.sh:1: `docker run` names image \"alpine:3.20\""},
		// Criterion 4: the image on a continuation line — the plant that proves the join.
		{"x=1\ndocker run --rm -v \"$WORK:/w\" \\\n  alpine:3.20 /w/nwctool \"$@\"",
			"planted.sh:2: `docker run` names image \"alpine:3.20\""},
		{`docker run --rm --net="container:$srv" alpine:3.20 netstat -tn`, `names image "alpine:3.20"`},
		{"docker run --rm " + digestOnly + " uname -m", `names image "alpine@sha256:`},
		// go-review: a second run on the line, the other spellings, and a comment.
		{`docker run --rm "$TOOL_IMAGE" true; docker run --rm alpine:3.20 uname -m`, `names image "alpine:3.20"`},
		{`x=$(docker run --rm "$TOOL_IMAGE" true && docker run --rm alpine:3.20 uname -m)`, `names image "alpine:3.20"`},
		{`docker  run --rm alpine:3.20 uname -m`, `names image "alpine:3.20"`},
		{`docker container run --rm alpine:3.20 uname -m`, `names image "alpine:3.20"`},
		{`x=1  # docker run alpine:3.20 is what this used to say`, ""},
		{`echo "a # not a comment"; docker run --rm alpine:3.20 true`, `names image "alpine:3.20"`},
		// An unknown boolean flag reads the command as the image: loud, not silent.
		{`docker run --rm --privileged "$TOOL_IMAGE" uname -m`, `names image "uname"`},
	})
}

func TestEveryToolImageDefaultIsTheDockerfilesFrom(t *testing.T) {
	want := toolFrom(t)
	scripts := realScripts(t)
	for _, name := range slices.Sorted(maps.Keys(scripts)) {
		for _, p := range checkToolImageDefault(name, scripts[name], ".", want) {
			t.Error(p)
		}
	}
	if got := scriptsWith(scripts, "$TOOL_IMAGE"); !slices.Equal(got, toolImageScripts) {
		t.Errorf("scripts using $TOOL_IMAGE are %v, and this file expects %v", got, toolImageScripts)
	}

	const guard = `[ -n "$TOOL_IMAGE" ] || { echo "FAIL could not read the tool image" >&2; exit 1; }`
	derive := func(path string) string {
		return `TOOL_IMAGE="${TOOL_IMAGE:-$(awk '$1 == "FROM" { print $2; exit }' ` + path + ` 2>/dev/null || true)}"`
	}
	use := "\ndocker run --rm \"$TOOL_IMAGE\" uname -m\n"
	assertPlants(t, func(src string) []string {
		return checkToolImageDefault("planted.sh", src, ".", want)
	}, []plant{
		{derive(toolDockerfile) + "\n" + guard + use, ""},
		// Criterion 5: a default that is not the Dockerfile's.
		{`TOOL_IMAGE="${TOOL_IMAGE:-alpine:3.24}"` + "\n" + guard + use, `TOOL_IMAGE defaults to "alpine:3.24"`},
		{derive("tools/nope/Dockerfile") + "\n" + guard + use, "does not resolve"},
		{derive(toolDockerfile) + use, "found 1 such lines"},
	})
}
