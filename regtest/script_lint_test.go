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
// AN *_IMAGE VARIABLE PASSES HERE BECAUSE ITS DEFAULT IS CHECKED, not because it is
// trusted: checkImageDefaults executes every *_IMAGE definition in every script
// with the variable unset and requires the value it resolves to — TOOL_IMAGE the
// Dockerfile's FROM, LND_IMAGE the compose file's parsed lnd image, SQLITE_IMAGE a
// brollyregtest-* build — and refuses an *_IMAGE variable it has no rule for. Any
// other variable is refused here, since nothing would check what it holds (0vk.61;
// until then every $variable passed, and $LND_IMAGE held a bare tag).
func acceptableImage(image string) bool {
	switch {
	case imageVariableRE.MatchString(image):
		return true
	case localBuildName(image):
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
					"(read from %s), another *_IMAGE variable, a brollyregtest-* image, or a tag@sha256 pin — "+
					"a bare tag is whatever was pulled first, and on a fresh runner whatever it means "+
					"that day", name, l.line, image, toolDockerfile))
			}
		}
	}
	return found
}

// imageStatement is where an image variable's default must come from: the one
// statement of that image in the tree, and the reference it holds — or, for a
// local build, nothing to pin at all.
type imageStatement struct {
	from string // for the message: "tools/sqlite/Dockerfile's FROM reference"
	want string
	// local is an image a script BUILDS (rotation.sh: `docker build -t
	// "$SQLITE_IMAGE" tools/sqlite`): there is no registry reference, so the
	// default must be a brollyregtest-* name, and a literal name has no read that
	// can come back empty, so it carries no guard.
	local bool
}

var (
	imageAssignRE = regexp.MustCompile(`^([A-Z][A-Z0-9_]*_IMAGE)=`)
	imageUseRE    = regexp.MustCompile(`\$\{?([A-Z][A-Z0-9_]*_IMAGE)\b`)
	// imageVariableRE is a `docker run` image word that is one *_IMAGE variable.
	imageVariableRE = regexp.MustCompile(`^\$(?:[A-Z][A-Z0-9_]*_IMAGE|\{[A-Z][A-Z0-9_]*_IMAGE\})$`)
)

// localBuildName is an image a script builds itself: brollyregtest-*, with no
// registry, tag or digest.
func localBuildName(image string) bool {
	return strings.HasPrefix(image, "brollyregtest-") && !strings.ContainsAny(image, ":/@")
}

// checkImageDefaults runs each image variable's definition in a script — its
// assignment and, for a pulled image, the guard after it, nothing else — in dir
// with the variable unset, and requires what it prints. Executed, not matched as
// text: the assertion is what the default RESOLVES to, which a string compare
// against one blessed spelling of the awk would not prove.
//
// Every *_IMAGE the script assigns or reads outside a comment is judged, so an
// image variable this file has no statement for is refused by name rather than
// trusted.
func checkImageDefaults(name, src, dir string, statements map[string]imageStatement) []string {
	vars := map[string]bool{}
	for _, l := range joinContinuations(src) {
		code := stripComment(l.text)
		for _, m := range imageUseRE.FindAllStringSubmatch(code, -1) {
			vars[m[1]] = true
		}
		if m := imageAssignRE.FindStringSubmatch(strings.TrimSpace(code)); m != nil {
			vars[m[1]] = true
		}
	}
	var found []string
	for _, v := range slices.Sorted(maps.Keys(vars)) {
		statement, known := statements[v]
		if !known {
			found = append(found, fmt.Sprintf("%s: uses $%s, which is not an image variable this file "+
				"knows; give it a statement to resolve to in imageStatements", name, v))
			continue
		}
		var def []string
		assigns, guards := 0, 0
		for line := range strings.Lines(src) {
			switch t := strings.TrimSpace(line); {
			case strings.HasPrefix(t, v+"="):
				def, assigns = append(def, t), assigns+1
			case strings.HasPrefix(t, `[ -n "$`+v+`" ]`):
				def, guards = append(def, t), guards+1
			}
		}
		shape, wantGuards := "one "+v+"= line and one [ -n \"$"+v+"\" ] guard", 1
		if statement.local {
			shape, wantGuards = "one "+v+"= line", 0
		}
		if assigns != 1 || guards != wantGuards {
			found = append(found, fmt.Sprintf("%s: uses $%s, so it must define it with %s; found %d such lines",
				name, v, shape, len(def)))
			continue
		}
		cmd := exec.Command("bash", "-c", "set -euo pipefail\n"+strings.Join(def, "\n")+"\nprintf %s \"$"+v+"\"")
		cmd.Dir = dir
		cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, v+"=") })
		out, err := cmd.CombinedOutput()
		if err != nil {
			found = append(found, fmt.Sprintf("%s: its %s definition does not resolve (%v): %s", name, v, err, out))
			continue
		}
		// A pulled want is pinned already: toolFrom and lndImage refuse one that is not.
		switch got := string(out); {
		case statement.local && !localBuildName(got):
			found = append(found, fmt.Sprintf("%s: %s defaults to %q, which is not a brollyregtest-* local build",
				name, v, got))
		case !statement.local && got != statement.want:
			found = append(found, fmt.Sprintf("%s: %s defaults to %q, not %s %q; read it from there so the "+
				"digest is stated once", name, v, got, statement.from, statement.want))
		}
	}
	return found
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

// lndImage is the image the compose file's lnd service runs, as the PARSER reads
// it — through `<<: *lnd-common`, which yaml.v3 decodes — so the scripts' awk over
// the text is proved against the document, and this file reads no compose text
// (BrollyZap-20i.24).
func lndImage(t *testing.T) string {
	t.Helper()
	c, _ := load(t)
	ref := c.Services["lnd"].Image
	if !pinnedImage(ref) {
		t.Fatalf("%s's lnd image %q is not tag@sha256-pinned; every script's LND_IMAGE inherits it",
			composePath, ref)
	}
	return ref
}

// imageStatements is every image variable a script may use, and what it must resolve to.
func imageStatements(t *testing.T) map[string]imageStatement {
	t.Helper()
	return map[string]imageStatement{
		"TOOL_IMAGE":   {from: toolDockerfile + "'s FROM reference", want: toolFrom(t)},
		"LND_IMAGE":    {from: composePath + "'s parsed lnd image", want: lndImage(t)},
		"SQLITE_IMAGE": {local: true},
	}
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
	dockerRunScripts   = []string{"authorise.sh", "cap.sh", "e2e.sh", "ipaddr.sh", "nwc.sh", "rotation.sh", "spend.sh"}
	toolImageScripts   = []string{"authorise.sh", "cap.sh", "e2e.sh", "nwc.sh", "rotation.sh", "spend.sh"}
	lndImageScripts    = []string{"cap.sh", "ipaddr.sh", "spend.sh"}
	sqliteImageScripts = []string{"rotation.sh"}
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
		{`docker run --rm "${LND_IMAGE}" true`, ""},
		// 0vk.61: a variable whose default nothing checks is not a pin.
		{`docker run --rm "$IMG" true`, `names image "$IMG"`},
		{`docker run --rm "${IMAGE_TAG}" true`, `names image "${IMAGE_TAG}"`},

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

func TestEveryImageVariableResolvesToItsOneStatement(t *testing.T) {
	statements := imageStatements(t)
	scripts := realScripts(t)
	for _, name := range slices.Sorted(maps.Keys(scripts)) {
		for _, p := range checkImageDefaults(name, scripts[name], ".", statements) {
			t.Error(p)
		}
	}
	for marker, want := range map[string][]string{
		"$TOOL_IMAGE":   toolImageScripts,
		"$LND_IMAGE":    lndImageScripts,
		"$SQLITE_IMAGE": sqliteImageScripts,
	} {
		if got := scriptsWith(scripts, marker); !slices.Equal(got, want) {
			t.Errorf("scripts using %s are %v, and this file expects %v", marker, got, want)
		}
	}

	check := func(src string) []string {
		return checkImageDefaults("planted.sh", src, ".", statements)
	}
	guard := func(v string) string {
		return `[ -n "$` + v + `" ] || { echo "FAIL could not read ` + v + `" >&2; exit 1; }`
	}
	use := func(v string) string { return "\ndocker run --rm \"$" + v + "\" true\n" }
	toolDerive := func(path string) string {
		return `TOOL_IMAGE="${TOOL_IMAGE:-$(awk '$1 == "FROM" { print $2; exit }' ` + path + ` 2>/dev/null || true)}"`
	}
	lndDerive := func(path string) string {
		return `LND_IMAGE="${LND_IMAGE:-$(awk '$1 == "x-lnd-common:" { in_lnd = 1; next } /^[^ #]/ { in_lnd = 0 } ` +
			`in_lnd && $1 == "image:" { print $2; exit }' ` + path + ` 2>/dev/null || true)}"`
	}
	toolGuard, toolUse := guard("TOOL_IMAGE"), use("TOOL_IMAGE")
	lndGuard, lndUse := guard("LND_IMAGE"), use("LND_IMAGE")
	assertPlants(t, check, []plant{
		{toolDerive(toolDockerfile) + "\n" + toolGuard + toolUse, ""},
		// 0vk.59 criterion 5: a default that is not the Dockerfile's.
		{`TOOL_IMAGE="${TOOL_IMAGE:-alpine:3.24}"` + "\n" + toolGuard + toolUse, `TOOL_IMAGE defaults to "alpine:3.24"`},
		{toolDerive("tools/nope/Dockerfile") + "\n" + toolGuard + toolUse, "TOOL_IMAGE definition does not resolve"},
		{toolDerive(toolDockerfile) + toolUse, "found 1 such lines"},
		{lndDerive(composePath) + "\n" + lndGuard + lndUse, ""},
		// 0vk.61 criterion 10: the bare tag this bead removed, and a read of a file that is not there.
		{`LND_IMAGE="${LND_IMAGE:-lightninglabs/lnd:v0.21.1-beta}"` + "\n" + lndGuard + lndUse,
			`LND_IMAGE defaults to "lightninglabs/lnd:v0.21.1-beta", not ` + composePath + `'s parsed lnd image "` + statements["LND_IMAGE"].want + `"`},
		{lndDerive("nope-compose.yml") + "\n" + lndGuard + lndUse, "LND_IMAGE definition does not resolve"},
		{`LND_IMAGE="${LND_IMAGE:-lightninglabs/lnd:v0.21.1-beta}"` + lndUse, "found 1 such lines"},
		{`LND_IMAGE="${LND_IMAGE:-x}"` + "\n" + `LND_IMAGE="${LND_IMAGE:-y}"` + lndUse, "found 2 such lines"},
		// A local build is a brollyregtest-* name, and nothing else.
		{"SQLITE_IMAGE=brollyregtest-sqlite\ndocker run --rm \"$SQLITE_IMAGE\" /data/db.sqlite\n", ""},
		{"SQLITE_IMAGE=keinos/sqlite3:latest\ndocker run --rm \"$SQLITE_IMAGE\" /data/db.sqlite\n", "not a brollyregtest-* local build"},
		// A comment naming an image variable is not a use of one.
		{"# was $RELAY_IMAGE once\n" + toolDerive(toolDockerfile) + "\n" + toolGuard + toolUse, ""},
		// An image variable nobody wrote a statement for is refused, not trusted.
		{`RELAY_IMAGE="${RELAY_IMAGE:-dockurr/strfry:latest}"` + "\ndocker run --rm \"$RELAY_IMAGE\" true\n", "not an image variable this file knows"},
	})
}
