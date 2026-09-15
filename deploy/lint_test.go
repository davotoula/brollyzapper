// Package deploy holds the plain-Docker deployment template and the lint that
// keeps it honest. It contains test files only.
//
// WHY A LINT AND NOT A README. This template is a second statement of two
// things that already exist elsewhere: the config package's environment
// contract, and the App Store package's pinned images. Both drift silently —
// a mistyped variable name is a silent default rather than an error, and a
// release that re-pins the package without re-pinning here ships a template
// that installs last month's binaries. Each check below is one of those.
//
// ONE READER FOR THE THREE LINTS, internal/composelint, since BrollyZap-20i.18.
// This file, umbrel/lint_test.go and regtest/lint_test.go each loaded their
// compose as `(struct, raw)`, and every defect the 20i epic closed in them was a
// raw-text scan standing beside a struct already parsed — several introduced
// inside the fix for the one before, because the string was in scope. The reader
// hands out no text: scalars with their lines, interpolations, defaults, a key's
// comment, the comments themselves for the one check whose subject is a comment.
//
// THE READER IS SHARED, THE STRUCT IS NOT. A shared composeFile would be the
// UNION of three different documents — umbrel alone needs container_name and
// env_file, this file alone top-level networks and depends_on, regtest alone
// command — and a field a lint does not read is exactly the vacuity risk this
// family of checks hunts. So each lint keeps its own struct, its own tests and
// its own messages, and decodes into it through the one loader.
//
// The .env.example is not compose and does not go through the reader: it has no
// structure to parse, and `#` genuinely starts a comment there.
package deploy

import (
	"cmp"
	"errors"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/composelint"
	"github.com/davotoula/brollyzapper/internal/config"
)

const (
	composePath = "docker-compose.yml"
	envPath     = ".env.example"
	// The package this template must stay in step with.
	packageCompose = "../umbrel/brollyzapper/docker-compose.yml"
)

type composeFile struct {
	Services map[string]struct {
		Image     string   `yaml:"image"`
		User      string   `yaml:"user"`
		Volumes   []string `yaml:"volumes"`
		Ports     []string `yaml:"ports"`
		Restart   string   `yaml:"restart"`
		DependsOn []string `yaml:"depends_on"`
		// The list spelling of environment decodes into a map with a LOUD error, not
		// a silent empty one, and loadCompose turns that into a Fatalf. networks is
		// not a field: the two services spell it differently, and the address check
		// asks the document for the server's mapping form.
		Environment map[string]string `yaml:"environment"`
	} `yaml:"services"`
	Networks map[string]struct {
		IPAM struct {
			Config []struct {
				Subnet string `yaml:"subnet"`
			} `yaml:"config"`
		} `yaml:"ipam"`
	} `yaml:"networks"`
}

// loadCompose is the template, decoded into this lint's own struct, and its
// document. There is no text: a check that wants to know what the file says asks
// the document (BrollyZap-20i.18).
func loadCompose(t *testing.T) (composeFile, *composelint.Document) {
	t.Helper()
	var compose composeFile
	doc := composelint.Load(t, composePath, &compose)
	// Both services, by name, or the assertions below inspect nothing. Every
	// check here keys off one of these two, so a rename would otherwise turn the
	// whole file into a set of vacuous passes.
	for _, want := range []string{"guard", "server"} {
		if _, ok := compose.Services[want]; !ok {
			t.Fatalf("%s declares no %q service; this lint is reading the wrong thing",
				composePath, want)
		}
	}
	for _, name := range []string{"guard", "server"} {
		if len(compose.Services[name].Environment) == 0 {
			t.Fatalf("the %s service declares no environment; this template sets one on "+
				"both, so the settings checks below would assert nothing", name)
		}
	}
	return compose, doc
}

// contract is what internal/config actually reads.
type contract struct{ required, optional []string }

// configContract asks the config package itself what it reads, by calling both
// loaders with a Lookup that records every name and supplies nothing.
//
// THE BEHAVIOUR, NOT THE ARTIFACT. The first version of this parsed config.go
// with go/ast and matched the p.required*/p.optional* call shape — which is
// asserting the source's spelling rather than the package's behaviour, and it
// needed its own floor guard because a parser that stopped matching would have
// made every check below it vacuous. This cannot go vacuous: the names come from
// the loader actually running, and if it asks for nothing the assertions below
// fail rather than pass.
//
// REQUIRED FALLS OUT OF THE ERROR. With nothing set, p.err() is an errors.Join
// of one *config.VarError per variable the loader insisted on, so the required
// subset needs no second rule to identify it — and a variable that moves from
// optional to required is picked up here the day it moves.
//
// It is also a fourth statement of nothing: regtest/lint_test.go keeps a
// hand-written genericSettings list, and this is the form that could replace it.
func configContract(t *testing.T) map[string]contract {
	t.Helper()
	out := map[string]contract{}
	for _, loader := range []struct {
		which string
		load  func(config.Lookup) error
	}{
		{"Server", func(l config.Lookup) error { _, err := config.LoadServer(l); return err }},
		{"Guard", func(l config.Lookup) error { _, err := config.LoadGuard(l); return err }},
	} {
		var asked []string
		err := loader.load(func(name string) (string, bool) {
			asked = append(asked, name)
			return "", false
		})
		if err == nil {
			t.Fatalf("%s accepted an entirely empty environment; this derivation reads the "+
				"required settings out of its complaint, and there is none", loader.which)
		}
		var required []string
		for _, e := range unwrapJoined(err) {
			var varErr *config.VarError
			if errors.As(e, &varErr) {
				required = append(required, varErr.Var)
			}
		}
		var optional []string
		for _, name := range asked {
			if !slices.Contains(required, name) {
				optional = append(optional, name)
			}
		}
		out[loader.which] = contract{required: required, optional: optional}
	}
	return out
}

// unwrapJoined splits an errors.Join, and returns a lone error unchanged.
func unwrapJoined(err error) []error {
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return []error{err}
	}
	return joined.Unwrap()
}

// TestTheTemplateSetsEveryRequiredSettingAndNoInventedOne is check 1: the
// template and the config package agree, in both directions.
//
// BOTH DIRECTIONS MATTER, and the second one is the reason this test exists.
// A missing required variable fails loudly on the operator's host at start-up.
// An INVENTED one — `LND_ADRESS`, `TRUSTED_PROXY` — never fails at all: the
// config package does not read it, the real setting takes its default, and the
// operator gets a working app with a setting they believe they set.
func TestTheTemplateSetsEveryRequiredSettingAndNoInventedOne(t *testing.T) {
	compose, _ := loadCompose(t)
	contracts := configContract(t)

	for _, s := range []struct{ service, which string }{{"server", "Server"}, {"guard", "Guard"}} {
		svc := compose.Services[s.service]
		env := svc.Environment
		c := contracts[s.which]
		for _, name := range c.required {
			if _, ok := env[name]; !ok {
				t.Errorf("the %s service does not set %s, which internal/config REQUIRES; "+
					"the container will refuse to start on the operator's host", s.service, name)
			}
		}
		for name := range env {
			if slices.Contains(c.required, name) || slices.Contains(c.optional, name) {
				continue
			}
			t.Errorf("the %s service sets %s, which internal/config never reads: it is a "+
				"typo or a leftover, and either way the setting the operator meant to make "+
				"is silently at its default", s.service, name)
		}
	}
}

// umbrelOnly are the variables that belong to the Umbrel package alone. None
// can mean anything here.
//
// NAMED RATHER THAN PATTERN-MATCHED on `APP_` alone, because NETWORK_IP and the
// PROXY_ family carry no prefix and are exactly the ones a copy-paste from the
// package would bring across.
//
// passwordManagedVar is the odd one out in that list, and the reason it has to
// be there: unlike the rest, internal/config DOES read it, so the "no invented
// setting" check above would wave it through — it is a real setting that is
// simply never right in this template. It says the PLATFORM supplies the admin
// password and displays it, which is true of umbrelOS and false of a host where
// the operator typed it into .env. Set here it would hide the Settings password
// field and leave that operator unable to change a password nothing else is
// showing them (`20i.5`).
const passwordManagedVar = "ADMIN_PASSWORD_MANAGED"

var umbrelOnly = []string{"APP_", "NETWORK_IP", "PROXY_", passwordManagedVar}

func TestNoUmbrelOnlySettingAppearsAnywhere(t *testing.T) {
	_, doc := loadCompose(t)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the deploy directory: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		scanned++
		// COMMENTS ARE EXEMPT, as they are in both neighbouring lints. This
		// repository's convention is that comments record WHY, and the template
		// cannot explain what it does differently from the Umbrel package without
		// naming the package's variables. What matters is what compose
		// INTERPOLATES, which is never a comment.
		//
		// THE COMPOSE FILE IS EXEMPTED BY ITS PARSER, NOT BY A `#` RULE, and the
		// difference is two measured holes. withoutComments cuts each line at the
		// first `#`, so `TRUSTED_PROXIES: "see # note: ${NETWORK_IP}"` hid an
		// umbrelOS-only variable that compose still interpolates — and a
		// double-quoted scalar folded with a trailing backslash split
		// `${NETWORK_I` / `P}` across two lines, which no line scan can rejoin
		// and which yaml rejoins for compose. Both measured on f49f08f, both in
		// the silent direction: the check exists to FORBID these names, so a name
		// it cannot see is a name it permits. Scalars carry neither hazard.
		//
		// The other files stay a line scan: .env.example has no structure to
		// parse, and `#` genuinely starts a comment there.
		cleaned := commentFreeText(t, e.Name(), doc)
		for _, needle := range umbrelOnly {
			if !strings.Contains(cleaned, needle) {
				continue
			}
			// Two different failures wear the same name, and telling an operator
			// the wrong one costs them the search: the injected variables
			// interpolate to nothing here, while ADMIN_PASSWORD_MANAGED is a
			// setting the app really reads and would really act on.
			if needle == passwordManagedVar {
				t.Errorf("%s sets %s. internal/config READS it, so nothing else will complain "+
					"— and it tells the app the platform supplies and displays the admin "+
					"password, which is umbrelOS and is not this. Here it hides the Settings "+
					"password field from an operator who chose that password themselves and "+
					"has no other way to change it (`20i.5`)", e.Name(), needle)
				continue
			}
			t.Errorf("%s mentions %s, which only umbrelOS sets; here it interpolates to "+
				"empty and the setting it was meant to make silently disappears",
				e.Name(), needle)
		}
	}
	// A scan that reads nothing passes silently, which is the one result this
	// check cannot afford.
	if scanned < 2 {
		t.Errorf("scanned %d files in deploy/; the template and its env example are both "+
			"here, so this check is reading the wrong thing", scanned)
	}
}

// commentFreeText is a file's content with its comments gone, by whichever route
// the file's own shape allows: the compose is its document's scalars and anchor
// names — never its text — and anything else is read and cut at `#`. See the two
// hazards recorded at the call site.
func commentFreeText(t *testing.T, name string, compose *composelint.Document) string {
	t.Helper()
	var out strings.Builder
	if name != composePath {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		return withoutComments(string(raw))
	}
	for _, scalar := range compose.Scalars() {
		out.WriteString(scalar.Value)
		out.WriteString("\n")
	}
	// ANCHORS TOO, and that is not theoretical tidiness. An anchor name is not a
	// scalar Value, so `environment: &NETWORK_IP_anchor` put a forbidden name in
	// the file and this check passed — measured, and it is the same silent
	// direction as the two holes above.
	for _, anchor := range compose.Anchors() {
		out.WriteString(anchor.Name)
		out.WriteString("\n")
	}
	return out.String()
}

// withoutComments blanks whole-line and trailing `#` comments, for the files
// that have no parser. The env example is shell-shaped, where `#` starts a
// comment and no value legitimately contains one.
func withoutComments(raw string) string {
	var out strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
	return out.String()
}

var imageRE = regexp.MustCompile(`ghcr\.io/davotoula/brollyzapper(-guard)?:[0-9][0-9a-zA-Z.\-]*@sha256:[0-9a-f]{64}`)

// TestTheImagesEqualThePackages is check 3, and it is aimed at the release
// procedure rather than at this file.
//
// A release re-pins the App Store package's digests. Nothing made it re-pin
// this template, so the failure mode is a template that quietly installs the
// previous release — with an operator following a procedure that says nothing
// is wrong. Equality here makes the pin step update both or go red.
func TestTheImagesEqualThePackages(t *testing.T) {
	compose, _ := loadCompose(t)
	var pkg composeFile
	composelint.Load(t, packageCompose, &pkg)

	// PER SERVICE, NOT AS A SET. The first version pulled every digest-pinned
	// reference out of each file's raw text and compared the two sorted sets —
	// which is blind to the one edit that matters most here: swap the two image
	// lines, so the server runs the guard's binary and the guard the server's,
	// and both files still yield the same two strings in the same sorted order.
	// The go-review pass reproduced that. The service is the unit, because the
	// guard/server split is what §3 is.
	for _, name := range []string{"guard", "server"} {
		mine, theirs := compose.Services[name].Image, pkg.Services[name].Image
		if !imageRE.MatchString(theirs) {
			t.Fatalf("the package's %s image is %q, which is not a digest-pinned ghcr.io "+
				"reference; this check is reading the wrong thing and would compare two "+
				"empty strings", name, theirs)
		}
		if mine != theirs {
			t.Errorf("the %s service runs a different image from the App Store package.\n"+
				"  template: %s\n  package:  %s\n"+
				"A release's pin step must update both, or this template installs the "+
				"previous release while nothing says so.", name, mine, theirs)
		}
	}

	// AND THE NAMES ARE NOT INTERCHANGEABLE, asserted separately so that a
	// package which itself had them swapped could not make the equality above
	// pass. -guard is the credential broker; the other is all of the attack
	// surface.
	if got := compose.Services["guard"].Image; !strings.Contains(got, "brollyzapper-guard:") {
		t.Errorf("the guard service runs %q, which is not the guard image", got)
	}
	if got := compose.Services["server"].Image; strings.Contains(got, "-guard:") {
		t.Errorf("the server service runs %q, which is the GUARD's image — the server would "+
			"then hold the only container that mounts admin.macaroon (spec §3, §6)", got)
	}
}

// TestTheServerHasAFixedAddressAndTheGuardBakesIt is check 4, and the two halves
// are one fact: the guard writes SERVER_IP into an `ipaddr` caveat on both
// credentials, and LND refuses a connection whose source address does not match.
// A server on a floating address gets a credential that stops working the next
// time Docker hands out addresses in a different order.
func TestTheServerHasAFixedAddressAndTheGuardBakesIt(t *testing.T) {
	compose, doc := loadCompose(t)

	networks, err := doc.Networks("server")
	if err != nil {
		t.Fatalf("the server's networks are not a mapping with an ipv4_address: %v", err)
	}
	var fixed, onNetwork string
	for name, n := range networks {
		if n.IPv4 != "" {
			fixed, onNetwork = n.IPv4, name
		}
	}
	if fixed == "" {
		t.Fatal("the server has no ipv4_address: Docker will assign whatever is free, and the " +
			"ipaddr caveat the guard bakes will stop matching the next time it changes")
	}
	if _, ok := compose.Networks[onNetwork]; !ok {
		t.Errorf("the server is addressed on network %q, which this file does not define; a "+
			"fixed address needs a user-defined network with an explicit subnet", onNetwork)
	}
	if len(compose.Networks[onNetwork].IPAM.Config) == 0 ||
		compose.Networks[onNetwork].IPAM.Config[0].Subnet == "" {
		t.Errorf("network %q declares no subnet; without one Docker chooses, and the fixed "+
			"address above may not be inside it", onNetwork)
	}
	guardEnv := compose.Services["guard"].Environment
	if got := guardEnv["SERVER_IP"]; got != fixed {
		t.Errorf("the guard bakes SERVER_IP=%q into both credentials but the server answers on "+
			"%q; LND checks the caveat against the connection's source address and will refuse "+
			"every call", got, fixed)
	}

	// ALL FOUR PLACES THE RANGE APPEARS, not two. An earlier version of this
	// checked SERVER_IP against ipv4_address and stopped, while the file's own
	// comment claimed it caught three of the four — so changing the subnet and
	// forgetting NETWORK_CIDR left the guard with a stale idea of its network and
	// nothing went red. The subnet, the address and NETWORK_CIDR are one fact.
	subnet, err := netip.ParsePrefix(compose.Networks[onNetwork].IPAM.Config[0].Subnet)
	if err != nil {
		t.Fatalf("network %q declares subnet %q, which is not a prefix: %v",
			onNetwork, compose.Networks[onNetwork].IPAM.Config[0].Subnet, err)
	}
	addr, err := netip.ParseAddr(fixed)
	if err != nil {
		t.Fatalf("the server's ipv4_address %q is not an address: %v", fixed, err)
	}
	if !subnet.Contains(addr) {
		t.Errorf("the server's fixed address %s is not inside the network's subnet %s; Docker "+
			"will refuse to start it", addr, subnet)
	}
	cidr, err := netip.ParsePrefix(guardEnv["NETWORK_CIDR"])
	if err != nil {
		t.Fatalf("the guard's NETWORK_CIDR %q is not a prefix: %v", guardEnv["NETWORK_CIDR"], err)
	}
	if cidr != subnet {
		t.Errorf("the guard is told NETWORK_CIDR=%s but the network's subnet is %s; change the "+
			"range in one place and it must change in all of them", cidr, subnet)
	}
}

// TestTheGuardMountsTwoFilesAndNotTheDirectory is the §6/§20 assertion, ported
// from umbrel/lint_test.go because the hazard is the deployment's, not
// umbrelOS's: mounting LND's data directory whole also exposes wallet.db,
// macaroons.db and channel.backup.
func TestTheGuardMountsTwoFilesAndNotTheDirectory(t *testing.T) {
	compose, _ := loadCompose(t)
	// `${LND_DIR` and not `${LND_DIR}`, because the mounts carry compose's
	// required-variable form — ${LND_DIR:?...} — so that an .env which never sets
	// it is refused rather than resolving these sources to the host filesystem
	// root. Matching the closing brace missed both mounts and reported zero,
	// which is how this was found: the check went red on a template that was
	// right, which is the good direction for a matcher to fail in.
	var fromLND []string
	for _, v := range compose.Services["guard"].Volumes {
		if strings.Contains(v, "${LND_DIR") {
			fromLND = append(fromLND, v)
		}
	}
	if len(fromLND) != 2 {
		t.Fatalf("the guard takes %d mounts from ${LND_DIR}, want exactly 2 (tls.cert and "+
			"admin.macaroon): %v", len(fromLND), fromLND)
	}
	for _, v := range fromLND {
		source := composelint.MountSource(v)
		if !strings.HasSuffix(source, "tls.cert") && !strings.HasSuffix(source, "admin.macaroon") {
			t.Errorf("the guard mounts %q out of LND's directory; only tls.cert and "+
				"admin.macaroon may be mounted, and never the directory itself — it also "+
				"holds wallet.db, macaroons.db and channel.backup (spec §6, §20)", source)
		}
		if !strings.HasSuffix(v, ":ro") {
			t.Errorf("the mount %q is not read-only; nothing here writes into LND's data "+
				"directory", v)
		}
	}
}

// TestTheServerNeverSeesAdminMacaroon is umbrel/lint_test.go's primary control,
// and it transfers verbatim: one added mount here silently undoes §3, §6 and
// half of §11, because the server could then bake its way past every other one.
func TestTheServerNeverSeesAdminMacaroon(t *testing.T) {
	compose, _ := loadCompose(t)
	for _, v := range compose.Services["server"].Volumes {
		if strings.Contains(v, "admin.macaroon") || strings.Contains(v, "${LND_DIR") {
			t.Errorf("the server mounts %q; only the guard may see LND's credentials "+
				"(spec §3, §6, §16)", v)
		}
	}
}

// TestTheGuardPublishesNoPort — the guard has no listener at all; its only input
// is a unix socket in the shared volume. A published port would be a surface
// that should not exist, and the fact that it would sit there answering nothing
// is exactly why nobody would notice.
func TestTheGuardPublishesNoPort(t *testing.T) {
	compose, _ := loadCompose(t)
	if ports := compose.Services["guard"].Ports; len(ports) != 0 {
		t.Errorf("the guard publishes %v; it has no listener, so this can only be a mistake "+
			"(spec §3, §16)", ports)
	}
}

// TestBothServicesRunAsTheUidThatOwnsTheData — the images default to uid 65532
// and the template overrides that to 1000. Both must agree: the guard WRITES
// recv.macaroon into the credential volume that the server then reads, and a
// mismatch shows up as a bake failure on first run rather than as a permission
// error anyone would recognise.
// TestBothServicesRestartAndTheServerWaitsForTheGuard — ported from
// umbrel/lint_test.go, where `restart: on-failure` is required because the
// guard's rotation recovery depends on it (spec §6): the guard exits when LND's
// macaroons rotate under it and comes back with the new ones. Without the
// restart policy that exit is permanent. depends_on is the ordering the server's
// first socket call needs.
func TestBothServicesRestartAndTheServerWaitsForTheGuard(t *testing.T) {
	compose, _ := loadCompose(t)
	for _, name := range []string{"guard", "server"} {
		if got := compose.Services[name].Restart; got != "on-failure" {
			t.Errorf("the %s service has restart: %q, want \"on-failure\" — the guard exits "+
				"when LND's macaroons rotate and only a restart policy brings it back (spec §6)",
				name, got)
		}
	}
	if got := compose.Services["server"].DependsOn; !slices.Contains(got, "guard") {
		t.Errorf("the server does not depend on the guard (%v); its first act is a call on the "+
			"guard's socket", got)
	}
}

func TestBothServicesRunAsTheUidThatOwnsTheData(t *testing.T) {
	compose, _ := loadCompose(t)
	guard, server := compose.Services["guard"].User, compose.Services["server"].User

	// THE SAME VALUE, not a particular one. The uid is overridable because an
	// Ubuntu host's LND files usually belong to an `lnd` user, admin.macaroon at
	// mode 0640, and a guard running as 1000 cannot read it — so the number is the
	// operator's.
	// What is NOT theirs is letting the two drift: the guard writes
	// recv.macaroon into the credential volume the server reads, and a
	// mismatch shows up as a bake failure on first run rather than as anything
	// resembling a permission error.
	if guard != server {
		t.Errorf("the guard runs as %q and the server as %q; they must be the same, or the "+
			"credential the guard bakes is one the server cannot open", guard, server)
	}
	if guard == "" {
		t.Fatal("neither service sets user:; the images default to uid 65532, which owns none " +
			"of the data directories")
	}
	// AND THE SHIPPED DEFAULT IS STILL 1000, which is what every instruction in
	// .env.example and the compose comments tells an operator to chown to. An
	// override that changed the default would leave all of those wrong.
	if !strings.Contains(guard, ":-1000") {
		t.Errorf("the user: expression %q does not default to 1000; the ownership "+
			"instructions in .env.example and this file's own comments all say 1000", guard)
	}
}

// assignedInExample is every variable .env.example ASSIGNS, commented or not.
//
// AN ASSIGNMENT, NOT A MENTION, and that distinction is the whole of `20i.6`.
// The first version of this check was strings.Contains over the whole file with
// comments included — and .env.example documents every variable by name in its
// own prose, so the check passed on the paragraph and never looked at the line.
// Measured twice: renaming the ASSIGNMENT `ADMIN_PASSWORD=` to `ADMIN_PASWORD=`
// left the example setting nothing and the test green. It certified nothing for
// any variable the file mentions, which is all of them.
//
// A LEADING `#` COUNTS, deliberately. `#HTTP_PORT=8080` is how this file shows
// an optional setting at its real default: the operator can see the name, the
// shape and the value, and uncommenting it is the whole edit. That is being
// SHOWN the setting, which is what this check is about — the failure it exists
// to catch is a variable the operator never sees at all.
//
// COLUMN ONE AND NO SPACE AFTER THE `#`, which is tighter than it first looks
// necessary — and the brief's `^#?\s*` was measured letting prose back in. This
// file explains the caps with an indented example:
//
//	#     GUARD_MAX_PAYMENT_MSAT=1000000
//
// which `\s*` reads as an assignment, so deleting the real `#GUARD_MAX_PAYMENT_MSAT=`
// line left the check green — the same failure this rule exists to fix, one
// comment later. The file's own convention for a commented setting is
// `#NAME=value` with nothing between, so that is what counts.
//
// THE VALUE IS KEPT, per assignment, because that same paragraph is a claim about
// the value too — and until 20i.14 nothing checked it. See
// TestTheExampleShowsEachSettingAtTheTemplatesDefault.
func assignedInExample(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("reading %s: %v", envPath, err)
	}
	assignment := regexp.MustCompile(`^#?([A-Z_][A-Z0-9_]*)=(.*)$`)
	out := map[string][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if m := assignment.FindStringSubmatch(line); m != nil {
			out[m[1]] = append(out[m[1]], m[2])
		}
	}
	return out
}

// TestTheExampleEnvNamesEveryVariableTheTemplateInterpolates keeps the interview
// complete: a variable the compose file reads and the example never SETS is one
// the operator cannot know to set, and it interpolates to empty.
func TestTheExampleEnvNamesEveryVariableTheTemplateInterpolates(t *testing.T) {
	_, doc := loadCompose(t)
	assigned := assignedInExample(t)
	// The document's interpolations: off its scalars in both spellings, with the
	// `$$` escape honoured — composelint's Interpolations says why each matters.
	seen := doc.InterpolatedNames()
	for _, name := range slices.Sorted(maps.Keys(seen)) {
		if len(assigned[name]) == 0 {
			t.Errorf("%s interpolates ${%s} and %s has no assignment line for it — a mention "+
				"in a comment is not one. The operator cannot set what they are not shown, "+
				"and it interpolates to empty. A commented `#%s=<default>` counts.",
				composePath, name, envPath, name)
		}
	}
	// THE INTERPOLATION SIDE IS THE ONLY VACUITY RISK LEFT, and that is the gain
	// over the old shape rather than an accident. A substring match always found
	// something, so a broken half passed silently; an assignment parser that
	// stopped matching makes the loop above fail once per variable instead. A
	// floor on the assignments would be dead code — reaching this line with
	// len(seen) >= 4 means four names were found in the map.
	if len(seen) < 4 {
		t.Errorf("found %d interpolated variables in %s; the template takes at least the four "+
			"an operator must fill, so this check is reading the wrong thing", len(seen), composePath)
	}
}

// TestTheExampleShowsEachSettingAtTheTemplatesDefault holds the other half of
// assignedInExample's argument: `#HTTP_PORT=8080` is fine BECAUSE the operator
// is shown the value they get by leaving it commented. Nothing checked that value
// (20i.14). Every pair agreed by hand, which is the state that drifts — and the
// caps paragraph now carries a second pair of numbers beside the real ones.
//
// VALUES, NOT RAW STRINGS: both sides are trimmed, and the example's surrounding
// quotes are dropped as compose's own .env reader drops them. A byte comparison
// fails `100000000` against ` 100000000` on a stray space, and a check that is
// red for that gets deleted rather than fixed.
//
// Names with no default in the template are not compared — LND_DIR, LND_ADDRESS
// and LND_NETWORK are the operator's to fill, and the example's value for those
// is an illustration.
func TestTheExampleShowsEachSettingAtTheTemplatesDefault(t *testing.T) {
	// TRUSTED_PROXIES IS SHOWN AT A SUGGESTED VALUE, NOT ITS DEFAULT. The template
	// defaults it to empty, which trusts no forwarding header; the example shows
	// the app network's range for an operator who adds a reverse proxy, and says
	// so in capitals. That difference is the point of the line, so it is exempt
	// here — and required to STAY different below, because a template default
	// that quietly started trusting a range is a security change this check would
	// otherwise now wave through as "the two agree".
	exempt := map[string]string{
		"TRUSTED_PROXIES": "the example shows the value for a reverse-proxy install; the default is empty",
	}

	_, doc := loadCompose(t)
	assigned := assignedInExample(t)
	// A slice per name, because DATA_DIR is read with its default seven times
	// over and a template that disagrees with itself is a finding, not a coin toss.
	defaults := doc.Defaults()

	compared := 0
	for _, name := range slices.Sorted(maps.Keys(defaults)) {
		want := strings.TrimSpace(defaults[name][0])
		if i := slices.IndexFunc(defaults[name], func(d string) bool { return strings.TrimSpace(d) != want }); i >= 0 {
			t.Errorf("%s gives ${%s} two different defaults, %q and %q; an operator leaving it unset "+
				"gets a different value depending on which line reads it", composePath, name, want, defaults[name][i])
			continue
		}
		shown := assigned[name]
		if len(shown) == 0 {
			continue // TestTheExampleEnvNamesEveryVariableTheTemplateInterpolates owns this
		}
		for _, value := range shown {
			got := envValue(value)
			if reason, ok := exempt[name]; ok {
				if got == want {
					t.Errorf("%s now shows %s=%s, which IS the template's default — the exemption "+
						"(%s) no longer describes the files. If the default moved, that is a change "+
						"to what the app trusts; decide it, then remove the exemption", envPath, name, got, reason)
				}
				continue
			}
			compared++
			if got != want {
				t.Errorf("%s shows %s=%s, but %s defaults it to %q — an operator who leaves the line "+
					"commented gets the template's value, not the one they were shown",
					envPath, name, got, composePath, want)
			}
		}
	}
	for name := range exempt {
		if len(defaults[name]) == 0 || len(assigned[name]) == 0 {
			t.Errorf("the exemption names %s, which %s no longer reads with a default or %s no "+
				"longer shows; remove it", name, composePath, envPath)
		}
	}
	// A reader that stopped matching compares nothing and passes. The template
	// defaults eight settings the example shows at a real value, and ADMIN_PASSWORD
	// and SESSION_SECRET at empty; fewer than eight means the capture broke, not
	// that the files got shorter.
	if compared < 8 {
		t.Errorf("compared %d example values against template defaults; there are at least eight, "+
			"so one of the two readers is reading the wrong thing", compared)
	}
}

// envValue is an .env.example right-hand side as compose's .env reader yields
// it: trimmed, and a quoted value is what lies between its quotes, whatever
// follows the closing one. An unquoted ` #` starts a comment there, so it ends
// the value here. QUOTES FIRST: cutting at ` #` first left `"./data" # note`
// with its quotes on, and a quoted `"a #b"` cut in half.
func envValue(rhs string) string {
	value := strings.TrimSpace(rhs)
	if value != "" && (value[0] == '"' || value[0] == '\'') {
		if end := strings.IndexByte(value[1:], value[0]); end >= 0 {
			return value[1 : end+1]
		}
	}
	if before, _, found := strings.Cut(value, " #"); found {
		value = strings.TrimSpace(before)
	}
	return value
}

// TestComposeValidatesTheTemplate is check 6, and it SKIPS LOUDLY rather than
// failing when there is no compose binary: the gate has no Docker daemon, and a
// test that needed one would either be red on every developer machine without
// it or quietly deleted. `config` parses and interpolates only — it starts
// nothing and talks to no daemon.
func TestComposeValidatesTheTemplate(t *testing.T) {
	bin, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("SKIPPED: no docker binary on PATH, so `docker compose config` could not be run " +
			"against docker-compose.yml with .env.example. Every other check in this file ran; " +
			"this one proves the file PARSES and interpolates, which nothing else here does. " +
			"It needs no daemon — `config` only reads and interpolates — so CI, which has the " +
			"CLI, does run it; this skip is for a machine without docker installed.")
	}
	env := filepath.Join(t.TempDir(), ".env")
	example, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("reading %s: %v", envPath, err)
	}
	if err := os.WriteFile(env, example, 0o600); err != nil {
		t.Fatalf("writing a temporary env file: %v", err)
	}
	cmd := exec.Command(bin, "compose", "--env-file", env, "-f", composePath, "config")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("`docker compose config` rejected the template with the example env:\n%s", out)
	}
}

// interimRE is the marker a note carries when it describes behaviour that will
// stop being true at a named version pin.
//
// THE TRIGGER IS DATA, not a convention someone remembers: the marker names the
// version, so the check below can compare it against what the template actually
// pins. `20i.8` and `20i.9` added two such notes about the 0.1.20 images, and
// two comments plus "remember at release" is the depth this repository has
// already been burned by — umbrel/lint_test.go's manifest check exists because
// "the 0.1.1 release shipped with the manifest still saying 0.1.0, caught by a
// human reading the file rather than by anything mechanical".
var interimRE = regexp.MustCompile(`INTERIM — remove at the ([0-9]+\.[0-9]+\.[0-9]+) pin`)

// interimFiles are the three an INTERIM note may live in. DEPLOYING.md is
// outside this directory and named by path for that reason.
var interimFiles = []string{envPath, composePath, "../DEPLOYING.md"}

// TestAnInterimNoteIsRemovedByThePinItNames fails the moment the template pins a
// version at or past the one an INTERIM note said it would go at.
//
// ZERO MARKERS IS THE CORRECT STEADY STATE, so there is no floor on how many are
// found — a floor would go red every time the notes are correctly removed. What
// IS guarded is the marker's spelling: any line carrying the bare word INTERIM in
// these files must match the full pattern, because an ASCII hyphen where the em
// dash belongs would disarm this check silently and leave the note in the
// release it was meant to be removed from.
func TestAnInterimNoteIsRemovedByThePinItNames(t *testing.T) {
	compose, doc := loadCompose(t)
	// BOTH IMAGES, AND THE NEWER OF THE TWO. The notes say they go "when the two
	// `image:` lines move", and nothing in this file asserts the two tags equal
	// each other — TestTheImagesEqualThePackages compares each service to the
	// package, not the two to one another. So a half-done bump has to fire:
	// taking the OLDER would stay green while the server already shipped the
	// behaviour the note says is not there yet, which is the failure this check
	// exists for. Firing one commit early costs a deletion; firing late ships
	// the note.
	pinned := imageTag(t, compose.Services["server"].Image)
	if guardTag := imageTag(t, compose.Services["guard"].Image); olderThan(pinned, guardTag) {
		pinned = guardTag
	}

	for _, path := range interimFiles {
		for _, candidate := range interimCandidates(t, path, doc) {
			i, line := candidate.Line-1, candidate.Text
			if !strings.Contains(line, "INTERIM") {
				continue
			}
			m := interimRE.FindStringSubmatch(line)
			if m == nil {
				t.Errorf("%s:%d says INTERIM but does not carry the marker this check reads "+
					"(`INTERIM — remove at the <version> pin`, with an em dash): %q. A note "+
					"whose marker does not parse is a note nothing will remind anyone to "+
					"remove.", path, i+1, strings.TrimSpace(line))
				continue
			}
			if !olderThan(pinned, m[1]) {
				t.Errorf("%s:%d is an interim note for the %s pin, and %s now pins %s. The "+
					"note describes behaviour that is no longer current; remove it in the "+
					"same commit that moved the image lines.", path, i+1, m[1], composePath, pinned)
			}
		}
	}
}

// interimCandidates is every line of path an INTERIM note could be on, in file
// order, each with its line number.
//
// THE COMPOSE GIVES ITS COMMENTS AND ITS SCALARS, NOT ITS TEXT — both, because
// the line scan this replaced read every line, and a malformed marker inside a
// value was caught by it. Comments alone was measured missing exactly that
// (go-review, 20i.18): red on main, green here. The document places each on its
// line, so nothing needs the file as lines. The other two files are prose
// throughout, and are read as lines.
func interimCandidates(t *testing.T, path string, compose *composelint.Document) []numberedLine {
	t.Helper()
	var out []numberedLine
	if path == composePath {
		for _, c := range compose.Comments() {
			out = append(out, numberedLine{Text: c.Text, Line: c.Line})
		}
		for _, s := range compose.Scalars() {
			out = append(out, numberedLine{Text: s.Value, Line: s.Line})
		}
		slices.SortStableFunc(out, func(a, b numberedLine) int { return cmp.Compare(a.Line, b.Line) })
		return out
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	for i, line := range strings.Split(string(raw), "\n") {
		out = append(out, numberedLine{Text: line, Line: i + 1})
	}
	return out
}

// numberedLine is a line of text and its 1-based number.
type numberedLine struct {
	Text string
	Line int
}

// imageTag is the tag out of a pinned reference, without the digest.
func imageTag(t *testing.T, image string) string {
	t.Helper()
	if !imageRE.MatchString(image) {
		t.Fatalf("the server image %q is not a digest-pinned reference, so no version can be "+
			"read out of it and the interim check above would compare against nothing", image)
	}
	_, rest, _ := strings.Cut(image, ":")
	tag, _, _ := strings.Cut(rest, "@")
	return tag
}

// olderThan reports whether the pinned version is strictly below want.
//
// FIELD BY FIELD, not string comparison, because "0.1.9" sorts above "0.1.21"
// as text and this check would then never fire on the release it exists for.
//
// A MISSING FIELD IS ZERO, not "older". `1.0` against a note naming `0.1.21`
// has to read as NEWER, or a major bump disarms every interim note silently —
// which is the failure this function exists to prevent, one release later.
//
// AN UNPARSEABLE FIELD READS AS NEWER TOO, so the caller fires. imageRE admits
// a `-` in a tag, so `0.1.21-rc1` is reachable by construction, and the safe
// reading of "I cannot tell whether this release has happened" is to make
// somebody look. Saying nothing would leave the note in the release.
func olderThan(pinned, want string) bool {
	p, w := strings.Split(pinned, "."), strings.Split(want, ".")
	for i := range w {
		a, b := 0, 0
		if i < len(p) {
			var err error
			if a, err = strconv.Atoi(p[i]); err != nil {
				return false
			}
		}
		var err error
		if b, err = strconv.Atoi(w[i]); err != nil {
			return false
		}
		if a != b {
			return a < b
		}
	}
	return false
}

// TestEnvValueIsTheValueComposeReads pins the normalisation the comparison
// depends on, so that "trim both sides" cannot quietly become a byte compare.
func TestEnvValueIsTheValueComposeReads(t *testing.T) {
	for rhs, want := range map[string]string{
		"8080":            "8080",
		" 100000000 ":     "100000000",
		`"./data"`:        "./data",
		`'INFO'`:          "INFO",
		"":                "",
		"8080  # port":    "8080",
		`"`:               `"`,
		`"./data" # note`: "./data",
		`"a #b"`:          "a #b",
		`"a" # "b"`:       "a",
	} {
		if got := envValue(rhs); got != want {
			t.Errorf("envValue(%q) = %q, want %q", rhs, got, want)
		}
	}
}
