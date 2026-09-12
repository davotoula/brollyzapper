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
// THE THIRD COMPOSE LOADER IN THIS REPOSITORY, and the threshold this repo wrote
// down for itself is three. internal/arch/arch_test.go's duplication note argues
// the trade for the secret predicates and ends "Two copies of forty lines is the
// cheaper trade at two consumers. AT THREE IT IS NOT: that is the moment to make
// the package." umbrel/lint_test.go and regtest/lint_test.go are the other two,
// and the §6/§20 mount rule is now stated in three of them.
//
// NOT EXTRACTED, AND THE REASON HAS CHANGED. It used to be scope — 20i.1's brief
// ruled out any change under umbrel/, and a shared package has to move that file
// to be worth making. Brief D changed umbrel/ AND regtest/, so that reason is
// dead and this paragraph would otherwise be a dead excuse the next reader
// either acts on or stops at.
//
// The honest reason is size and shape. The duplicated piece is the compose
// loader and the networks model — about fourteen lines per copy, where the bar
// arch set is forty. And a shared composeFile struct would be the UNION of three
// different documents: umbrel alone needs container_name, this file alone needs
// top-level networks and ipam, regtest alone needs aliases. A field a lint does
// not read is exactly the vacuity risk this whole family of checks hunts, so the
// union struct would be worse than the duplication it replaced.
//
// What IS duplicated deliberately is named identically in all three files —
// scalarNodes here, in umbrel/lint_test.go and in regtest/lint_test.go — because
// nothing detects drift between copies but the name. BrollyZap-20i.18 carries
// the full argument and the sequencing. internal/lnd/lndtest and
// internal/lnurl/lnurltest are the precedent for where it would go.
package deploy

import (
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

	"gopkg.in/yaml.v3"

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
		Image       string            `yaml:"image"`
		User        string            `yaml:"user"`
		Volumes     []string          `yaml:"volumes"`
		Ports       []string          `yaml:"ports"`
		Restart     string            `yaml:"restart"`
		DependsOn   []string          `yaml:"depends_on"`
		Environment map[string]string `yaml:"environment"`
		// A yaml.Node because the two services spell this differently: the server
		// needs the mapping form to carry ipv4_address, the guard only names the
		// network. Environment above needs no such treatment — the list spelling
		// decodes into a map with a LOUD error, not a silent empty one, and
		// loadCompose turns that into a Fatalf.
		Networks yaml.Node `yaml:"networks"`
	} `yaml:"services"`
	Networks map[string]struct {
		IPAM struct {
			Config []struct {
				Subnet string `yaml:"subnet"`
			} `yaml:"config"`
		} `yaml:"ipam"`
	} `yaml:"networks"`
}

func loadCompose(t *testing.T) (composeFile, string) {
	t.Helper()
	raw, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("reading %s: %v", composePath, err)
	}
	var compose composeFile
	if err := yaml.Unmarshal(raw, &compose); err != nil {
		t.Fatalf("parsing %s: %v", composePath, err)
	}
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
	return compose, string(raw)
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
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the deploy directory: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
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
		cleaned := commentFreeText(t, e.Name(), string(raw))
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
// the file's own shape allows: the compose is parsed and its scalars joined, and
// anything else is cut at `#`. See the two hazards recorded at the call site.
func commentFreeText(t *testing.T, name, raw string) string {
	t.Helper()
	if name != composePath {
		return withoutComments(raw)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("parsing %s as a document: %v", name, err)
	}
	// ANCHORS TOO, and that is not theoretical tidiness. An anchor name is not a
	// scalar Value, so `environment: &NETWORK_IP_anchor` put a forbidden name in
	// the file and this check passed — measured, and it is the same silent
	// direction as the two holes above. Anchors sit on mappings and sequences as
	// readily as on scalars, so every node is asked for one.
	var out strings.Builder
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Anchor != "" {
			out.WriteString(n.Anchor)
			out.WriteString("\n")
		}
		if n.Kind == yaml.ScalarNode {
			out.WriteString(n.Value)
			out.WriteString("\n")
			return
		}
		for _, child := range n.Content {
			walk(child)
		}
	}
	walk(&doc)
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
	pkgRaw, err := os.ReadFile(packageCompose)
	if err != nil {
		t.Fatalf("reading %s: %v", packageCompose, err)
	}
	var pkg composeFile
	if err := yaml.Unmarshal(pkgRaw, &pkg); err != nil {
		t.Fatalf("parsing %s: %v", packageCompose, err)
	}

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
	compose, _ := loadCompose(t)

	var networks map[string]struct {
		IPv4 string `yaml:"ipv4_address"`
	}
	serverNetworks := compose.Services["server"].Networks
	if err := serverNetworks.Decode(&networks); err != nil {
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
// mountSource returns the host side of a compose short-syntax volume.
//
// IT CANNOT JUST CUT AT THE FIRST COLON, which is what this did until the
// mounts gained compose's required-variable form: `${LND_DIR:?...}` puts a colon
// INSIDE the source, so cutting at the first one yielded "${LND_DIR" and the
// mount check reported that the guard mounts LND's directory whole — a false
// alarm on a template that had just been made safer. Blank the interpolations
// first; what is left has colons only where compose means them.
func mountSource(volume string) string {
	var out strings.Builder
	depth := 0
	for i := 0; i < len(volume); i++ {
		switch {
		case strings.HasPrefix(volume[i:], "${"):
			depth++
			out.WriteString("$_")
			i++
		case depth > 0 && volume[i] == '}':
			depth--
		case depth == 0:
			out.WriteByte(volume[i])
		}
	}
	source, _, _ := strings.Cut(out.String(), ":")
	// The blanked form is only for FINDING the boundary; the caller wants the
	// real text, so map the index back.
	return volume[:len(volume)-len(out.String())+len(source)]
}

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
		source := mountSource(v)
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
	// Ubuntu host's LND files usually belong to an `lnd` user at mode 0600 and a
	// guard running as 1000 cannot read them — so the number is the operator's.
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
func assignedInExample(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("reading %s: %v", envPath, err)
	}
	assignment := regexp.MustCompile(`^#?([A-Z_][A-Z0-9_]*)=`)
	out := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		if m := assignment.FindStringSubmatch(line); m != nil {
			out[m[1]] = true
		}
	}
	return out
}

// interpolatedNames is every variable the template reads, in either spelling,
// taken off the parsed document's scalars.
//
// BOTH SPELLINGS, because `\$\{([A-Z_]…)` required the brace and the bare form is
// equally valid compose: `$LND_DIR` would never have been collected, so
// .env.example would never have been required to show it and the operator would
// not have been shown a setting (BrollyZap-20i.19). Latent rather than live —
// this template has no bare form today, and the floor below would still have
// passed on the other names — but the Umbrel package writes bare
// interpolations eight times over six code lines, and this template is what a
// reader copies from.
//
// OFF THE SCALARS, not the raw text, for the two reasons brief D paid for next
// door: a comment naming `${SOMETHING}` would otherwise demand an assignment for
// a variable the template does not read, and a double-quoted scalar folded with
// a trailing backslash hides a name from a per-line regexp while compose still
// interpolates it. Measured 12 Sep 2026: both readings return the same fourteen
// names on the template as it stands, so this changes nothing today and closes
// both tomorrows.
func interpolatedNames(t *testing.T, raw string) map[string]bool {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("parsing %s as a document: %v", composePath, err)
	}
	out := map[string]bool{}
	for _, scalar := range scalarNodes(&doc) {
		// `$$` IS COMPOSE'S ESCAPE FOR A LITERAL `$`, never an interpolation, and
		// Go's regexp has no lookbehind to say so. Removing the pairs first is
		// exact rather than approximate: `$$NAME` becomes `NAME` and matches
		// nothing, while `$$$NAME` becomes `$NAME` — which is what compose does
		// with it too, a literal dollar followed by a real interpolation.
		// Measured: without this, `$$NOT_REAL_VAR` demanded an assignment for a
		// name compose never reads.
		value := strings.ReplaceAll(scalar.Value, "$$", "")
		for _, m := range anyInterpolationRE.FindAllStringSubmatch(value, -1) {
			out[m[1]] = true
		}
	}
	return out
}

// ${NAME}, ${NAME:-default} and bare $NAME alike; the default half is this
// file's own business and not the operator's, so only the name is captured.
//
// NOT NAMED interpolationRE, which umbrel/lint_test.go already uses for a
// DIFFERENT pattern — scoped to APP_BROLLYZAPPER_* and capturing the brace at
// m[1] and the name at m[2]. Identical names are this repo's only drift
// detector between deliberate copies, so a same-name-different-pattern pair is
// the one arrangement that turns the detector into a trap: code moved between
// the two packages compiles and reads the brace as the variable name. The
// genuinely identical twin of THIS pattern is the local `interpolation` in
// regtest/lint_test.go.
var anyInterpolationRE = regexp.MustCompile(`\$\{?([A-Z_][A-Z0-9_]*)`)

// scalarNodes is every scalar in a YAML document, keys included, carrying its
// Value and its Line. Comments are not scalars, and neither is a line break.
//
// An alias node carries no Content, only a pointer this does not follow, so a
// recursive alias terminates rather than recursing forever — and nothing is
// missed by not following it, since the anchor's own definition is a scalar
// elsewhere in the same tree.
//
// DELIBERATELY DUPLICATED, byte-identical and under this same name, in
// umbrel/lint_test.go and regtest/lint_test.go. THIS IS THE THIRD COPY, and
// nothing detects drift between them but the name — so a change here is a change
// in three places. BrollyZap-20i.18 carries the extraction argument.
func scalarNodes(node *yaml.Node) []*yaml.Node {
	if node.Kind == yaml.ScalarNode {
		return []*yaml.Node{node}
	}
	var out []*yaml.Node
	for _, child := range node.Content {
		out = append(out, scalarNodes(child)...)
	}
	return out
}

// TestTheExampleEnvNamesEveryVariableTheTemplateInterpolates keeps the interview
// complete: a variable the compose file reads and the example never SETS is one
// the operator cannot know to set, and it interpolates to empty.
func TestTheExampleEnvNamesEveryVariableTheTemplateInterpolates(t *testing.T) {
	_, raw := loadCompose(t)
	assigned := assignedInExample(t)
	seen := interpolatedNames(t, raw)
	for _, name := range slices.Sorted(maps.Keys(seen)) {
		if !assigned[name] {
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
	compose, _ := loadCompose(t)
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
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
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

// TestInterpolatedNamesReadsBothSpellingsAndOnlyTheCode is what makes the rule
// above survive a revert.
//
// Every claim its comment block makes was measured once, by hand, against a
// template that satisfies it: put the brace back in anyInterpolationRE and the
// whole suite stays green, because this template has no bare form to catch.
// That is a rule written rather than tested, and it is the shape
// umbrel/lint_test.go's own parser table exists to avoid.
func TestInterpolatedNamesReadsBothSpellingsAndOnlyTheCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want []string
	}{{
		name: "braced, with and without a default",
		raw:  "services:\n  s:\n    environment:\n      A: ${LND_DIR}\n      B: ${HTTP_PORT:-8080}\n",
		want: []string{"HTTP_PORT", "LND_DIR"},
	}, {
		name: "bare, which the brace-only pattern never saw",
		raw:  "services:\n  s:\n    environment:\n      A: $LND_DIR\n",
		want: []string{"LND_DIR"},
	}, {
		name: "a comment must not demand an assignment",
		raw:  "# an earlier draft read ${LND_SOCKET_PATH}\nservices:\n  s:\n    environment:\n      A: ${LND_DIR}\n",
		want: []string{"LND_DIR"},
	}, {
		name: "a folded scalar is one name, not two halves",
		raw:  "services:\n  s:\n    environment:\n      A: \"${LND_D\\\n        IR}\"\n",
		want: []string{"LND_DIR"},
	}, {
		name: "$$ is an escaped literal dollar, not an interpolation",
		raw:  "services:\n  s:\n    environment:\n      A: \"$$NOT_REAL\"\n      B: ${LND_DIR}\n",
		want: []string{"LND_DIR"},
	}, {
		name: "$$$NAME is a literal dollar and then a real one",
		raw:  "services:\n  s:\n    environment:\n      A: \"$$$LND_DIR\"\n",
		want: []string{"LND_DIR"},
	}, {
		name: "a name in a volume string counts, wherever it appears",
		raw:  "services:\n  s:\n    volumes:\n      - ${DATA_DIR}/guard:/guard\n",
		want: []string{"DATA_DIR"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := slices.Sorted(maps.Keys(interpolatedNames(t, tc.raw)))
			if !slices.Equal(got, tc.want) {
				t.Errorf("interpolatedNames(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}
