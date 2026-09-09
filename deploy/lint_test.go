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
// NOT EXTRACTED HERE, and the reason is scope rather than disagreement: 20i.1's
// brief rules out any change under umbrel/, and a shared test-support package
// has to move that file to be worth making. internal/lnd/lndtest and
// internal/lnurl/lnurltest are the precedent for where it would go. Named in
// this bead's report for the PM rather than done quietly.
package deploy

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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

// umbrelOnly are the variables umbrelOS injects. None can mean anything here.
//
// NAMED RATHER THAN PATTERN-MATCHED on `APP_` alone, because NETWORK_IP and the
// PROXY_ family carry no prefix and are exactly the ones a copy-paste from the
// package would bring across.
var umbrelOnly = []string{"APP_", "NETWORK_IP", "PROXY_"}

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
		for _, needle := range umbrelOnly {
			if strings.Contains(withoutComments(string(raw)), needle) {
				t.Errorf("%s mentions %s, which only umbrelOS sets; here it interpolates to "+
					"empty and the setting it was meant to make silently disappears",
					e.Name(), needle)
			}
		}
	}
	// A scan that reads nothing passes silently, which is the one result this
	// check cannot afford.
	if scanned < 2 {
		t.Errorf("scanned %d files in deploy/; the template and its env example are both "+
			"here, so this check is reading the wrong thing", scanned)
	}
}

// withoutComments blanks whole-line and trailing `#` comments. Both files this
// scans are YAML or shell-shaped env, where `#` starts a comment and no value in
// either legitimately contains one.
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
	compose, raw := loadCompose(t)
	pkg, err := os.ReadFile(packageCompose)
	if err != nil {
		t.Fatalf("reading %s: %v", packageCompose, err)
	}
	// Both spellings: the regex over the raw file is what catches a digest written
	// anywhere, and the parsed field is what proves the two services actually
	// CARRY one — a file with the images commented out would otherwise match
	// nothing in both places and compare equal.
	for _, name := range []string{"guard", "server"} {
		if !imageRE.MatchString(compose.Services[name].Image) {
			t.Errorf("the %s service's image %q is not a digest-pinned ghcr.io reference; a tag "+
				"alone can be moved under the operator", name, compose.Services[name].Image)
		}
	}
	mine := imageRE.FindAllString(raw, -1)
	theirs := imageRE.FindAllString(string(pkg), -1)
	slices.Sort(mine)
	slices.Sort(theirs)
	if len(theirs) != 2 {
		t.Fatalf("found %d pinned images in %s, want 2; this check is reading the wrong "+
			"thing and would pass whatever this template says", len(theirs), packageCompose)
	}
	if !slices.Equal(mine, theirs) {
		t.Errorf("the template's images are not the package's.\n  template: %v\n  package:  %v\n"+
			"A release's pin step must update both", mine, theirs)
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
func TestTheGuardMountsTwoFilesAndNotTheDirectory(t *testing.T) {
	compose, _ := loadCompose(t)
	var fromLND []string
	for _, v := range compose.Services["guard"].Volumes {
		if strings.Contains(v, "${LND_DIR}") {
			fromLND = append(fromLND, v)
		}
	}
	if len(fromLND) != 2 {
		t.Fatalf("the guard takes %d mounts from ${LND_DIR}, want exactly 2 (tls.cert and "+
			"admin.macaroon): %v", len(fromLND), fromLND)
	}
	for _, v := range fromLND {
		source, _, _ := strings.Cut(v, ":")
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
		if strings.Contains(v, "admin.macaroon") || strings.Contains(v, "${LND_DIR}") {
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
	for _, name := range []string{"guard", "server"} {
		if got := compose.Services[name].User; got != "1000:1000" {
			t.Errorf("the %s service runs as %q, want \"1000:1000\" — the uid the data "+
				"directories must be owned by", name, got)
		}
	}
}

// TestTheExampleEnvNamesEveryVariableTheTemplateInterpolates keeps the interview
// complete: a variable the compose file reads and the example never mentions is
// one the operator cannot know to set, and it interpolates to empty.
func TestTheExampleEnvNamesEveryVariableTheTemplateInterpolates(t *testing.T) {
	_, raw := loadCompose(t)
	example, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("reading %s: %v", envPath, err)
	}
	// ${NAME} and ${NAME:-default} alike; the default half is this file's own
	// business and not the operator's.
	interpolated := regexp.MustCompile(`\$\{([A-Z_][A-Z0-9_]*)`).FindAllStringSubmatch(raw, -1)
	seen := map[string]bool{}
	for _, m := range interpolated {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		if !strings.Contains(string(example), name) {
			t.Errorf("%s interpolates ${%s} and %s never mentions it; the operator cannot "+
				"set what they are not shown, and it interpolates to empty", composePath, name, envPath)
		}
	}
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
