// Package deploy holds the plain-Docker deployment template and the lint that
// keeps it honest. It contains test files only.
//
// WHY A LINT AND NOT A README. This template is a second statement of two
// things that already exist elsewhere: the config package's environment
// contract, and the App Store package's pinned images. Both drift silently —
// a mistyped variable name is a silent default rather than an error, and a
// release that re-pins the package without re-pinning here ships a template
// that installs last month's binaries. Each check below is one of those.
package deploy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	composePath = "docker-compose.yml"
	envPath     = ".env.example"
	// The package this template must stay in step with.
	packageCompose = "../umbrel/brollyzapper/docker-compose.yml"
	// The one place the environment contract is actually declared.
	configSource = "../internal/config/config.go"
)

type composeFile struct {
	Services map[string]struct {
		Image          string    `yaml:"image"`
		User           string    `yaml:"user"`
		Volumes        []string  `yaml:"volumes"`
		Ports          []string  `yaml:"ports"`
		Restart        string    `yaml:"restart"`
		DependsOn      []string  `yaml:"depends_on"`
		RawEnvironment yaml.Node `yaml:"environment"`
		Networks       yaml.Node `yaml:"networks"`
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
	return compose, string(raw)
}

// environmentOf returns a service's environment as a map, whichever of compose's
// two spellings it uses.
//
// THE MAPPING FORM AND THE LIST FORM are both legal and mean the same thing, and
// a lint that understood only one would pass silently on a file written in the
// other — which is the shape of every failure this file exists to catch.
func environmentOf(t *testing.T, node yaml.Node) map[string]string {
	t.Helper()
	out := map[string]string{}
	switch node.Kind {
	case yaml.MappingNode:
		var m map[string]string
		if err := node.Decode(&m); err != nil {
			t.Fatalf("decoding an environment mapping: %v", err)
		}
		return m
	case yaml.SequenceNode:
		var list []string
		if err := node.Decode(&list); err != nil {
			t.Fatalf("decoding an environment list: %v", err)
		}
		for _, entry := range list {
			name, value, _ := strings.Cut(entry, "=")
			out[name] = value
		}
	case 0:
		t.Fatal("a service declares no environment at all; this template sets one on both")
	}
	return out
}

// contract is what internal/config actually reads, derived from its source.
type contract struct{ required, optional []string }

// configContract parses internal/config's LoadServer and LoadGuard and returns
// the variables each one reads.
//
// DERIVED, NOT LISTED. A hand-kept copy here would be the THIRD statement of
// this contract — after the config package and the App Store package — and the
// failure of a stale one is silent in the direction that matters: a variable
// the template stops setting reads as a default, and a variable the config
// package starts requiring reads as a start-up error on the operator's host
// rather than on this branch.
//
// It keys off the `p.requiredX("NAME")` / `p.optionalX("NAME")` call shape,
// which is the same shape both loaders are written in. If that shape ever
// changes, this returns fewer names than it should — so the test below asserts
// a floor on the count rather than trusting whatever it finds.
func configContract(t *testing.T) map[string]contract {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), configSource, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", configSource, err)
	}
	out := map[string]contract{}
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || (fn.Name.Name != "LoadServer" && fn.Name.Name != "LoadGuard") {
			continue
		}
		which := strings.TrimPrefix(fn.Name.Name, "Load")
		found := out[which]
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			name := strings.Trim(lit.Value, `"`)
			switch {
			case strings.HasPrefix(sel.Sel.Name, "required"):
				found.required = append(found.required, name)
			case strings.HasPrefix(sel.Sel.Name, "optional"):
				found.optional = append(found.optional, name)
			}
			return true
		})
		out[which] = found
	}
	return out
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

	// A FLOOR ON WHAT WAS DERIVED, because a parser that silently matched
	// nothing would make every assertion below vacuous — the failure this whole
	// file is written against, one level up.
	for _, which := range []string{"Server", "Guard"} {
		c := contracts[which]
		if len(c.required) < 3 || len(c.optional) < 3 {
			t.Fatalf("derived only %d required and %d optional settings for %s from %s; "+
				"the call shape this reads must have changed, and every check below would "+
				"now be asserting nothing", len(c.required), len(c.optional), which, configSource)
		}
	}

	for _, s := range []struct{ service, which string }{{"server", "Server"}, {"guard", "Guard"}} {
		svc := compose.Services[s.service]
		env := environmentOf(t, svc.RawEnvironment)
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
		for _, needle := range umbrelOnly {
			if strings.Contains(string(raw), needle) {
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

var imageRE = regexp.MustCompile(`ghcr\.io/davotoula/brollyzapper(-guard)?:[0-9][0-9a-zA-Z.\-]*@sha256:[0-9a-f]{64}`)

// TestTheImagesEqualThePackages is check 3, and it is aimed at the release
// procedure rather than at this file.
//
// A release re-pins the App Store package's digests. Nothing made it re-pin
// this template, so the failure mode is a template that quietly installs the
// previous release — with an operator following a procedure that says nothing
// is wrong. Equality here makes the pin step update both or go red.
func TestTheImagesEqualThePackages(t *testing.T) {
	_, raw := loadCompose(t)
	pkg, err := os.ReadFile(packageCompose)
	if err != nil {
		t.Fatalf("reading %s: %v", packageCompose, err)
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
	guardEnv := environmentOf(t, compose.Services["guard"].RawEnvironment)
	if got := guardEnv["SERVER_IP"]; got != fixed {
		t.Errorf("the guard bakes SERVER_IP=%q into both credentials but the server answers on "+
			"%q; LND checks the caveat against the connection's source address and will refuse "+
			"every call", got, fixed)
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
		t.Skip("SKIPPED: docker is not on PATH, so `docker compose config` could not be run " +
			"against docker-compose.yml with .env.example. Every other check in this file ran; " +
			"this one proves the file PARSES and interpolates, which nothing else here does.")
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
