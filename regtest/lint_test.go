// Package regtest holds the off-Umbrel integration stack and the lint that
// keeps its central claim honest. It contains test files only.
//
// Spec §19 has promised since approval that the app takes generic settings and
// that Umbrel-specific config lives in the Umbrel package. This directory is
// the first place that promise is exercised rather than asserted, and this file
// is what stops it decaying back into a sentence: the moment someone reaches
// for ${APP_LIGHTNING_NODE_DATA_DIR} here because it was convenient, the gate
// fails.
//
// internal/config/seam_test.go makes the same assertion about the app's source.
// This one makes it about the deployment. Neither implies the other: source can
// be clean while the compose file is Umbrel-shaped, which is exactly the
// failure §19 is about.
package regtest

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/davotoula/brollyzapper/internal/config"
)

const composePath = "docker-compose.yml"

// genericSettings asks internal/config what it reads, per loader, rather than
// restating it.
//
// This was a hand-kept list of seventeen names — the settings contract's FOURTH
// statement, as 20i.1's report named it, after the config package, the deploy
// template and its example. It had already drifted: 20i.5 added
// ADMIN_PASSWORD_MANAGED and nothing here noticed, because the regtest compose
// deliberately does not set the Umbrel-only flag, so the gap could only ever
// show up as a WRONG failure — the day someone added it here, this lint would
// have called a generic setting a deployment leak. Measured 11 Sep 2026:
// eighteen names asked for, seventeen listed.
//
// PER LOADER, NOT THE UNION, and the first cut of this got that wrong. A union
// waves through the server setting GUARD_MAX_SPEND_MSAT — a plausible
// copy-paste from the guard block ten lines above it — which config.LoadServer
// never reads, so the cap silently is not set while the operator believes it
// is. deploy/lint_test.go keeps them apart for the same reason.
//
// THE BEHAVIOUR, NOT THE ARTIFACT, and the same shape deploy/lint_test.go uses
// (configContract, whose own comment names this list as the thing it could
// replace): each loader runs against a Lookup that records every name and
// supplies nothing. They accumulate rather than stopping at the first missing
// variable, so one pass sees the whole contract. It cannot go vacuous — the
// names come from the loaders actually running, and a floor below says so.
func genericSettings(t *testing.T) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	for _, loader := range []struct {
		service string
		load    func(config.Lookup) error
	}{
		{"brollyzapper", func(l config.Lookup) error { _, err := config.LoadServer(l); return err }},
		{"guard", func(l config.Lookup) error { _, err := config.LoadGuard(l); return err }},
	} {
		asked := map[string]bool{}
		record := func(name string) (string, bool) {
			asked[name] = true
			return "", false
		}
		if err := loader.load(record); err == nil {
			t.Fatalf("the %s loader accepted an entirely empty environment; this derivation "+
				"reads the contract out of a loader that insists on something, and this one "+
				"insisted on nothing", loader.service)
		}
		if len(asked) < 8 {
			t.Fatalf("the %s loader asked for %d settings; it takes more than that, so this "+
				"derivation is reading the wrong thing", loader.service, len(asked))
		}
		delete(asked, passwordManagedVar)
		out[loader.service] = asked
	}
	return out
}

// passwordManagedVar is read by internal/config, so the derivation above hands
// it over as generic — and it is never right HERE. It says the PLATFORM supplies
// the admin password and displays it, which is true of umbrelOS and false of
// this stack, where the compose sets ADMIN_PASSWORD itself. Set here it would
// hide the Settings password field and leave the operator unable to change a
// password nothing is showing them (`20i.5`). deploy/lint_test.go refuses it in
// the plain-Docker template by name for the same reason; the package compose's
// own comment says "only this file sets it", and this is the half of that claim
// that lives here.
const passwordManagedVar = "ADMIN_PASSWORD_MANAGED"

// The app's own two services. The rest of the stack is infrastructure and may
// legitimately mention anything.
var appServices = []string{"brollyzapper", "guard"}

type compose struct {
	Services map[string]struct {
		Image       string            `yaml:"image"`
		Volumes     []string          `yaml:"volumes"`
		Environment map[string]string `yaml:"environment"`
		// A yaml.Node because this file spells networks two ways — `networks:
		// [brolly]` for most services, and the mapping form where one needs an
		// address or an alias. Decoding the mapping on demand keeps both legal
		// and keeps a check from having to ask the raw text which service it is
		// looking at.
		Networks yaml.Node `yaml:"networks"`
	} `yaml:"services"`
}

// networkSettings is one service's entry in the mapping form of `networks:`.
// The sequence form decodes into it as an error, which is the right answer for
// every caller here: they are asking for something only the mapping form can
// carry.
type networkSettings struct {
	IPv4    string   `yaml:"ipv4_address"`
	Aliases []string `yaml:"aliases"`
}

func networksOf(t *testing.T, c compose, service string) map[string]networkSettings {
	t.Helper()
	s, ok := c.Services[service]
	if !ok {
		t.Fatalf("there is no %q service", service)
	}
	var out map[string]networkSettings
	if err := s.Networks.Decode(&out); err != nil {
		t.Fatalf("service %q does not give its networks in the mapping form, so it can carry "+
			"neither an address nor an alias: %v", service, err)
	}
	return out
}

func load(t *testing.T) (compose, string) {
	t.Helper()
	raw, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("reading %s: %v", composePath, err)
	}
	var c compose
	if err := yaml.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parsing %s: %v", composePath, err)
	}
	return c, string(raw)
}

// Criterion 2, and the whole point of the directory: no Umbrel anywhere.
//
// IT READS THE NAMES OUT OF THE PARSED DOCUMENT, and it took two goes to get
// there. The list was first ${APP_LIGHTNING…, ${APP_DATA_DIR…, ${APP_BITCOIN…
// with the braces IN the token — and the package writes these BARE:
//
//	umbrel/brollyzapper/docker-compose.yml:39   LND_ADDRESS: $APP_LIGHTNING_NODE_IP:$APP_LIGHTNING_NODE_GRPC_PORT
//
// so copying the single most copy-pasteable line in the package into this file
// matched none of the five tokens and the §19 lint stayed green.
//
// Collecting NAMES fixed the spelling, and left the reading. A raw LINE scan
// cannot see a folded scalar: yaml joins
//
//	LND_ADDRESS: "$APP_LIGHT\
//	  NING_NODE_IP:10009"
//
// back into one value, and compose then interpolates the real umbrelOS
// variable, while a per-line regexp sees `$APP_LIGHT` and `NING_NODE_IP` and
// matches neither. Measured: the whole regtest suite stayed green with that in
// the guard's environment. Asking the parser is the only reading that is not a
// spelling, and it is comment-immune for free, which the hand-rolled `#` skip
// was doing by hand.
//
// `APP_` alone is still not the rule: APP_PORT is this stack's own host-port
// knob. The umbrelOS families are named.
func TestComposeNamesNothingUmbrelSpecific(t *testing.T) {
	_, raw := load(t)
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("parsing %s as a document: %v", composePath, err)
	}
	umbrelFamilies := []string{"APP_LIGHTNING", "APP_DATA_DIR", "APP_BITCOIN", "APP_PASSWORD", "APP_BROLLYZAPPER"}
	interpolation := regexp.MustCompile(`\$\{?([A-Z_][A-Z0-9_]*)`)
	// Not variables, so they are matched as text — in a scalar, which is still
	// not the raw file: a path in a comment explaining what is absent must not
	// fail the package.
	textual := []string{"UMBREL_", "app-data"}
	for _, scalar := range scalarNodes(&doc) {
		for _, m := range interpolation.FindAllStringSubmatch(scalar.Value, -1) {
			for _, family := range umbrelFamilies {
				if strings.HasPrefix(m[1], family) {
					t.Errorf("%s:%d interpolates $%s — the regtest stack must run on generic "+
						"settings only (spec §19): %s",
						composePath, scalar.Line, m[1], scalar.Value)
				}
			}
		}
		for _, tok := range textual {
			if strings.Contains(scalar.Value, tok) {
				t.Errorf("%s:%d contains %q — the regtest stack must run on generic "+
					"settings only (spec §19): %s", composePath, scalar.Line, tok, scalar.Value)
			}
		}
	}
}

// scalarNodes is every scalar in a YAML document, keys included, carrying its
// Value and its Line.
//
// DELIBERATELY DUPLICATED, byte-identical and under this same name, in
// umbrel/lint_test.go and deploy/lint_test.go — three copies, and nothing
// detects drift between them but the name, so the name is kept identical on
// purpose. Not extracted, on size and shape: deploy/lint_test.go's package
// comment carries the argument, and BrollyZap-20i.18 the sequencing.
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

// Every environment key the two app services take must be a generic setting.
//
// GUARD_AUTHORISATION_LOCATION is the one that looks like a leak and is not —
// `06v`. It is a SENTENCE the deployment writes for its own operator, not a
// path the app resolves, which is exactly what makes it generic: the app
// renders whatever it is given and knows nothing about where it is running.
// §19's rule is against the app ASSUMING a deployment path, not against a
// deployment supplying one. It is in the derived set because internal/config
// reads it, which is now the only place that decision is recorded.
func TestAppServicesTakeOnlyGenericSettings(t *testing.T) {
	c, _ := load(t)
	generic := genericSettings(t)
	for _, name := range appServices {
		svc, ok := c.Services[name]
		if !ok {
			t.Fatalf("service %q is missing from %s", name, composePath)
		}
		var keys []string
		for k := range svc.Environment {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !generic[name][k] {
				t.Errorf("service %q sets %q, which is not one of the generic settings "+
					"§19 promises the app runs on — this service's loader never reads it",
					name, k)
			}
		}
	}
}

// The control for the test above. An empty environment, or a renamed service,
// would make it pass while proving nothing.
func TestTheAppServicesActuallyCarryTheSettings(t *testing.T) {
	c, _ := load(t)
	for _, name := range appServices {
		if len(c.Services[name].Environment) < 5 {
			t.Errorf("service %q has %d environment entries; too few for the assertion in "+
				"TestAppServicesTakeOnlyGenericSettings to mean anything",
				name, len(c.Services[name].Environment))
		}
	}
	if got := c.Services["brollyzapper"].Environment["LND_ADDRESS"]; got == "" {
		t.Error("brollyzapper has no LND_ADDRESS; the off-Umbrel claim rests on it")
	}
}

// Spec §3 and §6, restated for this deployment: the server never sees
// admin.macaroon. umbrel/lint_test.go asserts this for the App Store package;
// a second compose file that deploys the same split needs the same control, or
// the split holds only where someone remembered to check.
func TestServerHasNoMacaroonMount(t *testing.T) {
	c, _ := load(t)
	for _, v := range c.Services["brollyzapper"].Volumes {
		if strings.Contains(strings.ToLower(v), "macaroon") {
			t.Errorf("the server mounts %q; admin.macaroon belongs only to the guard "+
				"(spec §3, §6)", v)
		}
	}
}

// The control: if the guard stops mounting it, the test above is vacuous.
func TestGuardDoesMountTheMacaroonAsASingleFile(t *testing.T) {
	c, _ := load(t)
	found := false
	for _, v := range c.Services["guard"].Volumes {
		if !strings.Contains(v, "admin.macaroon") {
			continue
		}
		found = true
		// Spec §6, §20: the FILE, never the directory. Mounting the directory
		// would expose wallet.db, macaroons.db and channel.backup alongside it.
		if !strings.HasSuffix(strings.Split(v, ":")[0], "admin.macaroon") {
			t.Errorf("guard mounts %q; the source must be the macaroon file itself", v)
		}
	}
	if !found {
		t.Error("the guard mounts no admin.macaroon; it is the only container that should")
	}
}

// relay2 exists so o34.7 criterion 9 can fail, and the DOTTED alias is the whole
// mechanism: internal/lnurl refuses any single-label host a zap request names,
// so without a dotted name no transient socket is ever opened and "the count
// returned to the configured size" is true having tested nothing. Someone
// tidying the alias away would not break the stack — they would silently make
// the criterion unfailable, which is worse.
func TestTheSecondRelayKeepsItsDottedAlias(t *testing.T) {
	c, _ := load(t)
	if _, ok := c.Services["relay2"]; !ok {
		t.Fatal("service \"relay2\" is missing; e2e.sh criterion 9 cannot open a " +
			"sender-named connection without it, and would pass having tested nothing")
	}
	// READ OFF relay2, NOT OFF THE FILE. This took the FIRST `aliases:` line
	// containing a dot, anywhere in the compose, and was right only because
	// relay2 was the only service with one. Give `relay` — which precedes it —
	// a dotted alias and take relay2's away, and the check passed while
	// asserting the opposite of its own name. Measured on 279678d. That is the
	// hole this test's own comment was written to close.
	dotted := false
	for _, settings := range networksOf(t, c, "relay2") {
		for _, alias := range settings.Aliases {
			if strings.Contains(alias, ".") {
				dotted = true
			}
		}
	}
	if !dotted {
		t.Error("relay2 has no dotted network alias; a zap request may not name a " +
			"single-label host, so nothing would ever dial it (o34.7 criterion 9)")
	}
}

// The receive macaroon carries `ipaddr <SERVER_IP>` and LND checks the address
// it observes (verified against real LND in 0vk.12). If the server's static
// address and the guard's SERVER_IP drift apart, every authenticated call fails
// and it reads like a credential problem rather than a compose typo.
func TestServerIPMatchesTheStaticAddress(t *testing.T) {
	c, _ := load(t)
	serverIP := c.Services["guard"].Environment["SERVER_IP"]
	if serverIP == "" {
		t.Fatal("the guard sets no SERVER_IP")
	}
	// WHICH SERVICE, which the old check never asked. It was
	// strings.Contains(raw, "ipv4_address: "+serverIP) over the whole file, so
	// pinning the address on `lnd` instead of on the app satisfied it — measured
	// on 279678d — and so would a comment quoting the address with the real line
	// deleted. The address has to be on the container that dials.
	pinned := ""
	for _, settings := range networksOf(t, c, "brollyzapper") {
		if settings.IPv4 != "" {
			pinned = settings.IPv4
		}
	}
	if pinned != serverIP {
		t.Errorf("the guard bakes SERVER_IP=%q and the brollyzapper service answers on %q; "+
			"the ipaddr caveat would be checked against an address the app does not have",
			serverIP, pinned)
	}
}
