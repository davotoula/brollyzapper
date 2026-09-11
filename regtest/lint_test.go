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
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/davotoula/brollyzapper/internal/config"
)

const composePath = "docker-compose.yml"

// genericSettings asks internal/config what it reads, rather than restating it.
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
// THE BEHAVIOUR, NOT THE ARTIFACT, and the same shape deploy/lint_test.go uses
// (configContract, whose own comment names this list as the thing it could
// replace): both loaders run against a Lookup that records every name and
// supplies nothing. They accumulate rather than stopping at the first missing
// variable, so one pass sees the whole contract. It cannot go vacuous — the
// names come from the loaders actually running, and a floor below says so.
func genericSettings(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	record := func(name string) (string, bool) {
		out[name] = true
		return "", false
	}
	if _, err := config.LoadServer(record); err == nil {
		t.Fatal("LoadServer accepted an entirely empty environment; this derivation reads the " +
			"contract out of a loader that insists on something, and this one insisted on nothing")
	}
	if _, err := config.LoadGuard(record); err == nil {
		t.Fatal("LoadGuard accepted an entirely empty environment; see above")
	}
	if len(out) < 10 {
		t.Fatalf("the loaders asked for %d settings; the app takes more than that, so this "+
			"derivation is reading the wrong thing", len(out))
	}
	return out
}

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
	node := s.Networks
	if err := node.Decode(&out); err != nil {
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
func TestComposeNamesNothingUmbrelSpecific(t *testing.T) {
	_, raw := load(t)
	// "APP_" would match APP_PORT, which is this stack's own host-port knob and
	// not an Umbrel variable, so the forbidden token is the Umbrel spelling:
	// ${APP_<something>} as umbrelOS injects it.
	forbidden := []string{"UMBREL_", "${APP_LIGHTNING", "${APP_DATA_DIR", "${APP_BITCOIN", "app-data"}
	for i, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue // the comments explain what is deliberately absent
		}
		for _, tok := range forbidden {
			if strings.Contains(line, tok) {
				t.Errorf("%s:%d contains %q — the regtest stack must run on generic "+
					"settings only (spec §19): %s", composePath, i+1, tok, strings.TrimSpace(line))
			}
		}
	}
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
			if !generic[k] {
				t.Errorf("service %q sets %q, which is not one of the generic settings "+
					"§19 promises the app runs on", name, k)
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
	// deleted. The guard bakes `ipaddr <SERVER_IP>` into the receive macaroon
	// and LND checks the address it OBSERVES (verified against real LND in
	// 0vk.12), so the address has to be on the container that dials.
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
