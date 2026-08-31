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
)

const composePath = "docker-compose.yml"

// The generic settings the app takes on any LND (spec §19). This list is the
// brief's list; anything outside it in the two BrollyZapper services is either
// a new generic setting that belongs in the spec, or a deployment leak.
var genericSettings = map[string]bool{
	"LND_ADDRESS": true, "LND_CERT_FILE": true, "LND_ADMIN_MACAROON": true,
	"CREDENTIALS_DIR": true, "DATA_DIR": true, "SERVER_IP": true,
	"NETWORK_CIDR": true, "TRUSTED_PROXIES": true, "LISTEN_ADDR": true,
	"ADMIN_PASSWORD": true, "SESSION_SECRET": true, "LOG_LEVEL": true,
	"GUARD_SOCKET": true, "GUARD_MAX_SPEND_MSAT": true, "GUARD_MAX_PAYMENT_MSAT": true,
	"GUARD_ALLOW_SENDING": true,
	// `06v`. It is a SENTENCE the deployment writes for its own operator, not a
	// path the app resolves — which is exactly what makes it generic: the app
	// renders whatever it is given and knows nothing about where it is running.
	// §19's rule is against the app ASSUMING a deployment path, not against a
	// deployment supplying one.
	"GUARD_AUTHORISATION_LOCATION": true,
}

// The app's own two services. The rest of the stack is infrastructure and may
// legitimately mention anything.
var appServices = []string{"brollyzapper", "guard"}

type compose struct {
	Services map[string]struct {
		Image       string            `yaml:"image"`
		Volumes     []string          `yaml:"volumes"`
		Environment map[string]string `yaml:"environment"`
	} `yaml:"services"`
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
func TestAppServicesTakeOnlyGenericSettings(t *testing.T) {
	c, _ := load(t)
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
			if !genericSettings[k] {
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
	c, raw := load(t)
	if _, ok := c.Services["relay2"]; !ok {
		t.Fatal("service \"relay2\" is missing; e2e.sh criterion 9 cannot open a " +
			"sender-named connection without it, and would pass having tested nothing")
	}
	alias := ""
	for _, line := range strings.Split(raw, "\n") {
		if strings.Contains(line, "aliases:") && strings.Contains(line, ".") {
			alias = strings.TrimSpace(line)
			break
		}
	}
	if alias == "" {
		t.Error("relay2 has no dotted network alias; a zap request may not name a " +
			"single-label host, so nothing would ever dial it (o34.7 criterion 9)")
	}
}

// The receive macaroon carries `ipaddr <SERVER_IP>` and LND checks the address
// it observes (verified against real LND in 0vk.12). If the server's static
// address and the guard's SERVER_IP drift apart, every authenticated call fails
// and it reads like a credential problem rather than a compose typo.
func TestServerIPMatchesTheStaticAddress(t *testing.T) {
	_, raw := load(t)
	serverIP := c_env(raw, "SERVER_IP:")
	if serverIP == "" {
		t.Fatal("the guard sets no SERVER_IP")
	}
	if !strings.Contains(raw, "ipv4_address: "+serverIP) {
		t.Errorf("SERVER_IP is %q but no service is pinned to that address; the ipaddr "+
			"caveat would be checked against an address the server does not have", serverIP)
	}
}

func c_env(raw, key string) string {
	for _, line := range strings.Split(raw, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, key) {
			return strings.TrimSpace(strings.TrimPrefix(t, key))
		}
	}
	return ""
}
