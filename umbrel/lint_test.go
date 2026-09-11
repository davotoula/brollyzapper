// Package umbrel holds the App Store package and the lint that keeps it honest.
// It contains test files only.
//
// §11 and §16 are explicit that the compose lint is the PRIMARY control for the
// credential split, and the server's runtime preflight is the backstop: the
// runtime check cannot prove a negative, because a mount at an unexpected path
// is invisible to it. This file is that primary control.
package umbrel

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/davotoula/brollyzapper/internal/api"
)

const packageDir = "brollyzapper"

type composeFile struct {
	Services map[string]struct {
		Image         string            `yaml:"image"`
		User          string            `yaml:"user"`
		ContainerName string            `yaml:"container_name"`
		Volumes       []string          `yaml:"volumes"`
		Environment   map[string]string `yaml:"environment"`
		Ports         []string          `yaml:"ports"`
		Restart       string            `yaml:"restart"`
		DependsOn     []string          `yaml:"depends_on"`
	} `yaml:"services"`
}

func loadCompose(t *testing.T) (composeFile, string) {
	t.Helper()
	path := filepath.Join(packageDir, "docker-compose.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var compose composeFile
	if err := yaml.Unmarshal(raw, &compose); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	if len(compose.Services) == 0 {
		t.Fatalf("%s declares no services; the lint is not actually running", path)
	}
	return compose, string(raw)
}

// THE assertion. §16: adding an admin.macaroon mount to the server service is
// one line that silently undoes §3, §6 and half of §11 — the server would be
// able to bake its way past every other control.
func TestTheServerServiceHasNoAdminMacaroonMount(t *testing.T) {
	compose, _ := loadCompose(t)
	server, ok := compose.Services["server"]
	if !ok {
		t.Fatal("there is no server service to check")
	}
	for _, volume := range server.Volumes {
		if strings.Contains(strings.ToLower(volume), "macaroon") {
			t.Errorf("the server service mounts %q; only the guard may hold a macaroon "+
				"from the lightning app (spec §3, §6, §16)", volume)
		}
	}
	// The whole-directory mount is the same defect wearing a different spelling:
	// it grants wallet.db, macaroons.db and channel.backup along with it (§20).
	for _, volume := range server.Volumes {
		if strings.Contains(volume, "APP_LIGHTNING_NODE_DATA_DIR") {
			t.Errorf("the server service mounts %q from the lightning app; it must mount "+
				"nothing from there at all (spec §6, §20)", volume)
		}
	}
	for key, value := range server.Environment {
		if strings.Contains(strings.ToLower(key), "macaroon") {
			t.Errorf("the server service sets %s=%s; the server's own preflight refuses to "+
				"start with that variable present (spec §11)", key, value)
		}
	}
}

// TestThePackageDeclaresThePasswordManaged holds the one line `20i.5` added,
// and it is worth a test of its own because losing it is silent in the
// direction that matters.
//
// umbrelOS derives $APP_PASSWORD per install and DISPLAYS it to the user. The
// app must therefore refuse to change it — otherwise the dashboard shows a
// password that no longer works, with nothing anywhere saying why. Until
// `20i.5` the app inferred that from ADMIN_PASSWORD being set, which is equally
// true of a plain-Docker operator who typed their own password into .env, so
// the inference denied every off-Umbrel install a password change for ever.
//
// The signal is now explicit, and this file is the only place that sets it.
// DELETE THE LINE AND NOTHING ELSE GOES RED: the app would come up, work, and
// quietly offer Umbrel operators a change form that fights the platform on the
// next recreate. That is what this asserts.
//
// BESIDE THE PASSWORD, not merely present. The two are one decision — the
// value and who owns it — and a reader who finds them apart has to go looking
// for whether the separation meant something.
func TestThePackageDeclaresThePasswordManaged(t *testing.T) {
	compose, raw := loadCompose(t)
	server, ok := compose.Services["server"]
	if !ok {
		t.Fatal("no server service in the package compose")
	}
	const managed = "ADMIN_PASSWORD_MANAGED"
	got, ok := server.Environment[managed]
	if !ok {
		t.Fatalf("the server service does not set %s. umbrelOS displays the password it "+
			"derives, so the app must not offer to change it — and since `20i.5` the app "+
			"learns that from this line and from nowhere else (spec §9)", managed)
	}
	if got != "true" {
		t.Errorf("%s = %q, want \"true\"; internal/config parses it as a bool and anything "+
			"it cannot parse refuses to start", managed, got)
	}
	// The password itself must still be the platform's, or the flag is a claim
	// about a value the package no longer supplies.
	if want := "$APP_PASSWORD"; server.Environment["ADMIN_PASSWORD"] != want {
		t.Errorf("ADMIN_PASSWORD = %q, want %q — the managed flag says the platform owns "+
			"this password, so the platform has to be the one supplying it",
			server.Environment["ADMIN_PASSWORD"], want)
	}
	// Adjacency, read off the raw file because the parsed map has no order.
	//
	// NOTHING BUT COMMENT AND BLANK BETWEEN THEM, rather than "within N lines".
	// A line budget would have to grow every time the comment above the flag
	// does, and a number that has to be maintained to keep meaning the same
	// thing is a number that will be widened until it means nothing.
	lines := strings.Split(raw, "\n")
	pwLine, managedLine := lineOf(t, lines, "ADMIN_PASSWORD:"), lineOf(t, lines, managed+":")
	if managedLine < pwLine {
		t.Fatalf("%s is at line %d, ABOVE ADMIN_PASSWORD at line %d; the flag describes the "+
			"password, so it reads after it", managed, managedLine, pwLine)
	}
	for i, line := range lines[pwLine : managedLine-1] {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			t.Errorf("line %d, %q, sits between ADMIN_PASSWORD and %s. They are one decision "+
				"— the value and who owns it — and a reader who finds another setting "+
				"between them has to work out whether the separation meant something",
				pwLine+i+1, trimmed, managed)
		}
	}
}

// lineOf is the 1-based line whose SETTING is needle, for the adjacency check
// above.
//
// It matches a trimmed PREFIX rather than a substring, so a comment mentioning
// the variable — and this file has several — cannot be mistaken for the line
// that sets it. It fails the test rather than returning a sentinel, so a needle
// that stopped matching cannot quietly satisfy a comparison.
func lineOf(t *testing.T, lines []string, needle string) int {
	t.Helper()
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), needle) {
			return i + 1
		}
	}
	t.Fatalf("no line sets %q in the package compose", needle)
	return 0
}

// Box-verified 2026-08-21: PROXY_TRUST_UPSTREAM=true makes app_proxy forward a
// client-supplied X-Forwarded-For verbatim, which hands any caller a spoofed
// source address past the §7 rate limiter. It is undocumented in app-proxy's
// own README, so nothing warns an author who adds it.
func TestProxyTrustUpstreamAppearsNowhere(t *testing.T) {
	_, raw := loadCompose(t)
	if strings.Contains(raw, "PROXY_TRUST_UPSTREAM") {
		for i, line := range strings.Split(raw, "\n") {
			if strings.Contains(line, "PROXY_TRUST_UPSTREAM") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				t.Errorf("docker-compose.yml:%d sets PROXY_TRUST_UPSTREAM: %s", i+1, strings.TrimSpace(line))
			}
		}
	}
}

// §11: the whitelist and the public mux are two expressions of one list, in two
// files. Whitelisted-but-absent is dead config; the reverse is worse — a public
// route Umbrel still demands a login for, which breaks anonymous LNURL clients
// with no visible error at all.
func TestTheProxyWhitelistEqualsThePublicRouteSet(t *testing.T) {
	compose, _ := loadCompose(t)
	proxy, ok := compose.Services["app_proxy"]
	if !ok {
		t.Fatal("there is no app_proxy service")
	}
	raw, ok := proxy.Environment["PROXY_AUTH_WHITELIST"]
	if !ok {
		t.Fatal("app_proxy sets no PROXY_AUTH_WHITELIST, so the LNURL endpoints are behind " +
			"Umbrel auth and anonymous clients cannot reach them")
	}

	got := strings.Split(raw, ",")
	for i := range got {
		got[i] = strings.TrimSpace(got[i])
	}
	want := whitelistFor(api.PublicPaths)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("PROXY_AUTH_WHITELIST = %v, want exactly %v — the same list the public mux "+
			"registers (spec §10, §11)", got, want)
	}
}

// whitelistFor translates Go's mux patterns into app_proxy's globs: a pattern
// ending in "/" is a subtree, which app_proxy spells with a trailing "*".
func whitelistFor(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if strings.HasSuffix(pattern, "/") {
			out = append(out, pattern+"*")
			continue
		}
		out = append(out, pattern)
	}
	return out
}

// §19 reserves raw ports for non-HTTP protocols; app_proxy is sufficient here.
func TestNoServicePublishesARawPort(t *testing.T) {
	compose, _ := loadCompose(t)
	for name, service := range compose.Services {
		if len(service.Ports) > 0 {
			t.Errorf("service %q publishes %v; app_proxy is sufficient for an HTTP app (spec §19)",
				name, service.Ports)
		}
	}
}

// §6 and §20: the guard mounts two individual FILES. The whole-directory mount
// every other LND app on the box currently uses is seed exposure.
func TestTheGuardMountsTwoFilesAndNotTheDirectory(t *testing.T) {
	compose, _ := loadCompose(t)
	guard, ok := compose.Services["guard"]
	if !ok {
		t.Fatal("there is no guard service")
	}
	var fromLND []string
	for _, volume := range guard.Volumes {
		if strings.Contains(volume, "APP_LIGHTNING_NODE_DATA_DIR") {
			fromLND = append(fromLND, volume)
		}
	}
	if len(fromLND) != 2 {
		t.Fatalf("the guard mounts %d paths from the lightning app: %v; want exactly two files",
			len(fromLND), fromLND)
	}
	for _, volume := range fromLND {
		source, _, _ := strings.Cut(volume, ":")
		if !strings.HasSuffix(source, "tls.cert") && !strings.HasSuffix(source, "admin.macaroon") {
			t.Errorf("the guard mounts %q; only tls.cert and admin.macaroon, as files (spec §6, §20)", volume)
		}
	}
}

// Box-verified: if a bind-mount source is missing when the container starts,
// Docker creates a DIRECTORY there, the container dies at exit 127, and the
// host path stays broken until someone removes it.
func TestEveryBindMountSourceIsCommitted(t *testing.T) {
	compose, _ := loadCompose(t)
	for name, service := range compose.Services {
		for _, volume := range service.Volumes {
			source, _, _ := strings.Cut(volume, ":")
			rest, found := strings.CutPrefix(source, "${APP_DATA_DIR}/")
			if !found {
				continue
			}
			path := filepath.Join(packageDir, rest)
			info, err := os.Stat(path)
			if err != nil {
				t.Errorf("service %q mounts %s but %s is not committed; docker will create a "+
					"directory there on first start", name, source, path)
				continue
			}
			if !info.IsDir() {
				continue
			}
			if _, err := os.Stat(filepath.Join(path, ".gitkeep")); err != nil {
				t.Errorf("%s has no .gitkeep, so git will not carry the empty directory", path)
			}
		}
	}
}

// Images must be prebuilt, multi-arch and pinned by index digest (§10, and the
// App Store's own rules).
func TestImagesArePinnedByDigest(t *testing.T) {
	compose, _ := loadCompose(t)
	for name, service := range compose.Services {
		if name == "app_proxy" {
			continue // umbrelOS supplies its own image
		}
		image := service.Image
		if image == "" {
			t.Errorf("service %q has no image; App Store packages may not use compose build:", name)
			continue
		}
		tag, digest, pinned := strings.Cut(image, "@sha256:")
		if !pinned {
			t.Errorf("service %q image %q is not pinned by digest", name, image)
			continue
		}
		if len(digest) != 64 {
			t.Errorf("service %q image %q has a malformed digest", name, image)
		}
		if strings.HasSuffix(tag, ":latest") || !strings.Contains(tag, ":") {
			t.Errorf("service %q image %q has no version tag beside the digest", name, tag)
		}
	}
}

// The images default to uid 65532; umbrelOS creates app data owned by 1000.
// These two must agree or the guard cannot write recv.macaroon on first run —
// a failure that reads like a bake error and is not.
func TestBothServicesRunAsTheUidThatOwnsTheAppData(t *testing.T) {
	compose, raw := loadCompose(t)
	for _, name := range []string{"guard", "server"} {
		service, ok := compose.Services[name]
		if !ok {
			t.Fatalf("there is no %s service", name)
		}
		if service.User != "1000:1000" {
			t.Errorf("service %q runs as %q, want 1000:1000 — the uid umbrelOS gives the app data",
				name, service.User)
		}
		if service.ContainerName != "" {
			t.Errorf("service %q sets container_name; umbrelOS injects it", name)
		}
		if name == "server" && !slices.Contains(service.DependsOn, "guard") {
			t.Errorf("the server does not depend_on the guard; the guard writes the credentials " +
				"the server reads, and ordering is not a guarantee either way (spec §6)")
		}
		if service.Restart != "on-failure" {
			t.Errorf("service %q has restart %q, want on-failure — the guard's rotation recovery "+
				"depends on it (spec §6)", name, service.Restart)
		}
	}
	if !strings.Contains(raw, "65532") {
		t.Error("the compose file does not explain the uid mismatch; the next person to touch " +
			"user: will not know why 1000 matters")
	}
}

// The framework already defaults app_proxy auth on, and setting it explicitly
// is called out as wrong by umbrel-package-app.
func TestProxyAuthIsLeftAtTheFrameworkDefault(t *testing.T) {
	_, raw := loadCompose(t)
	for i, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "PROXY_AUTH_ADD") {
			t.Errorf("docker-compose.yml:%d sets PROXY_AUTH_ADD; it is already the framework "+
				"default and umbrel-package-app says not to set it", i+1)
		}
	}
}

type manifest struct {
	ManifestVersion       any      `yaml:"manifestVersion"`
	ID                    string   `yaml:"id"`
	Name                  string   `yaml:"name"`
	Version               string   `yaml:"version"`
	Dependencies          []string `yaml:"dependencies"`
	Port                  int      `yaml:"port"`
	Path                  string   `yaml:"path"`
	Gallery               []string `yaml:"gallery"`
	Icon                  string   `yaml:"icon"`
	Permissions           []string `yaml:"permissions"`
	BackupIgnore          []string `yaml:"backupIgnore"`
	DeterministicPassword bool     `yaml:"deterministicPassword"`
}

func loadManifest(t *testing.T) manifest {
	t.Helper()
	path := filepath.Join(packageDir, "umbrel-app.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var m manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return m
}

// Restored after d46.26 REPLACED it rather than adding beside it. Renaming a
// test to change its subject is how coverage disappears with no diff line that
// says "deleted" — six assertions went with it.
func TestTheManifestDeclaresWhatUmbrelNeeds(t *testing.T) {
	m := loadManifest(t)
	if m.ID != packageDir {
		t.Errorf("manifest id = %q, want %q — app_proxy derives container names from it, and "+
			"the store id must prefix it (spec §10)", m.ID, packageDir)
	}
	if !slices.Contains(m.Dependencies, "lightning") {
		t.Errorf("dependencies = %v, want it to contain lightning; the guard mounts two files "+
			"from that app (spec §10)", m.Dependencies)
	}
	if !m.DeterministicPassword {
		t.Error("deterministicPassword is false; §9 needs the operator to be able to SEE the " +
			"password the package wires into ADMIN_PASSWORD")
	}
	if m.Port == 0 {
		t.Error("the manifest declares no port")
	}
}

func TestBackupIgnoreNamesOnlyTheCredentialVolume(t *testing.T) {
	m := loadManifest(t)
	want := []string{"data/credentials"}
	if !slices.Equal(m.BackupIgnore, want) {
		t.Errorf("backupIgnore = %v, want exactly %v (spec §10, §11, d46.26).\n"+
			"data/credentials holds recv.macaroon, which in a stolen backup streams every "+
			"invoice on the node; the guard re-bakes on start so a restore loses nothing.\n"+
			"The DATABASE must stay in backup — it holds the zap-receipt signing key, and "+
			"losing it changes the nostrPubkey the address advertises.", m.BackupIgnore, want)
	}
	// The database must never join it, and neither must the guard's own state:
	// guard-state.json carries the root key ids that make revocation possible
	// after a restore.
	for _, forbidden := range []string{"data/server", "data/guard"} {
		if slices.Contains(m.BackupIgnore, forbidden) {
			t.Errorf("backupIgnore names %q; that is not what d46.26 adopted", forbidden)
		}
	}
}

// icon: must NOT appear. umbrel-package-app is explicit — "Omit `icon` for
// official App Store packages" — because Umbrel hosts the artwork in its own
// assets repo, keyed by app id, and umbreld falls back to that URL whenever the
// manifest has no icon (app-repository.ts:185).
//
// This lint exists because the pressure to add it is real and recurring. On the
// dev store that fallback URL 404s (measured 2026-08-30: brollyzapper 404, the
// bitcoin control 200), so the dashboard tile renders as a broken image and the
// one-line "fix" is to set icon:. That fix is correct ONLY for a community app
// store. In the submitted manifest it is a rule violation, and it is the kind
// that survives review by looking helpful.
//
// BrollyZap-3bv carries the full finding and reaches the same conclusion. The
// tile stops being broken when Umbrel adds the gallery assets before merge.
func TestTheManifestDeclaresNoIcon(t *testing.T) {
	m := loadManifest(t)
	if m.Icon != "" {
		t.Errorf("manifest sets icon: %q.\n"+
			"Official App Store packages must omit it — Umbrel hosts the icon in its own\n"+
			"assets repo and umbreld falls back to that URL when the field is absent.\n"+
			"If you added this to fix the broken dashboard tile on a DEV store, that is a\n"+
			"dev-store-only change (BrollyZap-3bv); it must not reach the submission.", m.Icon)
	}
}

// The container name app_proxy points at is derived from the app id and the
// service name. Get it wrong and the app opens on nothing.
func TestTheProxyPointsAtTheServerServiceByItsInjectedName(t *testing.T) {
	compose, _ := loadCompose(t)
	m := loadManifest(t)
	proxy := compose.Services["app_proxy"]
	want := m.ID + "_server_1"
	if got := proxy.Environment["APP_HOST"]; got != want {
		t.Errorf("APP_HOST = %q, want %q — umbrelOS injects <app-id>_<service>_1", got, want)
	}
	if got := proxy.Environment["APP_PORT"]; got != "8080" {
		t.Errorf("APP_PORT = %q, want the port the server listens on inside the container", got)
	}
}

// exports.sh is SOURCED, not executed, and umbrelOS runs it under set -euo
// pipefail. The unit is therefore an ASSIGNMENT, and this test parses one.
//
// It used to be strings.Contains over the whole file, and exports.sh is a file
// that explains itself in comments: the comment above the session-secret export
// contains the word derive_entropy, so deleting the export line left this test
// GREEN. Confirmed by plant (BrollyZap-20i.12). What would have shipped is not
// an install with no cookie key — internal/api/auth.go's persistedSessionSecret
// generates one and writes it to the settings table, so the app comes up and
// sessions survive a restart. What is lost is §10's "out of the database", with
// nothing to show for it. That is the shape a lint is the sole control for.
//
// The fix is BrollyZap-20i.6's, one directory over: the name comes from the
// assignment, the requirement from its value, and prose counts for neither.
func TestExportsIsSourcedNotExecuted(t *testing.T) {
	path := filepath.Join(packageDir, "exports.sh")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	body := string(raw)
	if strings.HasPrefix(body, "#!") {
		t.Error("exports.sh has a shebang; it is sourced, not executed")
	}

	for _, code := range codeLines(body) {
		// `exit` and `cd` are matched as WORDS, at the head of every command on
		// the line rather than only the line's first: the trailing space the old
		// check required was an artifact of substring-matching a whole file, and
		// a bare `exit` at the end of a sourced file ends umbrelOS's own shell,
		// which is the thing being forbidden.
		for _, head := range commandHeads(code) {
			switch head {
			case "exit", "cd":
				t.Errorf("exports.sh runs %q; it is sourced into umbrelOS's shell under set "+
					"-euo pipefail, so it must not exit or change directory", code)
			}
		}
		if strings.Contains(code, "docker") {
			t.Errorf("exports.sh line %q invokes docker; this file prepares the environment and "+
				"must not touch the daemon", code)
		}
	}

	// NO FLOOR ON THE NUMBER OF EXPORTS, and that is deliberate rather than an
	// oversight — the same call 20i.6 made in deploy/lint_test.go. Both
	// assertions below fail when the map is empty, once each and by name, so a
	// pattern that stopped matching is already red. A floor would replace two
	// accurate errors with one guess about which of the two causes it was.
	// WHAT WOULD REOPEN IT: an assertion here that only fires when the name is
	// present — an `if ok &&` shape — since that one WOULD pass on an empty map.
	exported := exportsIn(body)

	const secret = "APP_BROLLYZAPPER_SESSION_SECRET"
	if value, ok := exported[secret]; !ok {
		t.Errorf("exports.sh exports no %s; §10 wants the cookie key derived, stable across "+
			"restarts and updates, and out of the database. A comment naming derive_entropy is "+
			"not an export — that is exactly how this check passed with the line deleted", secret)
	} else if !strings.HasPrefix(strings.TrimPrefix(value, `"`), "$(derive_entropy") {
		// THE CALL, AT THE HEAD OF THE VALUE, AND ONLY THE DOUBLE QUOTE IS
		// STRIPPED. Three ways this check has been wrong, each found by a plant:
		//
		//   - matching the WORD anywhere: the comment above the export line
		//     satisfies it, which is the bug this bead was filed on;
		//   - matching the CALL anywhere in the value: `SESSION_SECRET="" # was
		//     $(derive_entropy …)` satisfies it, and a trailing comment saying
		//     what the line used to do is the likeliest way the call is ever
		//     lost;
		//   - stripping `'` as well as `"` before the prefix test: inside SINGLE
		//     quotes `$(…)` is literal text, never a substitution, so
		//     `SESSION_SECRET='$(derive_entropy "…")'` passed while every
		//     install got the same hardcoded key. Measured in bash, not
		//     reasoned: the single-quoted form prints the text.
		t.Errorf("%s = %s, which does not begin with a double-quoted $(derive_entropy …). "+
			"Single quotes do not substitute, so '$(derive_entropy …)' is a hardcoded key "+
			"shared by every install; anything else is either unstable across restarts or "+
			"stored where §10 says it must not be", secret, value)
	}

	const address = "APP_BROLLYZAPPER_IP"
	if value, ok := exported[address]; !ok {
		t.Errorf("exports.sh exports no %s; without one the server's address changes whenever "+
			"the container is recreated, and the spend macaroon's ipaddr caveat breaks", address)
	} else if addr, err := netip.ParseAddr(literalValue(value)); err != nil || !addr.Is4() {
		t.Errorf("%s = %s, which is not a literal IPv4 address; the guard bakes it into an "+
			"ipaddr caveat that LND compares against the connection's source address, so a "+
			"variable or a hostname here cannot be checked by anything before the node "+
			"refuses the credential", address, value)
	}
}

// TestTheExportsParserReadsWhatItClaimsTo tests the two helpers above against
// inputs exports.sh does not currently contain.
//
// Every claim codeLines and exportsIn make is otherwise measured once, by hand,
// against a file that passes — which is the state this whole bead exists to get
// out of. The CRLF case is the sharpest: it is the entire content of this
// branch's second commit, and without this table you can revert that fix and
// nothing goes red.
func TestTheExportsParserReadsWhatItClaimsTo(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want map[string]string
	}{{
		name: "a commented export is not an export",
		raw:  "# export APP_X=1\n#export APP_Y=2\n",
		want: map[string]string{},
	}, {
		name: "an indented export is a real export",
		raw:  "  export APP_X=1\n\texport APP_Y=2\n",
		want: map[string]string{"APP_X": "1", "APP_Y": "2"},
	}, {
		name: "a CRLF file parses rather than panicking",
		raw:  "export APP_X=1\r\n\r\n# a comment\r\n",
		want: map[string]string{"APP_X": "1"},
	}, {
		name: "a trailing comment stays in the value, for the caller to strip",
		raw:  "export APP_X=\"1.2.3.4\" # why this address\n",
		want: map[string]string{"APP_X": `"1.2.3.4" # why this address`},
	}, {
		name: "the last assignment wins, as it does in the shell",
		raw:  "export APP_X=1\nexport APP_X=2\n",
		want: map[string]string{"APP_X": "2"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := exportsIn(tc.raw)
			if len(got) != len(tc.want) {
				t.Fatalf("exportsIn(%q) = %v, want %v", tc.raw, got, tc.want)
			}
			for name, want := range tc.want {
				if got[name] != want {
					t.Errorf("exportsIn(%q)[%q] = %q, want %q", tc.raw, name, got[name], want)
				}
			}
		})
	}
}

// TestCodeLinesDropsCommentsAndKeepsCode asserts the skip DIRECTLY, and it took
// a plant to learn that it had to: removing the comment skip from codeLines left
// the parser table above green, because `^export` rejects a comment line anyway.
// The skip is load-bearing for the OTHER caller — the forbidden-token scan, where
// reading a comment as code is what would fail the package over a comment saying
// why docker is forbidden. Nothing asserted that until this test.
func TestCodeLinesDropsCommentsAndKeepsCode(t *testing.T) {
	const raw = "# never run docker here\r\n\r\n" +
		"export APP_X=1\n" +
		"   # an indented comment, and it must not exit\n" +
		"\texport APP_Y=2\n"
	// The CRLF blank line is the panic path in particular: a lone \r is not
	// empty to a narrower trim, and strings.Fields of it has no [0] for the
	// callers above to take. The parser table catches the same revert through a
	// corrupted VALUE; this catches it where the comment says it happens.
	want := []string{"export APP_X=1", "export APP_Y=2"}
	got := codeLines(raw)
	if !slices.Equal(got, want) {
		t.Errorf("codeLines(%q) = %q, want %q — a comment read as code fails the package for "+
			"the words in its own explanation", raw, got, want)
	}
}

func TestCommandHeadsFindsEveryCommandOnTheLine(t *testing.T) {
	for _, tc := range []struct {
		code string
		want []string
	}{
		{"export APP_X=1", []string{"export"}},
		{"cd;rm -rf /", []string{"cd", "rm"}},
		{"true && exit", []string{"true", "exit"}},
		{"cat x | grep y", []string{"cat", "grep"}},
		{";;;", nil},
		{"exit", []string{"exit"}},
	} {
		if got := commandHeads(tc.code); !slices.Equal(got, tc.want) {
			t.Errorf("commandHeads(%q) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func TestLiteralValueTakesTheAssignedLiteralAndNotTheComment(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{`"10.21.21.14"`, "10.21.21.14"},
		{`'10.21.21.14'`, "10.21.21.14"},
		{`10.21.21.14`, "10.21.21.14"},
		{`"10.21.21.14" # .14 is unallocated`, "10.21.21.14"},
		{`"${SOME_VAR}"`, "${SOME_VAR}"},
		{``, ""},
	} {
		if got := literalValue(tc.value); got != tc.want {
			t.Errorf("literalValue(%q) = %q, want %q", tc.value, got, tc.want)
		}
	}
}

// codeLines returns the lines of a sourced shell file that are CODE: comments
// and blanks dropped, indentation trimmed. Reading comments as code is what made
// the exports check vacuous, and it is also why a comment explaining WHY docker
// is forbidden used to fail the package — the same mistake in both directions.
// So the split happens once, here, and every check works from the result.
//
// TrimSpace, not TrimLeft of " \t": a file saved with CRLF leaves a lone \r as
// the whole line, which the narrower trim keeps — and strings.Fields of that is
// empty, so a caller taking the first word panics instead of reporting.
// Measured. A trimmed line that is not empty has at least one field, which is
// what makes strings.Fields(code)[0] safe above.
func codeLines(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		code := strings.TrimSpace(line)
		if code == "" || strings.HasPrefix(code, "#") {
			continue
		}
		out = append(out, code)
	}
	return out
}

// commandHeads returns the first word of every command on a shell line: the
// line split on `;`, `&` and `|`, each segment's head word. Taking only the
// line's first word — strings.Fields(code)[0] — misses `cd;rm -rf /`, whose
// first field is "cd;rm" and matches nothing. Found by review, and the same gap
// was in the substring check this file replaced, which wanted "cd " with a
// space after it.
//
// It is not a shell parser and does not claim to be: a separator inside quotes
// splits a segment that the shell would not. That direction only ever adds a
// candidate head, so it can fail this file loudly, never pass it quietly.
func commandHeads(code string) []string {
	var out []string
	for _, segment := range strings.FieldsFunc(code, func(r rune) bool {
		return r == ';' || r == '&' || r == '|'
	}) {
		if fields := strings.Fields(segment); len(fields) > 0 {
			out = append(out, fields[0])
		}
	}
	return out
}

// exportsIn maps each exported name to the text after its `=`, last assignment
// winning as it does in the shell.
//
// LEADING WHITESPACE IS ALLOWED AND 20i.6's PATTERN COULD NOT AFFORD IT: there
// the optional `#` meant \s* let an indented example inside a comment count as
// an assignment. Here comments are gone before the match and nothing optional
// precedes `export`, so the space costs nothing — and an indented export is a
// real export.
//
// ONE SPELLING IS ACCEPTED, and the others fail loudly rather than passing
// quietly. `declare -x NAME=`, a bare `NAME=` followed by `export NAME`, a
// second assignment on the same line (`export A=1 B=2`, where B is swallowed
// into A's value), a `\`-continued value and a leading byte-order mark are all
// working shell, or nearly, and none of them parse here — each one leaves a
// required name absent, which is the `!ok` branch and a red test naming it. A
// file that umbrelOS sources on every app start is worth keeping in one
// reviewable shape, and a lint that fails on an unfamiliar spelling is the
// cheap way to hold it there. What would reopen this: exports.sh needing a
// value long enough to wrap.
func exportsIn(raw string) map[string]string {
	export := regexp.MustCompile(`^export ([A-Z_][A-Z0-9_]*)=(.*)$`)
	out := map[string]string{}
	for _, code := range codeLines(raw) {
		if m := export.FindStringSubmatch(code); m != nil {
			out[m[1]] = m[2]
		}
	}
	return out
}

// literalValue is the first word of an assignment's right-hand side with its
// quotes stripped. It is what keeps a trailing comment — `export X="10.21.21.14"
// # why this address` — out of the value, and this file's habit of explaining
// every line is why that case is worth handling rather than a hypothetical.
//
// It does NOT parse shell quoting: a literal containing a space or a `#` comes
// back truncated. Its one caller asks whether the result is an IPv4 address, and
// no such literal is one, so the truncation can only turn a failure into the
// same failure. The session secret's value is spanned by quotes and spaces and
// is deliberately NOT put through here — it is matched at its head instead.
func literalValue(value string) string {
	if fields := strings.Fields(value); len(fields) > 0 {
		return strings.Trim(fields[0], `"'`)
	}
	return ""
}

// The manifest version is what umbrelOS displays and what it uses for update
// detection, and it is a second statement of the same fact the image tags
// carry. Two statements of one fact drift: the 0.1.1 release shipped with the
// manifest still saying 0.1.0, caught by a human reading the file rather than
// by anything mechanical. Digest pinning already stops the compose file
// disagreeing with what is published; this stops the manifest disagreeing with
// the compose file.
func TestTheManifestVersionMatchesTheImageTags(t *testing.T) {
	m := loadManifest(t)
	compose, _ := loadCompose(t)

	if m.Version == "" {
		t.Fatal("umbrel-app.yml has no version")
	}
	for name, service := range compose.Services {
		if service.Image == "" {
			continue // app_proxy: umbrelOS supplies its own image
		}
		tag, _, _ := strings.Cut(service.Image, "@sha256:")
		_, version, ok := strings.Cut(tag, ":")
		if !ok {
			continue // already reported by the pinning test
		}
		if version != m.Version {
			t.Errorf("service %q image is tagged %q but umbrel-app.yml says version %q;\n"+
				"umbrelOS shows the manifest version and uses it for update detection, so a\n"+
				"mismatch means the box reports a version it is not running", name, version, m.Version)
		}
	}
}
