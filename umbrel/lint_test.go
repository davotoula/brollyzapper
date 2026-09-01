// Package umbrel holds the App Store package and the lint that keeps it honest.
// It contains test files only.
//
// §11 and §16 are explicit that the compose lint is the PRIMARY control for the
// credential split, and the server's runtime preflight is the backstop: the
// runtime check cannot prove a negative, because a mount at an unexpected path
// is invisible to it. This file is that primary control.
package umbrel

import (
	"os"
	"path/filepath"
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

// exports.sh is sourced, not executed, and umbrelOS runs it under set -euo
// pipefail.
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
	for _, forbidden := range []string{"\nexit ", "\ncd ", "docker "} {
		if strings.Contains(body, forbidden) {
			t.Errorf("exports.sh contains %q; it must not exit, change directory or run docker",
				strings.TrimSpace(forbidden))
		}
	}
	if !strings.Contains(body, "derive_entropy") {
		t.Error("exports.sh does not derive the session secret; §10 wants it stable across " +
			"restarts and out of the database")
	}
	if !strings.Contains(body, "APP_BROLLYZAPPER_IP") {
		t.Error("exports.sh declares no static IP; without one the server's address changes " +
			"whenever the container is recreated, and the spend macaroon's ipaddr caveat breaks")
	}
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
