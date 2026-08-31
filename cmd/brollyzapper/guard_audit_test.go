package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/store"
)

// d46.18, and the seam §13 warns about: on the reference box audit_events held
// auth.fail rows and no macaroon.bake, though the guard had logged
// audit=macaroon.bake at startup. Both sides worked. Nothing carried the event
// between them, and the guard's stdout is not durable — which is the exact
// failure §12's trail exists to prevent.
//
// So this asserts the end-to-end fact and not that each side works alone: a
// real guard bakes over a real unix socket, and the row appears on the real
// Security page, with no operator action beyond looking at it.
func TestAGuardBakeReachesTheSecurityPage(t *testing.T) {
	socket, credentials := startGuard(t)

	const password = "correct-horse-battery-staple"
	environ := validEnv(t)
	environ["CREDENTIALS_DIR"] = credentials
	environ["GUARD_SOCKET"] = socket
	environ["ADMIN_PASSWORD"] = password
	environ["SESSION_SECRET"] = "0123456789abcdef0123456789abcdef"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var stdout, stderr syncBuffer
	exit := make(chan int, 1)
	go func() { exit <- run(ctx, nil, env(environ), &stdout, &stderr) }()

	base := "http://" + environ["LISTEN_ADDR"]
	client := newBrowser(t)
	waitForHTTP(t, client, base+"/health")

	// Before signing in, and therefore before any admin page render: the
	// background poll collects the guard's events on its own. Without this the
	// durability of the trail would quietly depend on an operator logging in.
	lndtest.WaitFor(t, "the guard's events to be collected with nobody watching", func() bool {
		return strings.Contains(stdout.String(), "recorded a guard security event")
	})

	signIn(t, client, base, password)

	page := fetch(t, client, base+"/security")
	if n := strings.Count(page, string(logging.EventMacaroonBake)); n != 1 {
		t.Errorf("the Security page names %s %d times, want exactly 1 — the guard baked at "+
			"startup and the row must reach the server's trail exactly once:\n%s",
			logging.EventMacaroonBake, n, page)
	}

	cancel()
	select {
	case <-exit:
	case <-time.After(30 * time.Second):
		t.Fatal("the server did not shut down when its context ended")
	}
}

// syncBuffer is a bytes.Buffer a test may read while the server is still
// writing to it. Reading a plain one mid-run is a data race, and -race says so.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startGuard runs a real guard against a real (fake) LND on a unix socket, with
// its receive macaroon already baked — which is what cmd/brollyguard does on
// every start, and the moment the macaroon.bake event is raised.
func startGuard(t *testing.T) (socket, credentials string) {
	t.Helper()
	node := lndtest.Start(t)
	// Short paths: a unix socket path is bounded by sun_path, around 104 bytes
	// on darwin, and t.TempDir() alone overruns it.
	short := lndtest.ShortDir(t)
	credentials = filepath.Join(short, "credentials")
	if err := os.MkdirAll(credentials, 0o700); err != nil {
		t.Fatalf("creating the credential volume: %v", err)
	}
	// The guard's own mounts live nowhere the server can read: Tier 1 refuses to
	// start a server that can reach admin.macaroon.
	mounts := t.TempDir()
	certPath := filepath.Join(mounts, "tls.cert")
	adminPath := filepath.Join(mounts, "admin.macaroon")
	node.WriteMounts(t, certPath, adminPath)

	g, err := guard.New(&config.Guard{
		LNDAddress:           node.Address(),
		LNDCertFile:          certPath,
		LNDAdminMacaroonFile: adminPath,
		CredentialsDir:       credentials,
		DataDir:              filepath.Join(short, "guard-data"),
		// Every credential the guard bakes is locked to the SERVER container's
		// address (§6, d46.26), so a guard without one cannot bake at all.
		ServerIP: netip.MustParseAddr("10.21.21.14"),
	}, guard.Options{Log: logging.New(io.Discard, logging.NewLevelVar(slog.LevelDebug))})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })

	if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon: %v", err)
	}
	socket = filepath.Join(short, "g.sock")
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = g.Serve(ctx, socket) }()

	probe := guard.NewSocketClient(socket, nil)
	lndtest.WaitFor(t, "the guard socket to accept", func() bool {
		_, err := probe.Status(ctx)
		return err == nil
	})
	return socket, credentials
}

// newBrowser is an HTTP client that keeps cookies, which is what the login flow
// needs and what curl did not do when d46.17 was being chased.
func newBrowser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{Timeout: 5 * time.Second, Jar: jar}
}

func fetch(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", url, resp.StatusCode, body)
	}
	return string(body)
}

func signIn(t *testing.T, client *http.Client, base, password string) {
	t.Helper()
	page := fetch(t, client, base+"/login")
	marker := `name="` + api.CSRFField + `" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("no CSRF token on the login page: %s", page)
	}
	rest := page[i+len(marker):]
	token := rest[:strings.Index(rest, `"`)]

	resp, err := client.PostForm(base+"/login",
		url.Values{"password": {password}, api.CSRFField: {token}})
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "Sign in") {
		t.Fatalf("signing in = %d: %s", resp.StatusCode, body)
	}
}

// §11: every dependency here is allowed to be absent, and a stored nostr key
// that cannot be parsed is no exception.
//
// Exiting would be a restart loop with no cap (`restart: on-failure`), and the
// only repair — importing a good key on the Settings page — is unreachable if
// the listener never binds. So a bad key is a degraded state the operator can
// see and fix, exactly like an absent LND.
func TestACorruptNostrKeyDegradesRatherThanPreventingStartup(t *testing.T) {
	environ := validEnv(t)
	environ["ADMIN_PASSWORD"] = "correct-horse-battery-staple"
	environ["SESSION_SECRET"] = "0123456789abcdef0123456789abcdef"

	db, err := store.Open(environ["DATA_DIR"])
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := db.SetSetting(t.Context(), nostr.SettingPrivateKey, "not-a-key"); err != nil {
		t.Fatalf("planting a corrupt key: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var stdout, stderr syncBuffer
	exit := make(chan int, 1)
	go func() { exit <- run(ctx, nil, env(environ), &stdout, &stderr) }()

	base := "http://" + environ["LISTEN_ADDR"]
	client := &http.Client{Timeout: 5 * time.Second}
	waitForHTTP(t, client, base+"/health")

	resp, err := client.Get(base + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /login = %d with a corrupt nostr key, want 200", resp.StatusCode)
	}
	if !strings.Contains(stdout.String(), "no usable nostr identity") {
		t.Errorf("nothing in the log says the identity is unusable:\n%s", stdout.String())
	}

	cancel()
	select {
	case code := <-exit:
		if code != 0 {
			t.Errorf("run = %d, want a clean shutdown (stdout: %s)", code, stdout.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the server did not shut down")
	}
}
