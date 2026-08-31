package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
)

// env turns a map into the lookup run takes, so these tests never touch the
// process environment.
func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestVersionFlagIsANoOpThatExitsZero(t *testing.T) {
	// --version must work with no environment at all: it is what proves the
	// binary is intact before anything is configured.
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"--version"}, env(nil), &stdout, &stderr); code != 0 {
		t.Fatalf("run(--version) = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "brollyguard") {
		t.Errorf("run(--version) stdout = %q, want it to name the binary", got)
	}
}

func TestFailsFastWhenRequiredConfigIsMissing(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), nil, env(nil), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run with an empty environment = 0, want non-zero")
	}
	for _, v := range REQUIRED {
		if !strings.Contains(stdout.String(), v) {
			t.Errorf("the log does not name the missing variable %q: %s", v, stdout.String())
		}
	}
}

func TestNamesTheOffendingVariableOnMalformedConfig(t *testing.T) {
	e := validEnv(t)
	e["LND_ADDRESS"] = "10.21.21.9"
	var stdout, stderr bytes.Buffer
	if code := run(serveCtx(t), nil, env(e), &stdout, &stderr); code == 0 {
		t.Fatal("run with a malformed LND_ADDRESS = 0, want non-zero")
	}
	if !strings.Contains(stdout.String(), "LND_ADDRESS") {
		t.Errorf("the log does not name LND_ADDRESS: %s", stdout.String())
	}
}

func TestStartsWithValidConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(serveCtx(t), nil, env(validEnv(t)), &stdout, &stderr); code != 0 {
		t.Fatalf("run with valid config = %d, want 0 (stderr: %s)", code, stderr.String())
	}
}

// Spec §12: log to stdout only — docker logs and umbrelOS handle collection.
func TestLogsGoToStdoutOnly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(serveCtx(t), nil, env(validEnv(t)), &stdout, &stderr); code != 0 {
		t.Fatalf("run with valid config = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	var line map[string]any
	first, _, _ := strings.Cut(strings.TrimSpace(stdout.String()), "\n")
	if err := json.Unmarshal([]byte(first), &line); err != nil {
		t.Fatalf("stdout is not structured log output (%v): %s", err, stdout.String())
	}
	if line["level"] != "INFO" {
		t.Errorf("startup line is at %v, want INFO — §12 requires normal diagnosis without debug", line["level"])
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want nothing: logs go to stdout only", stderr.String())
	}
}

// Spec §12: nothing secret-bearing may reach the log, including the startup
// configuration summary.
func TestStartupSummaryDoesNotLeakSecrets(t *testing.T) {
	const sentinel = "s3ntinel-must-never-be-logged-9f3a1c"
	e := validEnv(t)
	e["ADMIN_PASSWORD"] = sentinel
	e["SESSION_SECRET"] = sentinel
	var stdout, stderr bytes.Buffer
	if code := run(serveCtx(t), nil, env(e), &stdout, &stderr); code != 0 {
		t.Fatalf("run = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if strings.Contains(stdout.String(), sentinel) {
		t.Errorf("the startup summary leaked a secret: %s", stdout.String())
	}
}

func TestUnknownFlagFailsWithAMessage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"--not-a-real-flag"}, env(validEnv(t)), &stdout, &stderr); code == 0 {
		t.Fatal("run(--not-a-real-flag) = 0, want non-zero")
	}
	if stderr.Len() == 0 {
		t.Error("run(--not-a-real-flag) wrote nothing to stderr")
	}
}

var REQUIRED = []string{
	"LND_ADDRESS", "LND_CERT_FILE", "LND_ADMIN_MACAROON",
	"DATA_DIR", "CREDENTIALS_DIR", "SERVER_IP",
}

// validEnv points at real files: the guard now asserts at startup that its two
// single-file bind mounts are files, which is the whole point of criterion 8.
func validEnv(t *testing.T) map[string]string {
	t.Helper()
	mounts := t.TempDir()
	certPath := filepath.Join(mounts, "tls.cert")
	macaroonPath := filepath.Join(mounts, "admin.macaroon")
	for _, path := range []string{certPath, macaroonPath} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
	return map[string]string{
		"LND_ADDRESS":        "127.0.0.1:1",
		"LND_CERT_FILE":      certPath,
		"LND_ADMIN_MACAROON": macaroonPath,
		"DATA_DIR":           filepath.Join(t.TempDir(), "guard-data"),
		// The socket lives here, and sun_path is capped at ~104 bytes — shorter
		// than the test framework's temp directories on macOS.
		"CREDENTIALS_DIR": lndtest.ShortDir(t),
		"SERVER_IP":       "10.21.0.17",
	}
}

// serveCtx is already cancelled. The guard serves until its context ends, and
// these tests are about everything that happens before that.
func serveCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	return ctx
}

// Spec §6, box-verified: docker creates a DIRECTORY at a bind-mount source that
// does not exist, and the container then dies at exit 127 with nothing an
// operator can act on. The guard says what to remove instead.
func TestAMountThatIsADirectoryFailsWithAnActionableMessage(t *testing.T) {
	e := validEnv(t)
	macaroonPath := e["LND_ADMIN_MACAROON"]
	if err := os.Remove(macaroonPath); err != nil {
		t.Fatalf("removing the file: %v", err)
	}
	if err := os.MkdirAll(macaroonPath, 0o700); err != nil {
		t.Fatalf("creating the directory docker would have created: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := run(serveCtx(t), nil, env(e), &stdout, &stderr); code == 0 {
		t.Fatal("the guard started with a directory where admin.macaroon should be")
	}
	out := stdout.String()
	if !strings.Contains(out, macaroonPath) {
		t.Errorf("the log does not name the path to remove: %s", out)
	}
	if !strings.Contains(out, "rm -rf") {
		t.Errorf("the log does not tell the operator how to recover: %s", out)
	}
}
