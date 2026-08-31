package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/store"
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
	if got := stdout.String(); !strings.Contains(got, "brollyzapper") {
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

var REQUIRED = []string{"LND_ADDRESS", "CREDENTIALS_DIR", "DATA_DIR"}

// validEnv is a configuration whose dependencies are all ABSENT: the LND
// address answers nothing, the credential volume is empty, and there is no
// guard socket. That is criterion 8's case — the process must still serve.
func validEnv(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"LND_ADDRESS":     "127.0.0.1:1",
		"CREDENTIALS_DIR": filepath.Join(t.TempDir(), "credentials"),
		"DATA_DIR":        filepath.Join(t.TempDir(), "data"),
		"LISTEN_ADDR":     freeAddr(t),
	}
}

// serveCtx is already cancelled. The server runs until its context ends, and
// the tests that only care about startup end it immediately.
func serveCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	return ctx
}

// freeAddr picks a loopback port by binding and releasing it.
func freeAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("releasing the port: %v", err)
	}
	return addr
}

// Criterion 8: no LND, no credentials, no guard socket — and the server still
// comes up, serves, and shuts down cleanly. §11 forbids crash loops; Umbrel's
// rules require a degraded state rather than a dead tile.
func TestTheServerServesWithEveryDependencyAbsent(t *testing.T) {
	environ := validEnv(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var stdout, stderr bytes.Buffer
	exit := make(chan int, 1)
	go func() { exit <- run(ctx, nil, env(environ), &stdout, &stderr) }()

	base := "http://" + environ["LISTEN_ADDR"]
	client := &http.Client{Timeout: 2 * time.Second}
	waitForHTTP(t, client, base+"/health")

	// /health answers, and says nothing but ok.
	resp, err := client.Get(base + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Errorf("GET /health = %d %q, want 200 \"ok\"", resp.StatusCode, body)
	}

	// The admin UI is reachable and explains what is missing rather than failing.
	resp, err = client.Get(base + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /login = %d, want 200 with every dependency absent", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Sign in") {
		t.Errorf("the login page did not render: %s", body)
	}

	cancel()
	select {
	case code := <-exit:
		if code != 0 {
			t.Errorf("run = %d after a clean shutdown, want 0 (stdout: %s)", code, stdout.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the server did not shut down when its context ended")
	}
}

func waitForHTTP(t *testing.T, client *http.Client, url string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never answered: %v", url, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// §11 Tier 1: the server refuses to run if it can reach admin.macaroon —
// §3's credential inversion has been undone and every other control is
// decorative. It is a packaging defect, never a user condition.
func TestTierOneRefusesToRunWithAReachableAdminMacaroon(t *testing.T) {
	environ := validEnv(t)
	planted := filepath.Join(environ["DATA_DIR"], "chain", "bitcoin")
	if err := os.MkdirAll(planted, 0o700); err != nil {
		t.Fatal(err)
	}
	macaroonPath := filepath.Join(planted, "admin.macaroon")
	if err := os.WriteFile(macaroonPath, []byte("admin"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), nil, env(environ), &stdout, &stderr)
	if code == 0 {
		t.Fatal("the server started with a readable admin.macaroon under DATA_DIR")
	}

	out := stdout.String()
	if !strings.Contains(out, macaroonPath) {
		t.Errorf("the refusal does not name what it found: %s", out)
	}
	if !strings.Contains(strings.ToLower(out), "packaging defect") {
		t.Errorf("the refusal does not say this is a packaging defect: %s", out)
	}
	// §11: bind and serve FIRST, then check. The listener must have come up, so
	// the failure is visible rather than an unexplained dead container.
	listening := strings.Index(out, `"msg":"listening"`)
	refusing := strings.Index(out, "refusing to run")
	if listening < 0 {
		t.Fatalf("the server never bound a listener before refusing: %s", out)
	}
	if refusing < listening {
		t.Error("the Tier-1 refusal came before the listener was up; §11 says bind and serve first")
	}
}

// The same check fires on the environment variable, which is the other way the
// server ends up able to read admin.macaroon.
func TestTierOneRefusesToRunWithTheAdminMacaroonVariableSet(t *testing.T) {
	environ := validEnv(t)
	environ["LND_ADMIN_MACAROON"] = "/lnd/admin.macaroon"

	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), nil, env(environ), &stdout, &stderr); code == 0 {
		t.Fatal("the server started with LND_ADMIN_MACAROON set")
	}
	if !strings.Contains(stdout.String(), "LND_ADMIN_MACAROON") {
		t.Errorf("the refusal does not name the variable: %s", stdout.String())
	}
}

// Review L6. The listener faced the LAN with only ReadHeaderTimeout set, which
// bounds the request line and headers and nothing after them: a connection that
// sent a complete header block and then one byte of body per minute held a
// goroutine and a file descriptor indefinitely. With SetMaxOpenConns(1) on the
// store, enough of those is the whole app.
//
// This asserts the fields rather than the behaviour, which is the exception
// this project usually argues against — but the behaviour here IS net/http's,
// and a test that opened a slow socket and waited would be testing the standard
// library on a timer. What can actually regress is a field going unset, so that
// is what is checked, and every bound is checked rather than the one that was
// missing.
func TestTheListenerBoundsEveryPhaseOfARequest(t *testing.T) {
	server := newHTTPServer(nil)
	for _, bound := range []struct {
		name string
		got  time.Duration
	}{
		{"ReadHeaderTimeout", server.ReadHeaderTimeout},
		{"ReadTimeout", server.ReadTimeout},
		{"WriteTimeout", server.WriteTimeout},
		{"IdleTimeout", server.IdleTimeout},
	} {
		if bound.got <= 0 {
			t.Errorf("%s is unset; a request phase with no bound is a phase an "+
				"idle connection can hold open forever", bound.name)
		}
	}
	if server.MaxHeaderBytes <= 0 {
		t.Error("MaxHeaderBytes is unset, so a header block is bounded only by net/http's default")
	}
	// ReadTimeout covers the whole read including headers, so a ReadTimeout at
	// or below ReadHeaderTimeout makes the header bound unreachable.
	if server.ReadTimeout <= server.ReadHeaderTimeout {
		t.Errorf("ReadTimeout (%s) does not exceed ReadHeaderTimeout (%s); the header bound never fires",
			server.ReadTimeout, server.ReadHeaderTimeout)
	}
}

// o34.21's seam: WHICH field of the invoice becomes the receipt's created_at.
//
// The wallet tests cover what CreditInvoice does with the value it is handed.
// This covers the line that chooses it — the one that was wrong for four waves
// while every unit test passed, because nothing in Go ever read
// lnrpc.Invoice.SettleDate. Change it to CreationDate and this fails; before
// this test, the whole gate stayed green and only regtest noticed.
func TestTheSettleTimeComesFromTheInvoicesSettleDate(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	settled := int64(1_700_000_000)

	got := settleTimeOf(&lnrpc.Invoice{
		SettleDate: settled,
		// Deliberately different, and deliberately LATER — a handler clock is
		// always later than the settle time, so a test whose other candidates
		// were earlier could pass on the wrong field by accident.
		CreationDate: settled - 600,
	}, "hash", log)
	if want := time.Unix(settled, 0).UTC(); !got.Equal(want) {
		t.Errorf("settleTimeOf = %s, want the invoice's settle_date %s", got, want)
	}
}

// And the anomaly is loud, because absorbing it quietly is how the original bug
// survived four waves.
func TestASettledInvoiceWithNoSettleTimeIsReported(t *testing.T) {
	var logged strings.Builder
	log := slog.New(slog.NewTextHandler(&logged, nil))

	got := settleTimeOf(&lnrpc.Invoice{SettleDate: 0}, "abcdef0123", log)
	if !got.IsZero() {
		t.Errorf("settleTimeOf = %s for an invoice with no settle time, want the zero time", got)
	}
	if !strings.Contains(logged.String(), "no settle time") {
		t.Errorf("nothing was logged about a settled invoice carrying no settle time:\n%s",
			logged.String())
	}
}

// fakeCrediter answers CreditInvoice as told, and records what it was asked.
type fakeCrediter struct {
	err      error
	credited bool
	calls    int
}

func (f *fakeCrediter) CreditInvoice(_ context.Context, _, _ string, _ int64,
	_ time.Time) (bool, error) {
	f.calls++
	return f.credited, f.err
}

// vz1.8 criteria 1, 2 and 3, and the finding is from real traffic: the box saw
//
//	WARN invoice stream dropped; reconnecting
//	     error="handling settlement at index 7513: settling 78784f10…: store: not found"
//
// for a real settled 221-sat invoice created by ANOTHER APP on the shared node.
// Umbrel is deliberately shared — BTCPay, Alby Hub and LNDg receive on the same
// LND — so that is the normal case there, and as written every neighbour's
// payment dropped this app's subscription.
//
// The two rows are one errors.Is apart and the difference is money: skipping a
// hash we have no row for is definitionally safe, and skipping one we DO have a
// row for would be silent loss.
func TestAForeignSettlementIsSkippedAndOurOwnFailureIsNot(t *testing.T) {
	for _, tc := range []struct {
		name        string
		creditErr   error
		wantErr     bool
		wantSkipped bool
	}{{
		// The exact error shape from the box.
		name:        "an invoice this app did not create",
		creditErr:   fmt.Errorf("settling %s: %w", strings.Repeat("a", 64), store.ErrUnknownInvoice),
		wantSkipped: true,
	}, {
		// The negative that could not be written while the discriminator was
		// the package-wide sentinel. Skipping advances the resume point past
		// the settlement and nothing revisits it, so a not-found arising
		// anywhere ELSE under CreditInvoice must NOT be read as "not ours" —
		// that would be unrecoverable, silent money loss through the branch
		// built to prevent it.
		name:      "some other not-found from under the credit",
		creditErr: fmt.Errorf("reservation 7: %w", store.ErrNotFound),
		wantErr:   true,
	}, {
		name:      "our own invoice failing to credit",
		creditErr: errors.New("database is locked"),
		wantErr:   true,
	}, {
		name:      "an ordinary credited settlement",
		creditErr: nil,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			var logged bytes.Buffer
			log := logging.New(&logged, logging.NewLevelVar(slog.LevelDebug))
			purse := &fakeCrediter{err: tc.creditErr, credited: tc.creditErr == nil}
			var notified int

			err := handleSettlement(t.Context(), &lnrpc.Invoice{
				RHash:       bytes.Repeat([]byte{0xab}, 32),
				RPreimage:   bytes.Repeat([]byte{0xcd}, 32),
				AmtPaidMsat: 221_000,
				SettleIndex: 7513,
				SettleDate:  1_700_000_000,
			}, purse, func(context.Context, string) { notified++ }, log)

			if tc.wantErr {
				if err == nil {
					t.Fatal("a failure on OUR OWN invoice was swallowed; the stream would " +
						"carry on and the money would be lost silently")
				}
				return
			}
			if err != nil {
				t.Fatalf("handleSettlement = %v; the stream would drop and reconnect", err)
			}

			if tc.wantSkipped {
				if notified != 0 {
					t.Error("a receipt was asked for on an invoice this app never minted")
				}
				// One DEBUG line, carrying the two things a diagnosis needs.
				line := debugSkipLine(t, &logged)
				if line["level"] != "DEBUG" {
					t.Errorf("level = %v, want DEBUG — this fires on every neighbour's "+
						"payment on a shared node", line["level"])
				}
				if line["settle_index"] != float64(7513) {
					t.Errorf("settle_index = %v, want 7513", line["settle_index"])
				}
				if hash, _ := line["payment_hash"].(string); hash == "" || len(hash) >= 64 {
					t.Errorf("payment_hash = %q, want a truncated hash", hash)
				}
				return
			}
			if notified != 1 {
				t.Errorf("a credited settlement asked for %d receipts, want 1", notified)
			}
			if !strings.Contains(logged.String(), "invoice settled") {
				t.Errorf("a credited settlement logged nothing at INFO:\n%s", logged.String())
			}
		})
	}
}

// skipMessage is matched EXACTLY, like the two sibling helpers in
// internal/api and internal/nostr. The first version of this used
// strings.Contains, which would also match a future line merely mentioning the
// phrase and made its "exactly one" weaker than the helpers it was copied from.
const skipMessage = "a settlement for an invoice this app did not create; skipping"

func debugSkipLine(t *testing.T, out *bytes.Buffer) map[string]any {
	t.Helper()
	var found []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if raw == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			t.Fatalf("log line is not JSON: %s", raw)
		}
		if record["msg"] == skipMessage {
			found = append(found, record)
		}
	}
	if len(found) != 1 {
		t.Fatalf("found %d skip lines, want exactly 1:\n%s", len(found), out.String())
	}
	return found[0]
}
