package config_test

import (
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/secret"
)

// lookup turns a map into the environment accessor the loaders take, so tests
// never touch the process environment and can run in parallel.
func lookup(env map[string]string) config.Lookup {
	return func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
}

func validServerEnv() map[string]string {
	return map[string]string{
		"LND_ADDRESS":     "10.21.21.9:10009",
		"CREDENTIALS_DIR": "/credentials",
		"DATA_DIR":        "/data",
		"GUARD_SOCKET":    "/credentials/guard.sock",
		"LISTEN_ADDR":     "0.0.0.0:8080",
		"TRUSTED_PROXIES": "10.21.0.0/16",
		"ADMIN_PASSWORD":  "correct-horse-battery",
		"SESSION_SECRET":  "0123456789abcdef0123",
		"LOG_LEVEL":       "debug",
	}
}

func validGuardEnv() map[string]string {
	return map[string]string{
		"LND_ADDRESS":            "10.21.21.9:10009",
		"LND_CERT_FILE":          "/lnd/tls.cert",
		"LND_ADMIN_MACAROON":     "/lnd/admin.macaroon",
		"DATA_DIR":               "/guard",
		"CREDENTIALS_DIR":        "/credentials",
		"SERVER_IP":              "10.21.0.17",
		"NETWORK_CIDR":           "10.21.0.0/16",
		"GUARD_MAX_SPEND_MSAT":   "100000000",
		"GUARD_MAX_PAYMENT_MSAT": "25000000",
		"LOG_LEVEL":              "info",
	}
}

func TestLoadServerAcceptsAFullyPopulatedEnvironment(t *testing.T) {
	t.Parallel()
	got, err := config.LoadServer(lookup(validServerEnv()))
	if err != nil {
		t.Fatalf("LoadServer() error = %v, want nil", err)
	}
	if got.LNDAddress != "10.21.21.9:10009" {
		t.Errorf("LNDAddress = %q", got.LNDAddress)
	}
	if got.DataDir != "/data" || got.CredentialsDir != "/credentials" {
		t.Errorf("dirs = %q, %q", got.DataDir, got.CredentialsDir)
	}
	if got.GuardSocket != "/credentials/guard.sock" {
		t.Errorf("GuardSocket = %q", got.GuardSocket)
	}
	if got.ListenAddr != "0.0.0.0:8080" {
		t.Errorf("ListenAddr = %q", got.ListenAddr)
	}
	if got.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v, want debug", got.LogLevel)
	}
	if got.AdminPassword.Reveal() != "correct-horse-battery" {
		t.Error("AdminPassword did not round-trip")
	}
	if got.SessionSecret.Reveal() != "0123456789abcdef0123" {
		t.Error("SessionSecret did not round-trip")
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.21.0.0/16")}
	if len(got.TrustedProxies) != 1 || got.TrustedProxies[0] != want[0] {
		t.Errorf("TrustedProxies = %v, want %v", got.TrustedProxies, want)
	}
}

func TestLoadGuardAcceptsAFullyPopulatedEnvironment(t *testing.T) {
	t.Parallel()
	got, err := config.LoadGuard(lookup(validGuardEnv()))
	if err != nil {
		t.Fatalf("LoadGuard() error = %v, want nil", err)
	}
	if got.LNDCertFile != "/lnd/tls.cert" || got.LNDAdminMacaroonFile != "/lnd/admin.macaroon" {
		t.Errorf("cert/macaroon paths = %q, %q", got.LNDCertFile, got.LNDAdminMacaroonFile)
	}
	if got.ServerIP != netip.MustParseAddr("10.21.0.17") {
		t.Errorf("ServerIP = %v", got.ServerIP)
	}
	if got.NetworkCIDR != netip.MustParsePrefix("10.21.0.0/16") {
		t.Errorf("NetworkCIDR = %v", got.NetworkCIDR)
	}
	if got.MaxSpendMsat != 100_000_000 || got.MaxPaymentMsat != 25_000_000 {
		t.Errorf("caps = %d, %d", got.MaxSpendMsat, got.MaxPaymentMsat)
	}
}

// The required-variable table: dropping any one of these must fail with a
// message naming it.
func TestLoadServerRequiresVariables(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"LND_ADDRESS", "CREDENTIALS_DIR", "DATA_DIR"} {
		t.Run(v, func(t *testing.T) {
			env := validServerEnv()
			delete(env, v)
			assertNamesVariable(t, mustFail(t, func() (any, error) { return config.LoadServer(lookup(env)) }), v)
		})
	}
}

func TestLoadGuardRequiresVariables(t *testing.T) {
	t.Parallel()
	required := []string{
		"LND_ADDRESS", "LND_CERT_FILE", "LND_ADMIN_MACAROON",
		"DATA_DIR", "CREDENTIALS_DIR", "SERVER_IP",
	}
	for _, v := range required {
		t.Run(v, func(t *testing.T) {
			env := validGuardEnv()
			delete(env, v)
			assertNamesVariable(t, mustFail(t, func() (any, error) { return config.LoadGuard(lookup(env)) }), v)
		})
	}
}

func TestLoadServerRejectsMalformedValues(t *testing.T) {
	t.Parallel()
	cases := []struct{ variable, value string }{
		{"LND_ADDRESS", "10.21.21.9"}, // no port
		{"LND_ADDRESS", "10.21.21.9:not-a-port"},
		{"LND_ADDRESS", "10.21.21.9:99999"}, // out of range
		{"CREDENTIALS_DIR", "credentials"},  // relative
		{"DATA_DIR", "./data"},              // relative
		{"GUARD_SOCKET", "guard.sock"},      // relative
		{"LISTEN_ADDR", "8080"},             // no host:port
		{"TRUSTED_PROXIES", "10.21.0.0/33"}, // impossible prefix
		{"TRUSTED_PROXIES", "not-an-address"},
		{"TRUSTED_PROXIES", "10.21.0.0/16, "}, // trailing empty entry
		{"ADMIN_PASSWORD", "short"},           // below the minimum length
		{"SESSION_SECRET", "tooshort"},        // below the minimum length
		{"LOG_LEVEL", "verbose"},
	}
	for _, c := range cases {
		t.Run(c.variable+"="+c.value, func(t *testing.T) {
			env := validServerEnv()
			env[c.variable] = c.value
			assertNamesVariable(t, mustFail(t, func() (any, error) { return config.LoadServer(lookup(env)) }), c.variable)
		})
	}
}

func TestLoadGuardRejectsMalformedValues(t *testing.T) {
	t.Parallel()
	cases := []struct{ variable, value string }{
		{"LND_ADDRESS", "10.21.21.9"},
		{"LND_CERT_FILE", "tls.cert"},
		{"LND_ADMIN_MACAROON", "admin.macaroon"},
		{"DATA_DIR", "guard"},
		{"CREDENTIALS_DIR", "credentials"},
		{"SERVER_IP", "10.21.0.17/32"},
		{"SERVER_IP", "not-an-ip"},
		{"NETWORK_CIDR", "10.21.0.0"},
		{"GUARD_MAX_SPEND_MSAT", "-1"},
		{"GUARD_MAX_SPEND_MSAT", "100_000"},
		{"GUARD_MAX_SPEND_MSAT", "1.5"},
		{"GUARD_MAX_PAYMENT_MSAT", "-1"},
		{"LOG_LEVEL", "verbose"},
	}
	for _, c := range cases {
		t.Run(c.variable+"="+c.value, func(t *testing.T) {
			env := validGuardEnv()
			env[c.variable] = c.value
			assertNamesVariable(t, mustFail(t, func() (any, error) { return config.LoadGuard(lookup(env)) }), c.variable)
		})
	}
}

func TestGuardRejectsAPerPaymentCapAboveTheWindowCap(t *testing.T) {
	t.Parallel()
	env := validGuardEnv()
	env["GUARD_MAX_PAYMENT_MSAT"] = "200000000"
	err := mustFail(t, func() (any, error) { return config.LoadGuard(lookup(env)) })
	assertNamesVariable(t, err, "GUARD_MAX_PAYMENT_MSAT")
	assertNamesVariable(t, err, "GUARD_MAX_SPEND_MSAT")
}

func TestServerDefaults(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"LND_ADDRESS":     "10.21.21.9:10009",
		"CREDENTIALS_DIR": "/credentials",
		"DATA_DIR":        "/data",
	}
	got, err := config.LoadServer(lookup(env))
	if err != nil {
		t.Fatalf("LoadServer() error = %v", err)
	}
	if got.ListenAddr != config.DefaultListenAddr {
		t.Errorf("ListenAddr = %q, want %q", got.ListenAddr, config.DefaultListenAddr)
	}
	if got.GuardSocket != "/credentials/guard.sock" {
		t.Errorf("GuardSocket = %q, want it derived from CREDENTIALS_DIR", got.GuardSocket)
	}
	if got.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want info", got.LogLevel)
	}
	if !got.AdminPassword.IsZero() || !got.SessionSecret.IsZero() {
		t.Error("unset secrets should be zero, not defaulted")
	}
}

func TestGuardDefaults(t *testing.T) {
	t.Parallel()
	env := validGuardEnv()
	delete(env, "GUARD_MAX_SPEND_MSAT")
	delete(env, "GUARD_MAX_PAYMENT_MSAT")
	delete(env, "NETWORK_CIDR")
	delete(env, "LOG_LEVEL")
	got, err := config.LoadGuard(lookup(env))
	if err != nil {
		t.Fatalf("LoadGuard() error = %v", err)
	}
	if got.MaxSpendMsat != config.DefaultMaxSpendMsat {
		t.Errorf("MaxSpendMsat = %d, want %d", got.MaxSpendMsat, config.DefaultMaxSpendMsat)
	}
	if got.MaxPaymentMsat != config.DefaultMaxPaymentMsat {
		t.Errorf("MaxPaymentMsat = %d, want %d", got.MaxPaymentMsat, config.DefaultMaxPaymentMsat)
	}
	if got.NetworkCIDR.IsValid() {
		t.Errorf("NetworkCIDR = %v, want the zero prefix when unset", got.NetworkCIDR)
	}
	if got.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want info", got.LogLevel)
	}
}

// Spec §7: an empty TRUSTED_PROXIES is a distinct state — trust nothing — and
// must never be read as "trust everything".
func TestEmptyTrustedProxiesTrustsNoProxy(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", "   "} {
		env := validServerEnv()
		env["TRUSTED_PROXIES"] = value
		got, err := config.LoadServer(lookup(env))
		if err != nil {
			t.Fatalf("LoadServer(TRUSTED_PROXIES=%q) error = %v", value, err)
		}
		if len(got.TrustedProxies) != 0 {
			t.Errorf("TrustedProxies = %v, want empty", got.TrustedProxies)
		}
		if got.TrustsProxy(netip.MustParseAddr("10.21.0.1")) {
			t.Error("an empty TRUSTED_PROXIES trusted an address; empty must trust nothing")
		}
	}
}

func TestTrustsProxy(t *testing.T) {
	t.Parallel()
	env := validServerEnv()
	env["TRUSTED_PROXIES"] = "10.21.0.0/16, 192.0.2.7, fd00::/8"
	got, err := config.LoadServer(lookup(env))
	if err != nil {
		t.Fatalf("LoadServer() error = %v", err)
	}
	if len(got.TrustedProxies) != 3 {
		t.Fatalf("TrustedProxies = %v, want 3 entries", got.TrustedProxies)
	}
	cases := map[string]bool{
		// app_proxy hands over v4-mapped values, never bare dotted quad, so the
		// mapped form has to match the same prefix (box verification, §7).
		"::ffff:10.21.0.1": true,
		"::ffff:10.22.0.1": false,
		"::ffff:192.0.2.7": true,
		"10.21.0.1":        true,
		"10.22.0.1":        false,
		"192.0.2.7":        true, // a bare address is accepted and means exactly itself
		"192.0.2.8":        false,
		"fd00::1":          true,
		"2001:db8::1":      false,
	}
	for addr, want := range cases {
		if got := got.TrustsProxy(netip.MustParseAddr(addr)); got != want {
			t.Errorf("TrustsProxy(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestSecretsAreCarriedByTheSharedRedactingType(t *testing.T) {
	t.Parallel()
	got, err := config.LoadServer(lookup(validServerEnv()))
	if err != nil {
		t.Fatalf("LoadServer() error = %v", err)
	}
	var _ secret.String = got.AdminPassword
	var _ secret.String = got.SessionSecret
}

func mustFail(t *testing.T, load func() (any, error)) error {
	t.Helper()
	got, err := load()
	if err == nil {
		t.Fatalf("load succeeded (%+v), want an error", got)
	}
	return err
}

func assertNamesVariable(t *testing.T, err error, variable string) {
	t.Helper()
	if !strings.Contains(err.Error(), variable) {
		t.Errorf("error %q does not name the offending variable %q", err, variable)
	}
	var cfgErr *config.VarError
	if !errors.As(err, &cfgErr) {
		t.Errorf("error %v is not a *config.VarError", err)
	}
}

// tna.4 as reshaped by `06v`: GUARD_ALLOW_SENDING is the DEPLOYMENT CEILING, and
// it is ON unless a deployment says otherwise.
//
// THE FLIP IS A CHANGE OF MEANING, NOT OF APPETITE, and the reason it is safe is
// that the operator's gate MOVED rather than went away. It is now the guard's
// stored latch — off on a fresh install, turned on only through a ceremony the
// server cannot forge — so a missing variable, a typo, or a compose file that
// lost the line still lands on a receive-only install.
//
// What a false default bought before was a control an operator could reach. `06v`
// established they cannot: umbrelOS has no settings surface in any of 391 app
// manifests, and `exports.sh` is package content that an update overwrites. So
// false-by-default did not mean "off until the operator says so" — it meant
// "off, permanently, on every stock install", while the app's own Sending page
// told them to change a setting that did not exist.
func TestTheDeploymentCeilingIsOnUnlessADeploymentSaysOtherwise(t *testing.T) {
	t.Parallel()
	env := validGuardEnv()
	delete(env, "GUARD_ALLOW_SENDING")

	cfg, err := config.LoadGuard(lookup(env))
	if err != nil {
		t.Fatalf("LoadGuard: %v", err)
	}
	if !cfg.AllowSending {
		t.Error("an environment that never mentions GUARD_ALLOW_SENDING forbids sending. On " +
			"umbrelOS there is no supported way to change it, so this ships an app whose " +
			"Sending page names a remedy that cannot be performed — which is `06v`")
	}

	env["GUARD_ALLOW_SENDING"] = "false"
	cfg, err = config.LoadGuard(lookup(env))
	if err != nil {
		t.Fatalf("LoadGuard with the ceiling down: %v", err)
	}
	if cfg.AllowSending {
		t.Error("GUARD_ALLOW_SENDING=false was not honoured; a deployment that hardened " +
			"itself would find the app able to mint spend authority anyway")
	}
}

// A value the parser does not understand is REFUSED, not read as either answer.
//
// The failure mode of a lenient parser here is silent, and since `06v` it is
// silent in the more dangerous direction: a deployment that hardened itself by
// writing "no" would, under a lenient parser, fall back to the default — which
// is now TRUE. A startup that names the variable costs one restart; a mystery
// costs an evening, and here it would cost a property somebody deliberately
// asked for.
func TestAnUnreadableAllowSendingIsRefusedRatherThanTakenAsFalse(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"yes", "on", "TRUE!", "enabled", "0.0"} {
		env := validGuardEnv()
		env["GUARD_ALLOW_SENDING"] = value
		if _, err := config.LoadGuard(lookup(env)); err == nil {
			t.Errorf("GUARD_ALLOW_SENDING=%q was accepted; an operator who typed it would get "+
				"an app that refuses to send and never says why", value)
		} else if !strings.Contains(err.Error(), "GUARD_ALLOW_SENDING") {
			t.Errorf("the error for %q does not name the variable: %v", value, err)
		}
	}

	// TWO CONVENTIONS THIS PARSER ALREADY HAS, asserted here rather than
	// discovered: every option trims, and a value that is empty after trimming
	// is the same as unset — so "" takes the DEFAULT, which since `06v` is true.
	// The distinction between "" reaching a value through "unset" and through
	// "unparseable" is the kind of thing a reader should not have to derive, and
	// it matters more now that the two land on opposite answers.
	for value, want := range map[string]bool{"1": true, " true ": true, "0": false, "": true} {
		env := validGuardEnv()
		env["GUARD_ALLOW_SENDING"] = value
		cfg, err := config.LoadGuard(lookup(env))
		if err != nil {
			t.Errorf("GUARD_ALLOW_SENDING=%q: %v", value, err)
			continue
		}
		if cfg.AllowSending != want {
			t.Errorf("GUARD_ALLOW_SENDING=%q gave %v, want %v", value, cfg.AllowSending, want)
		}
	}
}
