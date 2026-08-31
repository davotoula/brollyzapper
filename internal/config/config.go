package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// Defaults for the optional settings. They are the values the packaging in §10
// happens to set explicitly; the app must work without it setting them.
const (
	DefaultListenAddr     = "0.0.0.0:8080"
	DefaultMaxSpendMsat   = 100_000_000 // 100k sat per rolling 24h window
	DefaultMaxPaymentMsat = 25_000_000  // 25k sat per payment

	// DefaultAllowSending is TRUE since `06v`, and the flip is a change of
	// meaning rather than of appetite.
	//
	// GUARD_ALLOW_SENDING was the operator's gate and defaulted to false, which
	// was right while an operator could reach it. `06v` established they cannot:
	// umbrelOS has no settings surface in any app manifest, and `exports.sh` —
	// the only live channel into compose interpolation — is package content that
	// `apps.update.mutate` overwrites, verified live when the 0.1.12 update wiped
	// a hand-added export. A false default therefore shipped an app on which
	// sending could not be enabled by any supported means, while its own Sending
	// page named a setting that did not exist.
	//
	// It is now the DEPLOYMENT ceiling: may sending ever be enabled here at all.
	// A hardened deployment sets it false and no in-app action lifts it. §6's
	// receive-only default is preserved by the guard's stored LATCH, which is off
	// on a fresh install and turns on only through the operator's ceremony.
	DefaultAllowSending = true

	minAdminPasswordLen = 8
	minSessionSecretLen = 16
)

// GuardSocketName is the guard's socket inside the shared credential volume.
// Both binaries derive their path from it: the server to dial, the guard to
// listen (spec §6).
const GuardSocketName = "guard.sock"

// VarError names the environment variable that was wrong. Startup failures are
// only actionable if the operator is told which variable to fix.
type VarError struct {
	Var    string
	Reason string
}

func (e *VarError) Error() string { return e.Var + ": " + e.Reason }

// Lookup reads one environment variable. Taking it as a parameter keeps the
// loaders pure and the tests free of process-wide state.
//
// Tests wrap a map in this shape in a few places. That is deliberately not
// factored into an exported MapLookup helper here: it would be production API
// with no production caller, and the closure's shape is checked by the compiler
// at every site anyway.
type Lookup func(name string) (value string, ok bool)

// OSLookup reads the real process environment.
func OSLookup(name string) (string, bool) { return os.LookupEnv(name) }

// Server is the configuration of the brollyzapper binary.
//
// It has no field for an admin macaroon, and must not grow one: §3 puts the
// only copy of admin.macaroon in the guard, and a server that cannot be
// configured to hold it cannot be talked into holding it.
type Server struct {
	LNDAddress     string
	CredentialsDir string
	DataDir        string
	GuardSocket    string
	ListenAddr     string
	TrustedProxies []netip.Prefix
	AdminPassword  secret.String
	SessionSecret  secret.String
	LogLevel       slog.Level
}

// LogValue is §12's "the settings struct": the configuration is logged at
// startup, and it holds two credentials.
//
// The paths and the address are the parts an operator debugging a start-up
// problem actually needs. Both secrets are structurally absent — whether one is
// SET is a fact worth having and is not the value.
func (s Server) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("lnd_address", s.LNDAddress),
		slog.String("credentials_dir", s.CredentialsDir),
		slog.String("data_dir", s.DataDir),
		slog.String("guard_socket", s.GuardSocket),
		slog.String("listen_addr", s.ListenAddr),
		slog.Int("trusted_proxies", len(s.TrustedProxies)),
		slog.Bool("admin_password_set", s.AdminPassword.Reveal() != ""),
		slog.Bool("session_secret_set", s.SessionSecret.Reveal() != ""),
		slog.String("log_level", s.LogLevel.String()),
	)
}

// TrustsProxy reports whether addr is a proxy whose forwarded-for headers may
// be believed (spec §7). An empty TrustedProxies trusts nothing, which is the
// safe reading: the TCP peer is then the client.
func (s *Server) TrustsProxy(addr netip.Addr) bool {
	return TrustsProxyIn(s.TrustedProxies, addr)
}

// Guard is the configuration of the brollyguard binary.
//
// LNDAdminMacaroonFile is a path, not a credential: the guard reads the file
// itself, and a redacted path would make a misconfigured mount undiagnosable.
type Guard struct {
	LNDAddress           string
	LNDCertFile          string
	LNDAdminMacaroonFile string
	DataDir              string
	CredentialsDir       string
	ServerIP             netip.Addr
	NetworkCIDR          netip.Prefix // zero value means "not configured"
	MaxSpendMsat         int64
	MaxPaymentMsat       int64
	// AllowSending is the DEPLOYMENT CEILING on minting spend authority — may
	// sending ever be enabled on this deployment at all (tna.4, reshaped by
	// `06v` Ruling 4).
	//
	// TRUE BY DEFAULT since `06v`; see DefaultAllowSending for why the flip is a
	// change of meaning rather than of appetite. It is a hard "never" for a
	// hardened off-Umbrel deployment and nothing else — no in-app action lifts
	// it, and the Sending page says so rather than offering a ceremony that
	// cannot work.
	//
	// IT IS NO LONGER THE OPERATOR'S GATE. That is the guard's stored latch,
	// off on a fresh install, which is what now preserves §6's receive-only
	// default. The two are ANDed: see Guard.sendingPermitted.
	//
	// IN THE GUARD'S ENVIRONMENT, which is precisely the channel the server
	// cannot write — the same precedent §6 sets for the hard cap. A flag in the
	// server's database, or in the server's own environment, would be a lock
	// whose key is kept in the room it locks. What `06v` established is that it
	// is a channel the OPERATOR cannot write either, on umbrelOS, which is why
	// it stopped being their gate.
	//
	// It gates MINTING and not the life of authority already minted: see
	// Guard.BakeSpend and Guard.EnsureSpendMacaroon for why finding it off at
	// start must not revoke.
	AllowSending bool
	// AuthorisationLocation is where the DEPLOYMENT says the operator will find
	// the guard's authorisation file, in words a person can follow (`06v`).
	//
	// §19 forbids the generic app assuming deployment-specific paths, and this
	// is the seam that satisfies it: the Umbrel package knows the string, the
	// guard relays it through Status, and neither internal/api nor the templates
	// contain an umbrelOS path. Unset, the guard states its own path inside its
	// container, which is the honest answer for a deployment that has not said.
	AuthorisationLocation string
	LogLevel              slog.Level
}

// LoadServer reads and validates the server's environment. Every problem is
// reported, not just the first, so one restart is enough to see them all.
func LoadServer(env Lookup) (*Server, error) {
	p := &parser{env: env}
	cfg := &Server{
		LNDAddress:     p.requiredHostPort("LND_ADDRESS"),
		CredentialsDir: p.requiredAbsPath("CREDENTIALS_DIR"),
		DataDir:        p.requiredAbsPath("DATA_DIR"),
		ListenAddr:     p.optionalHostPort("LISTEN_ADDR", DefaultListenAddr),
		TrustedProxies: p.optionalPrefixList("TRUSTED_PROXIES"),
		AdminPassword:  p.optionalSecret("ADMIN_PASSWORD", minAdminPasswordLen),
		SessionSecret:  p.optionalSecret("SESSION_SECRET", minSessionSecretLen),
		LogLevel:       p.optionalLevel("LOG_LEVEL"),
	}
	// The socket lives in the credential volume both containers share, so it
	// has a sensible default whenever CREDENTIALS_DIR is known.
	cfg.GuardSocket = p.optionalAbsPath("GUARD_SOCKET", path.Join(cfg.CredentialsDir, GuardSocketName))
	if err := p.err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadGuard reads and validates the guard's environment.
func LoadGuard(env Lookup) (*Guard, error) {
	p := &parser{env: env}
	cfg := &Guard{
		LNDAddress:            p.requiredHostPort("LND_ADDRESS"),
		LNDCertFile:           p.requiredAbsPath("LND_CERT_FILE"),
		LNDAdminMacaroonFile:  p.requiredAbsPath("LND_ADMIN_MACAROON"),
		DataDir:               p.requiredAbsPath("DATA_DIR"),
		CredentialsDir:        p.requiredAbsPath("CREDENTIALS_DIR"),
		ServerIP:              p.requiredAddr("SERVER_IP"),
		NetworkCIDR:           p.optionalPrefix("NETWORK_CIDR"),
		MaxSpendMsat:          p.optionalMsat("GUARD_MAX_SPEND_MSAT", DefaultMaxSpendMsat),
		MaxPaymentMsat:        p.optionalMsat("GUARD_MAX_PAYMENT_MSAT", DefaultMaxPaymentMsat),
		AllowSending:          p.optionalBool("GUARD_ALLOW_SENDING", DefaultAllowSending),
		AuthorisationLocation: p.optionalText("GUARD_AUTHORISATION_LOCATION"),
		LogLevel:              p.optionalLevel("LOG_LEVEL"),
	}
	// ZERO MEANS NOTHING MAY PASS, not "no cap" — see Guard.InterceptRequest.
	// The cross-check below catches a zero window against a non-zero payment
	// cap, but 0 and 0 together satisfy it (`0 > 0` is false), so the meaning of
	// zero is settled where it is enforced rather than refused here: refusing
	// would be a crash loop over a setting, and §19 is degraded over dead.
	//
	// A per-payment cap above the window cap is unenforceable and always a
	// mistake; §6 has the window as the outer bound.
	if p.ok("GUARD_MAX_PAYMENT_MSAT") && p.ok("GUARD_MAX_SPEND_MSAT") && cfg.MaxPaymentMsat > cfg.MaxSpendMsat {
		p.fail("GUARD_MAX_PAYMENT_MSAT", "%d exceeds GUARD_MAX_SPEND_MSAT (%d); the per-payment cap cannot be above the window cap",
			cfg.MaxPaymentMsat, cfg.MaxSpendMsat)
	}
	if err := p.err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parser accumulates validation failures so a single startup reports all of them.
type parser struct {
	env  Lookup
	errs []error
}

func (p *parser) fail(name, format string, args ...any) {
	p.errs = append(p.errs, &VarError{Var: name, Reason: fmt.Sprintf(format, args...)})
}

// ok reports whether a variable parsed without complaint, so cross-field checks
// do not pile a second error onto an already-broken value. The errors already
// name their variable, so there is nothing else to keep in step.
func (p *parser) ok(name string) bool {
	for _, err := range p.errs {
		var varErr *VarError
		if errors.As(err, &varErr) && varErr.Var == name {
			return false
		}
	}
	return true
}

func (p *parser) err() error { return errors.Join(p.errs...) }

// value returns the trimmed value and whether it was set to anything non-empty.
func (p *parser) value(name string) (string, bool) {
	raw, ok := p.env(name)
	if !ok {
		return "", false
	}
	v := strings.TrimSpace(raw)
	return v, v != ""
}

func (p *parser) required(name string) (string, bool) {
	v, ok := p.value(name)
	if !ok {
		p.fail(name, "is required and was not set")
		return "", false
	}
	return v, true
}

func (p *parser) requiredHostPort(name string) string {
	v, ok := p.required(name)
	if !ok {
		return ""
	}
	return p.hostPort(name, v)
}

func (p *parser) optionalHostPort(name, def string) string {
	v, ok := p.value(name)
	if !ok {
		return def
	}
	return p.hostPort(name, v)
}

func (p *parser) hostPort(name, v string) string {
	_, port, err := net.SplitHostPort(v)
	if err != nil {
		p.fail(name, "%q is not host:port: %v", v, err)
		return ""
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		p.fail(name, "%q has no valid port", v)
		return ""
	}
	return v
}

func (p *parser) requiredAbsPath(name string) string {
	v, ok := p.required(name)
	if !ok {
		return ""
	}
	return p.absPath(name, v)
}

func (p *parser) optionalAbsPath(name, def string) string {
	v, ok := p.value(name)
	if !ok {
		return def
	}
	return p.absPath(name, v)
}

func (p *parser) absPath(name, v string) string {
	if !path.IsAbs(v) {
		p.fail(name, "%q is not an absolute path", v)
		return ""
	}
	return path.Clean(v)
}

func (p *parser) requiredAddr(name string) netip.Addr {
	v, ok := p.required(name)
	if !ok {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(v)
	if err != nil {
		p.fail(name, "%q is not an IP address: %v", v, err)
		return netip.Addr{}
	}
	return addr
}

func (p *parser) optionalPrefix(name string) netip.Prefix {
	v, ok := p.value(name)
	if !ok {
		return netip.Prefix{}
	}
	prefix, err := netip.ParsePrefix(v)
	if err != nil {
		p.fail(name, "%q is not a CIDR prefix: %v", v, err)
		return netip.Prefix{}
	}
	return prefix
}

// ParsePrefixList parses a comma-separated CIDR list. An unset or empty value
// yields no entries, which every caller must read as "trust nothing" (spec §7)
// — never as "trust everything".
//
// Exported because §7 mirrors TRUSTED_PROXIES into settings.trusted_proxies,
// and the admin UI must parse an edited value exactly the way startup parsed
// the environment one.
func ParsePrefixList(value string) ([]netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, fmt.Errorf("%q has an empty entry; remove the stray comma", value)
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			out = append(out, prefix)
			continue
		}
		// A bare address is unambiguous — it means exactly that host — so it is
		// accepted and widened to a single-address prefix.
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("%q is neither a CIDR prefix nor an IP address", entry)
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}

// TrustsProxyIn reports whether addr falls in any of the prefixes.
func TrustsProxyIn(prefixes []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (p *parser) optionalPrefixList(name string) []netip.Prefix {
	v, ok := p.value(name)
	if !ok {
		return nil
	}
	out, err := ParsePrefixList(v)
	if err != nil {
		p.fail(name, "%s", err)
		return nil
	}
	return out
}

func (p *parser) optionalMsat(name string, def int64) int64 {
	v, ok := p.value(name)
	if !ok {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		p.fail(name, "%q is not a whole number of msat", v)
		return def
	}
	if n < 0 {
		p.fail(name, "%d is negative; a cap cannot be below zero", n)
		return def
	}
	return n
}

// optionalBool reads a flag, and REFUSES anything it does not recognise rather
// than reading it as false.
//
// The refusal matters more here than the parse does. GUARD_ALLOW_SENDING is a
// security control, and the failure mode of a lenient parser is silent: an
// operator who types "yes" or "on" gets a container that starts, says nothing,
// and refuses every attempt to enable sending — which reads as the app being
// broken rather than as the setting being wrong. A startup that names the
// variable is one restart; a mystery is an evening.
//
// Two of this parser's existing conventions ride along and are NOT special-cased
// here: every value is trimmed, so " true " parses; and empty-after-trim is
// "unset", so "" takes the default rather than failing. Both land on the safe
// answer for this flag, and the test writes them down because neither is
// derivable from this call site.
func (p *parser) optionalBool(name string, def bool) bool {
	v, ok := p.value(name)
	if !ok {
		return def
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		p.fail(name, "%q is not true or false", v)
		return def
	}
	return parsed
}

// optionalText reads a free-text setting, trimmed, with "" for unset.
//
// No validation, deliberately: GUARD_AUTHORISATION_LOCATION is a sentence the
// deployment writes for its own operator, and this app has no standing to judge
// what a route through someone else's file browser looks like. It grants
// nothing — it is displayed, never resolved — so the failure mode of a wrong
// value is an operator who has to look twice, not a security property.
func (p *parser) optionalText(name string) string {
	v, _ := p.value(name)
	return v
}

func (p *parser) optionalSecret(name string, minLen int) secret.String {
	v, ok := p.value(name)
	if !ok {
		return secret.String{}
	}
	if len(v) < minLen {
		// The value itself is never quoted back into the error.
		p.fail(name, "is %d characters; the minimum is %d", len(v), minLen)
		return secret.String{}
	}
	return secret.New(v)
}

func (p *parser) optionalLevel(name string) slog.Level {
	v, ok := p.value(name)
	if !ok {
		return slog.LevelInfo
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(v)); err != nil {
		p.fail(name, "%q is not one of debug, info, warn, error", v)
		return slog.LevelInfo
	}
	return level
}
