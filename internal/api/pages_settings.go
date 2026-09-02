package api

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/wallet"
	"github.com/davotoula/brollyzapper/internal/web"
)

// settingsForm are the keys the Settings page owns. Everything here is read
// back into the form and written on save; a key in one list and not the other
// is a field that silently discards what the operator typed.
var settingsForm = []string{
	SettingDomain,
	SettingAddressName,
	SettingTrustedProxies,
	SettingLogLevel,
	SettingPublicRateLimitMinute,
	SettingPublicRateLimitHour,
	SettingMaxFeePPM,
	SettingMaxFeeFloorMsat,
	SettingRelays,
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data, values, _ := s.page(ctx, "Settings")
	credit, _ := s.Wallet.CreditReceived(ctx)
	data.Settings = web.SettingsView{
		Domain: values.get(SettingDomain),
		AdvertisedOrigin: lnurl.BaseURL(values.get(SettingDomain),
			values.get(SettingDomainInsecure) == "true"),
		AddressName:              values.get(SettingAddressName),
		TrustedProxies:           values.get(SettingTrustedProxies),
		LogLevel:                 s.logLevelChoice(values.get(SettingLogLevel)),
		PublicRateLimitPerMinute: values.int(SettingPublicRateLimitMinute, DefaultGlobalBackstopPerMinute),
		PublicRateLimitPerHour:   values.int(SettingPublicRateLimitHour, DefaultGlobalBackstopPerHour),
		MaxFeePPM:                values.int(SettingMaxFeePPM, wallet.DefaultMaxFeePPM),
		Relays:                   values.get(SettingRelays),
		NostrPubkey:              values.get(SettingNostrPubkey),
		MaxFeeFloorMsat:          values.int(SettingMaxFeeFloorMsat, wallet.DefaultMaxFeeFloorMsat),
		CreditReceived:           credit,
		PasswordChangeable:       s.Auth.PasswordChangeable(),
		ProbeOK:                  values.get(SettingProbeOK) == "true",
		ProbeReason:              values.get(SettingProbeReason),
		ProbeAt:                  values.get(SettingProbeAt),
	}
	data.Flash = flashFrom(r)
	s.render(w, "settings", data)
}

// logLevelChoice is the option the Settings page shows as selected, and it is
// ALWAYS one of the four settings.html offers. That guarantee is the fix, not a
// nicety (BrollyZap-497).
//
// settings.html marks an option selected only when it equals this value, so any
// value outside that list selects nothing — and a select with nothing selected
// is not neutral: the browser submits its FIRST option, which is "debug".
// Observed on the box during the 0.1.17 fresh-install trip, where the row was
// simply absent: setting the domain and the address name requires saving that
// form, so a first-time operator wrote log_level=debug without touching the
// control, on paths that are publicly reachable and at the level OPERATING.md
// tells them to turn back off.
//
// THE FALLBACK IS THE LEVEL IN FORCE, NOT A CONSTANT. "info" hardcoded would
// fix the fresh install and break its mirror image: a deployment running with
// LOG_LEVEL=debug set deliberately would render "info" and have its first Save
// turn its own logging down, silently, which is the same bug pointing the other
// way. Precedence is untouched — a stored setting still overrides the
// environment — only the starting point for an ABSENT setting moved.
//
// IT PARSES RATHER THAN COMPARES for the same reason. saveSettings stores what
// was posted, trimmed and otherwise unvalidated, so "INFO", " warn " and
// "info+2" are all reachable rows that match no option and land on debug
// exactly as the empty row did. Fixing only the empty case would leave 497
// one input away.
func (s *Server) logLevelChoice(stored string) string {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.TrimSpace(stored))); err != nil {
		// Includes the empty row, which is what a fresh install has.
		level = s.levelInForce()
	}
	return levelOption(level)
}

// levelInForce is the running level. Nil is not a production shape — the
// binaries always wire the LevelVar — but a settings page that panicked on it
// would turn a wiring mistake into a dead admin surface, and slog's own zero
// LevelVar is INFO, so that is the honest answer rather than an invented one.
func (s *Server) levelInForce() slog.Level {
	if s.Level == nil {
		return slog.LevelInfo
	}
	return s.Level.Level()
}

// levelOption maps any level onto the nearest option settings.html offers.
//
// By threshold rather than by name: slog renders an offset level as "INFO+2",
// which lowercases to a string no option matches, and matching nothing is the
// defect this whole function exists to remove. Rounding down to the enclosing
// named level can lower an offset level by a step on the next Save; landing on
// debug would raise it, which is the direction that matters.
func levelOption(level slog.Level) string {
	switch {
	case level < slog.LevelInfo:
		return "debug"
	case level < slog.LevelWarn:
		return "info"
	case level < slog.LevelError:
		return "warn"
	default:
		return "error"
	}
}

// saveDomain normalises what the operator pasted and returns the bare
// host[:port] to store (o34.13).
//
// https://zap.example.com is the natural thing to paste, and stored verbatim it
// made the identifier name@https://zap.example.com and the description_hash a
// number no wallet reproduces — §16's silent failure, on the first day of real
// use.
//
// The scheme is kept in its own row because the identifier must not carry one
// and a LAN setup must still be able to say http. A paste with NO scheme leaves
// that row ALONE: the field renders the bare host, so opening Settings and
// pressing Save on an unchanged LAN address must not quietly promote it to
// https and break the very setup it was typed for.
func (s *Server) saveDomain(ctx context.Context, pasted string) string {
	host, scheme := lnurl.NormaliseDomain(pasted)
	setScheme := func(insecure bool) {
		if err := s.Settings.SetSetting(ctx, SettingDomainInsecure,
			strconv.FormatBool(insecure)); err != nil {
			s.Log.Error("saving the domain scheme", "error", err.Error())
		}
	}
	if scheme != "" {
		setScheme(scheme == "http")
		return host
	}
	// No scheme pasted. o34.13's round-trip rule says leave the flag alone,
	// because the field renders the bare host and a no-op Save must not promote
	// a LAN setup to https. That rule holds for the SAME host and only for it.
	//
	// A DIFFERENT host is not a no-op Save (vz1.7). The box moved from a LAN
	// address to a public hostname by pasting the bare host, inherited
	// insecure=true from the LAN era, and advertised an http:// callback for an
	// https address. Everything looked right while it was wrong.
	//
	// Secure is the safe default to land on: a public hostname that really is
	// plain HTTP is a LAN-shaped setup, and saying so explicitly costs one
	// paste of the scheme.
	current, _, err := s.Settings.Setting(ctx, SettingDomain)
	if err != nil {
		s.Log.Error("reading the current domain", "error", err.Error())
		return host
	}
	// BOTH sides normalised, and this is not tidiness. The stored row is bare
	// only on a box saved since o34.13; one configured before it still holds
	// "http://192.168.77.42:3033", and that row is not migrated until vz1.5.
	// Comparing the raw row against the normalised paste made a genuine no-op
	// Save look like a host change on exactly those boxes, and reset the flag —
	// promoting a LAN setup to https, which is the regression o34.13's
	// round-trip rule exists to prevent.
	stored, _ := lnurl.NormaliseDomain(current)
	if stored != host {
		setScheme(false)
	}
	return host
}

func (s *Server) saveSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Reject a bad CIDR list before storing it: this value gates which
	// forwarded-for headers are believed (§7), and a silently-ignored one would
	// leave the operator thinking they had changed a security boundary.
	proxies := strings.TrimSpace(r.PostFormValue(SettingTrustedProxies))
	if _, err := config.ParsePrefixList(proxies); err != nil {
		s.Log.Warn("rejected a trusted-proxies value", "error", err.Error())
		http.Redirect(w, r, "/settings?flash=refused", http.StatusSeeOther)
		return
	}

	for _, key := range settingsForm {
		value := strings.TrimSpace(r.PostFormValue(key))
		if key == SettingDomain {
			value = s.saveDomain(ctx, value)
		}
		if err := s.Settings.SetSetting(ctx, key, value); err != nil {
			s.Log.Error("saving a setting", "key", key, "error", err.Error())
			continue
		}
		s.auditRequest(r, slog.LevelInfo, "setting changed",
			logging.EventSettingChange, slog.String("key", key))
	}
	if err := s.Wallet.SetCreditReceived(ctx, r.PostFormValue("credit_received") != ""); err != nil {
		s.Log.Error("saving credit_received", "error", err.Error())
	}

	// §12: LOG_LEVEL applies without a restart. Persisting the row is not
	// enough — the running LevelVar has to move too, or the promise is only
	// true of the next start.
	s.applyLogLevel(r, r.PostFormValue(SettingLogLevel))

	// The next read must see what was just written, including the proxy list
	// the limiter keys on.
	s.settings.invalidate()
	s.demandProbe()
	http.Redirect(w, r, "/settings?flash=saved", http.StatusSeeOther)
}

// importNostrKey replaces the server's nostr identity with an operator-supplied
// key (o34.1).
//
// A separate form from the rest of Settings because it is not a setting: it
// changes the identity every zap receipt is signed with and every LNURL
// response announces, so it should not ride along with a domain edit.
func (s *Server) importNostrKey(w http.ResponseWriter, r *http.Request) {
	key := secret.New(strings.TrimSpace(r.PostFormValue("nostr_key")))
	if key.IsZero() {
		http.Redirect(w, r, "/settings?flash=refused", http.StatusSeeOther)
		return
	}
	identity, err := nostr.Import(r.Context(), s.Settings, key)
	if err != nil {
		// The error is deliberately not shown: go-nostr's parse errors can
		// quote the key they were handed, and §12 says it must not reach a log
		// or a page.
		s.Log.Warn("rejected a nostr identity key")
		http.Redirect(w, r, "/settings?flash=refused", http.StatusSeeOther)
		return
	}
	s.auditRequest(r, slog.LevelInfo, "the nostr identity key was replaced",
		logging.EventSettingChange, slog.String("pubkey", identity.PublicKey()))
	s.settings.invalidate()
	s.demandProbe()
	http.Redirect(w, r, "/settings?flash=saved", http.StatusSeeOther)
}

func (s *Server) applyLogLevel(r *http.Request, raw string) {
	if s.Level == nil || strings.TrimSpace(raw) == "" {
		return
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.TrimSpace(raw))); err != nil {
		s.Log.Warn("ignoring an unreadable log level", "value", raw)
		return
	}
	s.Level.Set(level)
	s.auditRequest(r, slog.LevelInfo, "log level changed",
		logging.EventSettingChange, slog.String("level", level.String()))
}

func (s *Server) probeNow(w http.ResponseWriter, r *http.Request) {
	s.demandProbe()
	http.Redirect(w, r, "/settings?flash=saved", http.StatusSeeOther)
}

// demandProbe asks for an out-of-schedule self-probe: §9 wants it hourly and on
// demand.
func (s *Server) demandProbe() { nudge(s.ProbeDemand) }

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	err := s.Auth.ChangePassword(r.Context(),
		secret.New(r.PostFormValue("current")), secret.New(r.PostFormValue("new")))
	if err != nil {
		s.auditRequest(r, slog.LevelWarn, "password change refused",
			logging.EventAuthFail, slog.String("error", err.Error()))
		http.Redirect(w, r, "/settings?flash=refused", http.StatusSeeOther)
		return
	}
	s.auditRequest(r, slog.LevelInfo, "admin password changed", logging.EventSettingChange)
	http.Redirect(w, r, "/settings?flash=saved", http.StatusSeeOther)
}

// flashFrom turns the redirect marker into the one-line result the layout
// shows. Kept to a fixed vocabulary so nothing a caller supplies is rendered.
// flashMessages is every outcome a handler may redirect with.
//
// A MAP rather than a switch, so the set can be asserted: a handler that
// redirects with a marker nobody translated renders a blank message, which is a
// page that says nothing happened when something did. Found by review — d24.5's
// two pages arrived with eight markers and none of them rendered, including both
// of the guard failures the Sending page exists to report.
var flashMessages = map[string]string{
	"saved":   "Saved.",
	"refused": "That change was refused — see the log for why.",
	"signed-out": "Signed out. That ended every session, on every device — " +
		"anyone still signed in elsewhere has to sign in again.",

	// Sending (§9 item 3).
	"enabled": "Sending is on. A spend macaroon has been baked, locked to this container " +
		"and set to expire on its own.",
	"disabled": "Sending is off and the macaroon has been revoked — your node will refuse it " +
		"from now on.",
	"bake_failed": "The guard could not bake a spend macaroon, so sending has NOT been " +
		"enabled and nothing has changed. Check that the guard is running.",
	"revoke_failed": "Sending is now off, so this app will refuse payments — but the guard " +
		"could not tell your node to stop honouring the macaroon. It is still valid at the " +
		"node. Try again once the guard is answering.",

	// The operator's ceremony (`06v`). Every one of these is a step in a
	// sequence, so each says what to do NEXT rather than only what happened — a
	// person halfway through a two-place task needs the next place named.
	"authorisation_written": "A confirmation code has been written where only you can read it. " +
		"Open the file, check it is asking for what you asked for, and type the code below.",
	"code_refused": "That code was not accepted, so nothing has changed. It may be mistyped, " +
		"expired, already used, or written for a different change — ask for a new one and " +
		"read what the file says before typing it.",
	"cap_changed": "Saved. Your node enforces the new limit from the next payment.",
	"cap_invalid": "A limit has to be a whole number of sats, and cannot be negative. Nothing " +
		"has been changed.",

	// Connections (§9 item 4).
	"created": "Connection created. Pair it with the code below — it is the only thing that " +
		"app needs, so treat it like a password.",
	"revoked": "Connection revoked. That pairing stops working immediately.",
	"resumed": "Connection re-enabled. It is being served again, with its panic count back " +
		"at zero — if the app that owns it still sends requests this one cannot handle, it " +
		"will be paused again.",
	"updated": "Saved. This connection's new limits are in force now — the app stays paired " +
		"and does not need to be set up again.",
	"conflicting_limits": "You ticked \u201cNo limits\u201d and also typed a limit, which are " +
		"opposite instructions. Nothing was changed \u2014 clear the boxes to remove the limits, " +
		"or untick No limits to use the numbers you typed.",
	"nothing_to_update": "Nothing was changed — that connection is revoked, or no longer exists.",
	"nothing_to_revoke": "Nothing was revoked — that connection is already revoked, or no " +
		"longer exists.",
	"nothing_to_resume": "Nothing was changed — that connection is not paused, or no longer " +
		"exists.",
	"name_required":  "A connection needs a name, so you can tell it from the others later.",
	"relay_required": "A connection needs at least one relay — the ones the wallet app will use.",
	"too_many_relays": "That is more relays than one pairing may name. Three is the limit: " +
		"each one is a socket this app holds open for as long as the pairing lasts.",
	"bad_amount": "A budget and a per-payment cap have to be whole numbers of sats, above " +
		"zero. Leave a field empty to take the default, or tick the unlimited box.",
	"bad_relay": "That does not look like a relay address. It should start with wss:// " +
		"(or ws:// on your own network).",
}

func flashFrom(r *http.Request) string { return FlashMessage(r.URL.Query().Get("flash")) }

// FlashMessage is the operator-facing text for one redirect marker, or empty if
// there is none. Exported so the rule that every marker has one can ask.
func FlashMessage(marker string) string { return flashMessages[marker] }
