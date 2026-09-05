package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// Settings keys this package owns.
const (
	SettingAdminPasswordHash = "admin_password_hash"
	SettingSessionSecret     = "session_secret"
	// SettingSessionGeneration is the session revocation counter (d46.28,
	// review L1). It is part of what every session cookie's MAC covers, so
	// bumping it invalidates every cookie ever issued — including copies taken
	// from a browser that is no longer under the operator's control.
	//
	// It lives in settings rather than in memory because SESSION_SECRET is
	// derived deterministically per Umbrel install and therefore survives a
	// restart. Without a persisted counter, not even restarting the app would
	// evict a stolen session.
	SettingSessionGeneration = "session_generation"
)

// SessionLifetime is the ABSOLUTE cap on a login, however actively it is used.
const SessionLifetime = 7 * 24 * time.Hour

// SessionIdleWindow is the sliding half (d46.28, ruled 22 Aug 2026).
//
// A seven-day absolute lifetime with no idle timeout, on an app that can be
// made to spend, is the wrong default: a session left behind on a shared or
// borrowed machine stays live for a week. Twenty-four hours sliding costs an
// operator at most one extra sign-in a day and ends a ridden session by the
// next morning. Both bounds apply — the idle window is what usually bites, and
// the absolute cap is what stops a session that is kept warm living forever.
const SessionIdleWindow = 24 * time.Hour

// argon2id parameters. OWASP's low-memory profile: a Raspberry Pi has to be
// able to run this on every login attempt without swapping.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

// SettingsStore is the narrow slice of the database this package needs.
// Declared here, by the consumer, in the shape internal/lnd and
// internal/logging established.
type SettingsStore interface {
	Setting(ctx context.Context, key string) (string, bool, error)
	SetSetting(ctx context.Context, key, value string) error
}

// AuthOptions configure Auth.
type AuthOptions struct {
	// AppPassword is Umbrel's derived per-install credential. When it is set,
	// the password is Umbrel-managed and not changeable here (§9).
	AppPassword secret.String
	// SessionSecret signs session cookies. Empty means one is generated and
	// persisted, which is what an off-Umbrel deployment needs.
	SessionSecret secret.String
	Now           func() time.Time
}

// LogValue keeps the whole options struct out of a log line (§12). Both fields
// are secret.String and would redact themselves; this is about the struct, which
// otherwise prints as a Go value with two Redacted holes and invites the habit.
func (o AuthOptions) LogValue() slog.Value {
	return slog.GroupValue(slog.Bool("umbrel_managed", !o.AppPassword.IsZero()))
}

// Auth owns the admin credential and the session cookie.
//
// The app has its own auth because Umbrel's packaging rules require the app to
// work as plain Docker outside Umbrel, where app_proxy does not exist, and say
// directly that the reverse proxy must not be the only security boundary (§19).
type Auth struct {
	store         SettingsStore
	sessionSecret secret.String
	now           func() time.Time

	// umbrelManaged records that APP_PASSWORD was set at startup.
	umbrelManaged bool
	// generatedPassword is shown in the browser on first run and nowhere else.
	// §9: a password that exists only in the logs is a failure.
	generatedPassword secret.String

	// generation mirrors SettingSessionGeneration. It is read on every session
	// check, which is every authenticated request, and the database here runs
	// on one connection shared with the invoice stream — so the durable row is
	// the record and this is the copy that is consulted. One process owns both,
	// so they cannot disagree.
	generation atomic.Int64
}

// LogValue keeps the admin credential and the session key out of a log line
// (§12). What an operator debugging a login actually needs is the state, not the
// values: whether the password is Umbrel's, and which session generation is
// current.
func (a *Auth) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("umbrel_managed", a.umbrelManaged),
		slog.Int64("session_generation", a.generation.Load()),
	)
}

// NewAuth loads or bootstraps the admin credential.
func NewAuth(ctx context.Context, store SettingsStore, opts AuthOptions) (*Auth, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	a := &Auth{
		store:         store,
		sessionSecret: opts.SessionSecret,
		now:           now,
		umbrelManaged: !opts.AppPassword.IsZero(),
	}
	if a.sessionSecret.IsZero() {
		persisted, err := a.persistedSessionSecret(ctx)
		if err != nil {
			return nil, err
		}
		a.sessionSecret = persisted
	}
	if err := a.bootstrapPassword(ctx, opts.AppPassword); err != nil {
		return nil, err
	}
	stored, _, err := a.store.Setting(ctx, SettingSessionGeneration)
	if err != nil {
		return nil, err
	}
	generation, err := strconv.ParseInt(stored, 10, 64)
	if err != nil {
		// Absent or unreadable is generation zero: a counter that refused to
		// start would take the whole app down over a row that has never
		// existed on a fresh install.
		generation = 0
	}
	a.generation.Store(generation)
	return a, nil
}

// EndEverySession bumps the revocation counter, so every cookie already issued
// stops authenticating.
//
// Two actions call it: signing out, and changing the password. Both are things
// an operator does when they want a session that is not in front of them to
// stop working.
//
// Two deliberately do NOT, and the next reader will reasonably ask why:
// **Disable sending** and **Revoke now**. Those are what an operator reaches
// for mid-incident, and logging them out in the middle of it — at the exact
// moment they most need the UI — would be worse than the thing they are
// responding to. If either ever needs to end sessions as well, that is a
// decision to take on its own and not a line to add here quietly.
func (a *Auth) EndEverySession(ctx context.Context) error {
	next := a.generation.Add(1)
	if err := a.store.SetSetting(ctx, SettingSessionGeneration,
		strconv.FormatInt(next, 10)); err != nil {
		// The in-memory counter has already moved, so sessions ARE ended for
		// this process; what is lost is that they stay ended across a restart.
		// Reported rather than swallowed, and never rolled back: undoing the
		// bump would revive the sessions the caller just asked to end.
		return fmt.Errorf("persisting the session generation: %w", err)
	}
	return nil
}

// persistedSessionSecret reads the stored signing secret, generating one the
// first time. §10 supplies SESSION_SECRET through derive_entropy on Umbrel;
// off Umbrel there is nobody to derive it, and demanding one by hand would
// fail §19's "setup must not require editing compose" gate.
func (a *Auth) persistedSessionSecret(ctx context.Context) (secret.String, error) {
	stored, ok, err := a.store.Setting(ctx, SettingSessionSecret)
	if err != nil {
		return secret.String{}, err
	}
	if ok && stored != "" {
		return secret.New(stored), nil
	}
	generated := secret.RandomToken(32)
	if err := a.store.SetSetting(ctx, SettingSessionSecret, generated); err != nil {
		return secret.String{}, err
	}
	return secret.New(generated), nil
}

// bootstrapPassword seeds the stored hash if there is none.
//
// §9: APP_PASSWORD seeds it ONLY when no hash exists yet. A later start with a
// different APP_PASSWORD must not reseed — the stored hash is the truth once it
// exists, and reseeding would silently lock the operator out of their own
// changed password.
func (a *Auth) bootstrapPassword(ctx context.Context, appPassword secret.String) error {
	stored, ok, err := a.store.Setting(ctx, SettingAdminPasswordHash)
	if err != nil {
		return err
	}
	if ok && stored != "" {
		return nil
	}
	password := appPassword
	if password.IsZero() {
		// First run with no Umbrel-derived credential: invent one and keep it
		// in memory so Setup can show it in the browser.
		password = secret.New(secret.RandomToken(16))
		a.generatedPassword = password
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return a.store.SetSetting(ctx, SettingAdminPasswordHash, hash)
}

// GeneratedPassword is the password invented on first run, for Setup to render.
// It is zero on every subsequent start and whenever APP_PASSWORD is set.
func (a *Auth) GeneratedPassword() secret.String { return a.generatedPassword }

// PasswordChangeable reports whether Settings may offer a password change.
// False on Umbrel: umbrelOS shows the derived password to the user, so a
// changed one would make that display silently wrong (§9).
func (a *Auth) PasswordChangeable() bool { return !a.umbrelManaged }

// Verify checks a password against the stored hash.
func (a *Auth) Verify(ctx context.Context, password secret.String) bool {
	stored, ok, err := a.store.Setting(ctx, SettingAdminPasswordHash)
	if err != nil || !ok {
		return false
	}
	matched, err := VerifyPassword(stored, password)
	return err == nil && matched
}

// ChangePassword replaces the stored hash after checking the current one.
func (a *Auth) ChangePassword(ctx context.Context, current, replacement secret.String) error {
	if !a.PasswordChangeable() {
		return errors.New("the admin password is managed by Umbrel and cannot be changed here")
	}
	if !a.Verify(ctx, current) {
		return errors.New("the current password is not correct")
	}
	if len(replacement.Reveal()) < 12 {
		return fmt.Errorf("the new password is %d characters; the minimum is 12", len(replacement.Reveal()))
	}
	hash, err := HashPassword(replacement)
	if err != nil {
		return err
	}
	if err := a.store.SetSetting(ctx, SettingAdminPasswordHash, hash); err != nil {
		return err
	}
	a.generatedPassword = secret.String{}
	// Changing the password is one of the two things an operator does when they
	// believe someone else has a session. A new password that left the old
	// sessions running would answer the question they were asking with a no.
	return a.EndEverySession(ctx)
}

// HashPassword returns an argon2id PHC string.
func HashPassword(password secret.String) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating a salt: %w", err)
	}
	key := argon2.IDKey([]byte(password.Reveal()), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against a PHC string, in constant time.
func VerifyPassword(encoded string, password secret.String) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("not an argon2id hash")
	}
	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false, fmt.Errorf("unreadable argon2id parameters: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("unreadable salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("unreadable hash: %w", err)
	}
	// argon2 PANICS rather than erroring on these, so they are checked here
	// (zu5.5). A stored hash with an empty key crashed the login handler with a
	// nil-pointer dereference inside x/crypto — an operator whose settings row
	// was truncated or hand-edited got an opaque 500 on a page whose whole job
	// is to say whether a password is right. Every one of these means the same
	// thing: the stored string is not a credential.
	if len(salt) == 0 || len(want) == 0 {
		return false, fmt.Errorf("argon2id hash has an empty salt or key")
	}
	if iterations < 1 || threads < 1 {
		return false, fmt.Errorf("argon2id parameters are out of range: t=%d, p=%d",
			iterations, threads)
	}
	got := argon2.IDKey([]byte(password.Reveal()), salt, iterations, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func (a *Auth) mac(message string) string {
	h := hmac.New(sha256.New, []byte(a.sessionSecret.Reveal()))
	h.Write([]byte(message))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
