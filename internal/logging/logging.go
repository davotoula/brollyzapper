package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
)

// identifierPrefix is how much of a hash or key is kept in a log line. §12:
// truncate identifiers rather than dropping them — enough to correlate, useless
// to an attacker.
const identifierPrefix = 8

// NewLevelVar returns the level holder the handler reads on every record, so
// LOG_LEVEL can change at runtime without a restart (spec §12, §19).
func NewLevelVar(level slog.Level) *slog.LevelVar {
	lv := new(slog.LevelVar)
	lv.Set(level)
	return lv
}

// New builds the application logger. The destination is a parameter and the
// binaries pass os.Stdout: §12 says stdout only, and that the app must not
// manage log files or rotation itself.
func New(w io.Writer, level *slog.LevelVar) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// Default is the process-wide logger, for the components that accept one and
// have to do something sensible when a caller passes nil.
//
// It exists so that "slog.Default()" appears in exactly one package. That is a
// rule with a test behind it, and the reason is Wave 16: the relay pool fell
// back to slog's default, which is plain text on stderr and deaf to LOG_LEVEL,
// so its one log line violated §12 in production while every test passed —
// each test having supplied its own logger. cliboot.Start now calls
// slog.SetDefault at boot, which is what makes this answer the right one.
//
// A nil logger is still a wiring mistake. This keeps it from also being a
// silent change of destination.
func Default() *slog.Logger { return slog.Default() }

// PaymentHash is the correlation key that joins an LNURL request, the invoice
// settlement minutes later, and every relay publish after that (spec §12).
func PaymentHash(hash string) slog.Attr {
	return slog.String("payment_hash", truncate(hash))
}

// RequestID labels one inbound HTTP or NWC request.
func RequestID(id string) slog.Attr { return slog.String("req_id", id) }

// Short truncates an identifier for logging — a pubkey, an event id.
func Short(id string) string { return truncate(id) }

func truncate(id string) string {
	if len(id) <= identifierPrefix {
		return id
	}
	return id[:identifierPrefix]
}

type contextKey struct{}

// WithRequestID mints a request id, attaches a logger carrying it to the
// context, and returns both. Handlers pass the context down; everything below
// logs through FromContext and the id comes along.
func WithRequestID(ctx context.Context, log *slog.Logger) (context.Context, string) {
	id := newRequestID()
	return context.WithValue(ctx, contextKey{}, log.With(RequestID(id))), id
}

// ContextWithLogger attaches a logger to ctx.
func ContextWithLogger(ctx context.Context, log *slog.Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, log)
}

// FromContext returns the request-scoped logger, or the default one when there
// is no request in play.
//
// LoggerOr with Default() as the fallback, rather than its own copy of the
// lookup: the two differ only in what they fall back to, and a second reader of
// contextKey would be a second place to change if what is stored ever does.
func FromContext(ctx context.Context) *slog.Logger { return LoggerOr(ctx, Default()) }

// LoggerOr returns the context's logger, or `fallback` when nothing attached
// one — FromContext for a component that already HAS a logger of its own (et8).
//
// The difference from FromContext is the whole point. FromContext falls back to
// slog.Default(), which is right for a handler whose only logger IS the
// request's, and wrong for a long-lived component: the pool writes through the
// logger it was built with, and switching it to FromContext would send every
// publish with no request in play to the process-wide default instead — silently
// dropping the pool's own handler, and with it every test that captures its
// output.
//
// It exists so that a caller who KNOWS which zap this publish is for can say so
// on the lines the pool writes, without the pool having to learn about zaps.
// A nil logger STORED on the context falls back too (go-review). The type
// assertion succeeds for a typed nil, so without the second test this would hand
// back a *slog.Logger that panics at the first call — a wiring mistake turned
// into a crash in the pool, some publishes later, far from the attach. Default's
// doc states the package's preference: a nil logger is a mistake, and it should
// not also be a change of destination.
func LoggerOr(ctx context.Context, fallback *slog.Logger) *slog.Logger {
	if log, ok := ctx.Value(contextKey{}).(*slog.Logger); ok && log != nil {
		return log
	}
	return fallback
}

func newRequestID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail in practice; a correlation id is not worth
		// a panic if it ever does.
		return "00000000"
	}
	return hex.EncodeToString(b[:])
}
