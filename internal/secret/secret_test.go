package secret_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// sentinel is deliberately distinctive so a leak is unambiguous (spec §13).
const sentinel = "s3ntinel-must-never-be-logged-9f3a1c"

func TestStringNeverRendersItsValue(t *testing.T) {
	s := secret.New(sentinel)
	holder := struct {
		Name     string
		Password secret.String
	}{Name: "admin", Password: s}

	renderings := map[string]string{
		"String()":         s.String(),
		"%v":               fmt.Sprintf("%v", s),
		"%s":               fmt.Sprintf("%s", s),
		"%q":               fmt.Sprintf("%q", s),
		"%+v":              fmt.Sprintf("%+v", s),
		"%#v":              fmt.Sprintf("%#v", s),
		"%v of pointer":    fmt.Sprintf("%v", &s),
		"%+v of struct":    fmt.Sprintf("%+v", holder),
		"%#v of struct":    fmt.Sprintf("%#v", holder),
		"json.Marshal":     mustJSON(t, s),
		"json.Marshal ptr": mustJSON(t, &s),
		"json of struct":   mustJSON(t, holder),
		"slog.Any json":    logged(t, jsonHandler, slog.Any("secret", s)),
		"slog.Any text":    logged(t, textHandler, slog.Any("secret", s)),
		"slog.Any pointer": logged(t, jsonHandler, slog.Any("secret", &s)),
		"slog struct json": logged(t, jsonHandler, slog.Any("config", holder)),
		"slog struct text": logged(t, textHandler, slog.Any("config", holder)),
	}

	for name, got := range renderings {
		if strings.Contains(got, sentinel) {
			t.Errorf("%s leaked the secret: %s", name, got)
		}
		if !strings.Contains(got, secret.Redacted) {
			t.Errorf("%s = %s, want it to contain %q", name, got, secret.Redacted)
		}
	}
}

func TestRevealReturnsTheValue(t *testing.T) {
	if got := secret.New(sentinel).Reveal(); got != sentinel {
		t.Errorf("Reveal() = %q, want %q", got, sentinel)
	}
}

func TestZeroValueIsEmptyAndSafe(t *testing.T) {
	var s secret.String
	if !s.IsZero() {
		t.Error("zero String().IsZero() = false, want true")
	}
	if got := s.Reveal(); got != "" {
		t.Errorf("zero String().Reveal() = %q, want empty", got)
	}
	if got := s.String(); got != secret.Redacted {
		t.Errorf("zero String().String() = %q, want %q — an empty secret must not "+
			"be distinguishable from a set one in a log line", got, secret.Redacted)
	}
	if secret.New("x").IsZero() {
		t.Error("New(\"x\").IsZero() = true, want false")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		// A marshal error is an acceptable outcome — it cannot leak — but the
		// message itself must not carry the secret.
		return err.Error()
	}
	return string(b)
}

func jsonHandler(w io.Writer, o *slog.HandlerOptions) slog.Handler { return slog.NewJSONHandler(w, o) }

func textHandler(w io.Writer, o *slog.HandlerOptions) slog.Handler { return slog.NewTextHandler(w, o) }

// logged renders one attribute through the given handler. Both handlers are
// exercised because they redact by different routes: JSON through MarshalJSON,
// text through fmt's %+v and Stringer.
func logged(t *testing.T, handler func(io.Writer, *slog.HandlerOptions) slog.Handler, attr slog.Attr) string {
	t.Helper()
	var buf bytes.Buffer
	slog.New(handler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})).
		LogAttrs(t.Context(), slog.LevelDebug, "message", attr)
	return buf.String()
}
