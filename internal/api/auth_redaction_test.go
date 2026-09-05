package api

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// §12, the per-type half for Auth: what its LogValue emits, not merely that it
// exists (BrollyZap-0vk.36).
//
// WHY HERE AND NOT IN internal/logging's redaction table. Auth holds two
// secrets, and one of them — sessionSecret — has no accessor, deliberately: it
// signs cookies and nothing else needs it. The table's entries are built around
// reading each secret back OUT of the value under test, because an entry whose
// fixture has stopped carrying its secret passes however broken the LogValue is
// (three of eight entries were in that state on 2026-09-02). From an external
// test package the only available read-back for sessionSecret is the constant
// that was passed in, which is a second statement and can be wrong in the same
// way twice. An INTERNAL test reads the field.
//
// Auth is also constructed rather than declared — NewAuth(ctx, store, opts) —
// which would have made its table entry the only one needing a database. The
// fake below is the two methods the interface asks for; a real store would add
// sqlite to a test about a log line.
//
//redaction:covers api.Auth
func TestAuthLogValueRedactsBothSecretsAndKeepsTheState(t *testing.T) {
	t.Parallel()

	// Distinctive, and not shared with any other test: a sentinel that appears
	// nowhere else cannot be matched by accident. Plain ASCII, so JSON encoding
	// is the identity function and "absent from the bytes" is the whole question.
	const sessionSecret = "session-secret-sentinel-0vk36"

	// No AppPassword and an empty store, which is what makes Auth invent a
	// password and keep it: generatedPassword is populated on exactly this path
	// (auth.go bootstrapPassword), and it is the second secret under test.
	auth, err := NewAuth(t.Context(), &fakeSettings{}, AuthOptions{
		SessionSecret: secret.New(sessionSecret),
	})
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}

	// The fixture must actually carry both secrets, or everything below is a test
	// of a value that had nothing to leak.
	if got := auth.sessionSecret.Reveal(); got != sessionSecret {
		t.Fatalf("the Auth under test does not hold the session secret this test looks for; "+
			"everything below would pass vacuously (got %q)", got)
	}
	generated := auth.generatedPassword.Reveal()
	if generated == "" {
		t.Fatal("the Auth under test invented no password, so the generatedPassword half of " +
			"this test would pass vacuously; NewAuth's bootstrap path has moved")
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	// ONE call, where the neighbouring per-type tests make two. slog turns a
	// string key followed by a non-Attr value into exactly slog.Any(key, value),
	// so `log.Info("auth", "auth", auth)` and `log.Info("auth", slog.Any(...))`
	// produce byte-identical records — measured 2026-09-05. The pair reads as two
	// paths being covered and is one; writing it here would have taught the next
	// person to copy it.
	log.Info("auth", "auth", auth)
	record := buf.String()

	for _, s := range []struct{ name, value string }{
		{"sessionSecret", sessionSecret},
		{"generatedPassword", generated},
	} {
		if !strings.Contains(record, s.value) {
			continue
		}
		// Masked: a test that proves a secret escaped by printing it again into
		// CI output has not finished the job.
		t.Errorf("a logged Auth carries %s's value; §11 and §12 say it must not. Record, "+
			"with the value masked:\n%s", s.name,
			strings.ReplaceAll(record, s.value, "<"+s.name+">"))
	}

	// Absence alone is satisfied by `return slog.GroupValue()` — a summary that
	// leaks nothing because it says nothing — and that mutation passes every
	// other test in this package. §12 wants the type logged AND redacted, so the
	// facts an operator debugging a login needs are asserted too.
	for _, want := range []string{"umbrel_managed", "session_generation"} {
		if !strings.Contains(record, want) {
			t.Errorf("the redacted Auth says nothing about %s, which is what an operator "+
				"debugging a login actually needs:\n%s", want, record)
		}
	}
}

// fakeSettings is the SettingsStore interface and nothing else. Auth reads and
// writes a handful of keys during NewAuth; none of that is what this test is
// about.
type fakeSettings struct{ values map[string]string }

func (f *fakeSettings) Setting(_ context.Context, key string) (string, bool, error) {
	v, ok := f.values[key]
	return v, ok, nil
}

func (f *fakeSettings) SetSetting(_ context.Context, key, value string) error {
	if f.values == nil {
		f.values = map[string]string{}
	}
	f.values[key] = value
	return nil
}
