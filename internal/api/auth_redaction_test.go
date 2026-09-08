package api

import (
	"bytes"
	"context"
	"log/slog"
	"strconv"
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

	// Distinctive, and deliberately not 0 or 1: a generation left at its zero
	// value cannot tell a working LogValue from one returning a constant.
	const generation = 37
	auth.generation.Store(generation)

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

	assertNoSecretInRecord(t, record, map[string]string{
		"sessionSecret":     sessionSecret,
		"generatedPassword": generated,
	})

	// THE VALUES, not the key names. Asserting that "umbrel_managed" and
	// "session_generation" merely APPEAR is satisfied by two constants —
	// slog.Bool("umbrel_managed", true) and slog.Int64("session_generation", 0)
	// would pass it while reporting the same thing on every install. That is the
	// weakness BrollyZap-0vk.47 fixed one type over, and leaving its neighbour
	// holding it would have made this file teach the weaker shape.
	//
	// This Auth has NO AppPassword and a generation moved off its zero value.
	// That pins session_generation away from any constant, but it pins
	// umbrel_managed only against a constant TRUE — a LogValue hardcoding FALSE
	// passes everything here. TestAnUmbrelManagedAuthReportsItself below is the
	// other half, and the PAIR is what makes the field's input matter; neither
	// test is sufficient alone.
	//
	// AuthOptions' own test does not cover this. It pins the fact on the options
	// struct, a different type with a different LogValue — Auth reads its own
	// umbrelManaged field, set once in NewAuth.
	for _, want := range []string{
		`"umbrel_managed":false`,
		`"session_generation":` + strconv.FormatInt(generation, 10),
	} {
		if !strings.Contains(record, want) {
			t.Errorf("the redacted Auth does not report %s, which is what an operator "+
				"debugging a login actually needs — and a summary that says the same thing "+
				"on every install is worse than one that says nothing:\n%s", want, record)
		}
	}
}

// The managed half of the pair above: an Auth built WITH an app password says
// so (BrollyZap-0vk.47).
//
// WHY A SECOND FIXTURE AND NOT A SECOND ASSERTION. umbrelManaged is set once,
// in NewAuth, from whether AuthOptions carried an AppPassword — so the only way
// to exercise the true direction is to build a second Auth. Without it a
// LogValue hardcoding `slog.Bool("umbrel_managed", false)` passes the whole
// package: the neighbouring test asserts exactly false, and no other test looks
// at the value at all. Verified by planting that constant.
//
// THE SECRETS DIFFER FROM THE NEIGHBOUR'S, and that is the fixture, not
// decoration. With an app password supplied NewAuth does not bootstrap one, so
// there is no generatedPassword here; the credential at risk is the app
// password itself, and it is the one asserted absent.
func TestAnUmbrelManagedAuthReportsItself(t *testing.T) {
	t.Parallel()

	const (
		appPassword   = "app-password-sentinel-0vk47-auth"
		sessionSecret = "session-secret-sentinel-0vk47-auth"
	)

	auth, err := NewAuth(t.Context(), &fakeSettings{}, AuthOptions{
		AppPassword:   secret.New(appPassword),
		SessionSecret: secret.New(sessionSecret),
	})
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	// NewAuth is what decides the fact under test, so it is worth knowing it
	// decided rather than defaulted: a bootstrap path that ignored AppPassword
	// would leave this false and the assertion below would read as a LogValue
	// bug when it was a constructor one.
	if !auth.umbrelManaged {
		t.Fatal("NewAuth did not record an app password as Umbrel-managed; this test would " +
			"be asserting over the wrong state")
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("auth", "auth", auth)
	record := buf.String()

	assertNoSecretInRecord(t, record, map[string]string{
		"appPassword":   appPassword,
		"sessionSecret": sessionSecret,
	})

	if want := `"umbrel_managed":true`; !strings.Contains(record, want) {
		t.Errorf("an Umbrel-managed Auth does not report %s. An operator debugging a login "+
			"is told this install manages its own password when it does not:\n%s", want, record)
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

// §12, the per-type half for AuthOptions: that the one fact it emits is TRUE,
// not merely present (BrollyZap-0vk.47).
//
// WHY THIS EXISTS WHEN THE REDACTION TABLE ALREADY COVERS api.AuthOptions.
// The table (internal/logging) asserts no secret bytes escape, and does it more
// thoroughly than this test does — four levels, both slog call shapes. That is
// a different question from whether the summary is ACCURATE, and the gap is
// demonstrable: flipping the negation in AuthOptions.LogValue leaves
// `go test ./...` green. A summary reporting the opposite of the truth leaks
// nothing and misleads every operator who reads it. config.Server got this
// assertion in 0vk.33 and api.Auth in 0vk.36; AuthOptions had neither.
//
// NO //redaction:covers MARKER, deliberately. The completeness rule takes the
// table entry first and never reaches a marker for a type that has one, so a
// marker here would assert coverage it is not providing — and would silently
// become the only coverage if the table entry were ever removed as duplicative.
// The entry is the coverage; this is the facts.
//
// WHY BOTH DIRECTIONS. umbrel_managed is a boolean, so a test pinning only the
// true case also passes against `slog.Bool("umbrel_managed", true)` — a
// constant. Asserting both is what makes the field's INPUT matter, and the pair
// is what the flipped negation cannot satisfy.
func TestAuthOptionsLogValueRedactsBothSecretsAndKeepsTheFacts(t *testing.T) {
	t.Parallel()

	// Distinctive, and not shared with the redaction table's own sentinels: a
	// value appearing nowhere else cannot be matched by accident. Plain ASCII,
	// so JSON encoding is the identity function and "absent from the bytes" is
	// the whole question rather than half of it.
	const (
		appPassword   = "app-password-sentinel-0vk47"
		sessionSecret = "session-secret-sentinel-0vk47"
	)

	for _, tc := range []struct {
		name        string
		options     AuthOptions
		wantManaged bool
		// The secrets this case's fixture carries. The not-managed case carries
		// one, which is that case's point: there is no app password to leak
		// because there is none at all.
		//
		// NO FIXTURE-CARRIES GUARD beside this, where config.Server and api.Auth
		// both have one. Theirs read the secret back out of a value some
		// CONSTRUCTOR produced — LoadServer, NewAuth — which can stop carrying
		// it. This literal is the fixture, so a read-back would only prove
		// secret.New and Reveal round-trip, which is the secret package's own
		// test. What guards this pair against going vacuous is wantManaged:
		// delete AppPassword from the managed case and that assertion fails.
		secrets map[string]string
	}{
		{
			name: "an app password from Umbrel is reported as managed",
			options: AuthOptions{
				AppPassword:   secret.New(appPassword),
				SessionSecret: secret.New(sessionSecret),
			},
			wantManaged: true,
			secrets:     map[string]string{"AppPassword": appPassword, "SessionSecret": sessionSecret},
		},
		{
			name:        "no app password is reported as not managed",
			options:     AuthOptions{SessionSecret: secret.New(sessionSecret)},
			wantManaged: false,
			secrets:     map[string]string{"SessionSecret": sessionSecret},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&buf, nil))
			log.Info("auth options", "options", tc.options)
			record := buf.String()

			assertNoSecretInRecord(t, record, tc.secrets)

			// The fact itself. slog's JSON handler renders a bool unquoted, so
			// this separates true from false without parsing.
			want := `"umbrel_managed":` + strconv.FormatBool(tc.wantManaged)
			if !strings.Contains(record, want) {
				t.Errorf("the redacted AuthOptions do not report %s. An operator reading this "+
					"line is told the opposite of the truth, which is worse than silence:\n%s",
					want, record)
			}
		})
	}
}

// assertNoSecretInRecord fails for every secret whose value appears in the
// rendered log line, naming the field and MASKING the value.
//
// The masking is the reason this is a helper rather than three copies: a test
// that proves a secret escaped by printing it again into CI output has not
// finished the job, and that policy should be stated once. Both tests in this
// file had the loop verbatim, comment included.
func assertNoSecretInRecord(t *testing.T, record string, secrets map[string]string) {
	t.Helper()
	for name, value := range secrets {
		if !strings.Contains(record, value) {
			continue
		}
		t.Errorf("the logged value carries %s; §11 and §12 say it must not. Record, with "+
			"the value masked:\n%s", name,
			strings.ReplaceAll(record, value, "<"+name+">"))
	}
}
