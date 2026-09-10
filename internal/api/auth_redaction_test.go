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

	// A supplied password and an UNMANAGED deployment — the plain-Docker case,
	// and the one that pins umbrel_managed against a hardcoded true below.
	//
	// It carried a second secret until `20i.5`: an Auth built with no password
	// invented one and kept it in generatedPassword, and this test watched that
	// field too. There is no such field now — the app refuses to start rather
	// than invent a credential nobody can read — so sessionSecret is the only
	// secret Auth holds, and it is the whole of what must not reach a log.
	const adminPassword = "app-password-sentinel-20i5-unmanaged"
	auth, err := NewAuth(t.Context(), &fakeSettings{}, AuthOptions{
		AdminPassword: secret.New(adminPassword),
		SessionSecret: secret.New(sessionSecret),
	})
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	// The fact under test is decided by NewAuth, so it is worth knowing it was
	// decided rather than defaulted — the mirror of the managed test below.
	if auth.passwordManaged {
		t.Fatal("NewAuth recorded an unmanaged deployment as managed; this test would be " +
			"asserting over the wrong state")
	}

	// The fixture must actually carry both secrets, or everything below is a test
	// of a value that had nothing to leak.
	if got := auth.sessionSecret.Reveal(); got != sessionSecret {
		t.Fatalf("the Auth under test does not hold the session secret this test looks for; "+
			"everything below would pass vacuously (got %q)", got)
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
		"sessionSecret": sessionSecret,
		"adminPassword": adminPassword,
	})

	// THE VALUES, not the key names. Asserting that "umbrel_managed" and
	// "session_generation" merely APPEAR is satisfied by two constants —
	// slog.Bool("umbrel_managed", true) and slog.Int64("session_generation", 0)
	// would pass it while reporting the same thing on every install. That is the
	// weakness BrollyZap-0vk.47 fixed one type over, and leaving its neighbour
	// holding it would have made this file teach the weaker shape.
	//
	// This Auth is UNMANAGED and its generation is moved off its zero value.
	// That pins session_generation away from any constant, but it pins
	// umbrel_managed only against a constant TRUE — a LogValue hardcoding FALSE
	// passes everything here. TestAnUmbrelManagedAuthReportsItself below is the
	// other half, and the PAIR is what makes the field's input matter; neither
	// test is sufficient alone.
	//
	// SINCE `20i.5` THE PAIR IS SHARPER THAN IT WAS. Both fixtures now supply a
	// password and differ only in the flag, so a LogValue — or a NewAuth — that
	// went back to inferring the fact from the password being set would fail
	// here rather than pass both halves.
	//
	// AuthOptions' own test does not cover this. It pins the fact on the options
	// struct, a different type with a different LogValue — Auth reads its own
	// passwordManaged field, set once in NewAuth.
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

// The managed half of the pair above: an Auth built with the deployment's
// managed flag says so (BrollyZap-0vk.47, and `20i.5` for what decides it).
//
// WHY A SECOND FIXTURE AND NOT A SECOND ASSERTION. passwordManaged is set once,
// in NewAuth, from AuthOptions.PasswordManaged — so the only way to exercise the
// true direction is to build a second Auth. Without it a LogValue hardcoding
// `slog.Bool("umbrel_managed", false)` passes the whole package: the
// neighbouring test asserts exactly false, and no other test looks at the value
// at all. Verified by planting that constant.
//
// THE ONLY DIFFERENCE FROM THE NEIGHBOUR IS THE FLAG, and that is the fixture
// rather than decoration. Both supply the same kind of credential, so a NewAuth
// that went back to inferring the fact from a password being present — which is
// what `20i.5` removed — reports true for both and fails the neighbour.
func TestAnUmbrelManagedAuthReportsItself(t *testing.T) {
	t.Parallel()

	const (
		adminPassword = "app-password-sentinel-0vk47-auth"
		sessionSecret = "session-secret-sentinel-0vk47-auth"
	)

	auth, err := NewAuth(t.Context(), &fakeSettings{}, AuthOptions{
		AdminPassword:   secret.New(adminPassword),
		PasswordManaged: true,
		SessionSecret:   secret.New(sessionSecret),
	})
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	// NewAuth is what decides the fact under test, so it is worth knowing it
	// decided rather than defaulted: a constructor that dropped PasswordManaged
	// would leave this false and the assertion below would read as a LogValue
	// bug when it was a constructor one.
	if !auth.passwordManaged {
		t.Fatal("NewAuth did not record the deployment's managed flag; this test would " +
			"be asserting over the wrong state")
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("auth", "auth", auth)
	record := buf.String()

	assertNoSecretInRecord(t, record, map[string]string{
		"adminPassword": adminPassword,
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
		adminPassword = "app-password-sentinel-0vk47"
		sessionSecret = "session-secret-sentinel-0vk47"
	)

	for _, tc := range []struct {
		name        string
		options     AuthOptions
		wantManaged bool
		// The secrets this case's fixture carries. BOTH CASES CARRY BOTH since
		// `20i.5`, and that is the whole strength of the pair now: the two
		// fixtures are identical except for PasswordManaged, so a LogValue that
		// went back to inferring the fact from AdminPassword being set — which is
		// what this field used to do, and what denied every plain-Docker
		// operator a password change — reports `true` for both and fails the
		// second case.
		//
		// NO FIXTURE-CARRIES GUARD beside this, where config.Server and api.Auth
		// both have one. Theirs read the secret back out of a value some
		// CONSTRUCTOR produced — LoadServer, NewAuth — which can stop carrying
		// it. This literal is the fixture, so a read-back would only prove
		// secret.New and Reveal round-trip, which is the secret package's own
		// test. What guards this pair against going vacuous is wantManaged
		// differing across two otherwise identical fixtures.
		secrets map[string]string
	}{
		{
			name: "a platform-managed password is reported as managed",
			options: AuthOptions{
				AdminPassword:   secret.New(adminPassword),
				PasswordManaged: true,
				SessionSecret:   secret.New(sessionSecret),
			},
			wantManaged: true,
			secrets:     map[string]string{"AdminPassword": adminPassword, "SessionSecret": sessionSecret},
		},
		{
			// The SAME password, unmanaged. This is a plain-Docker install whose
			// operator typed it into .env: nobody else displays that value, so
			// they may change it.
			name: "the same password without the flag is reported as not managed",
			options: AuthOptions{
				AdminPassword: secret.New(adminPassword),
				SessionSecret: secret.New(sessionSecret),
			},
			wantManaged: false,
			secrets:     map[string]string{"AdminPassword": adminPassword, "SessionSecret": sessionSecret},
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
