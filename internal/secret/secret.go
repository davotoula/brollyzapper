package secret

import (
	"crypto/rand"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
)

// Redacted is what a secret renders as, in every form. It is a fixed string so
// that an operator can grep for it, and so that a set secret is indistinguishable
// from an empty one in the output.
const Redacted = "[redacted]"

// String is a secret carried as text: the admin password, the session secret,
// a nostr private key, an NWC client secret.
//
// The value is unexported and every rendering path is overridden, so the only
// way to obtain it is [String.Reveal] — which is greppable, and which reviewers
// can be asked about. Spec §12: redaction is structural, not disciplinary.
type String struct {
	v string
}

// New wraps a secret value.
func New(v string) String { return String{v: v} }

// Reveal returns the underlying secret. Every call site is a place a secret can
// escape; keep them few and obvious.
func (s String) Reveal() string { return s.v }

// IsZero reports whether no secret was set. Callers use this to distinguish
// "unconfigured" from "configured", which [String.String] deliberately cannot.
func (s String) IsZero() bool { return s.v == "" }

// String implements fmt.Stringer, which covers %v, %s, %q and %+v.
func (s String) String() string { return Redacted }

// GoString implements fmt.GoStringer, which covers %#v — without it, %#v prints
// the struct literal including the unexported field.
func (s String) GoString() string { return "secret.String(" + Redacted + ")" }

// LogValue implements slog.LogValuer, so slog.Any on a secret — or on any struct
// holding one — emits the redacted form (spec §12).
func (s String) LogValue() slog.Value { return slog.StringValue(Redacted) }

// MarshalJSON covers encoding/json, including slog's JSON handler rendering a
// struct that holds a secret.
//
// IT STAYS REDACTING, and the Valuer below is why that is worth saying out loud.
// Both are "serialisation" if you squint, and they are not the same thing: JSON
// is what this app hands to a client and to a log handler, and a database is
// where the value has to be legible to come back at all. A Valuer that also
// leaked through here would be the worst of both, so a test asserts this form is
// still Redacted after the Valuer landed (twt).
func (s String) MarshalJSON() ([]byte, error) { return json.Marshal(Redacted) }

// Value implements driver.Valuer, so a secret can be bound to SQL directly.
//
// THIS IS THE EXPORT SEAM, and it is the one place a secret is revealed without
// a Reveal() call site to point at. internal/arch bans naming Reveal inside the
// five RENDERING seams — String, GoString, Format, LogValue, Error — on the
// argument that rendering a secret is never legitimate, and it deliberately does
// not extend that to marshalling, because persistence is also how a value is
// exported, stored and backed up. A database column is the case that argument was
// written for: a preimage that reaches sqlite as [redacted] is a row that can
// never answer the question it was written to answer.
//
// What it buys is that internal/store no longer calls Reveal to bind a parameter.
// Before twt, balance.go and nwc.go revealed the preimage and the connection
// secrets purely to hand them to the driver — reveals that existed for the type
// system and not for anything a reader could point at. Now the only Reveal call
// sites left on a preimage are the three the protocols require.
//
// NIL FOR THE ZERO VALUE, not the empty string, matching the nullString helper it
// replaces. Every column this type binds to was already NULL-when-absent, and a
// Valuer that wrote "" instead would silently change the shape of stored data on
// the day it landed — an unset preimage would start matching `WHERE preimage IS
// NOT NULL`.
func (s String) Value() (driver.Value, error) {
	if s.v == "" {
		return nil, nil
	}
	return s.v, nil
}

// Scan implements sql.Scanner, the other half of the export seam.
//
// It takes the three things a driver can hand back for a TEXT column: a string, a
// []byte (which some drivers return for TEXT and every driver returns for a
// BLOB), and nil for SQL NULL.
//
// NIL CLEARS THE DESTINATION rather than leaving it alone. database/sql reuses
// the destination across rows in a Rows loop, so a Scanner that ignored NULL
// would give an absent preimage the PREVIOUS row's value — which on this type
// means one payment's proof reported against another's. Planted.
func (s *String) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		s.v = ""
	case string:
		s.v = v
	case []byte:
		s.v = string(v)
	default:
		return fmt.Errorf("cannot scan %T into a secret.String", src)
	}
	return nil
}

// RandomToken returns n bytes of cryptographic randomness, URL-safe base64.
//
// It lives here because everything it is used for is a secret or a
// capability — a generated admin password, a session signing key, the per-boot
// probe token. On the impossible failure of crypto/rand it returns the empty
// string, which fails closed: every signature check against an empty key
// mismatches, and an empty password cannot be seeded.
func RandomToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
