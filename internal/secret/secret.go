package secret

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
func (s String) MarshalJSON() ([]byte, error) { return json.Marshal(Redacted) }

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
