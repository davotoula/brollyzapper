package guard

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The unforgeable operator channel (`06v`, Ruling 3).
//
// THE PROBLEM IT SOLVES. The server is the operator's only channel to the app,
// and the server is what the threat model defends against. So a loosening the
// operator asks for — turning sending on, raising a cap — cannot be authorised
// by anything that reaches the guard through the server alone: a compromised
// server would simply ask for it itself.
//
// THE PROPERTY IT RESTS ON is a filesystem fact that is already true and already
// relied on: the server has no mount for `data/guard`
// (`umbrel/brollyzapper/docker-compose.yml`, the guard's volumes), which is what
// has protected `guard-state.json` since P1. The guard writes the grant there.
// The operator reads it with a file browser their platform already gives them —
// on umbrelOS, the Files app — and types the code back into the page. The server
// relays a code it cannot read, to be checked against state it cannot read.
//
// WHY NOT A SIGNING KEY (option B of the design brief): its guarantee rests on a
// TOFU bootstrap — the guard must learn the operator's pubkey without the server
// substituting one, at a moment when the public LNURL endpoints are already
// live — and it requires the operator to hold a signer on the device they
// administer the box from, which for umbrelOS is as often a phone as a desktop.
// This needs a web browser, which the operator provably has.
//
// WHY NOT THE GUARD'S LOG (option C): §19 names log scraping in the same breath
// as SSH, and a log is not a durable operator surface — it rolls, it is filtered
// by level, and the level is itself a setting. This is that option with its one
// flaw removed.
//
// WHY IT IS OPERATION-BOUND, and this is the part that resists phishing: the
// description of what is being authorised is written BY THE GUARD, in a file the
// server cannot touch. A compromised server cannot ask the operator to "confirm
// your balance" and spend the answer on raising a cap, because what the operator
// reads is the guard's own sentence about the guard's own pending change.

// AuthorisationFile and AuthorisationCodeLine are the ONE statement of this
// file's name and format — the operator-facing half of the grant, in the guard's
// own data directory.
//
// `.txt` DELIBERATELY, and it is the WHOLE ROUTE rather than the better of two
// (corrected 28 Aug 2026 from a box measurement, `muj` item 1).
//
// The extension was chosen believing umbrelOS would fall back to sniffing the
// MIME type for anything it did not recognise. IT DOES NOT. `files.ts` types a
// listing with `mime.lookup(name)`, which is extension-only, falling back to
// `application/octet-stream`; the serving layer keeps an allow-list of MIME
// types it will render inline, and a miss forces `application/octet-stream`
// with `Content-Disposition: attachment` — a download, not a render. The
// response also sets `X-Content-Type-Options: nosniff`, so the browser will not
// rescue it either.
//
// So an unrecognised extension does not render badly, it does not render at
// all: the operator gets a file save dialog where they expected a code. There
// is no second path to that code, which makes this constant load-bearing for
// the whole ceremony rather than a formatting preference.
//
// Exported for the same reason and together, which is the point: the file is
// written here and read back by the regtest ceremony driver and by this
// package's external tests. Only the code line was exported at first, and the
// name was re-typed at four sites — so half the format was drift-proof and half
// was not, and renaming the file would have compiled cleanly and failed at
// regtest runtime as "the operator has nothing to read", which reads as a broken
// guard rather than a stale tool. Found by review.
const (
	AuthorisationFile     = "authorisation.txt"
	AuthorisationCodeLine = "Code: "
)

// authorisationTTL bounds how long a grant stays usable.
//
// Ten minutes: long enough to open a file browser on a phone, find the app's
// data directory and type eight characters; short enough that a code left on
// screen and forgotten is not a standing grant. WHAT WOULD CHANGE IT: evidence
// from a field trip that the umbrelOS Files route takes longer than this to
// walk. It is not a security parameter — the attempt bound below is — so
// lengthening it on that evidence costs nothing.
const authorisationTTL = 10 * time.Minute

// maxAuthorisationAttempts is how many wrong codes consume a grant.
//
// The code is 40 bits, so guessing it inside the TTL is not the threat this
// bounds — a compromised server making millions of socket calls would still need
// centuries. It bounds the ATTEMPT, which is the thing worth seeing: three wrong
// codes on a grant the operator never asked for is a server behaving like an
// attacker, and it ends the grant and raises `guard.reject` rather than
// accumulating quietly. WHAT WOULD CHANGE IT: nothing about the arithmetic. Only
// evidence that operators mistype often enough for three to be a support burden.
const maxAuthorisationAttempts = 3

// codeAlphabet is Crockford base32: the digits plus the letters that do not
// misread in a hand-copied string — no I, L, O or U, which are the four that
// become 1, 1, 0 and V. Thirty-two symbols over eight characters is 40 bits.
const codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

const codeLength = 8

// Authorisation is one outstanding grant. It lives in the guard's state file.
//
// The CODE is here and in the .txt the operator reads, and nowhere else — never
// in a log line, never in a socket response, never in an error. `slog.LogValuer`
// is not enough on its own for a string field, so the rule is enforced by there
// being no code-bearing type outside this package and by an arch rule over the
// guard's own logging call sites.
type Authorisation struct {
	// Change is what this grant authorises, and ONLY what it authorises. A code
	// issued for "turn sending on" cannot be spent on "raise the spend cap":
	// that is the whole of what operation-binding means, and it is checked by
	// value rather than by kind so that a grant for "raise the cap to 50k"
	// cannot be redeemed for 5M.
	Change Change `json:"change"`
	Code   string `json:"code"`
	// ExpiresAt is absolute, so a restart cannot extend a grant.
	ExpiresAt time.Time `json:"expires_at"`
	// Attempts counts wrong codes offered against this grant.
	Attempts int `json:"attempts,omitempty"`
}

// newCode returns a fresh operator code.
//
// Rejection sampling rather than `%` over a random byte. With 32 symbols the
// modulo happens to be uniform, so today the two are identical — but the
// alphabet's length is a constant someone will change, and a code generator that
// becomes biased on an edit to a nearby line is a defect nothing would catch.
// Uniformity that holds by construction costs one comparison.
func newCode() (string, error) {
	out := make([]byte, 0, codeLength)
	buf := make([]byte, 1)
	limit := 256 / len(codeAlphabet) * len(codeAlphabet)
	for len(out) < codeLength {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("guard: generating an authorisation code: %w", err)
		}
		if int(buf[0]) >= limit {
			continue
		}
		out = append(out, codeAlphabet[int(buf[0])%len(codeAlphabet)])
	}
	return string(out[:4]) + "-" + string(out[4:]), nil
}

// normaliseCode is what makes a code typed off a phone screen work.
//
// Case and the grouping dash are presentation. Nothing else is forgiven: a
// lenient parser on a security control is how "close enough" becomes the rule.
func normaliseCode(s string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
}

// matches reports whether code redeems this grant, in constant time.
//
// The comparison is constant-time because the alternative is a timing oracle a
// compromised server can query as fast as the socket allows — the one attacker
// in this design with unlimited local attempts.
func (a *Authorisation) matches(code string) bool {
	want := normaliseCode(a.Code)
	got := normaliseCode(code)
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

func (a *Authorisation) expired(now time.Time) bool { return !now.Before(a.ExpiresAt) }

// authorisationPath is where the operator-facing file lives.
func (g *Guard) authorisationPath() string { return filepath.Join(g.dataDir, AuthorisationFile) }

// operatorAuthorisationLocation is what the page tells the operator to open.
//
// THE DEPLOYMENT'S WORDS WHEN IT HAS ANY. §19 forbids the generic app assuming
// deployment-specific paths, and an umbrelOS operator needs "Files → Apps →
// brollyzapper → data → guard", not a path inside a container they will never
// see. The Umbrel package supplies that sentence through
// GUARD_AUTHORISATION_LOCATION; the guard relays it; the page renders it.
//
// THE CONTAINER PATH WHEN IT HAS NONE, because a deployment that said nothing is
// one whose operator is reading a compose file anyway, and a wrong-but-generic
// sentence would be worse than the literal truth. It is not a useful route on
// umbrelOS, which is exactly why the package sets the variable.
func (g *Guard) operatorAuthorisationLocation() string {
	if g.authorisationLocation != "" {
		return g.authorisationLocation
	}
	return g.authorisationPath() + " in the guard container"
}

// writeAuthorisationFile renders the grant for a person to read.
//
// EVERY SENTENCE HERE IS A SECURITY CONTROL, not decoration. This file is the
// trusted display: it is the only description of the pending change that the
// server did not write, so it is the only one an operator can believe. It
// therefore states what is being changed in the guard's own words, says plainly
// that the app could not have written it, and tells the reader what to do if
// they did not ask for this.
//
// 0600, and owned by whoever runs the guard — uid 1000 under the Umbrel package,
// which is also the uid umbreld's Files app reads as. A stricter mode would make
// the file unreadable by the one person it is for.
func (g *Guard) writeAuthorisationFile(a *Authorisation, now time.Time) error {
	var b strings.Builder
	b.WriteString("BrollyZapper — authorisation required\n")
	b.WriteString("=====================================\n\n")
	b.WriteString("The app is asking to:\n\n")
	b.WriteString("    " + a.Change.describe() + "\n\n")
	b.WriteString("Type the code below into the app's page to allow it.\n\n")
	b.WriteString("    " + AuthorisationCodeLine + a.Code + "\n\n")
	b.WriteString(fmt.Sprintf("It works once, only for the change named above, and expires at\n"+
		"%s (%d minutes from %s).\n\n",
		a.ExpiresAt.UTC().Format(time.RFC1123), int(authorisationTTL/time.Minute),
		now.UTC().Format(time.RFC1123)))
	b.WriteString("IF YOU DID NOT JUST ASK FOR THIS in BrollyZapper, do not type the code.\n")
	b.WriteString("Something else asked, and the code is the only thing standing in its way.\n\n")
	b.WriteString("Why this file exists: the part of the app that faces the network cannot\n")
	b.WriteString("read or write this directory, so it cannot write this file, read this\n")
	b.WriteString("code, or change the sentence above. That is what makes it worth reading.\n")
	return WriteCredential(g.authorisationPath(), []byte(b.String()), 0o600)
}

// clearAuthorisationFile removes the operator-facing file.
//
// A consumed or superseded grant's file must not linger: an operator returning
// to a stale code and typing it would be told it is wrong, which reads as the
// app being broken rather than as the code being spent. Failure is logged and
// swallowed — the grant is already gone from the state, which is the half that
// decides anything.
func (g *Guard) clearAuthorisationFile() {
	if err := os.Remove(g.authorisationPath()); err != nil && !os.IsNotExist(err) {
		g.log.Warn("could not remove the spent authorisation file",
			"path", g.authorisationPath(), "error", err.Error())
	}
}
