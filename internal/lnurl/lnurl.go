package lnurl

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// Limits on what the callback will mint (spec §7).
const (
	MinSendableMsat = 1_000
	MaxSendableMsat = 100_000_000_000
	// CommentAllowed is the LUD-12 comment length announced and enforced.
	CommentAllowed = 255
	// InvoiceExpirySeconds is §7's 600s: LNURL clients pay immediately or not
	// at all, and a short expiry bounds the open-invoice count.
	InvoiceExpirySeconds int64 = 600
)

// NormaliseDomain reduces whatever an operator pasted to the bare host[:port]
// a lightning address is made of, and reports whether they asked for plain
// HTTP.
//
// Pasting https://zap.example.com is the natural thing to do, and until o34.13
// it was stored verbatim — so the identifier became name@https://zap.example.com
// and the description_hash was computed over that. Every wallet computes a
// different hash from the metadata it was served, so every invoice looks
// tampered with: §16's silent failure, by a route the byte-stability test does
// not cover because it never sees a domain an operator typed.
//
// Lower-cased, because DNS is case-insensitive but a hash is not. name@Zap.
// Example.com and name@zap.example.com are the same address and two different
// description_hashes, which is the same bug wearing different clothes.
//
// This is applied at the settings boundary so the stored value is bare, AND
// wherever the domain is consumed — an install that already has a scheme in
// its settings row must be fixed on upgrade, not on the next time somebody
// happens to open Settings and press Save.
// scheme is what the operator pasted, lower-cased, or "" if they pasted none —
// which is a different answer from "https" and the caller needs to tell them
// apart: the Settings field renders the bare host, so a save with no scheme
// must leave the stored one alone rather than promoting a LAN address.
func NormaliseDomain(raw string) (host, scheme string) {
	raw = strings.TrimSpace(raw)
	if pasted, rest, found := strings.Cut(raw, "://"); found {
		scheme, raw = strings.ToLower(pasted), rest
	}
	// Credentials, path, query and fragment are not part of the host, and any
	// of them in the identifier is a hash nobody else computes.
	if _, after, found := strings.Cut(raw, "@"); found {
		raw = after
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	// A trailing dot is a legal FQDN and not how anyone writes an address.
	return strings.ToLower(strings.TrimSuffix(raw, ".")), scheme
}

// Identifier is the lightning address itself, name@host.
//
// One definition, because there were two: Metadata built it for the hash and
// the Setup page built it for the operator to read, and only one of them was
// ever going to be fixed by hand (o34.13).
func Identifier(name, domain string) string {
	host, _ := NormaliseDomain(domain)
	if name == "" || host == "" {
		return ""
	}
	return name + "@" + host
}

// BaseURL builds the origin every public URL is formed from.
//
// One definition, because two would drift silently and in the worst direction:
// §9's self-prober builds a URL from this setting and the callback advertises
// another, so a domain given with a scheme or a trailing slash could probe
// GREEN while every wallet is handed a callback that does not resolve.
//
// insecure comes from the operator's own setting, and a scheme still present in
// the stored value is honoured too: on a box that was configured before o34.13
// the row still reads http://192.168.77.42:3033, and silently promoting that to
// https would break the LAN setup it was typed for.
func BaseURL(domain string, insecure bool) string {
	host, pasted := NormaliseDomain(domain)
	if host == "" {
		return ""
	}
	if insecure || pasted == "http" {
		return "http://" + host
	}
	return "https://" + host
}

// Metadata is the LUD-06 metadata string for an address.
//
// It is returned in the lnurlp response AND hashed into description_hash for a
// plain payment, so it is built in exactly one place: the two must be
// byte-identical or every wallet rejects the invoice as not matching what it
// was shown.
//
// Marshalled rather than formatted, so a name containing a quote produces valid
// JSON instead of a document every wallet rejects. Byte-stability is unaffected
// — the response and the hash both come from here.
//
// The domain is normalised HERE and not only where it is stored, so the
// identifier is name@host whatever a settings row happens to hold (o34.13).
func Metadata(name, domain string) string {
	raw, err := json.Marshal([][]string{
		{"text/plain", "Zap " + name},
		{"text/identifier", Identifier(name, domain)},
	})
	if err != nil {
		// Unreachable: [][]string always marshals.
		return ""
	}
	return string(raw)
}

// §7's description_hash fork, as TWO functions. §16 calls this the one place in
// P2 where a passing suite and a broken product look identical: get it wrong
// and every client quietly ignores every receipt.
//
// It used to be one DescriptionHash(metadata, zapRequest) that chose its mode
// by which argument was empty. Two things were wrong with that. The mode was
// implicit, so DescriptionHash("", raw) and DescriptionHash(metadata, nil) were
// the same call shape meaning opposite things; and both arguments were
// stringish, so swapping them compiled and hashed the wrong thing silently. The
// caller now says which rule it is invoking, and there is no call site at which
// an argument swap is possible.
//
// The two rules, which conflating is the failure:
//
//   - MetadataHash — a plain LNURL payment hashes the metadata string,
//     byte-for-byte as served in the lnurlp response.
//   - ZapHash — a zap hashes the RAW URL-decoded `nostr` parameter alone. Not a
//     re-serialisation of a parsed struct, and with NO LNURL metadata appended.
//
// Go's encoding/json preserves neither key order nor whitespace, so a round-trip
// through a struct produces a different hash. The raw bytes are carried, hashed
// and stored unchanged; o34.3's receipt carries these same bytes as its
// description tag.

// MetadataHash is the plain-payment rule: sha256 of the metadata string.
func MetadataHash(metadata string) ([32]byte, error) {
	if strings.TrimSpace(metadata) == "" {
		return [32]byte{}, errors.New("lnurl: no metadata to hash")
	}
	return sha256.Sum256([]byte(metadata)), nil
}

// ZapHash is the zap rule: sha256 of the raw zap-request bytes, alone.
func ZapHash(zapRequest []byte) ([32]byte, error) {
	if len(zapRequest) == 0 {
		// Not a caller's mistake to tolerate: an empty zap request means the
		// caller chose this rule for a request that has none, and hashing
		// nothing would mint an invoice no receipt can ever match.
		return [32]byte{}, errors.New("lnurl: no zap request to hash")
	}
	return sha256.Sum256(zapRequest), nil
}

// RawParam returns a query parameter as the bytes it decoded to.
//
// Separate from a plain Get so the type says what matters: these bytes are
// hashed and stored verbatim, and anything that turns them back into a string
// and re-encodes them breaks the hash.
func RawParam(query url.Values, key string) []byte {
	value := query.Get(key)
	if value == "" {
		return nil
	}
	return []byte(value)
}
