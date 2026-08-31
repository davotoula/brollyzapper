package lnurl_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
)

// §16 names this the one place in P2 where a passing suite and a broken product
// look identical: get description_hash wrong and every client quietly ignores
// every receipt. So it is written before any handler exists.
//
// Two rules, and conflating them is the failure:
//
//   - plain LNURL payment — sha256 of the metadata string, byte-for-byte as
//     served in the lnurlp response;
//   - zap — sha256 of the RAW URL-decoded `nostr` query parameter, with no
//     LNURL metadata appended and NO re-serialisation.
func TestPlainPaymentHashesTheMetadataStringItServed(t *testing.T) {
	metadata := lnurl.Metadata("bob", "zap.example")
	want := sha256.Sum256([]byte(metadata))

	got, err := lnurl.MetadataHash(metadata)
	if err != nil {
		t.Fatalf("MetadataHash: %v", err)
	}
	if hex.EncodeToString(got[:]) != hex.EncodeToString(want[:]) {
		t.Errorf("description_hash = %x, want sha256 of the metadata string %x", got, want)
	}
}

// The fixture is deliberately NON-CANONICAL: keys out of alphabetical order and
// whitespace that encoding/json will not reproduce. That is what makes the test
// able to tell a correct implementation from one that parses and re-marshals —
// with canonical JSON the two agree and the test teaches nothing.
const nonCanonicalZapRequest = `{
  "kind": 9734,
  "content": "",
  "tags": [["relays","wss://relay.example"],["p","` +
	`0000000000000000000000000000000000000000000000000000000000000001"]],
  "pubkey": "0000000000000000000000000000000000000000000000000000000000000002",
  "id":      "0000000000000000000000000000000000000000000000000000000000000003",
  "created_at": 1700000000,
  "sig": "00"
}`

func TestAZapHashesTheRawRequestBytesAndNotAReSerialisation(t *testing.T) {
	raw := []byte(nonCanonicalZapRequest)

	// The premise: a round-trip really does change these bytes. If it ever
	// stops being true the fixture has gone canonical and everything below has
	// quietly stopped proving anything.
	//
	// Through lnurltest, which is the ONE implementation of this guard (ohi) —
	// and the only one that is itself tested to fail. This file was the third
	// copy, in the same package as the one the migration touched.
	lnurltest.AssertNonCanonical(t, raw)

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("the fixture is not valid JSON: %v", err)
	}
	remarshalled, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}

	want := sha256.Sum256(raw)
	got, err := lnurl.ZapHash(raw)
	if err != nil {
		t.Fatalf("ZapHash: %v", err)
	}
	if hex.EncodeToString(got[:]) != hex.EncodeToString(want[:]) {
		t.Errorf("zap description_hash = %x, want sha256 of the RAW request bytes %x", got, want)
	}
	if wrong := sha256.Sum256(remarshalled); hex.EncodeToString(got[:]) == hex.EncodeToString(wrong[:]) {
		t.Error("the hash matches a re-serialisation of the request; clients will ignore " +
			"every receipt built from it")
	}
}

// And the metadata must not be appended for a zap — NIP-57 hashes the request
// alone. Appending is the other half of the same mistake.
func TestAZapDoesNotMixInTheLNURLMetadata(t *testing.T) {
	raw := []byte(nonCanonicalZapRequest)
	metadata := lnurl.Metadata("bob", "zap.example")

	got, err := lnurl.ZapHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	appended := sha256.Sum256(append([]byte(metadata), raw...))
	if hex.EncodeToString(got[:]) == hex.EncodeToString(appended[:]) {
		t.Error("the zap hash includes the LNURL metadata; NIP-57 hashes the request alone")
	}
	// The zap hash cannot depend on the metadata, because ZapHash is not given
	// any: after the split that is the signature, not something a test can
	// usefully re-assert.
}

// The bytes that get hashed are the bytes that get stored, because o34.3's
// receipt carries them verbatim as its description tag. A caller that hashes
// one thing and stores another produces receipts nothing can verify.
func TestTheDecodedParameterSurvivesURLEncodingIntact(t *testing.T) {
	raw := []byte(nonCanonicalZapRequest)
	query, err := url.ParseQuery("amount=21000&nostr=" + url.QueryEscape(string(raw)))
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	decoded := lnurl.RawParam(query, "nostr")
	if string(decoded) != string(raw) {
		t.Fatalf("the decoded parameter differs from what was sent:\n got %q\nwant %q",
			decoded, raw)
	}
	want := sha256.Sum256(raw)
	got, err := lnurl.ZapHash(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != hex.EncodeToString(want[:]) {
		t.Errorf("hashing the decoded parameter gave %x, want %x", got, want)
	}
}

// The self-prober and the callback must agree about a configured domain, or the
// probe can go green against a URL no wallet is ever handed. One function, so
// they cannot disagree — asserted over the shapes an operator actually types.
func TestOneNormalisationForTheProbeAndTheCallback(t *testing.T) {
	for _, domain := range []string{
		"zap.example", "https://zap.example", "https://zap.example/",
		" zap.example ", "http://192.168.77.42:3033",
	} {
		base := lnurl.BaseURL(domain, false)
		if strings.HasSuffix(base, "/") {
			t.Errorf("BaseURL(%q) = %q, want no trailing slash", domain, base)
		}
		if !strings.Contains(base, "://") {
			t.Errorf("BaseURL(%q) = %q, want a scheme", domain, base)
		}
	}
	// A LAN address keeps the scheme it was given; forcing https would make a
	// box-local probe impossible (§9).
	if got := lnurl.BaseURL("http://192.168.77.42:3033", false); got != "http://192.168.77.42:3033" {
		t.Errorf("BaseURL rewrote an explicit scheme: %q", got)
	}
}

// The metadata string is served AND hashed, so it must be valid JSON for any
// address name an operator can set — a quote in the name used to produce a
// document every wallet rejects.
func TestMetadataIsValidJSONForAwkwardNames(t *testing.T) {
	for _, name := range []string{"bob", `he said "hi"`, `back\slash`, "ünïcøde"} {
		metadata := lnurl.Metadata(name, "zap.example")
		var decoded [][]string
		if err := json.Unmarshal([]byte(metadata), &decoded); err != nil {
			t.Errorf("Metadata(%q) is not valid JSON: %v (%s)", name, err, metadata)
			continue
		}
		if len(decoded) != 2 || decoded[1][1] != name+"@zap.example" {
			t.Errorf("Metadata(%q) = %s, want the identifier to round-trip", name, metadata)
		}
	}
}
