// Package lnurltest builds zap-request fixtures for tests in this module.
//
// It exists because three packages each grew their own — internal/lnurl,
// internal/api and internal/zap — and two of them carried their own copy of the
// non-canonical-JSON guard. That guard is what stands between this project and
// what §16 calls the most dangerous failure in P2: a re-serialisation anywhere
// on the zap path changes description_hash, every client silently ignores every
// receipt, and nothing looks wrong locally. Having the GUARD in two
// independently maintained copies was the risk; the duplicated fixture was
// merely how it got there.
//
// internal/lnurl is below internal/api and internal/zap and both already import
// it, so this inverts nothing. The precedent is internal/lnd/lndtest.
package lnurltest

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/lnurl"
)

// TB is the slice of testing.TB the GUARD uses, and only the guard.
//
// ohi criterion 3 is why it exists: testing.TB cannot be implemented outside
// the testing package — it has an unexported method — so a guard that took it
// could never be SHOWN to fail. This interface is what lets AssertNonCanonical
// be handed a recorder and proved to reject a canonical fixture. A guard that
// has only ever passed has been written, not tested, and this one has been
// wrong before: Wave 8's first fixture was canonical, the whitespace injection
// was a silent no-op, and a planted json.Marshal(parsed) passed anyway.
//
// The BUILDERS take the real testing.TB. Giving them this interface too meant
// every Fatalf needed a `return nil` after it, because a recorder does not halt —
// dead paths that every real caller ignored, since testing.T.Fatalf never
// returns. testing.TB satisfies TB, so callers pass t to both either way.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// Hex64 is a 64-character hex string of one repeated digit, for pubkeys and
// event ids that only have to be well-formed.
func Hex64(c byte) string { return strings.Repeat(string(c), 64) }

// ZapRequestEvent is the unsigned kind-9734 fixture every caller starts from.
//
// One definition of "a valid zap request", so a tightening of lnurl's rules
// fails ONE fixture rather than three in three packages.
func ZapRequestEvent() *gonostr.Event {
	return &gonostr.Event{
		Kind:      lnurl.ZapRequestKind,
		CreatedAt: gonostr.Timestamp(1_700_000_000),
		Content:   "",
		Tags: gonostr.Tags{
			{"p", Hex64('a')},
			{"e", Hex64('f')},
			{"relays", "wss://relay.example", "wss://other.example"},
		},
	}
}

// SignedZapRequest returns a signed zap request as CANONICAL JSON.
//
// mutate may be nil. Use this where the bytes only have to parse; where the
// test is about the bytes surviving unchanged, use NonCanonicalZapRequest.
func SignedZapRequest(t testing.TB, mutate func(*gonostr.Event)) []byte {
	t.Helper()
	event := ZapRequestEvent()
	if mutate != nil {
		mutate(event)
	}
	if err := event.Sign(gonostr.GeneratePrivateKey()); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshalling the fixture: %v", err)
	}
	return raw
}

// WithRewrittenID returns raw with its `id` field replaced, leaving the
// signature intact.
//
// The one tamper go-nostr's CheckSignature cannot see: it recomputes the id from
// the serialisation and verifies against THAT, never reading the id field, so an
// event can carry a valid signature and a wrong id — and the id is what a client
// matches a receipt against. Only CheckID catches it, which is why both zap
// request paths call it and both have a test for exactly this.
//
// Here rather than in either test, because it was in both: the inbound path's
// and the outgoing verifier's, six identical lines differing only in the filler
// hex. This package exists because that shape produced a guard maintained in two
// copies once already.
func WithRewrittenID(t testing.TB, raw []byte, id string) []byte {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("reading the fixture back: %v", err)
	}
	if fields["id"] == id {
		t.Fatalf("the fixture already has id %q, so rewriting it changes nothing and the "+
			"test would pass against an implementation that never checks", id)
	}
	fields["id"] = id
	rewritten, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("re-marshalling the fixture: %v", err)
	}
	return rewritten
}

// NonCanonicalZapRequest returns a signed zap request whose bytes a marshal
// round-trip does NOT reproduce, and proves that before returning.
//
// Any test asserting that raw bytes are carried unchanged needs this. With a
// canonical fixture, hashing the bytes and hashing a re-serialisation of them
// agree, so the assertion holds for a broken implementation too.
func NonCanonicalZapRequest(t testing.TB, mutate func(*gonostr.Event)) []byte {
	t.Helper()
	canonical := SignedZapRequest(t, mutate)
	// Whitespace go-nostr's own marshaller does not produce.
	raw := []byte(strings.Replace(string(canonical), "{", "{ ", 1))
	AssertNonCanonical(t, raw)
	return raw
}

// AssertNonCanonical fails t unless raw differs from a marshal round-trip of
// itself.
//
// It is the guard, and it is tested to fail — see the package doc and
// lnurltest_test.go. Handed a canonical fixture it must complain, because a
// fixture that survives the round-trip cannot tell a correct implementation
// from one that parses and re-marshals.
func AssertNonCanonical(t TB, raw []byte) {
	t.Helper()
	var event gonostr.Event
	if err := event.UnmarshalJSON(raw); err != nil {
		t.Fatalf("the fixture is not a parseable event: %v", err)
		return
	}
	round, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("re-marshalling the fixture: %v", err)
		return
	}
	if string(round) == string(raw) {
		t.Fatalf("the fixture survives a marshal round-trip unchanged, so nothing using " +
			"it can distinguish carrying the raw bytes from re-serialising them")
	}
}

// WithoutTag returns tags with every entry named name removed, so a caller can
// replace one rather than rebuild the set.
func WithoutTag(tags gonostr.Tags, name string) gonostr.Tags {
	var out gonostr.Tags
	for _, tag := range tags {
		if len(tag) > 0 && tag[0] == name {
			continue
		}
		out = append(out, tag)
	}
	return out
}

// DoubleEncoded is a zap request as Primal Web puts it on the wire: percent-
// encoded one time too many (BrollyZap-w0i). What it returns is the value a
// server holds AFTER the single decode query parsing performs — still encoded,
// which is the bug.
//
// %20 for a space, never "+". A browser's encodeURIComponent writes %20, and
// the captured report shows exactly that (%2520); form-encoding writes "+".
// The distinction is not cosmetic — the two are decoded differently and only
// one of them is rescued, which is what
// TestAFormEncodedInnerLayerIsRefusedRatherThanCorrupted pins. A caller
// "simplifying" this to a bare url.QueryEscape turns a rescue fixture into a
// refusal fixture.
func DoubleEncoded(raw []byte) []byte {
	return []byte(strings.ReplaceAll(url.QueryEscape(string(raw)), "+", "%20"))
}
