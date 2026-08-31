package lnurl_test

import (
	"bytes"
	"net/url"
	"strings"
	"testing"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
)

// Primal Web percent-encodes the `nostr` parameter twice, so after the single
// decode query parsing performs, ParseZapRequest is handed %7B%22id%22… rather
// than JSON and refuses at rule 3 (BrollyZap-w0i). The event underneath is
// well-formed; only its transport encoding is wrong.
//

// The rescued request must be INDISTINGUISHABLE from the correctly encoded one.
//
// Not merely "accepted": ZapRequest.Raw feeds ZapHash, which is the invoice's
// description hash, and it is stored as the receipt's zap-request JSON. A
// fallback that accepted the request while leaving Raw percent-encoded would
// mint invoices committed to a hash over percent-encoded text — every receipt
// wrong, and wrong in a way no wallet reports back to us.
func TestADoubleEncodedZapRequestIsAcceptedIdenticallyToACorrectOne(t *testing.T) {
	raw := lnurltest.SignedZapRequest(t, nil)

	want, err := lnurl.ParseZapRequest(raw, 21_000)
	if err != nil {
		t.Fatalf("the correctly encoded fixture was refused: %v", err)
	}
	got, err := lnurl.ParseZapRequest(lnurltest.DoubleEncoded(raw), 21_000)
	if err != nil {
		t.Fatalf("the double-encoded request was refused: %v", err)
	}

	// The bytes, and only the bytes. ZapHash is sha256 over exactly these, so a
	// hash comparison here could not fail unless this one already had — the
	// description hash is asserted where it can actually say something extra, in
	// TestTheRescuePreservesTheSendersExactBytes.
	if !bytes.Equal(got.Request().Raw, want.Request().Raw) {
		t.Errorf("rescued raw bytes differ from the correctly encoded ones:\n got %s\nwant %s",
			got.Request().Raw, want.Request().Raw)
	}
}

// A correctly encoded request must never enter the fallback.
//
// Asserted through the bytes rather than by observing the branch: if the second
// decode ever ran on a request that parsed, a content field carrying a literal
// percent sequence would be silently corrupted, and that is the failure this
// ordering exists to prevent.
func TestACorrectlyEncodedRequestIsUntouched(t *testing.T) {
	raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
		e.Content = "100%25 agreed, and 50% sure"
	})

	got, err := lnurl.ParseZapRequest(raw, 21_000)
	if err != nil {
		t.Fatalf("a valid request with a percent sequence in its content was refused: %v", err)
	}
	if !bytes.Equal(got.Request().Raw, raw) {
		t.Errorf("the raw bytes were rewritten:\n got %s\nwant %s", got.Request().Raw, raw)
	}
	if !strings.Contains(string(got.Request().Raw), "100%25 agreed") {
		t.Error("the content's literal percent sequence was decoded away")
	}
}

// Garbage that merely LOOKS double-encoded is still refused — and refused by
// the signature or the id, which is the whole safety argument. The fallback
// cannot manufacture a valid request: rules 5 and 6 run after the parse, so the
// worst an over-eager decode can do is reach the same rejection later.
func TestSomethingThatMerelyLooksDoubleEncodedIsStillRefused(t *testing.T) {
	// Tampered AFTER signing and in a VALUE, so the bytes still decode to
	// well-formed JSON and the request survives rule 3. Corrupting a key instead
	// would be refused as "not a JSON event", which proves nothing about the
	// rules this test is here for.
	raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) { e.Content = "zap zap" })
	tampered := lnurltest.DoubleEncoded(bytes.Replace(raw, []byte("zap zap"), []byte("zap ZAP"), 1))
	if bytes.Equal(tampered, lnurltest.DoubleEncoded(raw)) {
		t.Fatal("the fixture was not tampered with; this test asserts nothing")
	}

	_, err := lnurl.ParseZapRequest(tampered, 21_000)
	if err == nil {
		t.Fatal("a tampered double-encoded request was accepted")
	}
	if !strings.Contains(err.Error(), "signature") && !strings.Contains(err.Error(), "id") {
		t.Errorf("refused with %q; the signature or id rule should be what catches this, "+
			"which is what makes the fallback safe", err)
	}
}

// Once, not in a loop. A loop invites a decode bomb and makes the failure mode
// unbounded; two encodings is the bug in the wild.
func TestATripleEncodedRequestIsRefused(t *testing.T) {
	raw := lnurltest.SignedZapRequest(t, nil)
	if _, err := lnurl.ParseZapRequest(lnurltest.DoubleEncoded(lnurltest.DoubleEncoded(raw)), 21_000); err == nil {
		t.Error("a triple-encoded request was accepted; the fallback ran more than once")
	}
}

// The byte cap measures what a stranger actually made us hold, before any
// decode. Percent-decoding only ever shrinks, so an over-cap input that would
// fit once decoded must still be refused on the length we received.
func TestTheByteCapIsAppliedToTheBytesReceivedNotTheDecodedOnes(t *testing.T) {
	raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
		// Each % becomes %25 when encoded, so this is comfortably under the
		// cap as received and comfortably over it once encoded.
		e.Content = strings.Repeat("%", 3000)
	})
	encoded := lnurltest.DoubleEncoded(raw)
	if len(raw) > lnurl.MaxZapRequestBytes {
		t.Fatalf("the fixture is already over the cap at %d bytes; it must be under so that "+
			"only the ENCODED form exceeds it", len(raw))
	}
	if len(encoded) <= lnurl.MaxZapRequestBytes {
		t.Fatalf("the encoded fixture is %d bytes, not over the %d cap; this asserts nothing",
			len(encoded), lnurl.MaxZapRequestBytes)
	}

	_, err := lnurl.ParseZapRequest(encoded, 21_000)
	if err == nil {
		t.Fatal("an over-cap request was accepted because it decoded smaller")
	}
	if !strings.Contains(err.Error(), "at most") {
		t.Errorf("refused with %q, want the byte-cap rule; the cap must bind on what was "+
			"received, not on what it shrinks to", err)
	}
}

// The rescue carries the sender's EXACT bytes through, not a re-serialisation.
//
// The fixture is deliberately non-canonical — bytes a marshal round-trip does
// not reproduce — because a canonical one cannot tell a correct implementation
// from one that parses and re-marshals. This is the property o34.3's receipt
// rests on: the description tag is these bytes verbatim, and a conforming
// client recomputes the id from them. Rewrite them and the receipt is discarded
// after the invoice has been paid.
func TestTheRescuePreservesTheSendersExactBytes(t *testing.T) {
	raw := lnurltest.NonCanonicalZapRequest(t, nil)

	got, err := lnurl.ParseZapRequest(lnurltest.DoubleEncoded(raw), 21_000)
	if err != nil {
		t.Fatalf("the double-encoded non-canonical request was refused: %v", err)
	}
	if !bytes.Equal(got.Request().Raw, raw) {
		t.Errorf("the rescue rewrote the sender's bytes:\n got %s\nwant %s", got.Request().Raw, raw)
	}
	// And the same fixture parsed the ordinary way agrees, so the rescued path
	// and the direct one cannot drift apart on the one value the receipt commits
	// to.
	direct, err := lnurl.ParseZapRequest(raw, 21_000)
	if err != nil {
		t.Fatalf("the non-canonical fixture was refused without the fallback: %v", err)
	}
	if !bytes.Equal(direct.Request().Raw, got.Request().Raw) {
		t.Errorf("the two parse paths disagree on the bytes:\ndirect  %s\nrescued %s",
			direct.Request().Raw, got.Request().Raw)
	}
}

// A "+" in the inner layer is left alone, so a form-encoded inner layer is
// REFUSED rather than silently corrupted.
//
// The two conventions disagree about "+": form-encoding means a space by it,
// while encodeURIComponent means a literal plus and writes a space as %20. Once
// the outer decode has run there is nothing left to say which was used, so the
// fallback has to choose — and url.PathUnescape is chosen over QueryUnescape
// precisely because it does NOT translate "+".
//
// The choice is the safe direction, and only one direction is safe. Treating
// "+" as a space would rewrite every literal plus inside a signed JSON body; if
// that ever produced parseable JSON it would be accepted with content the sender
// did not write. Leaving it alone can only ever fail the signature, which is a
// loud refusal rather than a quiet corruption — and it is the same argument that
// makes the whole fallback defensible.
func TestAFormEncodedInnerLayerIsRefusedRatherThanCorrupted(t *testing.T) {
	raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) { e.Content = "great post" })
	formInner := []byte(url.QueryEscape(string(raw))) // spaces become "+"
	if !bytes.Contains(formInner, []byte("+")) {
		t.Fatal("the fixture has no + in its inner layer; this test asserts nothing")
	}

	if _, err := lnurl.ParseZapRequest(formInner, 21_000); err == nil {
		t.Error("a form-encoded inner layer was accepted; a literal + inside a signed body " +
			"would have been rewritten as a space")
	}
}
