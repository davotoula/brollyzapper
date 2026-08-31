package lnurl_test

import (
	"net/url"
	"strings"
	"testing"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
)

// The two rejection arms the validation table cannot express.
//
// TestZapRequestValidation signs a real event whenever its `unsigned` field is
// empty, so "the parameter was empty" is not a row it can hold — an empty
// string there means "sign one for me". Both of these are listed in the
// coverage analysis §3.3 and neither had a test.
func TestTheArmsTheValidationTableCannotReach(t *testing.T) {
	t.Run("an empty nostr parameter", func(t *testing.T) {
		// Distinct from " ", which is one byte of whitespace and fails as
		// not-JSON. This is the length check, and its own message.
		_, err := lnurl.ParseZapRequest([]byte(""), 21_000)
		reasonMustName(t, err, "the nostr parameter is empty")
	})

	t.Run("a callback amount that is not a number", func(t *testing.T) {
		// The QUERY parameter, not the event's amount tag — the table covers
		// the tag. This is the arm every wallet hits first if it sends junk.
		_, err := lnurl.AmountMsat(url.Values{"amount": {"twenty-one"}})
		reasonMustName(t, err, "amount must be a number of millisatoshis")
	})

	t.Run("a missing callback amount", func(t *testing.T) {
		_, err := lnurl.AmountMsat(url.Values{})
		reasonMustName(t, err, "amount must be a number of millisatoshis")
	})
}

// reasonMustName asserts the refusal is one a caller may be shown AND that it
// names the rule.
//
// The second half is the point: §7 answers a wallet with {"status":"ERROR",
// "reason"}, and a reason that does not say which rule was broken sends a
// wallet author to the wrong line. An error that is merely non-nil satisfies a
// test and nobody reading a log.
func reasonMustName(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted input that breaks the rule %q", want)
	}
	reason, ok := lnurl.AsRejection(err)
	if !ok {
		t.Fatalf("the refusal is not showable to the caller: %v", err)
	}
	if !strings.Contains(reason, want) {
		t.Errorf("reason = %q, want it to name the rule (%q)", reason, want)
	}
}

// FuzzParseZapRequest — the repo's first fuzz target, on its principal
// untrusted-input surface (zu5.3, coverage analysis §3.3).
//
// ParseZapRequest is hex, JSON, tags and a schnorr verification, reached over
// the PUBLIC route group by anyone on the internet. It is the textbook case.
//
// The target asserts ONLY that the function does not panic and returns exactly
// one of a verified request or an error. It deliberately asserts nothing about
// WHICH answer: a fuzzer explores inputs nobody reasoned about, so any expected
// output would encode today's behaviour as a rule and turn every future
// tightening into a false failure. The table tests above are where specific
// answers belong.
//
// The corpus is seeded from the shapes the table already uses, so the fuzzer
// starts from valid signed events and known-malformed ones rather than from
// random bytes that never get past the JSON parse.
func FuzzParseZapRequest(f *testing.F) {
	f.Add(lnurltest.SignedZapRequest(f, func(*gonostr.Event) {}), int64(21_000))
	f.Add(lnurltest.SignedZapRequest(f, func(e *gonostr.Event) {
		e.Tags = append(e.Tags, gonostr.Tag{"a", "30023:" + lnurltest.Hex64('b') + ":slug"})
	}), int64(21_000))
	f.Add(lnurltest.SignedZapRequest(f, func(e *gonostr.Event) {
		e.Tags = lnurltest.WithoutTag(e.Tags, "e")
	}), int64(21_000))
	// Rule 3's double-encoding fallback (BrollyZap-w0i) widened what reaches the
	// parser: percent-encoded text now gets a second decode and another
	// UnmarshalJSON. Seeded so the corpus explores that branch, and so a decode
	// that panics on client data is caught here rather than in the field.
	f.Add([]byte(url.QueryEscape(string(lnurltest.SignedZapRequest(f, nil)))), int64(21_000))
	f.Add([]byte("%7B%22"), int64(21_000))
	f.Add([]byte("%22%ZZ"), int64(21_000))
	f.Add([]byte("{not json"), int64(21_000))
	f.Add([]byte(""), int64(0))
	f.Add([]byte(" "), int64(-1))
	f.Add([]byte(`{"kind":9734,"tags":[[]],"content":""}`), int64(21_000))

	f.Fuzz(func(t *testing.T, raw []byte, amountMsat int64) {
		got, err := lnurl.ParseZapRequest(raw, amountMsat)
		switch {
		case err != nil && got != nil:
			t.Fatalf("returned BOTH a verified request and an error (%v); a caller that "+
				"checks only one of them would mint on a refused request", err)
		case err == nil && got == nil:
			t.Fatal("returned neither a verified request nor an error")
		case err == nil:
			// Touch it, so "verified" cannot be satisfied by a nil-bearing
			// value that panics the first time anyone reads it.
			if got.Request() == nil {
				t.Fatal("a verified request carries no request")
			}
		}
	})
}
