package zap_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/zap"
)

var settleTime = time.Unix(1_700_009_999, 0).UTC()

// tagValue returns the first value of the named tag, and whether it was there.
// gonostr.Tags.Find does the search; this only adds the presence answer the
// assertions below want.
func tagValue(event *gonostr.Event, name string) (string, bool) {
	tag := event.Tags.Find(name)
	if len(tag) < 2 {
		return "", false
	}
	return tag[1], true
}

// zapRequest is the shared fixture, with the amount tag this package's cases
// need. The builder and the non-canonical guard live in lnurltest (ohi).
func zapRequest(t *testing.T, shape func(*gonostr.Event)) []byte {
	t.Helper()
	return lnurltest.NonCanonicalZapRequest(t, func(e *gonostr.Event) {
		e.Tags = append(lnurltest.WithoutTag(e.Tags, "e"), gonostr.Tag{"amount", "21000"})
		if shape != nil {
			shape(e)
		}
	})
}

func settledZap(t *testing.T, raw []byte) store.SettledZap {
	t.Helper()
	return store.SettledZap{
		PaymentHash: strings.Repeat("f", 64),
		MintedMsat:  21_000,
		PaidMsat:    21_000,
		Bolt11:      "lnbcrt210n1example",
		Preimage:    secret.New(strings.Repeat("9", 64)),
		ZapRequest:  string(raw),
		SettledAt:   settleTime,
	}
}

// Criterion 2. created_at is the SETTLE time, never now(). §7 allows the retry
// to run for a day, so a receipt stamped at publish time tells every reader the
// zap happened up to a day after it did — and a sender's client orders and
// matches on that timestamp.
func TestTheReceiptIsStampedWithTheSettleTimeNotTheBuildTime(t *testing.T) {
	event, _, err := zap.Build(settledZap(t, zapRequest(t, nil)))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := time.Unix(int64(event.CreatedAt), 0).UTC(); !got.Equal(settleTime) {
		t.Errorf("created_at = %s, want the settle time %s", got, settleTime)
	}
	if event.Kind != zap.ReceiptKind {
		t.Errorf("kind = %d, want %d", event.Kind, zap.ReceiptKind)
	}
	if event.Content != "" {
		t.Errorf("content = %q, want empty", event.Content)
	}
}

// Criterion 3. The description tag is the raw bytes, byte-identical to what was
// hashed into the invoice. This is §16's failure in a third place: a
// re-serialisation here makes every receipt unverifiable, and it looks fine
// locally because our own copy still parses.
func TestTheDescriptionTagIsTheBytesThatWereHashed(t *testing.T) {
	raw := zapRequest(t, nil)
	event, _, err := zap.Build(settledZap(t, raw))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	description, ok := tagValue(event, "description")
	if !ok {
		t.Fatal("the receipt carries no description tag")
	}
	if description != string(raw) {
		t.Errorf("description tag is not the stored bytes:\n got %s\nwant %s", description, raw)
	}
	// And against the invoice's description_hash preimage, which is the thing a
	// client actually recomputes.
	want, err := lnurl.ZapHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := sha256.Sum256([]byte(description))
	if hex.EncodeToString(got[:]) != hex.EncodeToString(want[:]) {
		t.Errorf("sha256(description tag) = %x, but the invoice's description_hash is %x; "+
			"every client will discard this receipt", got, want)
	}
}

// Criterion 4, including the profile-zap case by name — the prior art
// nil-dereferences exactly here.
func TestTagsAreExactlyPerSpecAndAProfileZapHasNeitherENorA(t *testing.T) {
	eventID := strings.Repeat("c", 64)
	coordinate := "30023:" + strings.Repeat("d", 64) + ":slug"

	t.Run("a note zap carries e", func(t *testing.T) {
		raw := zapRequest(t, func(e *gonostr.Event) {
			e.Tags = append(e.Tags, gonostr.Tag{"e", eventID})
		})
		event, _, err := zap.Build(settledZap(t, raw))
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if got, ok := tagValue(event, "e"); !ok || got != eventID {
			t.Errorf("e tag = %q (present=%v), want the request's event id", got, ok)
		}
	})

	t.Run("an addressable zap carries a", func(t *testing.T) {
		raw := zapRequest(t, func(e *gonostr.Event) {
			e.Tags = append(e.Tags, gonostr.Tag{"a", coordinate})
		})
		event, _, err := zap.Build(settledZap(t, raw))
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if got, ok := tagValue(event, "a"); !ok || got != coordinate {
			t.Errorf("a tag = %q (present=%v), want the request's coordinate", got, ok)
		}
	})

	t.Run("a zap of a kind-1 note carries k", func(t *testing.T) {
		// o34.20. NIP-57 Appendix A lists k on the REQUEST — "the stringified
		// kind of the target event" — and Appendix E's own example RECEIPT
		// carries ["k","1"]. We copied e and a and dropped k, so a client that
		// reads it off the receipt to know what was zapped had to fall back to
		// fetching the event or parsing the description tag.
		raw := zapRequest(t, func(e *gonostr.Event) {
			e.Tags = append(e.Tags, gonostr.Tag{"e", eventID}, gonostr.Tag{"k", "1"})
		})
		event, _, err := zap.Build(settledZap(t, raw))
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if got, ok := tagValue(event, "k"); !ok || got != "1" {
			t.Errorf("k tag = %q (present=%v), want the request's \"1\"", got, ok)
		}
	})

	t.Run("a request without k produces a receipt without k", func(t *testing.T) {
		// The other half, and the one that stops "carry k" becoming "invent k".
		raw := zapRequest(t, func(e *gonostr.Event) {
			e.Tags = append(e.Tags, gonostr.Tag{"e", eventID})
		})
		event, _, err := zap.Build(settledZap(t, raw))
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if got, ok := tagValue(event, "k"); ok {
			t.Errorf("the receipt carries k = %q; the request had none", got)
		}
	})

	t.Run("a profile zap has neither", func(t *testing.T) {
		raw := zapRequest(t, nil)
		event, _, err := zap.Build(settledZap(t, raw))
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		for _, absent := range []string{"e", "a", "k"} {
			if got, ok := tagValue(event, absent); ok {
				t.Errorf("a profile zap's receipt carries %s = %q; the request had none",
					absent, got)
			}
		}
		// And the ones it must always have.
		var request gonostr.Event
		if err := request.UnmarshalJSON(raw); err != nil {
			t.Fatal(err)
		}
		for tag, want := range map[string]string{
			"p":        strings.Repeat("a", 64),
			"P":        request.PubKey,
			"bolt11":   "lnbcrt210n1example",
			"preimage": strings.Repeat("9", 64),
		} {
			if got, ok := tagValue(event, tag); !ok || got != want {
				t.Errorf("%s tag = %q (present=%v), want %q", tag, got, ok, want)
			}
		}
	})
}

// Criterion 4's other half, from Wave 8's defect in the opposite direction:
// CheckSignature recomputes the id and never reads the id field, so an event
// can carry a valid signature and a wrong id. A receipt whose description tag
// holds one verifies locally and is discarded by every conforming client —
// after the invoice has been paid.
func TestAStoredRequestWithAWrongIdIsRefusedRatherThanPublished(t *testing.T) {
	raw := zapRequest(t, nil)
	var event gonostr.Event
	if err := event.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	event.ID = strings.Repeat("e", 64) // valid signature, wrong id
	tampered, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := zap.Build(settledZap(t, tampered)); err == nil {
		t.Error("a stored zap request with a mismatched id built a receipt; every " +
			"conforming client would discard it, after the invoice was paid")
	}
}

// A payment that was never a zap has no receipt, and saying so is not an error
// the caller has to distinguish from a real failure.
func TestAnOrdinaryPaymentHasNoReceipt(t *testing.T) {
	if _, _, err := zap.Build(store.SettledZap{PaymentHash: "abc"}); err != zap.ErrNotAZap {
		t.Errorf("Build for a non-zap gave %v, want ErrNotAZap", err)
	}
}

// Criterion 6. The receipt goes where the SENDER said to look for it. The pool
// unions these with the operator's defaults; publishing only to the operator's
// own relays produces a receipt the person who paid never sees, which §7 says
// reads as theft just as surely as no receipt at all.
func TestTheSendersRelaysAreCarriedToThePublisher(t *testing.T) {
	_, got, err := zap.Build(settledZap(t, zapRequest(t, nil)))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := []string{"wss://relay.example", "wss://other.example"}
	if len(got) != len(want) {
		t.Fatalf("relays = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("relays = %v, want %v", got, want)
		}
	}
}

// 0vk.15, the end the sender sees: an OVERPAID zap still gets a receipt, and it
// verifies against the MINTED amount.
//
// The failure mode is the receipt's ABSENCE, which is why this asserts it
// exists. A zap that credits the wallet and publishes nothing is invisible to
// the sender and reads as theft (§7) — and the sender did nothing wrong: LND
// accepts overpayment, and the extra millisatoshi is the payer's doing.
func TestAnOverpaidZapStillProducesAReceipt(t *testing.T) {
	raw := zapRequest(t, nil)
	z := settledZap(t, raw)
	z.PaidMsat = z.MintedMsat + 1

	receipt, _, err := zap.Build(z)

	if err != nil {
		t.Fatalf("an overpaid zap produced no receipt: %v\n\nThe wallet was credited and the "+
			"sender sees nothing — §7 calls that indistinguishable from theft", err)
	}
	if receipt.Kind != 9735 {
		t.Errorf("receipt kind %d, want 9735", receipt.Kind)
	}
	// The description tag is the request verbatim, which is what a client
	// re-hashes against the invoice's description_hash. An overpayment changes
	// nothing about it.
	if got := receipt.Tags.GetFirst([]string{"description"}); got == nil || got.Value() != string(raw) {
		t.Error("the receipt's description tag is not the zap request verbatim")
	}
}

// And a GENUINE mismatch is still refused. The fix is to compare against the
// right number, not to stop comparing: Appendix D rule 5 is what stops a request
// claiming one amount while the invoice was minted for another.
func TestAZapRequestThatDisagreesWithTheMintedAmountIsStillRefused(t *testing.T) {
	raw := zapRequest(t, nil)
	z := settledZap(t, raw)
	z.MintedMsat = 50_000
	z.PaidMsat = 50_000

	if _, _, err := zap.Build(z); err == nil {
		t.Fatal("a zap request whose amount tag disagrees with the minted amount was accepted; " +
			"Appendix D rule 5 is what stops a request claiming one amount while the invoice " +
			"was minted for another")
	}
}
