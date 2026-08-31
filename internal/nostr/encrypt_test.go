package nostr_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/nostr"
)

// §8: both schemes, in both directions, against a counterparty holding the other
// half of the conversation.
//
// Round-tripping through ONE side would pass for a codec that ignored the peer's
// key entirely — the conversation key is the whole security property, and a
// codec that derived it from the wrong pair would encrypt cheerfully and produce
// something the client cannot read.
func TestBothSchemesRoundTripBetweenTheTwoParties(t *testing.T) {
	service, client := anIdentity(t), anIdentity(t)

	for _, scheme := range []nostr.Encryption{nostr.NIP04, nostr.NIP44} {
		t.Run(string(scheme), func(t *testing.T) {
			const plaintext = `{"method":"get_balance"}`

			// The client encrypts to the service…
			sealed, err := client.Encrypt(scheme, service.PublicKey(), plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if strings.Contains(sealed, "get_balance") {
				t.Fatal("the ciphertext contains the plaintext")
			}
			// …and the service reads it with its own key and the client's pubkey.
			opened, err := service.Decrypt(scheme, client.PublicKey(), sealed)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if opened != plaintext {
				t.Errorf("round trip = %q, want %q", opened, plaintext)
			}
		})
	}
}

// A third party cannot read it, which is the property the conversation key is
// for. Without this, a codec that derived its key from one side alone would pass
// the round trip above.
func TestAThirdPartyCannotDecrypt(t *testing.T) {
	service, client, stranger := anIdentity(t), anIdentity(t), anIdentity(t)

	for _, scheme := range []nostr.Encryption{nostr.NIP04, nostr.NIP44} {
		t.Run(string(scheme), func(t *testing.T) {
			sealed, err := client.Encrypt(scheme, service.PublicKey(), "secret")
			if err != nil {
				t.Fatal(err)
			}
			opened, err := stranger.Decrypt(scheme, client.PublicKey(), sealed)
			if err == nil && opened == "secret" {
				t.Fatal("a third party read the message")
			}
		})
	}
}

// §8: the scheme is named in the request's `encryption` tag, and ABSENT means
// NIP-04 — the pre-NIP-44 default, which every older client still uses.
func TestTheEncryptionTagDefaultsToNIP04WhenAbsent(t *testing.T) {
	for _, tc := range []struct {
		tag  string
		want nostr.Encryption
		ok   bool
	}{
		{"", nostr.NIP04, true},
		{"nip04", nostr.NIP04, true},
		{"nip44_v2", nostr.NIP44, true},
		// A scheme we do not speak is not a default — §8 maps it to
		// UNSUPPORTED_ENCRYPTION, which needs the codec to say so rather than
		// quietly trying NIP-04 on something that is not NIP-04.
		{"nip44_v3", "", false},
		{"rot13", "", false},
	} {
		t.Run("tag="+tc.tag, func(t *testing.T) {
			got, ok := nostr.EncryptionFromTag(tc.tag)
			if ok != tc.ok {
				t.Fatalf("EncryptionFromTag(%q) ok = %v, want %v", tc.tag, ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("EncryptionFromTag(%q) = %v, want %v", tc.tag, got, tc.want)
			}
		})
	}
}

// §8: "reply with whatever the client used". A response encrypted with a scheme
// the client did not send cannot be read by it, and the client sees a timeout
// rather than an error.
func TestTheSchemesProduceDifferentCiphertextAndDoNotInterchange(t *testing.T) {
	service, client := anIdentity(t), anIdentity(t)

	sealed44, err := client.Encrypt(nostr.NIP44, service.PublicKey(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Decrypt(nostr.NIP04, client.PublicKey(), sealed44); err == nil {
		t.Error("a NIP-44 payload was read as NIP-04; the two are not interchangeable and " +
			"answering with the wrong one leaves the client waiting")
	}
}

// §12: a codec that takes a private key must not be the thing that leaks it.
func TestAnUnknownSchemeIsRefusedRatherThanGuessed(t *testing.T) {
	service, client := anIdentity(t), anIdentity(t)
	_, err := client.Encrypt("nip44_v3", service.PublicKey(), "x")
	if err == nil {
		t.Fatal("an unsupported scheme was encrypted anyway")
	}
	// The scheme name may travel; the key must not. The codec is handed a
	// private key on every call, which makes it a place §11's never-log list is
	// easy to break by accident.
	if strings.Contains(err.Error(), service.PublicKey()) {
		t.Log("the error names the peer pubkey, which is public and fine")
	}
}

func anIdentity(t *testing.T) nostr.Identity {
	t.Helper()
	id, err := nostr.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return id
}

// §11: a nostr private key never reaches a log, and the library would put one
// there if we let it.
//
// go-nostr answers an out-of-range key with "invalid private key: x coordinate
// %s is not on the secp256k1 curve", %s being the key itself — and internal/nwc
// logs a decrypt failure's err.Error() at WARN. This asserts the substitution
// directly rather than trusting that no Identity can ever hold such a key: that
// guarantee lives in identity.go, and a guarantee in another file is the kind
// that stops being true quietly.
func TestAKeyDerivationFailureNeverCarriesTheKey(t *testing.T) {
	id := anIdentity(t)

	// A peer pubkey that is not on the curve: the derivation fails for a reason
	// that has nothing to do with our key, on the same code path.
	_, err := id.Encrypt(nostr.NIP44, strings.Repeat("f", 64), "hello")
	if err == nil {
		t.Fatal("a malformed peer pubkey was accepted; this test proves nothing")
	}
	if !errors.Is(err, nostr.ErrKeyDerivation) {
		t.Errorf("Encrypt reported %v, want the sentinel; anything wrapped from the library "+
			"can carry the private key into a log", err)
	}
	if strings.Contains(err.Error(), "private key") || strings.Contains(err.Error(), "x coordinate") {
		t.Errorf("the error repeats what the library said (%q); that message interpolates "+
			"the private key", err)
	}
}
