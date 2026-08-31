package nostr

import (
	"errors"
	"fmt"

	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// Encryption is one of NIP-47's two payload schemes (§8).
type Encryption string

const (
	// NIP04 is the original scheme, and the DEFAULT: §8 says an absent
	// `encryption` tag means NIP-04, which is what every client written before
	// NIP-44 still sends.
	NIP04 Encryption = "nip04"
	// NIP44 is nip44_v2, the versioned scheme. The version is part of the name
	// on the wire, so a future v3 is a different string and lands in the
	// unsupported branch rather than being decrypted as v2.
	NIP44 Encryption = "nip44_v2"
)

// SupportedEncryption is what the info event advertises, most-preferred first
// (§8: `["encryption", "nip44_v2 nip04"]`).
var SupportedEncryption = []Encryption{NIP44, NIP04}

// EncryptionFromTag reads the scheme named in a request's `encryption` tag.
//
// An EMPTY tag is NIP-04, per §8 — the tag postdates the scheme, so its absence
// is information rather than a gap. Anything else we do not speak is refused
// rather than guessed: §8 maps that to UNSUPPORTED_ENCRYPTION, and the caller
// can only send that if this says no. Trying NIP-04 on a payload that is not
// NIP-04 would produce a decrypt failure indistinguishable from a wrong key.
func EncryptionFromTag(tag string) (Encryption, bool) {
	switch Encryption(tag) {
	case "", NIP04:
		return NIP04, true
	case NIP44:
		return NIP44, true
	default:
		return "", false
	}
}

// Encrypt seals plaintext for peerPubkey, using this identity's private half.
//
// A METHOD, so the private key never leaves the type. Identity.Sign is the same
// shape and for the same reason (§12): a package-level Encrypt(privkey, …)
// would put the key in every caller's hands and on every caller's stack, and the
// arch rule that requires secret-bearing values to be secret.String cannot
// follow it once it has been Revealed into a parameter.
func (i Identity) Encrypt(scheme Encryption, peerPubkey, plaintext string) (string, error) {
	switch scheme {
	case NIP04:
		shared, err := nip04.ComputeSharedSecret(peerPubkey, i.private.Reveal())
		if err != nil {
			return "", ErrKeyDerivation
		}
		sealed, err := nip04.Encrypt(plaintext, shared)
		if err != nil {
			return "", fmt.Errorf("nostr: nip04 encrypt: %w", err)
		}
		return sealed, nil
	case NIP44:
		key, err := nip44.GenerateConversationKey(peerPubkey, i.private.Reveal())
		if err != nil {
			return "", ErrKeyDerivation
		}
		sealed, err := nip44.Encrypt(plaintext, key)
		if err != nil {
			return "", fmt.Errorf("nostr: nip44 encrypt: %w", err)
		}
		return sealed, nil
	default:
		return "", unsupported(scheme)
	}
}

// Decrypt opens a payload from peerPubkey.
//
// The scheme is the caller's to determine — from the request's `encryption` tag,
// via EncryptionFromTag — and NOT sniffed from the ciphertext. §8 says reply
// with whatever the client used, so the scheme is a fact about the conversation
// that has to travel; deducing it from the bytes would make a malformed NIP-44
// payload look like a NIP-04 one with a bad key.
func (i Identity) Decrypt(scheme Encryption, peerPubkey, ciphertext string) (string, error) {
	switch scheme {
	case NIP04:
		shared, err := nip04.ComputeSharedSecret(peerPubkey, i.private.Reveal())
		if err != nil {
			return "", ErrKeyDerivation
		}
		opened, err := nip04.Decrypt(ciphertext, shared)
		if err != nil {
			return "", fmt.Errorf("nostr: nip04 decrypt: %w", err)
		}
		return opened, nil
	case NIP44:
		key, err := nip44.GenerateConversationKey(peerPubkey, i.private.Reveal())
		if err != nil {
			return "", ErrKeyDerivation
		}
		opened, err := nip44.Decrypt(ciphertext, key)
		if err != nil {
			return "", fmt.Errorf("nostr: nip44 decrypt: %w", err)
		}
		return opened, nil
	default:
		return "", unsupported(scheme)
	}
}

// ErrKeyDerivation replaces what the library said, and the substitution is the
// point — this is the ONE error in this file that is not wrapped (§11, §12).
//
// go-nostr's GenerateConversationKey answers an out-of-range key with
// "invalid private key: x coordinate %s is not on the secp256k1 curve", where
// %s is OUR PRIVATE KEY IN HEX. Wrapping that with %w and logging err.Error()
// — which internal/nwc does, at WARN, on a decrypt failure — would put a nostr
// private key in the log, which §11 lists as never-log.
//
// Unreachable today: nostr.Parse proves a key by signing with it before an
// Identity exists, so no Identity holds a key these functions would reject. That
// is a guarantee living in another file, which is exactly the kind that stops
// being true quietly. Both schemes get the same treatment for the same reason:
// nip04's own key error is "error decoding sender private key: %w", one wrap
// away from the same shape.
//
// Nothing is lost. The peer pubkey is a public value and is in scope at every
// call site; the only thing the library could add is the key.
// Exported so a test can assert the substitution held, and so a caller that
// ever needs to tell "this key cannot be used" from "this payload is bad" has
// the seam without parsing text.
var ErrKeyDerivation = errors.New("nostr: the conversation key could not be derived")

// unsupported names the scheme and nothing else. The key is in scope at every
// call site above, and §11 lists nostr private keys as never-log.
func unsupported(scheme Encryption) error {
	return fmt.Errorf("nostr: unsupported encryption scheme %q", scheme)
}
