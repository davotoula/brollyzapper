package nostr

import (
	"fmt"

	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// Npub encodes a 32-byte hex pubkey in NIP-19's bech32 form.
//
// The form a person can compare against what their own client shows them. Hex is
// the form that only matches if you read all sixty-four characters, which nobody
// does.
//
// An ERROR rather than an empty string for a bad input, because this is a
// primitive and its callers are the ones who know what to do about it: a page
// wants to render nothing, and anything else would want to say so. Swallowing
// the difference here would make a corrupt pubkey and a valid one indistinguishable
// to every future caller (review).
//
// The eliding for display is NOT here. How much of an npub fits beside an amount
// and a date is a fact about a table, and it lives with the table.
func Npub(pubkey string) (string, error) {
	if !gonostr.IsValid32ByteHex(pubkey) {
		return "", fmt.Errorf("nostr: %q is not a 32-byte hex pubkey", pubkey)
	}
	return nip19.EncodePublicKey(pubkey)
}
