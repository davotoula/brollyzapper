package nostr_test

import (
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/nostr"
)

// doy.5: a pubkey becomes the npub a person can actually compare.
func TestNpubEncodesAPubkey(t *testing.T) {
	// The secp256k1 generator's x-coordinate: a valid 32-byte hex string with a
	// stable, checkable encoding.
	const pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

	npub, err := nostr.Npub(pubkey)
	if err != nil {
		t.Fatalf("Npub(%q): %v", pubkey, err)
	}
	if !strings.HasPrefix(npub, "npub1") {
		t.Errorf("Npub = %q, want a bech32 npub", npub)
	}
	if strings.Contains(npub, pubkey) {
		t.Errorf("Npub = %q, which still contains the hex — nothing was encoded", npub)
	}
}

// And anything that is not a pubkey is an ERROR, not a plausible-looking string.
//
// The caller decides what to do about it; a primitive that returned "" would make
// a corrupt pubkey and a valid one indistinguishable to everything downstream.
func TestNpubRefusesAnythingThatIsNotAPubkey(t *testing.T) {
	for _, bad := range []string{
		"",
		"not hex",
		"79be667e",                  // too short
		strings.Repeat("z", 64),     // right length, not hex
		"npub1already",              // already encoded
		"<script>alert(1)</script>", // what a page must never be handed
		strings.Repeat("7", 63),     // one character short of 32 bytes
	} {
		if got, err := nostr.Npub(bad); err == nil {
			t.Errorf("Npub(%q) = %q with no error", bad, got)
		}
	}
}
