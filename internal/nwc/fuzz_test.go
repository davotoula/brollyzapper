package nwc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/nostr"
)

// How a fuzz input's content is sealed. See FuzzHandle.
const (
	sealAsTagged   = iota // with the scheme handle will choose from the tags, so it decrypts
	sealNothing           // the fuzzed bytes ARE the content: garbage for the decryptor
	sealMismatched        // with the other scheme, so the decrypt runs and fails
	sealModes
)

// FuzzHandle drives §8's request handler with attacker-shaped input PAST PROOF
// (qag).
//
// WHY PAST PROOF. One NWC request with no encryption tag segfaulted the server 32
// times (`xmc`), and it was an authorised client that sent it. A fuzzer feeding
// arbitrary events would spend its whole budget on the first three lines of
// handle — the pubkey, the id and the signature — and never reach the surface
// that crashed. So the fuzzed values are what a PAIRED client controls once those
// checks have passed: the request JSON (method, params), the tag structure, the
// encryption tag, and whether the content is sealed properly at all. Each input
// is then sealed with the pairing's client key, signed, and handed to handle.
//
// A PANIC IS THE FAILURE, and the only assertion. handle has no recover() of its
// own — the one in the tree is run.go's, around dispatchOne, arch-pinned by `xmc`
// B2 — so a panic here reaches the fuzzer as a crash, which is what makes this
// target able to find one. Calling dispatchOne instead would contain the very
// thing this exists to report.
//
// ONE HARNESS PER WORKER, a fresh pairing per input. The store and the fakes are
// expensive and inert across inputs; the connection is not — its rate-limit
// bucket (l3j) would empty after ten inputs and every later one would stop at
// the limiter. `limited` puts an input through the limiter's refusal path on
// purpose instead.
//
// The pairing holds every permission group and sending is on, so pay_invoice's
// ladder is reachable too; a pairing without `pay` would answer RESTRICTED before
// any of it ran.
func FuzzHandle(f *testing.F) {
	for _, seed := range []struct {
		plaintext, tags string
		seal            uint8
		limited         bool
	}{
		// One valid request per method.
		{`{"method":"get_info"}`, `[["p","x"],["encryption","nip44_v2"]]`, sealAsTagged, false},
		{`{"method":"get_balance"}`, `[["p","x"],["encryption","nip44_v2"]]`, sealAsTagged, false},
		{`{"method":"make_invoice","params":{"amount":21000,"description":"tip"}}`,
			`[["p","x"],["encryption","nip44_v2"]]`, sealAsTagged, false},
		{`{"method":"lookup_invoice","params":{"payment_hash":"hash"}}`,
			`[["p","x"],["encryption","nip44_v2"]]`, sealAsTagged, false},
		{`{"method":"list_transactions","params":{"limit":5,"type":"incoming","unpaid":true}}`,
			`[["p","x"],["encryption","nip44_v2"]]`, sealAsTagged, false},
		{`{"method":"pay_invoice","params":{"invoice":"lnbc1fuzzseed","amount":1000}}`,
			`[["p","x"],["encryption","nip44_v2"]]`, sealAsTagged, false},
		// The `xmc` shape: no encryption tag, so NIP-04.
		{`{"method":"get_balance"}`, `[["p","x"]]`, sealAsTagged, false},
		// An encryption tag with no value, and one naming nothing we speak.
		{`{"method":"get_balance"}`, `[["encryption"]]`, sealAsTagged, false},
		{`{"method":"get_balance"}`, `[["encryption","rot13"]]`, sealAsTagged, false},
		// Invalid JSON, sealed properly so it reaches the parser.
		{`{"method":`, `[["encryption","nip44_v2"]]`, sealAsTagged, false},
		// An oversize method name.
		{`{"method":"` + strings.Repeat("m", 4*maxMethodLength) + `"}`,
			`[["encryption","nip44_v2"]]`, sealAsTagged, false},
		// Content that is not a ciphertext, and one sealed under the wrong scheme.
		{`not a ciphertext`, `[["encryption","nip44_v2"]]`, sealNothing, false},
		{`{"method":"get_balance"}`, `[["encryption","nip04"]]`, sealMismatched, false},
		// Over the rate limit.
		{`{"method":"make_invoice","params":{"amount":21000}}`,
			`[["encryption","nip44_v2"]]`, sealAsTagged, true},
	} {
		f.Add(seed.plaintext, seed.tags, seed.seal, seed.limited)
	}

	h := newHarness(f)
	h.grantPay()
	h.sendEnabled(true)
	h.decodesTo("lnbc1fuzzseed", 1000, "a fuzz seed")
	h.service.responseRetries = []time.Duration{time.Millisecond}

	f.Fuzz(func(t *testing.T, plaintext, tagsJSON string, seal uint8, limited bool) {
		var tags gonostr.Tags
		if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
			tags = nil
		}
		conn := newConnection(h.conn.row(), h.counting)
		if limited {
			conn.limit.started, conn.limit.last = true, h.clock.at
		}

		// The scheme handle will choose, read with the same Tags.Find and
		// EncryptionFromTag it uses. A copy of two lines, and if handle's reading
		// ever moves this goes on sealing with the old answer — which would still
		// fuzz, but would reach the decryptor less often, never crash wrongly.
		probe := gonostr.Event{Tags: tags}
		scheme, supported := nostr.NIP04, true
		if tag := probe.Tags.Find("encryption"); tag != nil {
			scheme, supported = nostr.EncryptionFromTag(tag[1])
		}
		if !supported {
			scheme = nostr.NIP44
		}
		content := plaintext
		switch seal % sealModes {
		case sealAsTagged:
			content = sealOrRaw(h, conn, scheme, plaintext)
		case sealMismatched:
			other := nostr.NIP44
			if scheme == nostr.NIP44 {
				other = nostr.NIP04
			}
			content = sealOrRaw(h, conn, other, plaintext)
		}

		event := &gonostr.Event{
			Kind:      KindRequest,
			CreatedAt: gonostr.Timestamp(h.clock.at.Unix()),
			Content:   content,
			Tags:      tags,
		}
		sign(t, h.client, event)
		h.service.handle(t.Context(), conn, event)
	})
}

// sealOrRaw encrypts as a client would, or hands back the plaintext when the
// scheme refuses it — NIP-44 will not seal an empty or oversize message, and that
// input is still worth sending as it stands.
func sealOrRaw(h *harness, conn *connection, scheme nostr.Encryption, plaintext string) string {
	sealed, err := h.client.Encrypt(scheme, conn.row().ServicePubkey, plaintext)
	if err != nil {
		return plaintext
	}
	return sealed
}
