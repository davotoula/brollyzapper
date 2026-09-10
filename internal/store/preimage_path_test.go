package store_test

import (
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

// The receive path end to end, as a secret.String the whole way (twt,
// criterion 4).
//
// WHAT THIS ADDS OVER THE ROUND-TRIP TEST. That one proves the type can go into
// sqlite and come back. This proves the PATH does it: the value goes in through
// CreditSettledInvoice, lands in txns.preimage, and comes back out of both
// readers — SettledZapFor, which internal/zap builds the NIP-57 receipt from, and
// Txns, which internal/nwc answers lookup_invoice from. Before twt the value was
// a plain string at every one of those seams and was wrapped at the very end; the
// point of the bead is that nothing between them can hold it as a string, and the
// point of this test is that the change did not lose it on the way.
func TestAPreimageSurvivesTheReceivePathAsASecret(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	const hash = "path-hash"
	preimage := secret.New("aabbccddeeff00112233445566778899")

	invoice := openInvoice(hash, 21_000, time.Unix(1_700_003_600, 0).UTC())
	invoice.ZapRequest = `{"kind":9734,"tags":[["amount","21000"]]}`
	if err := s.CreateInvoice(ctx, invoice); err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}
	settledAt := time.Unix(1_700_000_000, 0).UTC()
	if _, err := s.CreditSettledInvoice(ctx, hash, preimage, 21_000, settledAt, true); err != nil {
		t.Fatalf("CreditSettledInvoice: %v", err)
	}

	zap, err := s.SettledZapFor(ctx, hash)
	if err != nil {
		t.Fatalf("SettledZapFor: %v", err)
	}
	if got := zap.Preimage.Reveal(); got != preimage.Reveal() {
		t.Errorf("SettledZapFor returned preimage %q, want %q — internal/zap builds NIP-57's "+
			"preimage tag from this, so an empty one is a receipt the sender cannot verify",
			got, preimage.Reveal())
	}

	// The other reader, which NIP-47's lookup_invoice answers from.
	txns, err := s.Txns(ctx, store.TxnFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Txns: %v", err)
	}
	var found bool
	for _, txn := range txns {
		if txn.PaymentHash != hash {
			continue
		}
		found = true
		if got := txn.Preimage.Reveal(); got != preimage.Reveal() {
			t.Errorf("Txns returned preimage %q, want %q", got, preimage.Reveal())
		}
	}
	if !found {
		t.Fatalf("no txn row for %s; the settlement did not land", hash)
	}

	// THE ABSENT-PREIMAGE CASE IS NOT HERE, deliberately. It was, and it could not
	// fail: both readers select COALESCE(t.preimage, ''), which flattens NULL and ''
	// to the same answer, so a Valuer returning "" for the zero value would have
	// left IsZero() true and the assertion green. The property is real and is
	// asserted where it can be seen — secretsql_internal_test.go asks the column
	// directly with `SELECT v IS NULL`.

}

// The other half of the Valuer's nil-for-zero, which is NOT a no-op (twt).
//
// nwc_connections.service_privkey and client_secret are TEXT NOT NULL and were
// bound as .Reveal() before this bead, so an empty secret stored ” and the
// insert succeeded — a pairing with no service key, which cannot sign a single
// NIP-47 response. Binding the secret.String directly makes the same call violate
// the constraint, which is the right outcome by the wrong route: a raw driver
// error reaches the operator as a bare refusal.
//
// So the refusal says what is wrong, and this is what pins it. Unreachable from
// the UI today — both halves are minted by nostr.NewPairingKey — which is why it
// needs a test and not a comment.
func TestAConnectionWithAMissingKeyHalfIsRefusedByName(t *testing.T) {
	s, _ := open(t)
	base := store.NWCConnection{
		Name:           "half a pairing",
		ServicePrivkey: secret.New("aa"),
		ServicePubkey:  "service-pub",
		ClientPubkey:   "client-pub",
		ClientSecret:   secret.New("bb"),
		Relays:         []string{"wss://relay.example"},
		CreatedAt:      time.Unix(1_700_000_000, 0).UTC(),
	}
	for _, c := range []struct {
		name string
		of   func(store.NWCConnection) store.NWCConnection
	}{
		{"no service key", func(c store.NWCConnection) store.NWCConnection {
			c.ServicePrivkey = secret.String{}
			return c
		}},
		{"no client secret", func(c store.NWCConnection) store.NWCConnection {
			c.ClientSecret = secret.String{}
			return c
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := s.CreateNWCConnection(t.Context(), c.of(base), store.DefaultLimits)
			if err == nil {
				t.Fatal("a connection with a missing key half was created; it cannot sign a " +
					"NIP-47 response and the operator has no way to tell")
			}
			if !strings.Contains(err.Error(), "both key halves are required") {
				t.Errorf("refused with %q; the operator sees this as a bare flash unless the "+
					"message says what is wrong, and a NOT NULL constraint error does not", err)
			}
		})
	}

	// And the whole pairing still works, so the guard did not refuse the fix.
	if _, err := s.CreateNWCConnection(t.Context(), base, store.DefaultLimits); err != nil {
		t.Fatalf("a complete pairing was refused: %v", err)
	}
}
