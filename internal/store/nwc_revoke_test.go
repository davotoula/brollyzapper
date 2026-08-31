package store_test

import (
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

// RevokeNWCConnection reports whether it REVOKED anything, and the handler that
// writes §12's audit row depends on the answer.
//
// An UPDATE matching no rows is not an error in SQL, so before this the revoke
// path could not tell "this connection is now revoked" from "there is no such
// connection" — and it wrote a durable `connection.revoke` row either way. An
// audit trail that records revocations which never happened is worse than one
// that records none: it is a trail that has to be distrusted as a whole.
func TestRevokingReportsWhetherAnythingWasRevoked(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0).UTC()

	conn, err := s.CreateNWCConnection(t.Context(), store.NWCConnection{
		Name:           "a wallet app",
		ServicePrivkey: secret.New("aa"),
		ServicePubkey:  "service-pub",
		ClientPubkey:   "client-pub",
		ClientSecret:   secret.New("bb"),
		Relays:         []string{"wss://relay.example"},
		Permissions:    store.DefaultPermissions(),
		CreatedAt:      at,
	}, store.DefaultLimits)
	if err != nil {
		t.Fatalf("CreateNWCConnection: %v", err)
	}

	revoked, err := s.RevokeNWCConnection(t.Context(), conn.ID)
	if err != nil {
		t.Fatalf("RevokeNWCConnection: %v", err)
	}
	if !revoked {
		t.Error("revoking a live connection reported that nothing changed")
	}

	// Again. The row is already revoked, so there is nothing left to revoke and
	// nothing to claim in the trail.
	revoked, err = s.RevokeNWCConnection(t.Context(), conn.ID)
	if err != nil {
		t.Fatalf("RevokeNWCConnection (second): %v", err)
	}
	if revoked {
		t.Error("revoking an ALREADY revoked connection reported a revocation; the audit row " +
			"it writes would say a pairing stopped working at a moment when nothing happened")
	}

	// An id that was never a connection.
	revoked, err = s.RevokeNWCConnection(t.Context(), conn.ID+999_999)
	if err != nil {
		t.Fatalf("RevokeNWCConnection (absent): %v", err)
	}
	if revoked {
		t.Error("revoking an id that does not exist reported a revocation")
	}
}
