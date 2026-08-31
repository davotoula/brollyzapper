package store_test

import (
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

// d24.21 / ruling B: a connection remembers what it was last refused, and when.
//
// The record is DURABLE and on the connection because of what d24.22 measured:
// Amethyst renders RESTRICTED and SWALLOWS QUOTA_EXCEEDED, so a user whose
// payment met its budget is told nothing at all and the operator becomes the
// only possible explainer. Before this the only trace anywhere was one INFO line
// in a rotating log, and the operator's answer to "my zap did not work" was to
// read a database table over SSH.
//
// It is NOT an audit row: d24.14's ruling 3 stands, and the trail stays about
// capability boundaries rather than about honest clients meeting their own
// budget.
func TestAConnectionRemembersItsLastRefusal(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0).UTC()
	conn := aConnection(t, s, at)

	// Never refused: no code and no time, which the page has to be able to tell
	// apart from "refused at the zero time".
	if conn.LastRefusalCode != "" || !conn.LastRefusalAt.IsZero() {
		t.Errorf("a new connection already carries a refusal: %q at %v",
			conn.LastRefusalCode, conn.LastRefusalAt)
	}

	first := at.Add(time.Hour)
	if err := s.RecordNWCRefusal(t.Context(), conn.ID, "QUOTA_EXCEEDED",
		"this payment would exceed the connection's budget for this period", first); err != nil {
		t.Fatalf("RecordNWCRefusal: %v", err)
	}
	stored, found, err := s.NWCConnection(t.Context(), conn.ID)
	if err != nil || !found {
		t.Fatalf("NWCConnection: found=%v err=%v", found, err)
	}
	if stored.LastRefusalCode != "QUOTA_EXCEEDED" || !stored.LastRefusalAt.Equal(first) {
		t.Errorf("the connection carries %q at %v, want QUOTA_EXCEEDED at %v",
			stored.LastRefusalCode, stored.LastRefusalAt, first)
	}
	// THE MESSAGE AS WELL, because one code has six meanings: RESTRICTED covers
	// a permission this pairing lacks and also sending being off, and only the
	// sentence the service composed says which.
	if stored.LastRefusalMessage != "this payment would exceed the connection's budget for this period" {
		t.Errorf("the connection carries the message %q", stored.LastRefusalMessage)
	}

	// LAST, not first: the operator is asking about the refusal that just
	// happened, and a field that kept the oldest one would answer a question
	// nobody asked.
	second := first.Add(time.Minute)
	if err := s.RecordNWCRefusal(t.Context(), conn.ID, "RESTRICTED",
		"sending is disabled on this node", second); err != nil {
		t.Fatalf("RecordNWCRefusal (second): %v", err)
	}
	stored, _, err = s.NWCConnection(t.Context(), conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.LastRefusalCode != "RESTRICTED" || !stored.LastRefusalAt.Equal(second) {
		t.Errorf("after a second refusal the connection carries %q at %v, want RESTRICTED at %v",
			stored.LastRefusalCode, stored.LastRefusalAt, second)
	}
	if stored.LastRefusalMessage != "sending is disabled on this node" {
		t.Errorf("the second refusal's message is %q; the LAST message must travel with the "+
			"last code, or the page explains one refusal with another's words",
			stored.LastRefusalMessage)
	}

	// It reaches the page's own reader too, which is a different query.
	all, err := s.AllNWCConnections(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].LastRefusalCode != "RESTRICTED" {
		t.Errorf("AllNWCConnections — what the Connections page reads — lost the refusal: %+v", all)
	}
}

// A refusal recorded against an id that is not a connection changes nothing and
// says so. The service records refusals from a worker goroutine, and a row that
// was revoked and deleted underneath it must not become an error the operator
// sees.
func TestRecordingARefusalForAnAbsentConnectionIsNotAnError(t *testing.T) {
	s, _ := open(t)
	if err := s.RecordNWCRefusal(t.Context(), 999_999, "QUOTA_EXCEEDED", "over budget",
		time.Unix(1_700_000_000, 0).UTC()); err != nil {
		t.Errorf("recording a refusal for an absent connection: %v", err)
	}
}

func aConnection(t *testing.T, s *store.Store, at time.Time) store.NWCConnection {
	t.Helper()
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
	return conn
}
