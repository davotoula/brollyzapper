package store

import (
	"context"
	"database/sql"
	"io/fs"
	"path/filepath"
	"testing"
)

// Migration 0012 turns one relay into a list of one, and this is the test the
// README's rule demands: a migration that touches DATA needs a test that seeds
// the shapes it will meet on a real box.
//
// THE FAILURE SHAPE IT GUARDS IS 0004'S, and the conclusion is the opposite one.
// That migration renamed the rate-limit pair and carried the stored values across
// — correct for a number an operator typed, and wrong for one nobody chose,
// because the rename had changed what the number MEANT. Every upgraded box then
// ran a backstop six times tighter than designed, and the first 429 came at
// request 11 where the design expects about 60.
//
// Here the meaning does NOT change: the same relay, in a list of one, is the same
// pairing pointed at the same host. So what this asserts is precisely that
// nothing moved — the URL is byte-identical, it is alone in the list, and every
// other column of the row came across untouched. A migrated pairing is exactly as
// fragile as it was yesterday and no more, which is also what the Connections
// page has to say about it.
//
// It applies migrations 1..11, seeds rows as an upgraded box holds them, and then
// applies 12 over the top. The rewind-and-re-run trick the other data-migration
// tests use is available too — 0012 is a rebuild, so it is re-runnable — but
// building the OLD schema and stepping onto the new one is the thing a box
// actually does, and it is the only version that would have caught a carry
// written against a column that no longer exists.
func TestTheRelayListMigrationCarriesTheRelayUnchanged(t *testing.T) {
	ctx := t.Context()
	db, all := databaseAtVersion(t, 11)

	// Three rows an upgraded box can hold: an ordinary pairing, a revoked one
	// that must still migrate (the page renders it), and a row with NO relay —
	// which 0009 made possible with its `DEFAULT ''` and which the service reads
	// as "this pairing cannot be served".
	seed := []string{
		`INSERT INTO nwc_connections
		   (id, name, service_privkey, service_pubkey, client_pubkey, client_secret, relay,
		    permissions, budget_msat, budget_used_msat, created_at, last_used_at, revoked,
		    last_refusal_code, last_refusal_message, last_refusal_at)
		 VALUES (1, 'the phone', 'priv-1', 'pub-1', 'client-1', 'secret-1',
		         'wss://relay.damus.io', '["info","balance"]', 100000, 2500, 1700000000,
		         1700000900, 0, 'QUOTA_EXCEEDED', 'over budget', 1700000800)`,
		`INSERT INTO nwc_connections
		   (id, name, service_privkey, service_pubkey, client_pubkey, client_secret, relay,
		    permissions, created_at, revoked)
		 VALUES (2, 'a revoked pairing', 'priv-2', 'pub-2', 'client-2', 'secret-2',
		         'wss://nos.lol', '["info"]', 1700000001, 1)`,
		`INSERT INTO nwc_connections
		   (id, name, service_privkey, service_pubkey, client_pubkey, client_secret, relay,
		    permissions, created_at)
		 VALUES (3, 'a pairing with no relay', 'priv-3', 'pub-3', 'client-3', 'secret-3',
		         '', '["info"]', 1700000002)`,
		// A cache row that REFERENCES a connection: nwc_handled_requests has the
		// foreign key that makes 0012 a rebuild rather than an ALTER, and 0008's
		// lesson is that a rebuild tested only against an empty table has been
		// written rather than tested.
		`INSERT INTO nwc_handled_requests (event_id, connection_id, method, response_json, handled_at)
		 VALUES ('event-1', 1, 'get_balance', '{"result_type":"get_balance"}', 1700000900)`,
	}
	for _, q := range seed {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("seeding the pre-0012 rows: %v", err)
		}
	}

	if err := applyMigrations(ctx, db, all); err != nil {
		t.Fatalf("applying 0012 over real rows: %v", err)
	}

	// THE CARRY: the same URL, alone, byte for byte.
	for id, want := range map[int]string{1: `["wss://relay.damus.io"]`, 2: `["wss://nos.lol"]`} {
		var relays string
		if err := db.QueryRowContext(ctx,
			`SELECT relays FROM nwc_connections WHERE id = ?`, id).Scan(&relays); err != nil {
			t.Fatalf("reading connection %d: %v", id, err)
		}
		if relays != want {
			t.Errorf("connection %d migrated to %s, want %s — the same relay in a list of one, "+
				"which is the same pairing pointed at the same host", id, relays, want)
		}
	}

	// A row with NO relay becomes an EMPTY list, not a list containing nothing.
	// `[""]` would turn "this pairing is broken" into "this pairing has one relay,
	// which is the empty string" — a distinction prepare() acts on.
	var empty string
	if err := db.QueryRowContext(ctx,
		`SELECT relays FROM nwc_connections WHERE id = 3`).Scan(&empty); err != nil {
		t.Fatal(err)
	}
	if empty != `[]` {
		t.Errorf("a row with no relay migrated to %s, want [] — a pairing that cannot be "+
			"served must not read as one with a relay whose address is nothing", empty)
	}

	// EVERY OTHER COLUMN came across. A rebuild is a rename in disguise and this
	// is the half that catches a column retyped from memory or silently dropped:
	// the budget is money, the refusal is what the Connections page explains a
	// failure with, and `revoked` is a security property.
	var (
		name, permissions, refusalCode, refusalMessage string
		budget, used, createdAt, lastUsed, refusalAt   int64
		revoked                                        int
	)
	if err := db.QueryRowContext(ctx,
		`SELECT name, permissions, budget_msat, budget_used_msat, created_at, last_used_at,
		        revoked, last_refusal_code, last_refusal_message, last_refusal_at
		   FROM nwc_connections WHERE id = 1`).Scan(&name, &permissions, &budget, &used,
		&createdAt, &lastUsed, &revoked, &refusalCode, &refusalMessage, &refusalAt); err != nil {
		t.Fatalf("reading the migrated row: %v", err)
	}
	for _, check := range []struct {
		field     string
		got, want any
	}{
		{"name", name, "the phone"},
		{"permissions", permissions, `["info","balance"]`},
		{"budget_msat", budget, int64(100000)},
		{"budget_used_msat", used, int64(2500)},
		{"created_at", createdAt, int64(1700000000)},
		{"last_used_at", lastUsed, int64(1700000900)},
		{"revoked", revoked, 0},
		{"last_refusal_code", refusalCode, "QUOTA_EXCEEDED"},
		{"last_refusal_message", refusalMessage, "over budget"},
		{"last_refusal_at", refusalAt, int64(1700000800)},
	} {
		if check.got != check.want {
			t.Errorf("%s came across as %v, want %v", check.field, check.got, check.want)
		}
	}
	// And the revoked one is still revoked, which is the column whose loss would
	// be a revocation undone by an upgrade.
	if err := db.QueryRowContext(ctx,
		`SELECT revoked FROM nwc_connections WHERE id = 2`).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked != 1 {
		t.Error("a revoked pairing came back to life across the migration")
	}

	// The child row still resolves. This is what the rebuild directive and the
	// runner's foreign_key_check inside the transaction exist for, and 0008
	// found it the expensive way on a real box.
	orphans, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer orphans.Close()
	if orphans.Next() {
		t.Error("a foreign key is dangling after the rebuild; nwc_handled_requests rows no " +
			"longer resolve to their connection")
	}
}

// databaseAtVersion opens a database with the first n migrations applied, and
// returns it with the FULL list so the caller can step onto the next one.
//
// A raw database rather than a Store: Open runs every migration, which is the one
// thing a test about an upgrade cannot have.
func databaseAtVersion(t *testing.T, n int) (*sql.DB, []migration) {
	t.Helper()
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	all, err := loadMigrations(sub)
	if err != nil {
		t.Fatal(err)
	}
	var upTo []migration
	for _, m := range all {
		if m.version <= n {
			upTo = append(upTo, m)
		}
	}
	if len(upTo) != n {
		t.Fatalf("found %d migrations at or below version %d, want %d — this test names a "+
			"version and the ledger has moved under it", len(upTo), n, n)
	}
	db, err := sql.Open(driverName, "file:"+filepath.Join(t.TempDir(), "upgrade.db")+
		"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := applyMigrations(context.Background(), db, upTo); err != nil {
		t.Fatalf("building a database at version %d: %v", n, err)
	}
	return db, all
}
