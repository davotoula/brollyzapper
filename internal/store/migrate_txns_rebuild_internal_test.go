package store

import (
	"strings"
	"testing"
)

// Migration 0008 rebuilds `txns`, and `balance_entries` references it.
//
// THIS TEST EXISTS BECAUSE THE FIRST VERSION PASSED EVERYTHING ELSE AND STILL
// BRICKED THE BOX. Every other store test opens a fresh database, where the
// rebuild copies an empty table and no foreign key has anything to resolve. The
// regtest stack found it on the first start against real data:
//
//	migration 0008_...: constraint failed: FOREIGN KEY constraint failed (787)
//
// SQLite's own "other kinds of table schema changes" procedure requires `PRAGMA
// foreign_keys = OFF`, and that pragma is a no-op inside a transaction — which
// is where every migration ran. Two things were tried before the answer:
//
//   - `defer_foreign_keys`, which is NOT a substitute. Dropping a parent runs as
//     an implicit DELETE of every row and records a deferred violation per child
//     row; recreating the parent does not retract them, and they are counted
//     again at COMMIT.
//   - `legacy_alter_table` plus a rename dance, to avoid dropping a referenced
//     table at all. The pragma is not honoured partway through a multi-statement
//     migration, so the rename repointed balance_entries at the table being
//     thrown away.
//
// The answer is the documented one: the runner takes a single connection, sets
// the pragma BEFORE the transaction, and runs `PRAGMA foreign_key_check` inside
// it — so a rebuild that orphans a row rolls back. See rebuildDirective, and
// TestARebuildThatOrphansAChildRowIsRolledBack for the plant that proves the
// check can fail.
//
// A migration that only ever ran against an empty database has been written,
// not tested.
func TestTheTxnsRebuildSurvivesARealLedger(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()

	// A ledger with the shapes that matter: an inbound settlement, an outbound
	// payment, and balance entries pointing at both. The FK from
	// balance_entries.txn_id is what the first version of 0008 tripped over.
	seed := []string{
		`INSERT INTO txns (id, kind, state, amount_msat, payment_hash, created_at)
		   VALUES (1, 'invoice_in', 'settled', 21000, 'inbound-hash', 100)`,
		`INSERT INTO txns (id, kind, state, amount_msat, fee_reserved_msat, payment_hash, created_at)
		   VALUES (2, 'payment_out', 'pending', 5000, 100, 'outbound-hash', 200)`,
		`INSERT INTO txns (id, kind, state, amount_msat, created_at)
		   VALUES (3, 'allocation', 'settled', 1000000, 50)`,
		`INSERT INTO balance_entries (txn_id, amount_msat, reason, created_at)
		   VALUES (3, 1000000, 'allocate', 50)`,
		`INSERT INTO balance_entries (txn_id, amount_msat, reason, created_at)
		   VALUES (1, 21000, 'credit', 100)`,
		`INSERT INTO balance_entries (txn_id, amount_msat, reason, created_at)
		   VALUES (2, -5100, 'reserve', 200)`,
	}
	for _, q := range seed {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("seeding the ledger: %v", err)
		}
	}
	before, err := s.BalanceMsat(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Rewind just this migration and run it over the data.
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM schema_migrations WHERE version = 8`); err != nil {
		t.Fatalf("rewinding the migration ledger: %v", err)
	}
	if err := s.migrate(ctx); err != nil {
		t.Fatalf("re-running migration 0008 over a real ledger: %v", err)
	}

	// Every row survived, with its id — which is what makes the child rows still
	// resolve.
	var rows int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM txns`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 3 {
		t.Errorf("txns has %d rows after the rebuild, want 3", rows)
	}
	if after, err := s.BalanceMsat(ctx); err != nil {
		t.Fatal(err)
	} else if after != before {
		t.Errorf("the balance moved from %d to %d across a schema rebuild", before, after)
	}

	// And the references are intact, which is the assertion the FK failure was
	// really about: foreign_key_check reports nothing.
	orphans, err := s.db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer orphans.Close()
	if orphans.Next() {
		t.Error("a foreign key is dangling after the rebuild; balance_entries rows no longer " +
			"resolve to their txn")
	}

	// A column whose value came across, so a rebuild that silently dropped one
	// would be caught: the outbound row's fee reserve is what SettleSpend
	// refunds from.
	var reserved int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT fee_reserved_msat FROM txns WHERE id = 2`).Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	if reserved != 100 {
		t.Errorf("fee_reserved_msat = %d after the rebuild, want the seeded 100", reserved)
	}

	// The new constraint is in force on the rebuilt table.
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO txns (kind, state, amount_msat, payment_hash, created_at)
		   VALUES ('invoice_in', 'settled', 1, 'inbound-hash', 300)`); err == nil {
		t.Error("a duplicate inbound payment_hash was accepted after the rebuild")
	}
	// The seeded outbound row is PENDING, so a second in-flight payment for the
	// same invoice is refused — see idx_txns_pending_out_hash. A settled one is
	// not, which is the retry utt exists to allow.
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO txns (kind, state, amount_msat, payment_hash, created_at)
		   VALUES ('payment_out', 'pending', 1, 'outbound-hash', 300)`); err == nil {
		t.Error("a second IN-FLIGHT payment for the same invoice was accepted after the rebuild")
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO txns (kind, state, amount_msat, payment_hash, created_at)
		   VALUES ('payment_out', 'failed', 1, 'outbound-hash', 300)`); err != nil {
		t.Errorf("a retry of a resolved payment was refused after the rebuild: %v", err)
	}
}

// The safety net that makes running with foreign keys off acceptable.
//
// With enforcement disabled, a rebuild that loses a row commits silently and the
// child rows dangle for ever — a balance entry pointing at a transaction that
// does not exist, which the ledger would still sum. The runner therefore runs
// PRAGMA foreign_key_check INSIDE the transaction, so the migration rolls back.
//
// Planted, because a check that has only ever passed has been written rather
// than tested: this migration deliberately drops a row on the way across.
func TestARebuildThatOrphansAChildRowIsRolledBack(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()

	for _, q := range []string{
		`INSERT INTO txns (id, kind, state, amount_msat, created_at)
		   VALUES (1, 'allocation', 'settled', 1000, 10)`,
		`INSERT INTO balance_entries (txn_id, amount_msat, reason, created_at)
		   VALUES (1, 1000, 'allocate', 10)`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("seeding: %v", err)
		}
	}

	losing := migration{version: 9999, name: "loses_a_row", sql: rebuildDirective + `
CREATE TABLE txns_rebuilt (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, state TEXT NOT NULL,
  amount_msat INTEGER NOT NULL, fee_msat INTEGER NOT NULL DEFAULT 0,
  fee_reserved_msat INTEGER NOT NULL DEFAULT 0, payment_hash TEXT, bolt11 TEXT, preimage TEXT,
  description TEXT, zap_request TEXT, zap_receipt_id TEXT, nwc_connection_id INTEGER,
  note TEXT, created_at INTEGER NOT NULL, settled_at INTEGER, comment TEXT);
-- The plant: WHERE 1 = 0, so every child row is orphaned.
INSERT INTO txns_rebuilt (id, kind, state, amount_msat, created_at)
  SELECT id, kind, state, amount_msat, created_at FROM txns WHERE 1 = 0;
DROP TABLE txns;
ALTER TABLE txns_rebuilt RENAME TO txns;
`}
	err := applyOne(ctx, s.db, losing)
	if err == nil {
		t.Fatal("a rebuild that orphaned every balance entry was committed; running with " +
			"foreign keys off is only safe because of the check that was supposed to stop this")
	}
	if !strings.Contains(err.Error(), "dangling reference") {
		t.Errorf("error = %v, want it to name the dangling references", err)
	}

	// And the rollback was complete: the row is still there.
	var rows int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM txns`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("txns has %d rows after the rolled-back migration, want the original 1", rows)
	}

	// And foreign keys are ON again on the pooled connection — the pragma is
	// per-connection, the pool is one deep, and this connection went back to it
	// after a FAILURE, which is the path most likely to leak the setting.
	var on string
	if err := s.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&on); err != nil {
		t.Fatal(err)
	}
	if on != "1" {
		t.Errorf("foreign_keys = %q after a failed rebuild; §4's references would be "+
			"decorative from here on", on)
	}
}
