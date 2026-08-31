package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/logging"
)

// BrollyZap-dsi: migration 0012 must survive a database it did not create.
//
// THE REPRODUCTION IS THE POINT. 0012 rebuilds nwc_connections, so the runner
// runs foreign_key_check inside the transaction and refuses to commit on a
// dangling reference — and on the reference box's own volume that turned a
// latent inconsistency into "the app does not start": 0 connections, 14 orphaned
// txns rows, 111 orphaned nwc_handled_requests rows, no operator remedy short of
// hand-editing sqlite.
//
// Wave 29's test seeded the shapes its author expected. It did not seed an
// ORPHANED child row, which is the shape a real box actually had.
func TestTheRelayMigrationSurvivesOrphansItDidNotCreate(t *testing.T) {
	ctx := t.Context()
	db, all := databaseAtVersion(t, 11)
	seedOrphans(t, db)

	if err := applyMigrations(ctx, db, all); err != nil {
		t.Fatalf("0012 refused a database holding orphaned rows: %v\n\nThis is the crash loop: "+
			"the server calls this from Open, so it does not start at all", err)
	}

	// CRITERION 2, and it is the one that matters: the payments are STILL THERE,
	// unlinked rather than deleted. An orphaned txns row is a payment that really
	// happened, and money history is not a migration's to discard.
	var kept, unlinked int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE nwc_connection_id IS NULL)
	                                     FROM txns`).Scan(&kept, &unlinked); err != nil {
		t.Fatal(err)
	}
	if kept != 3 {
		t.Errorf("%d txns rows survive, want 3 — a migration must never delete a payment", kept)
	}
	if unlinked != 2 {
		t.Errorf("%d txns rows have no connection, want 2 (the orphan and the one that already "+
			"had none); NULL already means \"no connection recorded\" and the page renders it",
			unlinked)
	}
	// And the amounts are untouched: the criterion is that the history is
	// intact, not merely that the migration passed.
	var amount int64
	if err := db.QueryRowContext(ctx,
		`SELECT amount_msat FROM txns WHERE payment_hash = 'orphaned-payment'`).Scan(&amount); err != nil {
		t.Fatalf("the orphaned payment is gone: %v", err)
	}
	if amount != 4_200 {
		t.Errorf("the orphaned payment's amount is %d msat, want 4200", amount)
	}
	// The payment that DID have a live connection keeps it. A repair that
	// unlinked everything would pass every assertion above.
	var linked int
	if err := db.QueryRowContext(ctx,
		`SELECT nwc_connection_id FROM txns WHERE payment_hash = 'linked-payment'`).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if linked != 1 {
		t.Errorf("a payment with a LIVE connection was unlinked to %d, want 1", linked)
	}

	// CRITERION 3: the orphaned replay-cache rows are gone, and the live one is
	// not. connection_id is NOT NULL there, so nulling is unavailable — and the
	// table is a cache with its own retention sweep, not a record of anything.
	var events []string
	rows, err := db.QueryContext(ctx, `SELECT event_id FROM nwc_handled_requests ORDER BY event_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		events = append(events, id)
	}
	if len(events) != 1 || events[0] != "live-event" {
		t.Errorf("the replay cache holds %v, want only [live-event] — the orphans go and the "+
			"one that still resolves stays", events)
	}

	// And the database is consistent, which is what the runner was refusing to
	// commit without.
	assertNoDanglingReferences(t, db)
}

// CRITERION 4: a clean database migrates exactly as before, repairing nothing.
//
// Both halves matter. A repair that always reports work would put a line in
// front of every operator on every upgrade and train them to ignore it; a repair
// that always reports nothing is a no-op wearing a log statement.
func TestACleanDatabaseIsNotRepairedAndSaysNothing(t *testing.T) {
	ctx := t.Context()
	db, all := databaseAtVersion(t, 11)
	// A pairing and a payment that resolve, so the repair has rows to look at
	// and nothing to do with them.
	exec(t, db, `INSERT INTO nwc_connections
	   (id, name, service_privkey, service_pubkey, client_pubkey, client_secret, relay,
	    permissions, created_at)
	 VALUES (1, 'the phone', 'priv-1', 'pub-1', 'client-1', 'secret-1',
	         'wss://nos.lol', '["info"]', 1700000000)`)
	exec(t, db, `INSERT INTO txns (kind, state, amount_msat, payment_hash, nwc_connection_id, created_at)
	 VALUES ('payment_out', 'settled', 1000, 'linked-payment', 1, 1700000100)`)
	exec(t, db, `INSERT INTO nwc_handled_requests (event_id, connection_id, method, response_json, handled_at)
	 VALUES ('live-event', 1, 'get_balance', '{}', 1700000200)`)

	logs := captureDefaultLogger(t)
	if err := applyMigrations(ctx, db, all); err != nil {
		t.Fatalf("applying 0012 to a clean database: %v", err)
	}

	if strings.Contains(logs.String(), "repaired") {
		t.Errorf("a clean database logged a repair; every healthy box would see this on every "+
			"upgrade and learn to ignore it:\n%s", logs.String())
	}
	var linked int
	if err := db.QueryRowContext(ctx,
		`SELECT nwc_connection_id FROM txns WHERE payment_hash = 'linked-payment'`).Scan(&linked); err != nil {
		t.Fatalf("the linked payment was disturbed: %v", err)
	}
	if linked != 1 {
		t.Errorf("a healthy payment was unlinked to %d", linked)
	}
}

// CRITERION 5: the counts are logged, per row kind, at INFO.
//
// A migration that quietly rewrites data is a shape this repository distrusts on
// principle, and "it silently fixed itself" is not something an operator should
// have to infer from the app starting.
func TestTheRepairSaysHowMuchItChanged(t *testing.T) {
	db, all := databaseAtVersion(t, 11)
	seedOrphans(t, db)

	logs := captureDefaultLogger(t)
	if err := applyMigrations(t.Context(), db, all); err != nil {
		t.Fatal(err)
	}

	line := repairLine(t, logs)
	if line["level"] != "INFO" {
		t.Errorf("the repair logged at %v, want INFO", line["level"])
	}
	for field, want := range map[string]float64{
		"payments_unlinked":         1,
		"replay_cache_rows_dropped": 2,
	} {
		if got, ok := line[field].(float64); !ok || got != want {
			t.Errorf("the repair reports %s = %v, want %v — per row KIND, because the two are "+
				"treated differently and an operator reading one number cannot tell",
				field, line[field], want)
		}
	}
	if !strings.Contains(line["msg"].(string), "no payment history was removed") {
		t.Errorf("the line does not say what was NOT done: %q", line["msg"])
	}
}

// seedOrphans builds the shape a real box had: children whose connection is
// gone.
//
// WITH FOREIGN KEYS OFF, which is not a shortcut — it is the mechanism. The app
// carries foreign_keys(1) in its DSN, so it could not have made these rows; the
// `sqlite3` CLI defaults to OFF, and this volume had been hand-inspected across
// several field trips. Seeding them any other way would be seeding a shape the
// database cannot hold.
func seedOrphans(t *testing.T, db *sql.DB) {
	t.Helper()
	exec(t, db, `INSERT INTO nwc_connections
	   (id, name, service_privkey, service_pubkey, client_pubkey, client_secret, relay,
	    permissions, created_at)
	 VALUES (1, 'the phone', 'priv-1', 'pub-1', 'client-1', 'secret-1',
	         'wss://nos.lol', '["info"]', 1700000000)`)
	exec(t, db, `INSERT INTO txns (kind, state, amount_msat, payment_hash, nwc_connection_id, created_at)
	 VALUES ('payment_out', 'settled', 1000, 'linked-payment', 1, 1700000100)`)
	exec(t, db, `INSERT INTO txns (kind, state, amount_msat, payment_hash, created_at)
	 VALUES ('invoice_in', 'settled', 5000, 'unlinked-payment', 1700000150)`)
	exec(t, db, `INSERT INTO nwc_handled_requests (event_id, connection_id, method, response_json, handled_at)
	 VALUES ('live-event', 1, 'get_balance', '{}', 1700000200)`)

	exec(t, db, `PRAGMA foreign_keys = OFF`)
	exec(t, db, `INSERT INTO txns (kind, state, amount_msat, payment_hash, nwc_connection_id, created_at)
	 VALUES ('payment_out', 'settled', 4200, 'orphaned-payment', 99, 1700000300)`)
	exec(t, db, `INSERT INTO nwc_handled_requests (event_id, connection_id, method, response_json, handled_at)
	 VALUES ('orphan-a', 99, 'pay_invoice', '{}', 1700000400)`)
	exec(t, db, `INSERT INTO nwc_handled_requests (event_id, connection_id, method, response_json, handled_at)
	 VALUES ('orphan-b', 98, 'get_info', '{}', 1700000500)`)
	exec(t, db, `PRAGMA foreign_keys = ON`)
}

func exec(t *testing.T, db *sql.DB, query string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), query); err != nil {
		t.Fatalf("seeding: %v\n%s", err, query)
	}
}

func assertNoDanglingReferences(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Error("a foreign key is still dangling after the migration")
	}
}

// captureDefaultLogger points the process default at a buffer for one test.
//
// The store takes no logger — Open is called after cliboot.Start has set the
// default — so this is where its output goes in production too. No test in this
// package calls t.Parallel(), so swapping a package-global is safe here and the
// original is restored on the way out.
func captureDefaultLogger(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(logging.New(&buf, logging.NewLevelVar(slog.LevelInfo)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func repairLine(t *testing.T, logs *bytes.Buffer) map[string]any {
	t.Helper()
	for _, raw := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			continue
		}
		if msg, ok := line["msg"].(string); ok && strings.Contains(msg, "repaired references") {
			return line
		}
	}
	t.Fatalf("no repair line was logged; an operator has to infer that the app fixed itself "+
		"from the fact that it started:\n%s", logs.String())
	return nil
}
