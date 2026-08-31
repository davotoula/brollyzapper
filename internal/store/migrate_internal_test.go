package store

import (
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func memDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open(driverName, "file:"+filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestLoadMigrationsOrdersByVersion(t *testing.T) {
	fsys := fstest.MapFS{
		"0003_third.sql": {Data: []byte("CREATE TABLE c (id INTEGER PRIMARY KEY);")},
		"0001_first.sql": {Data: []byte("CREATE TABLE a (id INTEGER PRIMARY KEY);")},
		"0010_tenth.sql": {Data: []byte("CREATE TABLE d (id INTEGER PRIMARY KEY);")},
		"README.md":      {Data: []byte("not a migration")},
	}
	got, err := loadMigrations(fsys)
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	want := []int{1, 3, 10}
	if len(got) != len(want) {
		t.Fatalf("loaded %d migrations, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].version != w {
			t.Errorf("migration %d has version %d, want %d", i, got[i].version, w)
		}
	}
}

func TestLoadMigrationsRejectsDuplicateVersions(t *testing.T) {
	fsys := fstest.MapFS{
		"0001_first.sql": {Data: []byte("SELECT 1;")},
		"0001_again.sql": {Data: []byte("SELECT 1;")},
	}
	if _, err := loadMigrations(fsys); err == nil {
		t.Error("loadMigrations accepted two migrations with the same version")
	}
}

func TestApplyMigrationsIsIdempotent(t *testing.T) {
	db := memDB(t)
	ms := []migration{
		{version: 1, name: "first", sql: "CREATE TABLE a (id INTEGER PRIMARY KEY);"},
		{version: 2, name: "second", sql: "CREATE TABLE b (id INTEGER PRIMARY KEY);"},
	}
	for pass := 1; pass <= 3; pass++ {
		if err := applyMigrations(t.Context(), db, ms); err != nil {
			t.Fatalf("applyMigrations pass %d: %v", pass, err)
		}
	}
	if got := appliedVersions(t, db); len(got) != 2 {
		t.Errorf("applied versions = %v, want exactly [1 2]", got)
	}
}

// Spec §19: migrations must be tolerant of skipped versions. A database stamped
// with 1 and 3 — because 2 was added to the tree later — must get 2 applied and
// must not re-run 1 or 3.
func TestApplyMigrationsFillsGapsInTheSequence(t *testing.T) {
	db := memDB(t)
	first := []migration{
		{version: 1, name: "first", sql: "CREATE TABLE a (id INTEGER PRIMARY KEY);"},
		{version: 3, name: "third", sql: "CREATE TABLE c (id INTEGER PRIMARY KEY);"},
	}
	if err := applyMigrations(t.Context(), db, first); err != nil {
		t.Fatalf("applyMigrations: %v", err)
	}

	// 2 arrives later, out of order, and 1 and 3 must not be re-run — re-running
	// either would fail on "table already exists", which is the assertion.
	withGapFilled := []migration{
		first[0],
		{version: 2, name: "second", sql: "CREATE TABLE b (id INTEGER PRIMARY KEY);"},
		first[1],
	}
	if err := applyMigrations(t.Context(), db, withGapFilled); err != nil {
		t.Fatalf("applyMigrations after the gap was filled: %v", err)
	}
	got := appliedVersions(t, db)
	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Errorf("applied versions = %v, want [1 2 3]", got)
	}
	if _, err := db.Exec("INSERT INTO b (id) VALUES (1)"); err != nil {
		t.Errorf("migration 2 did not run: %v", err)
	}
}

func TestAFailedMigrationRollsBack(t *testing.T) {
	db := memDB(t)
	ms := []migration{{
		version: 1,
		name:    "broken",
		sql:     "CREATE TABLE ok (id INTEGER PRIMARY KEY); CREATE TABLE ok (id INTEGER PRIMARY KEY);",
	}}
	if err := applyMigrations(t.Context(), db, ms); err == nil {
		t.Fatal("applyMigrations accepted a broken migration")
	}
	if got := appliedVersions(t, db); len(got) != 0 {
		t.Errorf("applied versions = %v, want none after a failure", got)
	}
	if _, err := db.Exec("INSERT INTO ok (id) VALUES (1)"); err == nil {
		t.Error("the first statement of a failed migration was left committed")
	}
}

func appliedVersions(t *testing.T, db *sql.DB) []int {
	t.Helper()
	rows, err := db.Query("SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		t.Fatalf("querying schema_migrations: %v", err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// The sweep runs every minute forever and the invoices table keeps every
// invoice ever minted, so it must not scan.
//
// This explains the SAME string ExpireInvoices runs. Retyping the query here
// would let the test keep passing while asserting a plan for a query the code
// no longer executes — which is the failure the assertion exists to prevent,
// one level up.
func TestTheExpirySweepUsesItsIndexRatherThanScanning(t *testing.T) {
	plan := queryPlan(t, openStore(t), expirySweepSQL, 0)
	if !strings.Contains(plan, "idx_invoices_open_expiry") {
		t.Errorf("the sweep does not use its index. Plan:\n%s", plan)
	}
}

// The open-invoice count runs on every public callback, so it must use the
// partial index rather than scanning a table that keeps every invoice ever
// minted. Asserting the plan rather than the index's existence: an index sqlite
// never chooses would still be there, and the migration, the schema and the
// golden file would all look correct (§13).
func TestTheOpenInvoiceCountUsesTheSameIndexAsTheSweep(t *testing.T) {
	plan := queryPlan(t, openStore(t), openInvoiceCountSQL, 0)
	if !strings.Contains(plan, "idx_invoices_open_expiry") {
		t.Errorf("the open-invoice count does not use its index. Plan:\n%s", plan)
	}
}

// utt, §13: the settlement path RESOLVES against the partial index.
//
// A partial index that is never used still exists, so asserting its presence in
// the golden schema proves nothing about §6's idempotency. What matters is that
// the ON CONFLICT target binds to THIS index — and it is a partial index, so it
// binds only because the statement repeats the same WHERE clause. Drop that
// clause and SQLite does not fall back to a slower plan; it refuses the
// statement outright, which is how this was found.
//
// The lookup half is asserted too: after a reconnect LND redelivers, and the
// replay is a no-op only if the conflict is DETECTED, which is an index seek.
func TestTheSettlementIdempotencyUsesThePartialIndex(t *testing.T) {
	s := openStore(t)

	plan := queryPlan(t, s,
		`SELECT 1 FROM txns WHERE kind = 'invoice_in' AND payment_hash = ?`, "abcd")
	if !strings.Contains(plan, "idx_txns_invoice_hash") {
		t.Errorf("a settled-invoice lookup does not use the partial index; §6's replay "+
			"protection is an index seek, not a scan. Plan:\n%s", plan)
	}

	// And the conflict target itself. SQLite will not prepare an ON CONFLICT
	// whose target matches no index, so a statement that prepares is one bound
	// to the partial index — which is why the wrong version of this failed loudly
	// rather than silently getting slower.
	if _, err := s.db.ExecContext(t.Context(),
		`INSERT INTO txns (kind, state, amount_msat, payment_hash, created_at)
		 VALUES ('invoice_in', 'settled', 1, 'plan-probe', 0)
		 ON CONFLICT(payment_hash) WHERE kind = 'invoice_in' DO NOTHING`); err != nil {
		t.Fatalf("the settlement path's conflict target does not bind to the partial index: %v", err)
	}
}

// u0u, §13: the FREEZE's query uses the partial index.
//
// This one is the hot path — it runs on every Reserve — and `created_at <
// startedAt` is every row ever written, so without the index it walks the whole
// of history and EXISTS has no shortcut through that. Asserting the index exists
// would prove nothing: a partial index that is never used still exists.
//
// The RESOLVER's query is deliberately NOT asserted here. Measured: SQLite
// prefers `SCAN txns` for it even with the index covering its columns and its
// ordering, and even against a seeded table. That is a defensible choice — it
// returns rows rather than a bit, and it runs at boot and once per
// reconciliation tick, not once per payment — and writing an assertion the
// planner does not satisfy would mean contorting the query to please a test.
// The index still serves it if the planner ever changes its mind.
func TestTheUnresolvedPaymentFreezeUsesThePartialIndex(t *testing.T) {
	s := openStore(t)
	// Seeded, because a plan assertion against an EMPTY table proves nothing:
	// with no rows a scan is the cheapest thing there is and the planner picks
	// it whatever indexes exist. The mix matters too — mostly rows the partial
	// index excludes, which is what a real ledger looks like and what makes
	// choosing the index the right answer.
	for i := range 200 {
		kind, state := "invoice_in", "settled"
		if i%50 == 0 {
			kind, state = "payment_out", "pending"
		}
		if _, err := s.db.ExecContext(t.Context(),
			`INSERT INTO txns (kind, state, amount_msat, payment_hash, created_at)
			 VALUES (?, ?, 1, ?, ?)`, kind, state, fmt.Sprintf("h%d", i), i); err != nil {
			t.Fatalf("seeding: %v", err)
		}
	}

	plan := queryPlan(t, s, `SELECT EXISTS(SELECT 1 FROM txns `+unresolvedPaymentsWhere+`)`,
		KindPaymentOut, TxnPending, 0)
	if !strings.Contains(plan, "idx_txns_pending_out") {
		t.Errorf("the freeze walks the table instead of the index, on every Reserve. Plan:\n%s",
			plan)
	}
}

// The constraint is SCOPED: two outbound rows may share a hash, and two inbound
// rows may not. Both halves, because asserting only the first would pass
// against a schema with no uniqueness at all.
func TestThePaymentHashConstraintAppliesToInboundOnly(t *testing.T) {
	s := openStore(t)
	insert := func(kind, hash string) error {
		_, err := s.db.ExecContext(t.Context(),
			`INSERT INTO txns (kind, state, amount_msat, payment_hash, created_at)
			 VALUES (?, 'settled', 1, ?, 0)`, kind, hash)
		return err
	}

	if err := insert("payment_out", "shared"); err != nil {
		t.Fatalf("the first outbound row: %v", err)
	}
	if err := insert("payment_out", "shared"); err != nil {
		t.Errorf("a second outbound row with the same hash was refused: %v — that is the retry "+
			"utt exists to allow", err)
	}
	if err := insert("invoice_in", "inbound"); err != nil {
		t.Fatalf("the first inbound row: %v", err)
	}
	if err := insert("invoice_in", "inbound"); err == nil {
		t.Error("a second inbound row with the same hash was accepted; §6's settlement " +
			"idempotency rests on that being impossible")
	}
}

// queryPlan renders EXPLAIN QUERY PLAN for one statement.
func queryPlan(t *testing.T, s *Store, query string, args ...any) string {
	t.Helper()
	rows, err := s.db.QueryContext(t.Context(), "EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatalf("explaining %q: %v", query, err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scanning the plan: %v", err)
		}
		plan.WriteString(detail + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading the plan: %v", err)
	}
	return plan.String()
}

// openStore is the package-internal equivalent of store_test.go's open(t),
// which is unreachable from in here. Closing through t.Cleanup rather than at
// the end of the test matters: a t.Fatalf above the close leaks the handle.
func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// The retry loop asks "what is due now?" on every tick for the life of the
// node, over a table that grows with every failed relay run. Asserting the PLAN
// rather than the index's existence: an index sqlite never chooses would still
// be there, and the migration and the golden file would both look right (§13).
func TestTheDueZapReceiptQueryUsesItsIndex(t *testing.T) {
	plan := queryPlan(t, openStore(t), dueZapReceiptsSQL, 0, 8)
	if !strings.Contains(plan, "idx_pending_receipts_due") {
		t.Errorf("the due-receipt query does not use its index. Plan:\n%s", plan)
	}
	// The index must also satisfy the ORDER BY, or the LIMIT cannot
	// short-circuit and every tick sorts the whole due set.
	if strings.Contains(plan, "TEMP B-TREE FOR ORDER BY") {
		t.Errorf("the due-receipt query sorts in a temp b-tree, so LIMIT reads the "+
			"whole due set first. Plan:\n%s", plan)
	}
}

// The Wallet page's history runs on every render of the page an operator looks
// at most, over a table that grows with every zap for the life of the node. The
// existing idx_txns_created must serve the ordering, or the LIMIT cannot
// short-circuit and each render sorts the whole table (§13: assert the plan,
// not the index).
func TestTheTransactionHistoryUsesTheCreatedIndex(t *testing.T) {
	plan := queryPlan(t, openStore(t), recentTxnsSQL, MaxHistoryRows)
	if !strings.Contains(plan, "idx_txns_created") {
		t.Errorf("the history query does not use idx_txns_created. Plan:\n%s", plan)
	}
	if strings.Contains(plan, "TEMP B-TREE FOR ORDER BY") {
		t.Errorf("the history query sorts in a temp b-tree, so LIMIT reads the whole "+
			"table first. Plan:\n%s", plan)
	}
}

// The rule that would have caught this wave's bug before the regtest stack did.
//
// A migration that DROPs or RENAMEs a table is a rebuild, and a rebuild without
// the directive runs with foreign keys enforced — which passes every store test,
// because they all open an empty database where the copy has nothing to violate,
// and fails on the first box with real data. That is exactly what happened to
// 0008, and the failure mode is a box that cannot start.
//
// A test rather than a comment in the README, because the README had the
// neighbouring rule already and it did not stop this.
func TestARebuildingMigrationDeclaresItself(t *testing.T) {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	ms, err := loadMigrations(sub)
	if err != nil {
		t.Fatalf("loading migrations: %v", err)
	}
	if len(ms) == 0 {
		t.Fatal("no migrations loaded; this rule is not running")
	}
	for _, m := range ms {
		if !rebuilds(m.sql) || declaresRebuild(m.sql) {
			continue
		}
		t.Errorf("migration %04d_%s drops or renames a table without %q; it will run with "+
			"foreign keys enforced and fail on any box whose data actually references the "+
			"table being rebuilt", m.version, m.name, rebuildDirective)
	}

	// Planted, because a rule that has only ever passed has been written rather
	// than tested.
	planted := "DROP TABLE txns;\nALTER TABLE txns_rebuilt RENAME TO txns;"
	if !rebuilds(planted) || declaresRebuild(planted) {
		t.Error("the scanner does not recognise a rebuild that omits the directive")
	}
	// And the directive is only honoured on a line of its own: a migration that
	// merely quotes it while explaining itself must not be granted foreign keys
	// off by accident.
	if declaresRebuild("-- see " + rebuildDirective + " for why this is not one") {
		t.Error("the directive was honoured inside a sentence")
	}
}

// rebuilds reports whether a migration restructures a table rather than adding
// to one.
func rebuilds(sql string) bool {
	upper := strings.ToUpper(sql)
	return strings.Contains(upper, "DROP TABLE") || strings.Contains(upper, "RENAME TO")
}
