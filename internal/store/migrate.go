package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// driverName is the pure-Go sqlite driver. It must stay cgo-free: the images
// are gcr.io/distroless/static and the binaries build with CGO_ENABLED=0
// (the lnd module would drag in cgo).
const driverName = "sqlite"

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migration is one versioned schema step, named by its file: NNNN_name.sql.
type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations reads every NNNN_name.sql in fsys, ordered by version. Gaps in
// the sequence are fine — see applyMigrations.
func loadMigrations(fsys fs.FS) ([]migration, error) {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("listing migrations: %w", err)
	}
	seen := map[int]string{}
	out := make([]migration, 0, len(names))
	for _, name := range names {
		base := strings.TrimSuffix(path.Base(name), ".sql")
		digits, label, ok := strings.Cut(base, "_")
		if !ok {
			return nil, fmt.Errorf("migration %q is not named NNNN_name.sql", name)
		}
		version, err := strconv.Atoi(digits)
		if err != nil {
			return nil, fmt.Errorf("migration %q has no numeric version: %w", name, err)
		}
		if other, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrations %q and %q share version %d", other, name, version)
		}
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("reading migration %q: %w", name, err)
		}
		seen[version] = name
		out = append(out, migration{version: version, name: label, sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// applyMigrations brings db up to date.
//
// Spec §19 requires migrations that are automatic, idempotent, restart-safe and
// tolerant of skipped versions. That is why the bookkeeping records the *set* of
// applied versions rather than a high-water mark: a migration added later with a
// lower number than one already applied still runs, and nothing runs twice.
// Each migration is applied inside its own transaction, so a failure leaves the
// database on the last good version rather than half-way through a step.
func applyMigrations(ctx context.Context, db *sql.DB, ms []migration) error {
	const bookkeeping = `CREATE TABLE IF NOT EXISTS schema_migrations (
  version    INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  applied_at INTEGER NOT NULL
)`
	if _, err := db.ExecContext(ctx, bookkeeping); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}

	applied, err := appliedSet(ctx, db)
	if err != nil {
		return err
	}
	for _, m := range ms {
		if applied[m.version] {
			continue
		}
		if err := applyOne(ctx, db, m); err != nil {
			return fmt.Errorf("migration %04d_%s: %w", m.version, m.name, err)
		}
	}
	return nil
}

func appliedSet(ctx context.Context, db *sql.DB) (map[int]bool, error) {
	rows, err := db.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("reading schema_migrations: %w", err)
	}
	defer rows.Close()
	applied := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("scanning schema_migrations: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading schema_migrations: %w", err)
	}
	return applied, nil
}

// rebuildDirective marks a migration that REBUILDS a table other tables
// reference, and so must run with foreign keys disabled.
//
// SQLite's own procedure for changing a table in a way ALTER TABLE cannot
// express requires `PRAGMA foreign_keys = OFF` — and that pragma is a no-op
// inside a transaction, which is where every migration otherwise runs.
// `defer_foreign_keys` is NOT a substitute: dropping or renaming a parent
// records a deferred violation for every child row, and putting the parent back
// does not retract them.
//
// A directive rather than a filename convention so the reason travels with the
// file, and so that a migration acquiring this need later does not have to be
// renamed — migrations are append-only once released.
const rebuildDirective = "-- +brollyzapper:rebuild-with-foreign-keys-off"

func applyOne(ctx context.Context, db *sql.DB, m migration) error {
	// One connection for the whole step, because the pragma is per-connection
	// and would otherwise be left set on whichever connection served the
	// migration. (This pool is one connection deep today, which makes that
	// certain rather than likely — and makes taking it explicitly the thing
	// that keeps this correct if that ever changes.)
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck // returning it to the pool

	rebuild := declaresRebuild(m.sql)
	if rebuild {
		// BEFORE the transaction, which is the only place it takes effect.
		if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
			return fmt.Errorf("disabling foreign keys: %w", err)
		}
		// Restored on every path, including a failure, because this connection
		// goes back to the pool and §4's references are enforced, not
		// decorative. The driver applies the DSN's foreign_keys(1) only when a
		// connection is CREATED, so without this the pooled connection would
		// keep enforcement off for the life of the process.
		// TestARebuildThatOrphansAChildRowIsRolledBack asserts it after a
		// failure, which is the path most likely to leak it.
		//
		// WithoutCancel, so a cancelled context cannot be the thing that leaves
		// a connection poisoned — the restore is the last thing that should be
		// skipped.
		defer restoreForeignKeys(ctx, conn)
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the tx is committed
	// A DECLARED repair, for the migrations that need one, before their own SQL
	// — see repairs. Inside this transaction, so a repair that fails rolls the
	// step back and the migration never runs against a half-repaired database.
	if repair, ok := repairs[m.version]; ok {
		counts, err := repair(ctx, tx)
		if err != nil {
			return err
		}
		logRepair(m, counts)
	}
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return err
	}
	if rebuild {
		// SQLite's procedure ends here: with enforcement off, a rebuild that
		// orphaned a child row would commit silently. This is the check that
		// makes the whole thing safe, and it runs INSIDE the transaction, so a
		// dangling reference rolls the migration back rather than shipping.
		if err := requireNoDanglingReferences(ctx, tx); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx,
		"INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
		m.version, m.name, time.Now().Unix())
	if err != nil {
		return err
	}
	return tx.Commit()
}

// declaresRebuild reports whether the migration asks for SQLite's table-rebuild
// procedure.
//
// The directive must be a LINE OF ITS OWN. A substring match would also fire on
// a migration that merely quotes it while explaining why it does not need it —
// and that migration would then silently run with foreign keys off, which is the
// one thing this flag must never grant by accident.
func declaresRebuild(sql string) bool {
	for _, line := range strings.Split(sql, "\n") {
		if strings.TrimSpace(line) == rebuildDirective {
			return true
		}
	}
	return false
}

// restoreForeignKeys puts enforcement back, and discards the connection if it
// cannot.
//
// The pool is one connection deep, and the driver applies the DSN's
// foreign_keys(1) only when a connection is CREATED — so a failed restore would
// leave §4's references unenforced for the life of the process, silently.
// Poisoning the connection makes the pool throw it away and build a fresh one
// with the DSN's pragmas, turning a permanent state into a blip.
//
// WithoutCancel, because a cancelled context must not be the thing that skips
// this: it is the last work that should ever be dropped.
func restoreForeignKeys(ctx context.Context, conn *sql.Conn) {
	if _, err := conn.ExecContext(context.WithoutCancel(ctx), "PRAGMA foreign_keys = ON"); err == nil {
		return
	}
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
}

// requireNoDanglingReferences fails the migration if any foreign key is broken.
func requireNoDanglingReferences(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("checking foreign keys after the rebuild: %w", err)
	}
	defer rows.Close()
	var broken []string
	for rows.Next() {
		var table, parent string
		var rowid sql.NullInt64
		var fkid int
		if err := rows.Scan(&table, &rowid, &parent, &fkid); err != nil {
			return fmt.Errorf("reading the foreign key check: %w", err)
		}
		broken = append(broken, fmt.Sprintf("%s -> %s", table, parent))
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("reading the foreign key check: %w", err)
	}
	if len(broken) > 0 {
		// "found", not "left": a box that already had an orphan reports the same
		// thing, and blaming the rebuild would send the operator to the wrong
		// place. Either way the migration must not commit with FKs unenforced.
		return fmt.Errorf("foreign key check found %d dangling reference(s) after this "+
			"rebuild (%s); rolling back", len(broken), strings.Join(broken, ", "))
	}
	return nil
}
