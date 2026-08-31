package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	_ "modernc.org/sqlite" // pure-Go sqlite driver; see driverName
)

// ErrNotFound is returned when a row the caller named does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrUnknownInvoice is the ONE not-found that means "this app never minted this
// invoice", returned only when a settlement names a payment_hash with no
// invoices row.
//
// Its own sentinel because the caller acts on it in a way it must not act on
// any other: the invoice-stream handler SKIPS a settlement it sees this for,
// advances the resume point past it, and never revisits it (vz1.8). That is
// safe for a foreign invoice on a shared node and unrecoverable for anything
// else — the money is gone and nothing re-delivers it.
//
// ErrNotFound is a package-wide sentinel with several return sites, and it
// already means two different things to two consumers. Discriminating on it
// would leave that guarantee resting on the current shape of a call graph
// rather than on anything structural.
//
// It WRAPS ErrNotFound, so every existing errors.Is(err, ErrNotFound) caller is
// unaffected.
var ErrUnknownInvoice = fmt.Errorf("unknown invoice: %w", ErrNotFound)

// DBFileName is the database file inside the data directory.
const DBFileName = "brollyzapper.db"

// Invoice states (spec §4).
const (
	InvoiceOpen    = "open"
	InvoiceSettled = "settled"
	InvoiceExpired = "expired"
)

// Store owns the sqlite database. Nothing else in the tree opens it.
type Store struct {
	db   *sql.DB
	path string
}

// Open creates dataDir if needed, opens the database inside it and applies every
// outstanding migration. It is safe to call on an already-migrated database.
//
// The directory is 0700 and the file 0600: §4 stores the zap-receipt signing key
// and the NWC secrets unencrypted, and says plainly that the mitigation is
// filesystem-level.
func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating data dir %s: %w", dataDir, err)
	}
	// MkdirAll is subject to umask and does nothing at all if the directory
	// already exists, so the mode is set explicitly either way.
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("securing data dir %s: %w", dataDir, err)
	}

	path := filepath.Join(dataDir, DBFileName)
	if err := ensureFileMode(path, 0o600); err != nil {
		return nil, err
	}

	dsn := "file:" + path +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		// FULL, not NORMAL. Under WAL, NORMAL leaves the most recent commits
		// unfsynced, so a power cut can roll back a transaction the caller was
		// already told had succeeded — and the most recent transaction on this
		// app is a wallet reserve. That is §6's double-spend of the ceiling,
		// arriving as a hardware event rather than a bug (review L10). The cost
		// is an fsync per commit on a node doing a handful of writes a minute.
		"&_pragma=synchronous(FULL)"
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	// One writer, one connection. The load is a home node's, and serialising
	// every statement removes SQLITE_BUSY as a failure mode entirely.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, path: path}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// ensureFileMode creates the file if it does not exist and forces its mode, so
// the database is never briefly world-readable.
func ensureFileMode(path string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, mode)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("securing %s: %w", path, err)
	}
	return nil
}

func (s *Store) migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("opening embedded migrations: %w", err)
	}
	ms, err := loadMigrations(sub)
	if err != nil {
		return err
	}
	if err := applyMigrations(ctx, s.db, ms); err != nil {
		return err
	}
	version, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	// §4 lists schema_version among the settings keys, so the admin UI can read
	// it without knowing about the migration bookkeeping.
	return s.SetSetting(ctx, "schema_version", strconv.Itoa(version))
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// Path is the database file's location.
func (s *Store) Path() string { return s.path }

// SchemaVersion is the highest migration applied.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var version sql.NullInt64
	err := s.db.QueryRowContext(ctx, "SELECT MAX(version) FROM schema_migrations").Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("reading schema version: %w", err)
	}
	return int(version.Int64), nil
}

// Setting reads one settings row.
func (s *Store) Setting(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reading setting %q: %w", key, err)
	}
	return value, true, nil
}

// SetSetting writes one settings row, replacing any existing value.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value)
	if err != nil {
		return fmt.Errorf("writing setting %q: %w", key, err)
	}
	return nil
}

// Column is one column of the live schema.
type Column struct {
	Table string
	Name  string
	Type  string // as declared, e.g. INTEGER
}

// Columns lists every column of every table, with the type each was declared
// with. §4's "never floats for money" is asserted against this.
func (s *Store) Columns(ctx context.Context) ([]Column, error) {
	// pragma_table_info is the table-valued form of PRAGMA table_info, which
	// means the table name binds as a parameter and one query covers the whole
	// schema instead of one PRAGMA per table.
	rows, err := s.db.QueryContext(ctx,
		`SELECT m.name, ti.name, ti.type
		 FROM sqlite_master m JOIN pragma_table_info(m.name) ti
		 WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%'
		 ORDER BY m.name, ti.cid`)
	if err != nil {
		return nil, fmt.Errorf("reading columns: %w", err)
	}
	defer rows.Close()

	var out []Column
	for rows.Next() {
		var c Column
		if err := rows.Scan(&c.Table, &c.Name, &c.Type); err != nil {
			return nil, fmt.Errorf("scanning column: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SchemaDump renders the live schema in a stable order, for the golden-file
// drift check.
func (s *Store) SchemaDump(ctx context.Context) (string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT type, name, sql FROM sqlite_master
		 WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
		 ORDER BY type, name`)
	if err != nil {
		return "", fmt.Errorf("dumping schema: %w", err)
	}
	defer rows.Close()
	var dump string
	for rows.Next() {
		var typ, name, ddl string
		if err := rows.Scan(&typ, &name, &ddl); err != nil {
			return "", fmt.Errorf("scanning schema: %w", err)
		}
		dump += ddl + ";\n"
	}
	return dump, rows.Err()
}

// settleIndexKey is where the invoice stream's resume point lives (spec §4,
// §6). It is a setting rather than its own table so the admin UI can show it
// alongside everything else.
const settleIndexKey = "last_settle_index"

// LastSettleIndex is the settle_index of the last invoice settlement this
// process handled. Zero means "never handled one", which LND reads as "send me
// everything from the beginning".
func (s *Store) LastSettleIndex(ctx context.Context) (uint64, error) {
	raw, ok, err := s.Setting(ctx, settleIndexKey)
	if err != nil || !ok {
		return 0, err
	}
	index, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		// Falling back to zero here would silently replay every settlement the
		// node still remembers, so the caller has to see this.
		return 0, fmt.Errorf("reading %s: %q is not a settle index: %w", settleIndexKey, raw, err)
	}
	return index, nil
}

// SetLastSettleIndex records the resume point.
func (s *Store) SetLastSettleIndex(ctx context.Context, index uint64) error {
	return s.SetSetting(ctx, settleIndexKey, strconv.FormatUint(index, 10))
}

// AllSettings reads the whole settings table in one query.
//
// The admin UI needs most of these keys on most pages, and this database runs
// on a single connection — so one query for all of them beats a point read per
// key serialising behind the same mutex as the invoice stream.
func (s *Store) AllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM settings")
	if err != nil {
		return nil, fmt.Errorf("reading settings: %w", err)
	}
	defer rows.Close()

	values := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("scanning a setting: %w", err)
		}
		values[key] = value
	}
	return values, rows.Err()
}
