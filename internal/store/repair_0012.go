package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/davotoula/brollyzapper/internal/logging"
)

// repairs are data repairs a NAMED migration needs before its own SQL runs.
//
// One entry, keyed by version, and deliberately not a general "repair the
// database" pass that runs on every step: a migration that quietly rewrites
// data is a shape this repository distrusts, so each repair is declared beside
// the migration that needs it and explains why it does.
//
// It runs INSIDE the migration's transaction and BEFORE its SQL, so a repair
// that fails rolls the whole step back, and the migration meets a database that
// is already consistent.
var repairs = map[int]func(ctx context.Context, tx *sql.Tx) (repairCounts, error){
	12: repairOrphanedNWCChildren,
}

// repairCounts is what a repair actually changed.
type repairCounts struct {
	txnsUnlinked   int64
	handledDropped int64
}

func (c repairCounts) none() bool { return c.txnsUnlinked == 0 && c.handledDropped == 0 }

// repairOrphanedNWCChildren makes migration 0012 survive a database it did not
// create.
//
// WHAT BROKE. 0012 rebuilds `nwc_connections`, so it declares
// `rebuild-with-foreign-keys-off` and the runner therefore runs
// `foreign_key_check` inside the transaction and refuses to commit on a dangling
// reference. On a database holding rows in `txns` or `nwc_handled_requests` whose
// connection no longer exists, that turns a latent inconsistency into **the app
// does not start**, with no operator remedy short of hand-editing sqlite.
// Measured on the reference box's regtest volume at version 11: 0 connections,
// 14 orphaned `txns` rows, 111 orphaned `nwc_handled_requests` rows.
//
// WHERE THE ORPHANS CAME FROM — as far as the code can say. Not from this app:
// `foreign_keys(1)` is in the DSN and has been since Wave 1, so a DELETE that
// orphaned children would have FAILED rather than succeeded quietly; there is no
// `DELETE FROM nwc_connections` anywhere in the tree, and revocation is an
// `UPDATE ... SET revoked = 1`; and no migration before 0012 rebuilds that
// table. What is left is an external writer — the `sqlite3` CLI defaults to
// `foreign_keys=OFF` — on a volume hand-inspected across several field trips.
//
// THAT MAKES THE REPAIR MORE IMPORTANT, NOT LESS. If the app cannot produce
// orphans, then every orphan a migration meets arrived by restore, backup,
// partial recovery, or a human with a shell — which are exactly the
// circumstances in which a migration most needs to work. A migration that aborts
// on an inconsistency it did not create is the wrong failure.
//
// THE TWO TABLES GET DIFFERENT TREATMENT, because they are different things.
func repairOrphanedNWCChildren(ctx context.Context, tx *sql.Tx) (repairCounts, error) {
	var counts repairCounts

	// txns: NULL the link, NEVER delete the row.
	//
	// An orphaned `txns` row is a payment that really happened, and money
	// history is not a migration's to discard. The column is already nullable
	// and NULL already MEANS "no connection recorded" — the 0.1.10 field trip
	// observed `made_by=None` on payments predating `d24.15`, and the
	// Transactions page renders that today. So the repair writes a value the
	// schema, the code and the operator already understand.
	unlinked, err := tx.ExecContext(ctx, `
		UPDATE txns SET nwc_connection_id = NULL
		 WHERE nwc_connection_id IS NOT NULL
		   AND nwc_connection_id NOT IN (SELECT id FROM nwc_connections)`)
	if err != nil {
		return counts, fmt.Errorf("unlinking payments from connections that no longer exist: %w", err)
	}
	if counts.txnsUnlinked, err = unlinked.RowsAffected(); err != nil {
		return counts, err
	}

	// nwc_handled_requests: delete the orphans.
	//
	// `connection_id` is NOT NULL, so nulling is unavailable — and this table is
	// a REPLAY CACHE with its own retention sweep (PruneNWCHandled), not a
	// record of anything. Deleting an orphan cannot cause a double execution:
	// the service serves only connections from ActiveNWCConnections, so a
	// request addressed to a connection that no longer exists can never be
	// dispatched, replay or not. These rows would have aged out on schedule.
	dropped, err := tx.ExecContext(ctx, `
		DELETE FROM nwc_handled_requests
		 WHERE connection_id NOT IN (SELECT id FROM nwc_connections)`)
	if err != nil {
		return counts, fmt.Errorf("dropping replay-cache rows for connections that no longer "+
			"exist: %w", err)
	}
	if counts.handledDropped, err = dropped.RowsAffected(); err != nil {
		return counts, err
	}
	return counts, nil
}

// logRepair says what was changed, per row kind, and says NOTHING when nothing
// was.
//
// A migration that rewrites data silently is the shape this repository
// distrusts on principle: "it fixed itself" is not something an operator should
// have to infer from the app starting. Equally, a line on every upgrade of every
// healthy box would train them to ignore it — so the quiet case is quiet.
//
// Through logging.Default(), which is the sanctioned single reader (§12): the
// store takes no logger, and Open is called well after cliboot.Start has set the
// process default, so this lands on the configured JSON handler at the right
// level rather than on slog's plain-text stderr.
func logRepair(m migration, counts repairCounts) {
	if counts.none() {
		return
	}
	logging.Default().Info("repaired references left by something outside this app before "+
		"migrating; no payment history was removed",
		"migration", fmt.Sprintf("%04d_%s", m.version, m.name),
		"payments_unlinked", counts.txnsUnlinked,
		"replay_cache_rows_dropped", counts.handledDropped)
}
