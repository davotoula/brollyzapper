package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/davotoula/brollyzapper/internal/logging"
)

// MaxAuditEvents is the retention bound from §12: keep the most recent 10,000
// security events, so the trail cannot grow without limit on an SD card.
const MaxAuditEvents = 10_000

// AppendAuditEvent writes one row of the durable security trail and trims the
// table back to MaxAuditEvents.
//
// The vocabulary is not checked here: logging.Auditor is the sanctioned way in
// and it validates, which keeps this package free of the §12 event list.
func (s *Store) AppendAuditEvent(ctx context.Context, ev logging.AuditEvent) error {
	_, err := s.appendAuditEvent(ctx, ev)
	return err
}

// AppendUniqueAuditEvent writes one relayed event unless a row with the same
// SourceID is already stored, and reports whether it wrote one.
//
// This is the server's half of d46.18: the guard re-reports its events on every
// response because it cannot know whether a report was stored, and this is what
// makes that produce one row.
func (s *Store) AppendUniqueAuditEvent(ctx context.Context, ev logging.AuditEvent) (bool, error) {
	if ev.SourceID == "" {
		return false, fmt.Errorf("appending a relayed %q: it carries no source id, so "+
			"redelivery could not be told from a new event", ev.Event)
	}
	return s.appendAuditEvent(ctx, ev)
}

// appendAuditEventSQL is the one insert.
//
// The conflict clause is always on, and is a no-op for locally raised events:
// the index is partial (WHERE source_id IS NOT NULL), so a NULL source_id can
// never conflict with anything, including another NULL. INSERT OR IGNORE would
// be shorter and would also swallow a NOT NULL violation, turning a real defect
// into a row that silently never appears — which is the shape of the bug this
// whole mechanism exists to fix.
const appendAuditEventSQL = `INSERT INTO audit_events
	 (event, severity, detail, remote, source_id, created_at)
	 VALUES (?, ?, ?, ?, ?, ?)
	 ON CONFLICT(source_id) WHERE source_id IS NOT NULL DO NOTHING`

func (s *Store) appendAuditEvent(ctx context.Context, ev logging.AuditEvent) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("appending audit event: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the tx is committed

	result, err := tx.ExecContext(ctx, appendAuditEventSQL,
		string(ev.Event), ev.Severity, nullString(ev.Detail), nullString(ev.Remote),
		nullString(ev.SourceID), ev.CreatedAt.Unix())
	if err != nil {
		return false, fmt.Errorf("appending audit event %q: %w", ev.Event, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("appending audit event %q: %w", ev.Event, err)
	}
	if rows == 0 {
		// A relayed event that is already stored. Nothing changed, so there is
		// nothing to trim either.
		return false, tx.Commit()
	}
	// Trim by id rather than by count: id is the rowid, rows are only ever
	// removed from the oldest end, so this is a primary-key range delete.
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM audit_events WHERE id <= (SELECT MAX(id) - ? FROM audit_events)",
		MaxAuditEvents); err != nil {
		return false, fmt.Errorf("trimming audit events: %w", err)
	}
	return true, tx.Commit()
}

// AuditEvents returns the most recent events, newest first — the order the
// admin UI's Security page shows them in (spec §9, §12).
// CountAuditEventsSince counts one kind of security event at or after `since`.
//
// A RATE, and that is why it exists (tna.2). §11's guard-rejection banner used
// to count guard.reject rows among the last 200 audit events, which is neither a
// rate nor a total: twelve of the last two hundred could span a minute or a
// month, and a burst is about how fast. The 200-row cap also silently truncated
// exactly the case the banner is for.
//
// It counts in SQL rather than reading rows and filtering: a burst is when there
// are many, so the version that materialises them all is slowest precisely when
// it matters. idx_audit_created covers the range.
func (s *Store) CountAuditEventsSince(ctx context.Context, event logging.Event, since time.Time) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE event = ? AND created_at >= ?`,
		string(event), since.Unix()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting %s events: %w", event, err)
	}
	return count, nil
}

func (s *Store) AuditEvents(ctx context.Context, limit int) ([]logging.AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, event, severity, detail, remote, created_at
		 FROM audit_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("reading audit events: %w", err)
	}
	defer rows.Close()

	var out []logging.AuditEvent
	for rows.Next() {
		var (
			ev             logging.AuditEvent
			event          string
			detail, remote sql.NullString
			createdAt      int64
		)
		if err := rows.Scan(&ev.ID, &event, &ev.Severity, &detail, &remote, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning audit event: %w", err)
		}
		ev.Event = logging.Event(event)
		ev.Detail = detail.String
		ev.Remote = remote.String
		ev.CreatedAt = unixTime(createdAt)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// AuditEventCount is how many events the trail currently holds.
func (s *Store) AuditEventCount(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_events").Scan(&n); err != nil {
		return 0, fmt.Errorf("counting audit events: %w", err)
	}
	return n, nil
}
