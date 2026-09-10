package store

import (
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// secret.String goes into sqlite and comes back, through the REAL driver
// (twt, criterion 3).
//
// A REAL ROUND TRIP AND NOT A MOCK, which the brief asks for and which is the
// only version worth having: driver.Valuer's contract is with database/sql's
// conversion machinery, and a fake that calls Value() and Scan() by hand proves
// the two functions agree with each other rather than with the driver. The
// nullability half in particular is a driver question — a Valuer returning nil
// is what makes the column NULL, and nothing but a real INSERT shows that.
//
// It lives in internal/store rather than internal/secret because this is where
// the database is: internal/secret has no driver dependency and should not grow
// one for a test.
func TestASecretRoundTripsThroughSQL(t *testing.T) {
	db := openStore(t).db

	if _, err := db.ExecContext(t.Context(),
		`CREATE TABLE secret_roundtrip (id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatalf("creating the table: %v", err)
	}

	// A ROW PER CASE rather than one row cleaned up between them. The first
	// version deleted in a t.Cleanup, whose t.Context() is already CANCELLED by
	// the time cleanup runs — so the DELETE failed, its error was discarded, and
	// the second case hit a UNIQUE violation. Distinct ids need no teardown at all.
	for id, c := range map[int]struct {
		name     string
		in       secret.String
		wantNull bool
	}{
		1: {"a secret", secret.New("s3cr3t-preimage-aabbcc"), false},
		2: {"the zero value", secret.String{}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := db.ExecContext(t.Context(),
				`INSERT INTO secret_roundtrip (id, v) VALUES (?, ?)`, id, c.in); err != nil {
				t.Fatalf("binding a secret.String directly: %v", err)
			}

			// NULL and not the empty string, matching what nullString did before
			// this bead — otherwise every column this type touches changes shape.
			var isNull bool
			if err := db.QueryRowContext(t.Context(),
				`SELECT v IS NULL FROM secret_roundtrip WHERE id = ?`, id).Scan(&isNull); err != nil {
				t.Fatalf("asking whether the column is NULL: %v", err)
			}
			if isNull != c.wantNull {
				t.Errorf("column IS NULL = %v, want %v", isNull, c.wantNull)
			}

			var got secret.String
			if err := db.QueryRowContext(t.Context(),
				`SELECT v FROM secret_roundtrip WHERE id = ?`, id).Scan(&got); err != nil {
				t.Fatalf("scanning into a secret.String: %v", err)
			}
			if got.Reveal() != c.in.Reveal() {
				t.Errorf("round-tripped %q, want %q", got.Reveal(), c.in.Reveal())
			}
			if got.IsZero() != c.in.IsZero() {
				t.Errorf("IsZero = %v, want %v", got.IsZero(), c.in.IsZero())
			}
		})
	}

	// A column written as TEXT comes back as []byte from some drivers and string
	// from others, and NULL from a LEFT JOIN that matched nothing. Scan takes all
	// three, and the last one must not leave a stale value behind.
	t.Run("scanning a SQL NULL clears the destination", func(t *testing.T) {
		got := secret.New("not-cleared")
		if err := db.QueryRowContext(t.Context(), `SELECT NULL`).Scan(&got); err != nil {
			t.Fatalf("scanning NULL: %v", err)
		}
		if !got.IsZero() {
			t.Errorf("NULL scanned as %q; a Scanner that leaves the old value behind turns "+
				"an absent preimage into the PREVIOUS row's", got.Reveal())
		}
	})

	t.Run("scanning bytes", func(t *testing.T) {
		var got secret.String
		if err := db.QueryRowContext(t.Context(), `SELECT CAST('aabbcc' AS BLOB)`).Scan(&got); err != nil {
			t.Fatalf("scanning a BLOB: %v", err)
		}
		if got.Reveal() != "aabbcc" {
			t.Errorf("scanned %q from a BLOB, want %q", got.Reveal(), "aabbcc")
		}
	})
}

// THE EXPORT SEAM IS NOT A RENDERING SEAM, and this is the assertion that keeps
// the two apart. A Valuer that also leaked through JSON or slog would be the
// worst of both: the reason persistence may reveal is that a database is not a
// log line, and that argument does not extend one inch further.
func TestTheValuerDidNotWeakenTheRedactions(t *testing.T) {
	s := secret.New("s3cr3t-preimage-aabbcc")

	encoded, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(encoded) != `"`+secret.Redacted+`"` {
		t.Errorf("MarshalJSON = %s, want %q — a driver.Valuer must not reach encoding/json",
			encoded, secret.Redacted)
	}
	if got := s.LogValue().String(); got != secret.Redacted {
		t.Errorf("LogValue = %q, want %q", got, secret.Redacted)
	}
	if got := s.String(); got != secret.Redacted {
		t.Errorf("String = %q, want %q", got, secret.Redacted)
	}

	// The Valuer itself, asserted to be the one thing that DOES reveal.
	v, err := s.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	if v != "s3cr3t-preimage-aabbcc" {
		t.Errorf("Value = %v, want the revealed secret; a Valuer that redacted would write "+
			"[redacted] into the database", v)
	}
	var _ sql.Scanner = (*secret.String)(nil)
}
