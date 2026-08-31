package store

import "testing"

// Migration 0004 renames a settings key, which makes it the first migration
// that carries DATA rather than schema — and the golden schema snapshot cannot
// see it, so nothing else would.
//
// The value has to travel with the key. An operator who raised the limit did it
// so their zaps would stop bouncing; dropping the value on rename would quietly
// reinstate the default and look like the limiter had regressed.
func TestTheRateLimitRenameCarriesTheStoredValue(t *testing.T) {
	s := openStore(t)

	// Write the OLD spellings directly, as a database migrated from 0003 would
	// hold them, then re-run the migrations over it.
	for key, value := range map[string]string{
		"rate_limit_per_min":  "31",
		"rate_limit_per_hour": "311",
	} {
		if _, err := s.db.ExecContext(t.Context(),
			`INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)`, key, value); err != nil {
			t.Fatalf("seeding %s: %v", key, err)
		}
	}
	if _, err := s.db.ExecContext(t.Context(),
		// Exactly migration 4, not everything from 4 up: rewinding the tail of
		// the ledger re-runs every LATER migration too, and a CREATE TABLE two
		// migrations along then fails on a table that already exists. This test
		// is about one migration and should rewind one.
		`DELETE FROM schema_migrations WHERE version = 4`); err != nil {
		t.Fatalf("rewinding the migration ledger: %v", err)
	}
	if err := s.migrate(t.Context()); err != nil {
		t.Fatalf("re-running migrations: %v", err)
	}

	for key, want := range map[string]string{
		"public_rate_limit_per_min":  "31",
		"public_rate_limit_per_hour": "311",
	} {
		got, ok, err := s.Setting(t.Context(), key)
		if err != nil {
			t.Fatalf("Setting(%s): %v", key, err)
		}
		if !ok || got != want {
			t.Errorf("%s = %q (present=%v), want %q — the operator's value did not "+
				"travel with the rename", key, got, ok, want)
		}
	}
	for _, gone := range []string{"rate_limit_per_min", "rate_limit_per_hour"} {
		if _, ok, err := s.Setting(t.Context(), gone); err != nil {
			t.Fatalf("Setting(%s): %v", gone, err)
		} else if ok {
			t.Errorf("%s is still present; two spellings of one setting is how a "+
				"saved value and a read value drift apart", gone)
		}
	}
}
