package store

import "testing"

// o34.14, from the 0.1.4 box. Migration 0004 renamed the rate-limit pair and
// carried the stored values across — right for an operator's explicit choice,
// wrong for a value nobody chose. The box held the OLD defaults, 10/100, and
// the renamed setting's own default is 60/600, so every upgraded box ran a
// global anonymous backstop six times tighter than designed. Measured: first
// 429 at request 11, where the design expects about 60.
//
// The old number was a limit on a DIFFERENT thing — the pre-Wave-10 pair, with
// per-IP in the mix and the address document counted against it. Carrying it
// under a name that now means something else is what imposed it.
func TestTheOldRateLimitDefaultsAreNotCarriedUnderTheNewName(t *testing.T) {
	for _, tc := range []struct {
		name          string
		minute, hour  string
		wantRemaining bool
		why           string
	}{
		{
			name:   "the old defaults are dropped so the new ones apply",
			minute: "10", hour: "100", wantRemaining: false,
			why: "10/100 was the OLD pair's default, not a choice; leaving it " +
				"pins an upgraded box to a backstop nobody picked",
		},
		{
			name:   "an operator's explicit choice survives",
			minute: "25", hour: "250", wantRemaining: true,
			why: "25/250 is a number somebody typed, and a migration that " +
				"discarded it would undo a deliberate decision",
		},
		{
			// Only the pair together is recognisable as the old default. One
			// half matching is not evidence of anything.
			name:   "a half-match is left alone",
			minute: "10", hour: "250", wantRemaining: true,
			why: "only the complete old pair is distinguishable from a choice",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openStore(t)
			for key, value := range map[string]string{
				"public_rate_limit_per_min":  tc.minute,
				"public_rate_limit_per_hour": tc.hour,
			} {
				if err := s.SetSetting(t.Context(), key, value); err != nil {
					t.Fatalf("seeding %s: %v", key, err)
				}
			}
			// Rewind exactly this migration and re-run it over the seeded rows,
			// which is what an upgrade does.
			if _, err := s.db.ExecContext(t.Context(),
				`DELETE FROM schema_migrations WHERE version = 7`); err != nil {
				t.Fatalf("rewinding the migration ledger: %v", err)
			}
			if err := s.migrate(t.Context()); err != nil {
				t.Fatalf("re-running migrations: %v", err)
			}

			for key, want := range map[string]string{
				"public_rate_limit_per_min":  tc.minute,
				"public_rate_limit_per_hour": tc.hour,
			} {
				got, present, err := s.Setting(t.Context(), key)
				if err != nil {
					t.Fatalf("Setting(%s): %v", key, err)
				}
				if present != tc.wantRemaining {
					t.Errorf("%s present=%v, want %v — %s", key, present, tc.wantRemaining, tc.why)
				}
				if tc.wantRemaining && got != want {
					t.Errorf("%s = %q, want %q — %s", key, got, want, tc.why)
				}
			}
		})
	}
}
