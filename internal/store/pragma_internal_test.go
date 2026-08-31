package store

import "testing"

// The pragmas are read back from the open connection rather than asserted
// against the DSN string. A DSN is what we asked for; the pragma is what sqlite
// did — and modernc's driver silently ignores an option it does not recognise,
// so the two are not the same claim.
//
// synchronous=FULL (2), not NORMAL (1): under WAL, NORMAL lets a committed
// transaction be lost to a power cut, and the transaction most likely to be
// lost is the most recent one — which for this app is a wallet reserve. Losing
// it after the caller was told it succeeded is §6's double-spend of the
// ceiling, on a box that lives on a shelf behind a domestic power supply
// (review L10).
func TestOpenPutsTheDurabilityPragmasInForce(t *testing.T) {
	s := openStore(t)

	for _, want := range []struct {
		pragma string
		value  string
		why    string
	}{
		{"synchronous", "2", "FULL — a committed reserve must survive a power cut"},
		{"journal_mode", "wal", "readers must not block the writer"},
		{"foreign_keys", "1", "§4's references are enforced, not decorative"},
	} {
		var got string
		if err := s.db.QueryRowContext(t.Context(), "PRAGMA "+want.pragma).Scan(&got); err != nil {
			t.Fatalf("PRAGMA %s: %v", want.pragma, err)
		}
		if got != want.value {
			t.Errorf("PRAGMA %s = %s, want %s (%s)", want.pragma, got, want.value, want.why)
		}
	}
}
