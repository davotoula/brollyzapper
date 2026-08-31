package guard

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/logging"
)

// The §12 vocabulary is checked at source, not one process away.
//
// logging.Auditor makes this check for everything the server raises, and the
// guard cannot use the Auditor — §16 gives it no mount for the server's
// database. Without its own check a typo would be logged, shipped over the
// socket, and only refused by the server, with nothing at the point of the
// mistake to say so. Guard.audit is unexported, so this is the only way to
// reach it: an external test cannot construct an event the guard would not.
func TestAnEventOutsideTheVocabularyIsRefusedAtSource(t *testing.T) {
	var buf bytes.Buffer
	state, err := openStateStore(filepath.Join(t.TempDir(), "guard-data"), operatorSeed{})
	if err != nil {
		t.Fatalf("openStateStore: %v", err)
	}
	g := &Guard{
		state:    state,
		rotation: NewRotationDetector(nil, 0, 0),
		log:      logging.New(&buf, logging.NewLevelVar(slog.LevelDebug)),
	}

	g.audit(t.Context(), slog.LevelInfo, "a typo", logging.Event("macaroon.bakes"), nil)

	if events := g.recentAuditEvents(); len(events) != 0 {
		t.Errorf("the guard recorded %v; an event outside the §12 vocabulary must not be "+
			"reported to the server at all", events)
	}
	if out := buf.String(); !strings.Contains(out, "macaroon.bakes") {
		t.Errorf("the refusal does not name the offending event: %s", out)
	}
}
