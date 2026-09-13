package guard_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// 20i.7. The guard logged "baking the receive macaroon" BEFORE the attempt, in
// wording a grep for `bak` could not tell from the success line "receive
// macaroon baked". In a failing loop it appeared once per restart — four times
// in seven seconds on the 20i.2 reproduction — and read as progress.
//
// The spend credential's attempt line had the same wording and the same
// defect, so it is held to the same test.
//
// Both outcomes log the attempt line, identically. Only the one that worked may
// put `bak` in front of an operator.
func TestTheBakeAttemptLineCannotBeReadAsTheSuccessLine(t *testing.T) {
	for _, kind := range []struct {
		name             string
		file             string
		attempt, success string
		ensure           func(*guard.Guard, context.Context) error
		// enable is what makes the guard keep this credential alive at all:
		// the spend one only once sending is on, which is a recorded root key.
		enable func(*guard.Guard, context.Context) error
	}{
		{"receive", lnd.ReceiveMacaroon, "asking the node for a receive macaroon", "receive macaroon baked",
			(*guard.Guard).EnsureReceiveMacaroon, nil},
		{"spend", lnd.SpendMacaroon, "asking the node for a spend macaroon", "spend macaroon baked",
			(*guard.Guard).EnsureSpendMacaroon, (*guard.Guard).BakeSpend},
	} {
		for _, tc := range []struct {
			name   string
			refuse bool
		}{
			{"the node bakes", false},
			{"the node refuses", true},
		} {
			t.Run(kind.name+"/"+tc.name, func(t *testing.T) {
				attemptLineOnly(t, kind.file, kind.attempt, kind.success, kind.enable, kind.ensure, tc.refuse)
			})
		}
	}
}

func attemptLineOnly(t *testing.T, file, attempt, success string,
	enable, ensure func(*guard.Guard, context.Context) error, refuse bool) {
	t.Helper()
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	var logged bytes.Buffer
	g := openGuard(t, node, d, guard.Options{
		Log: logging.New(&logged, logging.NewLevelVar(slog.LevelDebug)),
	})
	if enable != nil {
		if err := enable(g, t.Context()); err != nil {
			t.Fatalf("enabling the %s: %v", file, err)
		}
	}
	// No credential of this kind, so the guard has a bake to attempt.
	if err := os.Remove(filepath.Join(d.credentials, file)); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	logged.Reset()
	node.SetReject(refuse)

	if err := ensure(g, t.Context()); (err != nil) != refuse {
		t.Fatalf("ensuring the %s = %v with the node refusing=%v", file, err, refuse)
	}

	var attempts, baked int
	for line := range strings.SplitSeq(logged.String(), "\n") {
		if line == "" {
			continue
		}
		var r struct{ Level, Msg, Reason string }
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("a log line is not JSON: %q", line)
		}
		if r.Msg == attempt {
			attempts++
			if r.Level != "INFO" || r.Reason == "" {
				t.Errorf("the attempt line is %s with reason %q, want INFO with the reason",
					r.Level, r.Reason)
			}
		}
		// An operator's grep, not a match on one message: whatever says
		// `bak` is what they will read as a bake. Not `baked`, which the
		// old "baking the receive macaroon" never matched either, so the
		// test would have passed against the defect. The message only:
		// a reason can say "the root key it was baked under".
		if strings.Contains(r.Msg, "bak") {
			baked++
			if r.Msg != success {
				t.Errorf("a line other than the success line reads as a bake: %s", line)
			}
		}
	}
	if attempts != 1 {
		t.Errorf("the attempt was logged %d times, want 1:\n%s", attempts, logged.String())
	}
	want := 1
	if refuse {
		want = 0
	}
	if baked != want {
		t.Errorf("%d lines read as a bake, want %d:\n%s", baked, want, logged.String())
	}
}
