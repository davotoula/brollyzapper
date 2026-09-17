package guard

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// newMemoryTestGuard is the smallest Guard the rotation memory runs on: a state
// store, a detector that trips on ONE rejected probe, and the mounted file. No
// node — these tests hand observeProbe its answer.
func newMemoryTestGuard(t *testing.T) (*Guard, string) {
	t.Helper()
	root := t.TempDir()
	store, err := openStateStore(filepath.Join(root, "guard"), operatorSeed{})
	if err != nil {
		t.Fatal(err)
	}
	admin := filepath.Join(root, "admin.macaroon")
	if err := os.WriteFile(admin, []byte{0xad, 0x44}, 0o600); err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC) }
	return &Guard{
		state:         store,
		rotation:      NewRotationDetector(clock, 0, 1),
		adminMacaroon: lnd.FileCredentials(filepath.Join(root, "tls.cert"), admin),
		log:           logging.New(os.Stderr, logging.NewLevelVar(slog.LevelError)),
		rotated:       make(chan struct{}),
	}, admin
}

// rejected is LND's answer to a macaroon it will not accept (dqd, measured 16 Sep
// 2026): code Unknown. lndtest.RejectedLikeLND is the same value for the tests
// that run a node.
var rejected = status.Error(codes.Unknown, "verification failed: signature mismatch after caveat verification")

func declared(g *Guard) bool {
	select {
	case <-g.rotated:
		return true
	default:
		return false
	}
}

func eventsOf(t *testing.T, g *Guard, event logging.Event) int {
	t.Helper()
	st, err := g.state.load()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range st.RecentAudit {
		if e.Event == event {
			n++
		}
	}
	return n
}

// go-review M1: a probe the node answered BEFORE a success landed is not current
// evidence, and must neither hold, record nor exit.
//
// The measured interleaving: the probe matched the memory and was about to hold;
// a Status's GetInfo succeeded and cleared everything; the probe then held —
// leaving the guard flagged "still rejected" against a node that accepts it, and
// a durable preflight.refuse row telling the operator to fix a mount that works.
// The same stale probe could equally record a fresh exit after the success had
// cleared the old one, and exit. Both are one fact: the success happened after
// the probe was sent. This drives that order serially.
func TestAProbeSentBeforeASuccessDoesNotAct(t *testing.T) {
	for name, withMemory := range map[string]bool{
		"the memory matched: it would have held":       true,
		"no memory: it would have recorded and exited": false,
	} {
		t.Run(name, func(t *testing.T) {
			g, _ := newMemoryTestGuard(t)
			ctx := context.Background()
			if withMemory {
				if d := g.recordRotationExit(g.acceptances.Load()); d.outcome != exitTake {
					t.Fatalf("recording the first exit came to %v, want exitTake", d.outcome)
				}
			}

			sent := g.acceptances.Load() // the probe goes out
			g.nodeAccepted()             // a Status's GetInfo succeeds meanwhile
			g.rotation.Rejected()
			g.observeProbe(ctx, rejected, sent) // the probe's rejection comes back

			if g.holdingExit.Load() {
				t.Error("the guard holds its exit against a node that accepted a call after the probe was sent")
			}
			if declared(g) {
				t.Error("the guard declared rotation on a probe older than a success")
			}
			if n := eventsOf(t, g, logging.EventPreflightRefuse); n != 0 {
				t.Errorf("%d preflight.refuse rows for a hold that is not current", n)
			}
			if st, _ := g.state.load(); st.RotationExit != nil {
				t.Errorf("a stale probe recorded %+v after the success cleared the memory", st.RotationExit)
			}
		})
	}
}

// go-review L1: a mount that cannot be read at the threshold has no identity, so
// the guard exits as before as0.10 — and must not overwrite the memory it has
// with an empty one, which would cost the restart its hold and one more lap.
func TestAnUnreadableMountExitsWithoutOverwritingTheMemory(t *testing.T) {
	g, admin := newMemoryTestGuard(t)
	if d := g.recordRotationExit(g.acceptances.Load()); d.outcome != exitTake {
		t.Fatalf("recording the first exit came to %v, want exitTake", d.outcome)
	}
	before, _ := g.state.load()

	if err := os.Remove(admin); err != nil {
		t.Fatal(err)
	}
	g.rotation.Rejected()
	g.observeProbe(context.Background(), rejected, g.acceptances.Load())

	if !declared(g) {
		t.Error("an unreadable mount did not exit; cannot tell must mean exit")
	}
	after, _ := g.state.load()
	if after.RotationExit == nil || *after.RotationExit != *before.RotationExit {
		t.Errorf("the memory went from %+v to %+v; an empty identity must not replace a real one",
			before.RotationExit, after.RotationExit)
	}
}
