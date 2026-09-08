package guard

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/logging"
)

// A sweep judged on a STALE snapshot must not clear the grant that replaced it.
//
// sweepExpired takes the State its caller has already loaded — that is the whole
// point, so the polled Status does not read the file twice — and stateStore's
// own doc names the hazard that creates: "the guard serves one goroutine per
// socket connection, so a load() then save() composed by the caller is a lost
// update waiting to happen". consumeAuthorisation writes `Authorisation = nil`
// unconditionally, and deletes authorisation.txt with it.
//
// THE SEQUENCE THIS REPRODUCES, which two socket connections reach on their own:
// a Status poll loads state holding an expired grant; before it acts, the
// operator asks for a code, which sweeps that grant properly and writes a new
// one, file and row; the poll then resumes and clears the state it was never
// looking at. The operator reads a code that stops working within milliseconds
// of being written, and ApplyChange tells them to ask for another — which is the
// same thing happening again.
//
// DRIVEN BY HAND RATHER THAN BY GOROUTINES, deliberately: the interleaving is
// the defect, and a test that raced for it would reproduce it on some runs and
// certify nothing on the others. Holding the stale State is exactly what the
// losing goroutine does.
//
// Found by review (`0vk.54`).
func TestASweepOnAStaleSnapshotLeavesTheCurrentGrantAlone(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "guard-data")
	store, err := openStateStore(data, operatorSeed{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	g := &Guard{
		state:           store,
		dataDir:         data,
		rotation:        NewRotationDetector(clock, 0, 0),
		authoriseBudget: logging.NewRefusalBudget(auditAuthorisationBound, clock),
		log:             logging.New(os.Stderr, logging.NewLevelVar(slog.LevelError)),
	}
	change := Change{Control: ControlSending, On: true}

	// The grant the poll will still be holding, and its expiry.
	expired := &Authorisation{Change: change, Code: "1111-1111", ExpiresAt: now}
	if err := g.state.update(func(st *State) { st.Authorisation = expired }); err != nil {
		t.Fatal(err)
	}
	stale, err := g.state.load()
	if err != nil {
		t.Fatal(err)
	}

	// Meanwhile the operator asks again: the old grant goes, a live one arrives,
	// and its file is on disk for them to read.
	live := &Authorisation{Change: change, Code: "2222-2222", ExpiresAt: now.Add(authorisationTTL)}
	if err := g.writeAuthorisationFile(live, now); err != nil {
		t.Fatal(err)
	}
	if err := g.state.update(func(st *State) { st.Authorisation = live }); err != nil {
		t.Fatal(err)
	}

	// The poll resumes, on the snapshot it took before any of that.
	g.sweepExpired(t.Context(), stale)

	current, err := g.state.load()
	if err != nil {
		t.Fatal(err)
	}
	if current.Authorisation == nil {
		t.Fatal("the stale sweep cleared a grant it never saw. The operator has a code the " +
			"guard has already forgotten, and redeeming it says the change needs an " +
			"authorisation — so the ceremony fails in a way nothing explains")
	}
	if current.Authorisation.Code != live.Code {
		t.Errorf("the stored grant is %q, want the live one %q",
			current.Authorisation.Code, live.Code)
	}
	if _, err := os.Stat(filepath.Join(data, AuthorisationFile)); err != nil {
		t.Errorf("the stale sweep deleted the live grant's code file: %v; the operator is "+
			"told to read a file that is no longer there", err)
	}
}
