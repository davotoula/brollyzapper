package guard

import (
	"log/slog"
	"net/netip"
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

// The superseded row names what was in the state AT THE LOCK, not what this
// call's snapshot held (`0vk.56`).
//
// THE SEQUENCE, which two socket connections reach on their own: the operator
// asks for a second code while a first is live, so RequestAuthorisation loads
// state holding grant A; before it takes the store's lock, another connection
// redeems A — row and file both gone. This call then takes the lock and finds
// nothing to supersede. If it captured from its own snapshot instead, it would
// write "an authorisation was discarded — superseded by a new request" for a
// grant that had already been consumed and audited as authorised, and §12 would
// carry two contradictory accounts of one grant's end.
//
// This is `0vk.54`'s stale-snapshot HIGH in a second coat, which is why the
// capture is inside the closure rather than beside the load.
//
// DRIVEN BY HAND, as its neighbour above is: the interleaving is the defect, and
// a test that raced for it would reproduce it on some runs and certify nothing
// on the others. THE CLOCK IS THE INJECTION POINT because it is called between
// the load and the lock and nothing else here is — RequestAuthorisation reads
// the clock to stamp the new grant's expiry, and that is the last thing it does
// before updateIf. Using it this way is a test seam, not a claim about
// production ordering.
func TestASupersedeOnAStaleSnapshotClaimsNothing(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "guard-data")
	store, err := openStateStore(data, operatorSeed{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	var g *Guard
	// consumed fires ONCE, on the clock read that stamps the new grant, which is
	// after RequestAuthorisation has loaded state and before it takes the lock.
	var consumed bool
	clock := func() time.Time {
		if g != nil && !consumed {
			if current, err := g.state.load(); err == nil && current.Authorisation != nil {
				consumed = true
				// The other connection redeems A: row and file together, which
				// is what consumeAuthorisation does.
				if err := g.state.update(func(st *State) {
					g.clearAuthorisationFile()
					st.Authorisation = nil
				}); err != nil {
					t.Error(err)
				}
			}
		}
		return now
	}
	g = &Guard{
		state:           store,
		dataDir:         data,
		serverIP:        netip.MustParseAddr("10.21.0.17"),
		rotation:        NewRotationDetector(clock, 0, 0),
		authoriseBudget: logging.NewRefusalBudget(auditAuthorisationBound, clock),
		log:             logging.New(os.Stderr, logging.NewLevelVar(slog.LevelError)),
	}

	// Grant A is live and stored: the state this call will load.
	a := &Authorisation{
		Change:    Change{Control: ControlSending, On: true},
		Code:      "1111-1111",
		ExpiresAt: now.Add(authorisationTTL),
	}
	if err := g.state.update(func(st *State) { st.Authorisation = a }); err != nil {
		t.Fatal(err)
	}

	if err := g.RequestAuthorisation(t.Context(), Change{Control: ControlSpendCap, Msat: 200_000_000}); err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatal("the interleaving never fired, so this test asserts nothing about a stale " +
			"snapshot; RequestAuthorisation's clock reads have moved")
	}

	var discards int
	for _, event := range g.recentAuditEvents() {
		if event.Event == logging.EventGuardAuthorise &&
			event.Attrs["outcome"] == "superseded by a new request" {
			discards++
		}
	}
	if discards != 0 {
		t.Errorf("a superseded row was written for a grant another connection had already "+
			"consumed (%d of them). The trail would hold two endings for one grant, and the "+
			"one this call invented never happened", discards)
	}
}

// A grant that runs out of time BETWEEN the sweep and the lock is not called
// superseded (`0vk.56`).
//
// WHY THE not-expired GUARD ON THE CAPTURE IS LOAD-BEARING, and it is not the
// case the brief predicted. On the ordinary expired path the sweep at the top of
// RequestAuthorisation has already cleared the row, so the closure finds nothing
// and the guard never runs — removing it changes nothing there. The window where
// it does run is this one: the sweep reads the clock and sees a LIVE grant, then
// the grant's TTL passes before the clock read that stamps the new one, so the
// closure meets a stored grant that is now expired. Without the guard the trail
// would call that a supersession, which is the one thing it was not — the
// operator's second request and the expiry are independent, and the row would
// blame the wrong one.
//
// It gets no row at all, which is what it got before `0vk.56` too: the sweep
// judged it live and the next sweep will never see it. That is a TTL-boundary
// race of microseconds and the honest cost of not folding the two paths; naming
// it wrongly would be worse than not naming it.
//
// DRIVEN BY HAND, on the clock, for the reason its neighbours give.
func TestAGrantThatExpiresBeforeTheLockIsNotCalledSuperseded(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "guard-data")
	store, err := openStateStore(data, operatorSeed{})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	// READ #1 is sweepExpired's own check, and it must see the grant live. Every
	// read after it is past the TTL, so the `now` that reaches the closure has
	// the grant expired. Counted rather than guessed: a probe printed the reads.
	reads := 0
	clock := func() time.Time {
		reads++
		if reads == 1 {
			return base
		}
		return base.Add(authorisationTTL + time.Minute)
	}
	g := &Guard{
		state:           store,
		dataDir:         data,
		serverIP:        netip.MustParseAddr("10.21.0.17"),
		rotation:        NewRotationDetector(clock, 0, 0),
		authoriseBudget: logging.NewRefusalBudget(auditAuthorisationBound, clock),
		log:             logging.New(os.Stderr, logging.NewLevelVar(slog.LevelError)),
	}
	a := &Authorisation{
		Change:    Change{Control: ControlSending, On: true},
		Code:      "1111-1111",
		ExpiresAt: base.Add(authorisationTTL),
	}
	if err := g.state.update(func(st *State) { st.Authorisation = a }); err != nil {
		t.Fatal(err)
	}

	if err := g.RequestAuthorisation(t.Context(), Change{Control: ControlSpendCap, Msat: 200_000_000}); err != nil {
		t.Fatal(err)
	}

	var outcomes []string
	for _, event := range g.recentAuditEvents() {
		if event.Event == logging.EventGuardAuthorise {
			outcomes = append(outcomes, event.Attrs["outcome"])
		}
	}
	// THE SWEEP MUST NOT HAVE TAKEN IT, or this test is exercising the ordinary
	// expired path and the guard it is about never ran.
	for _, got := range outcomes {
		if got == "expired" {
			t.Fatalf("the sweep took the grant, so the closure never met an expired one and "+
				"this test asserts nothing: %v", outcomes)
		}
	}
	for _, got := range outcomes {
		if got == "superseded by a new request" {
			t.Errorf("a grant that ran out of time was recorded as superseded: %v. The "+
				"operator's second request did not end it; the clock did, and the trail "+
				"would name the wrong cause", outcomes)
		}
	}
}
