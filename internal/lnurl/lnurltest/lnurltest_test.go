package lnurltest_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
)

// recorder stands in for *testing.T so the guard can be shown to FAIL.
//
// This is why lnurltest.TB exists: testing.TB has an unexported method and
// cannot be implemented outside the testing package, so a guard that took it
// could only ever be observed passing.
type recorder struct{ failures []string }

func (r *recorder) Helper() {}

func (r *recorder) Fatalf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

// ohi criterion 3, and the reason this package exists at all.
//
// The guard now lives in one place, so that one place has to be proved to
// guard. It has been wrong before: Wave 8's first fixture was canonical, the
// whitespace injection was a silent no-op, and a planted json.Marshal(parsed)
// passed the suite. A guard that has only ever passed has been written, not
// tested.
func TestAssertNonCanonicalRejectsACanonicalFixture(t *testing.T) {
	canonical := lnurltest.SignedZapRequest(t, nil)

	// The premise: go-nostr's own marshaller reproduces these bytes exactly.
	var event gonostr.Event
	if err := event.UnmarshalJSON(canonical); err != nil {
		t.Fatalf("the canonical fixture does not parse: %v", err)
	}
	round, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if string(round) != string(canonical) {
		t.Fatalf("the 'canonical' fixture does not survive a round-trip, so this test "+
			"cannot show the guard rejecting one:\n got %s\nwant %s", round, canonical)
	}

	var rec recorder
	lnurltest.AssertNonCanonical(&rec, canonical)
	if len(rec.failures) != 1 {
		t.Fatalf("AssertNonCanonical accepted a canonical fixture (%d failures); it is "+
			"the guard for §16's most dangerous failure and it does not guard",
			len(rec.failures))
	}
	if !strings.Contains(rec.failures[0], "round-trip") {
		t.Errorf("the failure does not say what is wrong: %q", rec.failures[0])
	}
}

// And it must accept the fixture the helpers actually hand out, or every test
// using them would fail for the wrong reason. The builder takes the real
// testing.TB — only the guard needs the recorder — so a rejection here would
// fail this test outright, which is the same signal.
func TestAssertNonCanonicalAcceptsTheNonCanonicalFixture(t *testing.T) {
	raw := lnurltest.NonCanonicalZapRequest(t, nil)
	if raw == nil {
		t.Fatal("no fixture was returned")
	}
	var rec recorder
	lnurltest.AssertNonCanonical(&rec, raw)
	if len(rec.failures) != 0 {
		t.Errorf("AssertNonCanonical rejected its own fixture: %v", rec.failures)
	}
}

// Garbage must be reported as garbage rather than sailing through as
// "different from its round-trip".
func TestAssertNonCanonicalRejectsSomethingThatIsNotAnEvent(t *testing.T) {
	var rec recorder
	lnurltest.AssertNonCanonical(&rec, []byte("{not json"))
	if len(rec.failures) != 1 || !strings.Contains(rec.failures[0], "parseable") {
		t.Errorf("failures = %v, want one naming the parse", rec.failures)
	}
}
