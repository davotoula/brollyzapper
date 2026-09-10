package guard_test

import (
	"slices"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// authoriseOutcomes is every guard.authorise outcome in the trail, in order.
//
// IN ORDER, and that is half the assertion: "superseded" and "issued" appearing
// somewhere is satisfied by a trail that records them the wrong way round,
// which would read as the new grant being discarded by the old one.
func authoriseOutcomes(t *testing.T, g *guard.Guard) []string {
	t.Helper()
	var out []string
	for _, row := range authoriseRows(t, g) {
		out = append(out, row["outcome"])
	}
	return out
}

// authoriseRows is the outcome and the change sentence together, so a row can be
// checked to name the grant it actually discarded.
func authoriseRows(t *testing.T, g *guard.Guard) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, event := range g.Handle(t.Context(), guard.Request{Op: guard.OpStatus}).Events {
		if event.Event == logging.EventGuardAuthorise {
			out = append(out, event.Attrs)
		}
	}
	return out
}

// `0vk.56` criterion 1. RequestAuthorisation's doc has always said a new request
// supersedes an outstanding one; until now it did that silently, so §12's trail
// showed a request for the first change and then nothing — not consumed, not
// expired, not misused.
//
// TWO DIFFERENT LOOSENINGS, because that is the case the doc calls out and the
// one where a silent overwrite is worst: the trail's last word about the sending
// grant would have been "issued", while what actually happened to it was that
// the operator asked for something else instead.
func TestSupersedingALiveGrantWritesItsDiscardRow(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	// A FIXED "now", not a testClock: nothing here advances time, and the whole
	// point is that the first grant is still live when the second supersedes it.
	now := func() time.Time { return time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC) }
	g := openGuardFull(t, node, d, guard.Options{Now: now}, serverAddr(), true)

	first := guard.Change{Control: guard.ControlSending, On: true}
	second := guard.Change{Control: guard.ControlSpendCap, Msat: 200_000_000}
	if err := g.RequestAuthorisation(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	// A LIVE FIRST GRANT IS THE PREMISE, checked here so a failure says which
	// half broke. The assertion below would catch an expired one anyway — that
	// list is ["issued", "expired", "issued"] and slices.Equal rejects it — but
	// it would read as the superseded row being missing rather than as the
	// first request never having stored anything.
	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !status.AuthorisationPending {
		t.Fatal("the first grant is not pending, so there is nothing live to supersede and " +
			"this test would prove nothing")
	}
	if err := g.RequestAuthorisation(t.Context(), second); err != nil {
		t.Fatal(err)
	}

	want := []string{"issued", "superseded by a new request", "issued"}
	if got := authoriseOutcomes(t, g); !slices.Equal(got, want) {
		t.Fatalf("the trail holds %v, want %v. §12 has to be able to say what became of the "+
			"first grant, and a request followed by nothing is the one answer it must not give",
			got, want)
	}

	// THE ROW NAMES THE OLD GRANT'S CHANGE, not the new one's. A row that named
	// the incoming change would read as the new grant discarding itself, and
	// would be satisfied by capturing the wrong side of the overwrite.
	rows := authoriseRows(t, g)
	if got := rows[1]["control"]; got != string(first.Control) {
		t.Errorf("the superseded row names control %q, want the OLD grant's %q",
			got, first.Control)
	}
	if got := rows[2]["control"]; got != string(second.Control) {
		t.Errorf("the issued row names control %q, want the new grant's %q",
			got, second.Control)
	}
}

// `0vk.56` criterion 2. An EXPIRED first grant is the sweep's row, not a
// superseded one, and the two must not double up: one discard, one row.
func TestAnExpiredGrantIsSweptRatherThanSuperseded(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	clock := &testClock{now: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)}
	g := openGuardFull(t, node, d, guard.Options{Now: clock.Now}, serverAddr(), true)

	change := guard.Change{Control: guard.ControlSending, On: true}
	if err := g.RequestAuthorisation(t.Context(), change); err != nil {
		t.Fatal(err)
	}
	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// Past the TTL, so the sweep at the top of the next request takes it.
	clock.now = status.AuthorisationExpiresAt.Add(time.Minute)
	if err := g.RequestAuthorisation(t.Context(), change); err != nil {
		t.Fatal(err)
	}

	want := []string{"issued", "expired", "issued"}
	if got := authoriseOutcomes(t, g); !slices.Equal(got, want) {
		t.Fatalf("the trail holds %v, want %v. An abandoned grant is EXPIRED — the word redeem "+
			"writes for the same fact — and a superseded row beside it would report one "+
			"discard twice, each blaming a different cause", got, want)
	}
}

// `0vk.56` criterion 5. The superseded code is dead, and which way it dies is
// asserted rather than assumed.
func TestTheSupersededCodeNoLongerRedeems(t *testing.T) {
	node := lndtest.Start(t)
	d := guardDirs(t, node)
	// A FIXED "now", not a testClock: nothing here advances time, and the whole
	// point is that the first grant is still live when the second supersedes it.
	now := func() time.Time { return time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC) }
	g := openGuardFull(t, node, d, guard.Options{Now: now}, serverAddr(), true)

	first := guard.Change{Control: guard.ControlSending, On: true}
	second := guard.Change{Control: guard.ControlSpendCap, Msat: 200_000_000}
	if err := g.RequestAuthorisation(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	stale := readAuthorisationCode(t, d)
	if err := g.RequestAuthorisation(t.Context(), second); err != nil {
		t.Fatal(err)
	}

	err := g.ApplyChange(t.Context(), first, stale)
	if err == nil {
		t.Fatal("a superseded code still redeemed; the ceremony's whole property is that one " +
			"code authorises one change, and two live codes is the phishing this prevents")
	}
	// It falls out as "for a different change": the stored grant is now the
	// SECOND one, and redeem checks the change before the code. Asserted as the
	// sentence the operator actually gets, because "it failed somehow" is
	// equally true of a guard that lost the grant altogether.
	if got := err.Error(); got != "guard: the outstanding authorisation is for a different change; ask for a new one" {
		t.Errorf("redeeming a superseded code says %q; the operator needs to be told the "+
			"outstanding grant is for something else, not that their code was wrong", got)
	}
}
