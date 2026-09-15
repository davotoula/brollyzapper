package api

import (
	"slices"
	"testing"

	"github.com/davotoula/brollyzapper/internal/preflight"
)

// as0.11 criterion 4: the banner is "what is wrong now", and a row nobody could
// evaluate is not that. Only failures reach it — by state, never by wording, so
// the not-checked rows here carry details that would read as alarming if they
// did.
func TestTheBannerListsFailuresAndNotRowsThatWereNotChecked(t *testing.T) {
	notChecked := []preflight.Check{
		{ID: "a", State: preflight.NotChecked, Detail: "The guard is not answering, so it could not be asked.",
			Blocks: preflight.BlocksSending},
		{ID: "b", State: preflight.NotChecked, Detail: "There is no receive macaroon yet."},
		{ID: "c", State: preflight.NotChecked, Title: "A row with no detail"},
	}
	if got := degraded(preflight.Report{Checks: notChecked}); len(got) != 0 {
		t.Errorf("a report of only not-checked rows puts %q in the banner, want nothing", got)
	}

	failed := preflight.Check{ID: "d", State: preflight.Fail, Detail: "The guard is not answering on its socket."}
	passed := preflight.Check{ID: "e", State: preflight.Pass, Detail: "Within the node's balance."}
	report := preflight.Report{Checks: append(slices.Clone(notChecked), failed, passed)}
	if got, want := degraded(report), []string{failed.Detail}; !slices.Equal(got, want) {
		t.Errorf("one failure beside three not-checked rows and a pass gives the banner %q, want %q", got, want)
	}
}
