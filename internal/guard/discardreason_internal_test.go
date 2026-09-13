package guard

import (
	"slices"
	"testing"
)

// The discard reasons are a closed set, pinned here word for word (`ic9`, in
// `rvw`).
//
// These are durable outcome words: the trail an operator reads after an incident
// carries them, and this package's tests match on them. A fifth, or a rewording, is a decision about how §12 reads — make it here,
// deliberately, rather than at a call site.
func TestTheDiscardReasonsArePinned(t *testing.T) {
	var got []string
	for _, why := range discardReasons {
		got = append(got, discarded(why).word)
	}
	want := []string{
		"expired",
		"offered against a different change",
		"too many wrong codes",
		"superseded by a new request",
	}
	if !slices.Equal(got, want) {
		t.Errorf("the discard reasons are %q, want %q. Changing this list changes the words in "+
			"§12's durable trail; update every reader of those words in the same change", got, want)
	}
	for _, why := range discardReasons {
		if discarded(why).tightening {
			t.Errorf("%q is recorded as a tightening; a grant only ever exists for a loosening",
				why.word)
		}
	}
}
