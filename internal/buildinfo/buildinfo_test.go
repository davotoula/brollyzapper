package buildinfo_test

import (
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/buildinfo"
)

func TestResolveKeepsAStampedVersionVerbatim(t *testing.T) {
	if got := buildinfo.Resolve("v1.2.3"); got != "v1.2.3" {
		t.Errorf("Resolve(v1.2.3) = %q, want it returned unchanged", got)
	}
}

// A plain `go build` leaves version at "dev", and the toolchain embeds the VCS
// revision — which is the only thing that identifies what an unstamped binary
// was built from.
func TestResolveFallsBackToTheVCSRevision(t *testing.T) {
	got := buildinfo.Resolve("dev")
	if got != "dev" && !strings.HasPrefix(got, "dev+") {
		t.Errorf("Resolve(dev) = %q, want \"dev\" or \"dev+<revision>\"", got)
	}
	if rev, ok := strings.CutPrefix(got, "dev+"); ok && len(rev) > 12 {
		t.Errorf("revision %q is %d characters, want it truncated to 12", rev, len(rev))
	}
}
