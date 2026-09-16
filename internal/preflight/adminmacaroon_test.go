package preflight_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/preflight"
)

// as0.10: the guard stayed up instead of crash-looping, and this row is what it
// stayed up to say. Why it is keyed on the guard's Status alone, and not on
// lnd.StateRelink, is on guardAdminMacaroonCheck — the Ready case in the table is
// the one a row keyed on the server's state would miss.
//
// TWO FACTS: the kind, and the node not answering the guard. The guard reads the
// kind after its own GetInfo, so the two agree within one answer; the row asks
// for both anyway, and the reachable case pins that it does.
func TestTheGuardAdminMacaroonRowNeedsTheKindAndAnUnreachableNode(t *testing.T) {
	stuck := lnd.BrokerStatus{RefusalKind: guard.KindAdminMacaroonStillRejected, ReceiveMacaroonPresent: true}
	for _, tc := range []struct {
		name   string
		state  lnd.State
		status lnd.BrokerStatus
		want   preflight.State
	}{
		{"the kind, the node refusing the guard, the server still Ready", lnd.StateReady, stuck, preflight.Fail},
		{"the kind, the server rejected as well", lnd.StateRelink, stuck, preflight.Fail},
		{"the kind, but the node answered this Status", lnd.StateReady,
			lnd.BrokerStatus{RefusalKind: guard.KindAdminMacaroonStillRejected, LNDReachable: true}, preflight.Pass},
		{"unreachable alone: a node that is down, or a first rejection run", lnd.StateReady,
			lnd.BrokerStatus{}, preflight.Pass},
		{"another kind, unreachable", lnd.StateRelink,
			lnd.BrokerStatus{RefusalKind: guard.KindAddressMismatch}, preflight.Pass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := inputs(t)
			in.NodeState = func() lnd.State { return tc.state }
			in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) { return tc.status, nil }

			report := preflight.Run(t.Context(), in)
			got := check(t, report, preflight.CheckGuardAdminMacaroon)
			if got.State != tc.want {
				t.Fatalf("row is %v, want %v: %+v", got.State, tc.want, got)
			}
			failed := tc.want == preflight.Fail
			if report.AdminMacaroonRejected != failed {
				t.Errorf("AdminMacaroonRejected = %v, want %v — the Node page reads the verdict from "+
					"here, and must not explain a finding the Security page does not make",
					report.AdminMacaroonRejected, failed)
			}
			if !failed {
				return
			}
			// The repair, named at the level §19 allows: what is mounted where,
			// never a deployment's path to it.
			for _, want := range []string{"admin macaroon mounted into the guard", "not a macaroon rotation",
				"then restart the guard"} {
				if !strings.Contains(got.Detail, want) {
					t.Errorf("Detail does not carry %q: %q", want, got.Detail)
				}
			}
			if strings.Contains(got.Detail, "/") {
				t.Errorf("Detail names a path, which the generic app may not assume (§19): %q", got.Detail)
			}
			// Re-link stays offered: see guardAdminMacaroonCheck's Blocks.
			if len(report.BlockedBy(preflight.BlocksRelink)) != 0 {
				t.Errorf("re-linking is blocked; the decision recorded on the row is that it is not")
			}
		})
	}
}

// The receive credential's expiry is cited only while the SERVER is Ready — the
// one state in which "the app keeps receiving" is true. With the server
// rejected too, the sentence would promise receiving that has already stopped.
func TestTheGuardAdminMacaroonRowCitesTheReceiveExpiryOnlyWhileReceiving(t *testing.T) {
	expiry := time.Date(2026, 9, 23, 8, 30, 0, 0, time.UTC)
	status := lnd.BrokerStatus{RefusalKind: guard.KindAdminMacaroonStillRejected,
		ReceiveMacaroonPresent: true, ReceiveExpiry: expiry}
	for state, want := range map[lnd.State]bool{lnd.StateReady: true, lnd.StateRelink: false} {
		t.Run(string(state), func(t *testing.T) {
			in := inputs(t)
			in.NodeState = func() lnd.State { return state }
			in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) { return status, nil }
			got := check(t, preflight.Run(t.Context(), in), preflight.CheckGuardAdminMacaroon)
			if cites := strings.Contains(got.Detail, "2026-09-23 08:30 UTC"); cites != want {
				t.Errorf("with the server %s the Detail cites the expiry = %v, want %v: %q",
					state, cites, want, got.Detail)
			}
		})
	}
}

// A guard that did not answer has said nothing about its mount.
func TestAnUnansweredGuardIsNotAnAdminMacaroonFinding(t *testing.T) {
	in := inputs(t)
	in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
		return lnd.BrokerStatus{RefusalKind: guard.KindAdminMacaroonStillRejected}, errors.New("dial: no such file")
	}
	report := preflight.Run(t.Context(), in)
	if got := check(t, report, preflight.CheckGuardAdminMacaroon); got.State != preflight.NotChecked {
		t.Errorf("the row is %v with the guard not answering, want not checked: %q", got.State, got.Detail)
	}
	if report.AdminMacaroonRejected {
		t.Error("a guard that did not answer was read as reporting a rejected mount")
	}
}
