package preflight_test

import (
	"context"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/preflight"
)

// `20i.11`: the certificate-name hint reaches the panel, in the app's words.
//
// It used to reach ONE surface, the logs — and DEPLOYING told a plain-Docker
// operator the app "says this itself", which was true only in `docker logs`.
//
// THE DETAIL IS APP-AUTHORED. The typed error's own Error() names every address
// in the node's certificate, which is the half written for a log; the row names
// the edit and the address the app dials, and nothing the certificate says.
func TestACertificateThatDoesNotNameTheDialAddressIsAFailedCheck(t *testing.T) {
	nameErr := &lnd.CertificateNameError{Dialled: "10.61.7.1", Names: []string{"localhost", "127.0.0.1", "10.30.0.3"}}
	in := inputs(t)
	in.NodeState = func() lnd.State { return lnd.StateConnecting }
	in.CertificateName = func() *lnd.CertificateNameError { return nameErr }

	got := check(t, preflight.Run(t.Context(), in), preflight.CheckCertificateName)

	if got.State != preflight.Fail {
		t.Fatalf("a certificate that does not name the dial address is %v, want a fail", got.State)
	}
	for _, want := range []string{"tlsextraip=10.61.7.1", "lnd.conf", "tls.cert", "tls.key", "restart"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("Detail = %q, want it to name %q", got.Detail, want)
		}
	}
	// None of the error's own text: not its sentence, and not the names the
	// certificate carries, which are the part only a log should hold.
	for _, forbidden := range []string{nameErr.Error(), "lnd:", "it names", "10.30.0.3", "localhost"} {
		if strings.Contains(got.Detail, forbidden) {
			t.Errorf("Detail = %q carries %q, which is the error's text rather than the app's", got.Detail, forbidden)
		}
	}
	if got.Blocks == preflight.BlocksReceiving {
		t.Error("the certificate row blocks receiving; §11 forbids any Tier-2 check doing that")
	}
}

// A hostname in LND_ADDRESS needs the other directive, and the row must choose
// it rather than repeat the address one.
func TestTheCertificateRowNamesTheDomainDirectiveForAName(t *testing.T) {
	in := inputs(t)
	in.NodeState = func() lnd.State { return lnd.StateConnecting }
	in.CertificateName = func() *lnd.CertificateNameError {
		return &lnd.CertificateNameError{Dialled: "lnd", Names: []string{"localhost"}}
	}
	got := check(t, preflight.Run(t.Context(), in), preflight.CheckCertificateName)
	if !strings.Contains(got.Detail, "tlsextradomain=lnd") {
		t.Errorf("Detail = %q, want tlsextradomain=lnd for a dial address that is a name", got.Detail)
	}
}

// A CONNECTION THE NODE ACCEPTED HAS ANSWERED THE QUESTION: gRPC verified the
// same certificate against the same address to get there. So the file is not
// read — which matters because this report is built before every payment, not
// only per render.
func TestTheCertificateIsNotReadWhileTheNodeIsReady(t *testing.T) {
	in := inputs(t)
	calls := 0
	in.CertificateName = func() *lnd.CertificateNameError { calls++; return nil }

	got := check(t, preflight.Run(t.Context(), in), preflight.CheckCertificateName)
	if got.State != preflight.Pass {
		t.Errorf("a Ready node did not pass the certificate row: %+v", got)
	}
	if calls != 0 {
		t.Errorf("the certificate was read %d times while the node was Ready", calls)
	}
}

// `20i.11` criterion 1, at the source: TWO FACTS, AND NEITHER IS ENOUGH ALONE.
//
// The guard's kind means only "a re-bake would change nothing", which is equally
// true of a healthy install whose operator pressed Re-link twice inside
// MinBakeInterval — `20i.3`'s measured false positive. The node must actually be
// rejecting the credential too.
func TestTheAddressMismatchNeedsTheGuardsKindAndTheNodesRejection(t *testing.T) {
	mismatch := lnd.BrokerStatus{
		LNDReachable:      true,
		RefusalKind:       guard.KindAddressMismatch,
		CredentialAddress: "10.61.7.20",
	}
	for _, tc := range []struct {
		name   string
		state  lnd.State
		status lnd.BrokerStatus
		want   bool
	}{
		{"kind and rejection: the condition", lnd.StateRelink, mismatch, true},
		{"kind alone, node answering: two Re-link clicks", lnd.StateReady, mismatch, false},
		{"rejection alone: a rotation", lnd.StateRelink, lnd.BrokerStatus{LNDReachable: true}, false},
		// NO ADDRESS, NO VERDICT. The Node page cannot explain a mismatch it
		// cannot name, so it keeps the Re-link button — and a verdict that blocked
		// re-linking here would have the handler refuse the button the page shows.
		{"kind and rejection, but no address to name", lnd.StateRelink,
			lnd.BrokerStatus{LNDReachable: true, RefusalKind: guard.KindAddressMismatch}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := inputs(t)
			in.NodeState = func() lnd.State { return tc.state }
			in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) { return tc.status, nil }

			report := preflight.Run(t.Context(), in)
			got := check(t, report, preflight.CheckCredentialAddress)

			if failed := got.State == preflight.Fail; failed != tc.want {
				t.Fatalf("mismatch check failed = %v, want %v: %+v", failed, tc.want, got)
			}
			if blocked := report.Blocked(preflight.BlocksRelink); blocked != tc.want {
				t.Errorf("Blocked(BlocksRelink) = %v, want %v", blocked, tc.want)
			}
			// The address travels with the verdict and only with it: a page must
			// not be able to name an address for a refusal that is not happening.
			wantAddress := ""
			if tc.want {
				wantAddress = "10.61.7.20"
				if !strings.Contains(got.Detail, wantAddress) {
					t.Errorf("Detail = %q, want it to name the address the credential is locked to", got.Detail)
				}
			}
			if report.MismatchedAddress != wantAddress {
				t.Errorf("MismatchedAddress = %q, want %q", report.MismatchedAddress, wantAddress)
			}

			// nodeCheck may now name the cause — and only when this says so.
			node := check(t, report, preflight.CheckNodeLinked)
			names := strings.Contains(node.Detail, "address")
			if tc.state == lnd.StateRelink && names != tc.want {
				t.Errorf("node.linked Detail = %q; naming the address cause = %v, want %v",
					node.Detail, names, tc.want)
			}
		})
	}
}

// A guard that did not answer has said nothing about a mismatch.
func TestAnUnansweredGuardIsNotAnAddressMismatch(t *testing.T) {
	in := inputs(t)
	in.NodeState = func() lnd.State { return lnd.StateRelink }
	in.BrokerStatus = func(context.Context) (lnd.BrokerStatus, error) {
		return lnd.BrokerStatus{RefusalKind: guard.KindAddressMismatch, CredentialAddress: "10.61.7.20"},
			context.DeadlineExceeded
	}
	report := preflight.Run(t.Context(), in)
	if report.Blocked(preflight.BlocksRelink) {
		t.Error("a guard that did not answer was read as reporting an address mismatch")
	}
}
