package api_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/preflight"
	"github.com/davotoula/brollyzapper/internal/store"
)

// SPELLED ONCE, because two of the three assertions below are NEGATIVE. A
// heading changed in the template would leave "the page does not contain the
// old heading" true and those tests green while asserting nothing — silence
// meaning "did not run" rather than "passed".
const (
	mismatchHeading = "refusing the credential for the address it sees"
	relinkForm      = `action="/node/relink"`
)

// livePreflight wires the harness to the REAL report, built from the same node
// state and broker the Node page reads — which is the whole claim these tests
// hold: one verdict, computed once, read by both pages. The default harness
// returns a canned report, and a test of "the two pages agree" against a canned
// report would be asserting the fixture.
func livePreflight(state lnd.State, extra func(*preflight.Inputs)) func(*api.ServerOptions, *store.Store) {
	return func(opts *api.ServerOptions, _ *store.Store) {
		opts.NodeState = func() lnd.State { return state }
		broker := opts.Broker
		opts.Preflight = func(ctx context.Context) preflight.Report {
			in := preflight.Inputs{NodeState: opts.NodeState, BrokerStatus: broker.Status}
			if extra != nil {
				extra(&in)
			}
			return preflight.Run(ctx, in)
		}
	}
}

// mismatchFixture is the guard's half of `20i.3`'s condition: it declined a
// re-bake because a fresh credential would carry the same address.
var mismatchFixture = lnd.BrokerStatus{
	ReceiveMacaroonPresent: true,
	RefusalKind:            guard.KindAddressMismatch,
	CredentialAddress:      "10.61.7.20",
}

// `20i.11` criterion 1: ONE VERDICT, on both pages.
//
// BOTH HALVES OF THE CONDITION, and then the guard's half alone. The guard's
// kind means only "a re-bake would change nothing", which is equally true of a
// healthy install whose operator pressed Re-link twice inside MinBakeInterval —
// `20i.3` measured exactly that telling a working deployment its address was
// wrong and removing its only recovery button. The Node page used to compute
// this itself, so the Security panel could only say "see the Node page"; now
// both read preflight's check, and the second half is where a verdict computed
// from the kind alone goes red on BOTH pages at once.
func TestTheNodePageAndTheSecurityPanelReadOneAddressVerdict(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state lnd.State
		want  bool
	}{
		{"the node is rejecting the credential", lnd.StateRelink, true},
		{"the node is answering: two Re-link clicks, not a mismatch", lnd.StateReady, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, livePreflight(tc.state, nil))
			h.broker.Answer = mismatchFixture
			cookie := h.login(t)
			node := h.get(t, "/node", cookie).Body.String()
			security := h.get(t, "/security", cookie).Body.String()

			for page, body := range map[string]string{"Node": node, "Security": security} {
				if names := strings.Contains(body, "10.61.7.20"); names != tc.want {
					t.Errorf("the %s page names the mismatched address = %v, want %v:\n%s",
						page, names, tc.want, body)
				}
			}
			if got := strings.Contains(node, mismatchHeading); got != tc.want {
				t.Errorf("the Node page explains an address mismatch = %v, want %v:\n%s", got, tc.want, node)
			}
			// THE BUTTON IS THE POINT. Copy explaining that re-linking cannot help,
			// beside a button offering to re-link, is worse than either alone; and
			// a healthy install losing its only recovery button is worse still.
			if offers := strings.Contains(node, relinkForm); offers == tc.want {
				t.Errorf("the Node page offers Re-link = %v with the mismatch verdict %v:\n%s",
					offers, tc.want, node)
			}
			if tc.want {
				for _, want := range []string{"Re-linking will not change this", "restart the guard"} {
					if !strings.Contains(node, want) {
						t.Errorf("the Node page does not carry %q:\n%s", want, node)
					}
				}
			}
		})
	}
}

// `20i.11` criterion 2: THE HANDLER IS GATED, not only the button.
//
// Hiding the form left POST /node/relink mounted, so the refusal lived in a
// template and a replayed or scripted request was honoured. The verdict that
// hides the button is the verdict the handler asks.
func TestARelinkWhileTheAddressIsRefusedIsRefusedWithAFlash(t *testing.T) {
	var retries int
	h := newHarness(t, livePreflight(lnd.StateRelink, nil), func(opts *api.ServerOptions, _ *store.Store) {
		opts.RetryNow = func() { retries++ }
	})
	h.broker.Answer = mismatchFixture
	cookie := h.login(t)

	rec := h.postForm(t, "/node/relink", cookie, url.Values{})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /node/relink = %d, want 303", rec.Code)
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	marker := location.Query().Get("flash")
	if marker == "saved" || api.FlashMessage(marker) == "" {
		t.Errorf("a blocked Re-link redirected with flash %q; want a marker that says why, not success", marker)
	}
	if bakes := h.broker.Bakes(); bakes != 0 {
		t.Errorf("the guard was asked for %d re-bakes while re-linking is blocked; want 0", bakes)
	}
	if retries != 0 {
		t.Errorf("a refused Re-link asked the reconnect loop for %d retries, want 0", retries)
	}
}

// `20i.11` criterion 3, rendered: the certificate hint is on the panel an
// operator reads, not only in `docker logs`.
func TestTheCertificateHintReachesTheSecurityPanel(t *testing.T) {
	nameErr := &lnd.CertificateNameError{Dialled: "10.61.7.1", Names: []string{"localhost", "10.30.0.3"}}
	h := newHarness(t, livePreflight(lnd.StateConnecting, func(in *preflight.Inputs) {
		in.CertificateName = func() *lnd.CertificateNameError { return nameErr }
	}))
	h.broker.Answer = lnd.BrokerStatus{ReceiveMacaroonPresent: true}
	security := h.get(t, "/security", h.login(t)).Body.String()

	if !strings.Contains(security, "tlsextraip=10.61.7.1") {
		t.Errorf("the Security panel does not name the lnd.conf edit:\n%s", security)
	}
	for _, forbidden := range []string{"10.30.0.3", "it names"} {
		if strings.Contains(security, forbidden) {
			t.Errorf("the Security panel carries %q, which is the error's log text:\n%s", forbidden, security)
		}
	}
}

// The other direction, and the one criterion 5 turns into a golden: with no
// refusal the page is exactly what it was. A hint that renders when nothing is
// wrong is a worse defect than the one it was written for.
func TestTheNodePageIsUnchangedWithNoRefusal(t *testing.T) {
	h := newHarness(t)
	h.broker.Answer = lnd.BrokerStatus{ReceiveMacaroonPresent: true}
	page := h.get(t, "/node", h.login(t)).Body.String()

	if strings.Contains(page, mismatchHeading) {
		t.Errorf("the Node page explains an address mismatch that is not happening:\n%s", page)
	}
	if !strings.Contains(page, relinkForm) {
		t.Errorf("the Node page no longer offers Re-link on a healthy install; that button is "+
			"the recovery for a ROTATED macaroon, which is a real and different case:\n%s", page)
	}
}
