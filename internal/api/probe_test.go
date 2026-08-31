package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
)

const testPubkey = "npub-abcdef0123456789"

// lnurlpServer stands in for this instance as reached over the public internet.
func lnurlpServer(t *testing.T, token, pubkey string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/.well-known/lnurlp/") {
			http.NotFound(w, r)
			return
		}
		if token != "" {
			w.Header().Set(api.ProbeHeader, token)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"callback":"https://x/cb","nostrPubkey":"` + pubkey + `","allowsNostr":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Spec §9: verification is an HTTP self-probe, never DNS — behind Cloudflare
// Tunnel the name resolves to Cloudflare's anycast, not to the box. The probe
// checks the response carries this instance's nostrPubkey AND its per-boot
// token, which is what distinguishes "my app answered" from "something
// answered".
func TestProbeSucceedsWhenTheEndpointIsThisInstance(t *testing.T) {
	const token = "per-boot-token-value"
	srv := lnurlpServer(t, token, testPubkey, http.StatusOK)
	prober := api.NewProber(token, srv.Client(), nil)

	got := prober.Probe(t.Context(), srv.URL, "bob", testPubkey)
	if !got.OK {
		t.Fatalf("probe failed against this instance: %+v", got)
	}
	if got.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", got.StatusCode)
	}
}

// Someone else's LNURL server answering on the domain is the failure this
// catches: the DNS name resolves, the endpoint responds, and the lightning
// address is still broken.
func TestProbeFailsWhenSomethingElseAnswers(t *testing.T) {
	cases := []struct {
		name          string
		token, pubkey string
		status        int
		wantReasonHas string
	}{
		{"no probe header at all", "", testPubkey, http.StatusOK, "token"},
		{"another instance's token", "someone-elses-token", testPubkey, http.StatusOK, "token"},
		{"our token but another key", "per-boot-token-value", "npub-somebody-else", http.StatusOK, "nostrPubkey"},
		{"endpoint errors", "per-boot-token-value", testPubkey, http.StatusBadGateway, "502"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := lnurlpServer(t, c.token, c.pubkey, c.status)
			prober := api.NewProber("per-boot-token-value", srv.Client(), nil)

			got := prober.Probe(t.Context(), srv.URL, "bob", testPubkey)
			if got.OK {
				t.Fatalf("probe succeeded against %s: %+v", c.name, got)
			}
			if !strings.Contains(got.Reason, c.wantReasonHas) {
				t.Errorf("reason = %q, want it to mention %q so the operator can act on it",
					got.Reason, c.wantReasonHas)
			}
		})
	}
}

// A failed probe keeps the domain saved and flags "not reachable" with the
// result shown — a wrong domain otherwise breaks the lightning address
// silently (§9).
func TestProbeAgainstAnUnreachableHostIsAResultNotAnError(t *testing.T) {
	prober := api.NewProber("token", nil, nil)
	got := prober.Probe(t.Context(), "https://127.0.0.1:1", "bob", testPubkey)
	if got.OK {
		t.Fatal("probe reported success against a closed port")
	}
	if got.Reason == "" {
		t.Error("an unreachable host produced no reason to show the operator")
	}
}

// The token has to reach the wire, or the probe can never succeed. Every LNURL
// response carries it, which is what makes the check work once P2 lands the
// real handler.
func TestProbeTokenIsEmittedOnLNURLResponses(t *testing.T) {
	handler := api.WithProbeToken("the-token", marker("lnurl-body"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/lnurlp/bob", nil))

	if got := rec.Header().Get(api.ProbeHeader); got != "the-token" {
		t.Errorf("%s = %q, want the per-boot token", api.ProbeHeader, got)
	}
	if rec.Body.String() != "lnurl-body" {
		t.Errorf("body = %q; the wrapper must not change the response", rec.Body.String())
	}
}

// §9: the probe re-runs hourly and on demand. Driven by an injected tick, so
// the test costs nothing.
func TestProbeLoopRunsOnEachTickAndOnDemand(t *testing.T) {
	const token = "per-boot-token-value"
	srv := lnurlpServer(t, token, testPubkey, http.StatusOK)
	prober := api.NewProber(token, srv.Client(), nil)

	results := make(chan api.ProbeResult, 4)
	tick := make(chan time.Time)
	demand := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go prober.Run(ctx, tick, demand, func() (domain, name, pubkey string) {
		return srv.URL, "bob", testPubkey
	}, func(r api.ProbeResult) { results <- r })

	tick <- time.Now()
	if got := <-results; !got.OK {
		t.Errorf("the scheduled probe failed: %+v", got)
	}
	demand <- struct{}{}
	if got := <-results; !got.OK {
		t.Errorf("the on-demand probe failed: %+v", got)
	}
}

// vz1.7 criterion 3 — the half that would have caught the field failure on its
// own, even with the old flag rule.
//
// The 0.1.7 box advertised an http:// callback for an https address. The edge
// 301s http to https, the client follows, and the app's own probe header comes
// back from the far side — so the ONE check built to catch a broken address
// reported GREEN while every wallet that requires https on the callback would
// fail, with nothing useful to show the payer.
//
// A redirect that changes the scheme means the probe measured the edge, not this
// app.
func TestAProbeThatOnlySucceedsAfterASchemeRedirectIsAFailure(t *testing.T) {
	const token = "per-boot-token-value"
	// The far side: answers correctly, with this instance's own token.
	real := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(api.ProbeHeader, token)
		_, _ = w.Write([]byte(`{"nostrPubkey":"` + testPubkey + `"}`))
	}))
	defer real.Close()

	// The edge: 301s to it, exactly as a tunnel does.
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, real.URL+r.URL.Path, http.StatusMovedPermanently)
	}))
	defer edge.Close()

	prober := api.NewProber(token, real.Client(), nil)
	got := prober.Probe(t.Context(), edge.URL, "bob", testPubkey)

	if got.OK {
		t.Fatal("the probe passed by following a redirect to a different scheme; that is " +
			"the edge answering, not this app, and it is exactly what reported green on " +
			"the box while the callback was unusable")
	}
	// The reason has to name the mismatch, not merely say "not reachable": an
	// operator reading this has to know the fix is the scheme, not the DNS.
	// "https" is not checked on its own — it contains "http", so that pair
	// would pass on either word alone.
	for _, want := range []string{"redirect", "https://" + strings.TrimPrefix(real.URL, "https://")} {
		if !strings.Contains(got.Reason, want) {
			t.Errorf("reason = %q, want it to name %q", got.Reason, want)
		}
	}

	// A redirect that KEEPS the scheme and changes the host is the same silence
	// — an apex-to-www edge, or one that rewrites hostnames. The advertised
	// callback sends wallets through the same redirect.
	sameScheme := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, real.URL+r.URL.Path, http.StatusMovedPermanently)
	}))
	defer sameScheme.Close()
	if hostMoved := prober.Probe(t.Context(), sameScheme.URL, "bob", testPubkey); hostMoved.OK {
		t.Error("a redirect to a different HOST passed; the wallet would follow it too")
	}

	// Ordering: a domain pointing at somebody ELSE's LNURL server, reached
	// through a redirect, must be told THAT — it is the more dangerous
	// misconfiguration and the token check is what names it.
	stranger := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"nostrPubkey":"` + testPubkey + `"}`))
	}))
	defer stranger.Close()
	toStranger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, stranger.URL+r.URL.Path, http.StatusMovedPermanently)
	}))
	defer toStranger.Close()
	elsewhere := prober.Probe(t.Context(), toStranger.URL, "bob", testPubkey)
	if elsewhere.OK {
		t.Fatal("a probe answered by somebody else's server passed")
	}
	if !strings.Contains(elsewhere.Reason, "points at something else") {
		t.Errorf("reason = %q, want the token check to name it — an operator told to "+
			"'set the scheme' would go and fix the wrong thing", elsewhere.Reason)
	}

	// The control: the same server, probed over the scheme it actually serves,
	// still passes. Without this the rule could be "always fail".
	direct := prober.Probe(t.Context(), real.URL, "bob", testPubkey)
	if !direct.OK {
		t.Errorf("probing the right scheme directly failed: %s", direct.Reason)
	}
}

// q22: the self-probe NAMES ITSELF when it fetches the address document.
//
// §9's probe fetches this endpoint over the public internet every few minutes,
// so the operator's own traffic lands in the same log as every stranger's — and
// devops reading that log during an investigation is looking for one specific
// fetch. A User-Agent is a CLAIM and not proof; the handler logs it under
// `user_agent` rather than deciding from it, and this is what makes the claim
// available at all.
func TestTheSelfProbeIdentifiesItselfToTheDocumentEndpoint(t *testing.T) {
	const token = "per-boot-token-value"
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("User-Agent")
		w.Header().Set(api.ProbeHeader, token)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"callback":"https://x/cb","nostrPubkey":"` + testPubkey + `","allowsNostr":true}`))
	}))
	t.Cleanup(srv.Close)

	if got := api.NewProber(token, srv.Client(), nil).Probe(t.Context(), srv.URL, "bob", testPubkey); !got.OK {
		t.Fatalf("the probe failed: %+v", got)
	}

	if seen != api.ProbeUserAgent {
		t.Errorf("the probe called itself %q, want %q — without it the operator's own fetches "+
			"are indistinguishable from a stranger's in the log this bead added", seen,
			api.ProbeUserAgent)
	}
}
