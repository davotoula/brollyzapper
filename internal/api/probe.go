package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ProbeHeader carries this instance's per-boot token on every LNURL response.
//
// It is what distinguishes "my app answered on that domain" from "something
// answered on that domain" — a lightning address pointed at somebody else's
// LNURL server resolves, responds, and is silently broken (§9).
const ProbeHeader = "X-BrollyZapper-Probe"

// ProbeUserAgent is what the self-probe calls itself when it fetches the
// address document, so the operator's own fetches are separable from strangers'
// in the log (`q22`). See probeOnce for why it is a hint and not a verdict.
const ProbeUserAgent = "BrollyZapper-self-probe"

// probeTimeout bounds one self-probe. It leaves the box and comes back through
// whatever tunnel the operator configured, so it is generous.
const probeTimeout = 15 * time.Second

// ProbeResult is the outcome of one self-probe, kept whole so the admin UI can
// show what happened rather than a bare "not reachable" (§9).
type ProbeResult struct {
	At         time.Time
	OK         bool
	StatusCode int
	Reason     string
}

// Prober verifies that a configured domain reaches THIS instance.
//
// Never DNS: behind Cloudflare Tunnel the name resolves to Cloudflare's
// anycast, not to the box, so a DNS check answers a question nobody asked.
type Prober struct {
	token  string
	client *http.Client
	now    func() time.Time
}

// NewProber builds a prober for the given per-boot token. A nil client gets a
// default with a timeout; a nil clock gets time.Now.
func NewProber(token string, client *http.Client, now func() time.Time) *Prober {
	if client == nil {
		client = &http.Client{Timeout: probeTimeout}
	}
	if now == nil {
		now = time.Now
	}
	return &Prober{token: token, client: client, now: now}
}

// Probe fetches the lightning address's LNURL endpoint over the public internet
// and checks the answer is ours.
func (p *Prober) Probe(ctx context.Context, baseURL, addressName, wantNostrPubkey string) ProbeResult {
	result := ProbeResult{At: p.now()}
	target := baseURL + "/.well-known/lnurlp/" + addressName
	// Every failure is the same shape: record why, and hand the whole result
	// back so the admin UI can show it rather than a bare "not reachable" (§9).
	fail := func(format string, args ...any) ProbeResult {
		result.Reason = fmt.Sprintf(format, args...)
		return result
	}

	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fail("cannot build a request for %s: %v", target, err)
	}
	// The probe NAMES ITSELF (`q22`). It fetches this endpoint over the public
	// internet every few minutes, so the operator's own traffic lands in the
	// same log as every stranger's — and devops reading that log is looking for
	// one specific fetch. A User-Agent is a CLAIM and not proof: anything can
	// send this string, which is why the handler logs it as `user_agent` rather
	// than deciding from it. It is a hint that costs nothing.
	req.Header.Set("User-Agent", ProbeUserAgent)
	resp, err := p.client.Do(req)
	if err != nil {
		return fail("%s is not reachable: %v", target, err)
	}
	defer resp.Body.Close()
	result.StatusCode = resp.StatusCode

	if resp.StatusCode != http.StatusOK {
		return fail("%s answered %d", target, resp.StatusCode)
	}
	if got := resp.Header.Get(ProbeHeader); got != p.token {
		// Something answered, but not us. This is the case that matters: the
		// domain is wrong, or points at another LNURL server entirely.
		return fail("%s answered without this instance's %s token — "+
			"the domain points at something else", target, ProbeHeader)
	}

	// And the ORIGIN that answered has to be the origin the address advertises
	// (vz1.7). Placed AFTER the identity checks on purpose: a domain pointing at
	// somebody else's LNURL server is the more dangerous misconfiguration and
	// the token check is what names it, so it must get its own message rather
	// than this one.
	//
	// The box advertised an http:// callback for an https address. The edge
	// 301s http to https, the client follows it, and the app's own probe header
	// comes back from the far side — so the ONE check built to catch a broken
	// address reported green while every wallet that requires https on the
	// callback would fail, with nothing useful to show the payer.
	//
	// Scheme AND host, because the same silence covers an apex-to-www redirect
	// or an edge that rewrites hostnames. resp.Request is the LAST request in
	// the chain, so its URL is where the answer actually came from, and both
	// sides come from net/url rather than one being hand-cut.
	if got := resp.Request.URL; got.Scheme != req.URL.Scheme || got.Host != req.URL.Host {
		return fail("%s answered as %s://%s — the probe followed a redirect, so it "+
			"measured whatever is in front of this app rather than this app. A wallet "+
			"handed the advertised callback will follow the same redirect, and one that "+
			"requires %s will fail. Set the domain to what actually serves it.",
			target, got.Scheme, got.Host, got.Scheme)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fail("cannot read the answer from %s: %v", target, err)
	}
	var payload struct {
		NostrPubkey string `json:"nostrPubkey"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fail("%s did not answer with an LNURL document: %v", target, err)
	}
	if payload.NostrPubkey != wantNostrPubkey {
		return fail("%s announced nostrPubkey %q, not this instance's",
			target, payload.NostrPubkey)
	}

	result.OK = true
	return result
}

// ProbeTarget supplies what to probe, read fresh each time so a domain change
// in Settings takes effect without a restart.
//
// The ORIGIN, not the domain: the scheme is a second setting since o34.13, and
// handing this the bare host would make the prober decide the scheme for
// itself — which is how it would end up probing https:// while the callback
// advertises http:// on a LAN.
type ProbeTarget func() (baseURL, addressName, nostrPubkey string)

// Run probes on every tick and on every demand, until ctx ends. §9: hourly and
// on demand. The tick channel is a parameter so the schedule is the caller's
// and the test's to decide.
func (p *Prober) Run(ctx context.Context, tick <-chan time.Time, demand <-chan struct{},
	target ProbeTarget, record func(ProbeResult)) {
	probe := func() {
		domain, name, pubkey := target()
		if domain == "" {
			// The domain is optional; with none configured there is nothing to
			// verify and nothing to complain about (§9).
			return
		}
		record(p.Probe(ctx, domain, name, pubkey))
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			probe()
		case <-demand:
			probe()
		}
	}
}

// WithProbeToken stamps the per-boot token onto every LNURL response, which is
// what makes the self-probe able to recognise us.
func WithProbeToken(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(ProbeHeader, token)
		next.ServeHTTP(w, r)
	})
}
