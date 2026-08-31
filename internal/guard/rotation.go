package guard

import (
	"sync"
	"time"
)

// Rotation-detection defaults (spec §6): three consecutive authentication
// failures inside thirty seconds mean the node's macaroons were rotated.
const (
	DefaultRotationWindow    = 30 * time.Second
	DefaultRotationThreshold = 3
	// RotationExitDelay is the settling pause before the guard exits, so
	// restart: on-failure does not spin.
	RotationExitDelay = 10 * time.Second
	// ProbeInterval is how often the guard asks LND about itself once it has
	// been rejected once (as0.8).
	//
	// Three samples at ten seconds span twenty, which fits inside the window
	// above with room for the rejection that started the loop. Nothing else in
	// the deployment produces samples anywhere near that fast: measured on
	// regtest, the server's re-bake ask is capped at one a minute, its guard
	// poll at one per five minutes, and the guard's own renewal check is
	// hourly — so seven failures arrived over 4m37s and no thirty-second
	// window ever held three. The detector fired only while a human was
	// refreshing the Node page.
	ProbeInterval = 10 * time.Second
)

// RotationDetector decides when repeated authentication failures stop looking
// like a flaky node and start looking like rotation.
//
// It counts ONLY the guard's own probes (§6, as0.8). Anything else that sees
// LND refuse admin.macaroon — a bake, a Status, the startup credential check —
// ARMS the detector and never advances it. That separation is the whole point:
// the old design counted whoever happened to call in, so the threshold could be
// reached by an operator clicking Re-link twice, and could not be reached at
// all when nobody was there. Measured both ways.
//
// The clock is injected because the alternative is a test that waits thirty
// seconds.
type RotationDetector struct {
	now       func() time.Time
	window    time.Duration
	threshold int

	mu sync.Mutex
	// armed means something saw a rejection and nothing has succeeded since.
	armed bool
	// consecutive is the run of rejected PROBES, and lastProbe is when the
	// most recent one landed.
	consecutive int
	lastProbe   time.Time
}

// NewRotationDetector builds a detector. Zero values take the §6 defaults.
func NewRotationDetector(now func() time.Time, window time.Duration, threshold int) *RotationDetector {
	if now == nil {
		now = time.Now
	}
	if window <= 0 {
		window = DefaultRotationWindow
	}
	if threshold <= 0 {
		threshold = DefaultRotationThreshold
	}
	return &RotationDetector{now: now, window: window, threshold: threshold}
}

// clock is the detector's injected time source, reused by the guard so
// everything it timestamps moves together in tests.
func (d *RotationDetector) clock() time.Time { return d.now() }

// Rejected records that LND refused admin.macaroon, from wherever.
//
// It arms the probe loop and nothing more. A caller cannot push the guard
// toward its own exit however often it calls: Re-link has no rate limit, and
// clicking it is exactly what an operator does while the node is rejecting.
func (d *RotationDetector) Rejected() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.armed = true
}

// Armed reports whether a rejection is outstanding — one has been seen and
// nothing has succeeded since. It is what tells the probe loop to sample.
func (d *RotationDetector) Armed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.armed
}

// ProbeFailed records one rejected probe and reports whether that completes a
// run of consecutive rejections.
//
// CONSECUTIVE is the false-positive protection §6 now rests on, and it is
// enforced two ways: a success clears the run (Success), and a gap longer than
// the window breaks it. The gap check is what stops a probe that took minutes —
// a loaded node, a TLS handshake that stalled — from being counted as adjacent
// to one from before the trouble started.
func (d *RotationDetector) ProbeFailed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if !d.lastProbe.IsZero() && now.Sub(d.lastProbe) > d.window {
		d.consecutive = 0
	}
	d.lastProbe = now
	d.consecutive++
	return d.consecutive >= d.threshold
}

// Success clears the run: §6 says three CONSECUTIVE failures, and a call that
// worked means the credential is fine.
func (d *RotationDetector) Success() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.armed = false
	d.consecutive = 0
	d.lastProbe = time.Time{}
}
