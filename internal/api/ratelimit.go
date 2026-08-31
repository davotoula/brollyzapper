package api

import (
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// KeyFunc decides which bucket a request counts against.
//
// It is a parameter because the groups must key differently and a second
// limiter implementation would be a second thing to get wrong. Measured on the
// reference box: on the Cloudflare tunnel path every internet client reaches
// the app as one address, so a per-IP limit on the public group would let the
// first abusive caller throttle every honest one — an availability bug wearing
// the costume of a security control. Per-IP is therefore not merely weakened on
// the public group but absent from it: the callback keys on the zap request's
// signed sender, or globally (§7).
type KeyFunc func(*http.Request) string

// KeyGlobal counts every request against one bucket. This is what the public
// callback's globalBackstop uses: a ceiling on total anonymous traffic, which
// is the only thing that is actually true behind a tunnel.
func KeyGlobal(*http.Request) string { return "" }

// KeyClientIP counts per derived client address. Correct for the admin group,
// which is reached over the LAN where addresses are real.
func KeyClientIP(trusted func(netip.Addr) bool) KeyFunc {
	return func(r *http.Request) string { return ClientIP(r, trusted).String() }
}

// Limits supplies the two windows, as a function rather than two ints, so a
// limiter can read a setting that changes under it.
//
// Exactly ONE limiter in this app does: the public callback's globalBackstop,
// which reads public_rate_limit_per_min / _per_hour. Its ceiling is what an
// operator's own zaps bounce off, and §7 has always expected them to raise it.
// The admin limiter takes FixedLimits instead, deliberately — see
// AdminPerMinute for why an adjustable brute-force ceiling is a footgun with a
// label on it (d46.27).
type Limits func() (perMinute, perHour int)

// FixedLimits is the constant form: the admin group, the per-sender bucket, and
// tests.
func FixedLimits(perMinute, perHour int) Limits {
	return func() (int, int) { return perMinute, perHour }
}

// sweepInterval is how often Allow reclaims buckets that have fallen silent.
//
// The public per-sender bucket keys on a nostr pubkey the CALLER chooses, and
// keys are free to mint, so every stranger who zaps once leaves an entry behind
// — 64 bytes of hex plus a one-element slice, for ever. The per-bucket cleanup
// below cannot reclaim those: it only runs for a key that is presented AGAIN
// after its timestamps age out, which is exactly what a one-shot key never is.
// At the default backstop of 60/minute that is roughly 17MB a day, monotonic,
// on a box with a gigabyte or two (review, wave 10).
const sweepInterval = time.Minute

// Limiter is a two-window counter: a burst limit per minute and a slower one
// per hour (spec §7).
type Limiter struct {
	limits Limits
	key    KeyFunc
	now    func() time.Time

	mu    sync.Mutex
	hits  map[string][]time.Time
	swept time.Time
}

// NewCallerKeyedLimiter builds a limiter whose bucket the CALLER supplies,
// through AllowKey.
//
// It exists for one case: the public callback's per-sender bucket, whose key is
// the zap request's verified pubkey. Deriving that means checking a schnorr
// signature, and callbackGate has to derive it anyway to know whether the
// request is a zap at all — so a KeyFunc here would verify the same signature a
// second time, about a millisecond of a Pi's time charged to honest senders.
func NewCallerKeyedLimiter(limits Limits, now func() time.Time) *Limiter {
	return NewLimiter(limits, nil, now)
}

// NewLimiter builds a limiter. The clock is injected so the windows are
// testable without waiting for them.
func NewLimiter(limits Limits, key KeyFunc, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		limits: limits,
		key:    key,
		now:    now,
		hits:   map[string][]time.Time{},
	}
}

// Allow records a request and reports whether it is within both windows.
func (l *Limiter) Allow(r *http.Request) bool {
	if l.key == nil {
		// A caller-keyed limiter reached through Allow. Counting the request
		// globally would silently merge every sender into one bucket — the
		// exact property this limiter exists to avoid — so it fails closed
		// instead of guessing. panic() is not available below api/web (§11).
		return false
	}
	return l.AllowKey(l.key(r))
}

// AllowKey is Allow for a caller that has already derived the bucket.
//
// It exists because deriving the public callback's key means verifying a schnorr
// signature, and the gate has to derive it anyway to know whether the request is
// a zap at all. Going through Allow would verify it a second time (review,
// wave 10) — about a millisecond of a Raspberry Pi's time, charged to honest
// senders only, since a forged request never reaches the second parse.
func (l *Limiter) AllowKey(key string) bool {
	perMinute, perHour := l.limits()
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(now)

	hourAgo := now.Add(-time.Hour)
	kept := l.hits[key][:0]
	var lastMinute int
	for _, at := range l.hits[key] {
		if at.After(hourAgo) {
			kept = append(kept, at)
			if at.After(now.Add(-time.Minute)) {
				lastMinute++
			}
		}
	}
	if len(kept) == 0 {
		// Buckets that fall silent are dropped, so the map tracks live callers
		// rather than every address ever seen.
		delete(l.hits, key)
	} else {
		l.hits[key] = kept
	}
	if lastMinute >= perMinute || len(kept) >= perHour {
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

// sweep drops every bucket whose last request has aged out of the hour window.
//
// Called with l.mu held, at most once a sweepInterval. The live set is bounded
// by the limits in force over an hour, so this walks thousands of entries at
// worst, once a minute — which is what stops a caller who mints a fresh key per
// request from growing the map for ever.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.swept) < sweepInterval {
		return
	}
	l.swept = now
	hourAgo := now.Add(-time.Hour)
	for key, at := range l.hits {
		// Timestamps are appended in order, so the last one is the newest.
		if len(at) == 0 || !at[len(at)-1].After(hourAgo) {
			delete(l.hits, key)
		}
	}
}

// Middleware refuses over-limit requests before they reach the handler.
//
// refuse renders the refusal, and is a parameter rather than a constant 429
// because the admin refusal needs state a Limiter must not hold: whether any
// proxy is trusted, and therefore whether this bucket is one operator's or the
// whole machine's (d46.19). A limiter that could answer that would be a limiter
// that had been handed the settings table.
//
// The public callback does NOT come through here — callbackGate applies its
// three layers itself, because two of them are conditional on the request and
// all three owe the caller an LNURL error body rather than plain text.
func (l *Limiter) Middleware(refuse http.HandlerFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(r) {
			refuse(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
