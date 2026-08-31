package api

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/wallet"
)

// Settings keys the HTTP layer reads or writes. §4 lists them; naming them here
// stops a typo turning "saves" and "reads back" into two different strings.
const (
	// Aliased, not spelled again: internal/lnurl is the package that COMPUTES
	// with the address rows — BaseURL, callbackURL, Metadata — so it owns their
	// names. Two literals for one row is how "saves" and "reads back" become
	// different strings, and the failure is silent (vz1.2).
	SettingDomain = lnurl.SettingDomain
	// SettingDomainInsecure is the scheme the bare domain no longer carries
	// (o34.13). A lightning address is a host[:port]; whether it is served over
	// plain HTTP is a separate fact, and only a LAN or regtest setup ever
	// answers yes.
	//
	// Aliased, not spelled again, by the rule stated below: internal/lnurl is
	// the package that COMPUTES with this row — BaseURL and callbackURL read it
	// — so it owns the name. A second literal here would fail open and in
	// silence: a typo reads back "", which means secure, which advertises an
	// https callback for a box that only answers plain HTTP, with no error
	// anywhere. (SettingDomain above is the same duplication, older than this
	// wave; see the bead.)
	SettingDomainInsecure = lnurl.SettingDomainInsecure
	SettingAddressName    = lnurl.SettingAddressName
	SettingTrustedProxies = "trusted_proxies"
	SettingLogLevel       = "log_level"
	// The rate-limit pair governs the PUBLIC callback and nothing else. It was
	// renamed from rate_limit_per_min/_per_hour by migration 0004: one
	// unlabelled pair used to feed both limiters, so raising it until zaps
	// stopped bouncing silently raised the admin login brute-force ceiling by
	// the same amount (d46.27). The admin limits are constants now — see
	// AdminPerMinute — because an operator has no legitimate reason to raise
	// their own brute-force ceiling, and a setting with no legitimate use is a
	// footgun with a label on it.
	SettingPublicRateLimitMinute = "public_rate_limit_per_min"
	SettingPublicRateLimitHour   = "public_rate_limit_per_hour"
	// The fee reserve's two keys are wallet's: §5 computes max_fee in exactly
	// one place, and the keys that feed it are declared there too.
	SettingMaxFeePPM       = wallet.SettingMaxFeePPM
	SettingMaxFeeFloorMsat = wallet.SettingMaxFeeFloorMsat
	SettingProbeToken      = "probe_token"
	SettingProbeOK         = "probe_ok"
	SettingProbeReason     = "probe_reason"
	SettingProbeAt         = "probe_at"
	// The nostr keys are internal/nostr's, for the same reason the fee keys are
	// internal/wallet's: the package that computes with a value owns the name
	// of the row it comes from.
	SettingNostrPubkey = nostr.SettingPublicKey
	SettingRelays      = nostr.SettingRelays
)

// settingsCacheTTL is how long one read of the settings table is reused.
//
// Every page render needs several settings, and sqlite here runs on a single
// connection, so a handful of point reads per render all serialise behind the
// same mutex as the invoice-stream writer. A short TTL collapses them to one
// query without making a settings change take noticeably longer to appear.
const settingsCacheTTL = 2 * time.Second

// settingsSnapshot is every settings row, read in one query.
type settingsSnapshot map[string]string

func (s settingsSnapshot) get(key string) string { return s[key] }

func (s settingsSnapshot) int(key string, fallback int64) int64 {
	value, err := strconv.ParseInt(s[key], 10, 64)
	if err != nil || value < 0 {
		return fallback
	}
	return value
}

// AllSettings reads the whole settings table at once. The store implements it;
// declared here because this package is the consumer.
type AllSettings interface {
	AllSettings(ctx context.Context) (map[string]string, error)
}

// settingsCache serves a whole-table snapshot, refreshed at most every TTL.
type settingsCache struct {
	source AllSettings
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	current settingsSnapshot
	fetched time.Time
}

func newSettingsCache(source AllSettings, ttl time.Duration, now func() time.Time) *settingsCache {
	if now == nil {
		now = time.Now
	}
	return &settingsCache{source: source, ttl: ttl, now: now}
}

// snapshot returns the settings, reading them if the cached copy is stale. A
// read failure yields the previous snapshot rather than an error: a page that
// renders slightly stale settings is better than one that does not render.
func (c *settingsCache) snapshot(ctx context.Context) settingsSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil && c.now().Sub(c.fetched) < c.ttl {
		return c.current
	}
	values, err := c.source.AllSettings(ctx)
	if err != nil {
		if c.current == nil {
			return settingsSnapshot{}
		}
		return c.current
	}
	c.current, c.fetched = values, c.now()
	return c.current
}

// invalidate forces the next read to go to the database, so a saved setting is
// visible on the redirect that follows the save.
func (c *settingsCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = nil
}
