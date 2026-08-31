package lnurl_test

import (
	"context"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnurl"
)

// countingSettings is a settings table that says how often it was read.
type countingSettings struct {
	values map[string]string
	reads  int
}

func (c *countingSettings) AllSettings(context.Context) (map[string]string, error) {
	c.reads++
	return c.values, nil
}

// §7 stopped rate-limiting the lnurlp document (ruled 22 Aug 2026), which means
// an anonymous caller can now fetch it as often as it likes. What makes that
// affordable is this cache: without it every fetch is three point reads on a
// database opened with ONE connection, shared with the invoice stream, so a
// flood of document requests would queue behind — and delay — settlements.
//
// The refresh half is asserted with the same weight. A cache that never expires
// would mean an operator changing their address name in Settings watched the
// document keep announcing the old one, with nothing to do about it but
// restart.
func TestTheAddressDocumentIsServedFromAnInProcessCacheThatStillRefreshes(t *testing.T) {
	settings := &countingSettings{values: map[string]string{
		lnurl.SettingAddressName: "bob",
		lnurl.SettingDomain:      "zap.example",
		lnurl.SettingNostrPubkey: "beef",
	}}
	now := time.Unix(1_700_000_000, 0).UTC()
	service := lnurl.NewService(nil, nil, settings, func() time.Time { return now })

	if _, err := service.PayRequest(t.Context(), "bob"); err != nil {
		t.Fatalf("the first PayRequest: %v", err)
	}
	first := settings.reads
	if first == 0 {
		t.Fatal("the first document was served without reading the settings at all")
	}
	if first != 1 {
		t.Errorf("one document cost %d settings reads; the three rows are read together "+
			"and the store runs on a single connection", first)
	}
	for range 50 {
		if _, err := service.PayRequest(t.Context(), "bob"); err != nil {
			t.Fatalf("a cached PayRequest: %v", err)
		}
	}
	if settings.reads != first {
		t.Errorf("50 further documents cost %d more settings reads; the document is not "+
			"cached, and it is no longer rate-limited either", settings.reads-first)
	}

	// A different name must be answerable from the same cached identity: a
	// cache keyed on the REQUESTED name would be emptied by any caller
	// alternating two names, which is the cheapest possible way to defeat it.
	if _, err := service.PayRequest(t.Context(), "alice"); err != lnurl.ErrUnknownAddress {
		t.Errorf("an unknown name gave %v, want ErrUnknownAddress", err)
	}
	if settings.reads != first {
		t.Error("an unknown name re-read the settings, so alternating two names " +
			"defeats the cache entirely")
	}

	settings.values[lnurl.SettingAddressName] = "robert"
	now = now.Add(3 * time.Second)
	if _, err := service.PayRequest(t.Context(), "robert"); err != nil {
		t.Errorf("a renamed address was still refused after the cache should have "+
			"expired: %v", err)
	}
}
