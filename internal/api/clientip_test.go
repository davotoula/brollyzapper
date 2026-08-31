package api_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
)

// trustsUmbrelSubnet is what the package sets: TRUSTED_PROXIES=${NETWORK_IP}/16.
func trustsUmbrelSubnet(addr netip.Addr) bool {
	return netip.MustParsePrefix("10.21.0.0/16").Contains(addr.Unmap())
}

func request(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/lnurlp/bob/callback", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// Spec §7: the TCP peer is never the client when it is a trusted proxy; walk
// X-Forwarded-For right to left and take the first address NOT in a trusted
// range. Trusting the header unconditionally lets any caller spoof past a limit.
func TestClientIPWalksForwardedForRightToLeft(t *testing.T) {
	cases := []struct {
		name    string
		remote  string
		headers map[string]string
		want    string
	}{
		{
			name:   "untrusted peer is the client, header ignored",
			remote: "203.0.113.9:5000",
			headers: map[string]string{
				"X-Forwarded-For": "1.2.3.4",
			},
			want: "203.0.113.9",
		},
		{
			name:    "trusted peer with no header falls back to the peer",
			remote:  "10.21.0.3:5000",
			headers: nil,
			want:    "10.21.0.3",
		},
		{
			name:   "one trusted hop, as app_proxy produces it",
			remote: "10.21.0.3:5000",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.7",
			},
			want: "203.0.113.7",
		},
		{
			name:   "several hops: the rightmost untrusted entry wins",
			remote: "10.21.0.3:5000",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.1, 203.0.113.7, 10.21.0.9",
			},
			want: "203.0.113.7",
		},
		{
			name:   "a client-supplied chain cannot promote itself",
			remote: "10.21.0.3:5000",
			headers: map[string]string{
				"X-Forwarded-For": "1.2.3.4, 203.0.113.7",
			},
			want: "203.0.113.7",
		},
		{
			name:   "every hop trusted: the leftmost is the best available answer",
			remote: "10.21.0.3:5000",
			headers: map[string]string{
				"X-Forwarded-For": "10.21.0.8, 10.21.0.9",
			},
			want: "10.21.0.8",
		},
		{
			name:   "v4-mapped values normalise, as app_proxy emits them",
			remote: "[::ffff:10.21.0.3]:5000",
			headers: map[string]string{
				"X-Forwarded-For": "::ffff:203.0.113.7",
			},
			want: "203.0.113.7",
		},
		{
			name:   "garbage in the header is skipped, not fatal",
			remote: "10.21.0.3:5000",
			headers: map[string]string{
				"X-Forwarded-For": "not-an-ip, 203.0.113.7",
			},
			want: "203.0.113.7",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := api.ClientIP(request(c.remote, c.headers), trustsUmbrelSubnet)
			if got.String() != c.want {
				t.Errorf("ClientIP = %s, want %s", got, c.want)
			}
		})
	}
}

// Box verification, 2026-08-21: app_proxy neither sets nor strips X-Real-IP, so
// it arrives verbatim from the client. Several rate-limiter helpers check it
// FIRST; behind app_proxy that is a free bypass.
func TestXRealIPIsNeverConsulted(t *testing.T) {
	r := request("10.21.0.3:5000", map[string]string{
		"X-Real-IP":       "9.9.9.9",
		"X-Forwarded-For": "203.0.113.7",
	})
	if got := api.ClientIP(r, trustsUmbrelSubnet); got.String() != "203.0.113.7" {
		t.Errorf("ClientIP = %s, want 203.0.113.7 — X-Real-IP must never be consulted", got)
	}

	// ...and with no X-Forwarded-For at all it must still be ignored.
	r = request("10.21.0.3:5000", map[string]string{"X-Real-IP": "9.9.9.9"})
	if got := api.ClientIP(r, trustsUmbrelSubnet); got.String() != "10.21.0.3" {
		t.Errorf("ClientIP = %s, want the peer 10.21.0.3 — X-Real-IP is attacker-controlled", got)
	}
}

// Spec §7 and criterion 14: the limiter takes its key as a parameter. Per-IP
// limiting is non-functional on the Cloudflare tunnel path — every internet
// client arrives as one address — so the public group keys globally and the
// admin group, which sees real LAN addresses, keys per client.
func TestLimiterKeysAreASeam(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	clock := func() time.Time { return now }

	perIP := api.NewLimiter(api.FixedLimits(2, 10), api.KeyClientIP(trustsUmbrelSubnet), clock)
	first := request("192.168.77.10:4000", nil)
	second := request("192.168.77.11:4000", nil)
	for range 2 {
		if !perIP.Allow(first) {
			t.Fatal("a client was limited inside its own allowance")
		}
	}
	if perIP.Allow(first) {
		t.Error("the third request from one client was allowed past a limit of 2/min")
	}
	if !perIP.Allow(second) {
		t.Error("a different client was limited by the first client's usage")
	}

	global := api.NewLimiter(api.FixedLimits(2, 10), api.KeyGlobal, clock)
	if !global.Allow(first) || !global.Allow(second) {
		t.Fatal("the global limiter refused inside its allowance")
	}
	if global.Allow(request("203.0.113.9:4000", nil)) {
		t.Error("the global limiter let a third request past; every caller shares one bucket")
	}
}

func TestLimiterWindowsExpire(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	limiter := api.NewLimiter(api.FixedLimits(2, 3), api.KeyGlobal, func() time.Time { return now })
	r := request("10.0.0.1:1", nil)

	if !limiter.Allow(r) || !limiter.Allow(r) || limiter.Allow(r) {
		t.Fatal("the per-minute allowance is not 2")
	}
	now = now.Add(61 * time.Second)
	if !limiter.Allow(r) {
		t.Error("the minute window did not roll over")
	}
	// The hourly cap of 3 is now reached and does not roll over with the minute.
	if limiter.Allow(r) {
		t.Error("the hourly cap was not enforced")
	}
	now = now.Add(time.Hour)
	if !limiter.Allow(r) {
		t.Error("the hour window did not roll over")
	}
}

func TestLimiterMiddlewareRefusesWithTheRefusalItWasGiven(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	limiter := api.NewLimiter(api.FixedLimits(1, 1), api.KeyGlobal, func() time.Time { return now })
	refused := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "the refusal this caller was owed", http.StatusTooManyRequests)
	}
	handler := limiter.Middleware(refused, marker("served"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, request("10.0.0.1:1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", rec.Code)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, request("10.0.0.1:1", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("second request = %d, want 429", rec.Code)
	}
	if rec.Body.String() == "served" {
		t.Error("the limited request still reached the handler")
	}
	// The refusal is the caller's, not the limiter's: each group owes its
	// caller a different explanation (d46.19).
	if !strings.Contains(rec.Body.String(), "the refusal this caller was owed") {
		t.Errorf("the refusal body was %q; the limiter rendered its own rather than "+
			"the one it was handed", rec.Body.String())
	}
}
