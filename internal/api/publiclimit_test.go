package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
	"github.com/davotoula/brollyzapper/internal/store"
)

// d46.27 / review M2. One settings pair used to feed both limiters, differing
// only in the fallback, so an operator raising the public ceiling until their
// zaps stopped bouncing raised their own login brute-force ceiling by the same
// amount — from a single unlabelled field.
//
// The test moves the public setting and then measures the ADMIN limiter's
// behaviour, in both directions. Asserting that the two constants differ would
// prove nothing: they differed before the fix too.
func TestThePublicRateLimitSettingDoesNotMoveTheAdminLimiter(t *testing.T) {
	adminRequests := func(t *testing.T, publicPerMinute string) (served, refused int) {
		t.Helper()
		h := newHarness(t, func(_ *api.ServerOptions, db *store.Store) {
			if err := db.SetSetting(t.Context(), api.SettingPublicRateLimitMinute,
				publicPerMinute); err != nil {
				t.Fatalf("seeding the public limit: %v", err)
			}
		})
		// One past the admin ceiling, so both counts are non-zero whichever
		// way the coupling would have gone.
		for range api.AdminPerMinute + 1 {
			if h.get(t, "/login", nil).Code == http.StatusTooManyRequests {
				refused++
			} else {
				served++
			}
		}
		return served, refused
	}

	t.Run("raising the public limit does not raise the login ceiling", func(t *testing.T) {
		served, refused := adminRequests(t, "100000")
		if served != api.AdminPerMinute || refused != 1 {
			t.Errorf("with the public limit at 100000, %d admin requests were served and %d "+
				"refused; want %d and 1 — the admin ceiling is a constant",
				served, refused, api.AdminPerMinute)
		}
	})

	t.Run("lowering the public limit does not throttle the operator", func(t *testing.T) {
		served, refused := adminRequests(t, "1")
		if served != api.AdminPerMinute || refused != 1 {
			t.Errorf("with the public limit at 1, %d admin requests were served and %d refused; "+
				"want %d and 1 — the operator must not be locked out by a public setting",
				served, refused, api.AdminPerMinute)
		}
	})
}

// §7 as ruled 22 Aug 2026, and o34.11 criterion 5. The lnurlp document mints
// nothing, so it is not limited at all — and §9's self-probe depends on that.
//
// The probe fetches this exact path over the public internet to check the
// operator's own domain reaches this instance. If a stranger could exhaust a
// bucket the probe shares, the Security page would report the operator's own
// address unreachable: a false diagnosis wearing a measurement's clothes. The
// exemption is structural — the document is behind no limiter — rather than a
// bypass keyed on the probe token, which is stamped on every response here and
// is therefore known to anyone who ever fetched the address.
func TestTheAddressDocumentIsNeverLimitedSoTheSelfProbeCannotBeStarved(t *testing.T) {
	h := newLNURLHarness(t, func(_ *api.ServerOptions, db *store.Store) {
		// As low as the setting goes, so a shared bucket would be exhausted
		// after one request rather than after sixty.
		if err := db.SetSetting(t.Context(), api.SettingPublicRateLimitMinute, "1"); err != nil {
			t.Fatalf("seeding the public limit: %v", err)
		}
	})

	// Drain whatever the callback's backstop allows, the way an attacker would.
	for range 20 {
		h.get(t, "/lnurlp/bob/callback?amount=21000", nil)
	}

	for i := range 20 {
		rec := h.get(t, "/.well-known/lnurlp/bob", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d for the address document = %d %q; the document must not "+
				"be limited, or the self-probe can be starved by a stranger",
				i+1, rec.Code, rec.Body)
		}
	}
	// The probe recognises this instance by the header, so a document served
	// without it is as useless to the probe as a refusal.
	if got := h.get(t, "/.well-known/lnurlp/bob", nil).Header().Get(api.ProbeHeader); got == "" {
		t.Error("the document carries no probe header")
	}
}

// §7's per-sender layer. The key is the zap request's SIGNED pubkey, so one
// sender flooding the callback cannot spend another sender's budget — which is
// the honest-caller collision §7 actually cares about.
//
// It is not a Sybil defence and the code says so: anyone can mint keys. What it
// buys is that two people zapping the same address at the same time stop
// colliding, which per-IP cannot buy on a path where every internet client
// arrives as one address.
func TestOneFloodingZapSenderDoesNotSpendAnotherSendersBudget(t *testing.T) {
	h := newLNURLHarness(t)
	noisy, quiet := gonostr.GeneratePrivateKey(), gonostr.GeneratePrivateKey()

	var refusedAt int
	for i := range api.PerSenderPerMinute + 1 {
		rec := h.get(t, zapCallback(t, noisy, 21_000), nil)
		if rec.Code == http.StatusTooManyRequests && refusedAt == 0 {
			refusedAt = i + 1
		}
	}
	if refusedAt != api.PerSenderPerMinute+1 {
		t.Errorf("the noisy sender was first refused on request %d, want %d",
			refusedAt, api.PerSenderPerMinute+1)
	}

	if rec := h.get(t, zapCallback(t, quiet, 21_000), nil); rec.Code != http.StatusOK {
		t.Errorf("a second sender's first zap = %d %q; one sender's flood must not "+
			"consume another's bucket", rec.Code, rec.Body)
	}
}

// The per-sender key comes from the SIGNED pubkey, and this is what that buys.
//
// Keying on a merely claimed pubkey would let anyone drain a named person's
// bucket by putting their key in an unsigned event — griefing one identified
// sender rather than the anonymous crowd, which is strictly worse than the
// collision problem this layer exists to fix. Verification does not make the
// key expensive to mint and is not claimed to: it makes the key unspendable by
// anyone but its owner.
func TestAForgedSenderCannotDrainTheBucketOfTheKeyItNames(t *testing.T) {
	h := newLNURLHarness(t)
	victim := gonostr.GeneratePrivateKey()
	victimPub, err := gonostr.GetPublicKey(victim)
	if err != nil {
		t.Fatal(err)
	}

	for range api.PerSenderPerMinute + 1 {
		h.get(t, unsignedZapCallback(t, victimPub, 21_000), nil)
	}

	if rec := h.get(t, zapCallback(t, victim, 21_000), nil); rec.Code != http.StatusOK {
		t.Errorf("the named sender's own zap = %d %q after %d forgeries in their name; "+
			"the bucket must key on a verified signature, not a claim",
			rec.Code, rec.Body, api.PerSenderPerMinute+1)
	}
}

// The globalBackstop. It is a ceiling on TOTAL anonymous traffic and isolates
// nobody from anybody — which is why it is the one layer the operator can move,
// and why it is named backstop in the code rather than anything suggesting
// per-caller fairness.
func TestTheGlobalBackstopBoundsTotalAnonymousTraffic(t *testing.T) {
	h := newLNURLHarness(t, func(_ *api.ServerOptions, db *store.Store) {
		if err := db.SetSetting(t.Context(), api.SettingPublicRateLimitMinute, "2"); err != nil {
			t.Fatalf("seeding the public limit: %v", err)
		}
	})

	for i := range 2 {
		if rec := h.get(t, "/lnurlp/bob/callback?amount=21000", nil); rec.Code != http.StatusOK {
			t.Fatalf("callback %d = %d %q, want 200 under the backstop", i+1, rec.Code, rec.Body)
		}
	}
	rec := h.get(t, "/lnurlp/bob/callback?amount=21000", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the third callback = %d, want 429 — the operator's setting is the backstop",
			rec.Code)
	}
	// A wallet reads {"status":"ERROR","reason"}; plain text tells the person
	// trying to pay nothing they can act on.
	var body struct{ Status, Reason string }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the refusal is not LNURL JSON: %v (%s)", err, rec.Body)
	}
	if body.Status != "ERROR" || body.Reason == "" {
		t.Errorf("refusal body = %+v, want an LNURL error with a reason", body)
	}
}

// The open-invoice cap: §7's real resource bound. Per-sender buckets and the
// backstop limit REQUESTS; what a caller actually consumes by reaching the
// callback is a row in LND's invoice database, and only this counts those.
func TestTheOpenInvoiceCapRefusesFurtherMinting(t *testing.T) {
	h := newLNURLHarness(t, func(_ *api.ServerOptions, db *store.Store) {
		for i := range api.OpenInvoiceCap {
			if err := db.CreateInvoice(t.Context(), store.Invoice{
				PaymentHash:     fmt.Sprintf("outstanding-%03d", i),
				AmountMsat:      21_000,
				DescriptionHash: "dh",
				Bolt11:          "lnbcrt",
				State:           store.InvoiceOpen,
				CreatedAt:       authTime,
				ExpiresAt:       authTime.Add(10 * time.Minute),
			}); err != nil {
				t.Fatalf("seeding an outstanding invoice: %v", err)
			}
		}
	})

	rec := h.get(t, "/lnurlp/bob/callback?amount=21000", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the callback = %d %q with %d invoices already open, want 429",
			rec.Code, rec.Body, api.OpenInvoiceCap)
	}
	if !strings.Contains(rec.Body.String(), "unpaid invoices") {
		t.Errorf("the refusal does not say which limit was hit: %s", rec.Body)
	}
	if minted := h.minted(t); len(minted) != 0 {
		t.Errorf("%d invoices were minted past the cap", len(minted))
	}
}

// d46.19. With no trusted proxy declared, every request behind one arrives from
// the proxy's own address, so "30 a minute per client" is really 30 a minute
// for the whole machine — and an operator locked out by their own browser tabs
// has nothing to go on unless the refusal says so.
//
// Both cases are asserted. A warning that is always shown is not a diagnosis,
// and an operator who HAS configured TRUSTED_PROXIES must not be sent to check
// a setting that is already correct.
func TestTheAdminRefusalSaysWhetherTheBucketIsShared(t *testing.T) {
	refusal := func(t *testing.T, overrides ...func(*api.ServerOptions, *store.Store)) string {
		t.Helper()
		h := newHarness(t, overrides...)
		for range api.AdminPerMinute + 1 {
			if rec := h.get(t, "/login", nil); rec.Code == http.StatusTooManyRequests {
				return rec.Body.String()
			}
		}
		t.Fatalf("the admin limiter never refused in %d requests", api.AdminPerMinute+1)
		return ""
	}

	t.Run("no proxy declared", func(t *testing.T) {
		body := refusal(t)
		if !strings.Contains(body, "TRUSTED_PROXIES") {
			t.Errorf("the 429 does not mention TRUSTED_PROXIES, so an operator locked out "+
				"by their own tabs cannot tell why: %q", body)
		}
	})

	t.Run("a proxy is declared", func(t *testing.T) {
		body := refusal(t, func(opts *api.ServerOptions, _ *store.Store) {
			opts.TrustedProxies = mustPrefixes(t, "10.21.0.0/16")
		})
		if strings.Contains(body, "TRUSTED_PROXIES") {
			t.Errorf("the 429 warns about TRUSTED_PROXIES on a deployment that sets it, "+
				"which sends the operator to check a correct setting: %q", body)
		}
		if !strings.Contains(body, fmt.Sprint(api.AdminPerMinute)) {
			t.Errorf("the 429 does not say what the limit is: %q", body)
		}
	})
}

// zapCallback builds a callback URL carrying a zap request signed by sk.
func zapCallback(t *testing.T, sk string, amountMsat int64) string {
	t.Helper()
	event := zapRequestEvent()
	if err := event.Sign(sk); err != nil {
		t.Fatal(err)
	}
	return callbackPath(t, event, amountMsat)
}

// unsignedZapCallback builds a callback carrying an event that NAMES pubkey but
// carries no valid signature — the forgery the per-sender key must ignore.
func unsignedZapCallback(t *testing.T, pubkey string, amountMsat int64) string {
	t.Helper()
	event := zapRequestEvent()
	event.PubKey = pubkey
	event.Sig = strings.Repeat("0", 128)
	event.ID = event.GetID()
	return callbackPath(t, event, amountMsat)
}

// zapRequestEvent is the shared fixture with this package's amount tag. The
// shape itself lives in lnurltest, so a tightening of lnurl's rules is one
// edit rather than one per package (ohi).
func zapRequestEvent() *gonostr.Event {
	event := lnurltest.ZapRequestEvent()
	event.Tags = append(lnurltest.WithoutTag(event.Tags, "e"), gonostr.Tag{"amount", "21000"})
	return event
}

func callbackPath(t *testing.T, event *gonostr.Event, amountMsat int64) string {
	t.Helper()
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("/lnurlp/bob/callback?amount=%d&nostr=%s",
		amountMsat, url.QueryEscape(string(raw)))
}

func mustPrefixes(t *testing.T, list string) []netip.Prefix {
	t.Helper()
	prefixes, err := config.ParsePrefixList(list)
	if err != nil {
		t.Fatalf("ParsePrefixList(%q): %v", list, err)
	}
	return prefixes
}

// n7v. The seam carries a proof, so the behaviour worth asserting is that the
// callback mints on exactly the requests whose signature was checked, and that
// the bytes it hashes are the verified ones.
//
// The forged case is the one that matters: an event naming a real pubkey with a
// signature that is not that pubkey's must be refused with Appendix D's reason
// and must mint nothing. Before n7v the api gate and the service each parsed
// independently, so the two could in principle disagree; now there is one parse
// and one answer.
func TestOnlyAVerifiedZapRequestReachesTheMint(t *testing.T) {
	h := newLNURLHarness(t)

	forged := h.get(t, unsignedZapCallback(t, strings.Repeat("b", 64), 21_000), nil)
	if forged.Code != http.StatusOK {
		t.Fatalf("an LNURL rejection rides inside a 200; got %d", forged.Code)
	}
	var answer map[string]string
	if err := json.Unmarshal(forged.Body.Bytes(), &answer); err != nil {
		t.Fatalf("the refusal is not JSON: %v (%s)", err, forged.Body)
	}
	if answer["status"] != "ERROR" || !strings.Contains(answer["reason"], "signature") {
		t.Errorf("a forged zap request was answered %v; want an ERROR naming the "+
			"signature rule", answer)
	}
	if minted := h.minted(t); len(minted) != 0 {
		t.Fatalf("a forged zap request minted %d invoices", len(minted))
	}

	// And the honest case still stores the bytes verbatim — the description tag
	// o34.3 will carry has to be the bytes whose signature was checked, not a
	// re-read of the query string.
	sk := gonostr.GeneratePrivateKey()
	path := zapCallback(t, sk, 21_000)
	if rec := h.get(t, path, nil); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"pr"`) {
		t.Fatalf("a valid zap was refused: %d %s", rec.Code, rec.Body)
	}
	minted := h.minted(t)
	if len(minted) != 1 {
		t.Fatalf("minted %d invoices, want 1", len(minted))
	}
	raw, err := url.QueryUnescape(strings.SplitN(path, "nostr=", 2)[1])
	if err != nil {
		t.Fatal(err)
	}
	if minted[0].ZapRequest != raw {
		t.Errorf("stored zap request:\n%s\nwant the bytes that were verified:\n%s",
			minted[0].ZapRequest, raw)
	}
}

// o34.14. The store-side test proves migration 0007 deletes the carried-over
// rows; this proves what deleting them BUYS, which is the thing the box was
// actually measuring wrong.
//
// With nothing stored — the state an upgraded box reaches after 0007 — the
// global backstop must be the designed default. On 0.1.4 it was 10/min because
// migration 0004 had carried the old pair's default under the new name, and the
// first 429 came at request 11.
func TestWithNothingStoredThePublicBackstopIsTheDesignedDefault(t *testing.T) {
	h := newLNURLHarness(t)

	for i := range api.DefaultGlobalBackstopPerMinute {
		if rec := h.get(t, "/lnurlp/bob/callback?amount=21000", nil); rec.Code != http.StatusOK {
			t.Fatalf("callback %d of %d was refused with %d; an unconfigured instance must "+
				"run the designed backstop, not one carried over from a rename",
				i+1, api.DefaultGlobalBackstopPerMinute, rec.Code)
		}
	}
	if rec := h.get(t, "/lnurlp/bob/callback?amount=21000", nil); rec.Code != http.StatusTooManyRequests {
		t.Errorf("callback %d = %d, want 429 — the backstop is looser than designed",
			api.DefaultGlobalBackstopPerMinute+1, rec.Code)
	}
}

// o34.14 pins the NUMBER, not just the mechanism. The test above drives
// DefaultGlobalBackstopPerMinute through the limiter, so it tracks whatever the
// constant says and cannot notice the constant moving — and a constant moving
// silently is exactly what happened on the box, by a different route.
//
// §7's table states these figures, so they are a design decision and not an
// implementation detail. If they are ever changed deliberately, this and the
// spec change together.
func TestTheDesignedBackstopIsTheOneSevenStates(t *testing.T) {
	if api.DefaultGlobalBackstopPerMinute != 60 || api.DefaultGlobalBackstopPerHour != 600 {
		t.Errorf("globalBackstop defaults = %d/min %d/hour, want 60/600 as §7's table says",
			api.DefaultGlobalBackstopPerMinute, api.DefaultGlobalBackstopPerHour)
	}
}
