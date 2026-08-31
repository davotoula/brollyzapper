package api_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/store"
)

// o34.13 criteria 1, 2 and 4, end to end and in the operator's own hands: paste
// the URL, then read what a wallet is served.
//
// https://zap.example.com is the natural thing to paste into a field labelled
// "Public domain", and until now it was stored exactly as typed — so the
// identifier became bob@https://zap.example.com and the description_hash was
// computed over that string. The wallet hashes the metadata IT was served and
// compares; the two agree here only because both came from the same function,
// which is why this hashes the bytes off the wire instead.
//
// §16 calls this the one place in P2 where a passing suite and a broken product
// look identical. The byte-stability test never sees a domain an operator typed,
// so this route around it was open on the first day of real use.
func TestAPastedURLBecomesABareAddressAndAHashAWalletCanReproduce(t *testing.T) {
	h := newLNURLHarness(t)
	cookie := h.login(t)

	rec := h.postForm(t, "/settings", cookie, url.Values{
		api.SettingDomain:      {"https://zap.example.com/"},
		api.SettingAddressName: {"bob"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /settings = %d %q, want 303", rec.Code, rec.Body)
	}

	// 1. The stored value is a bare host, with no scheme and no trailing slash.
	if got := h.setting(t, api.SettingDomain); got != "zap.example.com" {
		t.Errorf("stored domain = %q, want the bare host", got)
	}

	// 2. The document a wallet reads.
	doc := h.get(t, "/.well-known/lnurlp/bob", nil)
	if doc.Code != http.StatusOK {
		t.Fatalf("GET the address = %d %q", doc.Code, doc.Body)
	}
	var pay lnurl.PayResponse
	if err := json.Unmarshal(doc.Body.Bytes(), &pay); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, doc.Body)
	}
	if !strings.Contains(pay.Metadata, `"bob@zap.example.com"`) {
		t.Errorf("the metadata identifier is not bob@zap.example.com: %s", pay.Metadata)
	}
	if strings.Contains(pay.Metadata, "://") {
		t.Errorf("the identifier carries a scheme, which no wallet will reproduce: %s",
			pay.Metadata)
	}
	if want := "https://zap.example.com/lnurlp/bob/callback"; pay.Callback != want {
		t.Errorf("callback = %q, want %q", pay.Callback, want)
	}

	// 3. The hash, over the bytes that were actually SERVED. Hashing
	// lnurl.Metadata() again would only prove that one function agrees with
	// itself — the wallet has no access to it, and the whole failure mode is
	// the two diverging.
	if mint := h.get(t, "/lnurlp/bob/callback?amount=21000", nil); mint.Code != http.StatusOK {
		t.Fatalf("callback = %d %q", mint.Code, mint.Body)
	}
	invoices := h.minted(t)
	if len(invoices) != 1 {
		t.Fatalf("recorded %d invoices, want 1", len(invoices))
	}
	want := sha256.Sum256([]byte(pay.Metadata))
	if invoices[0].DescriptionHash != hex.EncodeToString(want[:]) {
		t.Errorf("description_hash = %s, want sha256 of the metadata as served (%s) — "+
			"every wallet computes the second and refuses the invoice",
			invoices[0].DescriptionHash, hex.EncodeToString(want[:]))
	}
}

// o34.13 criterion 3, and the trap the design is built around.
//
// The scheme lives in its own row now, and the Settings field renders the BARE
// host — so the value an operator sees when they open the page is not the value
// they originally pasted. If saving that bare value cleared the scheme row, then
// opening Settings and pressing Save with nothing changed would silently promote
// a LAN address to https and break the setup it was typed for. The regtest stack
// is exactly that setup, so this is not a hypothetical operator.
//
// A paste with no scheme therefore leaves the row alone. A paste WITH one still
// decides, which is how it is turned back off.
//
// The served document is read ONCE, after the first save, and every later
// assertion is on the stored rows. lnurl.Service caches the identity for
// identityTTL against a clock this harness holds still, so a second GET would
// answer from that cache — an assertion that "the callback did not change"
// would then hold whatever the boundary did, which is a test that cannot fail.
// The cache is a known finding, recorded beside identityTTL; this test declines
// to be its victim rather than pretending it is not there.
func TestReSavingTheBareHostKeepsAPlainHTTPAddressOnPlainHTTP(t *testing.T) {
	h := newLNURLHarness(t)
	cookie := h.login(t)

	save := func(domain string) {
		t.Helper()
		rec := h.postForm(t, "/settings", cookie, url.Values{
			api.SettingDomain:      {domain},
			api.SettingAddressName: {"bob"},
		})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("POST /settings %q = %d %q", domain, rec.Code, rec.Body)
		}
	}
	stored := func() (host, insecure string) {
		t.Helper()
		return h.setting(t, api.SettingDomain), h.setting(t, api.SettingDomainInsecure)
	}

	// A LAN test address, which needs the scheme it was given (§9).
	save("http://192.168.77.42:3033")
	if host, insecure := stored(); host != "192.168.77.42:3033" || insecure != "true" {
		t.Fatalf("stored %q insecure=%q, want the bare host[:port] on plain http",
			host, insecure)
	}
	doc := h.get(t, "/.well-known/lnurlp/bob", nil)
	var pay lnurl.PayResponse
	if err := json.Unmarshal(doc.Body.Bytes(), &pay); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, doc.Body)
	}
	if want := "http://192.168.77.42:3033/lnurlp/bob/callback"; pay.Callback != want {
		t.Errorf("callback = %q, want %q — forcing https would make a box-local probe "+
			"impossible", pay.Callback, want)
	}

	// What the field now renders, saved again with nothing changed.
	save("192.168.77.42:3033")
	if host, insecure := stored(); host != "192.168.77.42:3033" ||
		insecure != "true" {
		t.Errorf("stored %q insecure=%q after re-saving the bare host — pressing Save with "+
			"nothing changed moved the address to https and broke it", host, insecure)
	}

	// And an explicit paste is still how it is turned back off.
	save("https://zap.example.com")
	if host, insecure := stored(); host != "zap.example.com" ||
		insecure != "false" {
		t.Errorf("stored %q insecure=%q, want an explicit https paste to win", host, insecure)
	}
}

// The other half of o34.13, and the one an existing box depends on: the
// normalisation is applied where the domain is CONSUMED as well as where it is
// written.
//
// 0.1.6 is on the box right now with http://192.168.77.42:3033 in its settings
// row. Normalising only on save would leave that install serving
// bob@http://192.168.77.42:3033 — and a description_hash no wallet reproduces —
// until somebody happened to open Settings and press Save. The bug would
// survive the fix for it.
func TestAnUpgradedInstallServesABareIdentifierWithoutBeingReSaved(t *testing.T) {
	h := newLNURLHarness(t, func(_ *api.ServerOptions, db *store.Store) {
		// Written straight to the row, the way 0.1.6 stored it — no save path,
		// no normalisation.
		if err := db.SetSetting(t.Context(), api.SettingDomain, "http://192.168.77.42:3033"); err != nil {
			t.Fatalf("seeding the old-shaped domain: %v", err)
		}
	})

	doc := h.get(t, "/.well-known/lnurlp/bob", nil)
	if doc.Code != http.StatusOK {
		t.Fatalf("GET the address = %d %q", doc.Code, doc.Body)
	}
	var pay lnurl.PayResponse
	if err := json.Unmarshal(doc.Body.Bytes(), &pay); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, doc.Body)
	}
	if !strings.Contains(pay.Metadata, `"bob@192.168.77.42:3033"`) {
		t.Errorf("the identifier still carries what the old row held: %s", pay.Metadata)
	}
	// The scheme in that row is still honoured for the URL — the address it was
	// typed for is only reachable over plain http.
	if want := "http://192.168.77.42:3033/lnurlp/bob/callback"; pay.Callback != want {
		t.Errorf("callback = %q, want %q", pay.Callback, want)
	}
}

// setting reads a stored value, because what o34.13 changed is what gets
// WRITTEN and the served document alone cannot show that.
func (h *lnurlHarness) setting(t *testing.T, key string) string {
	t.Helper()
	value, _, err := h.store.Setting(t.Context(), key)
	if err != nil {
		t.Fatalf("reading %s: %v", key, err)
	}
	return value
}

// vz1.7 criteria 1 and 4, and the field failure it comes from.
//
// o34.13 made a bare paste leave the scheme row alone, so that a no-op Save on a
// LAN setup could not promote it to https. That rule is right for the SAME host
// and wrong for a different one — and the 0.1.7 box proved it: moving from the
// LAN address to a public hostname by pasting the bare host inherited
// insecure=true from the LAN era, and the app advertised
//
//	callback: http://zap.example.com/lnurlp/test/callback   ← for an https address
//
// Everything looked right while it was wrong, and the self-probe passed.
//
// Both directions here, because a rule that resets on every save is the bug
// o34.13 fixed and a rule that never resets is the bug this one fixes.
func TestChangingTheHostResetsTheSchemeAndReSavingTheSameHostDoesNot(t *testing.T) {
	h := newLNURLHarness(t)
	cookie := h.login(t)

	save := func(domain string) {
		t.Helper()
		rec := h.postForm(t, "/settings", cookie, url.Values{
			api.SettingDomain: {domain}, api.SettingAddressName: {"bob"},
		})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("POST /settings %q = %d %q", domain, rec.Code, rec.Body)
		}
	}
	stored := func() (host, insecure string) {
		t.Helper()
		return h.setting(t, api.SettingDomain), h.setting(t, api.SettingDomainInsecure)
	}

	// The LAN era.
	save("http://192.168.77.42:3033")
	if host, insecure := stored(); host != "192.168.77.42:3033" || insecure != "true" {
		t.Fatalf("stored %q insecure=%q, want the LAN address on plain http", host, insecure)
	}

	// A no-op Save of what the field renders. o34.13's rule: untouched.
	save("192.168.77.42:3033")
	if _, insecure := stored(); insecure != "true" {
		t.Errorf("insecure=%q after re-saving the same host; pressing Save with nothing "+
			"changed must not promote a LAN address to https", insecure)
	}

	// A no-op Save on a row written BEFORE o34.13, which still carries its
	// scheme — the reference box's shape until vz1.5 migrates it. The stored
	// row and the pasted host must be compared in the same form, or this reads
	// as a host change and resets the flag.
	if err := h.store.SetSetting(t.Context(), api.SettingDomain,
		"http://192.168.77.42:3033"); err != nil {
		t.Fatal(err)
	}
	save("192.168.77.42:3033")
	if _, insecure := stored(); insecure != "true" {
		t.Errorf("insecure=%q after a no-op Save on an un-migrated row; the LAN setup was "+
			"promoted to https by a Save that changed nothing", insecure)
	}

	// Moving to a public hostname, bare. A different host is not a no-op Save.
	save("zap.example.com")
	host, insecure := stored()
	if host != "zap.example.com" || insecure != "false" {
		t.Errorf("stored %q insecure=%q after moving to a public hostname; the flag was "+
			"inherited from the LAN era and the app would advertise an http callback for "+
			"an https address", host, insecure)
	}

	// And the page says which scheme it will hand out, rather than leaving the
	// operator to remember what they last pasted.
	page := h.get(t, "/settings", cookie).Body.String()
	if !strings.Contains(page, "https://zap.example.com") {
		t.Errorf("the Settings page does not show the scheme it will advertise:\n%s", page)
	}
}

// The Settings hint is the WHOLE origin, from the one function that builds it.
//
// Found by review, not by the suite: the first version carried only the scheme
// and let the template concatenate it with the raw domain row. On a box
// configured before o34.13 that row still holds "http://192.168.77.42:3033" — it
// is not migrated until vz1.5 — so the hint rendered
//
//	http://http://192.168.77.42:3033
//
// which is the page saying something the callback never would. That is the one
// thing this field exists to prevent, and the reference box is exactly that
// shape.
func TestTheSettingsHintIsTheOriginACallbackWouldCarry(t *testing.T) {
	for _, tc := range []struct {
		name     string
		domain   string
		insecure string
		want     string
	}{
		{"a normalised public host", "zap.example.com", "false", "https://zap.example.com"},
		{"a normalised LAN host", "192.168.77.42:3033", "true", "http://192.168.77.42:3033"},
		{"a row written before o34.13, still carrying its scheme",
			"http://192.168.77.42:3033", "true", "http://192.168.77.42:3033"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newLNURLHarness(t, func(_ *api.ServerOptions, db *store.Store) {
				for k, v := range map[string]string{
					api.SettingDomain: tc.domain, api.SettingDomainInsecure: tc.insecure,
				} {
					if err := db.SetSetting(t.Context(), k, v); err != nil {
						t.Fatalf("seeding %s: %v", k, err)
					}
				}
			})
			page := h.get(t, "/settings", h.login(t)).Body.String()
			if !strings.Contains(page, "<code>"+tc.want+"</code>") {
				t.Errorf("the hint is not %q; the page must show the origin a wallet is "+
					"handed, not a reassembly of it", tc.want)
			}
			// And it must agree with what the callback actually advertises.
			var doc lnurl.PayResponse
			if err := json.Unmarshal(
				h.get(t, "/.well-known/lnurlp/bob", nil).Body.Bytes(), &doc); err != nil {
				t.Fatalf("the address document is not JSON: %v", err)
			}
			if !strings.HasPrefix(doc.Callback, tc.want+"/") {
				t.Errorf("the page says %q but the callback is %q — the page and the "+
					"callback must not be able to disagree", tc.want, doc.Callback)
			}
		})
	}
}
