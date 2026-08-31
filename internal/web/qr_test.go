package web_test

import (
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/web"
)

// The QR is rendered SERVER-SIDE as inline SVG (d24.5's ruling), so what comes
// back is markup — not a data: URI, not an <img>, and nothing the browser has to
// fetch.
func TestAPairingURIRendersAsInlineSVG(t *testing.T) {
	const uri = "nostr+walletconnect://abc123?relay=wss%3A%2F%2Frelay.example&secret=deadbeef"

	got := string(web.QRCode(uri))

	if !strings.HasPrefix(got, "<svg ") {
		t.Fatalf("QRCode did not return an SVG element: %.80s", got)
	}
	for _, forbidden := range []string{"data:", "<img", "href", "src="} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the QR markup contains %q; it must fetch nothing and reference nothing",
				forbidden)
		}
	}
	if !strings.Contains(got, "<rect") {
		t.Error("the QR has no modules")
	}
}

// THE SECRET IS NOT IN THE MARKUP. The URI carries client_secret, and the whole
// point of a QR is that a phone reads it — but what leaves this function is a
// grid of rectangles, so the secret cannot be read out of the page source, found
// by a search, or copied out of a screenshot of the HTML.
func TestTheQRMarkupDoesNotContainTheSecret(t *testing.T) {
	const secret = "d34db33fd34db33fd34db33fd34db33f"
	uri := "nostr+walletconnect://abc123?relay=wss%3A%2F%2Frelay.example&secret=" + secret

	got := string(web.QRCode(uri))

	if strings.Contains(got, secret) {
		t.Error("the pairing secret appears verbatim in the QR markup")
	}
	if strings.Contains(got, "nostr+walletconnect") {
		t.Error("the pairing URI appears verbatim in the QR markup")
	}
}

// A quiet zone, drawn rather than assumed.
//
// Four modules is the specification's minimum and a symbol without it fails to
// scan against a dark background — which on this page is an operator who cannot
// pair, for a reason nothing on screen explains.
func TestTheQRCarriesItsQuietZone(t *testing.T) {
	got := string(web.QRCode("nostr+walletconnect://abc"))

	if !strings.Contains(got, `fill="#fff"`) {
		t.Error("the QR has no drawn quiet zone; it would rely on the page's background")
	}
	// The first module rect must start inside the margin, not at the origin.
	if strings.Contains(got, `<rect x="0" y="0" width="4" height="4"/>`) {
		t.Error("a module is drawn at the very edge, so the quiet zone is not there")
	}
}

// Text that will not encode degrades to nothing, not to an error page: the URI
// is rendered as text beside the QR, so a missing picture costs a convenience
// and not a capability (§11 — degraded over dead).
func TestUnencodableTextGivesNoQRRatherThanAnError(t *testing.T) {
	// Well past QR's capacity at this error-correction level.
	huge := strings.Repeat("x", 8000)

	if got := web.QRCode(huge); got != "" {
		t.Errorf("QRCode returned %d bytes for text that cannot be encoded", len(got))
	}
}
