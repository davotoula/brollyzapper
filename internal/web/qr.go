package web

import (
	"fmt"
	"html/template"
	"strings"

	"rsc.io/qr"
)

// qrQuietZone is the light margin around a QR symbol, in modules.
//
// Four is the specification's minimum, and it is not decoration: a scanner
// finds the symbol by its finder patterns and needs light either side of them.
// A QR rendered flush to its edge is one that phones fail to read against a dark
// background, which on this page means an operator who cannot pair.
const qrQuietZone = 4

// qrModuleSize is the side of one module in the SVG's own coordinate space.
//
// The SVG scales to whatever CSS gives it, so this is only the internal grid —
// but it is an integer so every module lands on a whole coordinate and no
// renderer has to decide how to round a half-pixel black square.
const qrModuleSize = 4

// QRCode renders text as an inline SVG QR symbol.
//
// SERVER-SIDE, INLINE, and both halves are the ruling (d24.5). Not a data: URI
// and not an <img>: an inline <svg> raises no image-src question, fetches
// nothing, and needs no CSP exception — the markup IS the picture. Not client
// side either, which would mean shipping an encoder to the browser and putting
// the pairing secret through JavaScript.
//
// It is fed our own pairing URI and nothing else. The only external input inside
// that string is the connection's relay, which the operator typed — and it
// reaches the page as SVG geometry rather than as text, since what comes out of
// here is a list of rectangles.
//
// Returns an empty value rather than an error page when the text will not
// encode: the URI is also rendered as text beside this, so a missing QR is a
// missing convenience and not a missing capability. §11's posture — degraded
// over dead — applied to a picture.
func QRCode(text string) template.HTML {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return ""
	}
	side := (code.Size + 2*qrQuietZone) * qrModuleSize

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" `+
		`class="qr" role="img" aria-label="Pairing QR code" shape-rendering="crispEdges">`,
		side, side)
	// The quiet zone is drawn rather than assumed: the page's background may be
	// anything, and a symbol that relies on it is one that stops scanning when
	// someone changes a colour.
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/>`, side, side)
	for y := range code.Size {
		// One <rect> per RUN of dark modules rather than per module.
		//
		// Measured on a real pairing URI — 191 characters: a 64-hex service key,
		// a damus.io relay and a 64-hex secret. That is a 57x57 symbol with 1630
		// dark modules, which becomes 766 rects and 33 KB of markup, against
		// roughly 68 KB written one square at a time. About HALF, not the order
		// of magnitude an earlier version of this comment claimed; review caught
		// the estimate and these numbers were measured. The page carries this
		// markup on every render.
		for x := 0; x < code.Size; {
			if !code.Black(x, y) {
				x++
				continue
			}
			run := 1
			for x+run < code.Size && code.Black(x+run, y) {
				run++
			}
			fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d"/>`,
				(x+qrQuietZone)*qrModuleSize, (y+qrQuietZone)*qrModuleSize,
				run*qrModuleSize, qrModuleSize)
			x += run
		}
	}
	b.WriteString(`</svg>`)

	// template.HTML because this IS markup and is meant to be rendered as such.
	// Everything in it was produced by this function from a QR grid — the only
	// values interpolated are integers from the encoder — so there is no path
	// from the input string to the output markup except through those integers.
	return template.HTML(b.String()) //nolint:gosec // see above: integers only
}
