#!/usr/bin/env python3
"""Build BrollyZapper's icon.svg and favicon.svg with the BZ letterforms outlined.

The shipped SVGs must not depend on a font being installed: umbrelOS renders
icon.svg on machines that have never heard of Archivo, and a <text> element there
would silently fall back to whatever the renderer happens to have. So the glyphs
are cut from Archivo ExtraBold here and emitted as path data.

The master and the favicon come out of ONE set of constants below, so they cannot
drift apart; the favicon differs only in how many bolts it draws.

Design and the reasoning behind the fixed geometry:
the icon design notes (private)

Nothing here runs in CI. The three outputs are committed build-once artifacts,
so no rasteriser and no font download is a build dependency of the project —
they are dependencies of *changing the mark*, which is rare and deliberate.

Requires fontTools (pip install fonttools) and, for the PNG, any one of
rsvg-convert, sips, inkscape or ImageMagick.
"""

import hashlib
import pathlib
import shutil
import subprocess
import sys
import urllib.request

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.misc.transform import Transform

HERE = pathlib.Path(__file__).parent
ROOT = HERE.parent
STATIC = ROOT / "internal" / "web" / "static"
FONT = HERE / "Archivo800.ttf"

# Pinned by URL AND hash. Without the hash a Google Fonts revision silently
# changes the outlines on the next re-cut, and "the master and the favicon
# cannot drift" stops being true with nobody having chosen it. The SVGs are
# committed, so this can only bite at re-cut time — which is exactly when the
# check earns its keep. Updating the font is a deliberate two-line change here.
FONT_URL = (
    "https://fonts.gstatic.com/s/archivo/v25/"
    "k3k6o8UDI-1M0wlSV9XAw6lQkqWY8Q82sJaRE-NWIDdgffTTtDRp8A.ttf"
)
FONT_SHA256 = "745c7f810c448f256b66e1beaf8d6ccc2be98c01e531a1da8b1e8cf805a5b857"

PURPLE_BLEED = "#8B5CF6"   # nostr purple, the tile's field
PURPLE_CANOPY = "#6D28D9"  # deeper, so the canopy holds against the white disc
GOLD = "#F5B70A"
WHITE = "#FFFFFF"

BOLT = "M28 0 L4 54 L22 54 L10 96 L44 38 L24 38 Z"

# Variant A geometry, as approved.
DISC_R = 102
CANOPY = ("M56 118 Q80 142 104 118 Q128 142 152 118 Q176 142 200 118 "
          "C200 168 172 196 128 196 C84 196 56 168 56 118 Z")

# (translate_x, translate_y, scale) for each falling bolt, largest in the centre.
BOLTS_THREE = [(63.3, 70, 0.78), (100.4, 34, 1.15), (160.6, 84, 0.64)]
BOLTS_ONE = [(104, 40, 1.05)]

BZ_SIZE = 38
BZ_CENTRE_X = 128
BZ_BASELINE = 177


def ensure_font():
    """Fetch the pinned TTF if absent, and refuse to proceed on a hash mismatch."""
    if not FONT.exists():
        print(f"fetching {FONT_URL}", file=sys.stderr)
        with urllib.request.urlopen(FONT_URL) as response:
            FONT.write_bytes(response.read())

    digest = hashlib.sha256(FONT.read_bytes()).hexdigest()
    if digest != FONT_SHA256:
        FONT.unlink()
        raise SystemExit(
            f"{FONT.name} does not match the pin.\n"
            f"  expected {FONT_SHA256}\n"
            f"  got      {digest}\n"
            "The letterforms would change. Verify the new font deliberately, then update "
            "FONT_URL and FONT_SHA256 together."
        )


def outline(text, size, centre_x, baseline):
    """Return SVG path data for `text`, centred on centre_x and sitting on baseline."""
    font = TTFont(FONT)
    upem = font["head"].unitsPerEm
    cmap = font.getBestCmap()
    glyphs = font.getGlyphSet()
    hmtx = font["hmtx"]

    names = [cmap[ord(ch)] for ch in text]
    advance = sum(hmtx[name][0] for name in names)

    scale = size / upem
    pen_x = centre_x - (advance * scale) / 2

    parts = []
    for name in names:
        svg_pen = SVGPathPen(glyphs)
        # y is flipped: font space is up-positive, SVG user space is down-positive.
        transform = Transform(scale, 0, 0, -scale, pen_x, baseline)
        glyphs[name].draw(TransformPen(svg_pen, transform))
        commands = svg_pen.getCommands()
        if commands:
            parts.append(commands)
        pen_x += hmtx[name][0] * scale

    return " ".join(parts)


def bolt_uses(bolts):
    return "\n".join(
        f'  <use href="#bolt" transform="translate({x} {y}) scale({s})" fill="{GOLD}"/>'
        for x, y, s in bolts
    )


def build(bolts, title, desc):
    bz = outline("BZ", BZ_SIZE, BZ_CENTRE_X, BZ_BASELINE)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256" role="img" aria-labelledby="t d">
  <title id="t">{title}</title>
  <desc id="d">{desc}</desc>
  <defs><path id="bolt" d="{BOLT}"/></defs>
  <rect width="256" height="256" fill="{PURPLE_BLEED}"/>
  <circle cx="128" cy="128" r="{DISC_R}" fill="{WHITE}"/>
{bolt_uses(bolts)}
  <path d="{CANOPY}" fill="{PURPLE_CANOPY}"/>
  <path d="{bz}" fill="{WHITE}"/>
</svg>
'''


TOUCH_ICON_PX = 180

# In preference order. rsvg-convert first because it is the one that is the same
# on every machine; sips is macOS-only but needs no install.
RASTERISERS = (
    ("rsvg-convert", lambda src, dst, px: ["rsvg-convert", "-w", str(px), "-h", str(px), str(src), "-o", str(dst)]),
    ("sips", lambda src, dst, px: ["sips", "-s", "format", "png", "-Z", str(px), str(src), "--out", str(dst)]),
    ("inkscape", lambda src, dst, px: ["inkscape", str(src), "-w", str(px), "-h", str(px), "-o", str(dst)]),
    ("magick", lambda src, dst, px: ["magick", "-background", "none", str(src), "-resize", f"{px}x{px}", str(dst)]),
)


def rasterise(src, dst, px):
    """Render src to a px-square PNG, naming every alternative if none is present."""
    for name, argv in RASTERISERS:
        if shutil.which(name):
            subprocess.run(argv(src, dst, px), check=True, capture_output=True)
            return name
    raise SystemExit(
        f"cannot render {dst.name}: no rasteriser found.\n"
        "Install any one of: " + ", ".join(name for name, _ in RASTERISERS) + ".\n"
        "The SVGs above are written; only the PNG is missing."
    )


def main():
    ensure_font()

    icon = build(
        BOLTS_THREE,
        "BrollyZapper",
        "An upturned umbrella catching three lightning bolts, marked BZ.",
    )
    favicon = build(
        BOLTS_ONE,
        "BrollyZapper",
        "An upturned umbrella catching a lightning bolt, marked BZ.",
    )

    master = HERE / "icon.svg"
    master.write_text(icon)
    (STATIC / "favicon.svg").write_text(favicon)

    touch_icon = STATIC / "apple-touch-icon.png"
    tool = rasterise(master, touch_icon, TOUCH_ICON_PX)

    for path in (master, STATIC / "favicon.svg", touch_icon):
        print(f"{path.relative_to(ROOT)}: {path.stat().st_size} bytes")
    print(f"(PNG rendered with {tool})")


if __name__ == "__main__":
    main()
