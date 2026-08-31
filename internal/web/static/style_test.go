package static_test

import (
	"fmt"
	"maps"
	"math"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// colourValuesIn returns the colour custom properties a block declares, by name.
func colourValuesIn(block string) map[string]string {
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`(--[a-z-]+)\s*:\s*(#[0-9a-fA-F]{3,8})\b`).FindAllStringSubmatch(block, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// colourTokensIn returns the names of the colours a CSS block declares, sorted.
// Only colours are compared between the themes: --gap and any later metric are
// theme-independent by definition, and requiring the dark block to restate them
// would be duplication that says nothing. A colour is what the bug in
// TestBothThemesDefineTheSameTokens is about.
func colourTokensIn(block string) []string {
	return slices.Sorted(maps.Keys(colourValuesIn(block)))
}

// blockAfter returns the text between the first "{" following marker and its
// matching "}", so a nested media query is read as one block.
func blockAfter(t *testing.T, css, marker string) string {
	t.Helper()
	i := strings.Index(css, marker)
	if i < 0 {
		t.Fatalf("the stylesheet has no %q block", marker)
	}
	rest := css[i+len(marker):]
	depth, start := 0, -1
	for j, r := range rest {
		switch r {
		case '{':
			if depth == 0 {
				start = j + 1
			}
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[start:j]
			}
		}
	}
	t.Fatalf("unbalanced braces after %q", marker)
	return ""
}

// themes reads the stylesheet and returns it whole alongside its two token
// blocks. One place knows how the blocks are found, so a change to the markers
// is one edit rather than three.
func themes(t *testing.T) (css, light, dark string) {
	t.Helper()
	raw, err := os.ReadFile("style.css")
	if err != nil {
		t.Fatal(err)
	}
	css = string(raw)
	return css, blockAfter(t, css, ":root"), blockAfter(t, css, "prefers-color-scheme: dark")
}

func TestBothThemesDefineTheSameTokens(t *testing.T) {
	_, lightBlock, darkBlock := themes(t)

	light := colourTokensIn(lightBlock)
	dark := colourTokensIn(darkBlock)

	if len(light) == 0 {
		t.Fatal("the light :root block declares no colour tokens")
	}
	if strings.Join(light, ",") != strings.Join(dark, ",") {
		t.Errorf("the two themes declare different colour tokens.\n light: %v\n dark:  %v\n"+
			"A token defined in only one theme renders that theme's colour on the other "+
			"theme's ground, which is the classic unreadable-artifact bug.", light, dark)
	}
}

// hexLiteral is compiled once: TestNoHexLiteralOutsideTheTokenBlocks asks it
// about every line of the stylesheet, and the stylesheet only gets longer.
var hexLiteral = regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`)

func TestNoHexLiteralOutsideTheTokenBlocks(t *testing.T) {
	css, light, dark := themes(t)

	for _, line := range strings.Split(css, "\n") {
		if !hexLiteral.MatchString(line) {
			continue
		}
		if strings.Contains(light, line) || strings.Contains(dark, line) {
			continue
		}
		t.Errorf("hex literal outside the token blocks: %s\n"+
			"Every colour is a token, so a theme change is one block and not a search.",
			strings.TrimSpace(line))
	}
}

func relLuminance(t *testing.T, hex string) float64 {
	t.Helper()
	if len(hex) != 7 {
		t.Fatalf("colour %q is not #rrggbb; the contrast measurement only reads that form", hex)
	}
	var rgb [3]float64
	for i := 0; i < 3; i++ {
		var v int
		if _, err := fmt.Sscanf(hex[1+2*i:3+2*i], "%02x", &v); err != nil {
			t.Fatalf("colour %q: %v", hex, err)
		}
		c := float64(v) / 255
		if c <= 0.04045 {
			rgb[i] = c / 12.92
		} else {
			rgb[i] = math.Pow((c+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*rgb[0] + 0.7152*rgb[1] + 0.0722*rgb[2]
}

func contrast(t *testing.T, fg, bg string) float64 {
	t.Helper()
	a, b := relLuminance(t, fg), relLuminance(t, bg)
	if a < b {
		a, b = b, a
	}
	return (a + 0.05) / (b + 0.05)
}

// TestTheTokensMeetContrast reads the values OUT OF THE STYLESHEET and measures
// them against that theme's own ground.
//
// It deliberately does not restate the hexes: a table of constants checked
// against constants passes forever and would not have noticed the value it
// exists to protect being edited. Planted 2026-08-26 by restoring caution to
// Amethyst's container value; this fails, the constant version did not.
//
// amount is AA-large by design and is asserted at 3.0 for that reason;
// everything else carries text and is held to AA.
func TestTheTokensMeetContrast(t *testing.T) {
	_, lightBlock, darkBlock := themes(t)
	light := colourValuesIn(lightBlock)
	dark := colourValuesIn(darkBlock)

	measured := []struct {
		token string
		min   float64
	}{
		{"--text", 4.5},
		{"--muted", 4.5},
		{"--primary", 4.5},
		{"--good", 4.5},
		{"--caution", 4.5},
		{"--danger", 4.5},
		{"--amount", 3.0},
	}
	for _, c := range measured {
		for theme, tokens := range map[string]map[string]string{"light": light, "dark": dark} {
			fg, ok := tokens[c.token]
			if !ok {
				t.Errorf("%s is not declared in the %s theme", c.token, theme)
				continue
			}
			ground, ok := tokens["--ground"]
			if !ok {
				t.Fatalf("the %s theme declares no --ground to measure against", theme)
			}
			if got := contrast(t, fg, ground); got < c.min {
				t.Errorf("%s on %s is %.2f against %s, want >= %.2f — see "+
					"the admin-UI palette design notes, which "+
					"records why this value is what it is", c.token, theme, got, ground, c.min)
			}
		}
	}

	// AND THE TABLE IS COMPLETE, which is the half that was missing. A
	// hand-listed set of tokens checked against the stylesheet still leaves the
	// SUBJECT hand-listed: --text, the primary foreground of every page, was
	// declared in both themes, used by the body rule, and measured by nothing at
	// all. Nobody omitted it on purpose — it simply was not on the list, and
	// nothing said a list could be short.
	//
	// So every colour token must be either measured above or named here as a
	// ground or a surface. A new token forces a decision instead of defaulting
	// to unchecked.
	notForeground := map[string]string{
		"--ground":   "the page's own background; it is what the others are measured against",
		"--raised":   "a surface, not a foreground",
		"--sunken":   "a surface, not a foreground",
		"--hairline": "a border, never text",
		"--secondary": "Amethyst's second accent, carried for the palette's completeness; " +
			"nothing renders text in it, and this must move to the measured table if anything does",
	}
	checked := map[string]bool{}
	for _, c := range measured {
		checked[c.token] = true
	}
	for token := range light {
		if checked[token] || notForeground[token] != "" {
			continue
		}
		t.Errorf("the colour token %s is measured by nothing and is not listed as a ground or "+
			"a surface; add it to the contrast table, or say here why it carries no text", token)
	}
}
