package composelint_test

import (
	"maps"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/davotoula/brollyzapper/internal/composelint"
)

// Moved from regtest/lint_test.go and deploy/lint_test.go with the primitives
// they test (BrollyZap-20i.18). Each assertion is unchanged but for the name of
// the function it calls.

func TestCommandLineDecodesBothSpellings(t *testing.T) {
	for _, doc := range []string{
		"command: [lnd, --tlsextradomain=lnd]",
		"command:\n  - lnd\n  - --tlsextradomain=lnd   # a trailing comment is not an argument\n",
		"command: lnd  --tlsextradomain=lnd",
	} {
		var got struct {
			Command composelint.CommandLine `yaml:"command"`
		}
		if err := yaml.Unmarshal([]byte(doc), &got); err != nil {
			t.Errorf("decoding %q: %v", doc, err)
			continue
		}
		if want := []string{"lnd", "--tlsextradomain=lnd"}; !slices.Equal(got.Command, want) {
			t.Errorf("decoding %q = %q, want %q", doc, got.Command, want)
		}
	}
}

func TestSplitPortReadsTheSpellingsItClaims(t *testing.T) {
	for _, tc := range []struct {
		mapping, host, container string
		wantErr                  bool
	}{
		{mapping: "${APP_PORT:-8080}:8080", host: "8080", container: "8080"},
		{mapping: "8081:8080", host: "8081", container: "8080"},
		{mapping: "127.0.0.1:8080:8080/tcp", host: "8080", container: "8080"},
		{mapping: "${APP_PORT}:8080", wantErr: true},
		{mapping: "8080", wantErr: true},
	} {
		host, container, err := composelint.SplitPort(tc.mapping)
		if (err != nil) != tc.wantErr || host != tc.host || container != tc.container {
			t.Errorf("SplitPort(%q) = %q, %q, %v; want %q, %q, error=%v", tc.mapping,
				host, container, err, tc.host, tc.container, tc.wantErr)
		}
	}
}

// TestInterpolatedNamesReadsBothSpellingsAndOnlyTheCode is what makes the rule
// above survive a revert.
//
// Every claim its comment block makes was measured once, by hand, against a
// template that satisfies it: put the brace back in anyInterpolationRE and the
// whole suite stays green, because this template has no bare form to catch.
// That is a rule written rather than tested, and it is the shape
// umbrel/lint_test.go's own parser table exists to avoid.
func TestInterpolatedNamesReadsBothSpellingsAndOnlyTheCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want []string
	}{{
		name: "braced, with and without a default",
		raw:  "services:\n  s:\n    environment:\n      A: ${LND_DIR}\n      B: ${HTTP_PORT:-8080}\n",
		want: []string{"HTTP_PORT", "LND_DIR"},
	}, {
		name: "bare, which the brace-only pattern never saw",
		raw:  "services:\n  s:\n    environment:\n      A: $LND_DIR\n",
		want: []string{"LND_DIR"},
	}, {
		name: "a comment must not demand an assignment",
		raw:  "# an earlier draft read ${LND_SOCKET_PATH}\nservices:\n  s:\n    environment:\n      A: ${LND_DIR}\n",
		want: []string{"LND_DIR"},
	}, {
		name: "a folded scalar is one name, not two halves",
		raw:  "services:\n  s:\n    environment:\n      A: \"${LND_D\\\n        IR}\"\n",
		want: []string{"LND_DIR"},
	}, {
		name: "$$ is an escaped literal dollar, not an interpolation",
		raw:  "services:\n  s:\n    environment:\n      A: \"$$NOT_REAL\"\n      B: ${LND_DIR}\n",
		want: []string{"LND_DIR"},
	}, {
		name: "$$$NAME is a literal dollar and then a real one",
		raw:  "services:\n  s:\n    environment:\n      A: \"$$$LND_DIR\"\n",
		want: []string{"LND_DIR"},
	}, {
		name: "a name in a volume string counts, wherever it appears",
		raw:  "services:\n  s:\n    volumes:\n      - ${DATA_DIR}/guard:/guard\n",
		want: []string{"DATA_DIR"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := slices.Sorted(maps.Keys(composelint.Parse(t, "fixture", []byte(tc.raw), nil).InterpolatedNames()))
			if !slices.Equal(got, tc.want) {
				t.Errorf("InterpolatedNames(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestInterpolatedDefaultsReadsOnlyARealDefault is the parser table for the
// value comparison, for the reason the one above exists: every row here is a
// template shape that would make TestTheExampleShowsEachSettingAtTheTemplatesDefault
// compare against something compose never substitutes.
func TestInterpolatedDefaultsReadsOnlyARealDefault(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want map[string][]string
	}{{
		name: "both default spellings, and a name read twice keeps both",
		raw:  "services:\n  s:\n    environment:\n      A: ${HTTP_PORT:-8080}\n      B: ${LOG_LEVEL-INFO}\n      C: ${HTTP_PORT:-8080}\n",
		want: map[string][]string{"HTTP_PORT": {"8080", "8080"}, "LOG_LEVEL": {"INFO"}},
	}, {
		name: "an empty default is a default",
		raw:  "services:\n  s:\n    environment:\n      A: ${TRUSTED_PROXIES:-}\n",
		want: map[string][]string{"TRUSTED_PROXIES": {""}},
	}, {
		name: "a required variable's message is not a default, and neither is no default",
		raw:  "services:\n  s:\n    environment:\n      A: ${LND_DIR:?LND_DIR is unset}\n      B: ${LND_ADDRESS}\n      C: $LND_NETWORK\n",
		want: map[string][]string{},
	}, {
		name: "a comment's default is not the template's",
		raw:  "# was ${HTTP_PORT:-9090}\nservices:\n  s:\n    ports:\n      - \"${HTTP_PORT:-8080}:8080\"\n",
		want: map[string][]string{"HTTP_PORT": {"8080"}},
	}, {
		name: "an escaped dollar is not an interpolation",
		raw:  "services:\n  s:\n    environment:\n      A: \"$${HTTP_PORT:-9090}\"\n",
		want: map[string][]string{},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := composelint.Parse(t, "fixture", []byte(tc.raw), nil).Defaults()
			if !maps.EqualFunc(got, tc.want, slices.Equal) {
				t.Errorf("Defaults(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
