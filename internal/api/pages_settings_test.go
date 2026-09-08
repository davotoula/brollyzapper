package api_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/store"
)

// logLevelSelect reads the Log level control back out of the rendered page: the
// options it offers, in order, and the ones marked selected.
//
// It parses the page rather than grepping it because the bug this file exists
// for is invisible to a substring check. On a fresh install every option is
// present and none carries `selected`, so `strings.Contains(page, "info")`
// passes while the browser submits the FIRST option — which is "debug". What
// matters is not that the option exists, it is which one the browser would send.
//
// Scoped to the settings <form> the way formFieldNames is, so nothing else on
// the page can be mistaken for it.
func logLevelSelect(t *testing.T, page string) (offered, selected []string) {
	t.Helper()
	const formMarker = `<form method="post" action="/settings">`
	start := strings.Index(page, formMarker)
	if start < 0 {
		t.Fatalf("no settings form in the rendered page:\n%s", page)
	}
	body := page[start:]
	body = body[:strings.Index(body, "</form>")]

	const selectMarker = `<select name="` + api.SettingLogLevel + `">`
	i := strings.Index(body, selectMarker)
	if i < 0 {
		t.Fatalf("no %s select in the settings form:\n%s", api.SettingLogLevel, body)
	}
	block := body[i+len(selectMarker):]
	block = block[:strings.Index(block, "</select>")]

	for _, option := range strings.Split(block, "<option")[1:] {
		tag := option[:strings.Index(option, ">")]
		at := strings.Index(tag, `value="`)
		if at < 0 {
			t.Fatalf("an <option> with no value in the log level select: %q", tag)
		}
		value := tag[at+len(`value="`):]
		value = value[:strings.Index(value, `"`)]
		offered = append(offered, value)
		if strings.Contains(tag, "selected") {
			selected = append(selected, value)
		}
	}
	if len(offered) == 0 {
		t.Fatalf("the log level select offers nothing; this test would assert over an empty list:\n%s", block)
	}
	return offered, selected
}

// whatTheBrowserWouldSubmit is the option a browser sends when the form is
// submitted untouched: the selected one, or — and this is the whole bug — the
// first in the list when nothing is selected.
func whatTheBrowserWouldSubmit(t *testing.T, page string) string {
	t.Helper()
	offered, selected := logLevelSelect(t, page)
	switch len(selected) {
	case 0:
		return offered[0]
	case 1:
		return selected[0]
	default:
		t.Fatalf("%d options are marked selected (%v); a browser's choice between them is "+
			"not something this test should be guessing at", len(selected), selected)
		return ""
	}
}

// BrollyZap-497, observed on the box during the 0.1.17 fresh-install trip.
//
// A fresh install stores no log_level, the handler passed that empty string
// through to the view, and settings.html marks an option selected only when it
// equals it — so nothing was selected and the browser fell back to the first
// option in the list, which is "debug". Setting the domain and address name
// requires saving that form, so a first-time operator could not avoid writing
// log_level=debug without noticing the select. Those paths are public and DEBUG
// is the level OPERATING.md tells the operator to turn back off.
//
// The assertion is on what the BROWSER WOULD SUBMIT rather than on the presence
// of a `selected` attribute, because "nothing is selected" and "debug is
// selected" are the same event at the far end of the form post, and it is the
// far end that wrote debug into the box's database.
func TestAFreshInstallDoesNotSubmitDebug(t *testing.T) {
	h := newHarness(t) // the harness runs at INFO, as the binaries do
	cookie := h.login(t)

	// Asserted, not assumed: this test is about the UNSET row, and a fixture
	// that had quietly stored one would make it pass while proving nothing.
	// That is exactly how the defect survived — internal/web/preview_test.go
	// sets Settings.LogLevel explicitly, so every preview showed the right
	// thing while the box did not.
	if _, ok, err := h.store.Setting(t.Context(), api.SettingLogLevel); err != nil || ok {
		t.Fatalf("the fixture already stores a %s row (ok=%v err=%v); this test is about "+
			"the fresh install, where there is none", api.SettingLogLevel, ok, err)
	}

	page := h.get(t, "/settings", cookie).Body.String()
	offered, selected := logLevelSelect(t, page)
	if got := whatTheBrowserWouldSubmit(t, page); got != "info" {
		t.Errorf("a fresh install's Settings form submits %s=%q, want \"info\" — the level "+
			"already in force. Offered %v, selected %v. Saving this form is not optional: "+
			"the domain and the address name are set on it.",
			api.SettingLogLevel, got, offered, selected)
	}

	// And pressing Save with nothing changed writes back what was already true,
	// rather than changing the level as a side effect of setting the domain.
	// The value posted is READ OFF THE PAGE, not typed here: that is the
	// coupling under test, and a page that starts selecting something else must
	// fail this. The rest of the form's round-trip is
	// TestEverySettingsFieldRoundTrips' job, not this test's.
	submitted := whatTheBrowserWouldSubmit(t, page)
	if rec := h.saveSettings(t, cookie, url.Values{
		api.SettingLogLevel: {submitted},
	}); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /settings = %d, want a redirect (%s)", rec.Code, rec.Body)
	}
	stored, ok, err := h.store.Setting(t.Context(), api.SettingLogLevel)
	if err != nil || !ok {
		t.Fatalf("no %s row after Save (ok=%v err=%v)", api.SettingLogLevel, ok, err)
	}
	if stored != "info" {
		t.Errorf("an unchanged Save stored %s=%q, want \"info\"", api.SettingLogLevel, stored)
	}
	if got := h.level.Level(); got != slog.LevelInfo {
		t.Errorf("the running level is %v after an unchanged Save, want INFO; DEBUG lines "+
			"about publicly reachable paths start here", got)
	}
}

// The environment's level, not a constant. A deployment that set
// LOG_LEVEL=debug deliberately must see debug selected and have an unchanged
// Save write debug: hardcoding "info" would fix the fresh install by silently
// turning such a deployment's logging DOWN on its first Save, which is the same
// class of bug pointing the other way.
func TestAnUnsetRowFollowsTheLevelInForce(t *testing.T) {
	for _, want := range []string{"debug", "info", "warn", "error"} {
		t.Run(want, func(t *testing.T) {
			var level slog.Level
			if err := level.UnmarshalText([]byte(want)); err != nil {
				t.Fatalf("UnmarshalText(%q): %v", want, err)
			}
			h := newHarness(t)
			h.level.Set(level) // as cmd/brollyzapper does from config.LogLevel
			cookie := h.login(t)

			page := h.get(t, "/settings", cookie).Body.String()
			if got := whatTheBrowserWouldSubmit(t, page); got != want {
				t.Errorf("with no stored row and the process at %v, the form submits %q, "+
					"want %q; an unchanged Save would change a level nobody asked to change",
					level, got, want)
			}
		})
	}
}

// The stored row still wins, and still round-trips. §12's precedence is
// unchanged by 497: the setting overrides the environment, and only the
// STARTING POINT for an absent setting moved.
func TestAStoredLevelStillWinsAndRoundTrips(t *testing.T) {
	h := newHarness(t)
	h.level.Set(slog.LevelDebug) // the environment says debug...
	// BEFORE the login. Logging in renders a page, which fills the settings
	// cache (settingsCacheTTL, 2s), and a row written after that is not read
	// again inside a test's lifetime — so this test would have run against an
	// EMPTY row and passed by agreeing with the fresh-install case instead of
	// with the stored one.
	if err := h.store.SetSetting(t.Context(), api.SettingLogLevel, "warn"); err != nil {
		t.Fatal(err)
	}
	cookie := h.login(t)

	page := h.get(t, "/settings", cookie).Body.String()
	if got := whatTheBrowserWouldSubmit(t, page); got != "warn" {
		t.Errorf("the form submits %q with warn stored, want \"warn\"; the stored setting "+
			"overrides the environment and this page is where an operator confirms that",
			got)
	}
}

// A stored value the template cannot render lands in exactly the same place 497
// did: no option matches, so the browser submits the first one, which is debug.
//
// It is reachable — saveSettings stores what was posted, trimmed and otherwise
// unvalidated — and it is the reason the handler parses the stored value rather
// than string-matching it. Fixing only the empty case would leave the same
// defect one input away, in a form whose Save an operator cannot avoid.
func TestAnUnrenderableStoredLevelDoesNotFallBackToDebug(t *testing.T) {
	for _, stored := range []string{
		"INFO",     // a case the parser accepts and the template does not offer
		" warn ",   // whitespace, which the parser tolerates
		"info+2",   // a level slog understands and settings.html has no option for
		"nonsense", // and one nothing understands
	} {
		t.Run(stored, func(t *testing.T) {
			h := newHarness(t) // running at INFO
			// Before the login, for the settings-cache reason spelt out in
			// TestAStoredLevelStillWinsAndRoundTrips. Written after it, every
			// case here passes against an empty row — which is a different
			// test that happens to give the same answer.
			if err := h.store.SetSetting(t.Context(), api.SettingLogLevel, stored); err != nil {
				t.Fatal(err)
			}
			cookie := h.login(t)
			page := h.get(t, "/settings", cookie).Body.String()
			if got := whatTheBrowserWouldSubmit(t, page); got == "debug" {
				t.Errorf("with %q stored the form submits \"debug\"; an unrenderable row "+
					"must not raise the level on the next Save, which is 497 with a "+
					"different input", stored)
			}
		})
	}
}

// The handler's guarantee is "always one of the options settings.html offers",
// and that sentence is only true relative to a list living in the template
// (`list "debug" "info" "warn" "error"`) while the other copy lives in
// levelOption. Two statements of one set, which is the shape this tree has been
// bitten by before — so the set is pinned here, where a divergence is a failing
// test rather than a control that silently selects nothing again.
//
// Adding a level is not forbidden; it is required to be a decision. Whoever
// adds one to the template lands here and has to teach levelOption about it.
// RETIRED by 0vk.38, and this note is what replaces it.
//
// TestTheLogLevelOptionsAreExactlyTheOnesTheHandlerCanChoose compared two lists:
// settings.html's `list "debug" "info" "warn" "error"` and the four strings
// levelOption could return. A pin like that is what you write when you cannot
// remove a duplicate — it cannot stop the two drifting, only report it after the
// fact, and it was the best available while the template held its own copy.
//
// There is one list now (logLevelOptions in pages_settings.go); the template
// ranges over what the handler exports. A pin on a single statement compares it
// with itself and passes whatever it says, which is a test that cannot fail —
// so keeping it would have been worse than deleting it, not merely redundant.
//
// WHAT STILL COVERS THIS: TestTheSettingsPageOffersTheLevelsTheHandlerExports
// below asserts the rendered select against logLevelOptions itself, which is a
// different claim — that the template really reaches the list, rather than that
// two lists agree. If the range were replaced by a hardcoded list again, that is
// what goes red.
func TestTheSettingsPageOffersTheLevelsTheHandlerExports(t *testing.T) {
	h := newHarness(t)
	page := h.get(t, "/settings", h.login(t)).Body.String()
	offered, _ := logLevelSelect(t, page)
	if want := api.LogLevelNamesForTest(); !slices.Equal(offered, want) {
		t.Errorf("settings.html offers %v, want %v — the select must range over the "+
			"handler's list, and an option outside it selects nothing, which makes the "+
			"browser submit the first one", offered, want)
	}
	// ANTI-VACUITY: logLevelNames() emptied would make the comparison above pass
	// against a select with no options at all, which is the browser-submits-debug
	// bug wearing a different hat.
	//
	// EMPTINESS, NOT A COUNT. This asserted `!= 4` first, which is the retired
	// pin in miniature: adding a fifth level deliberately would fail with "the
	// page offers 5 levels, want 4", pointing at a number instead of at the
	// decision. Whether four is the right set is a question for the ruling that
	// chose them, not for a vacuity guard. Found by review.
	if len(offered) == 0 {
		t.Error("the page offers no levels at all, so the comparison above asserted nothing")
	}
}

// 0vk.38 ruling 1: the write refuses a log level no reader could render, and
// 497's tolerant reader stays underneath it.
//
// BOTH LAYERS, asserted separately, because the ruling is that both exist. The
// write stops NEW bad rows; the reader copes with the ones already on disk —
// written by an older binary, by hand, or restored from a backup — and a reader
// that assumed the writer had checked would put 497 straight back.
//
// The plant is on the bead and in the report: remove the validation and this
// goes red while the reader test below stays GREEN. That pair is what "defence
// in depth" has to mean to be worth the words.
func TestAnUnrenderableLogLevelIsRefusedAtTheWrite(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)
	got := h.saveSettings(t, cookie, url.Values{
		api.SettingDomain:   {"kept.example"},
		api.SettingLogLevel: {"verbose"},
	})

	if got.Code != http.StatusSeeOther ||
		!strings.Contains(got.Header().Get("Location"), "bad_log_level") {
		t.Errorf("saving log_level=verbose = %d %q, want the refusal flash",
			got.Code, got.Header().Get("Location"))
	}
	if stored, ok, _ := h.store.Setting(t.Context(), api.SettingLogLevel); ok && stored == "verbose" {
		t.Error("the unrenderable level was stored anyway")
	}
	// ALL OR NOTHING, like the trusted-proxies refusal beside it: a save that
	// wrote the keys before the bad one would leave a partial state the page has
	// no way to describe.
	if stored, ok, _ := h.store.Setting(t.Context(), api.SettingDomain); ok && stored == "kept.example" {
		t.Error("the rest of the form was applied despite the refusal")
	}
}

// An ABSENT log_level is not a refusal. Several callers post the settings form
// without log_level at all; refusing that would reject a save for a field the
// operator never touched. It is also not what the ruling asks for — an empty row
// is the fresh-install case 497 handles on purpose. This is the boundary a
// failing test drew, so it is pinned.
//
// THE FIXTURE IS THE FULL FORM MINUS log_level. This test once posted `domain`
// alone, which was 1pd's evidence rather than its subject: under that ruling the
// lone POST is refused for the eight keys it omitted, so it could no longer fail
// for the reason this test is about.
func TestASettingsSaveWithNoLogLevelFieldIsNotRefused(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)
	form := h.browserForm(t, cookie, url.Values{api.SettingDomain: {"kept.example"}})
	form.Del(api.SettingLogLevel)
	got := h.postForm(t, "/settings", cookie, form)

	if location := got.Header().Get("Location"); strings.Contains(location, "bad_log_level") {
		t.Errorf("a form with no log_level field was refused (%q); an absent field is not "+
			"an unrenderable value", location)
	}
	if stored, ok, _ := h.store.Setting(t.Context(), api.SettingDomain); !ok || stored != "kept.example" {
		t.Errorf("domain = %q ok=%v, want the save to have gone through", stored, ok)
	}
}

// And the reader still copes, which is the half the write must not replace.
//
// THE PAIRING IS THE CLAIM, and it is what makes this different from
// TestAnUnrenderableStoredLevelDoesNotFallBackToDebug above: that one covers the
// reader on its own, this one uses the EXACT value the write now refuses, so the
// two tests together say "refused at the door, still handled once inside". Remove
// the validation and the refusal test goes red while this stays green; break the
// reader and this goes red on its own.
//
// IT ASSERTS THE LEVEL IN FORCE, not merely that the answer is one of the four,
// and that precision was bought by a plant. The first version checked membership,
// which the broken reader satisfied: with nothing selected the browser submits
// the FIRST option, "debug", and debug is in the list. The test agreed with 497
// itself. Naming the expected level is what makes it able to fail.
func TestATolerantReaderStillRendersARowTheWriteWouldRefuse(t *testing.T) {
	h := newHarness(t)
	h.level.Set(slog.LevelWarn) // distinctive, and not the first option
	// Before the login, for the settings-cache reason spelt out in
	// TestAStoredLevelStillWinsAndRoundTrips.
	if err := h.store.SetSetting(t.Context(), api.SettingLogLevel, "verbose"); err != nil {
		t.Fatal(err)
	}
	page := h.get(t, "/settings", h.login(t)).Body.String()

	if got := whatTheBrowserWouldSubmit(t, page); got != "warn" {
		t.Errorf("with the unrenderable row %q stored and the process at warn, the form "+
			"submits %q, want \"warn\" — the reader must fall back to the level in force, "+
			"and a form submitting \"debug\" here is 497", "verbose", got)
	}
}

// A POST that omits a key does not blank it — it is refused, whole
// (BrollyZap-1pd).
//
// WHY A REFUSAL AND NOT A PARTIAL UPDATE. Both were on the table; the ruling
// (David, 8 Sep) took the stricter one. Writing only the present keys would be
// friendlier, but it makes a truncated request look identical to a deliberate
// one, and several of these keys are security-relevant: trusted_proxies blanked
// believes no forwarded-for header, relays blanked stops receipts publishing
// anywhere. A refusal says what happened; a partial update says nothing.
//
// IT REFUSES BEFORE WRITING, in the same validate-first loop 0vk.38 added for
// exactly this reason: a check inside the write loop would refuse half way and
// leave the keys before it already saved, which is the partial save this bead is
// about.
func TestASettingsSaveMissingAKeyIsRefusedAndWritesNothing(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	// The shape the bead was filed on: one key, eight omitted.
	got := h.postForm(t, "/settings", cookie, url.Values{api.SettingDomain: {"kept.example"}})

	if location := got.Header().Get("Location"); !strings.Contains(location, "incomplete_form") {
		t.Errorf("a form missing eight keys was not refused (%q); under 1pd's ruling an "+
			"absent key refuses the whole save", location)
	}
	// ALL OR NOTHING. The refused key must not have taken the ones beside it
	// with it, and the domain in the request is the one that would show.
	if stored, ok, _ := h.store.Setting(t.Context(), api.SettingDomain); ok && stored == "kept.example" {
		t.Error("the save was applied despite the refusal")
	}
}

// An EMPTY value that WAS submitted is a deliberate blank and stays legal
// (BrollyZap-1pd's ruling, second half).
//
// This is the outcome a wrong mechanism produces, pinned so it cannot be reached
// by accident — see saveSettings' presence check for which mechanism and why.
// Relays is the sharper case, since clearing it is a thing an operator does on
// purpose.
func TestASettingsSaveWithAnEmptyRelaysFieldStoresTheBlank(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)
	if err := h.store.SetSetting(t.Context(), api.SettingRelays, "wss://relay.example"); err != nil {
		t.Fatalf("seeding relays: %v", err)
	}

	got := h.saveSettings(t, cookie, url.Values{api.SettingRelays: {""}})

	if location := got.Header().Get("Location"); !strings.Contains(location, "flash=saved") {
		t.Errorf("clearing relays was not accepted (%q); a submitted empty value is a "+
			"deliberate blank, not an absent key", location)
	}
	stored, _, _ := h.store.Setting(t.Context(), api.SettingRelays)
	if stored != "" {
		t.Errorf("relays = %q, want the blank the operator submitted", stored)
	}
}

// A refused settings value does not reach the log (§12).
//
// The rule has no exception for input that happens to be malformed, and the
// refusal path had one anyway: the log line carried err.Error(), and both
// wired validators embed the submitted value in their message
// (`%q is not a log level`, `%q is neither a CIDR prefix nor an IP address`).
// So the operator's typing was echoed into the record two lines below a
// comment saying it was not.
//
// BOTH VALIDATORS, because they leak by different routes — validLogLevel
// formats the value itself, validTrustedProxies inherits it from
// config.ParsePrefixList — and a fix that only stopped the local one would
// leave the inherited half in place.
//
// The sentinels are distinctive rather than realistic: "verbose" and
// "not-a-cidr" are what the neighbouring refusal tests post, and a value that
// appears nowhere else cannot be matched by accident.
func TestARefusedSettingsValueIsNotLogged(t *testing.T) {
	for _, tc := range []struct {
		name, key, value string
	}{
		{"an unrenderable log level", api.SettingLogLevel, "verbose-sentinel-1pd"},
		{"an unparseable proxy list", api.SettingTrustedProxies, "not-a-cidr-sentinel-1pd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logged bytes.Buffer
			h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
				opts.Log = logging.New(&logged, logging.NewLevelVar(slog.LevelDebug))
			})
			cookie := h.login(t)

			got := h.saveSettings(t, cookie, url.Values{tc.key: {tc.value}})
			// The refusal itself must still happen, or this test passes because
			// nothing was refused rather than because nothing was logged.
			if location := got.Header().Get("Location"); !strings.Contains(location, "flash=") ||
				strings.Contains(location, "flash=saved") {
				t.Fatalf("%s was not refused (%q); this test would prove nothing", tc.key, location)
			}

			record := logged.String()
			if !strings.Contains(record, "refused a settings value") {
				t.Fatalf("the refusal was not logged at all, so the assertion below has no "+
					"subject:\n%s", record)
			}
			if strings.Contains(record, tc.value) {
				// Masked, like every other leak assertion in this package: a
				// test that proves a value escaped by printing it again has not
				// finished the job.
				t.Errorf("the refused %s value reached the log; §12 has no exception for "+
					"malformed input. Record, with the value masked:\n%s", tc.key,
					strings.ReplaceAll(record, tc.value, "<submitted>"))
			}
		})
	}
}
