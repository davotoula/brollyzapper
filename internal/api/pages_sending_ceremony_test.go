package api_test

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/store"
)

// `06v`: THE SERVER RELAYS, IT DOES NOT DECIDE.
//
// The whole ceremony rests on this container not being the thing that judges
// whether a change needs authorisation — that judgement is exactly what a
// compromised server would get wrong on purpose. So the handler's contract is
// narrow and worth pinning: it passes the change and whatever the operator
// typed, unaltered, and takes whatever answer comes back.
//
// A handler that short-circuited "the code box is empty, so don't bother asking"
// would be the server deciding. It would also be a real bug: the latch may
// already be on, in which case no code is needed and the change succeeds.
func TestEnablingSendingRelaysTheOperatorsCodeUnaltered(t *testing.T) {
	g := &fakeGuard{}
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) { opts.Guard = g })
	cookie := h.login(t)

	rec := h.postForm(t, "/sending/enable", cookie, url.Values{"code": {"8f3k-2qpd"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /sending/enable = %d, want a redirect", rec.Code)
	}
	if len(g.applied) != 1 {
		t.Fatalf("the guard saw %d changes, want 1", len(g.applied))
	}
	got := g.applied[0]
	if got.Change != (guard.Change{Control: guard.ControlSending, On: true}) {
		t.Errorf("the guard was asked for %+v, want the sending latch on", got.Change)
	}
	if got.Code != "8f3k-2qpd" {
		t.Errorf("the guard was given the code %q, want it verbatim. Normalising here would "+
			"put a second opinion about the format in the container that must not have one",
			got.Code)
	}
	// And the bake happens only after the latch is set, in that order.
	if g.baked != 1 {
		t.Errorf("the spend macaroon was baked %d times, want 1", g.baked)
	}
}

// A refused code changes NOTHING, and the guard's raw words do NOT reach the URL.
//
// Two properties, and the second was a review finding. The order is the first:
// the latch, then the bake, then the setting — a bake attempted before the latch
// is one the guard refuses anyway, and the error it returns would be the wrong
// one to show.
//
// THE SECOND IS THAT THE REASON STAYS OUT OF THE QUERY STRING. It was relayed as
// `?reason=<the guard's text>`, which made the ceremony's own screen render
// arbitrary text from a URL parameter directly beside the box asking for a code.
// A page whose entire premise is "believe the file, not this page" must not be
// the easiest place in the app to put words in front of an operator. The reason
// lives in the guard's log and in the durable trail instead, where someone
// looking for it can find it and nobody else can plant it.
func TestARefusedCodeBakesNothingAndKeepsTheGuardsWordsOutOfTheURL(t *testing.T) {
	g := &fakeGuard{applyErr: errors.New("guard: that authorisation expired; ask for a new one")}
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Guard = g
		opts.Settings = db
	})
	cookie := h.login(t)

	rec := h.postForm(t, "/sending/enable", cookie, url.Values{"code": {"0000-0000"}})

	if g.baked != 0 {
		t.Errorf("the spend macaroon was baked %d times after a refused code; the guard would "+
			"have refused it, and the operator would be shown the wrong diagnosis", g.baked)
	}
	location := rec.Header().Get("Location")
	if !strings.Contains(location, "flash=code_refused") {
		t.Errorf("the redirect is %q; the page cannot tell the operator what happened", location)
	}
	if strings.Contains(location, "expired") || strings.Contains(location, "reason=") {
		t.Errorf("the redirect is %q; it carries the guard's raw text into a URL that renders "+
			"beside the code box. Anyone who can get the operator to follow a link can then "+
			"write whatever they like on the one page that tells them to trust the file "+
			"instead of the page", location)
	}
	if enabled, _, _ := h.store.Setting(t.Context(), "send_enabled"); enabled == "true" {
		t.Error("send_enabled was written after a refused code")
	}
}

// Enabling with NO code asks the guard for one, and mints nothing on the way.
//
// There is no separate "ask for a code" route: one click on a fresh install
// leads to the ceremony because the GUARD says this is a loosening, not because
// the server worked it out. The same POST on an already-latched install is
// refused a grant and falls through to the bake — see the test below.
func TestEnablingWithNoCodeAsksTheGuardForOne(t *testing.T) {
	g := &fakeGuard{}
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) { opts.Guard = g })
	cookie := h.login(t)

	rec := h.postForm(t, "/sending/enable", cookie, url.Values{})

	if len(g.authorised) != 1 {
		t.Fatalf("the guard was asked for %d authorisations, want 1", len(g.authorised))
	}
	if g.authorised[0] != (guard.Change{Control: guard.ControlSending, On: true}) {
		t.Errorf("the guard was asked to authorise %+v, want the sending latch on",
			g.authorised[0])
	}
	// And nothing was minted on the way. Asking for a code is not enabling.
	if g.baked != 0 || len(g.applied) != 0 {
		t.Errorf("asking for a code baked %d macaroons and applied %d changes; it must do "+
			"neither", g.baked, len(g.applied))
	}
	if location := rec.Header().Get("Location"); !strings.Contains(location, "authorisation_written") {
		t.Errorf("the redirect is %q; the operator is not sent to read the file", location)
	}
}

// And the SAME POST on an already-latched install skips the ceremony entirely.
//
// This is the retry path: an enable whose bake failed leaves the latch on, and
// the ceremony authorised the transition, which happened. Asking again would
// teach the operator that the ceremony is a formality they perform for
// everything — which is exactly how a phished one stops reading the sentence.
func TestEnablingOnAnAlreadyLatchedInstallSkipsTheCeremony(t *testing.T) {
	g := &fakeGuard{latched: true}
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Guard = g
		opts.Settings = db
	})
	cookie := h.login(t)

	h.postForm(t, "/sending/enable", cookie, url.Values{})

	if g.baked != 1 {
		t.Errorf("the spend macaroon was baked %d times, want 1 — the retry after a failed "+
			"bake must not stall on a second ceremony", g.baked)
	}
}

// The caps: SATS IN THE FORM, MSAT IN THE MODEL.
//
// §9 renders amounts as whole sats and §4 stores msat. An operator typing 50000
// into a box labelled sats must not set a cap of fifty thousand MILLISATS, which
// is fifty sats and would refuse every payment they make — a control that
// appears to loosen and in fact tightens by a thousandfold.
func TestACapIsSetInSatsAndReachesTheGuardInMsat(t *testing.T) {
	g := &fakeGuard{authoriseErr: errors.New("guard: spend_cap does not need an authorisation")}
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) { opts.Guard = g })
	cookie := h.login(t)

	h.postForm(t, "/sending/caps", cookie, url.Values{
		"control": {"spend_cap"}, "sats": {"50000"},
	})

	if len(g.applied) != 1 {
		t.Fatalf("the guard saw %d changes, want 1", len(g.applied))
	}
	if got := g.applied[0].Change; got.Msat != 50_000_000 {
		t.Errorf("the guard was asked for %d msat, want 50000000. An operator who typed 50000 "+
			"into a box labelled sats got %d sats", got.Msat, got.Msat/1000)
	}
}

// A raise with no code leads to the CEREMONY, not to a bare refusal.
//
// The operator does not know in advance which direction needs a code — the guard
// decides that against state this container cannot read — so the handler asks
// for an authorisation first and only falls through to applying when the guard
// says none is needed. A page that answered "refused" and left them to work out
// why would be a control that fails without saying what to do.
func TestRaisingACapWithNoCodeStartsTheCeremony(t *testing.T) {
	g := &fakeGuard{}
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) { opts.Guard = g })
	cookie := h.login(t)

	rec := h.postForm(t, "/sending/caps", cookie, url.Values{
		"control": {"spend_cap"}, "sats": {"500000"},
	})

	if len(g.authorised) != 1 {
		t.Fatalf("the guard was asked for %d authorisations, want 1", len(g.authorised))
	}
	if got := g.authorised[0]; got.Control != guard.ControlSpendCap || got.Msat != 500_000_000 {
		t.Errorf("the authorisation was requested for %+v; it has to name the SAME change the "+
			"operator asked for, or the code they are given will not redeem it", got)
	}
	if location := rec.Header().Get("Location"); !strings.Contains(location, "authorisation_written") {
		t.Errorf("the redirect is %q; the operator is not sent to the next step", location)
	}
	// And nothing was applied, because the guard has not been told a code yet.
	if len(g.applied) != 0 {
		t.Errorf("%d changes were applied before the operator confirmed anything", len(g.applied))
	}
}

// The caps route moves CAPS. It is not a second way to reach the sending latch.
//
// THE DEFECT THIS PINS was live: the handler validated its `control` field
// against `guard.Controls` — every control the guard has — so a POST here with
// `control=sending` was accepted and built `Change{Control: sending, On: false}`.
// The guard applies that quite correctly, as a tightening needing no code. What
// it does NOT do is anything the disable handler does: `send_enabled` stays
// "true" in the server's own settings, and the macaroon is never revoked.
//
// The result is the exact state this app spends most of its design avoiding: the
// page says sending is on, the guard says it is off, §8's ladder refuses every
// payment, and a live spend credential sits between them. Found by review.
//
// The lesson is more general than the fix: A CLOSED SET IS ONLY CLOSED AT THE
// POINT THAT USES IT. `guard.Controls` is the right list for the guard, and the
// wrong one here.
func TestTheCapsRouteIsNotASecondWayToReachTheSendingLatch(t *testing.T) {
	g := &fakeGuard{latched: true}
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Guard = g
		opts.Settings = db
	})
	cookie := h.login(t)
	if err := h.store.SetSetting(t.Context(), "send_enabled", "true"); err != nil {
		t.Fatal(err)
	}

	h.postForm(t, "/sending/caps", cookie, url.Values{
		"control": {"sending"}, "sats": {"0"},
	})

	if len(g.applied) != 0 || len(g.authorised) != 0 {
		t.Fatalf("the caps route moved the sending latch (applied %+v). It does not clear "+
			"send_enabled and does not revoke, so the page would go on saying sending is on "+
			"while the guard refuses every payment", g.applied)
	}
	if enabled, _, _ := h.store.Setting(t.Context(), "send_enabled"); enabled != "true" {
		t.Errorf("send_enabled is now %q; the caps route changed a setting that is not its own",
			enabled)
	}
	if g.revoked != 0 {
		t.Errorf("the caps route revoked %d macaroons", g.revoked)
	}
}

// A control this build does not have is refused HERE, before the socket.
//
// Not because the guard would accept it — it refuses an unknown control too —
// but because a form field is caller-supplied text and the handler that turns it
// into a guard.Control is where the closed set stops being a closed set. The
// cheap check keeps the vocabulary from widening by way of an HTML form.
func TestAnUnknownCapControlNeverReachesTheGuard(t *testing.T) {
	g := &fakeGuard{}
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) { opts.Guard = g })
	cookie := h.login(t)

	h.postForm(t, "/sending/caps", cookie, url.Values{
		"control": {"everything"}, "sats": {"1"},
	})

	if len(g.applied) != 0 || len(g.authorised) != 0 {
		t.Errorf("a control named by a form field reached the guard (applied %d, authorised "+
			"%d); the set of controls is closed and a form is not where it opens",
			len(g.applied), len(g.authorised))
	}
}

// The msat multiplication cannot be made to wrap from the form.
//
// ParseInt accepts up to 9.2e18 and `* 1000` on that wraps: 18446744073709552
// sats becomes 384 msat. Neither Change.valid nor checkCapPair can catch it,
// because by the time the guard sees it the number is small and positive — so
// the operator asks to raise a limit and silently sets one that refuses every
// payment, with no ceremony, because the guard reads it as a tightening. Found
// by review, against the bound the connections form has carried since its own
// review.
func TestACapThatWouldWrapTheMsatMultiplicationIsRefused(t *testing.T) {
	g := &fakeGuard{}
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) { opts.Guard = g })
	cookie := h.login(t)

	rec := h.postForm(t, "/sending/caps", cookie, url.Values{
		"control": {"spend_cap"}, "sats": {"18446744073709552"},
	})

	if len(g.applied) != 0 || len(g.authorised) != 0 {
		t.Fatalf("a cap that wraps int64 reached the guard: %+v", g.applied)
	}
	if location := rec.Header().Get("Location"); !strings.Contains(location, "cap_invalid") {
		t.Errorf("the redirect is %q; the operator is not told the number was rejected",
			location)
	}
}

// Disabling sending drops the LATCH as well as the credential, and needs no
// code.
//
// "Off must latch off" (`06v`, Ruling 1): the safe direction is the cheap one,
// and leaving the latch standing would mean turning sending back on afterwards
// needed no ceremony — so a compromised server could revoke and immediately
// re-mint, laundering a credential it already had into a fresh one under a new
// key.
func TestDisablingSendingDropsTheLatchWithNoCode(t *testing.T) {
	g := &fakeGuard{}
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Guard = g
		opts.Settings = db
	})
	cookie := h.login(t)

	h.postForm(t, "/sending/disable", cookie, url.Values{})

	if len(g.applied) != 1 {
		t.Fatalf("the guard saw %d changes on disable, want 1", len(g.applied))
	}
	got := g.applied[0]
	if got.Change != (guard.Change{Control: guard.ControlSending}) {
		t.Errorf("the guard was asked for %+v, want the sending latch off", got.Change)
	}
	if got.Code != "" {
		t.Errorf("the handler sent a code (%q) to turn sending OFF; ceremony on the safe "+
			"direction costs the operator and buys nothing, and there is no code to send",
			got.Code)
	}
	if g.revoked != 1 {
		t.Errorf("the macaroon was revoked %d times, want 1", g.revoked)
	}
}
