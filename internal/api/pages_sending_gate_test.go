package api_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/preflight"
	"github.com/davotoula/brollyzapper/internal/store"
)

// tna.4 criteria 4 and 5, re-aimed by `06v`: the off-states are DIFFERENT
// SENTENCES WITH DIFFERENT REMEDIES, and the page never offers a control that
// cannot work.
//
// THE ORIGINAL PAIR IS NOW A TRIO, and the third is why `06v` exists. tna.4 had
// two: "sending is off" (one click) and "this install does not permit sending"
// (an app setting and a restart). The second named a remedy that DID NOT EXIST —
// umbrelOS has no settings surface in any of 391 app manifests — so an operator
// following it found nothing and concluded the app was broken. That line is why
// `06v` was P1.
//
// The three now are:
//
//	off, permitted        one click, no ceremony — the latch is already thrown
//	off, not permitted    the ceremony: a code in a file only the operator reads
//	deployment forbids    NOTHING in the app changes it, and the page says so
//
// The rule that carries over unchanged is the reason it existed: sharing wording
// would send an operator to perform an action that cannot work.
func TestTheSendingOffStatesReadDifferently(t *testing.T) {
	// The latch already thrown, so a bake is one click.
	latched := sendingPageWith(t, lnd.BrokerStatus{
		LNDReachable: true, SendingAllowedByDeployment: true,
		SendingLatched: true, SendingPermitted: true,
	})
	// A fresh install: the deployment allows it, the operator has not.
	fresh := sendingPageWith(t, lnd.BrokerStatus{
		LNDReachable: true, SendingAllowedByDeployment: true,
	})
	// A deployment that forbids it outright.
	forbidden := sendingPageWith(t, lnd.BrokerStatus{LNDReachable: true})

	// All three that CAN enable offer the control; the one that cannot does not.
	for name, body := range map[string]string{"latched": latched, "fresh": fresh} {
		if !strings.Contains(body, "Enable sending") {
			t.Errorf("the %s off-state does not offer the button:\n%s", name, body)
		}
	}
	// ABSENT, not disabled. A button that fails is a worse explanation than no
	// button.
	if strings.Contains(forbidden, "Enable sending") {
		t.Errorf("the page offers Enable sending on a deployment whose guard will refuse to "+
			"mint it; the operator would click it and be told the app is broken:\n%s", forbidden)
	}

	// Each says what to do, in its own words. The fresh install is sent to the
	// ceremony; the forbidden one is told plainly that nothing here will help.
	if !strings.Contains(fresh, "type it back in") {
		t.Errorf("the fresh install's off-state does not explain the ceremony, so the extra "+
			"step arrives as a surprise after the click:\n%s", fresh)
	}
	if !strings.Contains(forbidden, "GUARD_ALLOW_SENDING") {
		t.Errorf("the forbidden page does not name the one thing that would change it:\n%s",
			forbidden)
	}
	if !strings.Contains(forbidden, "Nothing on this page will change that") {
		t.Errorf("the forbidden page does not say the remedy is out of the operator's "+
			"reach; they will go looking for a setting they cannot find, which is `06v`:\n%s",
			forbidden)
	}

	// THE NEGATIVE HALF: no state carries another's remedy.
	for name, body := range map[string]string{"latched": latched, "fresh": fresh} {
		if strings.Contains(body, "GUARD_ALLOW_SENDING") {
			t.Errorf("the %s off-state points at a deployment variable the operator cannot "+
				"reach, and which is not the reason sending is off here:\n%s", name, body)
		}
	}
	if strings.Contains(latched, "type it back in") {
		t.Errorf("the already-latched state offers the ceremony again; the ceremony "+
			"authorised the transition and the transition happened:\n%s", latched)
	}
	// And no state claims a residual it has no evidence for. These renders have
	// NO spend macaroon; "still live" would be the page inventing live spend
	// authority on an install that has none.
	if strings.Contains(forbidden, "still live") {
		t.Errorf("the forbidden page states a residual with no spend macaroon present; the "+
			"paragraph exists to state a true fact and is stating a false one:\n%s", forbidden)
	}
}

// `06v`: THE PAGE NAMES A ROUTE THAT EXISTS, and it does not invent one.
//
// This is the defect `06v` was filed on, one layer up. The old copy sent the
// operator to "this app's settings" — a place umbrelOS does not have — and §19
// forbids the generic app assuming a deployment-specific path in its place. So
// the location arrives from the GUARD, which gets it from the package, and this
// container renders what it is given.
//
// The negative half is the rule: no umbrelOS path anywhere in the app's own
// source. That is asserted structurally in internal/arch; here we assert the
// positive — that whatever the deployment said reaches the operator's eyes.
func TestThePageNamesTheDeploymentsOwnRouteToTheAuthorisation(t *testing.T) {
	const route = "Files → Apps → brollyzapper → data → guard"
	body := sendingPageWith(t, lnd.BrokerStatus{
		LNDReachable: true, SendingAllowedByDeployment: true,
		AuthorisationPending:  true,
		AuthorisationControl:  "sending",
		AuthorisationChange:   "TURN SENDING ON — let this app make your node pay invoices.",
		AuthorisationLocation: route,
	})

	if !strings.Contains(body, route) {
		t.Errorf("the page does not tell the operator where the guard put the file. They have "+
			"a code form and nowhere to get a code, which is the shape of `06v`:\n%s", body)
	}
	// And the guard's own sentence about the change, so the operator can check
	// the page against the file. The page composes none of it.
	if !strings.Contains(body, "TURN SENDING ON") {
		t.Errorf("the page does not echo what the guard says is being authorised, so an "+
			"operator cannot tell whether the two agree:\n%s", body)
	}
	// THE CODE IS NOT ON THE PAGE, and could not be — but a render is where a
	// future field would show up, so this asserts it directly.
	if strings.Contains(body, "value=\"") && strings.Contains(body, "name=\"code\" value") {
		t.Errorf("the code field is pre-filled; the whole ceremony is that this container "+
			"cannot know the code:\n%s", body)
	}
}

// The guard being DOWN is not the guard REFUSING, and the page must not confuse
// them.
//
// Permitted is false by its zero value, so a page that keyed the banner on it
// alone would print "This install does not permit sending… set
// GUARD_ALLOW_SENDING… restart the app" directly beneath "The guard is not
// answering" — a confident wrong diagnosis sending the operator to edit a
// setting that is fine. The banner is gated on GuardReachable for exactly this,
// and nothing asserted it.
func TestAnUnreachableGuardIsNotReportedAsARefusalToPermitSending(t *testing.T) {
	h := newHarness(t)
	h.broker.SetError(errors.New("dialling /credentials/guard.sock: no such file or directory"))
	cookie := h.login(t)

	body := h.body(t, "/sending", cookie)

	if !strings.Contains(body, "guard is not answering") {
		t.Errorf("the page does not say the guard is down:\n%s", body)
	}
	if strings.Contains(body, "GUARD_ALLOW_SENDING") {
		t.Errorf("the page diagnoses an unreachable guard as an install that does not permit "+
			"sending, and sends the operator to change a setting that is not the problem:\n%s",
			body)
	}
	// And it does not offer the ceremony either, for the same reason: it cannot
	// know whether a code would be needed, or whether the guard could write one.
	if strings.Contains(body, "type it back in") {
		t.Errorf("the page offers the authorisation ceremony with the guard down; the guard "+
			"is the thing that would write the file:\n%s", body)
	}
	// And it offers no button either, because it cannot know whether one would
	// work.
	if strings.Contains(body, "Enable sending") {
		t.Errorf("the page offers Enable sending with the guard down:\n%s", body)
	}
}

// The gate being off does not hide a credential that is still live.
//
// Ruling A.4 leaves an existing spend macaroon alone, so the page has to say the
// residual out loud: authority already minted keeps working until it expires.
func TestTheGatedPageStatesTheResidualWhenACredentialIsStillLive(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, db *store.Store) {
		opts.Settings = db
	})
	h.broker.Answer = lnd.BrokerStatus{
		SpendMacaroonPresent: true,
		SpendRootKeyListed:   true,
		SendingPermitted:     false,
		LNDReachable:         true,
	}
	if err := h.store.SetSetting(t.Context(), "send_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	cookie := h.login(t)

	body := h.body(t, "/sending", cookie)

	if !strings.Contains(body, "until it expires") {
		t.Errorf("a live spend macaroon on a gated install does not state the residual; the "+
			"operator cannot tell that authority already minted keeps working:\n%s", body)
	}
	if !strings.Contains(body, "Revoke now") {
		t.Errorf("the page does not offer the one action that ends the residual now:\n%s", body)
	}
}

func sendingPage(t *testing.T, permitted bool) string {
	t.Helper()
	return sendingPageWith(t, lnd.BrokerStatus{
		SendingPermitted:           permitted,
		SendingLatched:             permitted,
		SendingAllowedByDeployment: true,
		LNDReachable:               true,
	})
}

// sendingPageWith renders the page against one exact guard answer.
//
// `06v` split what used to be one bool into three — the deployment ceiling, the
// operator's latch, and their conjunction — so a helper taking `permitted bool`
// can no longer express the states that matter. Taking the whole status means
// each test says which off-state it is about rather than relying on a mapping in
// here.
func sendingPageWith(t *testing.T, status lnd.BrokerStatus) string {
	t.Helper()
	h := newHarness(t)
	h.broker.Answer = status
	cookie := h.login(t)
	return h.body(t, "/sending", cookie)
}

// The hard cap is stated on the page, from the GUARD's numbers (tna.1).
//
// §6's cap is the one limit a compromised server cannot raise, and an operator
// who cannot see it has to take the manifest's word for it. The numbers come
// from Status rather than from the server's own settings for the same reason
// Permitted does: the server's idea of what it has spent is what a compromised
// server rewrites, and this is the number that will refuse the next payment.
func TestTheSendingPageStatesTheHardCapAndWhatIsSpokenFor(t *testing.T) {
	h := newHarness(t)
	h.broker.Answer = lnd.BrokerStatus{
		LNDReachable:         true,
		SendingPermitted:     true,
		MiddlewareRegistered: true,
		SpendLimitMsat:       100_000_000,
		SpendUsedMsat:        25_000_000,
	}
	// From §11's REPORT, which is where the number lives since tna.2 — one
	// statement, so the Security page and this one cannot disagree.
	h.report.Spend = &preflight.SpendWindow{
		UsedMsat: 25_000_000, LimitMsat: 100_000_000, Period: 24 * time.Hour,
	}
	cookie := h.login(t)

	body := h.body(t, "/sending", cookie)

	for _, want := range []string{"100000.000 sats", "25000.000 sats", "any 24"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not state %q; an operator cannot see the one limit a "+
				"compromised server cannot raise:\n%s", want, body)
		}
	}
}

// With no limit configured the page says nothing rather than claiming a cap of
// zero, which would read as "this app cannot send at all".
func TestTheSendingPageClaimsNoCapWhenNoneIsConfigured(t *testing.T) {
	if body := sendingPage(t, true); strings.Contains(body, "in any 24 hours") {
		t.Errorf("the page states a 24-hour limit with none configured:\n%s", body)
	}
}
