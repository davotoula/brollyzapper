package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/nwc"
	"github.com/davotoula/brollyzapper/internal/preflight"
	"github.com/davotoula/brollyzapper/internal/store"
)

// fakeGuard is the two operations §9 item 3's page drives.
type fakeGuard struct {
	bakeErr   error
	revokeErr error
	baked     int
	revoked   int
	// onBake stands in for what a real bake changes on the other side of the
	// socket: the macaroon appears, so the guard's Status answer changes.
	onBake func()

	// `06v`'s ceremony. applyErr is what the guard says to a change it will not
	// make — a missing or wrong code, most often — and applied records what was
	// actually asked for, because "the server relayed the operator's change
	// unaltered" is the property these handlers exist to have.
	//
	// latched models the guard's own rule that a grant is issued only for a
	// LOOSENING: with the latch already thrown, "turn sending on" is not one, and
	// the real guard refuses to issue a code for it. A fake that always granted
	// would make every enable in this file take the ceremony branch, which is not
	// the state most of these tests are about.
	latched      bool
	authoriseErr error
	applyErr     error
	authorised   []guard.Change
	applied      []appliedChange
}

// appliedChange is one ApplyChange call, code included, so a test can assert
// that what the operator typed reached the guard verbatim.
type appliedChange struct {
	Change guard.Change
	Code   string
}

func (f *fakeGuard) RequestSpendBake(context.Context) error {
	f.baked++
	if f.bakeErr == nil && f.onBake != nil {
		f.onBake()
	}
	return f.bakeErr
}

func (f *fakeGuard) RequestSpendRevoke(context.Context) error {
	f.revoked++
	return f.revokeErr
}

func (f *fakeGuard) RequestAuthorisation(_ context.Context, change guard.Change) error {
	f.authorised = append(f.authorised, change)
	if f.authoriseErr != nil {
		return f.authoriseErr
	}
	if f.latched && change.Control == guard.ControlSending && change.On {
		return errors.New("guard: sending does not need an authorisation; it is not a loosening")
	}
	return nil
}

func (f *fakeGuard) ApplyChange(_ context.Context, change guard.Change, code string) error {
	f.applied = append(f.applied, appliedChange{Change: change, Code: code})
	return f.applyErr
}

// A guard that is not answering must never leave a half-toggled setting.
//
// The ruling's words, and the reason is that §8's ladder reads send_enabled: a
// setting written for a bake that did not happen is a page saying sending is on
// while every payment is refused at step 2. Two answers to one question.
func TestEnablingSendingWhenTheGuardRefusesWritesNothing(t *testing.T) {
	guard := &fakeGuard{latched: true, bakeErr: errors.New("the guard is not answering")}
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.Guard = guard
	})
	cookie := h.login(t)

	rec := h.postForm(t, "/sending/enable", cookie, url.Values{})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /sending/enable = %d, want a redirect", rec.Code)
	}
	if guard.baked != 1 {
		t.Errorf("the guard was asked %d times, want 1", guard.baked)
	}
	value, _, _ := h.store.Setting(t.Context(), nwc.SettingSendEnabled)
	if value == "true" {
		t.Error("sending was recorded as enabled although the bake failed; the page and the " +
			"pay ladder would disagree about whether this node can pay")
	}
}

// The bake happens FIRST and the setting follows, so the two cannot disagree.
func TestEnablingSendingBakesThenRecords(t *testing.T) {
	guard := &fakeGuard{latched: true}
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.Guard = guard
	})
	cookie := h.login(t)

	h.postForm(t, "/sending/enable", cookie, url.Values{})

	if guard.baked != 1 {
		t.Fatalf("the guard baked %d times, want 1", guard.baked)
	}
	if value, _, _ := h.store.Setting(t.Context(), nwc.SettingSendEnabled); value != "true" {
		t.Errorf("send_enabled = %q, want true", value)
	}
	// §12: "when was sending enabled, and by whom" is the question the Security
	// page answers without an SSH session.
	if !h.audited(t, "sending.toggle") {
		t.Error("enabling sending wrote no audit event")
	}
}

// Disabling clears the intent BEFORE revoking, which is the mirror of enabling:
// between the two writes the safe state is "the operator has said no".
func TestDisablingSendingClearsTheIntentEvenIfTheRevokeFails(t *testing.T) {
	guard := &fakeGuard{latched: true, revokeErr: errors.New("the guard is not answering")}
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) {
		opts.Guard = guard
	})
	cookie := h.login(t)
	if err := h.store.SetSetting(t.Context(), nwc.SettingSendEnabled, "true"); err != nil {
		t.Fatal(err)
	}

	h.postForm(t, "/sending/disable", cookie, url.Values{})

	if value, _, _ := h.store.Setting(t.Context(), nwc.SettingSendEnabled); value == "true" {
		t.Error("sending is still recorded as enabled after the operator turned it off")
	}
	if guard.revoked != 1 {
		t.Errorf("the guard was asked to revoke %d times, want 1", guard.revoked)
	}
}

// The page renders §11's Tier-2 rows that block sending — the SAME report the
// ladder consults before every payment (d24.6), so what the operator reads and
// what a wallet app is told cannot disagree.
func TestTheSendingPageShowsWhySendingIsBlocked(t *testing.T) {
	h := newHarness(t)
	h.report = preflight.Report{Checks: []preflight.Check{{
		ID:     preflight.CheckSpendIPMatches,
		Title:  "The spend macaroon is locked to this container",
		OK:     false,
		Detail: "the macaroon is locked to 10.21.0.99 but this container is 10.21.0.17",
		Blocks: preflight.BlocksSending,
	}}}
	body := h.get(t, "/sending", h.login(t)).Body.String()

	if !strings.Contains(body, "The spend macaroon is locked to this container") {
		t.Error("the sending page does not name the check that is blocking payments")
	}
	if !strings.Contains(body, "10.21.0.99") {
		t.Error("the sending page does not carry the row's Detail, which is the operator's " +
			"whole diagnosis (§11 names this text specifically)")
	}
}

// The page an operator lands on after enabling shows the macaroon THEY JUST
// BAKED, not a cached answer from before it existed.
//
// Status is cached for NodeStatusTTL because the Node and Security pages poll
// it, and CachedBroker invalidates on its own receive bake — but the spend half
// goes through Guard, which is the raw socket. So without an explicit
// invalidation the redirect target renders "No spend macaroon is in place, so
// payments are being refused" for up to ten seconds after a bake that worked:
// the most alarming sentence on the page, and false. Found by review.
//
// The harness's clock is fixed, so a cache that is not invalidated never expires
// here — which is what makes this an assertion rather than a race.
func TestThePageShowsTheMacaroonItJustBaked(t *testing.T) {
	h := newHarness(t, func(opts *api.ServerOptions, _ *store.Store) {})
	guard := &fakeGuard{latched: true, onBake: func() {
		h.broker.Answer = lnd.BrokerStatus{SpendMacaroonPresent: true, LNDReachable: true}
	}}
	h.server.Guard = guard
	cookie := h.login(t)
	h.broker.Answer = lnd.BrokerStatus{LNDReachable: true}

	// The login render has already warmed both caches with the state as it was:
	// sending off, no macaroon. That is exactly the operator's situation.
	before := h.get(t, "/sending", cookie)
	if !strings.Contains(before.Body.String(), "Sending is off") {
		t.Fatalf("the page did not start from the off state: %s", before.Body)
	}

	h.postForm(t, "/sending/enable", cookie, url.Values{})

	after := h.get(t, "/sending", cookie).Body.String()
	if !strings.Contains(after, "Sending is on") {
		t.Error("the page an operator lands on after enabling still says sending is OFF; the " +
			"toggle reads as having failed, and the obvious next move is to press it again")
	}
	if strings.Contains(after, "No spend macaroon is in place") {
		t.Error("after a bake that worked, the page still says no spend macaroon is in place — " +
			"the operator is told payments are being refused at the moment they enabled them")
	}
	if !strings.Contains(after, "A spend macaroon is in place") {
		t.Errorf("the page does not report the macaroon: %s", after)
	}
}
