package api

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/davotoula/brollyzapper/internal/guard"

	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nwc"
	"github.com/davotoula/brollyzapper/internal/preflight"
	"github.com/davotoula/brollyzapper/internal/web"
)

func (s *Server) sendingPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data, values, _ := s.page(ctx, "Sending")
	view := web.SendingView{
		Enabled: values.get(nwc.SettingSendEnabled) == "true",
		// §9's required sentence, carried on the view so a test can assert the
		// page renders exactly it rather than something like it.
		ResidualRisk: web.ResidualRisk,
	}

	if s.Broker != nil {
		status, err := s.Broker.Status(ctx)
		if err != nil {
			// An honest state, not a broken page: the guard being down is a
			// thing that happens, and the page's job is to say so rather than
			// to offer a button that cannot work (§11).
			//
			// NOT "nothing has changed" — this render also follows a POST that
			// failed at the guard, and after a failed revoke something HAS
			// changed: sending is off and the macaroon is still live. The flash
			// says what happened; this says what is possible now (found by
			// review, which caught the page telling the operator otherwise).
			data.Error = "The guard is not answering, so sending cannot be enabled or revoked " +
				"right now."
			s.Log.Warn("the guard did not answer the sending page", "error", err.Error())
		} else {
			view.GuardReachable = true
			view.Ready = status.SpendMacaroonPresent
			view.Expiry = status.SpendExpiry
			// FROM THE GUARD, which is the only thing that knows what the guard
			// will do (tna.4). Reading a copy of the flag from this container's
			// own environment would let the page offer a button the guard
			// refuses.
			view.Permitted = status.SendingPermitted
			view.AllowedByDeployment = status.SendingAllowedByDeployment
			view.SpendCapMsat = status.SpendLimitMsat
			view.PaymentCapMsat = status.MaxPaymentMsat
			// The pending ceremony, echoed from the guard's own words (`06v`).
			// Nothing here is composed by this container, and the CODE is not
			// among it — the server relays one it cannot read.
			view.Authorisation = web.AuthorisationView{
				Pending:   status.AuthorisationPending,
				Change:    status.AuthorisationChange,
				ExpiresAt: status.AuthorisationExpiresAt,
				// How long is LEFT, beside the instant it dies (BrollyZap-5z4).
				// The instant alone made the operator work out their offset from
				// UTC and subtract, inside a ten-minute window, on a phone.
				MinutesLeftAtRender: minutesUntil(status.AuthorisationExpiresAt, s.Now()),
				Control:             status.AuthorisationControl,
				Msat:                status.AuthorisationMsat,
				Location:            status.AuthorisationLocation,
			}
		}
	}

	// §11's Tier-2 rows that take sending away, in the operator's words. This is
	// the same report the ladder consults before every payment (d24.6), so what
	// the page says and what a wallet app is told cannot disagree.
	if s.Preflight != nil {
		report := s.Preflight(ctx)
		for _, check := range report.BlockedBy(preflight.BlocksSending) {
			view.Blocked = append(view.Blocked,
				web.SendingCheck{Title: check.Title, Detail: check.Detail})
		}
		// §6's hard cap, from §11's REPORT rather than read out of Status a
		// second time (tna.2). Displayed, never consulted: this page is in the
		// container the cap exists to bound, and one statement of the number
		// means the Security page and this one cannot come to disagree.
		//
		// ABSENT means absent: on a receive-only install the report carries no
		// window, and the page says nothing rather than "0 of 0".
		view.SpendWindowView = spendWindowView(report.Spend)
	}
	if s.Connections != nil {
		if n, err := s.Connections.CountPayingNWCConnections(ctx); err == nil {
			view.PayingConnections = n
		}
	}

	data.Sending = view
	data.Flash = flashFrom(r)
	s.render(w, "sending", data)
}

// moveGuardControl is the ceremony, said ONCE, for every control that has one.
//
// It was said twice — an explicit "ask for a code" route for sending, and an
// implicit ask-then-fall-through for the caps — which meant the ceremony's shape
// lived in two structures and any change to it had to be made in both. Two
// independent reviews found the same thing. This is that shape:
//
//  1. NO CODE TYPED: ask the guard for one. If this change is a loosening the
//     guard writes a grant into a volume this container has no mount for, and
//     the operator is sent to read it. If it is NOT a loosening the guard
//     refuses to issue a grant nothing needs, and we fall through — which is
//     what makes a tightening one click.
//  2. APPLY, relaying whatever the operator typed.
//  3. `then` is what this particular control does afterwards, and is the only
//     thing that differs between callers.
//
// THE SERVER DECIDES NOTHING HERE. It does not judge the direction, and it does
// not decide whether a code is needed — it offers what it has and takes the
// answer. Deciding either would be a compromised server deciding, and every one
// of its own changes would be a tightening (`06v`, Ruling 1).
//
// r.PostFormValue, not a fresh parse: the admin group's CSRF gate has already
// read this body under MaxFormBytes, and a second read here would be reading
// whatever the caller sent (see readForm).
// then always answers the request itself, so it returns nothing. It used to
// return a bool that no caller ever varied and that nothing acted on: this
// function ends immediately after calling it either way, so a `true` would have
// meant "carry on" to a function with nothing left to do — leaving the operator
// a blank 200. A contract nothing can enforce is better not stated.
func (s *Server) moveGuardControl(w http.ResponseWriter, r *http.Request, change guard.Change,
	then func(ctx context.Context)) {
	ctx := r.Context()
	if s.Guard == nil {
		http.Redirect(w, r, "/sending?flash=refused", http.StatusSeeOther)
		return
	}
	code := r.PostFormValue("code")
	if code == "" {
		if err := s.Guard.RequestAuthorisation(ctx, change); err == nil {
			s.forgetBrokerStatus()
			http.Redirect(w, r, "/sending?flash=authorisation_written", http.StatusSeeOther)
			return
		}
	}
	if err := s.Guard.ApplyChange(ctx, change, code); err != nil {
		// THE GUARD'S REASON GOES TO THE LOG AND THE TRAIL, NOT THE URL.
		//
		// It used to be relayed to the page as `?reason=<the guard's text>`, and
		// that was wrong twice over. It put untested operator-facing copy inside
		// fmt.Errorf calls — one of which renders msat on a page §9 says shows
		// sats — and, worse, it made the ceremony's own screen render arbitrary
		// text from a URL parameter, right beside the box asking for a code. A
		// page whose entire premise is "believe the file, not this page" must not
		// be the easiest place in the app to put words in front of an operator.
		//
		// Nothing is lost: of the four ways a code fails — wrong, expired,
		// already used, issued for something else — three have the same next
		// step, and the flash says it. The specific reason is in the guard's log
		// and in the durable trail, where an operator looking for it can find it
		// and an attacker cannot put it. Found by review.
		s.Log.Warn("the guard would not move an operator control",
			"control", string(change.Control), "error", err.Error())
		http.Redirect(w, r, "/sending?flash=code_refused", http.StatusSeeOther)
		return
	}
	s.forgetBrokerStatus()
	then(ctx)
}

// enableSending performs the ceremony, bakes the spend macaroon and records the
// intent.
//
// THE ORDER IS THE POINT: latch, then bake, then setting. A bake attempted
// before the latch is one the guard refuses anyway, and the error it returns
// would be the wrong one to show. A setting written for a bake that did not
// happen is a page that says sending is on while §8's ladder refuses every
// payment at step 2 — two answers to one question, which is the state this app
// spends most of its design avoiding.
func (s *Server) enableSending(w http.ResponseWriter, r *http.Request) {
	s.moveGuardControl(w, r, guard.Change{Control: guard.ControlSending, On: true},
		func(ctx context.Context) {
			if err := s.Guard.RequestSpendBake(ctx); err != nil {
				s.Log.Error("the guard refused to bake the spend macaroon", "error", err.Error())
				http.Redirect(w, r, "/sending?flash=bake_failed", http.StatusSeeOther)
				return
			}
			s.forgetBrokerStatus()
			if err := s.Settings.SetSetting(ctx, nwc.SettingSendEnabled, "true"); err != nil {
				// The macaroon exists and the intent did not land. Reported
				// rather than swallowed, and NOT rolled back: revoking here would
				// churn a root key on a database error, and the honest state is a
				// page that shows a credential present with sending off — which
				// is what the operator sees.
				s.Log.Error("sending was baked but the setting could not be written",
					"error", err.Error())
				http.Redirect(w, r, "/sending?flash=refused", http.StatusSeeOther)
				return
			}
			s.settings.invalidate()
			s.auditRequest(r, slog.LevelWarn, "sending was enabled", logging.EventSendingToggle,
				slog.Bool("enabled", true))
			// The capability changed, so every connection's info event is now
			// wrong (§8): a wallet app holding the pay group should see a pay
			// button appear.
			nudge(s.NWCDemand)
			http.Redirect(w, r, "/sending?flash=enabled", http.StatusSeeOther)
		})
}

// capControls are the two controls THIS route may move, and it is not
// guard.Controls.
//
// THE FULL LIST WAS A DEFECT. Validating against every control the guard has
// meant a POST here with `control=sending` was accepted and built
// `Change{Control: sending, On: false}` — a tightening the guard duly applies,
// dropping the latch WITHOUT this app clearing send_enabled and WITHOUT revoking
// the macaroon. The result is the exact state the whole design avoids: the page
// says sending is on, the guard says it is off, and a live credential sits
// between them. Found by review.
//
// The generic validator meeting a special-cased handler is the shape to
// remember: a closed set is only closed at the point that uses it.
var capControls = []guard.Control{guard.ControlSpendCap, guard.ControlPaymentCap}

// changeSpendCap moves one of §6's two caps.
//
// LOWERING IS PLAIN AND RAISING NEEDS THE CEREMONY, and this handler does not
// know which is which — it passes the number and whatever code the operator
// typed, and the guard decides. That is Ruling 1's whole point: the direction is
// exactly what a compromised server would lie about, so the container that could
// lie is not asked.
//
// THE CAPS ARE THE LARGER EXPOSURE, not the boolean (`06v`). Once sending has
// been enabled once, a compromised server can already read spend.macaroon and
// dial LND directly; what contains it is the caveat and the middleware, which is
// enforcement rather than secrecy. So a control that let the server raise its
// own ceiling would harm every sending install, while the sending latch only
// ever protects one that never enabled sending.
func (s *Server) changeSpendCap(w http.ResponseWriter, r *http.Request) {
	control := guard.Control(r.PostFormValue("control"))
	if !slices.Contains(capControls, control) {
		http.Redirect(w, r, "/sending?flash=refused", http.StatusSeeOther)
		return
	}
	// SATS IN THE FORM, MSAT IN THE MODEL. §9 renders amounts as whole sats and
	// §4 stores msat; an operator typing "50000" into a box labelled sats must
	// not set a cap of fifty thousand MILLISATS, which is fifty sats and would
	// refuse every payment they make.
	//
	// maxLimitSats, which is the connections form's bound, for the reason stated
	// beside it: ParseInt accepts up to 9.2e18 and `* 1000` on that WRAPS. A
	// wrapped cap is not merely wrong, it is wrong with no ceremony —
	// 18446744073709552 sats becomes 384 msat, a number the guard reads as a
	// tightening while the operator asked for the opposite. Neither Change.valid
	// nor checkCapPair can catch it, because by then it is small and positive.
	// Found by review.
	//
	// ZERO IS ACCEPTED HERE and rejected by limitMsat, which is why this does not
	// simply call it: a per-connection budget of zero means "no budget given",
	// and a guard cap of zero means "refuse every payment", which is a thing an
	// operator may deliberately set.
	sats, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("sats")), 10, 64)
	if err != nil || sats < 0 || sats > maxLimitSats {
		http.Redirect(w, r, "/sending?flash=cap_invalid", http.StatusSeeOther)
		return
	}
	change := guard.Change{Control: control, Msat: sats * 1000}
	s.moveGuardControl(w, r, change, func(context.Context) {
		s.auditRequest(r, slog.LevelWarn, "a guard spend limit was changed",
			logging.EventSendingToggle, slog.String("control", string(control)),
			slog.Int64("msat", change.Msat))
		http.Redirect(w, r, "/sending?flash=cap_changed", http.StatusSeeOther)
	})
}

// disableSending revokes the spend macaroon node-side and clears the intent.
//
// The setting is cleared FIRST here, which is the mirror of enabling and for the
// same reason: between the two writes the safe state is "the operator has said
// no". If the revoke then fails, the ladder is already refusing while the
// operator retries — rather than a live credential with the page claiming
// sending is off.
func (s *Server) disableSending(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.Settings.SetSetting(ctx, nwc.SettingSendEnabled, "false"); err != nil {
		s.Log.Error("sending could not be disabled", "error", err.Error())
		http.Redirect(w, r, "/sending?flash=refused", http.StatusSeeOther)
		return
	}
	s.settings.invalidate()
	nudge(s.NWCDemand)
	if s.Guard == nil {
		http.Redirect(w, r, "/sending?flash=disabled", http.StatusSeeOther)
		return
	}
	// THE LATCH FIRST, and it needs no code: turning sending off is a tightening
	// (`06v`, Ruling 1). It is a separate call from the revoke because the two
	// can fail independently — RevokeSpend drops the latch itself on the path
	// that succeeds, and this is what makes the intent stick when the node-side
	// half is the part that fails.
	if err := s.Guard.ApplyChange(ctx, guard.Change{Control: guard.ControlSending}, ""); err != nil {
		s.Log.Error("the guard would not record that sending is off", "error", err.Error())
	}
	if err := s.Guard.RequestSpendRevoke(ctx); err != nil {
		// Sending is already off as far as this app is concerned; what failed is
		// taking the credential back node-side, which is the half that matters
		// if the server is the thing compromised. Said plainly.
		s.Log.Error("the guard could not revoke the spend macaroon", "error", err.Error())
		s.auditRequest(r, slog.LevelWarn, "sending was disabled but the macaroon was not revoked",
			logging.EventSendingToggle, slog.Bool("enabled", false), slog.Bool("revoked", false))
		http.Redirect(w, r, "/sending?flash=revoke_failed", http.StatusSeeOther)
		return
	}
	s.forgetBrokerStatus()
	s.auditRequest(r, slog.LevelWarn, "sending was disabled", logging.EventSendingToggle,
		slog.Bool("enabled", false), slog.Bool("revoked", true))
	http.Redirect(w, r, "/sending?flash=disabled", http.StatusSeeOther)
}

// Both handlers also invalidate the SETTINGS snapshot, for the same reason and
// the same failure: it is cached with a TTL, so without this the page the
// operator is redirected to still says "Sending is off" immediately after they
// turned it on — the toggle looks like it did not work, and the obvious next
// move is to press it again. saveSettings has always invalidated; these two
// arrived without it (found by review's test, which caught both caches at once).

// forgetBrokerStatus drops the cached guard status after this page has changed
// what that status would say.
//
// Status is cached for NodeStatusTTL (ten seconds) because the Node and Security
// pages poll it, and CachedBroker already invalidates on its own receive bake.
// The spend half goes through Guard, which is the raw socket — so without this
// the page an operator is redirected to STILL renders "no spend macaroon is in
// place" for up to ten seconds after a bake that worked, which is the most
// alarming sentence on the page and it would be false. Found by review.
func (s *Server) forgetBrokerStatus() {
	if s.Broker != nil {
		s.Broker.Invalidate()
	}
}

// minutesUntil is how many whole minutes remain, ROUNDED UP, or zero once the
// deadline has passed.
//
// Up, because down is the dangerous direction here: a code with twenty seconds
// left would report "0 minutes", which reads as already dead on one that still
// works, and an operator who believes it stops typing. Zero is reserved for
// "gone", where the page then says nothing relative at all and the absolute
// instant speaks for itself.
func minutesUntil(deadline, now time.Time) int {
	left := deadline.Sub(now)
	if left <= 0 {
		return 0
	}
	return int((left + time.Minute - 1) / time.Minute)
}
