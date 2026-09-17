package api

import (
	"net/http"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/preflight"
	"github.com/davotoula/brollyzapper/internal/web"
)

func (s *Server) node(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data, _, report := s.page(ctx, "Node")
	view := web.NodeView{State: "unknown"}
	if s.NodeState != nil {
		view.State = string(s.NodeState())
	}
	if s.Broker != nil {
		status, err := s.Broker.Status(ctx)
		if err != nil {
			view.GuardError = "the guard is not answering on its socket"
		} else {
			view.GuardReachable = true
			view.LNDReachable = status.LNDReachable
			view.ReceiveMacaroonPresent = status.ReceiveMacaroonPresent
			view.SpendMacaroonPresent = status.SpendMacaroonPresent
			view.ReceiveExpiry = status.ReceiveExpiry
			view.NodeStage = nodeStage(status.NodeWalletState)
		}
	}
	// FROM THE REPORT, NOT COMPUTED HERE (`20i.11`). This page used to hold the
	// address verdict itself, so the Security panel could only point at it;
	// preflight's credential-address check now computes it once, from both
	// halves, for both pages — and the handler below asks the same one. The
	// address is set exactly when that check blocks re-linking, so it is the
	// verdict as well as the value.
	view.MismatchedAddress = report.MismatchedAddress
	// The same rule for as0.10's finding: the verdict the Security panel renders.
	view.AdminMacaroonRejected = report.AdminMacaroonRejected
	// The server's own credential, from the same report the Security panel
	// renders its check from (`20i.21`) — a cached answer with its time. A render
	// may START a probe when one is due; it never waits on the node.
	if probe := report.ServerCredential; probe != nil {
		view.ServerCheckedAt = probe.At
		view.ServerReachable = !probe.At.IsZero() && probe.Err == nil
	}
	data.Node = view
	data.Flash = flashFrom(r)
	s.render(w, "node", data)
}

// nodeStage turns the stage the node reported into the Node page's token, so the
// template holds wording and nothing about LND's names (dqd). UNLOCKED and
// WAITING_TO_START are one sentence to an operator: the node is not up yet.
// Every other value — an active stage, one this build does not know, or none —
// explains nothing and is empty.
func nodeStage(state lnd.WalletState) string {
	switch state {
	case lnd.WalletLocked:
		return "locked"
	case lnd.WalletUnlocked, lnd.WalletWaitingToStart:
		return "starting"
	case lnd.WalletNonExisting:
		return "no_wallet"
	default:
		return ""
	}
}

// relink asks the guard for a fresh receive macaroon. §6: the server never
// exits over a rotated macaroon — it shows this state and re-requests a bake.
func (s *Server) relink(w http.ResponseWriter, r *http.Request) {
	// THE HANDLER ASKS, NOT ONLY THE TEMPLATE (`20i.11`). Hiding the button left
	// this route mounted, so the refusal lived in HTML and a replayed or scripted
	// POST was honoured — a bake the guard declines anyway, a reconnect retry for
	// a credential that did not change, and a "saved" flash for nothing.
	if s.checks(r.Context()).Blocked(preflight.BlocksRelink) {
		http.Redirect(w, r, "/node?flash=relink_blocked", http.StatusSeeOther)
		return
	}
	if s.Broker != nil {
		if err := s.Broker.RequestReceiveBake(r.Context()); err != nil {
			s.Log.Warn("re-link failed", "error", err.Error())
			http.Redirect(w, r, "/node?flash=refused", http.StatusSeeOther)
			return
		}
	}
	// The credential is new; the reconnect loop may be part-way through a
	// backoff of up to a minute. Waiting it out makes a successful repair look
	// like a failed one (d46.20).
	s.retryNow()
	http.Redirect(w, r, "/node?flash=saved", http.StatusSeeOther)
}

func (s *Server) security(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data, _, report := s.page(ctx, "Security")
	events, err := s.Audit.AuditEvents(ctx, 200)
	if err != nil {
		data.Error = "The security trail could not be read."
		s.Log.Error("reading audit events", "error", err.Error())
	}
	view := web.SecurityView{}
	// The BURST comes from the report, which counts it in SQL over a stated
	// window (tna.2). It used to be counted here, over whatever happened to be
	// in the last 200 rows — which is not a rate, and which silently truncated
	// exactly the case the banner exists for.
	if report.Rejections != nil {
		view.GuardRejections = report.Rejections.Count
		view.RejectionWindowHours = int(report.Rejections.Within / time.Hour)
	}
	// The measurement, beside the verdicts (Ruling A). Absent when sending is
	// off, and absent means the paragraph does not render at all.
	view.SpendWindowView = spendWindowView(report.Spend)
	for _, e := range events {
		view.Events = append(view.Events, web.AuditRow{
			When:     e.CreatedAt.Format(time.RFC3339),
			Event:    string(e.Event),
			Severity: e.Severity,
			Detail:   e.Detail,
			Remote:   e.Remote,
		})
	}
	for _, c := range report.Checks {
		view.Checks = append(view.Checks, web.CheckRow{
			Title:   c.Title,
			Verdict: verdict(c.State),
			Threat:  c.Threat,
			Detail:  c.Detail,
			Blocks:  string(c.Blocks),
		})
	}
	view.BlindSpots = report.BlindSpots
	data.Security = view
	s.render(w, "security", data)
}

// verdict maps preflight's state onto the page's word for it (as0.11). The only
// mapping: internal/web imports nothing of the app's, so the page states the
// three itself and this is where the two statements meet. An unknown state is
// not checked, never a pass.
func verdict(state preflight.State) web.Verdict {
	switch state {
	case preflight.Pass:
		return web.VerdictPass
	case preflight.Fail:
		return web.VerdictFail
	}
	return web.VerdictNotChecked
}

// spendWindowView maps §11's window onto the shape both pages render.
//
// The mapping was written out by the Sending and Security handlers separately,
// identically. ABSENT means absent: a nil window yields the zero value, and
// both templates then render nothing rather than "0 of 0" — which is what a
// receive-only install, the default, must show.
func spendWindowView(w *preflight.SpendWindow) web.SpendWindowView {
	if w == nil {
		return web.SpendWindowView{}
	}
	return web.SpendWindowView{
		SpendUsedMsat:    w.UsedMsat,
		SpendLimitMsat:   w.LimitMsat,
		SpendWindowHours: int(w.Period / time.Hour),
	}
}
