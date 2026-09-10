package api

import (
	"net/http"
	"time"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/preflight"
	"github.com/davotoula/brollyzapper/internal/web"
)

func (s *Server) node(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data, _, _ := s.page(ctx, "Node")
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
			// TWO FACTS, AND NEITHER IS ENOUGH ALONE (`20i.3`).
			//
			// The guard's kind means "a re-bake would change nothing" — which
			// is equally true of an operator who pressed Re-link twice on a
			// healthy install inside MinBakeInterval, and measuring that was
			// what caught this: a working deployment was being told its address
			// was wrong, with its only recovery button removed, until the next
			// renewal days later.
			//
			// The other half is the node ACTUALLY rejecting the credential,
			// which this guard never observes and the server does. Together
			// they are the condition; apart they are a guess.
			if status.RefusalKind == guard.KindAddressMismatch &&
				view.State == string(lnd.StateRelink) {
				view.MismatchedAddress = status.CredentialAddress
			}
		}
	}
	data.Node = view
	data.Flash = flashFrom(r)
	s.render(w, "node", data)
}

// relink asks the guard for a fresh receive macaroon. §6: the server never
// exits over a rotated macaroon — it shows this state and re-requests a bake.
func (s *Server) relink(w http.ResponseWriter, r *http.Request) {
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
			Title:  c.Title,
			OK:     c.OK,
			Threat: c.Threat,
			Detail: c.Detail,
			Blocks: string(c.Blocks),
		})
	}
	view.BlindSpots = report.BlindSpots
	data.Security = view
	s.render(w, "security", data)
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
