package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/davotoula/brollyzapper/internal/lnurl"
)

// LNURLRoutes supplies the public group's two endpoints.
//
// A pair, not a mux: see LNURLHandlers.
type LNURLRoutes interface {
	Handlers() (payRequest, callback http.Handler)
}

// lnurlRoutes adapts a pair of handlers to LNURLRoutes.
type lnurlRoutes struct{ payRequest, callback http.Handler }

func (r lnurlRoutes) Handlers() (http.Handler, http.Handler) { return r.payRequest, r.callback }

// NewLNURLRoutes wires the service into the two public endpoints.
func NewLNURLRoutes(service LNURL, log *slog.Logger) LNURLRoutes {
	payRequest, callback := LNURLHandlers(service, log)
	return lnurlRoutes{payRequest: payRequest, callback: callback}
}

// unavailableLNURL answers both endpoints with a reason, for a build or a
// configuration in which zap receiving is not wired. The routes exist either
// way, because the public route set is a security boundary and must not change
// shape between builds.
func unavailableLNURL(what string) LNURLRoutes {
	handler := notYetHandler(what)
	return lnurlRoutes{payRequest: handler, callback: handler}
}

// LNURL is the slice of the LNURL service this layer needs. Declared by the
// consumer: internal/lnurl holds the protocol and cannot import net/http (§3),
// and this file holds the HTTP and knows nothing about description_hash.
type LNURL interface {
	PayRequest(ctx context.Context, name string) (lnurl.PayResponse, error)
	Callback(ctx context.Context, name string, query url.Values,
		zap lnurl.ZapParam) (lnurl.CallbackResponse, error)
}

// LNURLHandlers returns §7's two public endpoints, separately.
//
// Separately, and NOT behind an http.ServeMux of their own: §11 introduced
// api.Routes precisely because "the standard mux cannot be asked which patterns
// it holds", and a mux hidden behind a prefix registration would put routes on
// the public surface that the route-set equality assertion cannot see. The
// caller registers these on the public Routes, where they are counted.
//
// Both are GETs that read ONLY the query string. Never r.ParseForm: that merges
// a request body into the same map, so a POST body could shadow the `nostr`
// parameter whose bytes description_hash covers — and it is the query the
// signature was computed over.
func LNURLHandlers(service LNURL, log *slog.Logger) (payRequest, callback http.Handler) {
	// The address document. It is registered behind NO rate limiter (§7, ruled
	// 22 Aug 2026) and §9's self-probe depends on that staying true: the probe
	// fetches this path over the public internet, so a bucket it shared with
	// strangers could be drained to make the Security page report the
	// operator's own address unreachable. Do not "tidy up" by wrapping this the
	// way the callback is wrapped — see NewServer for the whole reasoning,
	// including why a bypass keyed on the probe token is not the answer.
	payRequest = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answer(w, r, log, func() (any, error) {
			document, err := service.PayRequest(r.Context(), r.PathValue("name"))
			if err == nil {
				// STAGE A, made visible (`q22`). A successful fetch used to
				// leave no trace at all, so "that wallet never reached us" and
				// "that wallet read our document and refused it" looked
				// identical from the log — and they point at completely
				// different places.
				//
				// DEBUG, and this is not a preference: §7 leaves this endpoint
				// behind NO rate limiter on purpose, so an INFO line here would
				// be a log-flood vector by construction. An operator turns DEBUG
				// on for the length of an investigation.
				log.Debug("served the lightning address document",
					"name", r.PathValue("name"), "user_agent", userAgent(r))
			}
			return document, err
		})
	})
	callback = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The ONE public response that must not be cached. The lnurlp document
		// is static and wants caching; this returns a single-use bolt11, and an
		// intermediary that served it twice would hand two payers one invoice —
		// LND settles a payment hash once, so the second payment is gone with
		// nothing recorded.
		w.Header().Set("Cache-Control", "no-store")
		answer(w, r, log, func() (any, error) {
			// The parse callbackGate already did. Repeating it here would
			// verify the same signature a second time, and — worse — would
			// hash bytes re-read from the query rather than the bytes whose
			// signature was checked.
			return service.Callback(r.Context(), r.PathValue("name"), r.URL.Query(),
				zapFrom(r.Context()))
		})
	})
	return payRequest, callback
}

// answer renders one endpoint's outcome.
//
// LNURL has no error status codes: a wallet reads {"status":"ERROR","reason"}
// out of a 200. The exception is an unknown name, which §7 makes a plain 404
// with no hint — a probe must not learn which addresses exist here.
func answer(w http.ResponseWriter, r *http.Request, log *slog.Logger, run func() (any, error)) {
	w.Header().Set("Content-Type", "application/json")
	body, err := run()
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, body)
	case errors.Is(err, lnurl.ErrUnknownAddress), errors.Is(err, lnurl.ErrNotConfigured):
		http.NotFound(w, r)
	default:
		reason, showable := lnurl.AsRejection(err)
		if showable {
			// STAGE B, made visible (`q22`). This branch told the STRANGER why
			// and told the operator nothing — the wallet author learns which of
			// Appendix D's rules it broke and the person running the node does
			// not. The Reason already names the rule; lnurl.reject formats it
			// in.
			//
			// The AMOUNT and not the query: `nostr` carries a stranger's signed
			// event, up to MaxZapRequestBytes, and the reason is what diagnoses
			// this. DEBUG for the same reason as the document above.
			log.Debug("refused an LNURL request", "reason", reason,
				"name", r.PathValue("name"), "amount", r.URL.Query().Get("amount"),
				"user_agent", userAgent(r))
		} else {
			// Ours, not theirs. The caller learns that it failed, never why:
			// what LND said about this node is not a stranger's business.
			//
			// STILL A WARN, and the two branches stay side by side rather than
			// one returning early: the first version of this change put a
			// `break` in here, which in a switch skips the write below — so the
			// caller got an empty body. The existing line and the new one are
			// two arms of one decision, and the response is written once after
			// both.
			reason = "the invoice could not be created"
			log.Warn("the LNURL callback failed", "error", err.Error())
		}
		writeLNURLError(w, http.StatusOK, reason)
	}
}

// userAgent is what the caller SAYS it is, truncated.
//
// A CLAIM AND NOT A FACT, which is why it is logged under its own name rather
// than turned into a verdict: anything can send anything here. It is here
// because "which wallet was this?" is the first question asked of this log, and
// because §9's self-probe fetches the document endpoint over the public internet
// — so the operator's own traffic appears alongside strangers', and the probe
// names itself here to make that separable. Neither answer is proof.
//
// Truncated because it is a stranger's string in a log line.
func userAgent(r *http.Request) string {
	const most = 80
	agent := r.Header.Get("User-Agent")
	if len(agent) > most {
		return agent[:most] + "…"
	}
	return agent
}

// writeLNURLError is the LNURL error envelope, in one place.
//
// The status is a parameter because the two callers legitimately differ: a
// protocol-level rejection rides inside a 200 (LUD-06 has no error codes and a
// wallet reads the body), while a rate-limited callback answers 429 so that
// anything reading status codes is told the truth as well.
func writeLNURLError(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, status, map[string]string{"status": "ERROR", "reason": reason})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
