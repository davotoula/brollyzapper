package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// withRequestID gives one public callback request its req_id, on a logger every
// line of that request reaches through logging.FromContext (o34.8).
//
// §12 has had the helper since the foundation wave and nothing called it: the
// LNURL callback — the first leg of a zap, the one a payment hash is born on —
// logged without any request identity at all, so the gate's lines about a
// request could not be joined to the line recording what it minted. OUTERMOST on
// the callback, so the gate's own lines, which are written before any invoice
// exists and so can never carry its hash, carry the id that joins them to the
// mint line that does.
//
// The callback only. The lnurlp document mints nothing and has no hash to join,
// and admin requests are an operator's own clicks.
func withRequestID(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, _ := logging.WithRequestID(r.Context(), log)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type sessionContextKey struct{}

func contextWithSession(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, s)
}

// SessionFrom returns the session RequireSession attached to the request. It is
// present on every admin handler and absent everywhere else.
func SessionFrom(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionContextKey{}).(Session)
	return s, ok
}

type zapContextKey struct{}

// contextWithZap attaches the single parse of a callback's nostr parameter to
// the request, so the handler does not repeat it. The parse is a schnorr
// verification; doing it twice is about a millisecond of a Raspberry Pi's time,
// charged only to honest senders because a forgery dies at the first check
// (n7v).
//
// The type is internal/lnurl's, carried verbatim. An api-side copy would be a
// second statement of "what a parsed nostr parameter is", in the package that
// is least entitled to define it.
func contextWithZap(ctx context.Context, zap lnurl.ZapParam) context.Context {
	return context.WithValue(ctx, zapContextKey{}, zap)
}

// zapFrom returns the parse callbackGate attached. A request that never went
// through the gate yields the zero value, which reads as "no nostr parameter" —
// the safe answer, since it mints a plain invoice with no zap request attached
// rather than one whose signature was never checked.
func zapFrom(ctx context.Context) lnurl.ZapParam {
	zap, _ := ctx.Value(zapContextKey{}).(lnurl.ZapParam)
	return zap
}
