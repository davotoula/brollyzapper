package api

import (
	"context"

	"github.com/davotoula/brollyzapper/internal/lnurl"
)

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
