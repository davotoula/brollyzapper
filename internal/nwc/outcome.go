package nwc

import (
	"context"
	"log/slog"
	"time"

	"github.com/davotoula/brollyzapper/internal/logging"
)

// MaxAuditedRefusalsPerHour bounds how many capability refusals reach §12's
// trail in an hour.
//
// bcf's lesson, applied to the other surface a stranger can drive. A paired
// client whose credential was revoked — or one whose operator turned sending off
// — retries, and some wallet apps retry hard: the 0.1.9 trip watched Amethyst
// poll get_info and get_balance eleven times in two idle minutes. The trail is a
// fixed ring (§12 trims to 10 000 rows, oldest first), so an unbounded refusal
// event would let one confused client evict macaroon.bake, guard.reject and
// wallet.shortfall — defeating exactly the durability it was added for.
//
// Twenty, and it is logging.DefaultRefusalsPerHour now rather than a number of
// its own (t0b): an episode's first rows carry the whole story — which
// connection, which method, when it started — and the hundredth adds nothing an
// operator acts on differently. Past the bound the refusal still happens and
// still logs; what it declines to do is spend the trail on repetition.
//
// The expiry condition this used to carry — "this and nostr's are two constants
// with one justification, so if either moves say why" — is discharged: there is
// one constant, and the two writers that had NO bound had none because nothing
// said the rule was general.
const MaxAuditedRefusalsPerHour = logging.DefaultRefusalsPerHour

// MaxAuditedPanicsPerHour bounds how many CONTAINED PANICS reach §12's trail
// (`xmc`). The default, and on its own budget rather than sharing the refusal
// one: a paired client that floods capability refusals must not be able to spend
// the allowance that would have recorded the first panic.
//
// The same number for a much rarer event is deliberate. If this bound is ever
// reached, the story the trail needs to tell is "this started happening", and
// twenty rows tell it.
const MaxAuditedPanicsPerHour = logging.DefaultRefusalsPerHour

// auditWriteTimeout bounds the trail write on the request path.
//
// Generous against a local sqlite write and short against a human. The store
// runs on one connection and the append opens a transaction and trims the ring,
// so a wedged writer must not be able to pin a connection's worker.
const auditWriteTimeout = 5 * time.Second

// reportOutcome says what happened to one NWC request (§12, d24.14).
//
// THE FIVE-PART RULING, in one function, because the alternative is five
// scattered log calls that drift:
//
//  1. A SUCCESSFUL PAYMENT logs at INFO and gets no audit row. Money already has
//     a durable structured record — the txns table — and a second one would be
//     two statements of one fact. That INFO line is payInvoice's, not this
//     function's: the amount, the fee and the hash are in scope there and not
//     here, and the thin "a payment was made" this used to add beside it was a
//     second INFO line per payment carrying nothing an operator could act on.
//  2. A refusal at a CAPABILITY BOUNDARY (RESTRICTED, UNAUTHORIZED) gets an
//     audit event. It means someone used a capability they do not have, nothing
//     durable recorded it before, and "probing a revoked connection leaves no
//     trace" was the sharpest part of the field trip's finding.
//  3. A refusal at a LIMIT (QUOTA_EXCEEDED, INSUFFICIENT_BALANCE) logs at INFO
//     and does not audit. An honest client meeting its own budget is routine,
//     and auditing it would drown (2) in noise.
//  4. The audited refusal is BOUNDED — see MaxAuditedRefusalsPerHour.
//  5. Every other request logs at DEBUG. The trip's eleven idle
//     get_info/get_balance pairs in two minutes must not fill an operator's log
//     at INFO, and §12 is explicit that INFO has to stand alone for diagnosis.
//
// The context is the request's, except for the trail write — see auditRefusal.
func (s *Service) reportOutcome(ctx context.Context, conn *connection, req Request, resp Response) {
	id := conn.row().ID
	if resp.Error == nil {
		// Ruling 1's INFO line is payInvoice's, not this one's: that is where the
		// amount, the fee and the hash are in scope, and a second thin line here
		// saying only "a payment was made" added nothing an operator could act
		// on. Two INFO lines per payment is what the first version shipped.
		s.log.Debug("an NWC request was answered", "connection", id, "method", req.Method)
		return
	}

	switch resp.Error.Code {
	case CodeRestricted, CodeUnauthorized:
		s.auditRefusal(ctx, id, req.Method, resp.Error.Code)
		s.recordRefusal(ctx, id, resp.Error)
	case CodeQuotaExceeded, CodeInsufficientBalance:
		// Ruling 3. INFO, because an operator asking "why did my phone stop
		// paying?" must not need debug mode to find out (§12).
		s.log.Info("an NWC request was refused by a limit", "connection", id,
			"method", req.Method, "code", resp.Error.Code)
		s.recordRefusal(ctx, id, resp.Error)
	case CodePaymentFailed:
		// Money that did not move, which is the same class of question as money
		// that did. Not a capability boundary, so not audited.
		s.log.Info("an NWC payment failed at the node", "connection", id,
			"method", req.Method)
		s.recordRefusal(ctx, id, resp.Error)
	default:
		s.log.Debug("an NWC request was refused", "connection", id,
			"method", req.Method, "code", resp.Error.Code)
	}
}

// recordRefusal remembers, ON THE CONNECTION, the last thing this pairing was
// refused (d24.21, ruling B).
//
// WHY IT IS NOT AN AUDIT ROW: ruling 3 above stands. The trail is about
// capability boundaries, and an honest client meeting its own budget would bury
// them. What ruling 3 assumed is what changed — it took for granted that the
// CLIENT tells the user, and d24.22 measured that false: Amethyst renders
// RESTRICTED and swallows QUOTA_EXCEEDED, so a user whose payment met a cap is
// told nothing and the operator becomes the only possible explainer. Their only
// record was one INFO line in a rotating log, and their only tool was reading
// nwc_handled_requests over SSH.
//
// WHY THESE THREE CASES AND NOT THE DEFAULT ONE: the switch above already draws
// the line this needs. Everything it treats as worth an operator's attention is
// recorded; the default branch is NOT_IMPLEMENTED and OTHER — a client's own
// programming, which cannot answer "what stopped my app" because nobody pressed
// anything. Widening it past ruling B's literal words (a LIMIT refusal) is
// deliberate: the operator's question is "my zap did not work, why", and a page
// that answered it for QUOTA_EXCEEDED and stayed silent for RESTRICTED would
// send them back to SSH for half the cases.
//
// WHY THE MESSAGE AND NOT ONLY THE CODE: one code has six meanings. RESTRICTED
// is emitted for a permission this pairing does not hold, and also for sending
// being off, for no spend credential, for spending being held, and for a Tier-2
// check failing — and on a stock receive-only install the second of those is far
// the most likely. A page that rendered one sentence per code told an operator
// whose sending was simply off that their app had asked for something it is not
// allowed to do, and sent them to permission boxes that were already right. The
// accurate sentence was already composed and already sent to the client (§8's
// ruling 2 differentiates these deliberately); throwing it away here and
// re-deriving a worse one there was the defect (found by review).
//
// Nothing new is disclosed to the paired app by keeping it: this is the message
// that app already received. Ruling 3 — a client must not learn WHICH control
// refused it — is untouched, because this is the operator's page.
//
// The context is the request's rather than a detached one, unlike auditRefusal:
// this is a field on a row and not §12's durable trail, so losing it when the
// request is cancelled costs the operator the newest of a series rather than the
// only copy of a security event.
func (s *Service) recordRefusal(ctx context.Context, id int64, refusal *ResponseError) {
	if err := s.store.RecordNWCRefusal(ctx, id, refusal.Code, refusal.Message, s.now()); err != nil {
		s.log.Debug("could not record a connection's last refusal", "connection", id,
			"error", err.Error())
	}
}

// auditRefusal writes a capability refusal to the trail, or to the log alone
// when this service was built without a sink or the hourly bound is spent.
//
// The context is a BOUNDED Background one, not the request's, and both halves
// are bcf's reasoning: the request is about to end — that is what is being
// recorded — and an audit row lost because the thing it describes finished is
// the failure §12's durability exists to prevent. Bounded, because this runs on
// a connection's worker goroutine.
//
// WHAT IT DOES NOT CARRY: the method's parameters, the invoice, or which check
// failed. §8's ruling 3 stands — a paired app learning which control refused it
// is a paired app being told how to pick the lock — and the trail is readable by
// the same admin UI. The connection, the method and the code are the operator's
// question; the diagnosis is the Security page's.
func (s *Service) auditRefusal(ctx context.Context, connectionID int64, method Method, code string) {
	s.auditBounded(ctx, s.refusals, slog.LevelWarn,
		"an NWC request was refused at a capability boundary",
		logging.EventConnectionRefuse,
		[]any{"connection", connectionID, "method", method, "code", code},
		slog.Int64("connection", connectionID),
		slog.String("method", string(method)),
		slog.String("code", code))
}

// auditBounded writes one event to §12's trail, or to the log alone when this
// service has no sink or the hourly bound is spent.
//
// ONE COPY OF THE DANCE, because there are two callers and they were written
// apart: a capability refusal (d24.14) and a contained panic (`xmc`). Each did
// the same four steps — the nil-sink fallback, the budget, the detached bounded
// context, the Record with an error log — and a change to any of them in one
// copy would have silently left the other behind.
//
// `fallback` is what the log line carries when the row cannot be written. It is
// the caller's own key/value list rather than the attrs, because the two say the
// same thing in the two vocabularies slog and the Auditor use, and building one
// from the other would be a conversion nobody reads.
//
// The context is a BOUNDED Background one, not the caller's: the request being
// described is usually over — that is what is being recorded — and an audit row
// lost because the thing it describes finished is the failure §12's durability
// exists to prevent (bcf).
func (s *Service) auditBounded(ctx context.Context, budget *logging.RefusalBudget,
	level slog.Level, msg string, event logging.Event, fallback []any, attrs ...slog.Attr) {
	if s.audit == nil {
		// A line, and deliberately NO audit= attribute: the Auditor's contract
		// is the line and the row together, so an attribute written by hand
		// would claim a trail entry that does not exist. internal/arch enforces
		// this, and it caught the pool doing it first.
		s.log.Log(ctx, level, msg+"; no audit trail is attached to this service", fallback...)
		return
	}
	// A plain sliding hour rather than a token bucket: the question is "have we
	// already told this story recently", and the answer only has to be right to
	// the nearest burst.
	if record, _ := budget.Allow(); !record {
		// "past the hourly audit bound" verbatim: d24.14's test pins that
		// phrase, and an operator grepping for it after an incident is the
		// reason it is pinned.
		s.log.Log(ctx, level, msg+"; past the hourly audit bound, so this one is logged only",
			fallback...)
		return
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	if err := s.audit.Record(writeCtx, level, msg, event, attrs...); err != nil {
		s.log.Error("could not write the audit trail", "event", event,
			"connection", connectionID(attrs), "error", err.Error())
	}
}

// connectionID digs the connection out of an attribute list for the one log line
// that reports a failed trail write, so that line names the pairing like every
// other line in this package.
func connectionID(attrs []slog.Attr) int64 {
	for _, a := range attrs {
		if a.Key == "connection" {
			return a.Value.Int64()
		}
	}
	return 0
}
