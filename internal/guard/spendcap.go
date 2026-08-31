package guard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc/routerrpc"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/secret"
)

// SpendWindow is the period the hard cap is measured over (§6): a ROLLING 24
// hours, not a calendar day. A daily reset would hand a compromised server two
// full caps back to back by waiting for midnight.
const SpendWindow = 24 * time.Hour

// MaxWindowAttempts bounds the per-attempt records the window is computed from.
//
// THE BOUND REJECTS; IT DOES NOT EVICT. Every other ring in this codebase drops
// its oldest entry, and here that would be a security hole rather than a lost
// log line: an evicted record leaves its amount out of the sum, so the window
// under-counts and the cap silently rises. A cap that forgets is not a cap. At
// the bound the guard refuses the attempt instead, which is the fail-closed
// direction.
//
// ITS EXPIRY CONDITION, which is what makes rejecting acceptable: records leave
// by AGE, not by count, so the bound is only reached by more than
// MaxWindowAttempts payment attempts inside one rolling 24 hours. At §6's
// default per-payment cap that is orders of magnitude more spending than the
// amount cap allows, so an install that meets it is either paying dust in a
// loop or is the compromised server this whole mechanism is for. Both are
// states to stop, and both clear themselves as the oldest records age out.
const MaxWindowAttempts = 5000

// SpendAttempt is one intercepted payment, recorded before LND is allowed to
// act on it.
type SpendAttempt struct {
	// Key identifies the attempt so a terminal failure can find its record.
	//
	// The middleware's request id identifies a call only within one middleware
	// STREAM — LND numbers them from a counter built at its own startup — so it
	// is namespaced by that stream's session AND by a per-guard-run nonce.
	//
	// Both restarts therefore make older records undecrementable, which is
	// Ruling 2 falling out of the data model rather than being remembered: a
	// payment the guard has stopped watching counts as spent. Without the
	// session half, an LND restart makes the ids begin again at 1 and a cheap
	// failing payment returns whatever large record happened to share its id.
	Key  string    `json:"key"`
	At   time.Time `json:"at"`
	Msat int64     `json:"msat"`
}

// spendWindowUsed is what the window holds, and the pruning that defines it.
//
// Pruning by age is NOT the eviction MaxWindowAttempts refuses to do: a record
// older than the window is outside the question being asked, while a record
// inside it is part of the answer.
func spendWindowUsed(attempts []SpendAttempt, now time.Time) (int64, []SpendAttempt) {
	cutoff := now.Add(-SpendWindow)
	kept := make([]SpendAttempt, 0, len(attempts))
	var used int64
	for _, attempt := range attempts {
		if attempt.At.After(cutoff) {
			kept = append(kept, attempt)
			used += attempt.Msat
		}
	}
	return used, kept
}

// errSpendRefused prefixes every refusal.
//
// UNEXPORTED, because it is a string and not a sentinel: the error crosses a
// gRPC boundary on its way to the caller, so nothing on the other side can ever
// errors.Is it. What survives is the TEXT, which is why the text names the
// limit and the setting — §8's payment path carries it to a wallet app, and a
// person reads it.
var errSpendRefused = errors.New("brollyzapper guard")

// InterceptRequest is the hard cap, enforced inside LND's request path.
//
// This is the whole of `tna.1`'s security claim, and the claim is about WHERE
// it runs rather than what it computes. The server checks its own ceiling
// before it ever calls SendPaymentV2 (§5), but a compromised server simply does
// not run that check — it holds the spend macaroon and can call the RPC
// directly. This code runs in the guard, on a limit read from the GUARD's
// environment, in a container the server cannot write to, and LND will not
// perform the RPC until it answers.
//
// ONLY SendPaymentV2 is priced. The spend macaroon grants three methods and the
// other two move no money — TrackPaymentV2 reads a payment already made and
// DecodePayReq is a pure function of its argument. Anything else carrying this
// caveat is allowed through: refusing unknown methods would make the middleware
// a second permission list, silently diverging from SpendPermissions, which is
// the drift §6 spent d46.26 removing.
func (g *Guard) InterceptRequest(ctx context.Context, in lnd.Interception) error {
	if in.MethodURI != SendPaymentMethod {
		return nil
	}
	var request routerrpc.SendPaymentRequest
	if err := proto.Unmarshal(in.Serialized, &request); err != nil {
		// FAIL CLOSED. A payment request this build cannot read is a payment it
		// cannot price, and letting it through would be the one case where the
		// cap does not apply — reachable by a compromised server simply sending
		// a message shaped to defeat the parser.
		return g.refuseSpend(ctx, in, "the guard could not read the payment request", 0)
	}
	// The round trip to the node happens HERE, before any lock is taken. §6's
	// stateStore holds its mutex across the whole read-modify-write, and a
	// network call inside that is how the guard deadlocks against a slow node.
	cost, err := g.priceAttempt(ctx, &request)
	if err != nil {
		return g.refuseSpend(ctx, in, err.Error(), 0)
	}
	// NO `> 0` GUARD, and that is deliberate. A cap of zero used to mean "no
	// cap", which is the worst possible reading of a security limit set to
	// zero: an operator who types 0 into an app setting called "maximum spend"
	// means "do not spend", and would have got "spend anything". Both
	// deployments set real defaults (`umbrel/…/docker-compose.yml`,
	// `regtest/docker-compose.yml`), so zero is always something a person chose
	// on purpose, and the only safe thing to do with it is refuse.
	// One state write decides and records together. Reading the window, then
	// deciding, then recording, would let two concurrent attempts both pass a
	// cap only one fits under — the lost update stateStore.update exists to
	// prevent, and the one that matters most in this package.
	//
	// BOTH CAPS ARE READ INSIDE IT since `06v`, because they are now stored
	// operator values rather than immutable environment ones. The per-payment
	// check moved in here with them: reading it from a separate load would let a
	// concurrent lowering be applied between the two reads, and the pair would
	// then have been checked against two different versions of the state.
	// updateIf, not update: a refusal decides but records nothing that has to
	// survive a restart, and saveLocked is an fsync and a rename. Skipping the
	// write on the refusal branches keeps a flood of refused payments — the very
	// thing a compromised server can drive as fast as the socket allows — from
	// costing a synchronous disk write each. The pruned SpendAttempts slice is
	// the only thing a refusal mutates, and every reader recomputes that prune,
	// so dropping the write is safe and not merely cheap. See stateStore.updateIf.
	var refusal string
	if err := g.state.updateIf(func(st *State) bool {
		used, kept := spendWindowUsed(st.SpendAttempts, g.rotation.clock())
		st.SpendAttempts = kept
		switch {
		case cost > st.MaxPaymentMsat:
			refusal = fmt.Sprintf("this payment would cost %d msat, over the per-payment "+
				"limit of %d msat", cost, st.MaxPaymentMsat)
		case len(kept) >= g.maxWindowAttempts:
			refusal = fmt.Sprintf("the guard is holding %d payment attempts for this window "+
				"and will not lose one to record another", len(kept))
		case used+cost > st.MaxSpendMsat:
			refusal = fmt.Sprintf("this payment would take the last %s to %d msat, over the "+
				"limit of %d msat", SpendWindow, used+cost, st.MaxSpendMsat)
		default:
			st.SpendAttempts = append(kept, SpendAttempt{
				Key:  g.attemptKey(in),
				At:   g.rotation.clock(),
				Msat: cost,
			})
		}
		return refusal == ""
	}); err != nil {
		// The record could not be kept, so the attempt is refused: allowing a
		// payment the window will not remember is how the cap is exceeded one
		// unrecorded payment at a time (Ruling 3).
		g.log.Error("could not record a payment attempt against the spend window",
			"error", err.Error())
		return g.refuseSpend(ctx, in, "the guard could not record this payment attempt", cost)
	}
	if refusal != "" {
		return g.refuseSpend(ctx, in, refusal, cost)
	}
	g.log.Info("allowing a payment attempt", "msat", cost, "request", in.RequestID)
	return nil
}

// ObserveResponse decrements the window when — and only when — the node reports
// a payment TERMINALLY FAILED.
//
// Ruling 2, and the distinction it turns on is not failure-versus-success but
// OBSERVED versus UNOBSERVED. A stream that closes, errors, or dies with the
// guard is not a failed payment; it is a payment nobody is watching any more,
// and it may well settle. Refunding the window there hands budget back for money
// that moved, which is the cap being wrong in the direction that costs the
// operator. Only an explicit FAILED comes back.
//
// IN_FLIGHT and SUCCEEDED are both "spent" and both no-ops here: the increment
// already happened on the attempt, which is what makes a payment the guard never
// sees the end of still count (§14).
func (g *Guard) ObserveResponse(ctx context.Context, in lnd.Interception) {
	if in.MethodURI != SendPaymentMethod || in.IsError {
		// An error message carries a string, not a Payment, and says nothing
		// about whether the payment was made — LND reports transport failures
		// this way too.
		return
	}
	var payment lnrpc.Payment
	if err := proto.Unmarshal(in.Serialized, &payment); err != nil {
		return
	}
	if payment.GetStatus() != lnrpc.Payment_FAILED {
		return
	}
	key := g.attemptKey(in)
	var refunded int64
	if err := g.state.update(func(st *State) {
		_, kept := spendWindowUsed(st.SpendAttempts, g.rotation.clock())
		remaining := make([]SpendAttempt, 0, len(kept))
		for _, attempt := range kept {
			// ONE record, not every record with this key: a decrement that
			// removed more than it recorded would be a refund for a payment
			// that happened.
			if attempt.Key == key && refunded == 0 {
				refunded = attempt.Msat
				continue
			}
			remaining = append(remaining, attempt)
		}
		st.SpendAttempts = remaining
	}); err != nil {
		// Not fatal and not retried: the failed payment simply stays counted,
		// which is the safe direction.
		g.log.Warn("could not return a failed payment to the spend window",
			"error", err.Error())
		return
	}
	if refunded > 0 {
		g.log.Info("returning a failed payment to the spend window",
			"msat", refunded, "reason", payment.GetFailureReason().String())
	}
}

// MiddlewareRegistered records that LND has accepted the registration, which is
// what §11's Tier 2 row and the Sending page read.
func (g *Guard) MiddlewareRegistered() {
	g.middlewareUp.Store(true)
	g.log.Info("registered as an LND RPC middleware; the spend cap is being enforced",
		"caveat", lnd.GuardCaveatName)
}

// priceAttempt is what this attempt may cost the node, in msat.
//
// AMOUNT PLUS FEE LIMIT, because §6's cap is on outbound total and the fee goes
// outbound too. The fee LIMIT rather than the fee paid: the fee paid is not
// known until the payment settles, and a cap that could only be applied
// afterwards is not a cap. It bounds the real loss correctly — the node cannot
// spend more than amount + fee limit on one attempt — at the cost of counting a
// little more than a cheap route will use.
//
// THE AMOUNT COMES FROM THE NODE, not from the request. An invoice's amount is
// in its signed human-readable part, and a compromised server holding the spend
// macaroon writes the request message: a field it controls is not a limit.
// DecodePayReq is already in SpendPermissions for §8's ladder, and §6 records
// why the alternative was rejected — "a second bolt11 parser in this repo, which
// would be a second opinion about where money goes".
//
// The request's own amount fields are used only where they ARE the amount: a
// zero-amount invoice, or a keysend with no invoice at all. There the number in
// the request is what LND will send, so reading it is not trust, it is the fact.
func (g *Guard) priceAttempt(ctx context.Context, req *routerrpc.SendPaymentRequest) (int64, error) {
	amount := req.GetAmtMsat()
	if amount == 0 {
		// BEFORE the multiply, not after. A satoshi amount near 2^63/1000 wraps
		// to a small POSITIVE msat value, which the amount <= 0 check below
		// would wave through at almost nothing — and both fields are written by
		// the container this function exists to bound.
		if !countableSats(req.GetAmt()) {
			return 0, errTooLargeToCount
		}
		amount = req.GetAmt() * 1000
	}
	if bolt11 := req.GetPaymentRequest(); bolt11 != "" {
		invoice, err := g.node.Decode(ctx, bolt11)
		if err != nil {
			return 0, errors.New("the guard could not read the invoice this payment is for, " +
				"so it cannot be counted against the spend limit")
		}
		if invoice.AmountMsat > 0 {
			// An invoice that names its own amount: LND refuses a request that
			// also carries one, so this IS the amount.
			amount = invoice.AmountMsat
		}
	}
	fee := req.GetFeeLimitMsat()
	if fee == 0 {
		if !countableSats(req.GetFeeLimitSat()) {
			return 0, errTooLargeToCount
		}
		fee = req.GetFeeLimitSat() * 1000
	}
	if amount <= 0 {
		return 0, errors.New("this payment names no amount the guard can count against the " +
			"spend limit")
	}
	if fee < 0 || amount > maxCountableMsat-fee {
		// Arithmetic that would wrap is refused rather than clamped: a negative
		// or overflowing cost sums to less than nothing and empties the window.
		return 0, errTooLargeToCount
	}
	return amount + fee, nil
}

// maxCountableMsat is far above 21 million BTC in msat, so the checks around it
// refuse only genuinely nonsensical numbers.
const maxCountableMsat = int64(1) << 62

// countableSats reports whether a satoshi figure survives ×1000.
func countableSats(sats int64) bool { return sats >= 0 && sats <= maxCountableMsat/1000 }

var errTooLargeToCount = errors.New("this payment's amount and fee limit are not a number the " +
	"guard can add to the spend window")

// refuseSpend audits the refusal and returns the error LND will abort with.
//
// AUDITED, through the guard's own auditor: §12 calls a burst of guard
// rejections the highest-signal event in the system, and this is the only place
// a payment the operator's own limits forbid is stopped. The refusal text also
// goes back to the caller, so the person who asked for the payment reads why.
func (g *Guard) refuseSpend(ctx context.Context, in lnd.Interception, why string, cost int64) error {
	attrs := map[string]string{
		"op":     "send_payment",
		"reason": why,
	}
	if cost > 0 {
		attrs["msat"] = strconv.FormatInt(cost, 10)
	}
	if g.auditReject(ctx) {
		g.audit(ctx, slog.LevelWarn, "refused a payment at the guard's hard spend limit",
			logging.EventGuardReject, attrs)
	} else {
		g.log.Warn("refused a payment at the guard's hard spend limit; past this hour's audit "+
			"bound, so this one is logged only", "reason", why)
	}
	return fmt.Errorf("%w: %s", errSpendRefused, why)
}

// auditRejectBound is the guard's own, and it is TIGHTER than §12's default for
// a reason the other writers do not have: the guard's ring is 32 slots
// (State.RecentAudit), not 10 000, and nothing drains it — every response
// carries the whole ring and the server dedupes by id. Twenty of thirty-two is
// already most of it, so this leaves room for the events an operator actually
// needs afterwards.
//
// EXPIRY CONDITION: if maxRetainedAuditEvents grows, this can grow with it. They
// are the same fact — how much of the guard's ring one repeated refusal may
// occupy — and the ratio is what matters, not either number.
const auditRejectBound = 8

// auditReject reports whether this refusal may take a slot in the guard's ring,
// and writes the one row that says the bound was reached (t0b).
//
// THE GUARD IS THE SHARPEST CASE. `tna.4` made guard.reject live on every
// refused BakeSpend and `tna.1` on every refused payment, and both are driven by
// the SERVER — the container this whole design assumes may be compromised. With
// no bound, thirty-two socket calls flush the ring before the server has
// necessarily collected it, taking `macaroon.bake` with them: the row an
// operator most needs after exactly the incident that produced the flood.
func (g *Guard) auditReject(ctx context.Context) bool {
	record, sayBounded := g.rejectBudget.Allow()
	if sayBounded {
		g.audit(ctx, slog.LevelWarn, "more guard rejections this hour than the audit bound "+
			"allows; the rest are in the log only", logging.EventGuardReject,
			map[string]string{
				"bound":  strconv.Itoa(auditRejectBound),
				"remedy": "read the guard's log for the ones not recorded here",
			})
	}
	return record
}

// attemptKey namespaces a middleware request id by the stream it arrived on and
// by this guard's run. See SpendAttempt.Key.
func (g *Guard) attemptKey(in lnd.Interception) string {
	return g.runNonce + ":" + in.Session + ":" + strconv.FormatUint(in.RequestID, 10)
}

// MiddlewareBackoff is how long the guard waits before re-registering.
//
// Short, because the whole time it is not registered the spend macaroon is
// dead: LND rejects a custom caveat with no middleware behind it, so an
// unregistered guard is a sending outage rather than a relaxation.
const MiddlewareBackoff = 5 * time.Second

// RunMiddleware keeps the guard registered with LND for as long as ctx lives.
//
// It reconnects for ever rather than exiting. The failure is SAFE — the caveat
// fails closed, so nothing can spend while this is down — but it must not read
// as a crash (§14): the guard still answers Status, still bakes the receive
// credential, and still holds the kill switch, so the container staying up is
// the correct behaviour and the state is reported instead.
func (g *Guard) RunMiddleware(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		err := g.node.RunMiddleware(ctx, g)
		g.middlewareUp.Store(false)
		if ctx.Err() != nil {
			return
		}
		// observe, not observeStream: this is the guard's own client, and the
		// guard's rotation detector is what acts on a rejected admin macaroon.
		g.observe(ctx, err) //nolint:errcheck // the value is recorded, not returned
		if errors.Is(err, lnd.ErrMiddlewareUnavailable) {
			g.log.Error("this node would not accept the guard's RPC middleware, so sending is "+
				"blocked; LND rejects the spend macaroon while no middleware is registered "+
				"for its caveat. Check that rpcmiddleware.enable is set on the node",
				"error", err.Error())
		} else {
			g.log.Warn("the middleware stream to LND ended; re-registering",
				"error", err.Error())
		}
		if err := g.sleep(ctx, MiddlewareBackoff); err != nil {
			return
		}
	}
}

// newRunNonce is the per-process half of an attempt key.
func newRunNonce() string { return secret.RandomToken(8) }

// spendUsedIn is what the window holds according to a state the caller already
// has. Status loads the state once and reads both halves of the cap from it.
func spendUsedIn(state State, now time.Time) int64 {
	used, _ := spendWindowUsed(state.SpendAttempts, now)
	return used
}
