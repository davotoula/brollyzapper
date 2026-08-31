package nwc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

// SettingSendEnabled is the operator's intent to allow outbound payments (§4,
// §8 step 2).
//
// ABSENT MEANS FALSE, and that is §2's posture rather than a convenience: this
// app is receive-only by default, and a fresh install that could pay because
// nobody had said no would be the opposite of the arrangement the whole design
// is built around. The Settings toggle that writes it is d24.5; until then the
// only way it becomes true is an operator (or the regtest stack) setting it
// deliberately.
//
// It is one half of step 2. The other is a spend macaroon that actually exists:
// the intent and the capability are separate facts, and either one missing is
// the same refusal.
const SettingSendEnabled = "send_enabled"

// Bolt11 is what the ladder needs to know about an invoice before it reserves.
//
// Declared here rather than imported from internal/lnd because this is the
// consumer (§3) — and because the ladder's questions are these four, not the
// twenty fields a PayReq carries.
type Bolt11 struct {
	PaymentHash string
	AmountMsat  int64
	Description string
	// DescriptionHash is the FIFTH, and it is not one of the ladder's questions:
	// nothing above decides anything with it. It is here because it is the only
	// fact on a decoded invoice that the paying client did not choose, which is
	// what lets outgoingMetadata check a client's claim about a payment
	// against the payment (y09). Lowercase hex, empty when the invoice has none.
	DescriptionHash string
	ExpiresAt       time.Time
}

// Expired reports whether the invoice can still be paid at now.
//
// An invoice with no expiry never expires here — the node will refuse it if it
// disagrees, and inventing one would refuse payments the payee still wants.
func (b Bolt11) Expired(now time.Time) bool {
	return !b.ExpiresAt.IsZero() && !now.Before(b.ExpiresAt)
}

// Spend is the outbound path: §8 step 8, plus the two facts steps 2 and 3 need
// in order to refuse before it.
//
// COMPOSED HERE, and deliberately not a widening of wallet.Spender (ruling 1).
// The freeze that matters lives inside wallet.Reserve, where no caller can get
// in front of it; Held is this package asking the same question EARLY so that a
// refusal carries §8's RESTRICTED rather than whatever a reservation error
// happens to say. If the two ever disagree, Reserve wins — and there is a test
// that deletes this package's opinion and asserts the payment is still refused.
type Spend interface {
	// CredentialReady reports whether a spend macaroon EXISTS (step 2, first
	// half). Presence only — an absent one is the receive-only default and not a
	// defect (§6), which is why it is a separate question from the one below.
	CredentialReady() bool
	// SendingBlocked is §11's Tier-2 report, asked whether it takes sending
	// away — step 2's second half, and the whole of d24.6.
	//
	// The REPORT, not a subset re-derived here. Every spend row already declares
	// Blocks: BlocksSending and nothing consulted it, so an expired macaroon, one
	// locked to another container, or one whose root key the node had already
	// deleted rendered a red row and paid anyway. Two statements of one policy is
	// how that comes back: the ladder asks, preflight decides.
	//
	// EMPTY means permitted. One return rather than a bool beside it, because
	// every blocked answer names at least one check and every permitted one
	// names none — a (bool, []string) pair could express "blocked by nothing"
	// and "permitted, but here are the failures", and neither means anything.
	//
	// The IDs are for the LOG. They never reach the client: a paired app
	// learning which control failed is a paired app being told how to pick the
	// lock.
	SendingBlocked(ctx context.Context) []string
	// Held reports whether spending is held, and why (step 3). Both freezes
	// surface here — a reconciliation shortfall and an unresolved payment — as
	// one code with different messages (ruling 2): both mean "spending is held
	// for reasons that are not about your quota".
	Held(ctx context.Context) (string, bool, error)
	// MaxFee is §5's single fee reserve. This package never computes one; an
	// arch rule says the wallet is the only place that arithmetic lives.
	MaxFee(ctx context.Context, amountMsat int64) (int64, error)
	// Decode reads a bolt11 through the node that will pay it — the same node,
	// which is the point: a second parser would be a second opinion about where
	// the money goes.
	Decode(ctx context.Context, bolt11 string) (Bolt11, error)
	// Pay reserves, sends, and closes the reservation (step 8).
	Pay(ctx context.Context, req PayRequest) (PayResult, error)
}

// ErrNotDispatched means the payment was refused BEFORE anything reached the
// node — so its fate is known, and the budget it took comes back.
//
// The distinction the seam has to carry (d24.4 review). A reservation the wallet
// refused and a send that errored are both "an error" to a caller that cannot
// tell them apart, and treating the first as the second keeps a budget for a
// payment that never happened and tells the client it might be in flight. The
// information exists where payInvoice returns; only the seam could lose it.
var ErrNotDispatched = errors.New("nwc: the payment was refused before it was dispatched")

// notDispatched says which refusal it was, in §8's vocabulary and without
// handing a client the wallet's internal error text.
//
// The three are genuinely different answers: raise the balance, wait for the
// payment already running, or take the freeze up with the operator.
func notDispatched(err error) (string, string) {
	switch {
	case errors.Is(err, ErrInsufficientBalance):
		return CodeInsufficientBalance,
			"the wallet does not hold enough to cover this payment and its fee reserve"
	case errors.Is(err, ErrAlreadyPaying):
		return CodeOther, "a payment for this invoice is already in flight"
	default:
		return CodeRestricted, "spending is held; the payment was not dispatched"
	}
}

// The two refusals a client can act on, distinguished from the general one.
// Declared here, matched by the adapter (§3): internal/nwc must not import the
// wallet or the store to recognise them.
var (
	ErrInsufficientBalance = errors.New("nwc: the wallet ceiling does not cover this payment")
	ErrAlreadyPaying       = errors.New("nwc: a payment for this invoice is already in flight")
)

// PayRequest is one outbound payment, already decoded and already authorised.
type PayRequest struct {
	Bolt11      string
	AmountMsat  int64
	MaxFeeMsat  int64
	PaymentHash string
	// Ref is what the operator sees on the transaction.
	Ref string
	// Description is the invoice's own memo (d24.16). The field trip found
	// outgoing rows blank while incoming rows carried the zap comment, so the
	// operator's own history showed unlabelled debits.
	Description string
	// Metadata is the NWC-06 `metadata` object the client sent alongside the
	// payment, empty when it sent none or when what it sent was dropped. Its
	// `nostr` member is the ONLY place a paid zap's payee exists: a NIP-57
	// invoice commits to a description_hash and carries no memo, so Description
	// above is empty on exactly these rows.
	//
	// DescriptionHash is what that invoice committed to, carried so the row can
	// hand a client the means to check the attribution rather than trust it.
	Metadata        string
	DescriptionHash string
	// ConnectionID is the pairing that asked for this payment (d24.15).
	//
	// It is written onto the txns row so the STARTUP RESOLVER can find the
	// connection whose budget a recovered payment over-charged. That column has
	// existed since migration 0001 and nothing ever wrote it, which is the
	// structural reason that arm was missing rather than an oversight.
	ConnectionID int64
}

// PayResult is what became of it.
//
// Settled and Failed are not opposites, and the gap between them is the point:
// an error from Pay means the payment's fate is UNKNOWN — it may be in flight at
// the node right now — and §6 forbids concluding anything from that. Only a
// definite Failed licenses returning the budget.
type PayResult struct {
	Settled bool
	// Preimage is secret.String all the way to the response, and internal/arch
	// insisted — correctly. It is the client's proof it paid, so it IS revealed,
	// but at exactly one line: the map that becomes the NIP-47 result. A plain
	// string here would have made every log line and every %+v between the node
	// and that map a place it could escape (§11, §12).
	Preimage secret.String
	FeeMsat  int64
	// Failed is the node saying it finished and did not pay.
	Failed        bool
	FailureReason string
	// Unbooked means the payment SETTLED but recording it did not (ruling 4).
	// The response is still a success — the money left the node — and the
	// resolver finishes the ledger.
	Unbooked bool
}

// LogValue keeps the preimage out of a log line even when the whole result is
// handed to slog (§12). What an operator needs is the outcome; the proof is the
// client's.
func (r PayResult) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("settled", r.Settled),
		slog.Bool("failed", r.Failed),
		slog.Int64("fee_msat", r.FeeMsat),
		slog.String("failure_reason", r.FailureReason),
	)
}

// payInvoice is §8's rejection ladder (steps 1–8), in order.
//
// THE ORDER IS THE BEHAVIOUR. A request that fails several steps is answered
// with the code of the EARLIEST, because the code is what a wallet app shows the
// operator: "quota exceeded" sent to someone whose node is frozen sends them to
// raise a budget that was never the problem.
//
// Steps 1 and 2 of §8 are split across this function and its caller: the `pay`
// group is checked by permits() before dispatch, with every other method's
// group, so a connection without it never arrives here.
//
// WHERE IT DEVIATES FROM §8, said plainly. §8 says the ladder runs "inside one
// DB transaction". It cannot: the budget lives on nwc_connections and the
// reservation lives in the wallet, whose store methods internal/nwc must not
// reach (an arch rule, and §5's rule that only the wallet touches the balance).
// So this is TWO atomic steps with a compensation — the budget reservation is
// one guarded UPDATE, wallet.Reserve is its own transaction, and a failure after
// the budget was taken returns it. What the single transaction was for is
// preserved: no request can spend past a budget, because the check and the
// increment are never separated.
func (s *Service) payInvoice(ctx context.Context, conn *connection, req Request) Response {
	var params struct {
		Invoice string `json:"invoice"`
		Amount  int64  `json:"amount"`
		// Metadata is NIP-47's optional per-payment metadata (NWC-06), and
		// json.RawMessage because its shape is the CLIENT'S and we keep only the
		// one member we understand. A typed struct here would be this app
		// asserting what a paired wallet may send.
		//
		// THE ONE WAY METADATA CAN STILL COST A PAYMENT, stated so nobody
		// concludes the drop-never-fail rule is absolute: RawMessage requires
		// syntactically valid JSON, so a client that sends broken JSON fails the
		// unmarshal above along with the rest of its request. That is not
		// metadata failing a payment — it is an unparseable request, and there is
		// no version of this where we pay on one.
		Metadata json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(nonNull(req.Params), &params); err != nil {
		return errorResponse(req.Method, CodeOther, "could not read the parameters")
	}

	// --- 2. sending enabled, and a spend macaroon to do it with -------------
	if enabled, err := s.sendEnabled(ctx); err != nil {
		s.log.Error("could not read whether sending is enabled", "error", err.Error())
		return errorResponse(req.Method, CodeInternal, "internal error")
	} else if !enabled {
		return errorResponse(req.Method, CodeRestricted, "sending is disabled on this node")
	}
	if !s.spend.CredentialReady() {
		return errorResponse(req.Method, CodeRestricted,
			"this node holds no spend credential, so it cannot pay")
	}
	// --- 3. the freezes, ABOVE the Tier-2 gate -------------------------------
	//
	// For the CODE only (ruling 1). wallet.Reserve carries the enforcement and
	// runs whatever this says.
	//
	// Above step 2's second half deliberately, and §8's numbering is not being
	// broken: both answer RESTRICTED, so the CODE earliest-wins produces is the
	// same either way — only the MESSAGE differs. §11's report contains rows for
	// both freezes too (reconciliation and unresolved payments, each declaring
	// Blocks: BlocksSending), so a Tier-2 gate consulted first would answer every
	// freeze with the generic "see the Security page" and ruling 2's
	// differentiated messages would be unreachable in a shipped binary. Asking
	// the specific question first costs nothing and keeps the better answer.
	if reason, held, err := s.spend.Held(ctx); err != nil {
		s.log.Error("could not read whether spending is held", "error", err.Error())
		return errorResponse(req.Method, CodeInternal, "internal error")
	} else if held {
		return errorResponse(req.Method, CodeRestricted, "spending is held: "+reason)
	}

	// And the credential has to be VALID, which is §11's Tier 2 and not this
	// package's to judge. Computed fresh per request by design: Inputs are
	// functions precisely so the report cannot cache into staleness, the
	// macaroon checks are local file reads, and §11's table requires "guard
	// unreachable blocks sending" — which can only be known by asking.
	//
	// UNLIKE step 3, there is no second enforcement behind this one, and saying
	// so is better than implying otherwise: wallet.Reserve knows nothing about
	// macaroons. What backs it is the NODE — a macaroon it has revoked or that
	// has expired is refused by LND itself, so a payment that got past this gate
	// would fail at the node rather than succeed. This gate is what turns that
	// failure into an honest answer instead of an attempted spend.
	if failing := s.spend.SendingBlocked(ctx); len(failing) > 0 {
		// DEBUG, not WARN. reportOutcome writes the WARN and the durable row for
		// this same RESTRICTED, and the Auditor's contract is the line and the
		// row together — a second WARN here is one refusal reported twice, which
		// this package's own Auditor doc forbids (found by review). What survives
		// is the half the audit row deliberately omits: WHICH controls failed,
		// which never reaches the client and is the operator's diagnosis.
		s.log.Debug("a Tier-2 check blocks sending",
			"connection", conn.row().ID, "checks", strings.Join(failing, ", "))
		// Ruling 3: no internals. The operator's diagnosis is the Security
		// page's row, which already carries the named text §11 asks for.
		return errorResponse(req.Method, CodeRestricted,
			"sending is unavailable on this node right now; its owner can see why on the "+
				"Security page")
	}

	// Only NOW is a missing invoice worth mentioning. Checked below the two
	// refusals above rather than beside the parse, so a send-disabled node
	// answers RESTRICTED whatever the client sent — earliest-wins is about the
	// order the answers come in, and a parameter complaint jumping the queue
	// tells an operator their invoice was wrong when sending was simply off.
	if params.Invoice == "" {
		return errorResponse(req.Method, CodeOther, "invoice is required")
	}

	// The invoice, read by the node that would pay it — before any reservation
	// exists (test-spec E2, E3, E4).
	invoice, err := s.spend.Decode(ctx, params.Invoice)
	if err != nil {
		s.log.Info("an NWC pay_invoice named an invoice the node could not read",
			"connection", conn.row().ID, "error", err.Error())
		return errorResponse(req.Method, CodeOther, "the invoice could not be read")
	}
	if invoice.Expired(s.now()) {
		return errorResponse(req.Method, CodeOther, "the invoice has expired")
	}
	amount, resp := payableAmount(req.Method, invoice, params.Amount)
	if resp != nil {
		return *resp
	}

	// --- 4. the per-payment cap ---------------------------------------------
	//
	// Separate from the budget on purpose: a monthly budget with no per-payment
	// cap lets one request spend the month.
	//
	// ONE snapshot of the row from here to the reservation. update() swaps the
	// whole row at once so that the limits are never read half-old, and calling
	// row() three times over gives that guarantee away — a reload landing
	// between the cap check and the renewal window would measure this payment
	// against limits that never existed together. Found by review, which noted
	// the atomicity comment on update() was promising more than the ladder took.
	limits := conn.row()
	if limit := limits.MaxPaymentMsat; limit != nil && amount > *limit {
		return errorResponse(req.Method, CodeQuotaExceeded,
			fmt.Sprintf("this connection may not pay more than %d msat at once", *limit))
	}

	// §5's single fee reserve, and the ONLY place this number comes from. It is
	// what the budget takes, what the wallet debits, and what the node is given
	// as its fee limit — one figure, so the three cannot disagree.
	maxFee, err := s.spend.MaxFee(ctx, amount)
	if err != nil {
		s.log.Error("could not compute the fee reserve", "error", err.Error())
		return errorResponse(req.Method, CodeInternal, "internal error")
	}
	total := amount + maxFee

	// --- 5 and 6. the budget window, rolled and taken in one statement -------
	outcome, err := s.store.ReserveNWCBudget(ctx, limits.ID, total, s.now(),
		nextRenewal(limits, s.now()))
	if err != nil {
		s.log.Error("could not reserve an NWC budget", "connection", conn.row().ID,
			"error", err.Error())
		return errorResponse(req.Method, CodeInternal, "internal error")
	}
	switch outcome {
	case store.BudgetRefused:
		return errorResponse(req.Method, CodeQuotaExceeded,
			"this payment would exceed the connection's budget for this period")
	case store.BudgetConnectionGone:
		// Since uhg the reload closes a revoked connection's subscription, so
		// this arm is the SECOND line of defence rather than the mechanism: it
		// catches a request already in flight when the revocation landed. Told
		// apart from an over-budget refusal because they are different sentences
		// — one is "raise the limit", the other is "this pairing is gone".
		return errorResponse(req.Method, CodeUnauthorized, "this connection has been revoked")
	}

	// From here on, every refusal has to give the budget back — the WHOLE
	// reservation, through the same BudgetCorrection the resolver uses, so the
	// live path and the recovery path cannot come to disagree about what a
	// payment that did not happen costs.
	//
	// On a context WITHOUT cancellation: the request's ctx may already be done —
	// a shutdown, a client that went away — and a budget that was taken for a
	// payment nobody made must still come back. It is a correction to a durable
	// number, not part of answering the request.
	release := func() {
		back := BudgetCorrection(false, amount, maxFee, 0)
		if err := s.store.AdjustNWCBudget(context.WithoutCancel(ctx), conn.row().ID, back); err != nil {
			s.log.Error("could not return an NWC budget reservation; this connection will "+
				"appear to have spent more than it did until its window rolls",
				"connection", conn.row().ID, "msat", total, "error", err.Error())
		}
	}

	// --- 7. the wallet ceiling ----------------------------------------------
	//
	// For the CODE, like step 3: the ceiling that DECIDES is inside the
	// reservation's transaction, where the balance cannot move under it. This
	// read is what turns that refusal into §8's INSUFFICIENT_BALANCE instead of
	// a wallet error's text, and it also saves taking a budget for a payment the
	// wallet was never going to make.
	balance, err := s.purse.Balance(ctx)
	if err != nil {
		release()
		s.log.Error("could not read the balance", "error", err.Error())
		return errorResponse(req.Method, CodeInternal, "internal error")
	}
	if total > balance {
		release()
		return errorResponse(req.Method, CodeInsufficientBalance,
			"the wallet does not hold enough to cover this payment and its fee reserve")
	}

	// --- 8. reserve, send, close --------------------------------------------
	result, err := s.spend.Pay(ctx, PayRequest{
		Bolt11:      params.Invoice,
		AmountMsat:  amount,
		MaxFeeMsat:  maxFee,
		PaymentHash: invoice.PaymentHash,
		Ref:         paymentRef(conn, invoice),
		Description: boundedDescription(invoice.Description),
		Metadata: s.outgoingMetadata(conn, params.Metadata, amount,
			invoice.DescriptionHash),
		DescriptionHash: invoice.DescriptionHash,
		ConnectionID:    limits.ID,
	})
	switch {
	case errors.Is(err, ErrNotDispatched):
		// NOTHING LEFT THE NODE. The wallet refused to reserve — its freeze, its
		// ceiling, or the partial index that stops a second payment for an
		// invoice already in flight — so the fate is known, the budget comes
		// back, and the client is told the truth.
		//
		// Collapsing this into the unknown-fate arm below was a real bug (found
		// by the d24.4 review): a frozen node answered "your payment may be in
		// flight" and kept the budget, so a retrying wallet app burned the whole
		// window in a handful of attempts, each one a payment that never
		// happened.
		release()
		s.log.Info("an NWC payment was refused before anything was dispatched",
			"connection", conn.row().ID, "error", err.Error())
		code, message := notDispatched(err)
		return errorResponse(req.Method, code, message)
	case err != nil:
		// The fate is UNKNOWN. It may be in flight at the node right now, so the
		// budget stays taken and nothing is reversed — §6's rule, and the
		// resolver is what finishes it. Reported as OTHER rather than
		// PAYMENT_FAILED deliberately: §8's table has no code for "in flight",
		// and telling a client its payment failed while it is being made is how
		// an invoice gets paid twice.
		s.log.Warn("an NWC payment could not be completed and its outcome is unknown",
			"connection", conn.row().ID, "payment_hash", invoice.PaymentHash,
			"error", err.Error())
		return errorResponse(req.Method, CodeOther,
			"the payment was dispatched and its outcome is not yet known")
	case result.Failed:
		// A definite failure, which is the ONLY answer that licenses returning
		// the budget: §8 says a failed payment consumes none.
		release()
		return errorResponse(req.Method, CodePaymentFailed, failureMessage(result))
	case !result.Settled:
		// Neither settled nor failed: the seam's contract broke. Nothing is
		// concluded and nothing is returned.
		s.log.Error("an NWC payment returned neither settled nor failed",
			"connection", conn.row().ID, "payment_hash", invoice.PaymentHash)
		return errorResponse(req.Method, CodeOther,
			"the payment was dispatched and its outcome is not yet known")
	}

	// Settled. The reservation took amount + max_fee, and §8 corrects that to
	// amount + ACTUAL fee — the same arithmetic the wallet does when it refunds
	// the unused reserve.
	//
	// Signed, so both directions are covered. A route that cost more than the
	// reserve cannot normally settle — the wallet refuses it — but that refusal
	// is exactly what produces ErrBooking, and on that path the payment DID
	// happen at the node. Under-counting there would leave a connection with
	// budget it has already spent.
	// NOT when the payment could not be BOOKED. The reservation is still pending
	// in that case, so it belongs to the resolver now — and the resolver applies
	// exactly this correction when it closes the row (d24.15). Applying it here
	// as well credits the connection the unused fee reserve TWICE, letting it
	// spend past its budget by one reserve per unbooked payment. Found by
	// review, in the one path this wave added a bool to keep idempotent.
	if correction := BudgetCorrection(true, amount, maxFee, result.FeeMsat); correction != 0 && !result.Unbooked {
		if err := s.store.AdjustNWCBudget(context.WithoutCancel(ctx), conn.row().ID, correction); err != nil {
			s.log.Error("could not correct an NWC budget to the actual fee",
				"connection", conn.row().ID, "error", err.Error())
		}
	}
	// THE LINE THE FIELD TRIP COULD NOT FIND (d24.14 ruling 1). A real payment
	// produced zero log lines at debug level, so an operator asking "did
	// something pay from my node?" had only the ledger.
	//
	// Here rather than in reportOutcome because this is where the numbers are:
	// the amount, the route's actual fee, and the hash an operator takes to
	// their node. No audit row — §12 says money's durable record is the txns
	// table, and a second one would be two statements of one fact. No preimage,
	// ever: §12 lists it with the macaroons, and it is the client's proof rather
	// than the operator's record.
	s.log.Info("an NWC payment settled", "connection", limits.ID,
		"payment_hash", invoice.PaymentHash, "amount_msat", amount,
		"fee_msat", result.FeeMsat, "unbooked", result.Unbooked)
	// THE one reveal. NIP-47 returns the preimage and the client that asked for
	// the payment is entitled to its proof; §11 keeps it out of logs, not out of
	// the answer.
	return Response{ResultType: req.Method, Result: map[string]any{
		"preimage":  result.Preimage.Reveal(),
		"fees_paid": result.FeeMsat,
	}}
}

// payableAmount decides what an invoice is for (test-spec E4).
//
// A zero-amount invoice is a question, not an error: NIP-47 lets the request
// answer it. Without an answer there is nothing to pay and nothing to reserve,
// and an invoice that DOES name an amount cannot be overridden — paying more
// than the payee asked for on a client's say-so is not this app's decision.
func payableAmount(method Method, invoice Bolt11, requested int64) (int64, *Response) {
	switch {
	case invoice.AmountMsat > 0 && requested > 0 && requested != invoice.AmountMsat:
		resp := errorResponse(method, CodeOther,
			"this invoice names its own amount, which cannot be overridden")
		return 0, &resp
	case invoice.AmountMsat > 0:
		return invoice.AmountMsat, nil
	case requested > store.MaxMsat:
		// The client chooses this number, so its RANGE is the client's choice
		// too. An amount near MaxInt64 makes `amount + max_fee` wrap, and a
		// wrapped debit is a CREDIT to the ceiling — see store.MaxMsat. Refused
		// in all three layers that touch the arithmetic, because a bound in one
		// of them is one edit from being routed around.
		resp := errorResponse(method, CodeOther, "that amount is not payable")
		return 0, &resp
	case requested > 0:
		return requested, nil
	default:
		resp := errorResponse(method, CodeOther,
			"this invoice names no amount, so the request must supply one")
		return 0, &resp
	}
}

// nextRenewal is when a rolled budget window would next roll.
//
// Computed from NOW rather than from the old renewal point, so a connection that
// went unused for a month gets a full window rather than one that expires the
// moment it is created.
func nextRenewal(conn store.NWCConnection, now time.Time) time.Time {
	switch conn.BudgetPeriod {
	case store.BudgetDaily:
		return now.AddDate(0, 0, 1)
	case store.BudgetWeekly:
		return now.AddDate(0, 0, 7)
	case store.BudgetMonthly:
		return now.AddDate(0, 1, 0)
	default:
		// never, or unset: the window does not roll, so there is nothing to
		// move. The counter keeps counting and the budget is a lifetime one.
		return time.Time{}
	}
}

// paymentRef is what the operator sees against the transaction.
//
// The connection's NAME, because "which app spent this" is the question an
// operator asks of an outbound payment, and the invoice's description if it has
// one. Truncated: a description is a stranger's text.
func paymentRef(conn *connection, invoice Bolt11) string {
	ref := conn.row().Name
	if invoice.Description != "" {
		ref += ": " + truncate(invoice.Description, 120)
	}
	return truncate(ref, 200)
}

// truncate cuts to a RUNE count, not a byte count.
//
// The text is a stranger's — an invoice description travels from whoever wrote
// the invoice — so a byte slice can land mid-rune and put invalid UTF-8 in the
// operator's transaction list. internal/lnurl already handles a stranger's
// comment this way; same input class, same rule.
func truncate(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	return string([]rune(s)[:limit]) + "…"
}

func failureMessage(result PayResult) string {
	if result.FailureReason == "" {
		return "the payment failed"
	}
	return "the payment failed: " + result.FailureReason
}

// sendEnabled reads §8 step 2's half of the toggle.
//
// Anything other than a recognisable true is FALSE, including an unreadable
// value: §2's posture is receive-only by default, and a settings row nobody can
// parse is not permission to spend.
func (s *Service) sendEnabled(ctx context.Context) (bool, error) {
	raw, ok, err := s.store.Setting(ctx, SettingSendEnabled)
	if err != nil {
		return false, fmt.Errorf("nwc: reading %s: %w", SettingSendEnabled, err)
	}
	if !ok {
		return false, nil
	}
	return raw == "true" || raw == "1", nil
}

// MaxDescriptionLength bounds the invoice memo this app stores and echoes back.
//
// The same reasoning as maxMethodLength, applied to the other client-chosen
// string that now reaches a durable row: a paired app can put ~64 kB in a NIP-44
// payload, the memo of a bolt11 IT supplies is entirely its choice, and since
// d24.16 that memo is written to the ledger on an SD card and returned by
// list_transactions. Bounded on the way IN, because a row already written cannot
// be un-written.
//
// 640 characters is far past any real memo — bolt11's own description field is
// rarely more than a line — and far short of anything that fills a disk.
const MaxDescriptionLength = 640

// boundedDescription truncates a memo to MaxDescriptionLength, on a rune
// boundary so the stored text is still valid UTF-8.
//
// A backward walk from the limit rather than re-encoding a shrinking rune slice:
// the first version rebuilt the string on every iteration, which is quadratic in
// the length of a string an attacker chooses — a 64 kB memo turned a truncation
// into seconds of CPU on the payment path. Its own test took 3.6 s and that is
// how it was noticed.
func boundedDescription(description string) string {
	if len(description) <= MaxDescriptionLength {
		return description
	}
	cut := MaxDescriptionLength
	for cut > 0 && !utf8.RuneStart(description[cut]) {
		cut--
	}
	return description[:cut]
}

// MaxMetadataChars is NWC-06's bound on `pay_invoice.metadata`, and it is
// NORMATIVE: "The metadata MUST be no more than 4096 characters, otherwise MUST
// be dropped."
//
// CHARACTERS, which is the spec's own word — and this counted BYTES until the
// client side pointed out what that costs. JSON on the wire is UTF-8, where a
// character is one byte or more, so a byte bound rejects payloads a conformant
// client believed were inside the limit: a 2,000-character CJK comment is about
// 6,000 bytes. Conservative in the wrong direction, because the thing it was
// conservative about was interoperability.
//
// Amethyst counts UTF-16 code units, which are never fewer than the code points
// here, so anything it is willing to send now fits — the failure this removes
// cannot recur in that direction (read, not run).
//
// NOT lnurl.MaxZapRequestBytes, which is 8 KiB and bounds an INBOUND zap request
// from an anonymous stranger under a different spec. Sharing one constant would
// tie two limits that belong to different threat models, and the next person to
// move one would move both.
const MaxMetadataChars = 4096

// MaxMetadataBytes bounds the DURABLE WRITE, which is a different question from
// conformance and needs its own answer.
//
// Exactly four times the character bound, because UTF-8 encodes a code point in
// at most four bytes: so it can never refuse something inside MaxMetadataChars,
// and it still stops a pathological encoding turning a 4,096-character promise
// into an unbounded row on an SD card.
const MaxMetadataBytes = 4 * MaxMetadataChars

// outgoingMetadata is the NWC-06 `metadata` object out of a `pay_invoice`, or ""
// when there is nothing worth storing.
//
// IT NEVER RETURNS AN ERROR, and that is the whole design of this function. A
// malformed, oversized or degenerate blob is dropped and logged; the money still
// moves. A cosmetic field that can block a payment is a worse bug than a blank
// row, which is why the bound and the shape check live here rather than as a
// validation step on the pay path (doy.2, and doy.4 keeps the same rule).
//
// AN OBJECT, not merely valid JSON, at both levels. `json.Valid` accepts `null`,
// `123` and `"str"`, and a degenerate `nostr` would be stored and later emitted
// as `"metadata":{"nostr":null}` — half a check, which is worse than none
// because it reads as a whole one. zapMetadata makes the same check on the way
// out for the same reason; this one is what stops the row being written at all.
//
// THE WHOLE OBJECT IS STORED, not just its `nostr` member. NWC-06 also defines
// `recipient_data.identifier` — the payee's lightning address — and `comment`,
// and a client's own row renderer falls back to that address when a kind 0
// profile has not resolved, so keeping only the event handed every row back
// nameless. One column, one thing: what the client said about this payment.
//
// AND ONLY WHEN ITS `nostr` MEMBER BINDS. The siblings are NOT covered by the
// invoice's commitment — the hash is over the event — so a bound event travelling
// beside a lying `recipient_data.identifier` is entirely possible. Storing the
// object only when the event binds means everything in the column arrived with a
// proof attached, even though not all of it is proved; and this node must never
// present the address as a payee, which is why the admin page renders the p tag's
// npub and not the identifier.
//
// Stored VERBATIM rather than re-encoded. The event id is a hash over a
// canonical serialisation of its own fields, so a round trip through a Go map
// would reorder and renumber it into something whose id no longer verifies —
// which is exactly the check lnurl.CheckOutgoingZapRequest makes below.
//
// AND IT IS CHECKED, NOT MERELY SHAPED (doy.4). Signature, id, and the amount
// tag against the amount actually being paid. The narrower verifier rather than
// ParseZapRequest, because four of that function's rules are inbound-only; the
// audit is written out at internal/lnurl.CheckOutgoingZapRequest.
//
// BUT THOSE CHECKS ALONE ARE SELF-CONSISTENCY, NOT TRUTH, and doy.4's comment
// here claimed otherwise until a security review of this branch said so (y09).
// Outbound the signer is the PAYER, so the caller chose that key: a valid
// signature over a well-formed event proves only that the caller authored it.
// Nothing in kind, signature, id or the p tag's shape says the event is about
// THIS payment, and the amount tag is optional, so omitting it skipped the one
// external cross-check there was. A pairing holding `pay` — which the spec's own
// threat model calls a hostile or buggy NWC client — could therefore label an
// exfiltration payment "to <somebody trusted>" on the operator's own history
// page, and have it echoed to every other pairing.
//
// SO THE INVOICE'S OWN COMMITMENT IS WHAT MAKES IT A FACT. A NIP-57 zap invoice
// commits to description_hash = sha256(raw zap request), which is the rule this
// app mints with (lnurl.ZapHash) read backwards. Binding on it covers the payee,
// the comment and the amount in one comparison, and it is the only check here
// that consults something the CLIENT did not write.
func (s *Service) outgoingMetadata(conn *connection, metadata json.RawMessage,
	amountMsat int64, descriptionHash string) string {
	if len(metadata) == 0 {
		return ""
	}
	dropped := func(why string) string {
		s.log.Info("an NWC pay_invoice carried metadata this node did not store",
			"connection", conn.row().ID, "reason", why, "bytes", len(metadata))
		return ""
	}
	// THE BYTE CEILING FIRST, because it is O(1) and the rune count is not: an
	// absurdly large blob is refused on its length rather than decoded to find
	// out how many characters it holds (review). It is also the wider of the two
	// — four bytes per code point — so nothing inside the character bound can
	// trip it, and the check below is the one that decides conformance.
	if len(metadata) > MaxMetadataBytes {
		return dropped("over the durable-write byte ceiling")
	}
	if utf8.RuneCount(metadata) > MaxMetadataChars {
		return dropped("over NWC-06's 4096-character bound")
	}
	// BYTES throughout, converted to a string exactly once, on the way out. The
	// first version worked in strings and handed CheckOutgoingZapRequest a
	// conversion back, which is a second copy of up to 4 kB per payment for
	// nothing (review).
	event, object := lnurl.NostrMember(metadata)
	if !object {
		// Valid JSON of the wrong shape: an array, a number, a string. Its own
		// arm rather than falling in with "no nostr member", so the log says
		// which of the two happened.
		return dropped("not a JSON object")
	}
	if len(event) == 0 {
		// The ordinary case, not a fault: a pasted bolt11 or a mint top-up sends
		// `recipient_data` and a comment, or no metadata at all. Nothing to say.
		return ""
	}
	// AND NO SHAPE CHECK OF OUR OWN on the member. There was one — a
	// leading-brace test with its own log reason — and the verification below
	// rejects everything it rejected, with a more specific message. Two opinions
	// about "is this a JSON object", one by prefix and one by actually parsing,
	// is the shape that desyncs the first time either learns about whitespace or
	// a BOM (review).
	// AN INVOICE THAT COMMITS TO NOTHING STORES NOTHING, and this arm is what
	// makes the binding worth having: without it the bypass is to pay a plain
	// invoice — which has no description_hash — and attach whatever event you
	// like. A zap invoice always has one, so an invoice without one is either
	// not a zap or not this zap.
	//
	// HERE RATHER THAN IN THE VERIFIER, because it is a statement about the
	// INVOICE's state rather than about the event, and it belongs with the other
	// "is this worth storing" questions this function asks. Behaviourally it is
	// redundant — a sha256 hex is never "" so the comparison would reject anyway
	// — and it is kept for the log reason, the same call the JSON-shape arms
	// above make: "this invoice commits to nothing" and "it commits to something
	// else" are different problems with different fixes.
	if descriptionHash == "" {
		return dropped("the invoice commits to no description_hash, so nothing binds this " +
			"event to it")
	}
	if err := lnurl.CheckOutgoingZapRequest(event, amountMsat, descriptionHash); err != nil {
		// The verification's verdict, never the payment's. Reached only after
		// the money's own checks have all passed, and the caller uses the return
		// value for one thing: whether a column gets written.
		return dropped(err.Error())
	}
	// The OBJECT, having checked the member. See the head of this function for
	// why the siblings ride along and what that does and does not prove.
	return string(metadata)
}

// BudgetCorrection is what a TERMINAL payment adds to its connection's spend
// counter (§8, d24.15).
//
// ONE function because there are two callers and they must not drift: §8's
// ladder applies it live, and the startup resolver applies it to a payment whose
// process died before the ladder could. The first version wrote the arithmetic
// out in both places and its own comment claimed it had been "moved" — review
// pointed out it had been copied, with nothing keeping the two in step. The
// numbers are money, and a future edit to one of them would be silent.
//
// Settled: the reservation took `amount + reserve` and the payment cost
// `amount + actual`, so the difference comes back. SIGNED, so both directions
// are covered — a route that cost more than the reserve cannot normally settle,
// but that refusal is what produces an unbooked payment, and under-counting
// there would leave a connection with budget it has already spent.
//
// Failed: the whole reservation, because §8 says a failed payment consumes no
// budget. actualFeeMsat is ignored — there was no route to pay for.
func BudgetCorrection(settled bool, amountMsat, feeReservedMsat, actualFeeMsat int64) int64 {
	if settled {
		return actualFeeMsat - feeReservedMsat
	}
	return -(amountMsat + feeReservedMsat)
}
