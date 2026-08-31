package nwc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
	"slices"
)

// §8's rejection ladder, in order, and the ORDER is the behaviour being tested.
//
// A request that fails several steps gets the code of the EARLIEST one. That is
// not tidiness: the code is what an operator's wallet app shows them, and
// "quota exceeded" sent to someone whose node is frozen sends them to raise a
// budget that was never the problem. Each row here fails at least two steps and
// pins which one answers.
func TestTheRejectionLadderAnswersWithTheEarliestFailure(t *testing.T) {
	const amount = 50_000
	cases := []struct {
		name  string
		setup func(h *harness)
		code  string
		why   string
	}{{
		name:  "no pay group, and everything else wrong too",
		setup: func(h *harness) { h.spend.held = "reconciliation shortfall"; h.spend.ready = false },
		code:  CodeRestricted,
		why:   "step 1: the default connection cannot spend at all (§8's LNbits deviation)",
	}, {
		name: "sending disabled, and over budget",
		setup: func(h *harness) {
			h.grantPay()
			h.sendEnabled(false)
			h.setBudget(1_000)
		},
		code: CodeRestricted,
		why:  "step 2: sending off answers before any quota arithmetic",
	}, {
		name: "no spend macaroon",
		setup: func(h *harness) {
			h.grantPay()
			h.sendEnabled(true)
			h.spend.ready = false
		},
		code: CodeRestricted,
		why:  "step 2: no valid spend macaroon is the same refusal as sending off",
	}, {
		name: "the spend macaroon is invalid, and over budget",
		setup: func(h *harness) {
			h.grantPay()
			h.sendEnabled(true)
			// §11's Tier 2 says sending is blocked. This is d24.6: until this
			// wave the checks rendered a RED ROW and the node paid anyway.
			h.spend.blocked = []string{"spend.ipaddr"}
			h.setBudget(1_000)
		},
		code: CodeRestricted,
		why:  "step 2: a macaroon that exists but is not valid is not permission to spend",
	}, {
		name: "spending frozen, and over budget",
		setup: func(h *harness) {
			h.grantPay()
			h.sendEnabled(true)
			h.spend.held = "the wallet authorises more than the node can send"
			h.setBudget(1_000)
		},
		code: CodeRestricted,
		why:  "step 3: a freeze is not about the connection's quota",
	}, {
		name: "over the per-payment cap, and over budget",
		setup: func(h *harness) {
			h.grantPay()
			h.sendEnabled(true)
			h.setMaxPayment(1_000)
			h.setBudget(1_000)
		},
		code: CodeQuotaExceeded,
		why:  "step 4: the per-payment cap is checked before the window",
	}, {
		name: "over budget, and over the balance",
		setup: func(h *harness) {
			h.grantPay()
			h.sendEnabled(true)
			h.setBudget(1_000)
			h.wallet.balance = 0
		},
		code: CodeQuotaExceeded,
		why:  "step 6: the budget answers before the ceiling",
	}, {
		name: "over the balance only",
		setup: func(h *harness) {
			h.grantPay()
			h.sendEnabled(true)
			h.wallet.balance = 1_000
		},
		code: CodeInsufficientBalance,
		why:  "step 7",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.decodesTo("lnbcrt1ladder", amount, "a payment")
			tc.setup(h)

			resp := h.handle(t, MethodPayInvoice, payParams("lnbcrt1ladder", 0))

			if resp.Error == nil {
				t.Fatalf("the payment was accepted; want %s (%s)", tc.code, tc.why)
			}
			if resp.Error.Code != tc.code {
				t.Errorf("code = %s, want %s — %s", resp.Error.Code, tc.code, tc.why)
			}
			if h.spend.payments() != 0 {
				t.Errorf("%d payments were attempted by a refused request", h.spend.payments())
			}
		})
	}
}

// Ruling 1: the early freeze check is an ADDITION for the error code, never the
// enforcement.
//
// wallet.Reserve holds the freeze and no caller can get in front of it. This
// test deletes the ladder's opinion — the seam reports nothing held — and leaves
// the wallet refusing, which is the arrangement the ruling describes. The
// payment must still not happen. It is also this property's plant: if the two
// ever disagree, Reserve wins.
func TestTheFreezeHoldsEvenWhenTheLadderDoesNotKnowAboutIt(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.decodesTo("lnbcrt1frozen", 50_000, "a payment")
	// The ladder is told nothing is held...
	h.spend.held = ""
	// ...and the wallet refuses anyway, which is where the freeze actually is.
	// Wrapped as the production seam wraps it: payInvoice marks a refused
	// reservation ErrNotDispatched, because nothing reached the node.
	h.spend.reserveErr = fmt.Errorf("%w: wallet: spending is frozen by a reconciliation shortfall",
		ErrNotDispatched)

	resp := h.handle(t, MethodPayInvoice, payParams("lnbcrt1frozen", 0))

	if resp.Error == nil {
		t.Fatal("the payment succeeded past a wallet that refused to reserve")
	}
	if h.spend.paid != 0 {
		t.Error("the node was asked to pay after the wallet refused the reservation")
	}
	// And it must not cost the connection its budget. A refused reservation
	// dispatched NOTHING, so §8's "a failed payment consumes no budget" applies
	// with room to spare — the first version collapsed this into the
	// unknown-fate arm and kept the budget, so a frozen node plus a retrying
	// wallet app burned the window in a handful of attempts.
	if used := h.budgetUsed(); used != 0 {
		t.Errorf("budget_used_msat = %d after a payment that was never dispatched", used)
	}
	if resp.Error.Code != CodeRestricted {
		t.Errorf("a held wallet answered %s, want RESTRICTED — the client is being told the "+
			"payment might be in flight when nothing left the node", resp.Error.Code)
	}
}

// d24.6, and it is the bead in one test: a spend macaroon locked to ANOTHER
// container must be refused by the LADDER, not merely rendered red.
//
// preflight.spendChecks has computed all four spend rows since §11 landed, and
// every one declares Blocks: BlocksSending — but nothing consulted it. Step 2
// asked whether the setting was on and whether a file existed, which is
// PRESENCE, not validity. So an expired macaroon, one missing its ipaddr
// caveat, one locked to a different container, or one whose root key the node
// has already deleted, showed a red row on the Security page and paid anyway.
// §11's own sentence is that a checklist of green ticks bounding nothing is
// worse than no checklist; this was that inverted.
func TestATierTwoBlockRefusesThePaymentRatherThanMerelyShowingRed(t *testing.T) {
	cases := []struct {
		name   string
		failed []string
	}{
		{"locked to another container", []string{"spend.ipaddr"}},
		{"expired", []string{"spend.expiry"}},
		{"the node has revoked the root key", []string{"spend.rootkey"}},
		{"missing its caveats", []string{"spend.caveats"}},
		{"the guard is not answering", []string{"guard.reachable"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.grantPay()
			h.sendEnabled(true)
			h.setBudget(1_000_000)
			h.decodesTo("lnbcrt1blocked", 50_000, "a payment")
			h.spend.blocked = tc.failed

			resp := h.handle(t, MethodPayInvoice, payParams("lnbcrt1blocked", 0))

			if resp.Error == nil || resp.Error.Code != CodeRestricted {
				t.Fatalf("%s answered %+v, want RESTRICTED", tc.name, resp)
			}
			if h.spend.payments() != 0 {
				t.Errorf("the node was asked to pay with %s", tc.name)
			}
			if used := h.budgetUsed(); used != 0 {
				t.Errorf("budget_used_msat = %d; a refusal at step 2 is above the budget", used)
			}
			// §11 ruling 3: the client is told nothing about our internals. The
			// operator's diagnosis is the Security page's row Detail, which
			// already carries the named IP-mismatch text.
			for _, leak := range append(tc.failed, "macaroon", "caveat", "ipaddr", "root key") {
				if strings.Contains(strings.ToLower(resp.Error.Message), strings.ToLower(leak)) {
					t.Errorf("the response names %q: %q — a paired app learns which control "+
						"failed", leak, resp.Error.Message)
				}
			}
		})
	}
}

// And a report with NOTHING failing does not refuse: the checks model
// receive-only-by-default as passing (there is no macaroon to be wrong), so a
// gate that read "any check failed" would refuse payments for an unrelated red
// row — an unreachable domain probe, say.
func TestOnlyASendingBlockStopsAPayment(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.decodesTo("lnbcrt1fine", 50_000, "a payment")
	// Something else is wrong, and it does not block sending.
	h.spend.blocked = nil

	if resp := h.handle(t, MethodPayInvoice, payParams("lnbcrt1fine", 0)); resp.Error != nil {
		t.Fatalf("the payment was refused: %+v", resp.Error)
	}
}

// The three refusals that dispatch nothing, each answered in its own words and
// each returning the budget (d24.4 review).
func TestARefusalBeforeDispatchAnswersHonestlyAndReturnsTheBudget(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code string
		why  string
	}{{
		name: "the wallet ceiling",
		err:  fmt.Errorf("%w: %w", ErrNotDispatched, ErrInsufficientBalance),
		code: CodeInsufficientBalance,
		why:  "raise the balance",
	}, {
		name: "an invoice already being paid",
		err:  fmt.Errorf("%w: %w", ErrNotDispatched, ErrAlreadyPaying),
		code: CodeOther,
		why:  "wait for the payment already running — test-spec E7's loser",
	}, {
		name: "a freeze",
		err:  fmt.Errorf("%w: spending is frozen", ErrNotDispatched),
		code: CodeRestricted,
		why:  "take it up with the operator",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.grantPay()
			h.sendEnabled(true)
			h.setBudget(1_000_000)
			h.decodesTo("lnbcrt1refused", 100_000, "a payment")
			h.spend.reserveErr = tc.err

			resp := h.handle(t, MethodPayInvoice, payParams("lnbcrt1refused", 0))

			if resp.Error == nil || resp.Error.Code != tc.code {
				t.Fatalf("%s answered %+v, want %s — %s", tc.name, resp, tc.code, tc.why)
			}
			if used := h.budgetUsed(); used != 0 {
				t.Errorf("budget_used_msat = %d; nothing was dispatched, so the budget must "+
					"come back", used)
			}
		})
	}
}

// Test-spec E2, E3, E4: an invoice the ladder will not pay is refused BEFORE a
// reservation exists — no balance moved, no txn row, nothing to resolve.
func TestAnUnusableInvoiceIsRefusedBeforeAnyReservation(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(h *harness)
		params json.RawMessage
	}{{
		name:   "malformed",
		setup:  func(h *harness) { h.spend.decodeErr = errors.New("invalid bech32 string") },
		params: payParams("not-an-invoice", 0),
	}, {
		name: "expired",
		setup: func(h *harness) {
			h.decodesTo("lnbcrt1old", 50_000, "stale")
			h.decoded["lnbcrt1old"].ExpiresAt = h.clock.at.Add(-time.Second)
		},
		params: payParams("lnbcrt1old", 0),
	}, {
		name:   "amountless with no amount parameter",
		setup:  func(h *harness) { h.decodesTo("lnbcrt1any", 0, "you choose") },
		params: payParams("lnbcrt1any", 0),
	}, {
		name:   "no invoice at all",
		setup:  func(h *harness) {},
		params: json.RawMessage(`{}`),
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.grantPay()
			h.sendEnabled(true)
			tc.setup(h)

			resp := h.handle(t, MethodPayInvoice, tc.params)

			if resp.Error == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if h.spend.reserves != 0 {
				t.Errorf("%d reservations were made for an invoice that cannot be paid; §8's "+
					"ladder refuses before the debit commits", h.spend.reserves)
			}
			if used := h.budgetUsed(); used != 0 {
				t.Errorf("budget_used_msat = %d for a refused invoice", used)
			}
		})
	}
}

// E4's other half: an amountless invoice WITH an amount pays that amount.
func TestAnAmountlessInvoiceIsPaidWithTheRequestedAmount(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.decodesTo("lnbcrt1any", 0, "you choose")

	resp := h.handle(t, MethodPayInvoice, payParams("lnbcrt1any", 30_000))

	if resp.Error != nil {
		t.Fatalf("the payment was refused: %+v", resp.Error)
	}
	if got := h.spend.lastRequest().AmountMsat; got != 30_000 {
		t.Errorf("paid %d msat, want the requested 30,000", got)
	}
}

// Test-spec E5, asserted through a REAL failure rather than by inspection.
func TestBudgetArithmeticAcrossSuccessAndFailure(t *testing.T) {
	t.Run("a settled payment corrects to the actual fee", func(t *testing.T) {
		h := newHarness(t)
		h.grantPay()
		h.sendEnabled(true)
		h.setBudget(1_000_000)
		h.decodesTo("lnbcrt1ok", 100_000, "a payment")
		h.spend.fee = 1        // the route cost almost nothing...
		h.spend.maxFee = 5_000 // ...against a 5,000 msat reserve

		if resp := h.handle(t, MethodPayInvoice, payParams("lnbcrt1ok", 0)); resp.Error != nil {
			t.Fatalf("the payment was refused: %+v", resp.Error)
		}

		if used := h.budgetUsed(); used != 100_001 {
			t.Errorf("budget_used_msat = %d, want 100,001 — the reservation takes amount + "+
				"max_fee and the settle corrects it to amount + actual fee (§8)", used)
		}
	})

	t.Run("a failed payment consumes no budget", func(t *testing.T) {
		h := newHarness(t)
		h.grantPay()
		h.sendEnabled(true)
		h.setBudget(1_000_000)
		h.decodesTo("lnbcrt1no", 100_000, "a payment")
		h.spend.failed = true

		resp := h.handle(t, MethodPayInvoice, payParams("lnbcrt1no", 0))

		if resp.Error == nil || resp.Error.Code != CodePaymentFailed {
			t.Fatalf("a failed payment answered %+v, want PAYMENT_FAILED", resp)
		}
		if used := h.budgetUsed(); used != 0 {
			t.Errorf("budget_used_msat = %d after a failure; §8: a failed payment must not "+
				"consume budget", used)
		}
	})

	t.Run("a payment whose fate is unknown keeps its budget", func(t *testing.T) {
		h := newHarness(t)
		h.grantPay()
		h.sendEnabled(true)
		h.setBudget(1_000_000)
		h.decodesTo("lnbcrt1maybe", 100_000, "a payment")
		h.spend.maxFee = 5_000
		h.spend.payErr = errors.New("the node stopped answering")

		resp := h.handle(t, MethodPayInvoice, payParams("lnbcrt1maybe", 0))

		if resp.Error == nil {
			t.Fatal("a payment of unknown fate was reported as success")
		}
		if resp.Error.Code == CodePaymentFailed {
			t.Error("a payment that may be in flight was reported as FAILED; the client would " +
				"retry an invoice that is being paid right now")
		}
		if used := h.budgetUsed(); used != 105_000 {
			t.Errorf("budget_used_msat = %d; a payment whose outcome is unknown may have left "+
				"the node, so its budget stays taken until the resolver says otherwise", used)
		}
	})
}

// Ruling 4: ErrBooking on a SETTLED payment answers SUCCESS.
//
// The payment result is the truth about the money and the booking error is the
// truth about the ledger. Reporting PAYMENT_FAILED for a payment that paid would
// make the client retry a paid invoice.
func TestASettledPaymentThatCouldNotBeBookedStillAnswersSuccess(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.decodesTo("lnbcrt1booking", 100_000, "a payment")
	h.spend.preimage = "deadbeef"
	h.spend.bookingFailed = true

	resp := h.handle(t, MethodPayInvoice, payParams("lnbcrt1booking", 0))

	if resp.Error != nil {
		t.Fatalf("a settled payment answered %+v; the money left the node", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	if result["preimage"] != "deadbeef" {
		t.Errorf("result = %+v, want the preimage — it is the client's proof it paid", result)
	}
}

// Test-spec E7, from the NWC side: two requests for the same invoice, one
// reservation. The loser is told, and does not pay.
func TestTwoRequestsForOneInvoiceProduceOnePayment(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.decodesTo("lnbcrt1once", 100_000, "a payment")
	// The wallet's partial index is what guarantees this; the fake stands in for
	// it, refusing a second reservation against the same hash.
	h.spend.onePerHash = true

	var wg sync.WaitGroup
	answers := make([]Response, 2)
	for i := range answers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Two DIFFERENT request ids, so the replay cache is not what is
			// being tested here — the invoice is.
			event := h.request(t, h.client, MethodPayInvoice, payParams("lnbcrt1once", 0))
			event.Content += ""
			resp, _ := h.service.handle(context.Background(), h.conn, event)
			answers[i] = resp
		}()
	}
	wg.Wait()

	if h.spend.paid != 1 {
		t.Errorf("the node was asked to pay %d times for one invoice, want 1", h.spend.paid)
	}
}

// E8, and it is the DEFAULT connection: pay is off unless granted (§8's
// deliberate deviation from LNbits, which defaults it on).
func TestTheDefaultConnectionCannotPay(t *testing.T) {
	h := newHarness(t)
	h.sendEnabled(true)
	h.decodesTo("lnbcrt1nope", 1_000, "a payment")

	resp := h.handle(t, MethodPayInvoice, payParams("lnbcrt1nope", 0))

	if resp.Error == nil || resp.Error.Code != CodeRestricted {
		t.Fatalf("a connection with the default permissions answered %+v, want RESTRICTED", resp)
	}
	if got := store.DefaultPermissions(); contains(got, store.PermissionPay) {
		t.Errorf("DefaultPermissions() = %v and includes pay; §2's posture is that a new "+
			"connection cannot spend until that is granted deliberately", got)
	}
}

// Ruling 6: pay_invoice is advertised only when the connection may actually use
// it — the pay group AND sending enabled.
func TestPayInvoiceIsAdvertisedOnlyWhenItCanBeUsed(t *testing.T) {
	cases := []struct {
		name      string
		pay       bool
		sending   bool
		advertise bool
	}{
		{"granted and sending on", true, true, true},
		{"granted but sending off", true, false, false},
		{"sending on but not granted", false, true, false},
		{"neither", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			if tc.pay {
				h.grantPay()
			}
			h.sendEnabled(tc.sending)

			methods := h.service.advertised(t.Context(), h.conn)

			if got := contains(methods, string(MethodPayInvoice)); got != tc.advertise {
				t.Errorf("pay_invoice advertised = %v, want %v; the info event is a PROMISE, "+
					"and a pay button that answers RESTRICTED is a broken wallet app",
					got, tc.advertise)
			}
		})
	}
}

func contains[T comparable](haystack []T, needle T) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func payParams(bolt11 string, amountMsat int64) json.RawMessage {
	return payParamsWithMetadata(bolt11, amountMsat, "")
}

// payParamsWithMetadata is the same request with NWC-06's optional `metadata`,
// as a raw string so a test can send a shape no Go type of ours would produce —
// which is the point: the client chooses that object, not us. Pass "" for none.
//
// ONE function knows the request's shape. Two would drift, and the first draft
// of this pair already had: the metadata variant always emitted `amount` while
// payParams omits it below 1, so the zero-amount case existed in one of them.
func payParamsWithMetadata(bolt11 string, amountMsat int64, metadata string) json.RawMessage {
	fields := fmt.Sprintf(`"invoice":%q`, bolt11)
	if amountMsat > 0 {
		fields += fmt.Sprintf(`,"amount":%d`, amountMsat)
	}
	if metadata != "" {
		fields += `,"metadata":` + metadata
	}
	return json.RawMessage("{" + fields + "}")
}

// fakeSpend stands in for the wallet-and-node path §8 step 8 runs through.
type fakeSpend struct {
	mu            sync.Mutex
	ready         bool
	held          string
	maxFee        int64
	fee           int64
	preimage      string
	failed        bool
	payErr        error
	reserveErr    error
	bookingFailed bool
	decoded       map[string]*Bolt11
	decodeErr     error
	blocked       []string
	// beforePay blocks inside Pay, so a test can hold a payment in flight.
	beforePay  func()
	onePerHash bool

	reserves int
	paid     int
	hashes   map[string]bool
	requests []PayRequest
}

func (f *fakeSpend) CredentialReady() bool { return f.ready }

// SendingBlocked stands in for §11's Tier-2 report (d24.6).
func (f *fakeSpend) SendingBlocked(context.Context) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.blocked
}

// Decode answers from what the harness scripted. The map is shared with the
// harness rather than copied, so decodesTo can be called after construction.
func (f *fakeSpend) Decode(_ context.Context, bolt11 string) (Bolt11, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.decodeErr != nil {
		return Bolt11{}, f.decodeErr
	}
	decoded, ok := f.decoded[bolt11]
	if !ok {
		return Bolt11{}, errors.New("no such invoice")
	}
	return *decoded, nil
}

func (f *fakeSpend) Held(context.Context) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held, f.held != "", nil
}

func (f *fakeSpend) MaxFee(_ context.Context, _ int64) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxFee, nil
}

// Pay records the request under the lock, then blocks OUTSIDE it if the test
// asked to hold a payment in flight — holding the mutex would deadlock the
// assertions, which is a fake pretending to be a bug.
func (f *fakeSpend) Pay(_ context.Context, req PayRequest) (PayResult, error) {
	f.mu.Lock()
	f.reserves++
	f.requests = append(f.requests, req)
	reserveErr, payErr, failed := f.reserveErr, f.payErr, f.failed
	duplicate := false
	if f.onePerHash && reserveErr == nil {
		if f.hashes == nil {
			f.hashes = map[string]bool{}
		}
		duplicate = f.hashes[req.PaymentHash]
		f.hashes[req.PaymentHash] = true
	}
	if reserveErr == nil && !duplicate {
		f.paid++
	}
	result := PayResult{
		Settled: true, Preimage: secret.New(f.preimage), FeeMsat: f.fee,
		Unbooked: f.bookingFailed,
	}
	hold := f.beforePay
	f.mu.Unlock()

	if hold != nil {
		hold()
	}
	switch {
	case reserveErr != nil:
		return PayResult{}, reserveErr
	case duplicate:
		return PayResult{}, fmt.Errorf("%w: %w", ErrNotDispatched, ErrAlreadyPaying)
	case payErr != nil:
		return PayResult{}, payErr
	case failed:
		return PayResult{Failed: true, FailureReason: "NO_ROUTE"}, nil
	}
	return result, nil
}

func (f *fakeSpend) payments() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.paid
}

func (f *fakeSpend) lastRequest() PayRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[len(f.requests)-1]
}

// A slow payment must not starve the requests behind it (d24.4 review).
//
// LND's PaymentTimeout and §8's freshness window are both 60 seconds, and they
// were chosen independently. Read serially, a request delivered while a payment
// is running is read after the window has passed and answered "request expired"
// — so the operator who taps pay and then taps refresh-balance is told their own
// balance request is stale.
func TestARunningPaymentDoesNotBlockTheRequestsBehindIt(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.decodesTo("lnbcrt1slow", 50_000, "a slow payment")

	// The payment blocks until the test lets it finish.
	releasePayment := make(chan struct{})
	h.spend.beforePay = func() { <-releasePayment }

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	conn := h.openConnection(ctx, h.conn.row())
	conn.identity = h.counting
	done := make(chan struct{})
	go func() { defer close(done); h.service.serve(ctx, conn, testRelay) }()

	h.relays.deliver(h.request(t, h.client, MethodPayInvoice, payParams("lnbcrt1slow", 0)))
	waitFor(t, "the payment to be in flight", func() bool { return h.spend.payments() == 1 })

	// A second request arrives while the payment is still going.
	h.wallet.balance = 4_242
	h.relays.deliver(h.request(t, h.client, MethodGetBalance, nil))

	waitFor(t, "the balance request to be answered while the payment runs", func() bool {
		return len(h.relays.published()) == 1
	})

	close(releasePayment)
	waitFor(t, "the payment to be answered too", func() bool {
		return len(h.relays.published()) == 2
	})

	cancel()
	conn.close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("serve did not return; a shutdown must wait for what is in flight, not hang on it")
	}
}

// A missing invoice is a parameter complaint, and parameter complaints do not
// jump the ladder (d24.4 review).
//
// Answering "invoice is required" on a node where sending is off tells the
// operator their request was malformed when the truth is that this node will not
// pay anything at all.
func TestAMissingInvoiceDoesNotJumpTheLadder(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(false)

	resp := h.handle(t, MethodPayInvoice, json.RawMessage(`{}`))

	if resp.Error == nil || resp.Error.Code != CodeRestricted {
		t.Errorf("a request with no invoice on a send-disabled node answered %+v, want "+
			"RESTRICTED — the earliest failure is what the client is told", resp)
	}
}

// A freeze answers with ITS message, not the Tier-2 gate's.
//
// §11's report carries rows for both freezes as well, each declaring
// Blocks: BlocksSending — so a Tier-2 gate consulted before step 3 answers every
// freeze with the generic "see the Security page", and ruling 2's differentiated
// messages become unreachable in a shipped binary. Found by review; nothing
// caught it, because the fake keeps the two independent and the regtest arc
// never puts a freeze up over NWC.
func TestAFreezeAnswersWithItsOwnMessageNotTheGenericOne(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.decodesTo("lnbcrt1frozen2", 50_000, "a payment")
	// Both are true at once, which is what production looks like: the freeze
	// rows are IN the report.
	h.spend.held = "3 payments from a previous run are still being resolved"
	h.spend.blocked = []string{"wallet.unresolved_payments"}

	resp := h.handle(t, MethodPayInvoice, payParams("lnbcrt1frozen2", 0))

	if resp.Error == nil || resp.Error.Code != CodeRestricted {
		t.Fatalf("answered %+v, want RESTRICTED", resp)
	}
	if !strings.Contains(resp.Error.Message, "being resolved") {
		t.Errorf("the client was told %q; ruling 2 says the two freezes are distinguished by "+
			"their message, and this one clears itself", resp.Error.Message)
	}
}

// payRequests is every PayRequest the ladder handed this fake, copied under the
// lock so a concurrent test can read it safely.
func (f *fakeSpend) payRequests() []PayRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// nwcMetadata wraps an event as the NWC-06 object a client actually sends, which
// is what the column holds since the whole object became the stored thing.
func nwcMetadata(event string) string { return `{"nostr":` + event + `}` }

// aPayee is the p tag anOutgoingZapRequest carries: on an outgoing row, the only
// identity there is.
var aPayee = lnurltest.Hex64('c')

// anOutgoingZapRequest is the kind 9734 event a client signs before fetching a
// zap invoice, and then — until NWC-06 — threw away. The `p` tag is the PAYEE.
//
// REALLY SIGNED, from the shared fixture builder, because doy.4 verifies the
// signature and the id before the row is written. A hand-written literal with a
// plausible-looking `sig` was what this was before, and it stopped being a
// fixture the moment the verification landed — which is the useful shape of that
// failure: the test was asserting storage of something no client could produce.
func anOutgoingZapRequest(t *testing.T, amountMsat int64) string {
	t.Helper()
	return string(lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
		e.Content = "thanks for the write-up"
		e.Tags = gonostr.Tags{
			{"p", aPayee},
			{"relays", "wss://relay.example"},
			{"amount", strconv.FormatInt(amountMsat, 10)},
		}
	}))
}

// doy.2: the event the client signed reaches the reservation VERBATIM.
//
// Verbatim is not fussiness. A nostr event id is a hash over a canonical
// serialisation of the event's own fields, so a round trip through a Go map
// reorders and renumbers it into something whose id no longer verifies — and
// doy.4's whole job is to verify exactly that. Storing the client's bytes is
// what keeps that check available.
func TestAPaymentCarriesTheZapRequestTheClientSigned(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)

	// A ZAP invoice, which commits to the event it was minted for. An ordinary
	// invoice commits to nothing and since y09 stores nothing, so a fixture
	// using one here would be asserting storage of an unbound claim.
	event := anOutgoingZapRequest(t, 21_000)
	h.decodesZapTo("lnbcrt1zap", 21_000, event)
	metadata := fmt.Sprintf(
		`{"nostr":%s,"recipient_data":{"identifier":"alice@example.com"},"comment":"thanks"}`,
		event)
	resp := h.handle(t, MethodPayInvoice, payParamsWithMetadata("lnbcrt1zap", 21_000, metadata))

	if resp.Error != nil {
		t.Fatalf("the payment was refused: %+v", resp.Error)
	}
	got := h.spend.lastRequest().Metadata
	if got != metadata {
		t.Errorf("the reservation carries\n%s\nwant the client's object unchanged\n%s",
			got, metadata)
	}
	// AND ITS SIBLINGS SURVIVED, which is the whole reason the column holds the
	// object rather than the event: a client's own row renderer falls back to
	// recipient_data.identifier when a profile has not resolved, and storing
	// only `nostr` handed every row back nameless.
	if !strings.Contains(got, "alice@example.com") {
		t.Errorf("recipient_data did not survive the round trip:\n%s", got)
	}
	// The memo stays empty, which is the fact the whole epic exists for: a
	// NIP-57 invoice has no plaintext description to lift, so without the zap
	// request this row would have nothing whatsoever to say.
	if got := h.spend.lastRequest().Description; got != "" {
		t.Errorf("Description = %q; a zap invoice has no memo, and a test that finds one is "+
			"testing a fixture rather than the path", got)
	}
}

// AND METADATA NEVER COSTS A PAYMENT. Every one of these is dropped, logged, and
// the money still moves.
//
// This is the constraint that made doy.4 its own bead: a validation step bolted
// onto the pay path in a hurry is exactly the thing that acquires an error
// return. A cosmetic field that can block a payment is a worse bug than a blank
// row, so the assertion here is the SUCCESS, and the empty column is secondary.
func TestMetadataNeverCostsAPayment(t *testing.T) {
	// EVERY ROW SCRIPTS THE INVOICE'S COMMITMENT, and that is not decoration.
	//
	// This table scripted a plain invoice — no description_hash — until a
	// cumulative review of the whole branch caught what that had come to mean.
	// y09 added the commits-to-nothing arm ABOVE the verifier, so every row was
	// dropping there and four of them had stopped testing the thing they are
	// named for: the whole `lnurl.CheckOutgoingZapRequest` call could be deleted
	// and all eleven stayed green. Proven by deleting it.
	//
	// So each row now says what the invoice commits to, and the rows that are
	// about the verifier commit to their OWN bytes — otherwise the hash refuses
	// them first and the signature and the amount tag are never reached. The
	// sibling table in internal/lnurl got this treatment when it was written
	// (its `commits` helper); this one did not, and drifted.
	//
	// A plain event for the rows where the commitment is beside the point: they
	// are refused before the invoice is ever consulted, and an empty hash would
	// put them all back on the arm this comment exists to route around.
	plain := anOutgoingZapRequest(t, 21_000)
	// Over NWC-06's bound, and valid in every other way — so nothing but the
	// bound can be what rejects it.
	oversized := fmt.Sprintf(`{"nostr":%s,"comment":%q}`, plain, strings.Repeat("x", 4096))
	// doy.4's own case: well-formed, correctly shaped, and NOT what any client
	// could have signed. The verification refuses it and the money still moves,
	// which is the constraint that made doy.4 a separate bead.
	forgedEvent := strings.Replace(plain,
		`"content":"thanks for the write-up"`, `"content":"paid someone else"`, 1)
	// And an event whose amount tag disagrees with the payment: signed, intact,
	// and a false statement about the operator's own money.
	wrongAmountEvent := anOutgoingZapRequest(t, 1_000_000)

	for _, c := range []struct {
		name     string
		metadata string
		// commitsTo is the event the paid invoice commits to. The rows that must
		// reach the verifier commit to their own, so the check they name is the
		// one that refuses them.
		commitsTo string
	}{
		{"a signature that does not cover the content",
			nwcMetadata(forgedEvent), forgedEvent},
		{"an amount tag that disagrees with the payment",
			nwcMetadata(wrongAmountEvent), wrongAmountEvent},
		{"an array where an object belongs", `["nostr"]`, plain},
		{"a bare string", `"nostr"`, plain},
		{"a number", `12345`, plain},
		{"null", `null`, plain},
		{"over the character bound", oversized, plain},
		{"a nostr member that is not an object", `{"nostr":"not an event"}`, plain},
		{"a nostr member that is null", `{"nostr":null}`, plain},
		{"no nostr member at all",
			`{"recipient_data":{"identifier":"alice@example.com"}}`, plain},
		{"an empty object", `{}`, plain},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.grantPay()
			h.sendEnabled(true)
			h.decodesZapTo("lnbcrt1zap", 21_000, c.commitsTo)

			resp := h.handle(t, MethodPayInvoice,
				payParamsWithMetadata("lnbcrt1zap", 21_000, c.metadata))

			if resp.Error != nil {
				t.Fatalf("the payment was REFUSED over metadata: %+v\nthe money must move "+
					"whatever the client attached to it", resp.Error)
			}
			if h.spend.payments() != 1 {
				t.Fatalf("payments = %d, want 1", h.spend.payments())
			}
			if got := h.spend.lastRequest().Metadata; got != "" {
				t.Errorf("stored %q; nothing here is an event this node should keep", got)
			}
		})
	}
}

// A dropped blob leaves a trace, because a client whose metadata silently
// vanishes has no way to find out why — and neither would the operator reading
// the log after they asked.
//
// Only for a blob that was MEANT as something: an absent `nostr` member is the
// ordinary case (a pasted bolt11, a mint top-up) and logging it would turn a
// non-event into a line per payment.
func TestADroppedMetadataBlobSaysWhy(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.decodesTo("lnbcrt1zap", 21_000, "")

	h.handle(t, MethodPayInvoice, payParamsWithMetadata("lnbcrt1zap", 21_000, `["nostr"]`))
	if !strings.Contains(h.logs.String(), "not a JSON object") {
		t.Errorf("the log does not say why the metadata was dropped:\n%s", h.logs.String())
	}

	quiet := newHarness(t)
	quiet.grantPay()
	quiet.sendEnabled(true)
	quiet.decodesTo("lnbcrt1zap", 21_000, "")
	quiet.handle(t, MethodPayInvoice, payParamsWithMetadata("lnbcrt1zap", 21_000,
		`{"recipient_data":{"identifier":"alice@example.com"}}`))
	if strings.Contains(quiet.logs.String(), "did not store") {
		t.Errorf("metadata with nothing to store logged a drop; a pasted bolt11 is the "+
			"ordinary case and this would be a line per payment:\n%s", quiet.logs.String())
	}
}

// y09: a stored zap request must HASH TO THE INVOICE it accompanies.
//
// Signature and id prove only that a blob the caller authored is internally
// consistent — outbound the signer is the payer, so the caller chose that key.
// Nothing in kind, signature, id or the p tag's shape says the event is about
// THIS payment, and the amount tag is optional, so omitting it removed the only
// external cross-check there was.
//
// NIP-57 supplies the binding and this app already mints it: a zap invoice's
// description_hash IS sha256 of the raw zap request. So the check is the exact
// inverse of lnurl.ZapHash, and it binds the payee, the comment and the amount
// in one comparison rather than three.
//
// FOUND BY A SECURITY REVIEW OF THIS BRANCH, and the harm it removes is
// concealment rather than theft: the attacker is a pairing that already holds
// the pay group and can already move money. What it could also do was render an
// exfiltration payment as "to npub1<someone trusted>" on the operator's own
// history page, and echo the same fabrication to every other pairing.
func TestAnOutgoingZapRequestMustHashToTheInvoiceItAccompanies(t *testing.T) {
	t.Run("a request the invoice commits to is stored", func(t *testing.T) {
		h := newHarness(t)
		h.grantPay()
		h.sendEnabled(true)
		event := anOutgoingZapRequest(t, 21_000)
		h.decodesZapTo("lnbcrt1zap", 21_000, event)

		resp := h.handle(t, MethodPayInvoice,
			payParamsWithMetadata("lnbcrt1zap", 21_000, nwcMetadata(event)))
		if resp.Error != nil {
			t.Fatalf("the payment was refused: %+v", resp.Error)
		}
		if got := h.spend.lastRequest().Metadata; got != nwcMetadata(event) {
			t.Errorf("stored %q, want the object whose event the invoice commits to", got)
		}
	})

	// THE ATTACK, as the review described it: a bolt11 for a destination the
	// caller controls, with a well-formed self-signed event naming somebody else
	// as the payee. Every check that existed before passes; this one does not.
	t.Run("a request the invoice does not commit to is dropped", func(t *testing.T) {
		h := newHarness(t)
		h.grantPay()
		h.sendEnabled(true)
		// The invoice commits to one event; the client attaches another. Both
		// are validly signed — that is the point.
		h.decodesZapTo("lnbcrt1zap", 21_000, anOutgoingZapRequest(t, 21_000))
		fabricated := string(lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
			e.Content = "monthly support"
			e.Tags = gonostr.Tags{{"p", lnurltest.Hex64('d')}}
		}))

		resp := h.handle(t, MethodPayInvoice,
			payParamsWithMetadata("lnbcrt1zap", 21_000, nwcMetadata(fabricated)))

		if resp.Error != nil {
			t.Fatalf("the payment was REFUSED over metadata: %+v — the money must move "+
				"whatever the client attached to it", resp.Error)
		}
		if h.spend.payments() != 1 {
			t.Fatalf("payments = %d, want 1", h.spend.payments())
		}
		if got := h.spend.lastRequest().Metadata; got != "" {
			t.Errorf("stored %q; this event names a payee the invoice says nothing about, "+
				"and the operator's history would report it as fact", got)
		}
		if !strings.Contains(h.logs.String(), "description_hash") {
			t.Errorf("the log does not say why it was dropped:\n%s", h.logs.String())
		}
	})

	// AND AN INVOICE WITH NO description_hash STORES NOTHING, which is the arm
	// that makes the check worth having: without it the bypass is to pay a plain
	// invoice, which commits to no event at all, and attach whatever you like.
	t.Run("an invoice that commits to nothing stores nothing", func(t *testing.T) {
		h := newHarness(t)
		h.grantPay()
		h.sendEnabled(true)
		h.decodesTo("lnbcrt1plain", 21_000, "a plain invoice")

		resp := h.handle(t, MethodPayInvoice, payParamsWithMetadata("lnbcrt1plain", 21_000,
			nwcMetadata(anOutgoingZapRequest(t, 21_000))))

		if resp.Error != nil {
			t.Fatalf("the payment was refused: %+v", resp.Error)
		}
		if got := h.spend.lastRequest().Metadata; got != "" {
			t.Errorf("stored %q against an invoice with no description_hash; a zap invoice "+
				"always has one, so this is either not a zap or not this zap", got)
		}
		// AND IT SAYS WHICH OF THE TWO, which is the whole reason this arm is
		// separate from the hash comparison. Falling through to that comparison
		// drops the row all the same — sha256 hex is never "" — so the behaviour
		// would be identical and the arm would look removable. What differs is
		// the answer an operator gets when they ask why their zap is unlabelled:
		// "this invoice commits to nothing" and "it commits to something else"
		// are different problems with different fixes.
		if !strings.Contains(h.logs.String(), "commits to no description_hash") {
			t.Errorf("the log blames a hash MISMATCH for an invoice that has no hash at "+
				"all:\n%s", h.logs.String())
		}
	})
}

// The 4096 is CHARACTERS, which is the spec's own word — and this counted bytes
// until the client side pointed out what that costs.
//
// A conformant client counts characters, so a byte bound rejects payloads it
// believed were inside the limit. This one is ~3,700 characters and ~9,600 bytes:
// fine by NWC-06, dropped by the old rule, and the operator would have seen a
// comment in their own language silently cost them the label.
func TestTheMetadataBoundCountsCharactersNotBytes(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	event := anOutgoingZapRequest(t, 21_000)
	h.decodesZapTo("lnbcrt1zap", 21_000, event)

	// Three bytes per rune in UTF-8, one UTF-16 unit each on the client's side.
	comment := strings.Repeat("感", 3_000)
	metadata := fmt.Sprintf(`{"nostr":%s,"comment":%q}`, event, comment)
	if runes := utf8.RuneCountInString(metadata); runes > MaxMetadataChars {
		t.Fatalf("the fixture is %d characters, over the bound it is meant to be inside",
			runes)
	}
	if len(metadata) <= MaxMetadataChars {
		t.Fatalf("the fixture is %d bytes; it has to EXCEED %d or it proves nothing about "+
			"which unit is counted", len(metadata), MaxMetadataChars)
	}

	resp := h.handle(t, MethodPayInvoice,
		payParamsWithMetadata("lnbcrt1zap", 21_000, metadata))

	if resp.Error != nil {
		t.Fatalf("the payment was refused: %+v", resp.Error)
	}
	if got := h.spend.lastRequest().Metadata; got != metadata {
		t.Errorf("a %d-character, %d-byte object was dropped; NWC-06 bounds characters and "+
			"a conformant client counts them", utf8.RuneCountInString(metadata), len(metadata))
	}
}

// The byte ceiling is the OUTER guard and it says so, which is the reason it is
// checked first and the reason it has its own test (plant F found it had none).
//
// It cannot refuse anything inside the character bound — UTF-8 spends at most
// four bytes on a code point and the ceiling is exactly four times the bound —
// so behaviourally the rune check below would reject this blob too. What the
// ceiling buys is that an absurd payload is refused on an O(1) length rather
// than decoded first to count its characters, and that the operator is told
// which of the two limits it broke.
func TestAnAbsurdlyLargeMetadataBlobIsRefusedOnItsLength(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	event := anOutgoingZapRequest(t, 21_000)
	h.decodesZapTo("lnbcrt1zap", 21_000, event)

	metadata := fmt.Sprintf(`{"nostr":%s,"comment":%q}`,
		event, strings.Repeat("x", MaxMetadataBytes))
	if len(metadata) <= MaxMetadataBytes {
		t.Fatalf("the fixture is %d bytes, inside the ceiling it is meant to break",
			len(metadata))
	}

	resp := h.handle(t, MethodPayInvoice,
		payParamsWithMetadata("lnbcrt1zap", 21_000, metadata))

	if resp.Error != nil {
		t.Fatalf("the payment was refused over metadata: %+v", resp.Error)
	}
	if got := h.spend.lastRequest().Metadata; got != "" {
		t.Errorf("stored %d bytes", len(got))
	}
	if !strings.Contains(h.logs.String(), "byte ceiling") {
		t.Errorf("the log blames the character bound for a blob that broke the byte "+
			"ceiling; they are different limits with different reasons:\n%s", h.logs.String())
	}
}
