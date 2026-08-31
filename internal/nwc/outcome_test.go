package nwc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
	"unicode/utf8"
)

// A capability refusal reaches §12's DURABLE TRAIL, not just the log (d24.14).
//
// The 0.1.9 field trip's sharpest finding: a RESTRICTED refusal produced zero
// log lines and no audit row, so someone probing a revoked connection left no
// trace at all. audit_events recorded every action the operator took and nothing
// a connection did.
func TestACapabilityRefusalIsAudited(t *testing.T) {
	h := newHarness(t)
	// The connection holds no pay group, which is the commonest boundary: a
	// pairing created without it, asking to spend.
	h.spend.ready = true
	h.sendEnabled(true)

	h.handle(t, MethodPayInvoice, json.RawMessage(`{"invoice":"lnbc210n1validlooking"}`))

	rows := h.audit.events()
	if len(rows) != 1 {
		t.Fatalf("%d audit rows, want 1 — a paired app asking for a capability it does not "+
			"have must leave a durable trace (§12)", len(rows))
	}
	if rows[0].event != logging.EventConnectionRefuse {
		t.Errorf("event = %q, want connection.refuse", rows[0].event)
	}
	if rows[0].attrs["method"] != string(MethodPayInvoice) {
		t.Errorf("the row does not name the method: %v", rows[0].attrs)
	}
	if rows[0].attrs["code"] != CodeRestricted {
		t.Errorf("code = %q, want RESTRICTED", rows[0].attrs["code"])
	}
}

// A refusal at a LIMIT is NOT audited (ruling 3).
//
// An honest client meeting its own budget is routine, not a security event, and
// auditing it would drown the boundary refusals in exactly the noise that makes
// a trail unreadable. It still LOGS, at INFO, because "why did my phone stop
// paying?" must not need debug mode (§12).
func TestALimitRefusalLogsAtInfoAndIsNotAudited(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.setBudget(1_000) // less than the payment plus its reserve
	h.decodesTo("lnbc210n1overbudget", 21_000, "over budget")

	resp := h.handle(t, MethodPayInvoice, json.RawMessage(`{"invoice":"lnbc210n1overbudget"}`))
	if resp.Error == nil || resp.Error.Code != CodeQuotaExceeded {
		t.Fatalf("want QUOTA_EXCEEDED, got %+v", resp)
	}

	if rows := h.audit.events(); len(rows) != 0 {
		t.Errorf("a budget refusal wrote %d audit rows; it is an honest client meeting its own "+
			"limit, and auditing it would bury the boundary refusals", len(rows))
	}
	if !loggedAt(t, h.logs.String(), "INFO", "refused by a limit") {
		t.Errorf("no INFO line for a budget refusal; an operator would need debug mode to "+
			"answer \"why did my phone stop paying?\" (§12)\n%s", h.logs.String())
	}
}

// A SUCCESSFUL payment logs at INFO and writes NO audit row (ruling 1).
//
// §12 is explicit that money's durable structured record is the txns table, so a
// second one would be two statements of one fact. What the log line carries is
// what the row cannot: which connection, and the ladder's outcome.
func TestASettledPaymentLogsAtInfoAndIsNotAudited(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.decodesTo("lnbc210n1good", 21_000, "coffee")
	h.spend.fee = 2_055
	h.spend.preimage = "28aa50a3"

	resp := h.handle(t, MethodPayInvoice, json.RawMessage(`{"invoice":"lnbc210n1good"}`))
	if resp.Error != nil {
		t.Fatalf("the payment was refused: %+v", resp.Error)
	}

	if rows := h.audit.events(); len(rows) != 0 {
		t.Errorf("a successful payment wrote %d audit rows; the txns table is money's durable "+
			"record (§12) and a second one is two statements of one fact", len(rows))
	}
	logs := h.logs.String()
	if !loggedAt(t, logs, "INFO", "an NWC payment settled") {
		t.Errorf("a real payment produced no INFO line — which is exactly what the field trip "+
			"found\n%s", logs)
	}
	// And NEVER the preimage — the VALUE, not the key. Asserting the key's
	// absence passes for a preimage logged as "proof", or folded into an error
	// string, which is exactly how one escapes (found by review).
	if strings.Contains(logs, h.spend.preimage) {
		t.Errorf("the preimage %q reached the log:\n%s", h.spend.preimage, logs)
	}
}

// An ordinary request logs at DEBUG (ruling 5).
//
// The trip watched Amethyst poll get_info and get_balance eleven times in two
// idle minutes. At INFO that fills an operator's log with nothing, and §12
// requires INFO to stand alone for diagnosis.
func TestAnOrdinaryRequestLogsAtDebug(t *testing.T) {
	h := newHarness(t)
	h.handle(t, MethodGetBalance, nil)

	logs := h.logs.String()
	if !loggedAt(t, logs, "DEBUG", "an NWC request was answered") {
		t.Errorf("get_balance produced no DEBUG line:\n%s", logs)
	}
	if loggedAt(t, logs, "INFO", "an NWC request was answered") {
		t.Errorf("an idle poll logged at INFO; eleven of these in two minutes is what a paired "+
			"phone does while doing nothing\n%s", logs)
	}
}

// The audited refusal is BOUNDED (ruling 4, bcf's lesson).
//
// A paired client whose credential was revoked can hammer, and §12's trail is a
// fixed ring trimmed oldest-first — so an unbounded refusal event would let one
// confused wallet app evict macaroon.bake and guard.reject.
func TestAuditedRefusalsAreBoundedPerHour(t *testing.T) {
	h := newHarness(t)
	h.sendEnabled(true)

	for i := 0; i < MaxAuditedRefusalsPerHour+5; i++ {
		h.service.auditRefusal(t.Context(), 1, MethodPayInvoice, CodeRestricted)
	}

	if got := len(h.audit.events()); got != MaxAuditedRefusalsPerHour {
		t.Errorf("%d audit rows for %d refusals, want the %d bound — past it the refusal still "+
			"happens and still logs; what it must not do is evict older rows",
			got, MaxAuditedRefusalsPerHour+5, MaxAuditedRefusalsPerHour)
	}
	// Past the bound it is still SAID. Silence would be worse than repetition.
	if !strings.Contains(h.logs.String(), "past the hourly audit bound") {
		t.Error("refusals past the bound vanished entirely")
	}
}

// A service with NO auditor still refuses, and says so without claiming a trail
// entry that does not exist.
func TestARefusalWithoutAnAuditorLogsWithoutAnAuditAttribute(t *testing.T) {
	h := newHarness(t)
	h.service.audit = nil

	h.service.auditRefusal(t.Context(), 1, MethodPayInvoice, CodeRestricted)

	logs := h.logs.String()
	if !strings.Contains(logs, "no audit trail is attached") {
		t.Errorf("the refusal was not reported at all:\n%s", logs)
	}
	if strings.Contains(logs, `"audit"`) {
		t.Errorf("a hand-built audit= attribute claimed a trail entry that was never written "+
			"(the Auditor's contract is the line AND the row):\n%s", logs)
	}
}

// loggedAt reports whether the JSON log holds a line at level whose message
// contains substr.
func loggedAt(t *testing.T, logs, level, substr string) bool {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		msg, _ := entry["msg"].(string)
		if entry["level"] == level && strings.Contains(msg, substr) {
			return true
		}
	}
	return false
}

// The ladder hands the payer WHICH connection asked and WHAT the invoice was
// for (d24.15, d24.16).
//
// Both end up on the txns row. The connection is what lets the startup resolver
// find whose budget a crash-recovered payment over-charged — the column has
// existed since migration 0001 and nothing ever wrote it, which is the
// structural reason that arm was missing. The description is what stops the
// operator's history being a list of unlabelled debits.
func TestThePayRequestCarriesTheConnectionAndTheDescription(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.decodesTo("lnbc210n1labelled", 21_000, "a coffee at the market")

	if resp := h.handle(t, MethodPayInvoice,
		json.RawMessage(`{"invoice":"lnbc210n1labelled"}`)); resp.Error != nil {
		t.Fatalf("the payment was refused: %+v", resp.Error)
	}

	reqs := h.spend.payRequests()
	if len(reqs) != 1 {
		t.Fatalf("%d pay requests, want 1", len(reqs))
	}
	if reqs[0].ConnectionID != h.conn.row().ID {
		t.Errorf("the pay request names connection %d, want %d — without it the resolver "+
			"cannot correct a recovered payment's budget", reqs[0].ConnectionID, h.conn.row().ID)
	}
	if reqs[0].Description != "a coffee at the market" {
		t.Errorf("the pay request carries description %q, want the invoice's own memo",
			reqs[0].Description)
	}
}

// A payment that SETTLED but could not be BOOKED leaves the budget correction to
// the resolver, and does not apply it here as well.
//
// Found by review. The row stays pending, so the resolver closes it on the next
// start and applies `actual - reserved` — the same number the ladder would have
// applied. Both firing credits the connection the unused fee reserve twice, and
// it can then spend past its budget by one reserve per unbooked payment. The
// permissive direction, in the one path this wave added a bool to keep
// idempotent.
func TestAnUnbookedPaymentLeavesTheBudgetCorrectionToTheResolver(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.setBudget(1_000_000)
	h.decodesTo("lnbc210n1unbooked", 21_000, "unbooked")
	h.spend.fee = 55
	h.spend.bookingFailed = true

	if resp := h.handle(t, MethodPayInvoice,
		json.RawMessage(`{"invoice":"lnbc210n1unbooked"}`)); resp.Error != nil {
		t.Fatalf("an unbooked payment must still answer success: %+v", resp.Error)
	}

	// The reservation took amount + the fake's max fee and nothing gave any of
	// it back: the resolver will, once it closes the row.
	if got, want := h.budgetUsed(), int64(21_000)+h.spend.maxFee; got != want {
		t.Errorf("budget_used = %d msat, want the full reservation %d — the ladder corrected a "+
			"reservation it no longer owns, and the resolver will correct it again", got, want)
	}
}

// list_transactions reveals a preimage ONLY for this connection's own payments.
//
// Found by review, and it is the sharpest thing in this wave. The history filter
// has no connection dimension — store.TxnFilter is dates, limit, offset,
// direction and paid-state — so the first version of txnResult handed every
// paired app the preimage of every zap the node had ever received and of every
// payment any other app or the operator had made. A preimage is the
// proof-of-payment token: an app holding one can assert to anyone that it paid
// an invoice it never paid. "Lets this app list payments in and out" is not
// consent to that, and `history` is granted by default.
func TestListTransactionsRevealsOnlyThisConnectionsPreimages(t *testing.T) {
	h := newHarness(t)
	mine := h.conn.row().ID
	h.invoices.txns = []store.Txn{{
		Kind: store.KindPaymentOut, State: store.TxnSettled, AmountMsat: 21_000,
		PaymentHash: "mine", Preimage: secret.New("proof-of-mine"), NWCConnectionID: mine,
	}, {
		Kind: store.KindPaymentOut, State: store.TxnSettled, AmountMsat: 21_000,
		PaymentHash: "theirs", Preimage: secret.New("proof-of-theirs"),
		NWCConnectionID: mine + 1,
	}, {
		// An incoming zap: nobody's connection asked for it, and its preimage is
		// the PAYER's proof.
		Kind: store.KindInvoiceIn, State: store.TxnSettled, AmountMsat: 21_000,
		PaymentHash: "received", Preimage: secret.New("proof-of-received"),
	}}

	resp := h.handle(t, MethodListTransactions, json.RawMessage(`{}`))
	if resp.Error != nil {
		t.Fatalf("list_transactions was refused: %+v", resp.Error)
	}
	body, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(body)

	if !strings.Contains(rendered, "proof-of-mine") {
		t.Errorf("this connection's OWN payment came back without its proof:\n%s", rendered)
	}
	for _, leaked := range []string{"proof-of-theirs", "proof-of-received"} {
		if strings.Contains(rendered, leaked) {
			t.Errorf("a preimage this connection never earned (%s) was handed to it; it could "+
				"assert to anyone that it made that payment:\n%s", leaked, rendered)
		}
	}
}

// The invoice memo this app STORES is bounded.
//
// The same reasoning maxMethodLength already carries, applied to the other
// client-chosen string that now reaches a durable row: a paired app can put
// ~64 kB in a NIP-44 payload, the memo of a bolt11 it supplies is entirely its
// choice, and since d24.16 that memo is written to the ledger on an SD card and
// echoed back by list_transactions. Bounded on the way IN, because a row already
// written cannot be un-written. Found by review.
func TestAnEnormousInvoiceMemoIsNotStoredWhole(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)
	h.decodesTo("lnbc210n1huge", 21_000, strings.Repeat("a", 40_000))

	if resp := h.handle(t, MethodPayInvoice,
		json.RawMessage(`{"invoice":"lnbc210n1huge"}`)); resp.Error != nil {
		t.Fatalf("the payment was refused: %+v", resp.Error)
	}

	reqs := h.spend.payRequests()
	if len(reqs) != 1 {
		t.Fatalf("%d pay requests, want 1", len(reqs))
	}
	if got := len(reqs[0].Description); got > MaxDescriptionLength {
		t.Errorf("%d bytes of client-chosen memo reached the ledger row, want at most %d",
			got, MaxDescriptionLength)
	}
	if !utf8.ValidString(reqs[0].Description) {
		t.Error("the truncated memo is not valid UTF-8; it is stored and rendered")
	}
}

// BudgetCorrection is the one definition both paths use, and this pins the
// numbers the 0.1.9 field trip measured on a real box.
//
// It exists as a function at all because review found the arithmetic written out
// twice — once in the ladder, once in the startup resolver — with a comment
// claiming it had been "moved" when it had been copied. Nothing kept them in
// step, and the numbers are money.
func TestBudgetCorrectionMatchesTheFieldTripsNumbers(t *testing.T) {
	// The trip's own payment: 21 000 msat, a 10 000 msat reserve, a route that
	// actually cost 2 055. The ladder charges 31 000 and corrects to 23 055; the
	// recovery path did not, and charged 31 000 where 23 055 was right.
	if got := BudgetCorrection(true, 21_000, 10_000, 2_055); got != -7_945 {
		t.Errorf("a settled payment corrects by %d msat, want -7945 — the unused fee reserve", got)
	}
	// §8: a failed payment consumes no budget. The whole reservation, back.
	if got := BudgetCorrection(false, 21_000, 10_000, 0); got != -31_000 {
		t.Errorf("a failed payment corrects by %d msat, want -31000 — the whole reservation", got)
	}
	// A route that cost MORE than the reserve cannot normally settle, but that
	// refusal is what produces an unbooked payment. Signed, so it is covered:
	// under-counting would leave a connection with budget it has already spent.
	if got := BudgetCorrection(true, 21_000, 10_000, 12_000); got != 2_000 {
		t.Errorf("an over-reserve settle corrects by %d msat, want +2000", got)
	}
	// Exactly the reserve: nothing to give back, and nothing is written.
	if got := BudgetCorrection(true, 21_000, 10_000, 10_000); got != 0 {
		t.Errorf("a payment that used its whole reserve corrects by %d msat, want 0", got)
	}
}
