package nwc

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
)

// exhaust spends one pairing's whole burst on get_balance, asserting every one of
// them was served — a bucket that refused inside its own burst would make every
// assertion after this one about the wrong thing.
func (h *harness) exhaust(t *testing.T, conn *connection) {
	t.Helper()
	for i := range RequestBurst {
		event := h.requestTo(t, conn, h.clientFor(conn), nostr.NIP44, MethodGetBalance, nil, h.clock.at)
		resp, answered := h.service.handle(t.Context(), conn, event)
		if !answered || resp.Error != nil {
			t.Fatalf("request %d of a burst of %d was not served: answered=%v %+v",
				i+1, RequestBurst, answered, resp.Error)
		}
	}
}

// clientFor is the client identity that may speak for a pairing the harness built.
func (h *harness) clientFor(conn *connection) nostr.Identity {
	if conn == h.conn {
		return h.client
	}
	return h.otherClient
}

// l3j criterion 1: a client over the limit is answered RATE_LIMITED, the answer
// names the method, and NOTHING reaches the replay cache.
//
// THE STORE IS ASKED, not the response flag. The cache row is the SD-card write
// this bead exists to bound, and a refusal written as a claim would also be the
// stale-request bug in a new place: a legitimate retry of the same id, once the
// bucket refilled, would be answered RATE_LIMITED from the cache for a day.
func TestAClientOverTheRateLimitIsRefusedAndNotCached(t *testing.T) {
	h := newHarness(t)
	h.exhaust(t, h.conn)

	event := h.request(t, h.client, MethodGetBalance, nil)
	calls := h.wallet.balanceCalls()
	resp, answered := h.service.handle(t.Context(), h.conn, event)
	if !answered || resp.Error == nil || resp.Error.Code != CodeRateLimited {
		t.Fatalf("request past the burst: answered=%v %+v, want RATE_LIMITED (§8)", answered, resp)
	}
	if resp.ResultType != MethodGetBalance {
		t.Errorf("result_type = %q, want the method echoed as every other error does", resp.ResultType)
	}
	if h.wallet.balanceCalls() != calls {
		t.Error("the refused request reached the wallet; a refusal must execute nothing")
	}
	if _, found, err := h.db.NWCHandledResponse(t.Context(), event.ID); err != nil {
		t.Fatal(err)
	} else if found {
		t.Error("the rate-limited request was written to nwc_handled_requests; a retry of the same " +
			"id after the bucket refills would be answered RATE_LIMITED from the cache")
	}
}

// l3j criterion 1's other half: under the limit, nothing changes. A burst of
// exactly RequestBurst is served in full (exhaust asserts each one), and a client
// pacing itself at the refill rate is never refused however long it keeps going.
func TestAClientUnderTheRateLimitIsUnaffected(t *testing.T) {
	h := newHarness(t)
	h.exhaust(t, h.conn)
	interval := time.Minute / RequestsPerMinute
	for i := range 3 * RequestsPerMinute {
		h.clock.at = h.clock.at.Add(interval)
		if resp := h.handle(t, MethodGetBalance, nil); resp.Error != nil {
			t.Fatalf("request %d at the refill rate was refused: %+v", i+1, resp.Error)
		}
	}
}

// l3j criterion 2: the bucket refills, and the same client is served again.
func TestTheRateLimitRefills(t *testing.T) {
	h := newHarness(t)
	h.exhaust(t, h.conn)
	if resp := h.handle(t, MethodGetBalance, nil); resp.Error == nil || resp.Error.Code != CodeRateLimited {
		t.Fatalf("precondition: the burst should be spent, got %+v", resp)
	}

	h.clock.at = h.clock.at.Add(time.Minute / RequestsPerMinute)
	if resp := h.handle(t, MethodGetBalance, nil); resp.Error != nil {
		t.Fatalf("one refill interval later the client was still refused: %+v", resp.Error)
	}
	// And a whole idle minute gives back the whole burst, not one token.
	h.clock.at = h.clock.at.Add(time.Minute)
	h.exhaust(t, h.conn)
}

// l3j criterion 3: two pairings, two buckets. One app's flood is that app's
// problem; refusing the operator's other wallet for it would turn a limiter into
// a way for one paired client to take the others down.
func TestOneConnectionsFloodDoesNotRefuseAnother(t *testing.T) {
	h := newHarness(t)
	other := h.secondConnection(t)
	// secondConnection's pairing names no relay, so its answers are never
	// delivered and the real retry spacing would hold each one for seconds.
	h.service.responseRetries = []time.Duration{time.Millisecond}
	h.exhaust(t, h.conn)
	if resp := h.handle(t, MethodGetBalance, nil); resp.Error == nil || resp.Error.Code != CodeRateLimited {
		t.Fatalf("precondition: the first pairing should be limited, got %+v", resp)
	}
	h.exhaust(t, other)
}

// A request delivered on several of a pairing's relays is ONE request, and the
// bucket charges it once (d24.18's fan-out).
//
// Not only arithmetic. Charged per copy, the last token would go to one relay's
// copy and the next copy would publish RATE_LIMITED onto the same relays the
// winner is about to publish the real answer to — d24.18's inconsistent answers,
// which a client taking the first response it sees renders as a failure for a
// request that succeeded.
func TestASiblingRelaysCopyOfAnAdmittedRequestIsNotCharged(t *testing.T) {
	h := newHarness(t)
	for i := range RequestBurst {
		event := h.request(t, h.client, MethodGetBalance, nil)
		if resp, _ := h.service.handle(t.Context(), h.conn, event); resp.Error != nil {
			t.Fatalf("request %d: %+v", i+1, resp.Error)
		}
		// The same event again, as the pairing's other relays deliver it.
		for copyN := 1; copyN < 3; copyN++ {
			resp, _ := h.service.handle(t.Context(), h.conn, event)
			if resp.Error != nil && resp.Error.Code == CodeRateLimited {
				t.Fatalf("copy %d of admitted request %d was answered RATE_LIMITED; a sibling "+
					"relay's copy must reach the claim, which dedupes it", copyN, i+1)
			}
		}
	}
}

// But a copy is a copy only while it is a sibling's. The same id re-sent after
// SiblingDeliveryWindow is a client asking again, and it pays — otherwise one
// admitted event, re-sent in a loop, would be a path around the bucket.
func TestAResentRequestAfterTheSiblingWindowIsCharged(t *testing.T) {
	h := newHarness(t)
	first := h.request(t, h.client, MethodGetBalance, nil)
	h.service.handle(t.Context(), h.conn, first)
	for range RequestBurst - 1 {
		h.handle(t, MethodGetBalance, nil)
	}
	// Still fresh for §8's window, past the sibling one — and not long enough
	// for a refill to put a token back.
	h.clock.at = h.clock.at.Add(SiblingDeliveryWindow)
	h.conn.limit.tokens, h.conn.limit.last = 0, h.clock.at
	resp, _ := h.service.handle(t.Context(), h.conn, first)
	if resp.Error == nil || resp.Error.Code != CodeRateLimited {
		t.Fatalf("a re-send past the sibling window was not charged: %+v", resp)
	}
}

// The refusal is audited ONCE PER EPISODE, not once per refused request, and a
// flood is not one log line per request either (l3j: a flood must not become a
// flood of rows, which is the SD-card point of the bead).
func TestARateLimitFloodIsAuditedOnce(t *testing.T) {
	h := newHarness(t)
	h.exhaust(t, h.conn)
	const flood = 50
	for range flood {
		if resp := h.handle(t, MethodGetBalance, nil); resp.Error == nil || resp.Error.Code != CodeRateLimited {
			t.Fatalf("expected RATE_LIMITED, got %+v", resp)
		}
	}
	rows := 0
	for _, row := range h.audit.events() {
		if row.event == logging.EventConnectionRefuse && row.attrs["code"] == CodeRateLimited {
			rows++
			if row.attrs["connection"] != strconv.FormatInt(h.conn.row().ID, 10) {
				t.Errorf("the audit row names connection %q, want %d", row.attrs["connection"], h.conn.row().ID)
			}
		}
	}
	if rows != 1 {
		t.Errorf("%d audit rows for one flood of %d refusals, want 1", rows, flood)
	}
	if n := strings.Count(h.logs.String(), `level=WARN`); n > 1 {
		t.Errorf("%d WARN lines for one flood; the episode's first refusal is the one worth saying", n)
	}
	// The operator's page names it too (d24.21), and that is a row write, so it
	// is once per episode as well.
	conn, _, err := h.db.NWCConnection(t.Context(), h.conn.row().ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn.LastRefusalCode != CodeRateLimited {
		t.Errorf("the connection's last refusal is %q, want %s", conn.LastRefusalCode, CodeRateLimited)
	}

	// A client that backs off until the bucket is full again, then floods, is a
	// second episode and says so.
	h.clock.at = h.clock.at.Add(time.Minute)
	h.exhaust(t, h.conn)
	h.handle(t, MethodGetBalance, nil)
	rows = 0
	for _, row := range h.audit.events() {
		if row.attrs["code"] == CodeRateLimited {
			rows++
		}
	}
	if rows != 2 {
		t.Errorf("%d audit rows after a second episode, want 2", rows)
	}
}

// l3j criterion 4: make_invoice cannot mint above the one invoice ceiling this
// app states, lnurl.MaxSendableMsat, and the refusal comes before the node is
// asked for anything. At the ceiling it is served.
func TestMakeInvoiceIsBoundedByTheLNURLCeiling(t *testing.T) {
	h := newHarness(t)
	over := json.RawMessage(`{"amount":` + strconv.FormatInt(lnurl.MaxSendableMsat+1, 10) + `}`)
	resp := h.handle(t, MethodMakeInvoice, over)
	if resp.Error == nil || resp.Error.Code != CodeOther {
		t.Fatalf("make_invoice one msat over the ceiling: %+v, want OTHER", resp)
	}
	if !strings.Contains(resp.Error.Message, strconv.FormatInt(lnurl.MaxSendableMsat, 10)) {
		t.Errorf("message %q does not name the ceiling", resp.Error.Message)
	}
	if h.invoices.minted != 0 {
		t.Errorf("Mint was called %d times for an amount over the ceiling", h.invoices.minted)
	}

	at := json.RawMessage(`{"amount":` + strconv.FormatInt(lnurl.MaxSendableMsat, 10) + `}`)
	if resp := h.handle(t, MethodMakeInvoice, at); resp.Error != nil {
		t.Fatalf("make_invoice at the ceiling was refused: %+v", resp.Error)
	}
	if h.invoices.minted != 1 {
		t.Errorf("Mint called %d times at the ceiling, want 1", h.invoices.minted)
	}
}
