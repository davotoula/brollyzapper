package nwc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"bytes"
	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

// §8 step 1, and the ordering is the security property: a request from a pubkey
// this connection does not know is refused WITHOUT DECRYPTING.
//
// Decrypt-then-check would work, and would let anyone on the relay make this
// node derive a conversation key by addressing an event at it — elliptic-curve
// work per event, for free, from anywhere. The counter on the identity is how
// the test can tell: the outcome is the same either way, so asserting on the
// answer would pass against the inversion.
func TestAForeignPubkeyIsRefusedWithoutDecrypting(t *testing.T) {
	h := newHarness(t)
	stranger := anIdentity(t)

	event := h.request(t, stranger, MethodGetBalance, nil)
	resp, answered := h.service.handle(t.Context(), h.conn, event)

	if answered {
		t.Errorf("a stranger got an answer (%+v); §8 says UNAUTHORIZED must never leak whether "+
			"a connection exists, and answering at all says this pubkey is live", resp)
	}
	if got := h.relays.published(); len(got) != 0 {
		t.Errorf("%d response events were published to a stranger", len(got))
	}
	if h.cryptoCalls() != 0 {
		t.Errorf("the service did %d crypto operations for an unauthorized pubkey; step 1 is "+
			"BEFORE step 2 so that a stranger cannot make this node do work", h.cryptoCalls())
	}
}

// An unknown method is echoed back in result_type and stored in the cache, so
// its length is an attacker's choice until something bounds it.
//
// A NIP-44 payload carries ~64 kB. A paired client putting all of it in the
// method name writes it into a durable row, on an SD card, once per request.
func TestAnAbsurdlyLongMethodNameIsNotEchoedBack(t *testing.T) {
	h := newHarness(t)
	huge := Method(strings.Repeat("m", 40_000))

	resp := h.handle(t, huge, nil)

	if resp.Error == nil || resp.Error.Code != CodeNotImplemented {
		t.Fatalf("a 40 kB method name answered %+v, want NOT_IMPLEMENTED", resp)
	}
	if len(resp.ResultType) > maxMethodLength {
		t.Errorf("the response repeats %d bytes of the client's method name; it is stored in "+
			"nwc_handled_requests as well as sent", len(resp.ResultType))
	}
}

// The info event is a PROMISE, and this is what keeps it one.
//
// Supported() is written out — §8's order is editorial and neither the group map
// nor the dispatch switch has one — so nothing structural stops it drifting from
// what dispatch answers. A client shown a method that returns NOT_IMPLEMENTED is
// a wallet app with a button that does not work.
func TestEveryAdvertisedMethodIsOneTheServiceAnswers(t *testing.T) {
	for _, method := range Supported() {
		if _, known := methodGroup[method]; !known {
			t.Errorf("%s is advertised but belongs to no permission group, so permits() can "+
				"never allow it and it can only reach NOT_IMPLEMENTED", method)
			continue
		}
		h := newHarness(t)
		// Every group granted and sending on: the question here is whether
		// DISPATCH answers, not whether this connection may ask.
		h.grantPay()
		h.sendEnabled(true)
		h.decodesTo("lnbcrt1drift", 1_000, "drift check")
		resp := h.handle(t, method,
			json.RawMessage(`{"payment_hash":"deadbeef","amount":1000,"invoice":"lnbcrt1drift"}`))
		if resp.Error != nil && resp.Error.Code == CodeNotImplemented {
			t.Errorf("%s is advertised in the info event and dispatch answers %s", method,
				resp.Error.Code)
		}
	}

	// The other direction, and it changed shape in d24.4: pay_invoice is
	// SUPPORTED now, and what keeps it off a receive-only wallet's info event is
	// advertised() rather than its absence from this list. The rule "advertised
	// == has a group" is therefore still wrong, and still worth pinning — see
	// TestPayInvoiceIsAdvertisedOnlyWhenItCanBeUsed for the four cases.
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(false)
	if slices.Contains(h.service.advertised(t.Context(), h.conn), string(MethodPayInvoice)) {
		t.Error("pay_invoice is advertised with sending disabled; a wallet app would show a " +
			"pay button that answers RESTRICTED")
	}
}

// A relay that drops the socket must not end the connection.
//
// go-nostr's Relay.Subscribe does not reconnect — unlike SimplePool's
// SubscribeMany — so a dropped socket closes the events channel, and a plain
// range loop over it returns. The first version did exactly that, silently: the
// connection was dead until the process restarted, Run never noticed, and the
// only symptom was a wallet app that stopped working. On a Pi behind a home
// connection that is days.
func TestASubscriptionThatDropsIsReestablished(t *testing.T) {
	h := newHarness(t)
	h.service.backoff = time.Millisecond

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	conn := h.openConnection(ctx, h.conn.row())
	conn.identity = h.counting
	done := make(chan struct{})
	go func() { defer close(done); h.service.serve(ctx, conn, testRelay) }()

	// The relay drops it, and a request arrives on whatever comes next.
	h.relays.drop()
	waitFor(t, "the connection to re-subscribe", func() bool { return h.relays.subscribes() == 2 })
	h.relays.deliver(h.request(t, h.client, MethodGetBalance, nil))

	waitFor(t, "the request delivered after the reconnect to be answered", func() bool {
		return len(h.relays.published()) == 1
	})

	cancel()
	conn.close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("serve did not return after the context ended")
	}
}

// And a relay that is still down is waited out rather than given up on.
func TestAReconnectRetriesWhileTheRelayIsDown(t *testing.T) {
	h := newHarness(t)
	h.service.backoff = time.Millisecond
	h.relays.failures = 0

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	conn := h.openConnection(ctx, h.conn.row())
	// The next two Subscribe calls fail: the relay has not come back yet.
	h.relays.mu.Lock()
	h.relays.failures = 2
	h.relays.mu.Unlock()

	done := make(chan struct{})
	go func() { defer close(done); h.service.serve(ctx, conn, testRelay) }()
	h.relays.drop()

	waitFor(t, "the reconnect to keep trying", func() bool { return h.relays.subscribes() >= 4 })

	cancel()
	conn.close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("serve did not return after the context ended; a retry loop must watch ctx")
	}
}

// subscribed waits until this pairing holds a subscription on each of the relays
// named, which is what reload no longer does for a test.
//
// Since d24.18 the first dial happens inside the relay-session goroutine rather
// than inside reload: with a list there is no single answer to "did it open", and
// reload would otherwise make the operator who nudged it wait on the slowest relay
// of the slowest pairing. So a test that reloads and then delivers is acting
// before the socket exists — which the fake now panics about rather than hanging
// on a nil channel.
func (h *harness) subscribed(t *testing.T, relays ...string) {
	t.Helper()
	for _, relay := range relays {
		waitFor(t, "a subscription on "+relay, func() bool {
			return h.relays.subscriptionsTo(relay) >= 1
		})
	}
}

// waitFor polls until want is true. The subject is a goroutine, so an assertion
// made immediately would be asserting a race.
func waitFor(t *testing.T, what string, want func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if want() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// §8 step 6: the PAIRING'S OWN relays and no others. Asserted here as well as in
// internal/nostr, where the pool proves it reaches only those — this half proves
// the service asks for the right ones, which is the half a fake can see.
//
// The list made this test matter more rather than less: the one thing that must
// never become normal, now that publishing to several relays is normal, is a
// relay the pairing did not name.
func TestTheResponseGoesToTheConnectionsOwnRelays(t *testing.T) {
	h := newHarness(t)
	own := []string{"wss://the-connections-own.example", "wss://its-second.example"}
	h.mutate(func(row *store.NWCConnection) { row.Relays = own })

	h.handle(t, MethodGetBalance, nil)

	got := h.relays.publishedTo()
	if len(got) != len(own) {
		t.Fatalf("the response was published to %v, want exactly %v", got, own)
	}
	for i, target := range got {
		if target != own[i] {
			t.Errorf("the response reached %q; the pairing named %v, and a response anywhere "+
				"else is a pairing announced somewhere it never agreed to be", target, own)
		}
	}
}

// The replay cache is keyed on the event id, so the id has to be the one the
// SIGNATURE covers — and go-nostr does not check that for us.
//
// Its CheckSignature "won't look at the ID field, instead it will recompute the
// id from the entire event body", so an event whose ID field has been rewritten
// still verifies and is still dispatched to a subscription. Whoever last touched
// the event chooses that field — including the relay, which is precisely the
// party §8's durable cache exists to defend against ("a relay re-delivering a
// request the process handled seconds before it died"). A relay that varies the
// id on redelivery would strip idempotency entirely.
//
// Read-only methods bound the damage TODAY. d24.4 puts pay_invoice behind this
// key, and §8's argument for the cache is that a re-delivered pay_invoice pays
// twice.
func TestARequestWhoseIdDoesNotMatchItsBodyIsRefused(t *testing.T) {
	h := newHarness(t)

	event := h.request(t, h.client, MethodGetBalance, nil)
	if ok, _ := event.CheckSignature(); !ok {
		t.Fatal("the harness produced an unsigned event; this test would prove nothing")
	}
	event.ID = strings.Repeat("0", 8) + event.ID[8:]
	if ok, _ := event.CheckSignature(); !ok {
		t.Fatal("go-nostr now rejects a rewritten id at signature check; this test's premise " +
			"has changed and the check it guards may be redundant")
	}

	resp, answered := h.service.handle(t.Context(), h.conn, event)

	if answered {
		t.Errorf("an event whose id does not match its body was answered (%+v); the cache key "+
			"and the response's e-tag would both be a value nobody signed", resp)
	}
	if got := h.relays.published(); len(got) != 0 {
		t.Errorf("%d events were published in reply to a forged id", len(got))
	}
	if h.cryptoCalls() != 0 {
		t.Errorf("the service did %d crypto operations for an event it could not trust the "+
			"identity of; the id check belongs with step 1, before any decryption",
			h.cryptoCalls())
	}
}

// §8: get_balance returns the CEILING, never the node's.
//
// One identifier apart, and the difference is §2's whole posture: the node's
// balance is shared with every app on the box, so reporting it tells a paired
// wallet how much bitcoin the operator has and invites it to try to spend it.
func TestGetBalanceReturnsTheCeilingNotTheNode(t *testing.T) {
	h := newHarness(t)
	h.wallet.balance = 42_000
	h.node.info.Alias = "the node has far more than this"

	resp := h.handle(t, MethodGetBalance, nil)
	result, _ := resp.Result.(map[string]any)
	if got := result["balance"]; got != int64(42_000) {
		t.Errorf("balance = %v, want the wallet ceiling 42000 (§8)", got)
	}
}

// §8's durable replay protection, and the LNbits lesson it cites: a redelivered
// request returns its CACHED response and executes NOTHING.
func TestAReplayedRequestReturnsTheCachedResponseAndExecutesNothing(t *testing.T) {
	h := newHarness(t)
	h.wallet.balance = 7

	event := h.request(t, h.client, MethodGetBalance, nil)
	first, _ := h.service.handle(t.Context(), h.conn, event)
	callsAfterFirst := h.wallet.balanceCalls()

	// The balance moves. A replay that RE-EXECUTED would report the new figure,
	// which is how this test can tell a cache hit from a coincidence.
	h.wallet.balance = 999
	second, answered := h.service.handle(t.Context(), h.conn, event)

	if !answered {
		t.Fatal("the replay was not answered at all; a client that retries must get its answer")
	}
	if h.wallet.balanceCalls() != callsAfterFirst {
		t.Errorf("the wallet was consulted %d more times on the replay; a known id must execute "+
			"nothing (§8)", h.wallet.balanceCalls()-callsAfterFirst)
	}
	// And the two published responses carry the same plaintext.
	published := h.relays.published()
	if len(published) != 2 {
		t.Fatalf("%d responses published, want 2", len(published))
	}
	if a, b := h.open(t, published[0]), h.open(t, published[1]); a != b {
		t.Errorf("the replay answered differently:\n first: %s\nsecond: %s", a, b)
	}
	_ = first
	_ = second
}

// The seam that matters: the cache is DURABLE, so a restart cannot forget it.
//
// §8 is explicit that an in-memory LRU is emptied by the very event that causes
// requests to be re-delivered. This builds a SECOND service over the same store
// — which is what a restart is — and redelivers.
func TestARestartStillRemembersAHandledRequest(t *testing.T) {
	h := newHarness(t)
	h.wallet.balance = 7
	event := h.request(t, h.client, MethodGetBalance, nil)
	h.service.handle(t.Context(), h.conn, event)

	// The "restart": a new service, same store, same connection row.
	restarted := New(h.db, h.relays, h.wallet, h.invoices, h.node, h.spend,
		Options{Log: quiet(), Now: h.clock.now})
	h.wallet.balance = 999
	callsBefore := h.wallet.balanceCalls()

	if _, answered := restarted.handle(t.Context(), h.conn, event); !answered {
		t.Fatal("the redelivered request was not answered after a restart")
	}
	if h.wallet.balanceCalls() != callsBefore {
		t.Errorf("the restarted service re-executed the request; the cache is in the database " +
			"precisely because a restart is when replay happens (§8)")
	}
}

// §8 step 3: a stale request is refused AND NOT CACHED.
//
// Caching it would answer a legitimate retry of the same id with "expired" for
// ever — the client would be told its fresh request was old.
func TestAStaleRequestIsRefusedAndNotCached(t *testing.T) {
	h := newHarness(t)
	event := h.requestAt(t, h.client, MethodGetBalance, nil, h.clock.at.Add(-5*time.Minute))

	resp, answered := h.service.handle(t.Context(), h.conn, event)
	if !answered || resp.Error == nil {
		t.Fatalf("a five-minute-old request was accepted: %+v", resp)
	}
	if resp.Error.Code != CodeOther || !strings.Contains(resp.Error.Message, "expired") {
		t.Errorf("error = %+v, want OTHER/request expired (§8)", resp.Error)
	}
	if _, found, err := h.db.NWCHandledResponse(t.Context(), event.ID); err != nil {
		t.Fatal(err)
	} else if found {
		t.Error("the stale request was written to the replay cache; a later retry of the same " +
			"id would then be told it had expired, for ever")
	}
}

// §8: pay_invoice is absent from this build's capabilities, and dispatching it
// answers NOT_IMPLEMENTED rather than paying without d24.4's rejection ladder.
// d24.4 replaced this wave-23 test's subject: pay_invoice IS implemented now.
//
// What survives is the property underneath it — a connection that may not pay
// cannot, and is not told it can. The ladder's own refusal is
// TestTheRejectionLadderAnswersWithTheEarliestFailure; this is the info event's
// half, which is what a wallet app builds its UI from.
func TestTheInfoEventAdvertisesExactlyWhatThisConnectionMayCall(t *testing.T) {
	h := newHarness(t)
	h.grantPay()
	h.sendEnabled(true)

	event, err := h.service.infoEvent(t.Context(), h.conn)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range Supported() {
		if !strings.Contains(event.Content, string(m)) {
			t.Errorf("the info event omits %s, which this connection may call", m)
		}
	}

	// And a connection without the group is shown a receive-only wallet.
	receiveOnly := newHarness(t)
	receiveOnly.sendEnabled(true)
	event, err = receiveOnly.service.infoEvent(t.Context(), receiveOnly.conn)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(event.Content, string(MethodPayInvoice)) {
		t.Errorf("the info event advertises pay_invoice to a connection without the pay "+
			"group: %q", event.Content)
	}
}

// §8 step 4: a method the connection's groups do not grant is RESTRICTED, and
// that is different from a method that does not exist.
func TestAMethodOutsideTheConnectionsGroupsIsRestricted(t *testing.T) {
	h := newHarness(t)
	h.mutate(func(row *store.NWCConnection) { row.Permissions = []string{store.PermissionInfo} })

	resp := h.handle(t, MethodGetBalance, nil)
	if resp.Error == nil || resp.Error.Code != CodeRestricted {
		t.Errorf("get_balance without the balance group answered %+v, want RESTRICTED", resp)
	}

	unknown := h.handle(t, "make_coffee", nil)
	if unknown.Error == nil || unknown.Error.Code != CodeNotImplemented {
		t.Errorf("an unknown method answered %+v, want NOT_IMPLEMENTED", unknown)
	}
}

// §8: the reply uses whatever the client used.
//
// A response sealed with a scheme the client did not send cannot be read by it,
// and what the user sees is a wallet that hangs rather than an error.
func TestTheReplyUsesTheSchemeTheClientUsed(t *testing.T) {
	for _, scheme := range []nostr.Encryption{nostr.NIP04, nostr.NIP44} {
		t.Run(string(scheme), func(t *testing.T) {
			h := newHarness(t)
			event := h.requestWith(t, h.client, scheme, MethodGetBalance, nil, h.clock.at)

			if _, answered := h.service.handle(t.Context(), h.conn, event); !answered {
				t.Fatal("not answered")
			}
			published := h.relays.published()
			if len(published) != 1 {
				t.Fatalf("%d responses published, want 1", len(published))
			}
			// Readable by the client with the scheme it used, and by nothing else.
			if _, err := h.client.Decrypt(scheme, h.conn.row().ServicePubkey,
				published[0].Content); err != nil {
				t.Errorf("the client cannot read the reply it was sent: %v", err)
			}
			if got := published[0].Tags.GetFirst([]string{"encryption"}).Value(); got != string(scheme) {
				t.Errorf("the response's encryption tag is %q, want %q", got, scheme)
			}
		})
	}
}

// §8: an encryption scheme we do not speak is UNSUPPORTED_ENCRYPTION, not a
// silent NIP-04 attempt that fails as a bad key.
func TestAnUnknownEncryptionSchemeIsNamedAsSuch(t *testing.T) {
	h := newHarness(t)
	event := h.request(t, h.client, MethodGetBalance, nil)
	event.Tags = gonostr.Tags{{"p", h.conn.row().ServicePubkey}, {"encryption", "nip44_v3"}}
	sign(t, h.client, event)

	resp, answered := h.service.handle(t.Context(), h.conn, event)
	if !answered || resp.Error == nil || resp.Error.Code != CodeUnsupportedEncryption {
		t.Errorf("answered %+v, want UNSUPPORTED_ENCRYPTION", resp)
	}
}

// §8 step 2, `xmc`: NO encryption tag means NIP-04, and it is a legal request.
//
// THE REGRESSION TEST FOR AN OUTAGE. v0.1.11 read the tag's value straight out
// of Tags.GetFirst, which returns nil when the tag is absent, on a Value() with
// a value receiver — so one such request from one paired client segfaulted the
// process. It then crash-looped: the resume cursor advances after this point, so
// the relay redelivered the same event on every reconnect and the app never came
// back. Every client written before NIP-44 sends exactly this request.
//
// It asserts the ANSWER and not merely the absence of a panic: handling it as
// NIP-04 is the spec's rule, and a version that answered UNSUPPORTED_ENCRYPTION
// would also not panic while still rejecting a legal request.
func TestARequestWithNoEncryptionTagIsNIP04(t *testing.T) {
	h := newHarness(t)
	h.wallet.balance = 4321

	event := h.requestWith(t, h.client, nostr.NIP04, MethodGetBalance, nil, h.clock.at)
	// The tag the old code could not survive the absence of.
	event.Tags = gonostr.Tags{{"p", h.conn.row().ServicePubkey}}
	sign(t, h.client, event)

	resp, answered := h.service.handle(t.Context(), h.conn, event)
	if !answered {
		t.Fatal("a request with no encryption tag was not answered at all")
	}
	if resp.Error != nil {
		t.Fatalf("answered %+v, want a result — §8 step 2 makes an absent tag NIP-04, and "+
			"every client written before NIP-44 sends one", resp.Error)
	}
	if resp.ResultType != MethodGetBalance {
		t.Errorf("result_type = %q, want %q", resp.ResultType, MethodGetBalance)
	}
}

// §8: a receive-only install still answers reads, and make_invoice works there.
// Neither of the wallet's freezes reaches these methods, which is correct — they
// live on Reserve, and nothing here reserves.
func TestReadsAndMakeInvoiceWorkWhileSpendingIsHeld(t *testing.T) {
	h := newHarness(t)
	// The wallet is frozen in both of §5's senses as far as this service is
	// concerned: it has no Spender at all.
	h.wallet.balance = 1234

	if resp := h.handle(t, MethodGetBalance, nil); resp.Error != nil {
		t.Errorf("get_balance while spending is held: %+v", resp.Error)
	}
	resp := h.handle(t, MethodMakeInvoice, json.RawMessage(`{"amount":21000,"description":"tip"}`))
	if resp.Error != nil {
		t.Fatalf("make_invoice while spending is held: %+v — §8 says a receive-only install "+
			"still mints invoices", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	if result["invoice"] == "" {
		t.Error("make_invoice returned no bolt11")
	}
}

// --- harness ---------------------------------------------------------------

type harness struct {
	t        *testing.T
	db       *store.Store
	relays   *fakeRelays
	wallet   *fakeWallet
	invoices *fakeInvoices
	node     *fakeNode
	spend    *fakeSpend
	service  *Service
	conn     *connection
	client   nostr.Identity
	counting *countingSigner
	clock    *testClock

	// audit is §12's trail as the service sees it, and logs is the log it wrote
	// (d24.14). Both, because the Auditor's contract is the line AND the row,
	// and the field trip found a spend path that produced neither.
	audit *fakeAuditor
	logs  *syncBuffer
	// demand is the reload signal the service nudges; see newHarness.
	demand chan struct{}

	// otherClient is the second pairing's client identity, set by
	// secondConnection. Fix C's scoping test needs two pairings that panic
	// independently (`xmc`).
	otherClient nostr.Identity

	// decoded is what the node says each bolt11 means (d24.4). A map rather
	// than one value because the ladder tests set several up per case, and it is
	// SHARED with the spend fake, which is what answers Decode.
	decoded map[string]*Bolt11
}

// grantPay adds §8's pay group to the connection — deliberately not the default
// (§2: a new connection cannot spend until that is granted).
func (h *harness) grantPay() {
	h.t.Helper()
	h.mutate(func(row *store.NWCConnection) { row.Permissions = append(row.Permissions, store.PermissionPay) })
	h.updateConnection()
}

func (h *harness) sendEnabled(on bool) {
	h.t.Helper()
	value := "false"
	if on {
		value = "true"
	}
	if err := h.db.SetSetting(h.t.Context(), SettingSendEnabled, value); err != nil {
		h.t.Fatal(err)
	}
	h.spend.ready = on
}

func (h *harness) setBudget(msat int64) {
	h.t.Helper()
	h.mutate(func(row *store.NWCConnection) { row.BudgetMsat = &msat })
	h.mutate(func(row *store.NWCConnection) { row.BudgetPeriod = store.BudgetDaily })
	h.mutate(func(row *store.NWCConnection) { row.BudgetRenewsAt = h.clock.at.Add(time.Hour) })
	h.updateConnection()
}

func (h *harness) setMaxPayment(msat int64) {
	h.t.Helper()
	h.mutate(func(row *store.NWCConnection) { row.MaxPaymentMsat = &msat })
	h.updateConnection()
}

// updateConnection rewrites the row, because the ladder reads the connection
// from the DATABASE rather than from the in-memory copy: the budget counter is
// shared state and the row is where it lives.
func (h *harness) updateConnection() {
	h.t.Helper()
	row := h.conn.row()
	if _, err := h.db.SetNWCConnectionLimits(h.t.Context(), row.ID, row.Permissions,
		row.BudgetMsat, row.BudgetPeriod, row.BudgetRenewsAt, row.MaxPaymentMsat); err != nil {
		h.t.Fatal(err)
	}
}

// mutate is how a test changes the connection's row: read, modify, swap — the
// same shape the production reload uses, because the row is an atomic pointer
// to an immutable value (uhg).
func (h *harness) mutate(change func(row *store.NWCConnection)) {
	h.t.Helper()
	row := h.conn.row()
	change(&row)
	h.conn.update(row)
}

func (h *harness) budgetUsed() int64 {
	h.t.Helper()
	conn, found, err := h.db.NWCConnection(h.t.Context(), h.conn.row().ID)
	if err != nil || !found {
		h.t.Fatalf("NWCConnection: found=%v err=%v", found, err)
	}
	return conn.BudgetUsedMsat
}

// decodesZapTo is decodesTo for a NIP-57 ZAP invoice: one that commits to the
// zap request it was minted for, the way lnurl.ZapHash mints it (y09).
//
// A separate helper rather than a fifth argument on decodesTo, because every
// existing caller means "an ordinary invoice" and an ordinary invoice commits to
// nothing — which since y09 is a meaningful state rather than an unset field.
func (h *harness) decodesZapTo(bolt11 string, amountMsat int64, zapRequest string) {
	h.t.Helper()
	h.decodesTo(bolt11, amountMsat, "")
	hash, err := lnurl.ZapHash([]byte(zapRequest))
	if err != nil {
		h.t.Fatalf("hashing the fixture: %v", err)
	}
	h.decoded[bolt11].DescriptionHash = hex.EncodeToString(hash[:])
}

// decodesTo scripts what the node makes of one bolt11: a PLAIN invoice, which
// commits to nothing.
func (h *harness) decodesTo(bolt11 string, amountMsat int64, description string) {
	if h.decoded == nil {
		h.decoded = map[string]*Bolt11{}
		h.spend.decoded = h.decoded
	}
	h.decoded[bolt11] = &Bolt11{
		PaymentHash: "hash-of-" + bolt11,
		AmountMsat:  amountMsat,
		Description: description,
		ExpiresAt:   h.clock.at.Add(time.Hour),
	}
}

// openConnection is prepare + subscribe, which is what reload does for a
// connection whose relay answers. A test that only wants a working connection
// should not have to know the two halves apart; the tests that DO care about the
// difference are in failedopen_test.go and call them directly.
func (h *harness) openConnection(ctx context.Context, row store.NWCConnection) *connection {
	h.t.Helper()
	conn, err := h.service.prepare(row)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, relay := range conn.relays() {
		if err := h.service.subscribe(ctx, conn, relay, time.Time{}); err != nil {
			h.t.Fatal(err)
		}
	}
	return conn
}

// pairingRelays is the harness's default of one relay, or whatever a test asked
// for.
func pairingRelays(relays []string) []string {
	if len(relays) == 0 {
		return []string{testRelay}
	}
	return relays
}

// testRelay is the harness connection's relay. Named because a test with two
// connections has to say which one it means.
const testRelay = "wss://relay.example"

// addConnection puts a SECOND pairing in the database, with its own keys and its
// own relay — which is what makes "one unusable connection does not stop the
// others" assertable rather than assumed.
//
// change runs on the row before it is stored, so a test can break the row in one
// of the three ways no relay will ever fix.
func (h *harness) addConnection(name, relay string, change func(row *store.NWCConnection)) store.NWCConnection {
	h.t.Helper()
	servicePriv := secret.New(gonostr.GeneratePrivateKey())
	service, err := nostr.Parse(servicePriv)
	if err != nil {
		h.t.Fatal(err)
	}
	clientPriv := secret.New(gonostr.GeneratePrivateKey())
	client, err := nostr.Parse(clientPriv)
	if err != nil {
		h.t.Fatal(err)
	}
	row := store.NWCConnection{
		Name:           name,
		ServicePrivkey: servicePriv,
		ServicePubkey:  service.PublicKey(),
		ClientPubkey:   client.PublicKey(),
		ClientSecret:   clientPriv,
		Relays:         []string{relay},
		Permissions:    store.DefaultPermissions(),
		CreatedAt:      h.clock.at,
	}
	if change != nil {
		change(&row)
	}
	created, err := h.db.CreateNWCConnection(h.t.Context(), row, store.DefaultLimits)
	if err != nil {
		h.t.Fatalf("CreateNWCConnection: %v", err)
	}
	return created
}

// newHarness builds a service with one pairing. The pairing's relays default to
// the single testRelay; a test that is about the LIST passes its own, because
// the relays are written at creation and are deliberately not editable
// afterwards — changing them is a re-pair, not an update (§9 item 4).
func newHarness(t *testing.T, relays ...string) *harness {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	servicePriv := secret.New(gonostr.GeneratePrivateKey())
	service, err := nostr.Parse(servicePriv)
	if err != nil {
		t.Fatal(err)
	}
	clientPriv := secret.New(gonostr.GeneratePrivateKey())
	client, err := nostr.Parse(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	clock := &testClock{at: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)}
	row, err := db.CreateNWCConnection(t.Context(), store.NWCConnection{
		Name:           "test app",
		ServicePrivkey: servicePriv,
		ServicePubkey:  service.PublicKey(),
		ClientPubkey:   client.PublicKey(),
		ClientSecret:   clientPriv,
		Relays:         pairingRelays(relays),
		Permissions:    store.DefaultPermissions(),
		CreatedAt:      clock.at,
	}, store.DefaultLimits)
	if err != nil {
		t.Fatalf("CreateNWCConnection: %v", err)
	}

	h := &harness{
		t: t, db: db, clock: clock, client: client,
		relays:   &fakeRelays{},
		wallet:   &fakeWallet{balance: 21_000_000},
		invoices: &fakeInvoices{},
		node:     &fakeNode{},
		spend:    &fakeSpend{ready: true, maxFee: 1_000},
	}
	h.audit = &fakeAuditor{}
	h.logs = &syncBuffer{}
	// The reload channel the service nudges when Fix C pauses a pairing. Buffered
	// by one and never drained here: what the tests assert is the ROW, and a
	// nudge nobody is listening for must not block the worker (`xmc`).
	h.demand = make(chan struct{}, 1)
	h.service = New(db, h.relays, h.wallet, h.invoices, h.node, h.spend,
		Options{Log: logging.New(h.logs, logging.NewLevelVar(slog.LevelDebug)),
			Now: clock.now, Audit: h.audit, Demand: h.demand})
	h.counting = &countingSigner{Identity: service}
	h.conn = newConnection(row, h.counting)
	return h
}

// cryptoCalls is how many conversation keys the service derived. The authorize
// step is only meaningful if it happens BEFORE any of them.
func (h *harness) cryptoCalls() int { return h.counting.count() }

// countingSigner wraps a real identity and records the crypto it does.
//
// Under a mutex since d24.4: the ladder's same-invoice test drives two requests
// through one connection concurrently, which is what a relay delivering two
// events at once does. -race found the counter first, and an unsynchronised test
// double is still a bug — it can make a real race look like a test flake.
type countingSigner struct {
	nostr.Identity
	mu    sync.Mutex
	calls int
}

func (c *countingSigner) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *countingSigner) record() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
}

func (c *countingSigner) Encrypt(scheme nostr.Encryption, peer, plaintext string) (string, error) {
	c.record()
	return c.Identity.Encrypt(scheme, peer, plaintext)
}

func (c *countingSigner) Decrypt(scheme nostr.Encryption, peer, ciphertext string) (string, error) {
	c.record()
	return c.Identity.Decrypt(scheme, peer, ciphertext)
}

func (h *harness) handle(t *testing.T, method Method, params json.RawMessage) Response {
	t.Helper()
	event := h.request(t, h.client, method, params)
	resp, answered := h.service.handle(t.Context(), h.conn, event)
	if !answered {
		t.Fatalf("%s was not answered", method)
	}
	return resp
}

func (h *harness) request(t *testing.T, from nostr.Identity, method Method,
	params json.RawMessage) *gonostr.Event {
	return h.requestAt(t, from, method, params, h.clock.at)
}

func (h *harness) requestAt(t *testing.T, from nostr.Identity, method Method,
	params json.RawMessage, at time.Time) *gonostr.Event {
	return h.requestWith(t, from, nostr.NIP44, method, params, at)
}

func (h *harness) requestWith(t *testing.T, from nostr.Identity, scheme nostr.Encryption,
	method Method, params json.RawMessage, at time.Time) *gonostr.Event {
	return h.requestTo(t, h.conn, from, scheme, method, params, at)
}

// requestTo is requestWith addressed to a particular pairing, which the scoping
// test needs and h.conn cannot express.
func (h *harness) requestTo(t *testing.T, conn *connection, from nostr.Identity,
	scheme nostr.Encryption, method Method, params json.RawMessage,
	at time.Time) *gonostr.Event {
	t.Helper()
	body, err := json.Marshal(Request{Method: method, Params: params})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := from.Encrypt(scheme, conn.row().ServicePubkey, string(body))
	if err != nil {
		t.Fatal(err)
	}
	event := &gonostr.Event{
		Kind:      KindRequest,
		CreatedAt: gonostr.Timestamp(at.Unix()),
		Content:   sealed,
		Tags: gonostr.Tags{
			{"p", conn.row().ServicePubkey},
			{"encryption", string(scheme)},
		},
	}
	sign(t, from, event)
	return event
}

// open reads a published response back, as the client would.
func (h *harness) open(t *testing.T, event gonostr.Event) string {
	t.Helper()
	scheme, _ := nostr.EncryptionFromTag(event.Tags.GetFirst([]string{"encryption"}).Value())
	plaintext, err := h.client.Decrypt(scheme, h.conn.row().ServicePubkey, event.Content)
	if err != nil {
		t.Fatalf("reading a response: %v", err)
	}
	return plaintext
}

func sign(t *testing.T, id nostr.Identity, event *gonostr.Event) {
	t.Helper()
	if err := id.Sign(event); err != nil {
		t.Fatalf("signing: %v", err)
	}
}

func anIdentity(t *testing.T) nostr.Identity {
	t.Helper()
	id, err := nostr.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// syncBuffer is the log, readable while connection goroutines are still writing
// to it.
//
// A plain bytes.Buffer here is a genuine -race failure, not a theoretical one:
// it reproduced on roughly one in fourteen `-race -count=20` runs, with the read
// in an assertion and the write in a retry goroutine. An unsynchronised test
// double can also make a real race look like a flake, which is the more
// expensive half (found by review).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type testClock struct{ at time.Time }

func (c *testClock) now() time.Time { return c.at }

// fakeRelays hands out subscriptions whose channel the TEST owns, so a dropped
// relay is something a test can cause: closing that channel is exactly what a
// closed socket does to a consumer.
//
// Under a mutex because serve() runs on its own goroutine and the assertions do
// not — the gate runs this package under -race.
type fakeRelays struct {
	mu       sync.Mutex
	events   []gonostr.Event
	targets  []string
	subs     []string
	channels []fakeSubscription
	failures int // Subscribe calls to refuse before handing one out
	// refusals is failures PER RELAY, so a test can have one connection's relay
	// refusing while another's answers (d24.24 criterion 3). The flat counter
	// above cannot express that: it refuses whichever connection asks first.
	refusals map[string]int
	filters  []gonostr.Filter
	// blocked holds every dial until a test releases it. Nil means dial freely.
	blocked chan struct{}
	// flapping hands out subscriptions that are already closed.
	flapping bool
	// The publish side (d24.25): how many publishes to refuse, whether to hang
	// on to one until its context expires, and what each attempt was given.
	refusePublishes  int
	refuseRelay      string
	blockPublish     bool
	publishedAt      []time.Time
	publishDeadlines []time.Time
}

// fakeSubscription remembers which relay handed a channel out, so a test with
// two connections can deliver to the one it means.
type fakeSubscription struct {
	relay  string
	events chan *gonostr.Event
}

func (f *fakeRelays) Subscribe(_ context.Context, relayURL string,
	filter gonostr.Filter) (*nostr.Subscription, error) {
	f.mu.Lock()
	f.subs = append(f.subs, relayURL)
	f.filters = append(f.filters, filter)
	blocked := f.blocked
	refused := false
	switch {
	case f.refusals[relayURL] > 0:
		f.refusals[relayURL]--
		refused = true
	case f.failures > 0:
		f.failures--
		refused = true
	}
	var ch chan *gonostr.Event
	if !refused {
		// CREATED IN THE SAME CRITICAL SECTION as the counter it will be found
		// by. The first version counted the dial here and appended the channel
		// after the lock was released, so a test that waited for the count and
		// then delivered was waiting on the second-to-last step: newestFor
		// returned nil and the send blocked for ever, or returned the PREVIOUS
		// subscription's channel — one of which the package's own drop test hit
		// as "send on closed channel" (found by review, by planting a stall in
		// the window).
		ch = make(chan *gonostr.Event, 4)
		f.channels = append(f.channels, fakeSubscription{relay: relayURL, events: ch})
		if f.flapping {
			// ACCEPTED and then dropped, which is a different failure from
			// refusing the upgrade, and the one that defeats a naive episode
			// model: every reconnect looks like a recovery.
			close(ch)
		}
	}
	f.mu.Unlock()

	// Held OUTSIDE the lock, so the test that installed it can still read the
	// counters while a dial is in flight.
	if blocked != nil {
		<-blocked
	}
	if refused {
		return nil, errNoRealRelay
	}
	return &nostr.Subscription{Events: ch}, nil
}

// flap makes every subscription arrive already closed, the way a relay that
// accepts and immediately drops behaves.
func (f *fakeRelays) flap(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flapping = on
}

// block makes every SUBSEQUENT dial hang until release is called, which is how
// a test gets a subscribe genuinely in flight while it asserts on shutdown.
func (f *fakeRelays) block() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked = make(chan struct{})
}

func (f *fakeRelays) release() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.blocked != nil {
		close(f.blocked)
		f.blocked = nil
	}
}

// refuse makes the next n Subscribe calls for ONE relay fail, which is what the
// 0.1.10 trip measured: relay.damus.io refused 8 of 20 websocket upgrades while
// the other two relays took every one.
func (f *fakeRelays) refuse(relayURL string, times int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refusals == nil {
		f.refusals = map[string]int{}
	}
	f.refusals[relayURL] = times
}

// deliver puts an event on the newest subscription, and drop closes it the way
// a dead socket would.
func (f *fakeRelays) deliver(event *gonostr.Event) { f.newest() <- event }
func (f *fakeRelays) drop()                        { close(f.newest()) }

// deliverTo puts an event on the newest subscription HELD BY ONE RELAY. With two
// connections live, deliver() would hand it to whichever subscribed last, which
// is a race dressed as a test.
func (f *fakeRelays) deliverTo(relayURL string, event *gonostr.Event) {
	f.newestFor(relayURL) <- event
}

// dropRelay closes ONE relay's newest subscription, the way a dead socket does —
// so a test can drop one session of a pairing and leave the others up.
func (f *fakeRelays) dropRelay(relayURL string) { close(f.newestFor(relayURL)) }

func (f *fakeRelays) newest() chan *gonostr.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.channels[len(f.channels)-1].events
}

// newestFor PANICS rather than returning nil when that relay holds no
// subscription. A send on a nil channel blocks for ever, which a test reports as
// a package-wide timeout naming no line — the loud failure is worth more than
// the tidy return (found by review).
func (f *fakeRelays) newestFor(relayURL string) chan *gonostr.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.channels) - 1; i >= 0; i-- {
		if f.channels[i].relay == relayURL {
			return f.channels[i].events
		}
	}
	panic("no subscription has been handed out for " + relayURL +
		"; wait for subscriptionsTo, not subscribesTo — a refused dial is counted too")
}

// subscriptionsTo is how many subscriptions this relay has actually HANDED OUT,
// as opposed to how many times it was asked. A test about to deliver an event
// waits on this one: a refused dial increments the other.
func (f *fakeRelays) subscriptionsTo(relayURL string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, sub := range f.channels {
		if sub.relay == relayURL {
			n++
		}
	}
	return n
}

func (f *fakeRelays) subscribes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs)
}

// subscribesTo is how many times ONE relay was asked, which is the assertion a
// per-connection retry needs: "this row was never tried again" is not the same
// claim as "nothing was tried again".
func (f *fakeRelays) subscribesTo(relayURL string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, sub := range f.subs {
		if sub == relayURL {
			n++
		}
	}
	return n
}

func (f *fakeRelays) PublishToConnection(ctx context.Context, event gonostr.Event,
	relays nostr.ConnectionRelays) []nostr.PublishResult {
	urls := relays.URLs()
	f.mu.Lock()
	f.events = append(f.events, event)
	f.targets = append(f.targets, urls...)
	f.publishedAt = append(f.publishedAt, time.Now())
	deadline, _ := ctx.Deadline()
	f.publishDeadlines = append(f.publishDeadlines, deadline)
	refuse := f.refusePublishes > 0
	if refuse {
		f.refusePublishes--
	}
	block := f.blockPublish
	refuseRelay := f.refuseRelay
	f.mu.Unlock()

	results := make([]nostr.PublishResult, 0, len(urls))
	if block {
		// A relay that took the event and never answered, which is what the
		// per-attempt timeout exists for. Held outside the lock so the
		// assertions can still read the counters.
		<-ctx.Done()
		for _, url := range urls {
			results = append(results, nostr.PublishResult{Relay: url, Err: ctx.Err()})
		}
		return results
	}
	for _, url := range urls {
		if refuse || url == refuseRelay {
			results = append(results, nostr.PublishResult{Relay: url, Err: errNoRealRelay})
			continue
		}
		results = append(results, nostr.PublishResult{Relay: url})
	}
	return results
}

// refuseRelayPublishes makes ONE relay refuse every publish while the others
// take them, which is the shape a pairing with a list has to survive.
func (f *fakeRelays) refuseRelayPublishes(relayURL string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refuseRelay = relayURL
}

// refusePublishesFor makes the next n publishes fail, so a test can watch the
// retry rather than assume it.
func (f *fakeRelays) refusePublishesFor(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refusePublishes = n
}

func (f *fakeRelays) holdPublishes() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockPublish = true
}

// publishTimes is when each publish attempt was made, on the REAL clock: the
// spacing between attempts is the thing being asserted, and the harness clock is
// frozen.
func (f *fakeRelays) publishTimes() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.publishedAt...)
}

// publishDeadline is the deadline the caller put on attempt i, which is how a
// test reads the per-attempt budget without waiting for it to expire.
func (f *fakeRelays) publishDeadline(i int) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i >= len(f.publishDeadlines) {
		return time.Time{}, false
	}
	return f.publishDeadlines[i], !f.publishDeadlines[i].IsZero()
}

// publishedTo is the relays each publish named.
func (f *fakeRelays) publishedTo() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.targets...)
}

// infoEvents is only the kind 13194 announcements, so a test can count
// republishes without a response getting in the way.
func (f *fakeRelays) infoEvents() []gonostr.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []gonostr.Event
	for _, e := range f.events {
		if e.Kind == KindInfo {
			out = append(out, e)
		}
	}
	return out
}

// published is only the RESPONSE events, so an info event does not count as an
// answer to a request.
func (f *fakeRelays) published() []gonostr.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []gonostr.Event
	for _, e := range f.events {
		if e.Kind == KindResponse {
			out = append(out, e)
		}
	}
	return out
}

// fakeWallet counts what it was asked, under a mutex: since d24.18 one request
// can arrive on three sockets at once, and "it was executed once" is asserted by
// reading this from the test goroutine while workers write it. An unsynchronised
// counter here is a -race failure, and worse, it can make a real race look like a
// flake.
type fakeWallet struct {
	mu      sync.Mutex
	balance int64
	calls   int
	// held, when set, keeps a Balance call from answering until it is closed.
	held chan struct{}
	// panicWith, when set, makes Balance panic. It is how the containment tests
	// inject a panic into the handle path: the SHAPE is what is being covered —
	// any panic while handling a request — and keying it on the one bug that
	// produced `xmc` would cover that bug and nothing else.
	panicWith string
}

func (f *fakeWallet) Balance(context.Context) (int64, error) {
	f.mu.Lock()
	f.calls++
	held := f.held
	boom := f.panicWith
	f.mu.Unlock()
	if boom != "" {
		panic(boom)
	}
	if held != nil {
		// A read that has not answered yet, so a test can have the winner of a
		// claim race still working while the duplicate deliveries arrive.
		<-held
	}
	return f.balance, nil
}

func (f *fakeWallet) hold(release chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.held = release
}

func (f *fakeWallet) balanceCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeInvoices struct {
	minted int
	// filters records what List was ASKED for, because d24.12's bug was a filter
	// parsed and then dropped — asserting on returned rows would have passed
	// against exactly that.
	filters []store.TxnFilter
	txns    []store.Txn
}

func (f *fakeInvoices) Mint(_ context.Context, amountMsat int64, description string) (Invoice, error) {
	f.minted++
	return Invoice{
		Bolt11: "lnbcrt1minted", PaymentHash: "hash", AmountMsat: amountMsat,
		Description: description,
	}, nil
}

func (f *fakeInvoices) Lookup(_ context.Context, hash string) (Invoice, bool, error) {
	if hash != "hash" {
		return Invoice{}, false, nil
	}
	return Invoice{Bolt11: "lnbcrt1minted", PaymentHash: hash}, true, nil
}

func (f *fakeInvoices) List(_ context.Context, filter store.TxnFilter) ([]store.Txn, error) {
	f.filters = append(f.filters, filter)
	return f.txns, nil
}

type fakeNode struct{ info NodeInfo }

func (f *fakeNode) Info(context.Context) (NodeInfo, error) { return f.info, nil }

func quiet() *slog.Logger {
	return logging.New(io.Discard, logging.NewLevelVar(slog.LevelDebug))
}

var errNoRealRelay = errors.New("no relay in this test")

// The bug the regtest stack found, and it is a denial of service.
//
// created_at is the CLIENT's claim. A request dated into the future is refused
// for being outside the freshness window — but the first version advanced
// nwc_since to its timestamp anyway, which moves the subscription filter into
// the future too. The relay then delivers NOTHING until real time catches up:
// one request dated a year ahead silences the service for a year, from anyone
// who can reach the relay.
//
// Both halves are asserted, because "never advance" would also pass the first:
// a request outside the window must not move the resume point, and one inside it
// must.
func TestAnOutOfWindowRequestCannotMoveTheResumePoint(t *testing.T) {
	h := newHarness(t)

	future := h.clock.at.Add(365 * 24 * time.Hour)
	h.service.handleOne(t.Context(), h.conn,
		h.requestAt(t, h.client, MethodGetBalance, nil, future))

	since, err := h.service.since(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if since.After(h.clock.at) {
		t.Fatalf("the resume point moved to %v, past now (%v) — the subscription would ask the "+
			"relay for events after that and be delivered nothing until real time caught up",
			since, h.clock.at)
	}

	// And a request INSIDE the window does advance it, or the resume point never
	// moves and every restart replays the whole window.
	fresh := h.clock.at.Add(-time.Second)
	h.service.handleOne(t.Context(), h.conn,
		h.requestAt(t, h.client, MethodGetBalance, nil, fresh))
	since, err = h.service.since(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !since.Equal(fresh.Truncate(time.Second)) {
		t.Errorf("the resume point is %v after a fresh request, want %v", since, fresh)
	}
}

// fakeAuditor is the nwc.Auditor seam: it records what would have reached §12's
// durable trail.
type fakeAuditor struct {
	mu     sync.Mutex
	rows   []auditedRow
	err    error
	calls  int
	closed bool
}

type auditedRow struct {
	level slog.Level
	msg   string
	event logging.Event
	attrs map[string]string
}

func (f *fakeAuditor) Record(_ context.Context, level slog.Level, msg string,
	event logging.Event, attrs ...slog.Attr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return f.err
	}
	row := auditedRow{level: level, msg: msg, event: event, attrs: map[string]string{}}
	for _, a := range attrs {
		row.attrs[a.Key] = a.Value.Resolve().String()
	}
	f.rows = append(f.rows, row)
	return nil
}

func (f *fakeAuditor) events() []auditedRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.rows)
}

// `xmc` Fix B: a panic while handling a request is contained and written down.
//
// THE SHAPE, NOT THE INSTANCE. The panic is injected into the wallet rather than
// produced by a missing encryption tag: that bug has its own regression test and
// Fix A closed it. What this covers is the property that made it an outage — one
// authorized client's request must not be able to take LNURL, zap receipts and
// the admin UI down with it, which is what sharing a process means.
func TestAPanicWhileHandlingARequestIsContainedAndRecorded(t *testing.T) {
	h := newHarness(t)
	h.wallet.panicWith = "injected: a handler that cannot finish"

	event := h.request(t, h.client, MethodGetBalance, nil)
	// Through dispatchOne, because that is where the recover lives. Calling
	// handle directly takes the test process down, which is the point.
	h.service.dispatchOne(t.Context(), h.conn, event)
	h.conn.working.Wait()

	// Reaching this line at all is criterion 1: the process survived.
	var row *auditedRow
	for _, r := range h.audit.events() {
		if r.event == logging.EventNWCPanic {
			row = &r
			break
		}
	}
	if row == nil {
		t.Fatalf("no %s row was written. The panic happens before §8's replay claim, so the "+
			"request was never claimed, cached or answered — without this row nothing "+
			"anywhere records that it arrived, and a contained panic is a silent drop",
			logging.EventNWCPanic)
	}
	if got := row.attrs["connection"]; got != strconv.FormatInt(h.conn.row().ID, 10) {
		t.Errorf("the row names connection %q, want %d", got, h.conn.row().ID)
	}
	if row.attrs["event"] == "" {
		t.Error("the row does not name the event, which is what identifies the dropped request")
	}
	// The body is a paired client's encrypted content and must not be in it.
	for key, value := range row.attrs {
		if strings.Contains(value, event.Content) {
			t.Errorf("the %s attribute carries the request body", key)
		}
	}

	// The connection keeps serving: one poison request costs one request.
	h.wallet.panicWith = ""
	h.wallet.balance = 777_000
	if resp := h.handle(t, MethodGetBalance, nil); resp.Error != nil {
		t.Errorf("the connection stopped serving after a contained panic: %+v", resp.Error)
	}
}

// `xmc` Fix C: a pairing whose requests keep crashing is paused, and only that
// pairing.
//
// Recover alone turns a crash loop into a panic loop — same client, same
// request, same failure, for ever. This is what stops it, and the second half of
// the test is the half that matters: a counter kept anywhere but on the row
// would disable the operator's OTHER pairings too.
func TestRepeatedPanicsPauseOnlyTheOffendingPairing(t *testing.T) {
	h := newHarness(t)
	other := h.secondConnection(t)
	h.wallet.panicWith = "injected"

	for range MaxPanicsPerConnection {
		h.panicOnce(t, h.conn, h.client)
	}
	// THE ORDER IS THE TEST. One panic on the innocent pairing AFTER the first
	// is already over its threshold: with a per-connection count that is its
	// first and it keeps serving, and with a global one it is over the line the
	// moment it touches it. Panicking it first proves nothing, because the PAUSE
	// is per-id either way — measured, by planting a global counter and watching
	// the earlier version of this test pass.
	h.panicOnce(t, other, h.otherClient)

	rows, err := h.db.AllNWCConnections(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		switch row.ID {
		case h.conn.row().ID:
			if !row.Paused() {
				t.Errorf("the pairing panicked %d times and is not paused; recover without a "+
					"quarantine is a panic loop that never ends", MaxPanicsPerConnection)
			}
			if row.PausedAt.IsZero() {
				t.Error("the pause records no time, so the page cannot say when")
			}
			if !strings.Contains(row.PausedReason, "re-enable") {
				t.Errorf("the reason %q does not tell the operator what to do about it",
					row.PausedReason)
			}
		case other.row().ID:
			if row.Paused() {
				t.Error("a DIFFERENT pairing was paused by this one's panics; the count is not " +
					"per connection, and one client's broken build just disabled the " +
					"operator's others")
			}
		}
	}

	// It stops being served, which is what the quarantine is for.
	active, err := h.db.ActiveNWCConnections(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range active {
		if row.ID == h.conn.row().ID {
			t.Error("the paused pairing is still in the served set; a quarantine that still " +
				"answers is a quarantine that did nothing")
		}
	}

	// And the operator can see it and undo it, without re-pairing a phone.
	resumedIt, err := h.db.ResumeNWCConnection(t.Context(), h.conn.row().ID)
	if err != nil || !resumedIt {
		t.Fatalf("resuming the pairing: changed=%v err=%v", resumedIt, err)
	}
	// And a second resume changes nothing, so the handler has something honest
	// to key its audit row on.
	if again, err := h.db.ResumeNWCConnection(t.Context(), h.conn.row().ID); err != nil || again {
		t.Errorf("resuming an unpaused pairing reported a change (%v, %v); the trail would "+
			"carry a row for something that did not happen", again, err)
	}
	resumed, found, err := h.db.NWCConnection(t.Context(), h.conn.row().ID)
	if err != nil || !found {
		t.Fatalf("reading the resumed pairing: found=%v err=%v", found, err)
	}
	if resumed.Paused() {
		t.Error("the pairing is still paused after the operator re-enabled it")
	}
	if resumed.PanicCount != 0 {
		t.Errorf("the panic count is %d after a resume; the next single panic would pause it "+
			"again and the operator's action would have bought nothing", resumed.PanicCount)
	}
}

// `xmc` Fix C, Ruling B: the quarantine outlives the process.
//
// A per-process counter is re-armed by exactly the restarts a crash loop
// produces — during the incident the process restarted fifteen times. This
// asserts the state a fresh Service reads, which is what a restart is.
func TestTheQuarantineSurvivesARestart(t *testing.T) {
	h := newHarness(t)
	h.wallet.panicWith = "injected"
	for range MaxPanicsPerConnection {
		h.panicOnce(t, h.conn, h.client)
	}

	// A brand-new service over the SAME store is what a restart looks like from
	// here: nothing in memory survives, and the row is all there is.
	restarted := New(h.db, h.relays, h.wallet, h.invoices, h.node, h.spend,
		Options{Log: logging.New(h.logs, logging.NewLevelVar(slog.LevelDebug)),
			Now: h.clock.now, Audit: h.audit})
	rows, err := restarted.store.ActiveNWCConnections(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID == h.conn.row().ID {
			t.Error("the paused pairing is served again after a restart; a limit that forgets " +
				"is not a limit, and the restart is the thing a crash loop produces")
		}
	}
}

// secondConnection is another pairing on the same store, with its own keys.
//
// Fix C's scoping test needs two, because the mistake it is looking for — a
// panic counter that is not per connection — is invisible with one. It goes
// through addConnection rather than building a row of its own, so a change to
// how a test connection is made reaches this too.
func (h *harness) secondConnection(t *testing.T) *connection {
	t.Helper()
	row := h.addConnection("another app", "", nil)
	service, err := nostr.Parse(row.ServicePrivkey)
	if err != nil {
		t.Fatal(err)
	}
	client, err := nostr.Parse(row.ClientSecret)
	if err != nil {
		t.Fatal(err)
	}
	h.otherClient = client
	return newConnection(row, service)
}

// panicOnce drives one request that crashes the handler, through the dispatch
// path where the recover lives, and waits for the worker to finish.
func (h *harness) panicOnce(t *testing.T, conn *connection, from nostr.Identity) {
	t.Helper()
	// A fresh timestamp per call, so §8's replay cache does not answer the
	// second one from the first one's row and skip the handler entirely.
	h.clock.at = h.clock.at.Add(time.Second)
	event := h.requestTo(t, conn, from, nostr.NIP44, MethodGetBalance, nil, h.clock.at)
	h.service.dispatchOne(t.Context(), conn, event)
	conn.working.Wait()
}

// `xmc`: an inbound NWC request is visible in the log, once, whatever becomes
// of it — and it carries nothing a client chose the contents of.
//
// The 0.1.11 outage was diagnosed from stack traces because nothing logged the
// event. A box that crashed 32 times with DEBUG live could not produce the
// request that did it; the tag names alone would have answered it in seconds.
func TestAnInboundRequestIsLoggedWithoutItsContents(t *testing.T) {
	for _, c := range []struct {
		name    string
		prepare func(h *harness) *gonostr.Event
	}{
		{
			// Answered.
			name: "answered",
			prepare: func(h *harness) *gonostr.Event {
				h.wallet.balance = 12_345
				return h.request(t, h.client, MethodGetBalance, nil)
			},
		},
		{
			// REFUSED, and this half is the point: a line that appears only on
			// success is worthless for the class of bug it exists for.
			name: "refused",
			prepare: func(h *harness) *gonostr.Event {
				event := h.request(t, h.client, Method("not_a_method"), nil)
				return event
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			event := c.prepare(h)
			h.service.handle(t.Context(), h.conn, event)

			logs := h.logs.String()
			line := ""
			for _, l := range strings.Split(logs, "\n") {
				if strings.Contains(l, "handling an NWC request") {
					line = l
					break
				}
			}
			if line == "" {
				t.Fatalf("no line logged the inbound request, so it cannot be produced from "+
					"the log at any level. Logs were:\n%s", logs)
			}
			if !strings.Contains(line, event.ID) {
				t.Error("the line does not name the event id, which is what identifies it")
			}
			if !strings.Contains(line, "encryption") {
				t.Error("the line does not carry the tag names; 'was there an encryption tag' " +
					"is the question that cost an outage")
			}
			// The two things that must never be there.
			if strings.Contains(line, event.Content) {
				t.Error("the line carries the request content, which is a paired client's " +
					"encrypted payload (§12)")
			}
			for _, tag := range event.Tags {
				// `encryption` is EXEMPT, and narrowly. The line names the
				// negotiated scheme as a token this app chose from a closed
				// vocabulary — see TestTheInboundLineNamesTheRequestedEncryption
				// Scheme, which asserts that an unsupported one prints the word
				// "unsupported" and never the client's own string. For the two
				// supported schemes the token happens to equal the tag's text,
				// which is what makes the blanket check below fire on it; the
				// value was not copied, it was canonicised by
				// nostr.EncryptionFromTag.
				//
				// The exemption is per-TAG rather than per-value so this stays a
				// list of one: a second tag whose value someone wants on the line
				// has to be argued for here, which is the point.
				if len(tag) > 0 && tag[0] == "encryption" {
					continue
				}
				if len(tag) > 1 && tag[1] != "" && strings.Contains(line, tag[1]) {
					t.Errorf("the line carries the value of tag %q; a tag value is whatever "+
						"the client chose to put there, and the NAME is what answers the "+
						"question", tag[0])
				}
			}
		})
	}
}

// `xmc`, Ruling C: a healthy install adds nothing at INFO. The line is for an
// investigation, and it fires once per authorized request.
func TestTheInboundRequestLineIsDebugOnly(t *testing.T) {
	h := newHarness(t)
	h.service.log = logging.New(h.logs, logging.NewLevelVar(slog.LevelInfo))
	h.wallet.balance = 1

	h.service.handle(t.Context(), h.conn, h.request(t, h.client, MethodGetBalance, nil))

	if strings.Contains(h.logs.String(), "handling an NWC request") {
		t.Error("the inbound-request line is written at INFO; on a busy pairing that is the " +
			"app's noisiest line, on every install, for ever")
	}
}

// The inbound line names WHICH encryption scheme the client asked for, as a
// token this app chose (`2026-08-27-log-encryption-scheme.md`).
//
// The measurement that wanted this: three Amethyst builds, one stalling on new
// pairings and one without the NIP-44 fix not stalling at all, which no "the
// fixes help" story explains. The hypothesis is that they are not all speaking
// the same scheme — and the tag NAMES on this line say only that an encryption
// tag was present, which is not the question.
//
// FOUR OUTCOMES, and the first two are why "log the resolved scheme" is not
// enough: `scheme` is already defaulted to NIP-04 when the tag is absent, so it
// cannot tell an implicit fallback from an explicit choice, and telling those
// apart is the whole point.
//
// THE FOURTH IS A TOKEN AND NOT THE CLIENT'S STRING, which is the one decision
// in this test. The blanket rule above — a tag value is whatever the client
// chose to put there — is not weakened for the sake of a diagnostic: what is
// logged for an unsupported scheme is the word "unsupported", so an operator
// learns it happened without the client's bytes reaching their log. The two
// supported cases coincide with the client's text because the vocabulary is
// fixed, not because the value was copied — nostr.EncryptionFromTag canonicises
// it, so odd casing or padding logs as the constant.
func TestTheInboundLineNamesTheRequestedEncryptionScheme(t *testing.T) {
	for _, c := range []struct {
		name string
		tags func(h *harness) gonostr.Tags
		want string
		deny string
	}{
		{
			name: "absent",
			tags: func(h *harness) gonostr.Tags {
				return gonostr.Tags{{"p", h.conn.row().ServicePubkey}}
			},
			want: "absent",
		},
		{
			name: "explicit nip04",
			tags: func(h *harness) gonostr.Tags {
				return gonostr.Tags{{"p", h.conn.row().ServicePubkey}, {"encryption", "nip04"}}
			},
			want: "nip04",
		},
		{
			name: "nip44",
			tags: func(h *harness) gonostr.Tags {
				return gonostr.Tags{{"p", h.conn.row().ServicePubkey}, {"encryption", "nip44_v2"}}
			},
			want: "nip44_v2",
		},
		{
			// Invisible until now: this request is refused on the next line and
			// logged nowhere at all.
			name: "unsupported",
			tags: func(h *harness) gonostr.Tags {
				return gonostr.Tags{{"p", h.conn.row().ServicePubkey}, {"encryption", "nip44_v3"}}
			},
			want: "unsupported",
			deny: "nip44_v3",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.wallet.balance = 1
			event := h.request(t, h.client, MethodGetBalance, nil)
			event.Tags = c.tags(h)
			sign(t, h.client, event)

			h.service.handle(t.Context(), h.conn, event)

			line := inboundLine(t, h)
			if !strings.Contains(line, `"encryption":"`+c.want+`"`) {
				t.Errorf("the line does not name the requested scheme as %q; without it "+
					"'which scheme did this build ask for' cannot be answered from the log:\n%s",
					c.want, line)
			}
			if c.deny != "" && strings.Contains(line, c.deny) {
				t.Errorf("the line carries the client's own string %q; an unsupported scheme "+
					"is reported as a token this app chose, because a tag value is whatever "+
					"the client put there:\n%s", c.deny, line)
			}
		})
	}
}

// inboundLine returns the one line that logs the inbound request.
func inboundLine(t *testing.T, h *harness) string {
	t.Helper()
	for _, l := range strings.Split(h.logs.String(), "\n") {
		if strings.Contains(l, "handling an NWC request") {
			return l
		}
	}
	t.Fatalf("no line logged the inbound request. Logs were:\n%s", h.logs.String())
	return ""
}
