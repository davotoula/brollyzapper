package store_test

import (
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

// plk: a connection created with the pay group and no limits is BOUNDED.
//
// Both limits are nullable and nil means "no limit", so before this a
// connection granted `pay` with stock values could spend the entire wallet
// ceiling in ONE request. The ladder enforces what it is given; the defaults
// were the problem, and they were the opposite of §2's posture everywhere else.
func TestAPayingConnectionIsNeverCreatedUnbounded(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0).UTC()

	conn, err := s.CreateNWCConnection(t.Context(), store.NWCConnection{
		Name:           "a wallet app",
		ServicePrivkey: secret.New("aa"),
		ServicePubkey:  "service-pub",
		ClientPubkey:   "client-pub",
		ClientSecret:   secret.New("bb"),
		Relays:         []string{"wss://relay.example"},
		Permissions:    append(store.DefaultPermissions(), store.PermissionPay),
		CreatedAt:      at,
		// No budget, no cap, no period: exactly what an operator who ticked the
		// box and typed nothing else would produce.
	}, store.DefaultLimits)
	if err != nil {
		t.Fatalf("CreateNWCConnection: %v", err)
	}

	if conn.BudgetMsat == nil {
		t.Fatal("a connection with the pay group was created with no budget; it can spend the " +
			"whole ceiling in one request")
	}
	if got := *conn.BudgetMsat; got != store.DefaultConnectionBudgetMsat {
		t.Errorf("budget = %d msat, want %d — the guard's own GUARD_MAX_SPEND_MSAT default, so "+
			"the system carries one set of numbers", got, store.DefaultConnectionBudgetMsat)
	}
	if conn.BudgetPeriod != store.BudgetDaily {
		t.Errorf("budget period = %q, want daily — a budget with no window is a lifetime one",
			conn.BudgetPeriod)
	}
	if conn.BudgetRenewsAt.IsZero() {
		t.Error("the budget has a period and no renewal point; the window would have to be " +
			"established by the first payment")
	}
	if conn.MaxPaymentMsat == nil {
		t.Fatal("a connection with the pay group was created with no per-payment cap; a daily " +
			"budget with no cap lets one request spend the day")
	}
	if got := *conn.MaxPaymentMsat; got != store.DefaultConnectionMaxPaymentMsat {
		t.Errorf("cap = %d msat, want %d — the guard's own GUARD_MAX_PAYMENT_MSAT default",
			got, store.DefaultConnectionMaxPaymentMsat)
	}

	// And it survives the round trip, because the ladder reads the ROW.
	stored, found, err := s.NWCConnection(t.Context(), conn.ID)
	if err != nil || !found {
		t.Fatalf("NWCConnection: found=%v err=%v", found, err)
	}
	if stored.BudgetMsat == nil || stored.MaxPaymentMsat == nil {
		t.Error("the defaults were returned but not written")
	}
}

// nil stays EXPRESSIBLE: unlimited-within-the-ceiling is a legitimate operator
// choice. It must simply never be what happens by default.
//
// The two are told apart by the caller saying so, which is what the UI's
// explicit "remove this limit" act produces.
func TestAnOperatorCanStillChooseUnlimited(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0).UTC()

	conn, err := s.CreateNWCConnection(t.Context(), store.NWCConnection{
		Name:           "deliberately unbounded",
		ServicePrivkey: secret.New("aa"),
		ServicePubkey:  "service-pub-2",
		ClientPubkey:   "client-pub",
		ClientSecret:   secret.New("bb"),
		Relays:         []string{"wss://relay.example"},
		Permissions:    append(store.DefaultPermissions(), store.PermissionPay),
		CreatedAt:      at,
	}, store.NoLimits)
	if err != nil {
		t.Fatalf("CreateNWCConnection: %v", err)
	}
	if conn.BudgetMsat != nil || conn.MaxPaymentMsat != nil {
		t.Errorf("an explicitly unlimited connection was given limits: budget=%v cap=%v",
			conn.BudgetMsat, conn.MaxPaymentMsat)
	}
}

// A connection WITHOUT the pay group gets no limits, because it cannot spend.
// Writing a budget for a connection that may not pay would be a number an
// operator has to reason about for no reason.
func TestAReceiveOnlyConnectionIsNotGivenSpendingLimits(t *testing.T) {
	s, _ := open(t)
	conn, err := s.CreateNWCConnection(t.Context(), store.NWCConnection{
		Name:           "read only",
		ServicePrivkey: secret.New("aa"),
		ServicePubkey:  "service-pub-3",
		ClientPubkey:   "client-pub",
		ClientSecret:   secret.New("bb"),
		Relays:         []string{"wss://relay.example"},
		Permissions:    store.DefaultPermissions(),
		CreatedAt:      time.Unix(1_700_000_000, 0).UTC(),
	}, store.DefaultLimits)
	if err != nil {
		t.Fatalf("CreateNWCConnection: %v", err)
	}
	if conn.BudgetMsat != nil || conn.MaxPaymentMsat != nil {
		t.Errorf("a connection that cannot pay was given spending limits: budget=%v cap=%v",
			conn.BudgetMsat, conn.MaxPaymentMsat)
	}
}

// The defaults ARE the guard's caps, and this is what keeps them so.
//
// internal/store must not import internal/config, so the numbers are written
// twice — and two copies of a number is exactly how they come to disagree. This
// test is the join: a stock connection may spend up to what the guard would
// allow it anyway, and if the guard's caps move, this goes red rather than the
// two silently parting company.
//
// EXPIRY CONDITION: when the guard's caps become operator-configurable (§10),
// "equal to the default" stops being the right relationship and this test has to
// be rewritten rather than updated.
func TestTheConnectionDefaultsAreTheGuardsCaps(t *testing.T) {
	if store.DefaultConnectionBudgetMsat != config.DefaultMaxSpendMsat {
		t.Errorf("a stock connection's budget is %d msat and the guard's window cap is %d; "+
			"they are meant to be one number so a stock connection cannot exceed what the "+
			"guard would allow anyway",
			store.DefaultConnectionBudgetMsat, config.DefaultMaxSpendMsat)
	}
	if store.DefaultConnectionMaxPaymentMsat != config.DefaultMaxPaymentMsat {
		t.Errorf("a stock connection's per-payment cap is %d msat and the guard's is %d",
			store.DefaultConnectionMaxPaymentMsat, config.DefaultMaxPaymentMsat)
	}
}
