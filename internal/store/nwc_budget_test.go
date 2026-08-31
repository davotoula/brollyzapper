package store_test

import (
	"sync"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

// §8 steps 5 and 6, and they are ONE statement rather than two.
//
// The ladder reads "budget window expired → reset budget_used_msat, roll the
// window" and then "amount + max_fee > budget remaining → QUOTA_EXCEEDED". Read
// as two, they are a check followed by an increment with a gap in between, and
// two requests can both pass the check before either increments (test-spec E6).
// The roll, the check and the increment are therefore one guarded UPDATE, and
// these tests are about that statement.
func TestABudgetReservationFitsOrItDoesNot(t *testing.T) {
	s, _ := open(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	conn := seedBudgetConnection(t, s, 100_000, store.BudgetDaily, now.Add(time.Hour))

	outcome, err := s.ReserveNWCBudget(t.Context(), conn.ID, 60_000, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("ReserveNWCBudget: %v", err)
	}
	if outcome != store.BudgetTaken {
		t.Fatal("60,000 msat did not fit a 100,000 msat budget")
	}
	if used := budgetUsed(t, s, conn.ID); used != 60_000 {
		t.Errorf("budget_used_msat = %d, want 60,000 — the reservation takes amount + max_fee", used)
	}

	// The second does not fit, and the first must still be there afterwards: a
	// refused reservation that had already incremented would charge a connection
	// for a payment it was not allowed to make.
	outcome, err = s.ReserveNWCBudget(t.Context(), conn.ID, 60_000, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("ReserveNWCBudget: %v", err)
	}
	if outcome == store.BudgetTaken {
		t.Error("120,000 msat fitted a 100,000 msat budget")
	}
	if used := budgetUsed(t, s, conn.ID); used != 60_000 {
		t.Errorf("budget_used_msat = %d after a refused reservation, want 60,000 unchanged", used)
	}
}

// A NULL budget is unlimited — §4's own comment — and still bounded by the
// ceiling, which is a different check at a different layer (§8 step 7).
func TestANullBudgetAlwaysFits(t *testing.T) {
	s, _ := open(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	conn := seedBudgetConnection(t, s, 0, store.BudgetNever, time.Time{})

	outcome, err := s.ReserveNWCBudget(t.Context(), conn.ID, 21_000_000_000, now, time.Time{})
	if err != nil {
		t.Fatalf("ReserveNWCBudget: %v", err)
	}
	if outcome != store.BudgetTaken {
		t.Error("a connection with no budget refused a payment; NULL means unlimited (§4)")
	}
	if used := budgetUsed(t, s, conn.ID); used != 21_000_000_000 {
		t.Errorf("budget_used_msat = %d; an unlimited budget still COUNTS, so the operator "+
			"can see what a connection has spent", used)
	}
}

// §8 step 5: an expired window resets the counter, in the same statement that
// checks it.
func TestAnExpiredWindowRollsAndTheReservationFitsAgain(t *testing.T) {
	s, _ := open(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	conn := seedBudgetConnection(t, s, 100_000, store.BudgetDaily, now.Add(time.Hour))

	if outcome, err := s.ReserveNWCBudget(t.Context(), conn.ID, 90_000, now, now.Add(24*time.Hour)); err != nil || outcome != store.BudgetTaken {
		t.Fatalf("ReserveNWCBudget: outcome=%v err=%v", outcome, err)
	}

	// A day later the window has rolled, so the same 90,000 fits again — and the
	// counter shows only the new payment, not the sum of both.
	later := now.Add(2 * time.Hour)
	outcome, err := s.ReserveNWCBudget(t.Context(), conn.ID, 90_000, later, later.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("ReserveNWCBudget: %v", err)
	}
	if outcome != store.BudgetTaken {
		t.Fatal("the reservation was refused after its window expired; §8 step 5 rolls it")
	}
	if used := budgetUsed(t, s, conn.ID); used != 90_000 {
		t.Errorf("budget_used_msat = %d after the roll, want 90,000 — the old window's spend "+
			"must not carry into the new one", used)
	}
	if renews := budgetRenewsAt(t, s, conn.ID); renews != later.Add(24*time.Hour).Unix() {
		t.Errorf("budget_renews_at = %d, want %d — the window has to move too, or every "+
			"reservation from now on rolls it again", renews, later.Add(24*time.Hour).Unix())
	}
}

// Test-spec E6, at the layer that has to make it true.
//
// Sixteen goroutines, one budget with room for exactly four. If the check and
// the increment are not one statement, more than four see room and the
// connection spends past its budget — which is the whole reason §8 puts the
// ladder in a transaction.
func TestConcurrentReservationsCannotOverspendOneWindow(t *testing.T) {
	s, _ := open(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	conn := seedBudgetConnection(t, s, 40_000, store.BudgetDaily, now.Add(time.Hour))

	const racers = 16
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		fits  int
		fails []error
	)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcome, err := s.ReserveNWCBudget(t.Context(), conn.ID, 10_000, now, now.Add(24*time.Hour))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				fails = append(fails, err)
				return
			}
			if outcome == store.BudgetTaken {
				fits++
			}
		}()
	}
	wg.Wait()

	for _, err := range fails {
		t.Errorf("ReserveNWCBudget: %v", err)
	}
	if fits != 4 {
		t.Errorf("%d of %d reservations fitted a budget with room for 4; the check and the "+
			"increment must be one statement or two racers both see room", fits, racers)
	}
	if used := budgetUsed(t, s, conn.ID); used != 40_000 {
		t.Errorf("budget_used_msat = %d, want exactly 40,000", used)
	}
}

// §8: a failed payment must not consume budget — so what a reservation took has
// to be returnable, exactly.
func TestReleasingABudgetReservationReturnsIt(t *testing.T) {
	s, _ := open(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	conn := seedBudgetConnection(t, s, 100_000, store.BudgetDaily, now.Add(time.Hour))

	if _, err := s.ReserveNWCBudget(t.Context(), conn.ID, 60_000, now, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.AdjustNWCBudget(t.Context(), conn.ID, -60_000); err != nil {
		t.Fatalf("AdjustNWCBudget: %v", err)
	}
	if used := budgetUsed(t, s, conn.ID); used != 0 {
		t.Errorf("budget_used_msat = %d after the payment failed, want 0 — §8: a failed "+
			"payment consumes no budget", used)
	}
}

// A release can outlive its window, and the counter must not go negative.
//
// Reserve, the window rolls (resetting the counter to zero), then the payment
// fails and returns what it took. Subtracting from zero would leave a NEGATIVE
// used figure, which is a connection with MORE than its budget for the rest of
// the window — a refunded payment turning into extra spending authority.
func TestAReleaseAcrossAWindowRollCannotGoNegative(t *testing.T) {
	s, _ := open(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	conn := seedBudgetConnection(t, s, 100_000, store.BudgetDaily, now.Add(time.Hour))

	if _, err := s.ReserveNWCBudget(t.Context(), conn.ID, 60_000, now, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// The window rolls under it.
	later := now.Add(2 * time.Hour)
	if _, err := s.ReserveNWCBudget(t.Context(), conn.ID, 1_000, later, later.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.AdjustNWCBudget(t.Context(), conn.ID, -60_000); err != nil {
		t.Fatalf("AdjustNWCBudget: %v", err)
	}
	if used := budgetUsed(t, s, conn.ID); used < 0 {
		t.Errorf("budget_used_msat = %d; a release that outlived its window must clamp at "+
			"zero, or a refund becomes spending authority", used)
	}
}

func seedBudgetConnection(t *testing.T, s *store.Store, budgetMsat int64,
	period string, renewsAt time.Time) store.NWCConnection {
	t.Helper()
	conn := store.NWCConnection{
		Name:           "budget test",
		ServicePrivkey: secret.New("aa"),
		ServicePubkey:  "pub" + period + time.Now().Format("150405.000000000"),
		ClientPubkey:   "client",
		ClientSecret:   secret.New("bb"),
		Relays:         []string{"wss://relay.example"},
		Permissions:    append(store.DefaultPermissions(), store.PermissionPay),
		BudgetPeriod:   period,
		BudgetRenewsAt: renewsAt,
		CreatedAt:      time.Unix(1_700_000_000, 0).UTC(),
	}
	limits := store.NoLimits
	if budgetMsat > 0 {
		conn.BudgetMsat = &budgetMsat
		limits = store.DefaultLimits
	}
	// NoLimits when no budget was asked for, which since plk has to be SAID: a
	// connection with the pay group and a blank budget now gets the guard's caps
	// by default, and these tests are about the unlimited case on purpose.
	created, err := s.CreateNWCConnection(t.Context(), conn, limits)
	if err != nil {
		t.Fatalf("CreateNWCConnection: %v", err)
	}
	return created
}

func budgetUsed(t *testing.T, s *store.Store, id int64) int64 {
	t.Helper()
	conn, found, err := s.NWCConnection(t.Context(), id)
	if err != nil || !found {
		t.Fatalf("NWCConnection(%d): found=%v err=%v", id, found, err)
	}
	return conn.BudgetUsedMsat
}

func budgetRenewsAt(t *testing.T, s *store.Store, id int64) int64 {
	t.Helper()
	conn, found, err := s.NWCConnection(t.Context(), id)
	if err != nil || !found {
		t.Fatalf("NWCConnection(%d): found=%v err=%v", id, found, err)
	}
	return conn.BudgetRenewsAt.Unix()
}

// A period with no renewal point set is a "daily" budget that never rolls.
//
// Found by the d24.4 review, and it is a trap laid for d24.5: the CASE requires
// budget_renews_at IS NOT NULL, so a connection created with a period and no
// point counts up once and then refuses for ever — and SetNWCConnectionLimits
// deliberately does not touch budget_used_msat, so the UI cannot clear it
// either. The roll has to be able to ESTABLISH the point, not only advance it.
func TestAPeriodWithNoRenewalPointStillRolls(t *testing.T) {
	s, _ := open(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	// No renewal point: exactly what CreateNWCConnection writes for a zero time.
	conn := seedBudgetConnection(t, s, 10_000, store.BudgetDaily, time.Time{})

	if outcome, err := s.ReserveNWCBudget(t.Context(), conn.ID, 10_000, now, now.AddDate(0, 0, 1)); err != nil || outcome != store.BudgetTaken {
		t.Fatalf("the first reservation: outcome=%v err=%v", outcome, err)
	}

	// A month later the window has long since rolled.
	later := now.AddDate(0, 1, 0)
	outcome, err := s.ReserveNWCBudget(t.Context(), conn.ID, 10_000, later, later.AddDate(0, 0, 1))
	if err != nil {
		t.Fatalf("ReserveNWCBudget: %v", err)
	}
	if outcome != store.BudgetTaken {
		t.Error("a daily budget with no renewal point never rolled; the connection is refused " +
			"for ever and no UI can clear the counter")
	}
	if renews := budgetRenewsAt(t, s, conn.ID); renews != later.AddDate(0, 0, 1).Unix() {
		t.Errorf("budget_renews_at = %d, want the point the roll should have established", renews)
	}
}

// A period of `never` is a LIFETIME budget: the counter keeps counting.
//
// The roll's "establish a missing window" clause must not fire for it, or the
// counter resets on every reservation and the budget stops being one. Both
// halves of that came from the same review finding, and they pull in opposite
// directions — which is exactly why both are tested.
func TestALifetimeBudgetAccumulatesRatherThanRolling(t *testing.T) {
	s, _ := open(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	conn := seedBudgetConnection(t, s, 100_000, store.BudgetNever, time.Time{})

	for i := range 3 {
		outcome, err := s.ReserveNWCBudget(t.Context(), conn.ID, 30_000,
			now.AddDate(0, i, 0), time.Time{})
		if err != nil || outcome != store.BudgetTaken {
			t.Fatalf("reservation %d: outcome=%v err=%v", i, outcome, err)
		}
	}
	if used := budgetUsed(t, s, conn.ID); used != 90_000 {
		t.Fatalf("budget_used_msat = %d after three 30,000 msat payments, want 90,000 — a "+
			"`never` period never rolls, so the counter accumulates", used)
	}

	// And the fourth does not fit, which is the point of a lifetime budget.
	if outcome, err := s.ReserveNWCBudget(t.Context(), conn.ID, 30_000,
		now.AddDate(1, 0, 0), time.Time{}); err != nil || outcome == store.BudgetTaken {
		t.Errorf("a fourth payment fitted a spent lifetime budget: outcome=%v err=%v", outcome, err)
	}
}

// The correction goes UP as well as down: a route that cost more than the
// reserve has to be charged for, or a connection keeps budget it has spent.
func TestABudgetCorrectionCanCharge(t *testing.T) {
	s, _ := open(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	conn := seedBudgetConnection(t, s, 100_000, store.BudgetDaily, now.Add(time.Hour))

	if _, err := s.ReserveNWCBudget(t.Context(), conn.ID, 60_000, now, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.AdjustNWCBudget(t.Context(), conn.ID, 500); err != nil {
		t.Fatalf("AdjustNWCBudget: %v", err)
	}
	if used := budgetUsed(t, s, conn.ID); used != 60_500 {
		t.Errorf("budget_used_msat = %d, want 60,500 — the route cost 500 msat more than the "+
			"reserve, and the connection has spent it", used)
	}
}
