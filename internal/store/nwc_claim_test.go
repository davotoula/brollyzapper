package store_test

import (
	"sync"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"
)

// §8's replay cache, claimed BEFORE the work rather than recorded after it.
//
// Wave 23 looked the request id up, executed, then wrote the row. Two
// deliveries of one request that overlap both find nothing, both execute, and
// the second write is discarded — which for make_invoice is two invoices and for
// d24.4's pay_invoice is two payments. The lookup and the claim have to be the
// same statement, and the insert is what makes them one.
func TestOnlyOneClaimOfARequestIdWins(t *testing.T) {
	s, _ := open(t)
	conn := seedBudgetConnection(t, s, 0, store.BudgetNever, time.Time{})
	at := time.Unix(1_700_000_000, 0).UTC()

	won, existing, _, err := s.ClaimNWCRequest(t.Context(), "event-1", conn.ID, "pay_invoice", "in progress", at)
	if err != nil {
		t.Fatalf("ClaimNWCRequest: %v", err)
	}
	if !won || existing != "" {
		t.Fatalf("the first claim did not win: won=%v existing=%q", won, existing)
	}

	won, existing, _, err = s.ClaimNWCRequest(t.Context(), "event-1", conn.ID, "pay_invoice", "in progress", at)
	if err != nil {
		t.Fatalf("ClaimNWCRequest: %v", err)
	}
	if won {
		t.Error("a second claim of the same request id won; the winner would execute twice")
	}
	if existing != "in progress" {
		t.Errorf("the loser was handed %q, want the stored response — a loser with nothing to "+
			"say would have to either execute or answer nothing", existing)
	}
}

// The claim is a PLACEHOLDER; completing it is what stores the real answer.
func TestCompletingAClaimReplacesItsResponse(t *testing.T) {
	s, _ := open(t)
	conn := seedBudgetConnection(t, s, 0, store.BudgetNever, time.Time{})
	at := time.Unix(1_700_000_000, 0).UTC()

	if _, _, _, err := s.ClaimNWCRequest(t.Context(), "event-2", conn.ID, "get_balance", "in progress", at); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteNWCRequest(t.Context(), "event-2", `{"result":{"balance":1}}`, at); err != nil {
		t.Fatalf("CompleteNWCRequest: %v", err)
	}

	got, found, err := s.NWCHandledResponse(t.Context(), "event-2")
	if err != nil || !found {
		t.Fatalf("NWCHandledResponse: found=%v err=%v", found, err)
	}
	if got != `{"result":{"balance":1}}` {
		t.Errorf("the cached response is %q; a replay would answer with the placeholder", got)
	}
}

// Twenty concurrent deliveries of one request id: exactly one may execute.
func TestConcurrentClaimsOfOneRequestElectOneWinner(t *testing.T) {
	s, _ := open(t)
	conn := seedBudgetConnection(t, s, 0, store.BudgetNever, time.Time{})
	at := time.Unix(1_700_000_000, 0).UTC()

	const racers = 20
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
		fails   []error
	)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			won, _, _, err := s.ClaimNWCRequest(t.Context(), "event-3", conn.ID, "pay_invoice", "busy", at)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				fails = append(fails, err)
			case won:
				winners++
			}
		}()
	}
	wg.Wait()

	for _, err := range fails {
		t.Errorf("ClaimNWCRequest: %v", err)
	}
	if winners != 1 {
		t.Errorf("%d of %d concurrent claims won; every winner executes the request", winners, racers)
	}
}

// The prune boundary, both sides (test-spec C6).
//
// A pruned row is a replay window reopened, so the test that only proves old
// rows go would pass for a prune that deleted everything.
func TestThePruneKeepsRowsYoungerThanTheRetention(t *testing.T) {
	s, _ := open(t)
	conn := seedBudgetConnection(t, s, 0, store.BudgetNever, time.Time{})
	now := time.Unix(1_700_000_000, 0).UTC()
	cutoff := now.Add(-24 * time.Hour)

	claim := func(id string, at time.Time) {
		t.Helper()
		if _, _, _, err := s.ClaimNWCRequest(t.Context(), id, conn.ID, "get_balance", "{}", at); err != nil {
			t.Fatal(err)
		}
	}
	claim("old", cutoff.Add(-time.Second))
	claim("boundary", cutoff)
	claim("young", cutoff.Add(time.Second))

	removed, err := s.PruneNWCHandled(t.Context(), cutoff)
	if err != nil {
		t.Fatalf("PruneNWCHandled: %v", err)
	}
	if removed != 1 {
		t.Errorf("the prune removed %d rows, want 1", removed)
	}
	for _, id := range []string{"boundary", "young"} {
		if _, found, err := s.NWCHandledResponse(t.Context(), id); err != nil || !found {
			t.Errorf("%q was pruned at the boundary; a row younger than the retention is a "+
				"replay window that must stay closed (found=%v err=%v)", id, found, err)
		}
	}
	if _, found, _ := s.NWCHandledResponse(t.Context(), "old"); found {
		t.Error("a row older than the retention survived the prune")
	}
}
