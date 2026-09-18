package main

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/wallet"
)

// digits is `0vk.14`'s rule as a pattern: no refusal a client reads may carry a
// quantity. Shared by both tests below — one policy, one expression of it.
var digits = regexp.MustCompile(`[0-9]`)

// 0vk.14: the held-spending refusal carries NO quantity.
//
// It used to format the shortfall verbatim — "the wallet authorises %d msat more
// than the node can send". A paired client also calls get_balance, and
// subtracting one from the other gives it the NODE'S OUTBOUND CHANNEL BALANCE to
// the millisatoshi: a fact about the operator's node that nothing in NIP-47
// entitles a client to, handed over in a refusal (§8 ruling 3, no internals).
//
// The count in the unresolved-payments arm goes for the same reason. It is a
// smaller fact and it is the same kind of fact.
func TestTheHeldSpendingRefusalCarriesNoQuantity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		purse heldPurse
	}{
		{"a reconciliation shortfall", heldPurse{
			shortfall: wallet.Deficit{ShortfallMsat: 4_200_000, Cause: "a settled payment"},
			frozen:    true,
		}},
		{"payments from a previous run", heldPurse{unresolved: 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spend := nwcSpend{purse: heldSeam{heldPurse: tc.purse}, log: quietLog()}

			message, held, err := spend.Held(t.Context())

			if err != nil {
				t.Fatalf("Held: %v", err)
			}
			if !held {
				t.Fatal("spending is not reported as held; the fixture would prove nothing")
			}
			if digits.MatchString(message) {
				t.Errorf("the refusal carries a number: %q\n\nA client that also calls "+
					"get_balance can subtract this from that and learn the node's outbound "+
					"channel balance", message)
			}
			// It still says WHERE the operator looks — a refusal with the
			// diagnosis removed and nothing put back is a dead end.
			if !strings.Contains(message, "Security page") {
				t.Errorf("the refusal does not point at the Security page: %q", message)
			}
			if !strings.Contains(message, "held") {
				t.Errorf("the refusal does not say spending is held: %q", message)
			}
		})
	}
}

// heldPurse scripts the two freezes.
type heldPurse struct {
	shortfall  wallet.Deficit
	frozen     bool
	unresolved int
	// named is the subset of unresolved the resolver has given up on (`669`),
	// and it is what tells the self-clearing hold from the one that never will.
	named int
}

// heldSeam borrows seamPurse's spender half — Held touches none of it, and a
// second hand-written copy would be four methods that can drift from the ones
// already under test, for no gain.
type heldSeam struct {
	heldPurse
	seamPurse
}

func (h heldSeam) Shortfall(context.Context) (wallet.Deficit, bool, error) {
	return h.heldPurse.shortfall, h.heldPurse.frozen, nil
}

func (h heldSeam) UnresolvedPayments(context.Context) (int, error) {
	return h.heldPurse.unresolved, nil
}

func (h heldSeam) NamedUnresolvedPayments(context.Context) (int, error) {
	return h.heldPurse.named, nil
}

// `v7u`: a hold that does NOT clear itself must not tell the payer it does.
//
// The message Amethyst showed on the reference box for 22 hours was "this clears
// itself, and its owner can see the detail on the Security page" — about a row
// the resolver had already given up on, while the server's own log for the
// identical condition said "This does not clear itself". A payer told to wait,
// waits; the operator only found the button because someone wrote the diagnosis
// down.
//
// TWO PAGES, and the distinction is the fix: the Security page is where the
// operator READS about a hold, the Wallet page is where they ACT on one. Naming
// the wrong one is a dead end wearing an instruction's clothes.
func TestTheHeldRefusalNamesTheWalletPageOnlyForAHoldThatNeedsOne(t *testing.T) {
	// ONE BIT of expectation, not three. There are two pages and two sentences,
	// so "which page" and "may it say it clears itself" are the same fact said
	// three ways — and three columns are three places a new row can contradict
	// itself.
	for _, tc := range []struct {
		name  string
		purse heldPurse
		// named is whether the resolver has given up on at least one of the rows
		// holding this freeze, which is the whole of what the message turns on.
		named bool
	}{{
		name:  "the resolver has given up on one",
		purse: heldPurse{unresolved: 2, named: 1},
		named: true,
	}, {
		// A named row wins even when self-clearing ones outnumber it: it is the
		// only one with an action behind it, and the others may close on the next
		// pass without changing what the operator has to do.
		name:  "one named among several that are not",
		purse: heldPurse{unresolved: 9, named: 1},
		named: true,
	}, {
		name:  "none named yet",
		purse: heldPurse{unresolved: 3},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			// The Security page REPORTS a hold; the Wallet page is where the
			// operator acts on one. A named row needs the second.
			wantPage, wantOther := "Security page", "Wallet page"
			if tc.named {
				wantPage, wantOther = wantOther, wantPage
			}
			spend := nwcSpend{purse: heldSeam{heldPurse: tc.purse}, log: quietLog()}

			message, held, err := spend.Held(t.Context())
			if err != nil {
				t.Fatalf("Held: %v", err)
			}
			if !held {
				t.Fatal("spending is not reported as held; the fixture would prove nothing")
			}
			if !strings.Contains(message, wantPage) {
				t.Errorf("the refusal does not send the operator to the %s: %q",
					wantPage, message)
			}
			if strings.Contains(message, wantOther) {
				t.Errorf("the refusal sends the operator to the %s, where there is nothing "+
					"for them to do about this hold: %q", wantOther, message)
			}
			if got, want := strings.Contains(message, "clears itself"), !tc.named; got != want {
				t.Errorf("the refusal says the hold clears itself = %v, want %v: %q\n\n"+
					"A named row is waiting for a human and nothing else will ever move it "+
					"(`v7u`)", got, want, message)
			}
			// `0vk.14` still applies to the new sentence: no quantities.
			if digits.MatchString(message) {
				t.Errorf("the refusal carries a number: %q", message)
			}
		})
	}
}
