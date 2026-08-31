package main

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/wallet"
)

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
	digits := regexp.MustCompile(`[0-9]`)

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
