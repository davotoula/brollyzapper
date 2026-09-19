package main

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/preflight"
	"github.com/davotoula/brollyzapper/internal/wallet"
)

// holdClass is which unresolved-payment hold a surface says this is: none, one
// that clears itself, or one waiting for the operator on the Wallet page.
type holdClass string

const (
	holdNone     holdClass = "none"
	holdClearing holdClass = "clears itself"
	holdNamed    holdClass = "named"
)

// classOf reads a class back out of a surface's sentence, and refuses a
// sentence that claims both or neither: an ambiguous one is not a class.
func classOf(t *testing.T, surface, text string) holdClass {
	t.Helper()
	// The Security row's fallback, for a named count it could not read, is true
	// of both holds and so is neither: here it means the wiring failed.
	if strings.Contains(text, "Could not tell") {
		t.Fatalf("the %s could not read which hold it is: %q", surface, text)
	}
	walletPage, clears := strings.Contains(text, "Wallet page"), strings.Contains(text, "clears itself")
	switch {
	case walletPage && !clears:
		return holdNamed
	case clears && !walletPage:
		return holdClearing
	}
	t.Fatalf("the %s's sentence names neither hold or both, so it says nothing about which: %q",
		surface, text)
	return ""
}

// `j9d` criterion 2: the Security page and the NWC refusal cannot put one hold
// in different classes.
//
// FOUR readers of one fact, each composing its own sentence, is the root cause
// of `v7u`'s whole C class: fix C taught three of them to tell a named hold from
// a self-clearing one and missed the fourth, which went on telling the operator
// "usually … clears itself" on the page they were actually reading. The two
// sentences stay separate — the client's carries no count (`0vk.14`) and the
// operator's may — so what is shared is the classification, and this is where
// that sharing is held.
//
// Over a REAL store and wallet, through the production wiring on each side:
// newPreflightSources for the Security row, nwcSpend for the refusal. Each side's
// own tests pass with the other side reading a different count; only this one
// reads both off one state.
func TestTheSecurityRowAndTheNWCRefusalAgreeWhichHoldItIs(t *testing.T) {
	db, _ := openSeamStore(t)

	// A previous run that reserved two payments and died.
	past := time.Now().Add(-time.Hour)
	previous := wallet.New(db, wallet.Options{Now: func() time.Time { return past }, StartedAt: past})
	if err := previous.Allocate(t.Context(), 1_000_000, "float"); err != nil {
		t.Fatal(err)
	}
	var ids []wallet.ReservationID
	for _, hash := range []string{"0a", "0b"} {
		id, err := previous.Reserve(t.Context(), wallet.Reservation{
			AmountMsat: 10_000, MaxFeeMsat: 100, PaymentHash: hash, Ref: "the run that died"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	purse := wallet.New(db, wallet.Options{StartedAt: time.Now()})
	sources := newPreflightSources(&config.Server{}, nil, nil, db, nil,
		purse.UnresolvedPayments, purse.NamedUnresolvedPayments, netip.Addr{}, nil,
		func() bool { return false }, func(string) {})
	refusal := nwcSpend{purse: purse, log: quietLog()}

	both := func(t *testing.T) (security, client holdClass) {
		t.Helper()
		// ONLY the two inputs this row reads, taken from the production
		// construction; every other row renders not checked, which is not what
		// is under test and needs no node.
		wired := sources.inputs(func(context.Context) (lnd.BrokerStatus, error) {
			return lnd.BrokerStatus{}, nil
		})
		report := preflight.Run(t.Context(), preflight.Inputs{
			UnresolvedPayments:      wired.UnresolvedPayments,
			NamedUnresolvedPayments: wired.NamedUnresolvedPayments,
		})
		i := slices.IndexFunc(report.Checks, func(c preflight.Check) bool {
			return c.ID == preflight.CheckUnresolvedSpend
		})
		if i < 0 {
			t.Fatal("the report has no unresolved-payments row")
		}
		row := report.Checks[i]
		switch row.State {
		case preflight.Pass:
			security = holdNone
		case preflight.Fail:
			security = classOf(t, "Security row", row.Detail)
		default:
			t.Fatalf("the Security row is %v: %q", row.State, row.Detail)
		}

		message, held, err := refusal.Held(t.Context())
		if err != nil {
			t.Fatalf("Held: %v", err)
		}
		client = holdNone
		if held {
			client = classOf(t, "NWC refusal", message)
		}
		return security, client
	}

	for _, step := range []struct {
		name string
		// then moves the store to the state this step is about.
		then func(t *testing.T)
		want holdClass
	}{
		{"two payments no one has named", func(*testing.T) {}, holdClearing},
		{"the resolver names one of them, beside one it has not", func(t *testing.T) {
			if err := purse.MarkUnresolvable(t.Context(), ids[0], "the node has no record of it"); err != nil {
				t.Fatal(err)
			}
		}, holdNamed},
		{"the named one is settled, and the other is still pending", func(t *testing.T) {
			if err := purse.AssertOutcome(t.Context(), ids[0], false); err != nil {
				t.Fatal(err)
			}
		}, holdClearing},
		{"the last one is named and settled too", func(t *testing.T) {
			if err := purse.MarkUnresolvable(t.Context(), ids[1], "the node has no record of it"); err != nil {
				t.Fatal(err)
			}
			if err := purse.AssertOutcome(t.Context(), ids[1], false); err != nil {
				t.Fatal(err)
			}
		}, holdNone},
	} {
		t.Run(step.name, func(t *testing.T) {
			step.then(t)
			security, client := both(t)
			if security != client {
				t.Fatalf("one store state, two classes: the Security page says %q and the paired "+
					"client is told %q", security, client)
			}
			if security != step.want {
				t.Errorf("both surfaces say %q, want %q — they agree, and are both wrong", security, step.want)
			}
		})
	}
}
