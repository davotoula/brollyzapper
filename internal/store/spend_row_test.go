package store_test

import (
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

// An outgoing payment records WHICH connection asked for it and WHAT it was for
// (d24.15, d24.16).
//
// txns.nwc_connection_id has existed since migration 0001 and nothing ever wrote
// it, which is the structural reason the startup resolver could not correct a
// crash-recovered payment's connection budget: it lives in cmd, knows nothing
// about NWC, and had only a ref string to go on. The description is the other
// half of the same row — the 0.1.9 field trip found every outgoing row rendering
// as an unlabelled debit while incoming rows carried their zap comment.
func TestAReservationRecordsItsConnectionAndItsDescription(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0).UTC()
	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		1_000_000, "float", at); err != nil {
		t.Fatal(err)
	}
	conn := aPayingConnection(t, s, at)

	id, err := s.ReserveSpend(t.Context(), store.SpendReservation{
		AmountMsat: 21_000, MaxFeeMsat: 10_000, PaymentHash: "hash-desc",
		Ref: "Amethyst on my phone", Description: "coffee",
		NWCConnectionID: conn.ID,
	}, at)
	if err != nil {
		t.Fatal(err)
	}

	pending := pendingByID(t, s, id)
	if pending.NWCConnectionID != conn.ID {
		t.Errorf("the reservation records connection %d, want %d — without it the resolver "+
			"cannot find whose budget a recovered payment over-charged",
			pending.NWCConnectionID, conn.ID)
	}
	if pending.AmountMsat != 21_000 || pending.FeeReservedMsat != 10_000 {
		t.Errorf("the reservation reports %d + %d msat, want 21000 + 10000 — the resolver "+
			"computes the budget correction from these", pending.AmountMsat, pending.FeeReservedMsat)
	}

	out := outgoingTxn(t, s)
	if out.Description != "coffee" {
		t.Errorf("the outgoing row's description is %q, want \"coffee\" — an operator's history "+
			"of unlabelled debits is what the field trip found", out.Description)
	}
}

// Settling records the PREIMAGE, which is the row's proof it paid.
//
// The irreversible edge d24.16 turns on: every payment made before this has no
// proof-of-payment in this app's ledger, permanently. LND keeps its own copy;
// the app's history cannot be backfilled honestly.
func TestSettlingRecordsThePreimage(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0).UTC()
	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		1_000_000, "float", at); err != nil {
		t.Fatal(err)
	}
	id, err := s.ReserveSpend(t.Context(), store.SpendReservation{
		AmountMsat: 21_000, MaxFeeMsat: 10_000, PaymentHash: "hash-preimage", Ref: "ref",
	}, at)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.SettleSpend(t.Context(), id, 2_055, secret.New("28aa50a3"), at); err != nil {
		t.Fatalf("SettleSpend: %v", err)
	}

	if got := outgoingTxn(t, s).Preimage.Reveal(); got != "28aa50a3" {
		t.Errorf("the settled row's preimage is %q, want 28aa50a3 — without it the row cannot "+
			"later prove settlement to anyone", got)
	}
}

// A settle with NO preimage leaves the column alone rather than blanking it.
//
// The resolver can meet a payment the node reports as SUCCEEDED without handing
// back a preimage, and a settle that refused — or that overwrote a good value
// with an empty one — would either strand the reservation for ever or destroy
// the proof the live path had already written.
func TestSettlingWithoutAPreimageDoesNotEraseOne(t *testing.T) {
	s, _ := open(t)
	at := time.Unix(1_700_000_000, 0).UTC()
	if err := s.AdjustBalance(t.Context(), store.KindAllocation, store.ReasonAllocate,
		1_000_000, "float", at); err != nil {
		t.Fatal(err)
	}
	id, err := s.ReserveSpend(t.Context(), store.SpendReservation{
		AmountMsat: 21_000, MaxFeeMsat: 10_000, PaymentHash: "hash-blank", Ref: "ref",
	}, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SettleSpend(t.Context(), id, 2_055, secret.String{}, at); err != nil {
		t.Fatalf("SettleSpend with no preimage: %v", err)
	}
	if got := outgoingTxn(t, s); got.State != store.TxnSettled {
		t.Errorf("state = %q, want settled — a settle must never be refused over a missing "+
			"proof, or the ceiling stays debited for ever", got.State)
	}
}

// aPayingConnection is a connection with the pay group, for tests that need a
// real id on the txns row's foreign key.
func aPayingConnection(t *testing.T, s *store.Store, at time.Time) store.NWCConnection {
	t.Helper()
	conn, err := s.CreateNWCConnection(t.Context(), store.NWCConnection{
		Name:           "a wallet app",
		ServicePrivkey: secret.New("aa"),
		ServicePubkey:  "service-pub-spend-row",
		ClientPubkey:   "client-pub",
		ClientSecret:   secret.New("bb"),
		Relays:         []string{"wss://relay.example"},
		Permissions:    append(store.DefaultPermissions(), store.PermissionPay),
		CreatedAt:      at,
	}, store.DefaultLimits)
	if err != nil {
		t.Fatalf("CreateNWCConnection: %v", err)
	}
	return conn
}

// outgoingTxn is the one payment_out row these tests write. Named rather than
// indexed: RecentTxns orders by created_at, and every row here shares a
// timestamp, so txns[0] was whichever row sqlite felt like returning.
func outgoingTxn(t *testing.T, s *store.Store) store.Txn {
	t.Helper()
	txns, err := s.RecentTxns(t.Context(), 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, txn := range txns {
		if txn.Kind == store.KindPaymentOut {
			return txn
		}
	}
	t.Fatal("no payment_out row in the history")
	return store.Txn{}
}
