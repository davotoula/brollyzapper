package store_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
)

// A Txn put through slog reveals no preimage (§12, d24.16).
//
// internal/arch requires a secret-bearing struct to IMPLEMENT LogValue; it
// cannot check what that LogValue says. This is the other half, and it is not
// theoretical: the obvious way to make "did this row keep its proof" answerable
// on the Wallet page is to put the preimage on the view, and the obvious way to
// debug that is to log the row.
//
//redaction:covers store.Txn
func TestATxnNeverLogsItsPreimage(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	txn := store.Txn{
		Kind: store.KindPaymentOut, State: store.TxnSettled,
		AmountMsat: 21_000, FeeMsat: 2_055,
		PaymentHash: "6e484e0ab97be167",
		Preimage:    secret.New("28aa50a3deadbeef"),
	}

	log.Info("a payment", "txn", txn)

	if strings.Contains(buf.String(), "28aa50a3deadbeef") {
		t.Errorf("the preimage reached a log line; §12 lists preimages with the macaroons and "+
			"the proof belongs to the client that paid, not to the operator's log:\n%s", buf.String())
	}
	// The FACT is reportable, and it is the operator's real question — d24.16
	// exists because the answer used to be no.
	if !strings.Contains(buf.String(), "has_preimage") {
		t.Errorf("the log says nothing about whether the row kept its proof:\n%s", buf.String())
	}
}
