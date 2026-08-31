package lnd_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/secret"
)

// d24.4 ruling 5: the preimage arrives now, because pay_invoice's response has
// to carry it — NIP-47 returns it and the client is entitled to it, being the
// proof it paid.
//
// It was deliberately absent until something needed it: §12 lists preimages with
// the macaroons and the private keys, and a secret.String nobody reads is
// write-only state.
func TestASettledPaymentCarriesItsPreimage(t *testing.T) {
	node := lndtest.Start(t)
	client := spendClient(t, node)
	node.SetPaymentUpdates("lnbcrt1preimage", lndtest.SucceededWithPreimage(1_234, "aabbcc"))

	result, err := client.SendPayment(t.Context(), "lnbcrt1preimage", 5_000)
	if err != nil {
		t.Fatalf("SendPayment: %v", err)
	}
	if !result.Succeeded() {
		t.Fatalf("the payment did not succeed: %v", result.Status)
	}
	if got := result.Preimage.Reveal(); got != "aabbcc" {
		t.Errorf("preimage = %q, want the node's; without it pay_invoice cannot answer", got)
	}
}

// §11 and §12: a preimage never reaches a log, and the type is what makes that
// structural rather than a rule people remember.
func TestAPaymentResultRedactsItsPreimage(t *testing.T) {
	var buf bytes.Buffer
	log := logging.New(&buf, logging.NewLevelVar(slog.LevelDebug))
	result := lnd.PaymentResult{FeeMsat: 7, Preimage: secret.New("s3cr3tpreimage")}

	log.Info("payment", "result", result)
	log.Info("payment", slog.Any("result", result))

	if got := buf.String(); strings.Contains(got, "s3cr3tpreimage") {
		t.Errorf("the preimage reached the log: %s", got)
	}
	if got := buf.String(); !strings.Contains(got, "fee_msat") {
		t.Errorf("the redacted form says nothing useful about the payment: %s", buf.String())
	}
}
