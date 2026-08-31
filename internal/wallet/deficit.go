package wallet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SettingDeficitState is where §4 keeps the reconciliation result.
const SettingDeficitState = "deficit_state"

// ErrPaymentsUnresolved means a payment from a previous run has not been
// resolved against the node yet, so the ceiling is holding reservations whose
// fate is unknown (§6, u0u).
//
// A SIBLING of ErrSpendingFrozen, not a wrap of it, and the reason is what an
// operator does about it. A reconciliation shortfall says the wallet authorises
// more than the node can send and may need an adjustment; this says only that
// we have not finished asking, and it clears itself the moment the node answers
// — no operator action at all. Wrapping would make errors.Is(err,
// ErrSpendingFrozen) true for a state that has nothing to do with
// reconciliation, and §11's Tier-2 row and the Node page would report a
// shortfall where there is none.
//
// A caller that wants one question — "may I spend?" — checks both. Two names is
// the honest shape when there are two causes with two remedies.
var ErrPaymentsUnresolved = errors.New(
	"wallet: payments from a previous run are still unresolved, so spending is held")

// ErrSpendingFrozen means reconciliation found the wallet authorising more than
// the node can actually send (spec §5).
//
// It freezes OUTBOUND payments only. Receiving stays enabled: a wallet that
// stops accepting zaps because it is unsure how much it can spend has turned a
// recoverable accounting problem into lost income. P3 maps this to NIP-47's
// RESTRICTED for pay_invoice.
var ErrSpendingFrozen = errors.New("wallet: spending is frozen by a reconciliation shortfall")

// Deficit is the recorded shortfall. It carries the amount AND a candidate
// cause, because a number with no explanation sends the operator to the wrong
// place (§5, §9).
type Deficit struct {
	At            time.Time `json:"at"`
	ShortfallMsat int64     `json:"shortfall_msat"`
	WalletMsat    int64     `json:"wallet_msat"`
	NodeMsat      int64     `json:"node_msat"`
	Cause         string    `json:"cause"`
}

// RecordShortfall freezes spending and records why.
//
// It writes no balance entry. §5 is explicit that the balance is never silently
// rewritten: a correction is an explicit adjustment txn with a reason, made by
// the operator and visible in history.
func (w *localSpender) RecordShortfall(ctx context.Context, deficit Deficit) error {
	encoded, err := json.Marshal(deficit)
	if err != nil {
		return fmt.Errorf("wallet: encoding the deficit: %w", err)
	}
	return w.store.SetSetting(ctx, SettingDeficitState, string(encoded))
}

// ClearShortfall lifts the freeze. §5: recovery needs no operator action and no
// restart — a freeze a human has to release is an outage with extra steps.
func (w *localSpender) ClearShortfall(ctx context.Context) error {
	return w.store.SetSetting(ctx, SettingDeficitState, "")
}

// Shortfall reports the recorded deficit, if spending is frozen.
func (w *localSpender) Shortfall(ctx context.Context) (Deficit, bool, error) {
	raw, ok, err := w.store.Setting(ctx, SettingDeficitState)
	if err != nil {
		return Deficit{}, false, err
	}
	if !ok || raw == "" {
		return Deficit{}, false, nil
	}
	var deficit Deficit
	if err := json.Unmarshal([]byte(raw), &deficit); err != nil {
		// Fail closed. An unreadable deficit row is not evidence that the
		// shortfall went away, and unfreezing on a parse error would make
		// corrupting one setting the way to re-enable spending.
		return Deficit{}, true, fmt.Errorf("wallet: %s is unreadable, so spending stays frozen: %w",
			SettingDeficitState, err)
	}
	return deficit, true, nil
}
