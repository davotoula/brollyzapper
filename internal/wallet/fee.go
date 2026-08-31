package wallet

import (
	"context"
	"fmt"
	"strconv"

	"github.com/davotoula/brollyzapper/internal/store"
)

// ppmDivisor is parts-per-million.
const ppmDivisor = 1_000_000

// MaxFee is THE fee number (spec §5):
//
//	max_fee = max(max_fee_floor_msat, amount_msat × max_fee_ppm / 1_000_000)
//
// It is what Reserve debits, what the per-connection budget check consumes
// (§8), and what SendPaymentV2 receives as fee_limit_msat (§6). There is no
// separate estimate and there must be no second computation anywhere: a payment
// that reserves one amount and spends another is the bug this exists to
// prevent. An arch rule keeps the settings keys inside this package.
func (w *localSpender) MaxFee(ctx context.Context, amountMsat int64) (int64, error) {
	// The amount reaches here from a remote wallet app (§8's pay_invoice), so
	// its range is not this package's to assume: `amountMsat * ppm` wraps for an
	// amount near MaxInt64 and the multiply is what makes a nonsense figure look
	// like a small fee. Refused where the arithmetic happens, as well as at the
	// ledger and at the ladder — a bound that lives in only one of the three is
	// one edit from being routed around (d24.4 review).
	if amountMsat < 0 || amountMsat > store.MaxMsat {
		return 0, fmt.Errorf("wallet: %d msat is not an amount this wallet can price: %w",
			amountMsat, store.ErrAmountOutOfRange)
	}
	floorMsat, err := w.intSetting(ctx, SettingMaxFeeFloorMsat, DefaultMaxFeeFloorMsat)
	if err != nil {
		return 0, err
	}
	ppm, err := w.intSetting(ctx, SettingMaxFeePPM, DefaultMaxFeePPM)
	if err != nil {
		return 0, err
	}
	return max(floorMsat, amountMsat*ppm/ppmDivisor), nil
}

func (w *localSpender) intSetting(ctx context.Context, key string, fallback int64) (int64, error) {
	raw, ok, err := w.store.Setting(ctx, key)
	if err != nil {
		return 0, err
	}
	if !ok {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("wallet: %s is %q, which is not a whole number of msat: %w", key, raw, err)
	}
	if value < 0 {
		return 0, fmt.Errorf("wallet: %s is %d; a fee bound cannot be negative", key, value)
	}
	return value, nil
}
