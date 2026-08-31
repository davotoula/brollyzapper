package recon

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/wallet"
)

// Defaults for the periodic check (spec §5).
const (
	DefaultInterval = 5 * time.Minute

	// DefaultToleranceMsat is how far the two numbers may disagree before this
	// is called a shortfall — 10,000 sats.
	//
	// It is not an attempt to model the node's real spendable balance. §5 is
	// explicit that the check is coarse: local_balance still counts channel
	// reserves that can never be sent, which makes the comparison conservative
	// in the safe direction already. The tolerance is for transient movement —
	// a payment in flight, a settlement not yet credited — because an
	// over-sensitive check freezes a working node, and an operator who sees one
	// spurious freeze will distrust the real one.
	//
	// Deliberately a constant rather than a setting, unlike max_fee_ppm and
	// max_fee_floor_msat which §9 puts on the Settings page. §9 does not list
	// this one, and a settings key with no way to set it is the mirror of the
	// unread setting Wave 2's review objected to. Exposing it is a §9 decision,
	// not an implementation detail to invent here.
	DefaultToleranceMsat int64 = 10_000_000
)

// Node is the slice of LND this needs. ChannelBalance is one of the five
// methods the receive-only macaroon grants (§6).
type Node interface {
	ChannelBalance(ctx context.Context) (*lnrpc.ChannelBalanceResponse, error)
}

// Wallet is the slice of the wallet this needs.
//
// Note what is absent: Reserve, Allocate, Adjust — anything that writes a
// balance entry. §5 says the balance is never silently rewritten, and a
// reconciler that cannot write one cannot be talked into it.
type Wallet interface {
	Balance(ctx context.Context) (int64, error)
	RecordShortfall(ctx context.Context, deficit wallet.Deficit) error
	ClearShortfall(ctx context.Context) error
	Shortfall(ctx context.Context) (wallet.Deficit, bool, error)
}

// Auditor writes a security event to the log and the durable trail (§12).
type Auditor interface {
	Record(ctx context.Context, level slog.Level, msg string, event logging.Event, attrs ...slog.Attr) error
}

// Options configure a Reconciler. The zero value takes §5's defaults.
type Options struct {
	ToleranceMsat int64
	Now           func() time.Time
	Log           *slog.Logger

	// ResolvePayments finishes payments a previous run left in flight, if the
	// wiring supplied one (u0u). Nil simply never runs.
	//
	// A callback rather than a dependency because internal/recon must not import
	// the payment orchestration — that lives in cmd/brollyzapper, which is the
	// consumer and the wiring. Same shape as Run's observe.
	//
	// It belongs on THIS loop rather than a loop of its own: reconciliation is
	// already "compare our ledger against the node and fix what we can", and an
	// unresolved payment is the ledger disagreeing with the node about a
	// specific row. It also already has the demand channel, which is what turns
	// "the node came back" into "resolved now" instead of "resolved within five
	// minutes".
	ResolvePayments func(context.Context) error
}

// Reconciler compares what the wallet believes it may spend against what the
// node can actually send.
//
// This is a sanity check, not an accounting identity: the node's balance is
// shared with every other app on the box and moves for reasons BrollyZapper
// cannot see. A shortfall means "stop spending and tell the operator", never
// "recompute the ceiling" (§5).
type Reconciler struct {
	node      Node
	wallet    Wallet
	auditor   Auditor
	tolerance int64
	now       func() time.Time
	log       *slog.Logger

	// The previous observation, kept in memory to tell "the node lost funds"
	// from "the ceiling was raised" — they send the operator to different
	// places. After a restart the first check has no history and says so.
	mu       sync.Mutex
	previous *observation

	// resolvePayments is the wiring-supplied resolver; see Options.
	resolvePayments func(context.Context) error
}

type observation struct {
	walletMsat int64
	nodeMsat   int64
}

// New builds a reconciler.
func New(node Node, purse Wallet, auditor Auditor, opts Options) *Reconciler {
	if opts.ToleranceMsat <= 0 {
		opts.ToleranceMsat = DefaultToleranceMsat
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Log == nil {
		opts.Log = logging.Default()
	}
	return &Reconciler{
		node: node, wallet: purse, auditor: auditor,
		tolerance: opts.ToleranceMsat, now: opts.Now, log: opts.Log,
		resolvePayments: opts.ResolvePayments,
	}
}

// Check runs one comparison and records or clears the shortfall.
func (r *Reconciler) Check(ctx context.Context) error {
	balance, err := r.node.ChannelBalance(ctx)
	if err != nil {
		// An unreachable node is not a shortfall. Freezing spending because LND
		// is restarting would be an outage caused by the check itself.
		return fmt.Errorf("recon: reading the node's balance: %w", err)
	}
	nodeMsat := int64(balance.GetLocalBalance().GetMsat())

	walletMsat, err := r.wallet.Balance(ctx)
	if err != nil {
		return fmt.Errorf("recon: reading the wallet balance: %w", err)
	}

	shortfall := walletMsat - nodeMsat
	short := shortfall > r.tolerance

	var cause string
	if short {
		// Read before the observation is replaced: the cause is derived from
		// which side moved since last time.
		cause = r.cause(walletMsat, nodeMsat)
	}
	r.remember(walletMsat, nodeMsat)

	_, frozen, err := r.wallet.Shortfall(ctx)
	if err != nil {
		return err
	}
	switch {
	case short && !frozen:
		return r.froze(ctx, wallet.Deficit{
			At:            r.now(),
			ShortfallMsat: shortfall,
			WalletMsat:    walletMsat,
			NodeMsat:      nodeMsat,
			Cause:         cause,
		})
	case !short && frozen:
		return r.recovered(ctx, walletMsat, nodeMsat)
	default:
		// Healthy and clear, or already frozen for this reason — re-recording
		// every five minutes would flood the trail with the same fact.
		return nil
	}
}

func (r *Reconciler) froze(ctx context.Context, deficit wallet.Deficit) error {
	if err := r.wallet.RecordShortfall(ctx, deficit); err != nil {
		return err
	}
	return r.auditor.Record(ctx, slog.LevelWarn,
		"reconciliation shortfall: spending frozen", logging.EventWalletShortfall,
		slog.Int64("shortfall_msat", deficit.ShortfallMsat),
		slog.Int64("wallet_msat", deficit.WalletMsat),
		slog.Int64("node_msat", deficit.NodeMsat),
		slog.String("cause", deficit.Cause))
}

func (r *Reconciler) recovered(ctx context.Context, walletMsat, nodeMsat int64) error {
	if err := r.wallet.ClearShortfall(ctx); err != nil {
		return err
	}
	return r.auditor.Record(ctx, slog.LevelInfo,
		"reconciliation shortfall cleared: spending resumed", logging.EventWalletShortfall,
		slog.Int64("wallet_msat", walletMsat), slog.Int64("node_msat", nodeMsat))
}

// cause names the likeliest explanation, because a number with no candidate
// explanation sends the operator to the wrong place (§9).
func (r *Reconciler) cause(walletMsat, nodeMsat int64) string {
	const generic = "the wallet ceiling is above what the node can send. Likely causes: a force " +
		"close locking funds, channel reserve becoming unspendable, over-allocation, or another " +
		"app spending on the same node"

	r.mu.Lock()
	previous := r.previous
	r.mu.Unlock()
	if previous == nil {
		return generic
	}
	nodeFell := previous.nodeMsat - nodeMsat
	ceilingRose := walletMsat - previous.walletMsat
	switch {
	case nodeFell > ceilingRose && nodeFell > 0:
		return fmt.Sprintf("the node's spendable balance fell by %d msat since the last check. "+
			"Likely a force close locking funds, or another app spending on the same node", nodeFell)
	case ceilingRose > 0:
		return fmt.Sprintf("the wallet ceiling was allocated %d msat higher since the last check, "+
			"past what the node can send. Deallocate, or allocate less", ceilingRose)
	default:
		return generic
	}
}

func (r *Reconciler) remember(walletMsat, nodeMsat int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.previous = &observation{walletMsat: walletMsat, nodeMsat: nodeMsat}
}

// Shortfall is the producer for §11's Tier-2 reconciliation row, in exactly the
// shape preflight.Inputs.Shortfall wants.
//
// The cause travels with the number because a number on its own sends the
// operator to the wrong place (§9).
func (r *Reconciler) Shortfall(ctx context.Context) (shortfallMsat int64, cause string, present bool) {
	deficit, frozen, err := r.wallet.Shortfall(ctx)
	if err != nil || !frozen {
		return 0, "", false
	}
	return deficit.ShortfallMsat, deficit.Cause, true
}

// Run checks on every tick and on every demand, until ctx ends.
//
// The tick channel is a parameter so the schedule is the caller's, and so a
// test costs microseconds. The demand channel is how a ceiling change gets
// checked at once rather than up to five minutes later: on the box a ceiling
// allocated past the node's balance showed a confident green tick for ~3.6
// minutes, and §11 argues a checklist of green ticks that bounds nothing is
// worse than no checklist (d46.21). The same shape as §9's on-demand probe.
//
// A nil demand channel simply never fires, which is the periodic-only case.
func (r *Reconciler) Run(ctx context.Context, tick <-chan time.Time, demand <-chan struct{},
	observe func(error)) {
	check := func() {
		// RESOLUTION FIRST, then the comparison. Settling or reversing a payment
		// moves the balance, so comparing before resolving would measure a
		// ledger we already know is mid-flight and could record a shortfall that
		// resolution was about to erase.
		//
		// Its failure does not skip the check: an unreachable node fails both,
		// and a resolver that cannot finish is exactly when the shortfall
		// comparison is most worth having.
		if r.resolvePayments != nil {
			if err := r.resolvePayments(ctx); err != nil {
				r.log.Warn("could not resolve payments from a previous run; spending stays held "+
					"until they resolve", "error", err.Error())
			}
		}
		err := r.Check(ctx)
		if err != nil {
			r.log.Warn("reconciliation check failed", "error", err.Error())
		}
		if observe != nil {
			observe(err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-tick:
			if !ok {
				return
			}
			check()
		case _, ok := <-demand:
			// Symmetric with tick: a closed channel yields forever, and an
			// unguarded case would spin Check against LND and the wallet.
			if !ok {
				return
			}
			check()
		}
	}
}
