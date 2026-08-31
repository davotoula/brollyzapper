package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/nwc"
	"github.com/davotoula/brollyzapper/internal/preflight"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/wallet"

	"github.com/davotoula/brollyzapper/internal/logging"
)

// The adapters between §8's service and what this process already has.
//
// They live here rather than in internal/nwc because that package declares what
// it needs as interfaces (§3) and this is the wiring — the same shape as the
// payment path's spender and payer.

// nwcInvoices is the receiving half, over the SAME invoice table zaps use (§8).
//
// An NWC-minted invoice is an ordinary invoice: it settles through the same
// stream, credits the same ledger, and appears in the same history. Minting it
// anywhere else would be a second path to the one table §5's invariants are
// about.
type nwcInvoices struct {
	node interface {
		AddInvoice(ctx context.Context, invoice *lnrpc.Invoice) (*lnrpc.AddInvoiceResponse, error)
	}
	db  *store.Store
	now func() time.Time
}

// invoiceExpiry is how long an NWC-minted invoice stays payable.
//
// The same hour the LNURL path uses. A wallet app's user is looking at a QR code
// when they ask, so this is a human's patience rather than a protocol limit.
const invoiceExpiry = time.Hour

func (n nwcInvoices) Mint(ctx context.Context, amountMsat int64, description string) (nwc.Invoice, error) {
	created := n.now()
	expires := created.Add(invoiceExpiry)
	added, err := n.node.AddInvoice(ctx, &lnrpc.Invoice{
		ValueMsat: amountMsat,
		Memo:      description,
		Expiry:    int64(invoiceExpiry / time.Second),
	})
	if err != nil {
		return nwc.Invoice{}, fmt.Errorf("minting an NWC invoice: %w", err)
	}
	hash := hex.EncodeToString(added.RHash)
	if err := n.db.CreateInvoice(ctx, store.Invoice{
		PaymentHash: hash,
		AmountMsat:  amountMsat,
		Bolt11:      added.PaymentRequest,
		// The memo lands in Comment, which is the column that holds a human's
		// words about an invoice. store.Invoice has no separate description:
		// the LNURL path's description is the LUD-06 METADATA and is hashed, and
		// putting an NWC memo there would put it inside a description_hash the
		// payer never agreed to.
		Comment:   description,
		CreatedAt: created,
		ExpiresAt: expires,
	}); err != nil {
		// The node has minted it, so the bolt11 exists and could be paid. A row
		// we failed to write means a settlement we would later skip as "not
		// ours" — so this is reported rather than swallowed, and the client
		// retries against an invoice nobody will honour rather than being told
		// one is live.
		return nwc.Invoice{}, fmt.Errorf("recording an NWC invoice: %w", err)
	}
	return nwc.Invoice{
		Bolt11: added.PaymentRequest, PaymentHash: hash, AmountMsat: amountMsat,
		Description: description, CreatedAt: created, ExpiresAt: expires,
	}, nil
}

func (n nwcInvoices) Lookup(ctx context.Context, paymentHash string) (nwc.Invoice, bool, error) {
	inv, found, err := n.db.Invoice(ctx, paymentHash)
	if err != nil || !found {
		return nwc.Invoice{}, found, err
	}
	return nwc.Invoice{
		Bolt11: inv.Bolt11, PaymentHash: inv.PaymentHash, AmountMsat: inv.AmountMsat,
		Description: inv.Comment, CreatedAt: inv.CreatedAt, ExpiresAt: inv.ExpiresAt,
		Settled: inv.State == store.InvoiceSettled,
	}, true, nil
}

func (n nwcInvoices) List(ctx context.Context, filter store.TxnFilter) ([]store.Txn, error) {
	return n.db.Txns(ctx, filter)
}

// nwcNode is the read-only node facts get_info reports.
type nwcNode struct {
	node interface {
		GetInfo(ctx context.Context) (*lnrpc.GetInfoResponse, error)
	}
}

func (n nwcNode) Info(ctx context.Context) (nwc.NodeInfo, error) {
	info, err := n.node.GetInfo(ctx)
	if err != nil {
		return nwc.NodeInfo{}, err
	}
	network := ""
	if len(info.Chains) > 0 {
		network = info.Chains[0].Network
	}
	return nwc.NodeInfo{
		Alias:       info.Alias,
		Pubkey:      info.IdentityPubkey,
		Network:     network,
		BlockHeight: info.BlockHeight,
	}, nil
}

// nwcPurse is everything §8's ladder needs from the wallet, declared here
// because this is the consumer (§3).
//
// The wallet's concrete type is deliberately unexported — reaching for one
// capability must not hand a caller spend authority — so this names the four
// things the ladder actually uses and nothing else. Note what is NOT here: no
// Allocate, no Adjust, no CreditInvoice. A payment path that could allocate
// would be a payment path that could raise its own ceiling.
type nwcPurse interface {
	spender
	Balance(ctx context.Context) (int64, error)
	MaxFee(ctx context.Context, amountMsat int64) (int64, error)
	Shortfall(ctx context.Context) (wallet.Deficit, bool, error)
	UnresolvedPayments(ctx context.Context) (int, error)
}

// nwcSpend is the outbound half of §8's ladder: the two facts it refuses on, the
// fee reserve it takes, and the payment itself.
//
// It composes what already exists rather than widening anything (d24.4 ruling
// 1). The freeze it reports is the SAME state wallet.Reserve refuses on, read
// early so the client gets §8's RESTRICTED instead of a reservation error's
// text — and if the two ever disagree, Reserve is the one that decides, because
// it is the one the payment has to pass through.
type nwcSpend struct {
	purse       nwcPurse
	node        spendNode
	credentials lnd.CredentialSource
	// checks is §11's Tier-2 report — the SAME construction the Security page and
	// the degraded banner render, differing in one argument: this one reads the
	// guard's status straight from its socket rather than through the UI's
	// ten-second cache (d24.6).
	//
	// That cache exists for page renders, and the ladder inherited it along with
	// a ten-second window in which a macaroon the node had ALREADY REVOKED still
	// paid — which the regtest stack reproduced. Invalidating it per payment was
	// the first fix and was worse: a consumer managing a cache it does not own,
	// non-atomically, so a concurrent page render could refill it between the
	// invalidate and the read. Two closures over one set of inputs is the honest
	// shape. One statement of the policy; two freshness policies, each chosen by
	// the caller that lives with it.
	checks func(ctx context.Context) preflight.Report
	log    *slog.Logger
}

// spendNode is what §8's ladder needs from the node it pays through: payInvoice's
// two calls, plus reading the invoice before any of it happens.
//
// One object holds all three, which is the property worth naming — "the payment
// path reads the invoice it is about to pay" is true of the client that pays,
// not of a second one wired to the same address.
type spendNode interface {
	payer
	Decode(ctx context.Context, bolt11 string) (lnd.Bolt11, error)
}

// CredentialReady is §8 step 2's second half: a spend macaroon that exists.
//
// A FILE CHECK, and it claims nothing more. Whether the node would accept it is
// established by using it, at step 8 — a credential the node has revoked still
// sits on disk, and a check that pretended otherwise would be a check that lies.
func (n nwcSpend) CredentialReady() bool { return n.credentials.Ready() }

// SendingBlocked asks §11's Tier 2 whether sending is available at all.
//
// FRESH per payment, and that is the ruling rather than an oversight: the
// report's Inputs are functions so it cannot cache into staleness, the four
// spend-macaroon rows are local file reads, and "the guard is not answering"
// blocks sending and can only be known by asking. The regtest arc measures what
// that costs.
//
// A missing report blocks. Not being able to compute whether sending is safe is
// not permission to send — the same direction §2 takes everywhere else.
func (n nwcSpend) SendingBlocked(ctx context.Context) []string {
	if n.checks == nil {
		return []string{"preflight.unavailable"}
	}
	var failing []string
	for _, check := range n.checks(ctx).BlockedBy(preflight.BlocksSending) {
		failing = append(failing, check.ID)
	}
	return failing
}

// Held reports whether spending is frozen, and why (§8 step 3, ruling 2).
//
// BOTH freezes, because both mean the same thing to a client: spending is held
// for reasons that are not about its quota. The message is what distinguishes
// them, since they need different things from the operator — a reconciliation
// shortfall wants looking at, an unresolved payment clears itself.
//
// NO QUANTITIES, and that is `0vk.14` (§8 ruling 3: no internals). The shortfall
// arm used to format `deficit.ShortfallMsat` verbatim, so a paired client that
// also calls get_balance could subtract one from the other and compute the
// NODE'S OUTBOUND CHANNEL BALANCE to the millisatoshi — a fact about the
// operator's node that nothing in NIP-47 entitles a client to, handed over in a
// refusal.
//
// FIXED HERE, at the composition site, rather than at the publish boundary. Wave
// 28 made this string durable in `nwc_connections.last_refusal_message`, so
// redacting on the way out to the client would have left the UNREDACTED number
// on disk while the client saw the redacted one — the fix inverted. One
// composition, both consumers.
//
// Not rounded, either. Rounding leaks less per refusal and still leaks, and it
// invites the question of how much rounding is enough. The quantity is gone.
// `internal/nwc/pay.go` answers a Tier-2 refusal exactly this way already, and
// it is the model: the operator's diagnosis is the Security page's, and it has
// the numbers.
func (n nwcSpend) Held(ctx context.Context) (string, bool, error) {
	if _, frozen, err := n.purse.Shortfall(ctx); err != nil {
		return "", false, err
	} else if frozen {
		return "sending is held on this node right now; its owner can see why on the " +
			"Security page", true, nil
	}
	unresolved, err := n.purse.UnresolvedPayments(ctx)
	if err != nil {
		return "", false, err
	}
	if unresolved > 0 {
		// The COUNT goes too. It is smaller than the shortfall but it is the
		// same kind of fact — how many payments this node has in flight — and
		// the client can do nothing with it either way.
		return "sending is held while payments from a previous run are resolved against the " +
				"node; this clears itself, and its owner can see the detail on the Security page",
			true, nil
	}
	return "", false, nil
}

// Decode reads a bolt11 through the node that will pay it, in the shape §8's
// ladder asks for.
//
// The same spend client Pay uses, so "the payment path reads the invoice it is
// about to pay" is true of one object rather than of two that happen to be wired
// to the same node.
func (n nwcSpend) Decode(ctx context.Context, bolt11 string) (nwc.Bolt11, error) {
	decoded, err := n.node.Decode(ctx, bolt11)
	if err != nil {
		return nwc.Bolt11{}, err
	}
	return nwc.Bolt11{
		PaymentHash: decoded.PaymentHash,
		AmountMsat:  decoded.AmountMsat,
		Description: decoded.Description,
		// The invoice's commitment, and this line is the one that was missing
		// (y09). Without it every zap paid through NWC was dropped with "the
		// invoice commits to no description_hash" — the feature dead in the
		// field while internal/lnd tested Decode, internal/nwc tested against a
		// fake Decode, and nothing tested the wire between them. Found by
		// regtest on its first run that could reach section 14.
		DescriptionHash: decoded.DescriptionHash,
		ExpiresAt:       decoded.ExpiresAt,
	}, nil
}

// MaxFee is §5's single fee reserve, from the one place that computes it.
func (n nwcSpend) MaxFee(ctx context.Context, amountMsat int64) (int64, error) {
	return n.purse.MaxFee(ctx, amountMsat)
}

// Pay is §8 step 8, and it is payInvoice — the orchestrator d24.2 built, which
// has been waiting two waves for its production caller.
//
// The ErrBooking arm is ruling 4: a payment that SETTLED but could not be
// recorded is answered as a success, because the payment result is the truth
// about the money and the booking error is the truth about the ledger.
// Reporting a failure would make the client retry an invoice it has paid.
func (n nwcSpend) Pay(ctx context.Context, req nwc.PayRequest) (nwc.PayResult, error) {
	result, err := payInvoice(ctx, payment{
		bolt11:          req.Bolt11,
		amountMsat:      req.AmountMsat,
		maxFeeMsat:      req.MaxFeeMsat,
		paymentHash:     req.PaymentHash,
		ref:             req.Ref,
		description:     req.Description,
		connectionID:    req.ConnectionID,
		metadata:        req.Metadata,
		descriptionHash: req.DescriptionHash,
	}, n.purse, n.node, n.log)

	switch {
	case errors.Is(err, ErrNotDispatched):
		// Translated into the ladder's vocabulary, so internal/nwc can answer in
		// §8's codes without importing the wallet or the store to recognise
		// their errors (§3).
		return nwc.PayResult{}, notDispatched(err)
	case errors.Is(err, ErrBooking) && result.Succeeded():
		// Logged HERE and not by the ladder, because this is where the booking
		// error itself is in scope — the ladder only learns that it happened.
		n.log.Warn("an NWC payment settled but could not be recorded; the reservation stays "+
			"pending and reconciliation will close it (§8, d24.4 ruling 4)",
			"payment_hash", req.PaymentHash, "error", err.Error())
		return nwc.PayResult{
			Settled: true, Preimage: result.Preimage, FeeMsat: result.FeeMsat,
			Unbooked: true,
		}, nil
	case err != nil:
		return nwc.PayResult{}, err
	case result.Failed():
		return nwc.PayResult{Failed: true, FailureReason: result.FailureReason.String()}, nil
	case result.Succeeded():
		// The preimage travels as secret.String the whole way; internal/nwc
		// reveals it at the one line that builds the NIP-47 result.
		return nwc.PayResult{
			Settled: true, Preimage: result.Preimage, FeeMsat: result.FeeMsat,
		}, nil
	default:
		return nwc.PayResult{}, fmt.Errorf("the payment ended in a non-terminal state %v",
			result.Status)
	}
}

// notDispatched maps a refused reservation to the sentinels internal/nwc knows.
//
// The mapping lives HERE because this is where both vocabularies are in scope:
// the ladder must not import internal/store to recognise a constraint, and the
// store must not know what a NIP-47 error code is.
func notDispatched(err error) error {
	switch {
	case errors.Is(err, store.ErrInsufficientBalance):
		return fmt.Errorf("%w: %w: %w", nwc.ErrNotDispatched, nwc.ErrInsufficientBalance, err)
	case errors.Is(err, store.ErrPaymentInFlight):
		return fmt.Errorf("%w: %w: %w", nwc.ErrNotDispatched, nwc.ErrAlreadyPaying, err)
	default:
		return fmt.Errorf("%w: %w", nwc.ErrNotDispatched, err)
	}
}

// runNWC serves §8's wallet service until ctx ends.
//
// A background loop, started with the others — which are ordered after the
// startup resolver pass, though that ordering is no longer what enforces
// anything: every pay_invoice passes wallet.Reserve's freezes whatever starts
// when (u0u). Since d24.4 this service CAN pay, which is what made that
// distinction matter rather than being a note about the future.
//
// A failure to start is a WARN and not an exit. §11: an unreachable relay is a
// degraded state, and a node that refuses to boot because a wallet app's relay
// is down would be an outage caused by the pairing.
func runNWC(ctx context.Context, service *nwc.Service, demand <-chan struct{}, log *slog.Logger) {
	prune := time.NewTicker(nwc.PruneInterval)
	defer prune.Stop()
	if err := service.Run(ctx, prune.C, demand); err != nil && ctx.Err() == nil {
		log.Warn("the NWC wallet service stopped", "error", err.Error())
	}
}

// newNWCService assembles §8's service.
//
// Built by the caller rather than inside runNWC since d24.21: the Connections
// page asks this same object which pairings can currently reach their relay, so
// it has to exist before the server does. It performs no I/O, so building it
// early costs nothing and starts nothing.
func newNWCService(db *store.Store, relays nwc.Relays, purse nwcPurse,
	node *lnd.Client, spendNode *lnd.Client, spendCredentials lnd.CredentialSource,
	checks func(ctx context.Context) preflight.Report,
	auditor *logging.Auditor, demand chan<- struct{}, log *slog.Logger) *nwc.Service {
	return nwc.New(db, relays, purse,
		nwcInvoices{node: node, db: db, now: time.Now},
		nwcNode{node: node},
		nwcSpend{purse: purse, node: spendNode, credentials: spendCredentials,
			checks: checks, log: log},
		// The auditor, so a capability refusal reaches §12's trail rather than
		// only the log (d24.14). Its contract is the line and the row together,
		// which is why the service holds this and not an AuditSink.
		// The SAME channel runNWC hands to Run and the Connections page nudges:
		// the service pauses a pairing whose requests keep crashing (`xmc` Fix
		// C) and needs the reload to happen then, not at the next thing the
		// operator does.
		nwc.Options{Log: log, Audit: auditor, Demand: demand})
}
