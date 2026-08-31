// Command brollyzapper is the BrollyZapper server: HTTP listener, relays, wallet and store.
//
// See internal/arch for the container split (§3 of the design).
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/cliboot"
	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/preflight"
	"github.com/davotoula/brollyzapper/internal/recon"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/wallet"
	"github.com/davotoula/brollyzapper/internal/web"
	"github.com/davotoula/brollyzapper/internal/zap"
)

// newHTTPServer builds the listener with every phase of a request bounded.
//
// ReadHeaderTimeout alone — which is all this had — bounds the request line and
// the headers, and nothing after them. A caller that sent a complete header
// block and then dribbled a body held a goroutine, a connection and a file
// descriptor for as long as it liked; with the store on a single connection,
// enough of those is the whole app (review L6). The values are generous by
// design: the slowest legitimate request here is an admin form over a domestic
// uplink, not a long poll or an upload.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler: handler,
		// Headers first, then the body: ReadTimeout covers both, so it has to
		// exceed ReadHeaderTimeout for the header bound to mean anything.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		// Keep-alives are the cheap way to hold a descriptor without sending
		// anything at all.
		IdleTimeout: 120 * time.Second,
		// net/http defaults to 1MB of headers. Nothing here needs a tenth of
		// that, and cookies are the only header this app reads at length.
		MaxHeaderBytes: 64 << 10,
	}
}

// zapRetryInterval is how often the queue of unpublished receipts is checked.
// The per-receipt backoff lives in internal/zap; this only decides how finely
// that schedule is observed.
const zapRetryInterval = 30 * time.Second

// Exit codes.
const (
	exitConfig  = 1
	exitRuntime = 3
	// exitPackagingDefect is §11's Tier 1: the server can reach
	// admin.macaroon, so §3's credential inversion has been undone and every
	// other control is decorative. Never a user condition.
	exitPackagingDefect = 4
)

// lndMountPath is where an Umbrel package would mount LND's files. The server
// must have nothing there; Tier 1 looks anyway, because that is the point.
const lndMountPath = "/lnd"

// shutdownGrace is how long in-flight requests get once the process is asked to
// stop.
const shutdownGrace = 10 * time.Second

// crediter is the slice of the wallet the settlement path needs.
//
// The wallet's implementation is unexported (§3), so consumers declare what
// they use — and what this one uses is the ability to credit an inbound
// payment, not the ability to spend.
type crediter interface {
	CreditInvoice(ctx context.Context, paymentHash, preimage string, amountPaidMsat int64,
		settledAt time.Time) (bool, error)
}

// version is stamped at link time with -X main.version=<tag>; it stays "dev"
// for a plain go build.
var version = "dev"

func main() {
	// SIGTERM is what docker stop sends.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], config.OSLookup, os.Stdout, os.Stderr))
}

// run is the whole of main's behaviour, extracted so it is testable without a
// process. It returns the process exit code.
func run(ctx context.Context, args []string, env config.Lookup, stdout, stderr io.Writer) int {
	boot, code, done := cliboot.Start("brollyzapper", version, args, stdout, stderr)
	if done {
		return code
	}
	log, level, build := boot.Log, boot.Level, boot.Build

	cfg, err := config.LoadServer(env)
	if err != nil {
		boot.ReportConfigError(err)
		return exitConfig
	}
	// LOG_LEVEL applies from here on, and the LevelVar means the admin UI can
	// change it later without a restart (spec §12).
	level.Set(cfg.LogLevel)

	// P1 scaffold: the wiring lands with the packages it wires together. The
	// summary is safe to log because every secret-bearing field renders itself
	// redacted (spec §12).
	log.Info("starting", "version", build, "config", cfg)
	switch err := serve(ctx, cfg, env, log, level, build); {
	case errors.Is(err, errTierOne):
		return exitPackagingDefect
	case err != nil && !errors.Is(err, context.Canceled):
		log.Error("server stopped", "error", err.Error())
		return exitRuntime
	}
	log.Info("server stopped")
	return 0
}

// serve wires the packages together and runs until ctx ends.
//
// Every dependency here is allowed to be absent: no LND, no credentials, no
// guard socket. §11 forbids crash loops, and Umbrel's rules require an app to
// surface setup, retrying and degraded states instead — so the listener comes
// up first and the admin UI explains what is missing.
// errTierOne is the Tier-1 refusal, mapped to an exit code by run.
var errTierOne = errors.New("preflight: the server can reach admin.macaroon")

func serve(ctx context.Context, cfg *config.Server, env config.Lookup, log *slog.Logger, level *slog.LevelVar, build string) error {
	db, err := store.Open(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("opening the database: %w", err)
	}
	defer db.Close()

	// §9: the probe token is regenerated at each start, so a stale answer from
	// a previous boot cannot pass the self-probe.
	probeToken := secret.RandomToken(16)
	if err := db.SetSetting(ctx, api.SettingProbeToken, probeToken); err != nil {
		log.Warn("could not persist the probe token", "error", err.Error())
	}
	if stored, ok, _ := db.Setting(ctx, api.SettingLogLevel); ok && stored != "" {
		var parsed slog.Level
		if parsed.UnmarshalText([]byte(stored)) == nil {
			level.Set(parsed)
		}
	}

	// §12: every security event is written to the log AND to the durable trail,
	// because log rotation must not be able to erase it.
	auditor := logging.NewAuditor(log, db)
	// The guard raises security events too — a bake, a rotation — and it has no
	// mount for this database and must not have one (§16). So they ride back on
	// every socket answer and are written HERE (§12, d46.18).
	relayGuardEvents := func(ctx context.Context, events []logging.RelayedEvent) {
		for _, ev := range events {
			switch stored, err := auditor.Relay(ctx, ev); {
			case err != nil:
				log.Error("could not record a guard security event",
					"event", string(ev.Event), "error", err.Error())
			case stored:
				// Operational telemetry, not the §12 line: no audit= attribute,
				// stamped at delivery, and fired once per event because the
				// relay itself is deliberately silent.
				log.Info("recorded a guard security event", "event", string(ev.Event))
			}
		}
	}
	// §7's LNURL response announces this key and §7's receipts are signed with
	// it, so a fresh install mints one by starting — §19 forbids one-off
	// operator commands for normal setup. It also writes server_nostr_pubkey,
	// which the domain self-prober has been reading since P1 and which nothing
	// wrote until now (o34.1).
	// §11: every dependency here is allowed to be absent, and this one is no
	// exception. A stored key that cannot be parsed — hand-edited, truncated,
	// written by a full disk — must not exit: restart: on-failure has no retry
	// cap, and the only repair is importing a good key at POST /settings/nostr,
	// which is unreachable if the listener never binds.
	identity, err := nostr.LoadOrCreate(ctx, db)
	if err != nil {
		log.Error("no usable nostr identity; zap receiving is degraded until one is imported "+
			"on the Settings page", "error", err.Error())
	} else {
		log.Info("nostr identity ready", "identity", identity)
	}

	// One pool for the process, like the one invoice stream. The relay list is
	// read fresh on every publish, so an edited list needs no restart.
	relays := nostr.NewPool(ctx, func() []string {
		configured, _, _ := db.Setting(ctx, nostr.SettingRelays)
		return nostr.ParseRelays(configured)
		// The pool's own line goes through the application logger like every
		// other: slog.Default is plain text on stderr, which §12 does not allow
		// and LOG_LEVEL does not reach. Caught by reading the regtest stack's
		// output, not by any test — every unit test passes its own logger in.
		// bcf: a relay refused at DIAL time is an audit event, not a log line —
		// the pre-check said the host was public and the socket got a private
		// address, which is a rebinding attempt rather than a bad relay list.
	}, nostr.Options{Log: log, Audit: auditor})
	defer relays.Close()

	// §7's zap receipts. The signer reads the identity fresh on every use
	// rather than closing over the one loaded above: the Settings page can
	// replace the key at runtime, and a receipt signed with a held copy is
	// signed by an identity the lightning address has stopped announcing.
	receipts := zap.New(db, nostr.NewSigner(db), relays, auditor, time.Now, log)

	// The guard's socket client, and the cache in front of it, are kept as two
	// values rather than one (d24.6). The cache exists for PAGE RENDERS —
	// guard.Status makes one or two gRPC calls to LND, and the Node and Security
	// pages are the ones an operator leaves open — but §8's ladder reads the same
	// report before every payment, and a ten-second window in which a revoked
	// macaroon still pays is not a page-render concern. The regtest stack found
	// exactly that. So the spend path reads the socket directly, and the
	// measured cost of doing so is ~1 ms per call on a local unix socket.
	guardSocket := guard.NewSocketClient(cfg.GuardSocket, relayGuardEvents)
	broker := api.NewCachedBroker(guardSocket, api.NodeStatusTTL, time.Now)
	node := lnd.New(cfg.LNDAddress,
		lnd.VolumeCredentials(cfg.CredentialsDir, lnd.ReceiveMacaroon),
		lnd.Options{Log: log, Broker: broker})
	defer node.Close()

	// A SECOND client, for the payment path only (d24.2).
	//
	// Two clients rather than one, because the macaroon is a connection-level
	// per-RPC credential: grpc-go applies BOTH sets when a call carries its own
	// as well ("if these credentials are provided both via dial options and call
	// options, then both sets of credentials will be applied" — its own comment),
	// so a per-call override would send two macaroons under one metadata key and
	// LND would refuse the pair. Each client therefore holds exactly ONE
	// CredentialSource, which is what makes "the receive paths never present the
	// spend macaroon, and vice versa" structural rather than a discipline (§6).
	//
	// NO BROKER, deliberately. The invoice stream is the sole call site that may
	// conclude the node rejected our credential (§6, o34.10, and an arch rule);
	// a payment client that cannot ask for a re-bake cannot be made to by a
	// later edit. Its state machine is its own and drives nothing the Node page
	// shows — that page is about the receive connection.
	// Bound once and used twice: the client presents it, and §8's ladder asks
	// whether it EXISTS before it starts a payment that cannot work without one
	// (step 2). Two calls to VolumeCredentials would be two statements of one
	// fact, and a later edit could give them different paths.
	spendCredentials := lnd.VolumeCredentials(cfg.CredentialsDir, lnd.SpendMacaroon)
	spendNode := lnd.New(cfg.LNDAddress, spendCredentials, lnd.Options{Log: log})
	defer spendNode.Close()

	// ONE moment, handed to both readers of it. The wallet's unresolved-payments
	// freeze and the resolver must agree about which payments belong to a
	// previous run; two calls to time.Now() would be two statements of one fact,
	// disagreeing by however long startup takes (u0u).
	startedAt := time.Now()
	// The auditor rides along so a fee adjustment the app makes to ITSELF
	// reaches §12's trail from the one door both the live path and the resolver
	// pass through (hdu).
	purse := wallet.New(db, wallet.Options{StartedAt: startedAt, Auditor: auditor, Log: log})
	auth, err := api.NewAuth(ctx, db, api.AuthOptions{
		AppPassword:   cfg.AdminPassword,
		SessionSecret: cfg.SessionSecret,
	})
	if err != nil {
		return fmt.Errorf("preparing admin auth: %w", err)
	}
	renderer, err := web.New(build)
	if err != nil {
		return err
	}
	if generated := auth.GeneratedPassword(); !generated.IsZero() {
		// §9: shown in the browser, never only in the logs — so the log says
		// only that there is one to collect.
		log.Info("an admin password was generated for first run; open the Setup page to read it")
	}

	demand := make(chan struct{}, 1)
	reconDemand := make(chan struct{}, 1)
	// The NWC service reloads its connections on this (uhg): the Connections and
	// Sending pages signal after a create, a revoke or a permission change, and
	// nothing restarts. Buffered by one, like the others — a signal that arrives
	// while a reload is running is a reload that will happen again.
	nwcDemand := make(chan struct{}, 1)
	prober := api.NewProber(probeToken, nil, time.Now)
	// §5's reconciliation, and the producer §11's Tier-2 row has been waiting
	// for: without it the spending freeze is unreachable.
	// Reconciliation also re-runs payment resolution (u0u): it already ticks, it
	// already takes demand, and an unresolved payment IS the ledger disagreeing
	// with the node about a row. A resolver that failed at boot therefore gets
	// another go every cycle, and the freeze it leaves standing lifts by itself.
	// Bound once and used twice — here and by the startup pass below. The
	// argument list is long enough that two copies would be two chances to hand
	// one of them a different cutoff, which is the one thing they must share.
	resolvePayments := func(ctx context.Context) error {
		// The cutoff comes from the WALLET, not from startedAt again. They must
		// be the same moment — the freeze and the resolver disagreeing about
		// which payments belong to a previous run is the one way this goes
		// wrong — and reading it from the thing that owns it makes them the same
		// value rather than two copies that a later edit could separate.
		// db twice, and they are different slices of it: the rows to resolve and
		// the one method that corrects an NWC connection's budget (d24.15).
		return resolvePendingPayments(ctx, db, purse, spendNode, db,
			purse.UnresolvedCutoff(), log)
	}
	reconciler := recon.New(node, purse, auditor, recon.Options{
		Log:             log,
		ResolvePayments: resolvePayments,
	})

	// §11's Tier 2, computed fresh on every render. The degraded banner and the
	// Security panel are two renderings of this one report.
	serverIP, _ := preflight.LocalAddress()
	// The server is built below and this closure runs per render, so the
	// forward reference is safe. It exists so §11's panel and the admin
	// limiter read ONE trusted-proxy list rather than two that drift (d46.19).
	var handler *api.Server
	// ONE report, built from one set of inputs, differing in a single argument:
	// where the guard's status comes from. The UI reads the cache; the ladder
	// reads the socket. Two closures over one construction, so the policy cannot
	// come to differ between the page an operator looks at and the check that
	// refuses their payment.
	makeChecks := func(brokerStatus func(context.Context) (lnd.BrokerStatus, error)) func(context.Context) preflight.Report {
		return func(ctx context.Context) preflight.Report {
			return preflight.Run(ctx, preflight.Inputs{
				NodeState:    node.State,
				BrokerStatus: brokerStatus,
				SpendMacaroon: func() ([]byte, bool) {
					raw, err := lnd.VolumeCredentials(cfg.CredentialsDir, lnd.SpendMacaroon).Macaroon()
					return raw, err == nil
				},
				ServerIP: serverIP,
				DataDir:  cfg.DataDir,
				Domain: func(ctx context.Context) (string, bool, string) {
					domain, _, _ := db.Setting(ctx, api.SettingDomain)
					ok, _, _ := db.Setting(ctx, api.SettingProbeOK)
					reason, _, _ := db.Setting(ctx, api.SettingProbeReason)
					return domain, ok == "true", reason
				},
				Shortfall: reconciler.Shortfall,
				// §5's SECOND freeze, its own row (1xp). Read through the
				// wallet, which owns the cutoff, so the dashboard and the freeze
				// cannot disagree about which payments count.
				UnresolvedPayments: purse.UnresolvedPayments,
				// §12's burst signal, counted in the trail the guard already
				// relays into (tna.2). No second store: the guard.reject rows
				// ARE the record, and a counter beside them would be two
				// statements of one fact.
				GuardRejections: func(ctx context.Context, since time.Time) (int, error) {
					return db.CountAuditEventsSince(ctx, logging.EventGuardReject, since)
				},
				ProxiesDeclared: func() bool { return handler != nil && handler.ProxiesDeclared() },
				Repair: func(what string) {
					if err := auditor.Record(ctx, slog.LevelWarn, "preflight repaired a permission",
						logging.EventPreflightRepair, slog.String("detail", what)); err != nil {
						log.Error("could not write the audit trail", "error", err.Error())
					}
				},
				Now: time.Now,
			})
		}
	}
	// The UI's, cached. The ladder's, straight to the guard.
	checks := makeChecks(broker.Status)
	spendChecks := makeChecks(guardSocket.Status)
	// §7's public endpoints. The service holds the protocol and no HTTP; the
	// handler holds the HTTP and knows nothing about description_hash.
	payments := lnurl.NewService(node, db, db, time.Now)
	// Built here rather than inside its own goroutine because the Connections
	// page asks it which pairings can reach their relay (d24.21). It performs no
	// I/O until Run.
	nwcService := newNWCService(db, relays, purse, node, spendNode, spendCredentials,
		spendChecks, auditor, nwcDemand, log)

	handler, err = api.NewServer(api.ServerOptions{
		Auth:        auth,
		Wallet:      purse,
		NodeState:   node.State,
		Broker:      broker,
		Audit:       db,
		Settings:    db,
		Renderer:    renderer,
		AllSettings: db,
		Level:       level,
		ProbeToken:  probeToken,
		ProbeDemand: demand,
		ReconDemand: reconDemand,
		// d24.5's two pages. NWCDemand is uhg: a create, a revoke or a
		// permission change takes effect without a restart.
		NWCDemand:   nwcDemand,
		Connections: db,
		// d24.21: so the page can say which pairings are currently reachable
		// rather than leaving the operator to read nwc_handled_requests by hand.
		NWCHealth:      nwcService,
		Guard:          guardSocket,
		Preflight:      checks,
		LNURL:          api.NewLNURLRoutes(payments, log),
		Auditor:        auditor,
		RetryNow:       node.RetryNow,
		Ready:          func() bool { return ctx.Err() == nil },
		TrustedProxies: cfg.TrustedProxies,
		Invoices:       db,
		History:        db,
		Log:            log,
	})
	if err != nil {
		return err
	}

	server := newHTTPServer(handler)
	// §11: bind and serve FIRST, then check. A preflight that gates the
	// listener means the operator cannot see why it failed — so the socket is
	// open and answering before Tier 1 runs, and a Tier-1 exit comes from a
	// process that got far enough to be diagnosable.
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.ListenAddr, err)
	}
	// Logged here rather than inside the serving goroutine: the socket is bound
	// by this line, and saying so on the main path is what makes the ordering
	// against the Tier-1 refusal below a fact about the program rather than a
	// race between two goroutines' writes.
	log.Info("listening", "addr", listener.Addr().String(), "version", build)
	// Every goroutine started here logs, and the logger writes to a stream the
	// caller owns. Returning while one is still running is a write to that
	// stream after the caller has moved on — which -race reports, and which in
	// production interleaves lines into a stopping process.
	var running sync.WaitGroup
	defer running.Wait()

	serverErr := make(chan error, 1)
	running.Add(1)
	go func() {
		defer running.Done()
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serverErr <- err
	}()

	// Tier 1, and the whole of it: the server must not be able to read
	// admin.macaroon. This cannot prove a negative — a mount at an unexpected
	// path is invisible to it — which is why the compose lint is the primary
	// control and this is the backstop.
	if finding := preflight.AdminMacaroonExposure(env, lndMountPath, cfg.CredentialsDir, cfg.DataDir); finding != nil {
		if err := auditor.Record(ctx, slog.LevelError, "refusing to run: "+finding.Detail,
			logging.EventPreflightRefuse, slog.String("check", finding.ID)); err != nil {
			log.Error("could not write the audit trail", "error", err.Error())
		}
		_ = server.Close()
		return errTierOne
	}

	// The background loops. Each survives its dependency being absent: the
	// stream retries forever, the sweep touches only the local database, and
	// the prober does nothing at all until a domain is configured.
	background := func(name string, run func()) {
		running.Add(1)
		go func() {
			defer running.Done()
			run()
			log.Debug("background loop stopped", "loop", name)
		}()
	}

	// The common case, cleared before any traffic. §6's resolve-before-accept
	// rule is NOT this ordering — it is the freeze in wallet.Reserve (u0u), and
	// it has to be, because the HTTP listener is already serving well above
	// here. This pass just does the easy part early: on a clean start it is one
	// local query and the node is never touched.
	//
	// A failure does not stop the app, and no longer drops the invariant either.
	// The freeze stays up and reconciliation retries until the node answers
	// (§11: a missing dependency is a degraded state, never a refusal to run).
	if err := resolvePayments(ctx); err != nil {
		log.Error("some payments from a previous run could not be resolved; spending stays held "+
			"until they do, and reconciliation will keep trying", "error", err.Error())
	}

	background("invoice stream", func() { runInvoiceStream(ctx, node, db, purse, receipts, log) })
	background("expiry sweep", func() { runExpirySweep(ctx, db, log) })
	background("domain probe", func() { runProbe(ctx, prober, db, demand, auditor, log) })
	background("reconciliation", func() { runRecon(ctx, reconciler, reconDemand, log) })
	background("guard events", func() { runGuardEvents(ctx, broker, log) })
	background("zap receipts", func() { runZapReceipts(ctx, receipts) })
	background("nwc", func() { runNWC(ctx, nwcService, nwcDemand, log) })

	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()
	return server.Shutdown(shutdown)
}

// guardEventInterval is how often the guard is polled purely so its security
// events reach the durable trail.
//
// Admin page renders poll the guard anyway, so most of the time this finds
// nothing new. It exists for the case where nobody is looking: without it the
// durability of a security trail would have an unwritten precondition — that an
// operator logs in — and §12 states no such thing (d46.18). It also bounds how
// long the guard's undrained ring has to hold events.
const guardEventInterval = 5 * time.Minute

// runGuardEvents polls the guard so its security events reach audit_events
// whether or not anyone is watching.
//
// The collection is a side effect of the call: the socket client hands every
// response's events to the relay. Polling once before the first tick is
// deliberate — a bake raised at install time should be on the Security page
// when the operator first opens it, not five minutes later.
func runGuardEvents(ctx context.Context, broker *api.CachedBroker, log *slog.Logger) {
	poll := func() {
		if _, err := broker.Status(ctx); err != nil && ctx.Err() == nil {
			log.Debug("could not reach the guard to collect its security events",
				"error", err.Error())
		}
	}
	poll()
	ticker := time.NewTicker(guardEventInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}

// runInvoiceStream credits settled invoices. The wallet decides whether a
// credit raises the ceiling (§5's credit_received); this only carries the
// settlement across.
func runInvoiceStream(ctx context.Context, node *lnd.Client, db *store.Store, purse crediter,
	receipts *zap.Publisher, log *slog.Logger) {
	err := node.RunInvoiceStream(ctx, db, func(ctx context.Context, invoice *lnrpc.Invoice) error {
		return handleSettlement(ctx, invoice, purse, receipts.OnSettled, log)
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Error("the invoice stream stopped", "error", err.Error())
	}
}

// handleSettlement credits one settled invoice and, if it was ours, asks for its
// receipt.
//
// Extracted so both of its answers can be tested: a settlement this app did not
// create is skipped, and one it DID create that fails to credit still stops the
// stream. Those two differ by one errors.Is and the difference is money.
//
// onCredited is a func rather than an interface because there is exactly one
// implementation, and a test needs to see whether it was called at all.
func handleSettlement(ctx context.Context, invoice *lnrpc.Invoice, purse crediter,
	onCredited func(context.Context, string), log *slog.Logger) error {
	hash := hex.EncodeToString(invoice.RHash)
	credited, err := purse.CreditInvoice(ctx, hash, hex.EncodeToString(invoice.RPreimage),
		invoice.AmtPaidMsat, settleTimeOf(invoice, hash, log))
	switch {
	case errors.Is(err, store.ErrUnknownInvoice):
		// Not ours, and that is the NORMAL case on the platform this ships to.
		// Umbrel is a deliberately shared node — BTCPay, Alby Hub and LNDg all
		// receive on the same LND — so every neighbour's payment arrives here.
		//
		// Safe because it is definitional: our invoices always have an invoices
		// row BEFORE they can settle, written by the callback at mint time. A
		// settlement whose payment_hash has no row was therefore not minted by
		// this app, full stop.
		//
		// ErrUnknownInvoice, not the package-wide ErrNotFound: skipping
		// advances the resume point past the settlement and nothing revisits
		// it, so the discriminator has to mean exactly one thing. Any other
		// not-found reaching here is a fault in our own path and falls through
		// to the arm below.
		//
		// It used to be returned as an error, which dropped the subscription
		// and forced a reconnect — one that re-reads the credential and walks
		// the resume path. The box saw it once in a quiet hour; on a busy node
		// it is continuous (0.1.7 results §E).
		//
		// DEBUG, not INFO: this fires on every neighbour's payment, and an INFO
		// line here would be the node's other apps deciding how fast this one
		// writes to its log.
		log.Debug("a settlement for an invoice this app did not create; skipping",
			logging.PaymentHash(hash), "settle_index", invoice.SettleIndex)
		return nil
	case err != nil:
		// A hash we DO have a row for, that failed to credit. That is a fault
		// in our own path and it stays fatal to the stream: skipping it would
		// be silent money loss, which is the one outcome worse than a reconnect.
		return err
	}
	if credited {
		log.Info("invoice settled", logging.PaymentHash(hash), "amount_msat", invoice.AmtPaidMsat)
		// AFTER the credit has committed, and it neither blocks nor returns
		// (§7). The money arriving is the event; the receipt is a consequence
		// of it. This stream is strictly serial and writes its durable resume
		// point only after this callback returns, so a publish done here would
		// stall the next settlement for as long as a relay took to time out —
		// OnSettled hands off to the publishing goroutine instead.
		onCredited(ctx, hash)
	}
	return nil
}

// settleTimeOf is the NODE's settle time for a settled invoice — the value §7
// makes the zap receipt's created_at, and which it says is never the handler's
// clock.
//
// This is the line o34.21 was about, and it is a named function so a test can
// reach it: for four waves the receipt carried this process's clock, every unit
// test passed, and the two only differ when the server was down at settlement —
// by exactly the outage. Measured on regtest at 60 seconds.
//
// A zero is an anomaly, not a case to absorb quietly: RunInvoiceStream filters
// to SETTLED before the handler is called, and a settled invoice always carries
// a settle time. Absorbing it silently would rebuild the blind spot one layer
// up, which is how the original bug survived. What happens to a zero afterwards
// is wallet.CreditInvoice's to state, and it does.
func settleTimeOf(invoice *lnrpc.Invoice, paymentHash string, log *slog.Logger) time.Time {
	if invoice.SettleDate > 0 {
		return time.Unix(invoice.SettleDate, 0).UTC()
	}
	log.Warn("the node reported a settled invoice with no settle time; the receipt will carry "+
		"this process's clock instead of when the zap was paid",
		logging.PaymentHash(paymentHash))
	return time.Time{}
}

// runZapReceipts republishes receipts no relay accepted (§7, o34.3). The
// cadence is the caller's, like every other loop here, so the schedule is a
// decision made in one place rather than inside the package.
func runZapReceipts(ctx context.Context, receipts *zap.Publisher) {
	ticker := time.NewTicker(zapRetryInterval)
	defer ticker.Stop()
	receipts.RunRetry(ctx, ticker.C)
}

func runExpirySweep(ctx context.Context, db *store.Store, log *slog.Logger) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	err := db.RunExpirySweep(ctx, ticker.C, time.Now, func(expired int64, err error) {
		switch {
		case err != nil:
			log.Warn("the invoice expiry sweep failed", "error", err.Error())
		case expired > 0:
			log.Debug("invoices expired", "count", expired)
		}
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Error("the expiry sweep stopped", "error", err.Error())
	}
}

// runProbe re-verifies the lightning address hourly and on demand (§9).
func runProbe(ctx context.Context, prober *api.Prober, db *store.Store, demand <-chan struct{},
	auditor *logging.Auditor, log *slog.Logger) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	prober.Run(ctx, ticker.C, demand, func() (string, string, string) {
		domain, _, _ := db.Setting(ctx, api.SettingDomain)
		name, _, _ := db.Setting(ctx, api.SettingAddressName)
		pubkey, _, _ := db.Setting(ctx, api.SettingNostrPubkey)
		insecure, _, _ := db.Setting(ctx, api.SettingDomainInsecure)
		// The origin, built by the one function the callback URL comes from,
		// so the probe cannot go green against a URL no wallet is given.
		return lnurl.BaseURL(domain, insecure == "true"), name, pubkey
	}, func(result api.ProbeResult) {
		record := map[string]string{
			api.SettingProbeOK:     strconv.FormatBool(result.OK),
			api.SettingProbeReason: result.Reason,
			api.SettingProbeAt:     result.At.Format(time.RFC3339),
		}
		for key, value := range record {
			if err := db.SetSetting(ctx, key, value); err != nil {
				log.Warn("could not record the probe result", "error", err.Error())
			}
		}
		if err := auditor.Record(ctx, slog.LevelInfo, "lightning address probed",
			logging.EventDomainProbe,
			slog.Bool("ok", result.OK), slog.String("reason", result.Reason)); err != nil {
			log.Error("could not write the audit trail", "error", err.Error())
		}
	})
}

// runRecon compares the wallet ceiling against the node's spendable balance
// every five minutes (§5). It is the only thing that can freeze spending, and
// it never writes a balance entry.
func runRecon(ctx context.Context, reconciler *recon.Reconciler, demand <-chan struct{},
	log *slog.Logger) {
	ticker := time.NewTicker(recon.DefaultInterval)
	defer ticker.Stop()
	// Once at startup, so a shortfall that opened while the process was down is
	// visible before the first tick rather than five minutes later.
	//
	// Check, not the loop's full pass: the payment resolution that rides that
	// pass has already run inline above, and running it twice at boot would ask
	// the node about the same rows a second time for nothing. Every LATER pass
	// does both.
	if err := reconciler.Check(ctx); err != nil {
		log.Debug("the first reconciliation check could not run", "error", err.Error())
	}
	reconciler.Run(ctx, ticker.C, demand, nil)
}
