// Command brollyguard is the BrollyZapper guard: credential broker; no
// listeners, sole holder of admin.macaroon.
//
// See internal/arch for the container split (§3 of the design) and §6
// for what this binary is allowed to do.
package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/davotoula/brollyzapper/internal/cliboot"
	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/guard"
)

// version is stamped at link time with -X main.version=<tag>; it stays "dev"
// for a plain go build.
var version = "dev"

// Exit codes. Anything non-zero makes restart: on-failure restart the
// container, which is exactly what rotation recovery needs.
const (
	exitConfig   = 1
	exitRotation = 3
)

func main() {
	// SIGTERM is what docker stop sends; without this the guard would be killed
	// mid-write rather than closing its socket.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], config.OSLookup, os.Stdout, os.Stderr))
}

// run is the whole of main's behaviour, extracted so it is testable without a
// process. It returns the process exit code.
func run(ctx context.Context, args []string, env config.Lookup, stdout, stderr io.Writer) int {
	boot, code, done := cliboot.Start("brollyguard", version, args, stdout, stderr)
	if done {
		return code
	}
	log, level, build := boot.Log, boot.Level, boot.Build

	cfg, err := config.LoadGuard(env)
	if err != nil {
		boot.ReportConfigError(err)
		return exitConfig
	}
	// LOG_LEVEL applies from here on, and the LevelVar means the admin UI can
	// change it later without a restart (spec §12).
	level.Set(cfg.LogLevel)
	log.Info("starting", "version", build, "config", cfg)

	// Before anything else: the two single-file bind mounts must be files. If
	// one is a directory, docker created it because the source was missing, and
	// saying so is the difference between an operator knowing what to remove
	// and reading "exit 127" (spec §6).
	if err := guard.PreflightMounts(cfg.LNDCertFile, cfg.LNDAdminMacaroonFile); err != nil {
		log.Error("mount preflight failed", "error", err.Error())
		return exitConfig
	}
	// Not fatal: the guard can still answer Status, so the admin UI shows what
	// is wrong rather than the tile going dead (§11). But it is the difference
	// between an operator reading one chown command and chasing a bake that
	// appears to succeed and leaves no file.
	if err := guard.PreflightCredentialsDir(cfg.CredentialsDir); err != nil {
		log.Error("the credential volume is not writable", "error", err.Error())
	}

	broker, err := guard.New(cfg, guard.Options{Log: log})
	if err != nil {
		log.Error("cannot start the guard", "error", err.Error())
		return exitConfig
	}
	defer broker.Close()

	// A regenerated certificate reaches the server only through this copy, and
	// the server holds no mount from the lightning app at all (§6).
	if err := broker.CopyCertificate(); err != nil {
		// Not fatal: the socket still answers Status, so the admin UI can show
		// what is wrong rather than the tile going dead (§11).
		log.Error("could not copy tls.cert into the credential volume", "error", err.Error())
	}
	if err := broker.EnsureReceiveMacaroon(ctx); err != nil {
		log.Warn("could not bake the receive macaroon yet; the server will ask again",
			"error", err.Error())
	}
	// And the spend credential, which before tna.1 was only ever touched by the
	// renewal tick. §14 says a spend macaroon baked without P4's custom caveat
	// is dealt with "at the first start after the upgrade", and this is that
	// start: waiting for the tick would leave an install spending uncapped for
	// up to an hour after every upgrade.
	if err := broker.EnsureSpendMacaroon(ctx); err != nil {
		log.Warn("could not settle the spend macaroon yet; the renewal loop will try again",
			"error", err.Error())
	}

	// §6: the credentials carry a time-before caveat, so something has to
	// replace them before it passes. A guard that only baked on demand would
	// let a healthy install expire itself.
	renewal := time.NewTicker(guard.RenewInterval)
	defer renewal.Stop()
	renewing, stopRenewing := context.WithCancel(ctx)
	// Stopped and WAITED FOR before run returns. The goroutine logs, and the
	// logger writes to a stream the caller owns — returning while it is still
	// running is a write after the caller has moved on, which -race reports and
	// which in production interleaves lines into a stopping process.
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		defer running.Done()
		broker.RunRenewal(renewing, renewal.C)
	}()
	// The RPC middleware (§14, tna.1). It reconnects for ever and never exits
	// the process: while it is down the spend macaroon is DEAD rather than
	// unrestricted — LND rejects a custom caveat with no middleware registered
	// for it — so the safe response is to keep the guard up, keep re-registering,
	// and report the state through Status.
	running.Add(1)
	go func() {
		defer running.Done()
		broker.RunMiddleware(renewing)
	}()
	defer func() {
		stopRenewing()
		running.Wait()
	}()

	socketPath := filepath.Join(cfg.CredentialsDir, config.GuardSocketName)
	err = broker.Serve(ctx, socketPath)
	switch {
	case errors.Is(err, guard.ErrMacaroonRotated):
		// The one sanctioned exit in the codebase: a single-file bind mount
		// follows the inode, so only a container restart can re-resolve it (§6).
		log.Warn("exiting so the container restart picks up the rotated macaroon")
		return exitRotation
	case err != nil && !errors.Is(err, context.Canceled):
		log.Error("guard stopped", "error", err.Error())
		return exitConfig
	}
	log.Info("guard stopped")
	return 0
}
