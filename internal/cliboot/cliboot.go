// Package cliboot brings a binary up to the point where its own work starts:
// flags, --version, and a logger, in that order.
//
// Both binaries need exactly this and nothing more before they diverge — the
// server into an HTTP listener, the guard into a unix socket. §3's split is a
// runtime boundary about which container holds admin.macaroon, not a reason for
// two copies of the same twenty lines; the copies had already drifted by the
// time this package was extracted.
package cliboot

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/davotoula/brollyzapper/internal/buildinfo"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// ExitFlags is the code for an unusable command line.
const ExitFlags = 2

// Result is what a started binary has before it reads its configuration.
type Result struct {
	Log   *slog.Logger
	Level *slog.LevelVar
	Build string
}

// Start parses args and brings up the logger.
//
// done reports that the binary should return code immediately — because
// --version was asked for, or because the flags were unusable.
func Start(name, version string, args []string, stdout, stderr io.Writer) (result Result, code int, done bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return Result{}, ExitFlags, true
	}
	build := buildinfo.Resolve(version)
	if *showVersion {
		fmt.Fprintf(stdout, "%s %s\n", name, build)
		return Result{}, 0, true
	}

	// The logger comes up before the configuration is read, at the default
	// level, so a configuration failure is reported the same way as everything
	// else rather than through a channel nothing collects. Stdout only (§12).
	level := logging.NewLevelVar(slog.LevelInfo)
	log := logging.New(stdout, level)
	// And it becomes the process default (vz1.3). Several components take a
	// logger and fall back to the default one when a caller does not pass it;
	// until this line that fallback was slog's own — plain text on stderr, with
	// LOG_LEVEL unable to reach it, in a project whose §12 says JSON on stdout.
	//
	// Wave 16 shipped exactly that bug in the relay pool and NO unit test could
	// have caught it, because every test passes its own logger in. This is the
	// half that makes the fallbacks correct; the arch rule is the half that
	// stops a new package reintroducing a private one.
	slog.SetDefault(log)
	return Result{Log: log, Level: level, Build: build}, 0, false
}

// ReportConfigError logs every variable that needs fixing, so one restart is
// enough to see the whole list rather than the first problem only.
func (r Result) ReportConfigError(err error) {
	for _, line := range strings.Split(err.Error(), "\n") {
		r.Log.Error("invalid configuration", "variable", line)
	}
}
