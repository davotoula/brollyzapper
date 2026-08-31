package cliboot_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/cliboot"
)

func TestVersionFlagPrintsAndStops(t *testing.T) {
	var stdout, stderr bytes.Buffer
	boot, code, done := cliboot.Start("brollytest", "v1.2.3", []string{"--version"}, &stdout, &stderr)
	if !done || code != 0 {
		t.Fatalf("--version = done %v code %d, want done 0", done, code)
	}
	if got := stdout.String(); !strings.Contains(got, "brollytest") || !strings.Contains(got, "v1.2.3") {
		t.Errorf("stdout = %q, want the binary name and version", got)
	}
	if boot.Log != nil {
		t.Error("no logger should be built for a --version run")
	}
}

func TestAnUnknownFlagStopsWithANonZeroCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	_, code, done := cliboot.Start("brollytest", "dev", []string{"--nope"}, &stdout, &stderr)
	if !done || code == 0 {
		t.Fatalf("--nope = done %v code %d, want done and non-zero", done, code)
	}
	if stderr.Len() == 0 {
		t.Error("nothing was written to stderr about the bad flag")
	}
}

// The logger comes up before the configuration is read, so a configuration
// failure is reported the same way as everything else.
func TestTheLoggerIsUpBeforeAnyConfigIsRead(t *testing.T) {
	var stdout, stderr bytes.Buffer
	boot, _, done := cliboot.Start("brollytest", "dev", nil, &stdout, &stderr)
	if done {
		t.Fatal("Start reported done for an ordinary run")
	}
	boot.Log.Info("hello")

	var line map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout.String())), &line); err != nil {
		t.Fatalf("the logger did not write structured output to stdout: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q; §12 says logs go to stdout only", stderr.String())
	}
}

// Every offending variable is named, so one restart is enough to see the whole
// list.
func TestReportConfigErrorNamesEveryVariable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	boot, _, _ := cliboot.Start("brollytest", "dev", nil, &stdout, &stderr)
	boot.ReportConfigError(errors.Join(
		errors.New("LND_ADDRESS: is required and was not set"),
		errors.New("DATA_DIR: is required and was not set"),
	))
	out := stdout.String()
	for _, want := range []string{"LND_ADDRESS", "DATA_DIR"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log does not name %s: %s", want, out)
		}
	}
}

// vz1.3, and the one assertion that could have caught Wave 16's bug.
//
// Several components accept a *slog.Logger and fall back to the process default
// when a caller passes nil. slog's OWN default is plain text on stderr and deaf
// to LOG_LEVEL, which §12 forbids — and no unit test anywhere can see it,
// because every test supplies its own logger. That is precisely how the relay
// pool shipped a line in the wrong format to the wrong stream: the fallback is
// the one path the suite never takes.
//
// So the boot makes ITS logger the default, and this asserts it end to end:
// something written through slog's default has to come out of the writer the
// binary was handed, in the format §12 requires.
func TestStartMakesItsLoggerTheProcessDefault(t *testing.T) {
	// slog.SetDefault is process-wide, so put back whatever was there.
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	var stdout, stderr bytes.Buffer
	boot, code, done := cliboot.Start("brollytest", "v1.2.3", nil, &stdout, &stderr)
	if done || code != 0 {
		t.Fatalf("Start = done %v code %d, want a running boot", done, code)
	}

	slog.Default().Info("through the default logger", "key", "value")

	if stderr.Len() != 0 {
		t.Errorf("the default logger wrote to stderr: %q — §12 says stdout only", stderr.String())
	}
	line := stdout.String()
	if line == "" {
		t.Fatal("the default logger did not write to the boot's stdout; a component that " +
			"falls back to it would log somewhere nobody is collecting, in a format §12 " +
			"does not allow, and no other test in this repo can see that")
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &record); err != nil {
		t.Fatalf("the default logger is not writing JSON: %v (%q)", err, line)
	}
	if record["msg"] != "through the default logger" || record["key"] != "value" {
		t.Errorf("the default logger wrote %v, want the message and its attribute", record)
	}

	// And it is the same logger the boot handed back, not a second one that
	// happens to point at the same place.
	boot.Log.Info("through the returned logger")
	if got := strings.Count(stdout.String(), "\n"); got != 2 {
		t.Errorf("%d lines on stdout after two logs, want 2", got)
	}
}
