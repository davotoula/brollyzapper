package preflight_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/preflight"
)

// clock is a fake time a test moves by hand.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// inline runs a refresh before Result returns, so a test reads its outcome
// without waiting on a goroutine.
func inline(f func()) { f() }

// `20i.21`: the probe must not turn a page render into a node call. This report
// is built on every admin render AND before every payment (`e0n`), so a probe
// that dialled each time would put a GetInfo in front of both.
func TestTheServerCredentialProbeAsksTheNodeAtMostOncePerInterval(t *testing.T) {
	var calls atomic.Int32
	now := &clock{now: time.Unix(1_700_000_000, 0)}
	probe := preflight.NewCredentialProbe(t.Context(), func(context.Context) error {
		calls.Add(1)
		return nil
	}, preflight.ProbeOptions{Interval: time.Minute, Now: now.Now, Spawn: inline})

	for range 20 {
		probe.Result()
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("20 reads inside one interval asked the node %d times, want 1", got)
	}
	now.Advance(59 * time.Second)
	probe.Result()
	if got := calls.Load(); got != 1 {
		t.Errorf("a read 59s in asked again (%d calls); the interval is a minute", got)
	}
	now.Advance(time.Second)
	result := probe.Result()
	if got := calls.Load(); got != 2 {
		t.Errorf("a read a full interval later made %d calls, want 2", got)
	}
	if !result.At.Equal(now.Now()) {
		t.Errorf("the refreshed answer is dated %v, want %v", result.At, now.Now())
	}
}

// A FAILURE IS RATE-LIMITED TOO. An unreachable node is the case where asking
// is slowest and an answer least likely to change; timing the interval from
// the last SUCCESS would ask on every render for exactly as long as it fails.
func TestAFailingProbeIsNotRetriedInsideTheInterval(t *testing.T) {
	var calls atomic.Int32
	now := &clock{now: time.Unix(1_700_000_000, 0)}
	probe := preflight.NewCredentialProbe(t.Context(), func(context.Context) error {
		calls.Add(1)
		return errors.New("unreachable")
	}, preflight.ProbeOptions{Interval: time.Minute, Now: now.Now, Spawn: inline})

	for range 10 {
		probe.Result()
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("a failing probe was asked %d times inside one interval, want 1", got)
	}
}

// A read never waits on the node: while a probe is out, readers get the last
// answer, and no second probe starts beside it.
func TestAReadDoesNotWaitOnAProbeInFlight(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	// A NANOSECOND INTERVAL, so the in-flight guard is the only thing that can
	// stop a second probe. With a minute here the interval alone did, and the
	// guard could be deleted with this test green — measured.
	probe := preflight.NewCredentialProbe(t.Context(), func(context.Context) error {
		started <- struct{}{}
		<-release
		return nil
	}, preflight.ProbeOptions{Interval: time.Nanosecond})
	defer close(release)

	done := make(chan preflight.ProbeResult, 1)
	go func() { done <- probe.Result() }()
	select {
	case result := <-done:
		if !result.At.IsZero() {
			t.Errorf("the first read returned an answer dated %v before the probe finished", result.At)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a read waited on the node")
	}
	<-started
	probe.Result()
	// WAIT FOR THE SECOND START RATHER THAN COUNT. A probe goroutine that was
	// started has not necessarily run by the next line, so reading a counter here
	// passed with the guard deleted — measured, again.
	select {
	case <-started:
		t.Error("a second probe started while the first was in flight")
	case <-time.After(200 * time.Millisecond):
	}
}

// NEVER A TICK OVER A QUESTION NOBODY ASKED (`d46.25`, §11). Before the first
// answer the row says so; a green "works" here would be a claim about a
// credential no call has presented.
func TestAServerCredentialNotYetCheckedIsNotAPass(t *testing.T) {
	in := inputs(t)
	in.ServerCredential = func() preflight.ProbeResult { return preflight.ProbeResult{} }
	report := preflight.Run(t.Context(), in)

	got := check(t, report, preflight.CheckServerCredential)
	if got.OK {
		t.Errorf("an unasked server credential passed: %+v", got)
	}
	if report.ServerCredential == nil || !report.ServerCredential.At.IsZero() {
		t.Errorf("Report.ServerCredential = %+v, want present and not yet checked", report.ServerCredential)
	}
}

// `20i.21` criterion 4, at the source: a refusal is "no", dated, and in the
// app's words — never the node's status text.
func TestARefusedServerCredentialFailsWithItsTime(t *testing.T) {
	at := time.Date(2026, 9, 13, 14, 5, 9, 0, time.UTC)
	nodeText := "verification failed: signature mismatch after caveat verification"
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"refused", status.Error(codes.Unauthenticated, nodeText), "refused"},
		{"not linked", lnd.ErrNotLinked, "no credential"},
		{"certificate", &lnd.CertificateNameError{Dialled: "10.61.7.1"}, "certificate"},
		// The node ANSWERED, with a code that is not an auth failure — d46.20's
		// malformed macaroon arrives as Unknown. "Could not reach" would be the
		// wrong sentence for a node that plainly did.
		{"answered but not accepted", status.Error(codes.Unknown, nodeText), "would not accept"},
		{"unreachable", status.Error(codes.Unavailable, nodeText), "could not reach"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := inputs(t)
			in.ServerCredential = func() preflight.ProbeResult { return preflight.ProbeResult{At: at, Err: tc.err} }
			got := check(t, preflight.Run(t.Context(), in), preflight.CheckServerCredential)

			if got.OK {
				t.Fatalf("a failed probe passed: %+v", got)
			}
			if !strings.Contains(got.Detail, tc.want) {
				t.Errorf("Detail = %q, want it to say %q", got.Detail, tc.want)
			}
			if !strings.Contains(got.Detail, "as of 14:05:09 UTC") {
				t.Errorf("Detail = %q, want the time of the answer", got.Detail)
			}
			if strings.Contains(got.Detail, "signature mismatch") || strings.Contains(got.Detail, tc.err.Error()) {
				t.Errorf("Detail = %q carries the error's own text", got.Detail)
			}
			if got.Blocks == preflight.BlocksReceiving {
				t.Error("the server-credential row blocks receiving; §11 forbids it")
			}
		})
	}
}

func TestAWorkingServerCredentialPassesWithItsTime(t *testing.T) {
	at := time.Date(2026, 9, 13, 14, 5, 9, 0, time.UTC)
	in := inputs(t)
	in.ServerCredential = func() preflight.ProbeResult { return preflight.ProbeResult{At: at} }
	got := check(t, preflight.Run(t.Context(), in), preflight.CheckServerCredential)
	if !got.OK || !strings.Contains(got.Detail, "as of 14:05:09 UTC") {
		t.Errorf("a working credential = %+v, want a pass carrying its time", got)
	}
}

// SHUTDOWN JOINS A PROBE IN FLIGHT (go-review, `20i.21`). serve() waits for every
// background goroutine before it closes the node client; a probe started by a
// render was the one it did not, so the client could close under a GetInfo. And
// once closed, a late render must not start another.
func TestCloseWaitsForAProbeInFlightAndStartsNoMore(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	probe := preflight.NewCredentialProbe(t.Context(), func(context.Context) error {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return nil
	}, preflight.ProbeOptions{Interval: time.Nanosecond})

	probe.Result()
	<-started
	closed := make(chan struct{})
	go func() { probe.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned while a probe was still in flight")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return once the probe finished")
	}

	probe.Result()
	select {
	case <-started:
		t.Error("a probe started after Close")
	case <-time.After(100 * time.Millisecond):
	}
}
