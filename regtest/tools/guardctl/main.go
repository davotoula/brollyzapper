// guardctl drives the guard's socket API from the regtest stack.
//
// It exists because the guard has no CLI and the server's sending toggle is
// d24.5: without it, nothing on the stack can ask the guard to bake or revoke
// the spend macaroon, and `regtest/spend.sh` would have to prove d24.1 by
// baking with lncli — which would prove something about lncli.
//
// It goes through guard.SocketClient, the SERVER's own side of the socket,
// rather than writing JSON at the socket itself. That is the point: the wire
// format, the operation vocabulary and the audit relay are production's,
// so a defect in any of them is a defect this finds. It is the same reasoning
// that puts regtest/tools/mactool on internal/lnd's encoder.
//
// It runs INSIDE a container with the credential volume mounted, because that
// is where the socket lives. Cross-compiled by the script that uses it; an arch
// rule keeps main-module regtest tooling free of third-party imports, which is
// what lets it live here rather than in a module of its own.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/davotoula/brollyzapper/internal/guard"
)

func main() {
	socket := flag.String("socket", "/credentials/guard.sock", "the guard's unix socket")
	// The guard's OWN data directory, which the server has no mount for. The
	// script mounts it into this tool for one reason and one only: to play the
	// OPERATOR, who is the only party that can read the code. Everything else
	// here goes through the socket, as the server does.
	authorisation := flag.String("authorisation", "/guard",
		"the guard's data directory, for read-code — the operator's half of the ceremony")
	timeout := flag.Duration("timeout", 30*time.Second, "how long to wait for the guard")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: guardctl [-socket path] [-authorisation dir] "+
			"status|bake-spend|revoke-spend|authorise <control> [sats]|"+
			"apply <control> <sats|on|off> [code]|read-code|permit-sending")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// DiscardEvents, deliberately and visibly: the guard reports its security
	// events on every answer, and this tool is not the thing that writes the
	// durable trail — the server is, and spend.sh asserts they arrive there.
	client := guard.NewSocketClient(*socket, guard.DiscardEvents)

	switch command := flag.Arg(0); command {
	case "status":
		got, err := client.Status(ctx)
		if err != nil {
			fail(err)
		}
		// Re-shaped into guard.Status rather than encoded straight through.
		// lnd.BrokerStatus is the SERVER's internal view and carries no json
		// tags, so marshalling it would print Go field names and tie every
		// assertion in spend.sh to a field a refactor may rename. guard.Status
		// is the guard's own WIRE type and already carries the names — so this
		// borrows them instead of declaring a third copy that can drift.
		out := guard.Status{
			ReceiveMacaroonPresent: got.ReceiveMacaroonPresent,
			SpendMacaroonPresent:   got.SpendMacaroonPresent,
			ReceiveExpiry:          got.ReceiveExpiry,
			SpendExpiry:            got.SpendExpiry,
			SpendRootKeyListed:     got.SpendRootKeyListed,
			LNDReachable:           got.LNDReachable,
			// P4's four (tna.1, tna.2). cap.sh reads spend_used_msat as a
			// BEFORE/AFTER pair rather than grepping a log line, which is the
			// assertion shape this repo's integration scripts have learned to
			// prefer.
			SendingPermitted:     got.SendingPermitted,
			MiddlewareRegistered: got.MiddlewareRegistered,
			SpendUsedMsat:        got.SpendUsedMsat,
			SpendLimitMsat:       got.SpendLimitMsat,
			// `06v`'s four. The two halves of the gate separately, because the
			// script asserts they are DIFFERENT states; the pending grant so it
			// can tell "the guard wrote a file" from "the guard did not"; and
			// the per-payment cap, which had no wire field before this.
			SendingAllowedByDeployment: got.SendingAllowedByDeployment,
			SendingLatched:             got.SendingLatched,
			AuthorisationPending:       got.AuthorisationPending,
			MaxPaymentMsat:             got.MaxPaymentMsat,
		}
		if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
			fail(err)
		}
	case "bake-spend":
		if err := client.RequestSpendBake(ctx); err != nil {
			fail(err)
		}
	case "revoke-spend":
		if err := client.RequestSpendRevoke(ctx); err != nil {
			fail(err)
		}
	case "authorise":
		// `06v`: ask the guard to write a one-time grant. It returns NOTHING
		// useful on success — deliberately, and the whole design is that this
		// side cannot learn the code.
		if err := client.RequestAuthorisation(ctx, mustChange(flag.Args()[1:])); err != nil {
			fail(err)
		}
	case "apply":
		// The code is the LAST argument and is optional, because a tightening
		// needs none. Whether this one is a tightening is the guard's to decide,
		// so the tool passes what it has and reports what comes back — the same
		// contract the server has.
		args := flag.Args()[1:]
		var code string
		if len(args) == 3 {
			code, args = args[2], args[:2]
		}
		if err := client.ApplyChange(ctx, mustChange(args), code); err != nil {
			fail(err)
		}
	case "permit-sending":
		// THE WHOLE CEREMONY, in one command, because three regtest scripts were
		// each carrying their own four-step copy of it and had already drifted in
		// the wording. It is a protocol sequence rather than a formatting helper,
		// and the failure mode of a stale copy is a script that keeps passing
		// because it stopped exercising the ceremony. Found by review.
		//
		// authorise.sh deliberately does NOT use this: its subject IS the
		// ceremony, so its steps stay written out where they can be asserted
		// between.
		if err := permitSending(ctx, client, *authorisation); err != nil {
			fail(err)
		}
	case "read-code":
		// THE OPERATOR'S STEP, and it is here so that the script drives the
		// whole ceremony rather than half of it. It reads the guard's own file
		// out of the guard's own volume, through the ONE statement of that
		// file's format — guard.AuthorisationCodeLine — so a script holding a
		// second copy of the format cannot pass while the file changes.
		code, err := readCode(*authorisation)
		if err != nil {
			fail(err)
		}
		fmt.Println(code)
	default:
		fail(fmt.Errorf("unknown command %q", command))
	}
}

// permitSending is the operator's ceremony end to end: ask, read, redeem.
//
// IDEMPOTENT, because a script that restarts a guard over the same volumes comes
// back to a latch that is already on — and asking to authorise a change that has
// already happened is refused, by design (Ruling 1).
func permitSending(ctx context.Context, client *guard.SocketClient, dir string) error {
	status, err := client.Status(ctx)
	if err != nil {
		return err
	}
	if status.SendingLatched {
		return nil
	}
	change := guard.Change{Control: guard.ControlSending, On: true}
	if err := client.RequestAuthorisation(ctx, change); err != nil {
		return fmt.Errorf("the guard would not write an authorisation: %w", err)
	}
	code, err := readCode(dir)
	if err != nil {
		return err
	}
	if err := client.ApplyChange(ctx, change, code); err != nil {
		return fmt.Errorf("the guard refused the code it had just written: %w", err)
	}
	return nil
}

// mustChange turns the tool's arguments into the guard's own Change.
//
// It builds guard.Change rather than a shape of its own, for the same reason
// this whole tool goes through guard.SocketClient: the vocabulary under test has
// to be production's. An arch rule already forbids regtest tooling from building
// the wire protocol itself.
func mustChange(args []string) guard.Change {
	if len(args) < 2 {
		fail(fmt.Errorf("usage: authorise|apply <control> <sats|on|off> [code]"))
	}
	change := guard.Change{Control: guard.Control(args[0])}
	switch args[1] {
	case "on":
		change.On = true
	case "off":
		change.On = false
	default:
		// SATS IN, MSAT OUT, matching the page: a script that typed msat here
		// while the operator types sats there would be exercising a different
		// number from the one a person can set.
		sats, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			fail(fmt.Errorf("%q is neither on, off nor a number of sats", args[1]))
		}
		change.Msat = sats * 1000
	}
	return change
}

// readCode lifts the code out of the file the guard wrote for the operator.
func readCode(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, guard.AuthorisationFile))
	if err != nil {
		return "", fmt.Errorf("the operator has nothing to read: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if _, code, ok := strings.Cut(line, guard.AuthorisationCodeLine); ok {
			return strings.TrimSpace(code), nil
		}
	}
	return "", fmt.Errorf("no %q line in the authorisation file", guard.AuthorisationCodeLine)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
