// mactool adds a first-party caveat to a macaroon, or lists the ones it
// carries.
//
// It exists for a caveat lncli cannot add: bakemacaroon and constrainmacaroon
// offer --ip_address and --custom_caveat_name, and nothing for
// "iprange <cidr>" — which spec §6 names as the fallback when a static
// container address cannot be obtained. A fallback that ships untested is a
// fallback nobody has run.
//
// It does the work through internal/lnd's own AddCaveats and Caveats — the
// same functions the guard bakes and verifies real credentials with — rather
// than through gopkg.in/macaroon directly. That is the point: a script proving
// the caveat binds should exercise the encoder that ships it, or a defect in
// production's path is exactly what it cannot catch.
//
// Reads a hex macaroon on stdin. Four modes:
//
//	mactool '<caveat>'      add it; writes a hex macaroon
//	mactool -caveats        list the conditions, one per line
//	mactool -require <name> exit non-zero unless that CONDITION is present
//	mactool -value <name>   print that condition's ARGUMENT
//
// The last two are separate because production's own checks are separate, and
// the split is the interesting part: lnd.RequireCaveats matches condition NAMES
// — "does this carry an ipaddr at all" — while lnd.CaveatValue is what reads the
// address it is locked TO. A credential carrying `ipaddr` bound to the wrong
// container satisfies the first and is refused by the node, which is exactly the
// failure §11's post-bake verification exists to prevent. Both are the guard's
// own functions, so a defect in either is a defect this finds.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/davotoula/brollyzapper/internal/lnd"
)

func main() {
	list := flag.Bool("caveats", false, "print the macaroon's caveats instead of adding one")
	require := flag.String("require", "", "exit non-zero unless this condition is present")
	value := flag.String("value", "", "print this condition's argument")
	flag.Parse()

	raw, err := readHex()
	if err != nil {
		fail(err)
	}

	if *list {
		caveats, err := lnd.Caveats(raw)
		if err != nil {
			fail(err)
		}
		for _, caveat := range caveats {
			fmt.Println(caveat)
		}
		return
	}

	if *require != "" {
		if err := lnd.RequireCaveats(raw, []string{*require}); err != nil {
			fail(err)
		}
		return
	}

	if *value != "" {
		got, ok := lnd.CaveatValue(raw, *value)
		if !ok {
			fail(fmt.Errorf("the macaroon carries no %q caveat", *value))
		}
		fmt.Println(got)
		return
	}

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr,
			"usage: mactool '<caveat>' | mactool -caveats | mactool -require <name> |"+
				" mactool -value <name>   (hex macaroon on stdin)")
		os.Exit(2)
	}
	out, err := lnd.AddCaveats(raw, []string{flag.Arg(0)})
	if err != nil {
		fail(err)
	}
	fmt.Println(hex.EncodeToString(out))
}

func readHex() ([]byte, error) {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(in)))
	if err != nil {
		return nil, fmt.Errorf("the input is not hex: %w", err)
	}
	return raw, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
