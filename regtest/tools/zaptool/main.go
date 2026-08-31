// zaptool signs a NIP-57 zap request and reads receipts back off a relay.
//
// It is a SEPARATE Go module on purpose. The repo's own go.mod carries a
// `replace` for a go-nostr fork (bead bym); a helper that shares that module
// would couple this stack's tooling to that work and vice versa. Nothing here
// is production code — it exists so the stack can assert a kind-9735 ARRIVED
// rather than that a publish returned no error.
//
// It stays on UPSTREAM go-nostr rather than the repo's pinned fork so that a
// change to the fork cannot quietly change what this tool sees. That is worth
// having, but it is NOT criterion 10's independence and must not be read as it:
// this tool is written in this repo, by the same author, against the same
// upstream project — a different BUILD, not a different implementation. The
// independent check is nak, in client-check.sh. `verify` here is the
// no-extra-dependency sanity check that lets e2e.sh assert a receipt is
// well-formed without requiring nak on PATH.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage:\n" +
			"  zaptool request <relay> <recipient-pubkey> <amount-msat> [-e <id>] [-a <coord>] [-k <kind>] [-content <text>]\n" +
			"  zaptool receipts <relay> <seconds> [-wait]\n" +
			"  zaptool verify            # a receipt event as JSON on stdin")
	}
	switch os.Args[1] {
	case "request":
		request(os.Args[2:])
	case "receipts":
		receipts(os.Args[2:])
	case "verify":
		verify()
	default:
		fail("unknown command %q", os.Args[1])
	}
}

// request prints a signed kind-9734 as compact JSON, ready to be handed to the
// LNURL callback's `nostr=` parameter.
//
// With neither -e nor -a it is a PROFILE zap, which is the shape §7 says the
// prior art nil-derefs on: p and nothing else to hang the receipt off.
func request(argv []string) {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	event := fs.String("e", "", "an e tag: the event id being zapped")
	addr := fs.String("a", "", "an a tag: the addressable event coordinate being zapped")
	kind := fs.String("k", "", "a k tag: the stringified kind of the target event (NIP-57 Appendix A)")
	content := fs.String("content", "regtest zap", "the zap request's content")
	// Positional args come first so the call reads like the LNURL parameters do.
	if len(argv) < 3 {
		fail("request needs <relay> <recipient-pubkey> <amount-msat>")
	}
	relay, recipient, amountMsat := argv[0], argv[1], argv[2]
	if err := fs.Parse(argv[3:]); err != nil {
		fail("%v", err)
	}

	sk := nostr.GeneratePrivateKey()
	pk, err := nostr.GetPublicKey(sk)
	must(err)
	tags := nostr.Tags{
		// NIP-57: ONE relays tag carrying many values, not many tags.
		append(nostr.Tag{"relays"}, strings.Split(relay, ",")...),
		nostr.Tag{"amount", amountMsat},
		nostr.Tag{"p", recipient},
	}
	if *event != "" {
		tags = append(tags, nostr.Tag{"e", *event})
	}
	if *addr != "" {
		tags = append(tags, nostr.Tag{"a", *addr})
	}
	if *kind != "" {
		tags = append(tags, nostr.Tag{"k", *kind})
	}
	ev := nostr.Event{
		Kind:      nostr.KindZapRequest,
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Content:   *content,
		Tags:      tags,
	}
	must(ev.Sign(sk))
	out, err := json.Marshal(ev)
	must(err)
	fmt.Println(string(out))
}

// receipts prints every kind-9735 the relay has stored, as JSON, and returns.
//
// It returns on END OF STORED EVENTS, not on the timeout. The relay hands over
// everything it holds in about 20ms and then says so; waiting out the window
// after that is dead time, and it was the single largest cost in the suite —
// measured at ~63s of a ~140s e2e.sh run, because six poll sites each burned a
// full 6-10s window whether or not the receipt was already there.
//
// The seconds argument is now an upper BOUND rather than a duration: it is what
// stops a relay that never answers from hanging the run. Waiting for a receipt
// that has not been published yet is the CALLER's job, by asking again — which
// is where that policy belongs, because only the caller knows how long the thing
// it is waiting for should take.
//
// -wait keeps the old behaviour, listening for the whole window, for the case
// where the point is to observe events arriving rather than to read what is
// already stored.
func receipts(argv []string) {
	fs := flag.NewFlagSet("receipts", flag.ExitOnError)
	wait := fs.Bool("wait", false, "listen for the whole window instead of returning at end-of-stored-events")
	if len(argv) < 2 {
		fail("receipts needs <relay> <seconds>")
	}
	relayURL, seconds := argv[0], argv[1]
	if err := fs.Parse(argv[2:]); err != nil {
		fail("%v", err)
	}
	secs, err := strconv.Atoi(seconds)
	must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()

	r, err := nostr.RelayConnect(ctx, relayURL)
	must(err)
	since := nostr.Timestamp(time.Now().Add(-60 * time.Minute).Unix())
	sub, err := r.Subscribe(ctx, nostr.Filters{{
		Kinds: []int{nostr.KindZap},
		Since: &since,
	}})
	must(err)

	for {
		select {
		case ev, ok := <-sub.Events:
			if !ok {
				return
			}
			out, _ := json.Marshal(ev)
			fmt.Println(string(out))
		case <-sub.EndOfStoredEvents:
			if !*wait {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// verify re-derives a receipt's id and checks its signature.
//
// §16's failure is a receipt that is internally consistent to its author and
// discarded by every conforming client. CheckSignature RE-COMPUTES the id from
// the serialised event, so a receipt whose id field disagrees with its own
// content fails here exactly as it would in a client — Wave 8 found that defect
// pointing the other way, in the zap REQUEST path.
//
// This is the cheap check e2e.sh can make on every receipt. Criterion 10's
// claim — that a real, independently-written client accepts it — is nak's, in
// client-check.sh.
func verify() {
	var ev nostr.Event
	if err := json.NewDecoder(os.Stdin).Decode(&ev); err != nil {
		fail("reading the event: %v", err)
	}
	derived := ev.GetID()
	idOK := derived == ev.ID
	sigOK, err := ev.CheckSignature()
	if err != nil {
		sigOK = false
	}
	out, _ := json.Marshal(map[string]any{
		"id":         ev.ID,
		"derived_id": derived,
		"id_ok":      idOK,
		"sig_ok":     sigOK,
		"kind":       ev.Kind,
		"pubkey":     ev.PubKey,
		"created_at": ev.CreatedAt,
		"tag_names":  tagNames(ev.Tags),
	})
	fmt.Println(string(out))
	if !idOK || !sigOK {
		os.Exit(1)
	}
}

// tagNames is every tag's first element, in order, so a caller can assert on
// the SHAPE of a receipt (which tags, and which absent) without re-parsing.
func tagNames(tags nostr.Tags) []string {
	names := make([]string, 0, len(tags))
	for _, t := range tags {
		if len(t) > 0 {
			names = append(names, t[0])
		}
	}
	return names
}

func must(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "zaptool: "+f+"\n", a...)
	os.Exit(1)
}
