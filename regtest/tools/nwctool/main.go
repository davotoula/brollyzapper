// nwctool is a NIP-47 client for the regtest stack: it sends one request to the
// wallet service and prints what comes back.
//
// A SEPARATE module, like zaptool and for the same reason: it needs go-nostr's
// nip04/nip44 packages directly, and main-module regtest tooling is kept free of
// third-party imports by an arch rule (a tool's dependency enters go.mod and
// make vuln's reachable set for something neither binary ships).
//
// It speaks the protocol rather than calling our code, which is the point: a
// client that shared our codec would prove the two halves agree with each other
// rather than with NIP-47.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
)

func main() {
	relayURL := flag.String("relay", "ws://relay:7777", "the connection's relay")
	servicePubkey := flag.String("service", "", "the connection's service pubkey")
	secret := flag.String("secret", "", "the client secret (a private key, hex)")
	method := flag.String("method", "get_balance", "the NIP-47 method")
	params := flag.String("params", "{}", "the method's params, JSON")
	scheme := flag.String("encryption", "nip44_v2", "nip44_v2 or nip04")
	// Deliberately settable: the stack asserts that a stale request is refused
	// and that a REPLAYED one returns the cached answer, and both need control
	// over what goes on the wire.
	age := flag.Duration("age", 0, "backdate created_at by this much")
	save := flag.String("save", "", "write the signed request event here, for a later -resend")
	resend := flag.String("resend", "", "publish a saved event VERBATIM (a true replay)")
	timeout := flag.Duration("timeout", 20*time.Second, "how long to wait for a response")
	genkey := flag.Bool("genkey", false, "print one fresh keypair as \"<privkey> <pubkey>\" and exit")
	flag.Parse()

	// Here rather than in a second tool, and that is not just tidiness: a
	// key-printer in the MAIN module had to reach a private key out of
	// internal/nostr.Identity, which holds it as a secret.String precisely so
	// that nothing can. This module already has go-nostr, so it mints one
	// without that escape hatch existing at all.
	if *genkey {
		sk := nostr.GeneratePrivateKey()
		pk, err := nostr.GetPublicKey(sk)
		if err != nil {
			fail(err)
		}
		fmt.Printf("%s %s\n", sk, pk)
		return
	}

	if *servicePubkey == "" || *secret == "" {
		fail(fmt.Errorf("both -service and -secret are required"))
	}
	clientPubkey, err := nostr.GetPublicKey(*secret)
	if err != nil {
		fail(err)
	}

	body, err := json.Marshal(map[string]any{
		"method": *method,
		"params": json.RawMessage(*params),
	})
	if err != nil {
		fail(err)
	}
	sealed, err := seal(*scheme, *secret, *servicePubkey, string(body))
	if err != nil {
		fail(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	relay, err := nostr.RelayConnect(ctx, *relayURL)
	if err != nil {
		fail(fmt.Errorf("connecting to %s: %w", *relayURL, err))
	}
	defer relay.Close()

	request := nostr.Event{
		Kind:      23194,
		PubKey:    clientPubkey,
		CreatedAt: nostr.Timestamp(time.Now().Add(-*age).Unix()),
		Content:   sealed,
		Tags: nostr.Tags{
			{"p", *servicePubkey},
			{"encryption", *scheme},
		},
	}
	if err := request.Sign(*secret); err != nil {
		fail(err)
	}
	if *resend != "" {
		// A REPLAY is the same event, byte for byte — which is what a relay
		// re-delivering one actually produces, and what the service's durable
		// cache keys on. Re-encrypting would make new ciphertext, a new id and a
		// new signature: a different request that merely asks the same thing.
		// (Overwriting just the id was the first attempt, and the relay rejected
		// it as "bad event id", correctly.)
		raw, err := os.ReadFile(*resend)
		if err != nil {
			fail(err)
		}
		request = nostr.Event{}
		if err := json.Unmarshal(raw, &request); err != nil {
			fail(fmt.Errorf("reading the saved event: %w", err))
		}
	}
	if *save != "" {
		raw, err := json.Marshal(request)
		if err != nil {
			fail(err)
		}
		if err := os.WriteFile(*save, raw, 0o600); err != nil {
			fail(err)
		}
	}

	// Subscribed BEFORE publishing, or the response can arrive first and be
	// missed — which would read as "no answer" and fail the wrong assertion.
	since := nostr.Timestamp(time.Now().Add(-time.Minute).Unix())
	sub, err := relay.Subscribe(ctx, nostr.Filters{{
		Kinds: []int{23195},
		Tags:  nostr.TagMap{"p": []string{clientPubkey}},
		Since: &since,
	}})
	if err != nil {
		fail(err)
	}
	defer sub.Unsub()

	if err := relay.Publish(ctx, request); err != nil {
		fail(fmt.Errorf("publishing the request: %w", err))
	}
	fmt.Fprintf(os.Stderr, "request id %s\n", request.ID)

	for {
		select {
		case event := <-sub.Events:
			if event == nil {
				continue
			}
			if e := event.Tags.GetFirst([]string{"e"}); e == nil || e.Value() != request.ID {
				continue // someone else's answer
			}
			tag := event.Tags.GetFirst([]string{"encryption"})
			replyScheme := "nip04"
			if tag != nil && tag.Value() != "" {
				replyScheme = tag.Value()
			}
			plaintext, err := open(replyScheme, *secret, *servicePubkey, event.Content)
			if err != nil {
				fail(fmt.Errorf("reading the response: %w", err))
			}
			fmt.Println(plaintext)
			return
		case <-ctx.Done():
			fail(fmt.Errorf("no response within %s", *timeout))
		}
	}
}

func seal(scheme, sk, peer, plaintext string) (string, error) {
	switch scheme {
	case "nip04":
		shared, err := nip04.ComputeSharedSecret(peer, sk)
		if err != nil {
			return "", err
		}
		return nip04.Encrypt(plaintext, shared)
	case "nip44_v2":
		key, err := nip44.GenerateConversationKey(peer, sk)
		if err != nil {
			return "", err
		}
		return nip44.Encrypt(plaintext, key)
	default:
		return "", fmt.Errorf("unsupported scheme %q", scheme)
	}
}

func open(scheme, sk, peer, ciphertext string) (string, error) {
	switch scheme {
	case "nip04":
		shared, err := nip04.ComputeSharedSecret(peer, sk)
		if err != nil {
			return "", err
		}
		return nip04.Decrypt(ciphertext, shared)
	case "nip44_v2":
		key, err := nip44.GenerateConversationKey(peer, sk)
		if err != nil {
			return "", err
		}
		return nip44.Decrypt(ciphertext, key)
	default:
		return "", fmt.Errorf("unsupported scheme %q", scheme)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
