package lnurl_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/davotoula/brollyzapper/internal/lnurl"
	"github.com/davotoula/brollyzapper/internal/lnurl/lnurltest"
)

const amount = 21_000

// §7 Appendix D, one case per rule, and every rejection names the rule it
// broke — the caller is a stranger's wallet whose author needs to know which.
func TestZapRequestValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		// mutate is applied to a valid request before it is signed.
		mutate func(*gonostr.Event)
		// unsigned replaces the whole body, for cases about the bytes.
		unsigned string
		// wantReason is a fragment the refusal must contain, naming the rule.
		wantReason string
	}{
		{name: "a valid zap request", mutate: func(*gonostr.Event) {}},
		{
			name:       "a PROFILE zap has no e tag at all",
			mutate:     func(e *gonostr.Event) { e.Tags = lnurltest.WithoutTag(e.Tags, "e") },
			wantReason: "",
		},
		{
			name:       "an amount tag that matches",
			mutate:     func(e *gonostr.Event) { e.Tags = append(e.Tags, gonostr.Tag{"amount", "21000"}) },
			wantReason: "",
		},
		{
			name: "an optional a tag that is a valid coordinate",
			mutate: func(e *gonostr.Event) {
				e.Tags = append(e.Tags, gonostr.Tag{"a", "30023:" + lnurltest.Hex64('b') + ":slug"})
			},
			wantReason: "",
		},
		{
			name:       "an optional P tag",
			mutate:     func(e *gonostr.Event) { e.Tags = append(e.Tags, gonostr.Tag{"P", lnurltest.Hex64('c')}) },
			wantReason: "",
		},

		{name: "not JSON at all", unsigned: "{not json", wantReason: "not a JSON event"},
		{name: "an empty parameter", unsigned: " ", wantReason: "not a JSON event"},
		{
			name:       "the wrong kind",
			mutate:     func(e *gonostr.Event) { e.Kind = 1 },
			wantReason: "kind 9734",
		},
		{
			name:       "no p tag",
			mutate:     func(e *gonostr.Event) { e.Tags = lnurltest.WithoutTag(e.Tags, "p") },
			wantReason: "exactly one p tag",
		},
		{
			name:       "two p tags",
			mutate:     func(e *gonostr.Event) { e.Tags = append(e.Tags, gonostr.Tag{"p", lnurltest.Hex64('d')}) },
			wantReason: "exactly one p tag",
		},
		{
			name:       "a p tag that is not a pubkey",
			mutate:     func(e *gonostr.Event) { e.Tags = replaceTag(e.Tags, "p", "nope") },
			wantReason: "not a 32-byte hex pubkey",
		},
		{
			name:       "two e tags",
			mutate:     func(e *gonostr.Event) { e.Tags = append(e.Tags, gonostr.Tag{"e", lnurltest.Hex64('e')}) },
			wantReason: "at most one e tag",
		},
		{
			name:       "an e tag that is not an event id",
			mutate:     func(e *gonostr.Event) { e.Tags = replaceTag(e.Tags, "e", "nope") },
			wantReason: "not a 32-byte hex event id",
		},
		{
			name:       "no relays tag",
			mutate:     func(e *gonostr.Event) { e.Tags = lnurltest.WithoutTag(e.Tags, "relays") },
			wantReason: "must carry a relays tag",
		},
		{
			name:       "an amount tag that disagrees with the request",
			mutate:     func(e *gonostr.Event) { e.Tags = append(e.Tags, gonostr.Tag{"amount", "9000"}) },
			wantReason: "amount tag says 9000",
		},
		{
			name:       "an amount tag that is not a number",
			mutate:     func(e *gonostr.Event) { e.Tags = append(e.Tags, gonostr.Tag{"amount", "lots"}) },
			wantReason: "not a number of millisatoshis",
		},
		{
			name: "two a tags",
			mutate: func(e *gonostr.Event) {
				e.Tags = append(e.Tags,
					gonostr.Tag{"a", "30023:" + lnurltest.Hex64('b') + ":one"},
					gonostr.Tag{"a", "30023:" + lnurltest.Hex64('b') + ":two"})
			},
			wantReason: "at most one a tag",
		},
		// zu5.1: validCoordinate's rejection arms, one case each. Every one of
		// these was untested — only the "too few parts" arm above had a case,
		// so three quarters of the function could be deleted without the suite
		// noticing. A coordinate is copied into a PUBLIC receipt verbatim (§7),
		// which is why it is held to the same standard as the k tag.
		{
			name:       "an a tag that is not a coordinate",
			mutate:     func(e *gonostr.Event) { e.Tags = append(e.Tags, gonostr.Tag{"a", "30023:nope"}) },
			wantReason: "not a valid event coordinate",
		},
		{
			name: "an a tag with a fourth part",
			mutate: func(e *gonostr.Event) {
				e.Tags = append(e.Tags, gonostr.Tag{"a", "30023:" + lnurltest.Hex64('b') + ":slug:extra"})
			},
			wantReason: "not a valid event coordinate",
		},
		{
			// The kind inside a coordinate goes through validKind, so "01" and
			// "1" cannot be two spellings of one coordinate. Clients compare
			// these as whole strings.
			name: "an a tag whose kind is not canonical",
			mutate: func(e *gonostr.Event) {
				e.Tags = append(e.Tags, gonostr.Tag{"a", "01:" + lnurltest.Hex64('b') + ":slug"})
			},
			wantReason: "not a valid event coordinate",
		},
		{
			name: "an a tag whose kind is negative",
			mutate: func(e *gonostr.Event) {
				e.Tags = append(e.Tags, gonostr.Tag{"a", "-1:" + lnurltest.Hex64('b') + ":slug"})
			},
			wantReason: "not a valid event coordinate",
		},
		{
			name: "an a tag whose pubkey is the wrong length",
			mutate: func(e *gonostr.Event) {
				e.Tags = append(e.Tags, gonostr.Tag{"a", "30023:abcdef:slug"})
			},
			wantReason: "not a valid event coordinate",
		},
		{
			// Right length, wrong alphabet — the arm the length check cannot
			// reach.
			name: "an a tag whose pubkey is 64 characters of non-hex",
			mutate: func(e *gonostr.Event) {
				e.Tags = append(e.Tags, gonostr.Tag{"a", "30023:" + strings.Repeat("z", 64) + ":slug"})
			},
			wantReason: "not a valid event coordinate",
		},
		{
			name: "two k tags",
			mutate: func(e *gonostr.Event) {
				e.Tags = append(e.Tags, gonostr.Tag{"k", "1"}, gonostr.Tag{"k", "30023"})
			},
			wantReason: "at most one k tag",
		},
		{
			name:       "a k tag that is not a kind",
			mutate:     func(e *gonostr.Event) { e.Tags = append(e.Tags, gonostr.Tag{"k", "note"}) },
			wantReason: "not a nostr event kind",
		},
		{
			name:       "a k tag with a leading zero, which is a second spelling of one kind",
			mutate:     func(e *gonostr.Event) { e.Tags = append(e.Tags, gonostr.Tag{"k", "01"}) },
			wantReason: "not a nostr event kind",
		},
		{
			name:       "a negative k tag",
			mutate:     func(e *gonostr.Event) { e.Tags = append(e.Tags, gonostr.Tag{"k", "-1"}) },
			wantReason: "not a nostr event kind",
		},
		{
			name: "two P tags",
			mutate: func(e *gonostr.Event) {
				e.Tags = append(e.Tags, gonostr.Tag{"P", lnurltest.Hex64('c')}, gonostr.Tag{"P", lnurltest.Hex64('d')})
			},
			wantReason: "at most one P tag",
		},
		// zu5.3 / coverage analysis §3.3: the rejection arms that had no case.
		{
			name: "a P tag that is not a pubkey",
			mutate: func(e *gonostr.Event) {
				e.Tags = append(e.Tags, gonostr.Tag{"P", "not-a-pubkey"})
			},
			wantReason: "the P tag is not a 32-byte hex pubkey",
		},
		{
			// Distinct from "no relays tag": the tag is present and every value
			// in it is refused, which is what a stranger naming only LAN
			// addresses produces. The request is well-formed and there is still
			// nowhere to publish a receipt.
			name: "a relays tag naming only relays this node will not dial",
			mutate: func(e *gonostr.Event) {
				e.Tags = append(lnurltest.WithoutTag(e.Tags, "relays"),
					gonostr.Tag{"relays", "ws://192.168.77.1:4444", "ws://localhost:7777", "nonsense"})
			},
			wantReason: "names no usable websocket relay",
		},
		{
			// A zero-length tag is SKIPPED, not refused — the branch is a
			// continue. Asserted as an acceptance so that a future "reject it"
			// would show up here rather than as a stranger's zap silently
			// failing on a tag no spec forbids.
			name: "a zero-length tag alongside the real ones",
			mutate: func(e *gonostr.Event) {
				e.Tags = append(e.Tags, gonostr.Tag{})
			},
			wantReason: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(tc.unsigned)
			if tc.unsigned == "" {
				raw = lnurltest.SignedZapRequest(t, tc.mutate)
			}
			got, err := lnurl.ParseZapRequest(raw, amount)
			if tc.wantReason == "" {
				if err != nil {
					t.Fatalf("a valid request was refused: %v", err)
				}
				if string(got.Request().Raw) != string(raw) {
					t.Error("the request does not carry the bytes it arrived as")
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted a request that breaks the rule %q", tc.wantReason)
			}
			reason, ok := lnurl.AsRejection(err)
			if !ok {
				t.Fatalf("the refusal is not showable to the caller: %v", err)
			}
			if !strings.Contains(reason, tc.wantReason) {
				t.Errorf("reason = %q, want it to name the rule (%q)", reason, tc.wantReason)
			}
		})
	}
}

// §11 makes this a rule of its own: a forged request is refused BEFORE anything
// is minted, so a stranger cannot make the node do work by lying.
func TestAnInvalidSignatureIsRefused(t *testing.T) {
	raw := lnurltest.SignedZapRequest(t, func(*gonostr.Event) {})
	var event map[string]any
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	event["content"] = "tampered after signing"
	tampered, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lnurl.ParseZapRequest(tampered, amount); err == nil {
		t.Fatal("a tampered zap request was accepted")
	} else if reason, _ := lnurl.AsRejection(err); !strings.Contains(reason, "signature") {
		t.Errorf("reason = %q, want it to name the signature", reason)
	}
}

// The case the prior art gets wrong, tested by name: a profile zap carries no
// e tag and must succeed, with nothing dereferenced that is not there.
func TestAProfileZapWithNoEventTagSucceeds(t *testing.T) {
	raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) { e.Tags = lnurltest.WithoutTag(e.Tags, "e") })
	got, err := lnurl.ParseZapRequest(raw, amount)
	if err != nil {
		t.Fatalf("a profile zap was refused: %v", err)
	}
	if got.Request().EventID != "" {
		t.Errorf("EventID = %q, want empty for a profile zap", got.Request().EventID)
	}
	if got.Request().Recipient == "" {
		t.Error("the recipient was not read")
	}
	if len(got.Request().Relays) == 0 {
		t.Error("the relays tag was not read")
	}
}

// --- helpers ---------------------------------------------------------------

// The fixture builder lives in internal/lnurl/lnurltest now: three packages had
// their own, and two carried their own copy of the non-canonical guard (ohi).

func replaceTag(tags gonostr.Tags, name, value string) gonostr.Tags {
	out := lnurltest.WithoutTag(tags, name)
	return append(out, gonostr.Tag{name, value})
}

// Everything an anonymous caller controls is bounded. invoices.zap_request
// keeps the bytes verbatim and ExpireInvoices never deletes a row, so an
// unbounded parameter is permanent growth on an SD card paid for by nobody —
// and the relays tag is the list o34.3 opens websockets to.
func TestWhatAStrangerSendsIsBounded(t *testing.T) {
	t.Run("an oversized request is refused before it is parsed", func(t *testing.T) {
		raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
			e.Content = strings.Repeat("x", lnurl.MaxZapRequestBytes)
		})
		if len(raw) <= lnurl.MaxZapRequestBytes {
			t.Fatalf("the fixture is %d bytes, not over the %d-byte bound",
				len(raw), lnurl.MaxZapRequestBytes)
		}
		_, err := lnurl.ParseZapRequest(raw, amount)
		if reason, ok := lnurl.AsRejection(err); !ok || !strings.Contains(reason, "at most") {
			t.Errorf("a %d-byte request was answered with %v", len(raw), err)
		}
	})

	// 0ak: over the cap is TRUNCATED, not refused. A sender naming nine relays
	// has done nothing wrong, and answering a well-formed zap with a rejection
	// because our cap moved would turn a tightening of ours into their failed
	// payment. The cap is on sockets this node opens, so the cap is what has to
	// hold — not the request.
	t.Run("more relays than the cap are dropped, not refused", func(t *testing.T) {
		relays := gonostr.Tag{"relays"}
		for i := range lnurl.MaxZapRelays * 3 {
			relays = append(relays, fmt.Sprintf("wss://relay%d.example", i))
		}
		raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
			e.Tags = append(lnurltest.WithoutTag(e.Tags, "relays"), relays)
		})
		got, err := lnurl.ParseZapRequest(raw, amount)
		if err != nil {
			t.Fatalf("a request naming %d relays was refused: %v", len(relays)-1, err)
		}
		if kept := got.Request().Relays; len(kept) != lnurl.MaxZapRelays {
			t.Errorf("kept %d relays, want the cap of %d — this is the number of "+
				"sockets a stranger can make this node open at once",
				len(kept), lnurl.MaxZapRelays)
		}
	})

	// Padding must not be able to push the real relays out. The cap applies
	// after the scheme filter and the dedup, not to the raw tag length.
	t.Run("junk and repeats do not consume the cap", func(t *testing.T) {
		// The junk comes FIRST, and there is more of it than the cap. Capping
		// the raw tag before filtering would keep only junk, filter it all
		// away, and refuse a request that named a perfectly good relay — so
		// this ordering is what the subtest actually distinguishes.
		relays := gonostr.Tag{"relays"}
		for range lnurl.MaxZapRelays * 2 {
			relays = append(relays, "http://not-a-relay.example", "wss://dup.example")
		}
		relays = append(relays, "wss://real.example")
		raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
			e.Tags = append(lnurltest.WithoutTag(e.Tags, "relays"), relays)
		})
		got, err := lnurl.ParseZapRequest(raw, amount)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		kept := got.Request().Relays
		if len(kept) != 2 || !slices.Contains(kept, "wss://real.example") {
			t.Errorf("kept %v, want the two distinct real relays including real.example — "+
				"padding must not push a named relay past the cap", kept)
		}
	})

	t.Run("a bare relays tag names nowhere", func(t *testing.T) {
		raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
			e.Tags = append(lnurltest.WithoutTag(e.Tags, "relays"), gonostr.Tag{"relays"})
		})
		_, err := lnurl.ParseZapRequest(raw, amount)
		if err == nil {
			t.Fatal("a relays tag naming no relay satisfied the relays rule; the sender has " +
				"named nowhere to read the receipt")
		}
		if reason, _ := lnurl.AsRejection(err); !strings.Contains(reason, "at least one") {
			t.Errorf("reason = %q, want it to name the rule", reason)
		}
	})

	t.Run("only websocket relays survive", func(t *testing.T) {
		raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
			e.Tags = append(lnurltest.WithoutTag(e.Tags, "relays"),
				gonostr.Tag{"relays", "wss://good.example", "https://not-a-relay.example",
					"file:///etc/passwd", "wss://good.example/"})
		})
		got, err := lnurl.ParseZapRequest(raw, amount)
		if err != nil {
			t.Fatalf("a request with one usable relay was refused: %v", err)
		}
		if len(got.Request().Relays) != 1 {
			t.Errorf("kept %v, want only the websocket relay, deduplicated", got.Request().Relays)
		}
	})
}

// CheckSignature recomputes the id and verifies against THAT, so a valid
// signature says nothing about the id field. Those bytes are what o34.3's
// receipt carries verbatim: a client that recomputes the id and finds it wrong
// discards the receipt, after the invoice has been paid.
func TestAnEventWhoseIDDoesNotMatchIsRefused(t *testing.T) {
	raw := lnurltest.SignedZapRequest(t, func(*gonostr.Event) {})
	tampered := lnurltest.WithRewrittenID(t, raw, lnurltest.Hex64('0'))
	if _, err := lnurl.ParseZapRequest(tampered, amount); err == nil {
		t.Fatal("an event whose id does not match its contents was accepted")
	} else if reason, _ := lnurl.AsRejection(err); !strings.Contains(reason, "id") {
		t.Errorf("reason = %q, want it to name the id", reason)
	}
}

// 0ak criterion 5. A zap request names the relays this node will open
// websockets to, so the relays tag is a stranger choosing outbound connections
// — and the node is on a home LAN, next to the router's admin interface, the
// Umbrel dashboard and every other app on the box.
//
// This rule was written in Wave 8 and never re-verified. It did not hold: the
// filter checked the SCHEME and nothing else, so ws://192.168.77.1,
// ws://127.0.0.1 and ws://169.254.169.254 — the cloud metadata address — were
// all kept, while the comment beside the code said they were not. The comment
// had outrun the code, and only planting against it found that out.
//
// This is the PARSE-time refusal, so it sees literals only: a hostname that
// resolves to a private address passes here and is stopped at the pool, which
// resolves before it dials (z9k, internal/nostr/dialable_test.go). The
// allow-list itself lives in internal/nostr and has its own table test, one row
// per reserved range (zu5.1).
func TestAStrangerCannotNameALANAddressToPublishTo(t *testing.T) {
	for _, target := range []string{
		"ws://192.168.77.1:4444",  // the router, or a neighbouring app
		"ws://10.0.0.5:80",        // RFC1918
		"ws://172.17.0.1:8080",    // the docker bridge gateway
		"ws://127.0.0.1:4444",     // the box itself
		"ws://[::1]:4444",         // the box itself, v6
		"ws://169.254.169.254:80", // cloud metadata
		"ws://[fd00::1]:4444",     // unique-local v6
		"ws://localhost:4444",     // loopback by name
		"ws://0.0.0.0:4444",       // unspecified
	} {
		raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
			e.Tags = append(lnurltest.WithoutTag(e.Tags, "relays"),
				gonostr.Tag{"relays", target, "wss://real.example"})
		})
		got, err := lnurl.ParseZapRequest(raw, amount)
		if err != nil {
			t.Errorf("a request naming %s alongside a real relay was refused: %v", target, err)
			continue
		}
		for _, kept := range got.Request().Relays {
			if strings.Contains(kept, "real.example") {
				continue
			}
			t.Errorf("kept %q from %q; a stranger must not be able to make this node "+
				"open a websocket to an address on its own network", kept, target)
		}
	}
}

// The allow-list must not be so tight that ordinary relays stop working. An
// SSRF filter that blocks the product is not a filter, it is an outage.
func TestOrdinaryPublicRelaysSurviveTheFilter(t *testing.T) {
	for _, target := range []string{
		"wss://relay.damus.io", "wss://nos.lol", "wss://relay.snort.social",
		"ws://relay.example.com:7777", "wss://8.8.8.8:443",
	} {
		raw := lnurltest.SignedZapRequest(t, func(e *gonostr.Event) {
			e.Tags = append(lnurltest.WithoutTag(e.Tags, "relays"),
				gonostr.Tag{"relays", target})
		})
		got, err := lnurl.ParseZapRequest(raw, amount)
		if err != nil {
			t.Errorf("%s was refused: %v", target, err)
			continue
		}
		if len(got.Request().Relays) != 1 {
			t.Errorf("%s was filtered out; kept %v", target, got.Request().Relays)
		}
	}
}
