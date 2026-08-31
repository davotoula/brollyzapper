package nostr_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/secret"
)

// §12, and criterion 1: the private key must be unable to reach a log at any
// level, by any route someone might reasonably take while debugging.
func TestTheIdentityKeyCannotReachALog(t *testing.T) {
	id, private := knownIdentity(t)

	var buf bytes.Buffer
	log := logging.New(&buf, logging.NewLevelVar(slog.LevelDebug))
	log.Info("identity", "id", id)
	log.Debug("identity by value", "id", slog.AnyValue(id))
	log.Error("identity in a format string", "text", id.String())
	encoded, err := json.Marshal(struct {
		ID nostr.Identity `json:"id"`
	}{id})
	if err == nil {
		buf.Write(encoded)
	}

	if strings.Contains(buf.String(), private) {
		t.Fatalf("the private key reached the log:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), id.PublicKey()) {
		t.Errorf("nothing identifiable was logged at all, so the redaction proves nothing:\n%s",
			buf.String())
	}
}

// Criterion 1: an operator has the key as nsec or as hex, so both are accepted
// and both produce the same identity.
func TestAKeyIsAcceptedAsNsecOrHex(t *testing.T) {
	generated, hexKey := knownIdentity(t)
	nsec, err := nip19.EncodePrivateKey(hexKey)
	if err != nil {
		t.Fatalf("EncodePrivateKey: %v", err)
	}

	for name, raw := range map[string]string{"hex": hexKey, "nsec": nsec} {
		t.Run(name, func(t *testing.T) {
			id, err := nostr.Parse(secret.New(raw))
			if err != nil {
				t.Fatalf("Parse(%s): %v", name, err)
			}
			if id.PublicKey() != generated.PublicKey() {
				t.Errorf("pubkey = %s, want %s", id.PublicKey(), generated.PublicKey())
			}
		})
	}

	// A PUBLIC key where a private one belongs — the operator pasting their npub
	// into the nsec box. Encoded from the test's own identity rather than
	// written down: a literal npub is somebody's, and a real person's key in a
	// rejection table reads as an association nobody intended.
	npub, err := nip19.EncodePublicKey(generated.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"empty":        "",
		"short hex":    "abcd",
		"not hex":      strings.Repeat("z", 64),
		"npub":         npub,
		"nonsense":     "nsec1notrealatall",
		"hex too long": strings.Repeat("a", 65),
	} {
		if _, err := nostr.Parse(secret.New(raw)); err == nil {
			t.Errorf("Parse(%s) accepted %q", name, raw)
		}
	}
}

// Criterion 2. The domain self-prober reads server_nostr_pubkey and nothing
// wrote it, so no configured domain could probe green. Generating the identity
// is what writes it.
func TestGeneratingTheIdentityWritesThePubkeyTheProberReads(t *testing.T) {
	settings := newSettings()
	id, err := nostr.LoadOrCreate(t.Context(), settings)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	stored, ok, _ := settings.Setting(t.Context(), nostr.SettingPublicKey)
	if !ok || stored != id.PublicKey() {
		t.Fatalf("server_nostr_pubkey = %q (present %v), want %q", stored, ok, id.PublicKey())
	}

	// And a second start reuses the key rather than minting a new identity —
	// the announced nostrPubkey must not change under the sender's feet.
	again, err := nostr.LoadOrCreate(t.Context(), settings)
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if again.PublicKey() != id.PublicKey() {
		t.Errorf("restart changed the identity from %s to %s", id.PublicKey(), again.PublicKey())
	}
}

// A stored private key whose pubkey row has drifted — hand-edited, or written
// by an older build — must be corrected, not believed. Announcing one identity
// and signing with another makes every receipt unverifiable.
func TestAStoredKeyRewritesTheDerivedPubkey(t *testing.T) {
	settings := newSettings()
	id, err := nostr.LoadOrCreate(t.Context(), settings)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if err := settings.SetSetting(t.Context(), nostr.SettingPublicKey, "deadbeef"); err != nil {
		t.Fatal(err)
	}
	if _, err := nostr.LoadOrCreate(t.Context(), settings); err != nil {
		t.Fatalf("LoadOrCreate over a drifted pubkey: %v", err)
	}
	stored, _, _ := settings.Setting(t.Context(), nostr.SettingPublicKey)
	if stored != id.PublicKey() {
		t.Errorf("pubkey row = %q, want it corrected to %q", stored, id.PublicKey())
	}
}

// Criterion 1: import replaces the identity, and writes the derived pubkey too.
func TestImportReplacesTheIdentityAndItsPubkey(t *testing.T) {
	settings := newSettings()
	if _, err := nostr.LoadOrCreate(t.Context(), settings); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	incoming, incomingKey := knownIdentity(t)
	imported, err := nostr.Import(t.Context(), settings, secret.New(incomingKey))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if imported.PublicKey() != incoming.PublicKey() {
		t.Errorf("imported pubkey = %s, want %s", imported.PublicKey(), incoming.PublicKey())
	}
	stored, _, _ := settings.Setting(t.Context(), nostr.SettingPublicKey)
	if stored != incoming.PublicKey() {
		t.Errorf("server_nostr_pubkey = %q, want %q", stored, incoming.PublicKey())
	}
	// A refused import must leave the working identity alone.
	if _, err := nostr.Import(t.Context(), settings, secret.New("not-a-key")); err == nil {
		t.Fatal("Import accepted a key that is not one")
	}
	stored, _, _ = settings.Setting(t.Context(), nostr.SettingPublicKey)
	if stored != incoming.PublicKey() {
		t.Errorf("a refused import changed the identity to %q", stored)
	}
}

// Criterion 5: go-nostr signs; we do not. This asserts the signature it
// produces verifies, which is what proves we are using the library rather than
// approximating it.
func TestSigningProducesAVerifiableEvent(t *testing.T) {
	id, err := nostr.Generate()
	if err != nil {
		t.Fatal(err)
	}
	event := &gonostr.Event{
		Kind:      9735,
		CreatedAt: gonostr.Timestamp(1_700_000_000),
		Tags:      gonostr.Tags{{"p", strings.Repeat("a", 64)}},
	}
	if err := id.Sign(event); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if event.PubKey != id.PublicKey() {
		t.Errorf("event pubkey = %s, want the server identity %s", event.PubKey, id.PublicKey())
	}
	ok, err := event.CheckSignature()
	if err != nil || !ok {
		t.Errorf("CheckSignature = %v, %v; want a valid signature", ok, err)
	}
	if !event.CheckID() {
		t.Error("the event id does not match its serialisation")
	}

	// And an empty identity refuses rather than signing with nothing.
	if err := (nostr.Identity{}).Sign(&gonostr.Event{}); err == nil {
		t.Error("an absent identity signed an event")
	}
}

// Criterion 4: the relay list comes from settings and falls back to the
// decided default; an unusable entry is dropped rather than dialled.
func TestRelaysComeFromSettingsAndFallBackToTheDefault(t *testing.T) {
	if got := nostr.ParseRelays("  "); len(got) != len(nostr.DefaultRelays) {
		t.Errorf("an empty setting gave %v, want the default set", got)
	}
	// A relay is a websocket. Anything else — a bare word, an https URL pasted
	// from a browser — is dropped rather than dialled, because a receipt sent
	// nowhere is the silent failure §7 names.
	got := nostr.ParseRelays("wss://one.example, ws://two.example\nnot a url\nhttps://three.example")
	want := []string{"wss://one.example", "ws://two.example"}
	if len(got) != len(want) {
		t.Fatalf("ParseRelays = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ParseRelays[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// Criterion 4 again, and the reason it is a criterion: a relay that refuses is
// a silent failure unless the caller is told WHICH one. o34.3's 24-hour retry
// depends on it.
func TestPublishReportsEveryRelaySeparately(t *testing.T) {
	// Two addresses that cannot accept anything: the results must name both,
	// and both must carry an error rather than one bool for the batch.
	pool := nostr.NewPool(t.Context(), func() []string {
		return []string{"wss://127.0.0.1:1", "wss://127.0.0.1:2"}
	}, nostr.Options{})
	defer pool.Close()

	results := pool.Publish(t.Context(), signedNote(t))
	if len(results) != 2 {
		t.Fatalf("got %d results for 2 relays: %+v", len(results), results)
	}
	named := map[string]bool{}
	for _, r := range results {
		named[r.Relay] = true
		if r.OK() {
			t.Errorf("%s reported success against a closed port", r.Relay)
		}
	}
	if len(named) != 2 {
		t.Errorf("the results do not name both relays: %+v", results)
	}
	if got := nostr.Accepted(results); got != 0 {
		t.Errorf("Accepted = %d, want 0", got)
	}
}

// --- helpers ---------------------------------------------------------------

// knownIdentity builds an identity from a key the TEST holds, which is how
// these assertions get at the private half at all: Identity deliberately offers
// no way out, and adding one for tests would be the "test-only method on a
// production type" this repo has already been bitten by.
func knownIdentity(t *testing.T) (nostr.Identity, string) {
	t.Helper()
	key := gonostr.GeneratePrivateKey()
	id, err := nostr.Parse(secret.New(key))
	if err != nil {
		t.Fatalf("Parse a freshly generated key: %v", err)
	}
	return id, key
}

func newSettings() *settingsStub {
	return &settingsStub{values: map[string]string{}}
}

type settingsStub struct {
	mu     sync.Mutex
	values map[string]string
}

func (s *settingsStub) Setting(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[key]
	return v, ok, nil
}

func (s *settingsStub) SetSetting(_ context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = value
	return nil
}

// GetPublicKey does not range-check the scalar: zero and the curve order both
// yield a pubkey of sixty-four zeros and fail only at signing time. Accepting
// one would announce allowsNostr with that pubkey, take every zap, and fail to
// sign every receipt — invisible until money had already moved.
func TestAKeyThatCannotSignIsNotAnIdentity(t *testing.T) {
	for name, key := range map[string]string{
		"zero":        strings.Repeat("0", 64),
		"curve order": "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
	} {
		t.Run(name, func(t *testing.T) {
			id, err := nostr.Parse(secret.New(key))
			if err == nil {
				t.Fatalf("accepted a %s key; it announces pubkey %q and signs nothing",
					name, id.PublicKey())
			}
			if strings.Contains(err.Error(), key) {
				t.Errorf("the refusal quotes the key: %v", err)
			}
		})
	}
}

// Publishing with nowhere to publish to is a distinguishable result, not a
// silent nil: o34.3 must tell "nobody took it" from "there was nowhere to send".
func TestPublishingWithNoRelaysSaysSo(t *testing.T) {
	pool := nostr.NewPool(t.Context(), func() []string { return nil }, nostr.Options{})
	defer pool.Close()
	id, err := nostr.Generate()
	if err != nil {
		t.Fatal(err)
	}
	event := &gonostr.Event{Kind: 1}
	if err := id.Sign(event); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	results := pool.Publish(t.Context(), *event)
	if len(results) != 1 || !errors.Is(results[0].Err, nostr.ErrNoRelays) {
		t.Errorf("results = %+v, want one result naming ErrNoRelays", results)
	}
	if nostr.Accepted(results) != 0 {
		t.Error("Accepted counted a publish that went nowhere")
	}
}
