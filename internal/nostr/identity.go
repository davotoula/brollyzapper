package nostr

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/davotoula/brollyzapper/internal/secret"
)

// Settings keys this package owns (spec §4).
//
// Declared here rather than in internal/api for the same reason the fee keys
// live in internal/wallet: the package that computes with a value owns the name
// of the row it comes from, so "saves" and "reads back" cannot become two
// different strings.
const (
	SettingPrivateKey = "server_nostr_privkey"
	SettingPublicKey  = "server_nostr_pubkey"
)

// ErrNoIdentity is returned when the server has no nostr key yet. It is a state
// the admin UI shows, never a reason to exit (§11).
var ErrNoIdentity = errors.New("nostr: the server has no identity key")

// Identity is the server's nostr key: the one announced as nostrPubkey in the
// LNURL response and the one that signs zap receipts (§7).
//
// The private half is secret.String end to end. §4 stores it in plaintext and
// says why; §12 requires that it be unable to serialise itself into a log line
// whatever anyone does with it, which is what the type and LogValue below give.
type Identity struct {
	private secret.String
	public  string
}

// Generate mints a new identity.
func Generate() (Identity, error) {
	return newIdentity(secret.New(gonostr.GeneratePrivateKey()))
}

// Parse accepts a private key as bech32 `nsec1…` or as 64 hex characters, which
// are the two forms an operator will have to hand.
func Parse(raw secret.String) (Identity, error) {
	value := strings.TrimSpace(raw.Reveal())
	if value == "" {
		return Identity{}, ErrNoIdentity
	}
	if strings.HasPrefix(value, "nsec1") {
		prefix, decoded, err := nip19.Decode(value)
		if err != nil {
			return Identity{}, fmt.Errorf("nostr: that is not a valid nsec: %w", err)
		}
		key, ok := decoded.(string)
		if prefix != "nsec" || !ok {
			return Identity{}, errors.New("nostr: that bech32 string is not a private key")
		}
		return newIdentity(secret.New(key))
	}
	if len(value) != 64 {
		return Identity{}, errors.New("nostr: a private key is 64 hex characters or an nsec1… string")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return Identity{}, errors.New("nostr: a private key is 64 hex characters or an nsec1… string")
	}
	return newIdentity(secret.New(value))
}

func newIdentity(private secret.String) (Identity, error) {
	public, err := gonostr.GetPublicKey(private.Reveal())
	if err != nil {
		// Deliberately not wrapped: go-nostr's error can quote the key it was
		// handed, and §12's rule is that the key cannot reach a log at all.
		return Identity{}, errUnusableKey
	}
	identity := Identity{private: private, public: public}
	// GetPublicKey does NOT range-check the scalar: zero, and the curve order,
	// both yield a pubkey of sixty-four zeros and fail only at signing time.
	// Accepting one would announce allowsNostr with that pubkey, take every zap,
	// and fail to sign every receipt — invisible until money had already moved.
	// So the key is proved by using it, once, here.
	if err := identity.Sign(&gonostr.Event{Kind: 1, CreatedAt: 1}); err != nil {
		return Identity{}, errUnusableKey
	}
	return identity, nil
}

// errUnusableKey is deliberately one error for every way a key can be wrong:
// the distinctions are not the operator's to act on, and the alternative is
// error text derived from the key.
var errUnusableKey = errors.New("nostr: that private key cannot sign")

// PublicKey is the hex pubkey, which is public by definition — it is announced
// in every LNURL response.
func (i Identity) PublicKey() string { return i.public }

// NewPairingKey mints a keypair and hands back BOTH halves, for §8's pairing.
//
// A package-level function and NOT a method, which is the whole design. A
// connection needs its private key written into a row and a client secret
// written into a URI, so those bytes must leave this package exactly once — at
// creation. An accessor on Identity would have made that true of EVERY identity,
// including the server's own signing key, which §11 lists as never-log and which
// nothing outside this package has any business holding.
//
// So this mints and returns; it can be called with anything and reveals nothing
// that existed before the call. An earlier PrivateKeyForPairing was removed for
// exactly that reason (d24.3 review), with the note that d24.5 should add what it
// actually needed. This is it.
//
// Plain strings deliberately: a secret.String here would look like it stayed
// protected while being written into a URI a moment later. The caller wraps them
// as it stores them.
func NewPairingKey() (privkey, pubkey string, err error) {
	id, err := Generate()
	if err != nil {
		return "", "", err
	}
	return id.private.Reveal(), id.public, nil
}

// IsZero reports whether there is no identity yet.
func (i Identity) IsZero() bool { return i.public == "" }

// LogValue renders the identity by its PUBLIC half only, so no call site can
// log the private one by accident (§12).
func (i Identity) LogValue() slog.Value {
	return slog.GroupValue(slog.String("pubkey", i.public))
}

// String is the same redaction for %s and friends.
func (i Identity) String() string { return "nostr:" + i.public }

// Sign fills in the event's pubkey, id and signature.
//
// One of the THREE places this type reveals the private key, and all three are
// in this package: Sign, and Encrypt/Decrypt in encrypt.go. Everything outside
// holds it as secret.String and has no way to ask for more — an earlier
// PrivateKeyForPairing was removed for that reason, its only caller being a
// regtest key-printer that now mints its own (d24.3 review).
func (i Identity) Sign(event *gonostr.Event) error {
	if i.IsZero() {
		return ErrNoIdentity
	}
	if err := event.Sign(i.private.Reveal()); err != nil {
		return fmt.Errorf("nostr: signing a kind %d event: %w", event.Kind, err)
	}
	return nil
}

// Settings is the slice of the settings table this package needs. Declared
// here, by the consumer, so internal/nostr depends on no database (§3).
type Settings interface {
	Setting(ctx context.Context, key string) (string, bool, error)
	SetSetting(ctx context.Context, key, value string) error
}

// LoadOrCreate returns the server's identity, minting one on first run.
//
// §19's packaging gate says normal setup must not need one-off operator
// commands, so a fresh install gets a working nostr identity by starting —
// exactly as the guard bakes the receive macaroon by starting.
func LoadOrCreate(ctx context.Context, settings Settings) (Identity, error) {
	identity, found, err := load(ctx, settings)
	if err != nil {
		return Identity{}, err
	}
	if found {
		// Rewritten on every start: the pubkey is derived, and a row that has
		// drifted from the key it claims to describe would make the LNURL
		// response announce one identity and the receipts carry another.
		return identity, publish(ctx, settings, identity)
	}
	generated, err := Generate()
	if err != nil {
		return Identity{}, err
	}
	return generated, store(ctx, settings, generated)
}

// Import replaces the identity with an operator-supplied key.
func Import(ctx context.Context, settings Settings, raw secret.String) (Identity, error) {
	identity, err := Parse(raw)
	if err != nil {
		return Identity{}, err
	}
	return identity, store(ctx, settings, identity)
}

func store(ctx context.Context, settings Settings, identity Identity) error {
	if err := settings.SetSetting(ctx, SettingPrivateKey, identity.private.Reveal()); err != nil {
		return fmt.Errorf("nostr: storing the identity key: %w", err)
	}
	return publish(ctx, settings, identity)
}

// publish writes the PUBLIC half.
//
// It is a separate step because the pubkey is what everything else reads: the
// LNURL response announces it and the domain self-prober checks the answer
// against it. Before this existed the prober read a row nothing wrote, so no
// configured domain could ever probe green (§9, o34.1).
func publish(ctx context.Context, settings Settings, identity Identity) error {
	if err := settings.SetSetting(ctx, SettingPublicKey, identity.public); err != nil {
		return fmt.Errorf("nostr: storing the identity pubkey: %w", err)
	}
	return nil
}

// Signer signs with the server's identity, READ FRESH on every use.
//
// Never a held Identity. The Settings page can replace the nostr key at
// runtime, and the lnurlp document announces whatever is in settings at the
// moment it is served — so a component holding a copy would sign receipts with
// an identity the lightning address has stopped announcing, and every sender's
// client would fail to match them up. The bug would be invisible locally: the
// receipts verify, they just verify as somebody else (o34.1's note, o34.3
// criterion 5).
//
// It owns the settings reader rather than taking one per call, the same shape
// as NewPool(ctx, relays func() []string): the caller wires the source once and
// cannot later forget to re-read it.
type Signer struct{ settings Settings }

// NewSigner returns a signer over a settings source.
func NewSigner(settings Settings) *Signer { return &Signer{settings: settings} }

// Sign fills in the event's pubkey, id and signature with the CURRENT identity.
func (s *Signer) Sign(ctx context.Context, event *gonostr.Event) error {
	identity, err := s.identity(ctx)
	if err != nil {
		return err
	}
	return identity.Sign(event)
}

// identity reads the stored key. It does NOT mint one: LoadOrCreate is the
// startup path, and a signer that created an identity on first use would give
// the first zap receipt a key the lnurlp document has never announced.
func (s *Signer) identity(ctx context.Context) (Identity, error) {
	identity, found, err := load(ctx, s.settings)
	if err != nil {
		return Identity{}, err
	}
	if !found {
		return Identity{}, ErrNoIdentity
	}
	return identity, nil
}

// load reads and parses the stored identity, reporting whether there was one.
//
// One read path for the two callers. They used to have one each, and had
// already drifted: LoadOrCreate treated a whitespace-only row as absent and
// minted a new key, while Signer treated it as present and failed to parse it.
// One row, two readings, in the same file.
func load(ctx context.Context, settings Settings) (Identity, bool, error) {
	stored, ok, err := settings.Setting(ctx, SettingPrivateKey)
	if err != nil {
		return Identity{}, false, fmt.Errorf("nostr: reading the identity key: %w", err)
	}
	if !ok || strings.TrimSpace(stored) == "" {
		return Identity{}, false, nil
	}
	identity, err := Parse(secret.New(stored))
	if err != nil {
		return Identity{}, false, err
	}
	return identity, true, nil
}
