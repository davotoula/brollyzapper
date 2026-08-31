package lnurl

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/store"
)

// ErrUnknownAddress is returned when {name} is not this instance's address.
//
// §7 says anything else is a plain 404 with no hint: a probe should not be able
// to learn which names exist here.
var ErrUnknownAddress = errors.New("lnurl: no such address")

// ErrNotConfigured is returned before the operator has set an address. It is a
// state the admin UI explains, never a crash (§11).
var ErrNotConfigured = errors.New("lnurl: no lightning address is configured")

// Node is the slice of LND this needs — one method, and it cannot move a
// satoshi. §6's receive macaroon grants exactly five, and this is one of them.
type Node interface {
	AddInvoice(ctx context.Context, invoice *lnrpc.Invoice) (*lnrpc.AddInvoiceResponse, error)
}

// Invoices records what was minted, so the settlement can find it again.
type Invoices interface {
	CreateInvoice(ctx context.Context, inv store.Invoice) error
}

// Settings is the slice of the settings table this needs.
//
// The whole table in one query, not three point reads. The three rows below are
// read together every time, and the store runs on a single connection shared
// with the invoice-settlement stream — so three round trips is three chances to
// queue behind a settlement for one answer.
type Settings interface {
	AllSettings(ctx context.Context) (map[string]string, error)
}

// Settings keys this reads.
//
// The nostr pubkey is internal/nostr's, aliased rather than re-spelled: the
// package that computes with a value owns the name of the row it comes from,
// and three literals naming one row is how "saves" and "reads back" become
// different strings.
const (
	SettingDomain = "domain"
	// SettingDomainInsecure carries the scheme the bare domain no longer does.
	// The address is a host[:port]; whether it is served over plain HTTP is a
	// separate fact, and one only a LAN or regtest setup ever answers yes to.
	SettingDomainInsecure = "domain_insecure"
	SettingAddressName    = "address_name"
	SettingNostrPubkey    = nostr.SettingPublicKey
)

// PayResponse is §7's LUD-06 document.
type PayResponse struct {
	Callback       string `json:"callback"`
	MaxSendable    int64  `json:"maxSendable"`
	MinSendable    int64  `json:"minSendable"`
	Metadata       string `json:"metadata"`
	Tag            string `json:"tag"`
	CommentAllowed int    `json:"commentAllowed"`
	AllowsNostr    bool   `json:"allowsNostr"`
	NostrPubkey    string `json:"nostrPubkey"`
}

// CallbackResponse is what a wallet pays.
type CallbackResponse struct {
	PaymentRequest string   `json:"pr"`
	Routes         []string `json:"routes"`
}

// identityTTL is how long one read of the configured identity is reused.
//
// §7 does not rate-limit the lnurlp document at all (ruled 22 Aug 2026): it
// mints nothing, and limiting it made one zap cost two of the instance's
// requests — and put §9's self-probe in a bucket a stranger could drain. What
// pays for that is this cache. Without it every anonymous fetch of the document
// is three point reads on a database deliberately opened with one connection,
// shared with the invoice stream.
//
// Two seconds, matching the settings cache the admin pages use, so a change
// made in Settings is visible about as fast either way.
//
// KNOWN GAP: internal/api's settingsCache has an invalidate() that the Settings
// save path calls, and this has no equivalent — the admin page shows a renamed
// address immediately while the public document announces the old one for up to
// two seconds. Two TTL caches over one table is the real finding and the fix is
// to share one, which is a bigger change than this wave; recorded rather than
// papered over.
const identityTTL = 2 * time.Second

// identity is the configured lightning address, as three settings rows.
type identity struct {
	name string
	// domain is the bare host[:port], normalised when the identity is read.
	domain string
	pubkey string
	// insecure is the operator saying this address is served over plain HTTP,
	// which only a LAN or regtest setup ever is (o34.13).
	insecure bool
}

// Service answers both endpoints. It holds no HTTP: §3 requires everything
// below api/web to be usable without a server, and an arch rule asserts this
// package imports no net/http.
type Service struct {
	node     Node
	invoices Invoices
	settings Settings
	now      func() time.Time

	// idMu guards the memoised identity. Held across the read on purpose: a
	// burst of anonymous document fetches then costs one query rather than one
	// each, which is the whole reason the document needs no limiter.
	//
	// idAt zero means "never read": a zero time is two millennia ago, so the
	// TTL comparison below answers that too and no separate flag is needed.
	idMu sync.Mutex
	id   identity
	idAt time.Time
}

// NewService wires the callback.
func NewService(node Node, invoices Invoices, settings Settings, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{node: node, invoices: invoices, settings: settings, now: now}
}

// identity returns the configured address, reading it at most once per TTL.
//
// A read failure is returned and NOT cached: it is a transient fault, and
// remembering it would extend a moment of database trouble into two seconds of
// answering 404 to wallets.
func (s *Service) identity(ctx context.Context) (identity, error) {
	s.idMu.Lock()
	defer s.idMu.Unlock()
	if s.now().Sub(s.idAt) < identityTTL {
		return s.id, nil
	}
	values, err := s.settings.AllSettings(ctx)
	if err != nil {
		return identity{}, err
	}
	// Normalised HERE, once, so every reader of an identity holds a bare host.
	// Leaving the raw row on the struct meant Identifier, Metadata and BaseURL
	// each normalised it again and the scheme had two sources — the row and the
	// string — for BaseURL to arbitrate between on every call.
	host, scheme := NormaliseDomain(values[SettingDomain])
	id := identity{
		name:   strings.TrimSpace(values[SettingAddressName]),
		domain: host,
		pubkey: strings.TrimSpace(values[SettingNostrPubkey]),
		// A scheme still sitting in the domain row is a box configured before
		// o34.13; it means the same thing the flag means.
		insecure: strings.TrimSpace(values[SettingDomainInsecure]) == "true" || scheme == "http",
	}
	s.id, s.idAt = id, s.now()
	return id, nil
}

// address returns the configured identity, refusing any name but this one.
func (s *Service) address(ctx context.Context, name string) (identity, error) {
	id, err := s.identity(ctx)
	if err != nil {
		return identity{}, err
	}
	if id.name == "" || id.domain == "" {
		return identity{}, ErrNotConfigured
	}
	if !strings.EqualFold(name, id.name) {
		return identity{}, ErrUnknownAddress
	}
	return id, nil
}

// PayRequest answers GET /.well-known/lnurlp/{name}.
func (s *Service) PayRequest(ctx context.Context, name string) (PayResponse, error) {
	id, err := s.address(ctx, name)
	if err != nil {
		return PayResponse{}, err
	}
	return PayResponse{
		Callback:       callbackURL(id.domain, id.name, id.insecure),
		MaxSendable:    MaxSendableMsat,
		MinSendable:    MinSendableMsat,
		Metadata:       Metadata(id.name, id.domain),
		Tag:            "payRequest",
		CommentAllowed: CommentAllowed,
		// allowsNostr is only honest when there is a key to announce.
		AllowsNostr: id.pubkey != "",
		NostrPubkey: id.pubkey,
	}, nil
}

func callbackURL(domain, name string, insecure bool) string {
	return BaseURL(domain, insecure) + "/lnurlp/" + name + "/callback"
}

// Callback answers GET /lnurlp/{name}/callback and mints the invoice.
//
// query is the RAW parsed query string, never a merged form: the zap request
// must survive as the bytes it was sent as, and anything that re-encodes it
// breaks description_hash and every receipt built from it (§7, §16).
//
// zap is the ONE parse of the nostr parameter, done by the caller (§11 still
// holds — see VerifiedZapRequest). It carries a proof or a rejection, and the
// rejection is surfaced HERE rather than by the caller so that Appendix D keeps
// its place in the order of refusals: amount, then comment, then the zap
// request. A caller that surfaced it earlier would answer a too-long comment
// with a nostr error.
func (s *Service) Callback(ctx context.Context, name string, query url.Values,
	zap ZapParam) (CallbackResponse, error) {
	id, err := s.address(ctx, name)
	if err != nil {
		return CallbackResponse{}, err
	}

	amountMsat, err := AmountMsat(query)
	if err != nil {
		return CallbackResponse{}, err
	}
	if amountMsat < MinSendableMsat || amountMsat > MaxSendableMsat {
		return CallbackResponse{}, reject("amount must be between %d and %d millisatoshis",
			MinSendableMsat, MaxSendableMsat)
	}
	comment := query.Get("comment")
	// Runes, because commentAllowed is announced to wallets as a character
	// count: counting bytes refuses a 200-character comment at an endpoint
	// advertising 255.
	if utf8.RuneCountInString(comment) > CommentAllowed {
		return CallbackResponse{}, reject("a comment may be at most %d characters", CommentAllowed)
	}

	if zap.err != nil {
		return CallbackResponse{}, zap.err
	}
	// The verified request, or nil for an ordinary payment. Its Raw is the
	// bytes that get hashed and stored — taken from the VERIFIED value rather
	// than re-read from the query, so the bytes hashed are provably the bytes
	// whose signature was checked.
	var request *ZapRequest
	if zap.verified != nil {
		request = zap.verified.Request()
	}

	// The rule is named at the call site rather than inferred from which
	// argument is empty, so the zap case and the plain case cannot be confused
	// and no argument swap is expressible (§16).
	var hash [32]byte
	if request != nil {
		hash, err = ZapHash(request.Raw)
	} else {
		hash, err = MetadataHash(Metadata(id.name, id.domain))
	}
	if err != nil {
		return CallbackResponse{}, err
	}

	added, err := s.node.AddInvoice(ctx, &lnrpc.Invoice{
		ValueMsat:       amountMsat,
		DescriptionHash: hash[:],
		Expiry:          InvoiceExpirySeconds,
	})
	if err != nil {
		// Deliberately not a Rejection: an anonymous caller learns that this
		// failed, never why. Whatever LND said about our node is ours.
		return CallbackResponse{}, fmt.Errorf("lnurl: minting an invoice: %w", err)
	}

	minted := s.now().UTC()
	invoice := store.Invoice{
		PaymentHash:     hex.EncodeToString(added.RHash),
		AmountMsat:      amountMsat,
		DescriptionHash: hex.EncodeToString(hash[:]),
		Bolt11:          added.PaymentRequest,
		// LUD-12's comment, in the sender's own words. The endpoint advertises
		// commentAllowed and checked it above; storing it is what makes that
		// advertisement honest (o34.12). It is deliberately absent from the
		// metadata: description_hash is computed over the metadata, and folding
		// a comment in would change a hash the wallet has already committed to.
		Comment:   comment,
		CreatedAt: minted,
		ExpiresAt: minted.Add(time.Duration(InvoiceExpirySeconds) * time.Second),
	}
	if request != nil {
		// The bytes the sender SIGNED, byte-identical. o34.3's receipt carries
		// these verbatim as its description tag, and a re-serialisation here
		// would make every receipt unverifiable (§7, §16). Not "as received":
		// rule 3's fallback can decode what arrived, and it is the verified form
		// that must be stored (BrollyZap-w0i).
		invoice.ZapRequest = string(request.Raw)
		if relays, err := json.Marshal(request.Relays); err == nil {
			invoice.ZapRelays = string(relays)
		}
	}
	if err := s.invoices.CreateInvoice(ctx, invoice); err != nil {
		return CallbackResponse{}, fmt.Errorf("lnurl: recording a minted invoice: %w", err)
	}

	// routes is always empty; it exists because LUD-06 requires the field.
	return CallbackResponse{PaymentRequest: added.PaymentRequest, Routes: []string{}}, nil
}
