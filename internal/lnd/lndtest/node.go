// Package lndtest runs a real gRPC server speaking LND's protocol over real
// TLS, so tests exercise the dial path the production code actually uses rather
// than a stub of it. Nothing outside tests imports it.
package lndtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	macaroonpkg "gopkg.in/macaroon.v2"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc/routerrpc"
)

// Node is a fake LND. Its zero value is not usable; call Start.
type Node struct {
	lnrpc.UnimplementedLightningServer

	address string
	certPEM []byte
	server  *grpc.Server

	mu sync.Mutex
	// macaroons seen, in order, so a test can assert what was sent and that a
	// replaced file was picked up.
	macaroons []string
	// rejectErr, when set, makes every RPC fail with it.
	rejectErr error
	// ledger is every settled invoice the node remembers, settle_index ascending.
	ledger []*lnrpc.Invoice
	// breakAfter, when > 0, drops the invoice stream after that many sends.
	breakAfter int
	// subscriptions records the settle_index each SubscribeInvoices resumed
	// from — the assertion that resume semantics are right.
	subscriptions []uint64
	// bakeRequests records every BakeMacaroon call, so a test can assert the
	// exact permission slice the guard asked for.
	bakeRequests []*lnrpc.BakeMacaroonRequest
	// listIDsErr makes ListMacaroonIDs fail while every other RPC still works.
	listIDsErr error
	// onListIDs runs while a ListMacaroonIDs call is in flight, which is how a
	// test opens the window between a caller's question and its answer.
	onListIDs func()
	// deleteErrors makes DeleteMacaroonID fail for specific root key ids.
	deleteErrors map[uint64]error
	// The routerrpc half (d24.2): scripted payment answers, keyed by bolt11 for
	// SendPaymentV2 and by hex payment hash for TrackPaymentV2, and a record of
	// what each was asked.
	payments      map[string]paymentScript
	tracked       map[string]paymentScript
	sendRequests  []*routerrpc.SendPaymentRequest
	trackedHashes []string
	baked         []byte
	// bakedIsFixed records that a test pinned the answer with
	// SetBakedMacaroon, so the root-key-derived default is not used.
	bakedIsFixed      bool
	rootKeyIDs        []uint64
	deletedRootKeyIDs []uint64
	onDelete          func(uint64)
	// localBalanceMsat is what ChannelBalance reports.
	localBalanceMsat int64
	// onDecode runs while a DecodePayReq call is in flight.
	onDecode func()
	// decoded and decodeErrors script DecodePayReq (d24.4): §8's ladder reads an
	// invoice through the node before it reserves anything.
	decoded      map[string]*lnrpc.PayReq
	decodeErrors map[string]error
	// invoiceRequests is every AddInvoice seen, in order.
	invoiceRequests []*lnrpc.Invoice
	// middleware is the RegisterRPCMiddleware side, with its own lock: a
	// middleware stream lives for the whole test and would otherwise hold n.mu
	// while an interception is in flight.
	middleware middleware
}

// Start brings up a node on a loopback port with a fresh self-signed
// certificate, and stops it when the test ends.
func Start(t testing.TB) *Node {
	t.Helper()
	certPEM, keyPEM := selfSignedCert(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("loading test keypair: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	n := &Node{
		address: listener.Addr().String(),
		certPEM: certPEM,
		// A real macaroon by default: the guard parses what it bakes to check
		// the caveats actually landed (§11), so a fake that returns arbitrary
		// bytes would make that check untestable.
		baked: Macaroon(t),
	}
	n.payments = map[string]paymentScript{}
	n.tracked = map[string]paymentScript{}
	n.middleware.intercepts = make(chan *lnrpc.RPCMiddlewareRequest)
	n.middleware.waiting = map[uint64]chan *lnrpc.InterceptFeedback{}
	n.server = grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	lnrpc.RegisterLightningServer(n.server, n)
	routerrpc.RegisterRouterServer(n.server, &router{node: n})
	go func() { _ = n.server.Serve(listener) }()
	t.Cleanup(n.server.Stop)
	return n
}

// Address is the host:port to dial.
func (n *Node) Address() string { return n.address }

// CertPEM is the node's certificate, as LND would write tls.cert.
func (n *Node) CertPEM() []byte { return n.certPEM }

// WriteCredentialVolume lays out a credential volume the way the guard would.
// A nil macaroon writes only the certificate.
func (n *Node) WriteCredentialVolume(t testing.TB, dir, macaroonName string, macaroon []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("creating credential dir: %v", err)
	}
	WriteFile(t, filepath.Join(dir, "tls.cert"), n.certPEM)
	if macaroon != nil {
		WriteFile(t, filepath.Join(dir, macaroonName), macaroon)
	}
}

// WriteMounts lays out the two single-file bind mounts the guard reads (§6).
func (n *Node) WriteMounts(t testing.TB, certPath, adminMacaroonPath string) {
	t.Helper()
	for _, dir := range []string{filepath.Dir(certPath), filepath.Dir(adminMacaroonPath)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("creating mount dir: %v", err)
		}
	}
	WriteFile(t, certPath, n.certPEM)
	WriteFile(t, adminMacaroonPath, []byte{0xad, 0x11, 0x11})
}

// WriteFile writes a file the way the guard would, 0600.
func WriteFile(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// SetReject makes every RPC fail the way LND fails a macaroon it cannot verify
// — which is what a rotated node looks like from the outside.
func (n *Node) SetReject(reject bool) {
	if !reject {
		n.SetRejectWith(nil)
		return
	}
	// The shape LND uses once a macaroon is invalidated by rotation.
	n.SetRejectWith(status.Error(codes.Unauthenticated,
		"verification failed: signature mismatch after caveat verification"))
}

// SetRejectWith makes every RPC fail with a specific status.
//
// It exists because d46.20: the real node rejects a *corrupted* macaroon with
// code=Unknown from its parser, not with the Unauthenticated this fake found
// convenient, and a test that can only produce the convenient one tests the
// spec's scenario rather than the field's.
func (n *Node) SetRejectWith(err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.rejectErr = err
}

// SetLedger replaces the settled invoices the node remembers.
func (n *Node) SetLedger(invoices ...*lnrpc.Invoice) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ledger = invoices
}

// SetBreakAfter drops the invoice stream after n sends.
func (n *Node) SetBreakAfter(count int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.breakAfter = count
}

// macaroonUnder builds the macaroon this node answers with for a root key id.
func macaroonUnder(rootKeyID uint64) ([]byte, error) {
	m, err := macaroonpkg.New(fmt.Appendf(nil, "root-key-%d", rootKeyID),
		fmt.Appendf(nil, "%d", rootKeyID), "lnd", macaroonpkg.LatestVersion)
	if err != nil {
		return nil, fmt.Errorf("lndtest: building a macaroon: %w", err)
	}
	return m.MarshalBinary()
}

// Macaroon builds a serialised macaroon carrying the given first-party
// caveats — what LND's BakeMacaroon plus §6's client-side caveat additions
// produce. With no caveats it is the receive macaroon's shape; with
// "ipaddr ..." and "time-before ..." it is the spend macaroon's.
func Macaroon(t testing.TB, caveats ...string) []byte {
	t.Helper()
	m, err := macaroonpkg.New([]byte("root-key"), []byte("0"), "lnd", macaroonpkg.LatestVersion)
	if err != nil {
		t.Fatalf("building a macaroon: %v", err)
	}
	for _, caveat := range caveats {
		if err := m.AddFirstPartyCaveat([]byte(caveat)); err != nil {
			t.Fatalf("adding caveat %q: %v", caveat, err)
		}
	}
	raw, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling a macaroon: %v", err)
	}
	return raw
}

// MacaroonHexUnder is a real macaroon baked under one root key, hex-encoded —
// the same bytes BakeMacaroon would answer with.
//
// For a test that has to put a credential on disk WITHOUT the guard having
// written it: the shape a crash between the credential write and the state
// update leaves behind. Hand-written bytes would fail the hardening check for
// the wrong reason.
func (n *Node) MacaroonHexUnder(t testing.TB, rootKeyID uint64) string {
	t.Helper()
	raw, err := macaroonUnder(rootKeyID)
	if err != nil {
		t.Fatalf("baking a macaroon under root key %d: %v", rootKeyID, err)
	}
	return hex.EncodeToString(raw)
}

// SetBakedMacaroon is what BakeMacaroon will return.
func (n *Node) SetBakedMacaroon(macaroon []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.baked = macaroon
	n.bakedIsFixed = true
}

// BakeRealMacaroons undoes SetBakedMacaroon: the node goes back to minting a
// distinct macaroon per root key.
//
// A test that makes a bake FAIL and then needs the next one to succeed cannot
// express that with SetBakedMacaroon alone — passing nil sets a fixed empty
// answer, which fails differently rather than not at all.
func (n *Node) BakeRealMacaroons() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.baked, n.bakedIsFixed = nil, false
}

// SeenMacaroons is every macaroon the node was sent, hex, in order.
func (n *Node) SeenMacaroons() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.macaroons...)
}

// ResumePoints is the settle_index each subscription asked to resume from.
func (n *Node) ResumePoints() []uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]uint64(nil), n.subscriptions...)
}

// BakeRequests is every BakeMacaroon call the node received.
func (n *Node) BakeRequests() []*lnrpc.BakeMacaroonRequest {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]*lnrpc.BakeMacaroonRequest(nil), n.bakeRequests...)
}

// authorise records the macaroon the client sent and applies the reject switch.
func (n *Node) authorise(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no metadata")
	}
	values := md.Get("macaroon")
	n.mu.Lock()
	if len(values) == 1 {
		n.macaroons = append(n.macaroons, values[0])
	}
	rejectErr := n.rejectErr
	n.mu.Unlock()

	if len(values) != 1 || values[0] == "" {
		return status.Error(codes.Unauthenticated, "expected 1 macaroon, got 0")
	}
	if err := n.honourCustomCaveats(values[0]); err != nil {
		return err
	}
	return rejectErr
}

// customCaveatPrefix is LND's own, spelled out here rather than imported: this
// package is the fake NODE, and taking the constant from the code under test
// would make the two agree by construction.
const customCaveatPrefix = "lnd-custom"

// honourCustomCaveats is LND's fail-closed rule, and the reason P4 is safe:
// a macaroon carrying `lnd-custom <name> …` is REJECTED unless a middleware is
// registered under <name> and its stream is live.
//
// Implemented in the fake because it is the property the whole phase rests on
// (§14: "if the guard dies, the spend macaroon is dead, not unrestricted"), and
// a fake that let such a macaroon through would make the one test that proves it
// impossible to write — the test would be asserting the fake, not the design.
func (n *Node) honourCustomCaveats(macaroonHex string) error {
	raw, err := hex.DecodeString(macaroonHex)
	if err != nil {
		return nil // not our business here; other paths report a bad macaroon
	}
	var m macaroonpkg.Macaroon
	if err := m.UnmarshalBinary(raw); err != nil {
		return nil
	}
	for _, caveat := range m.Caveats() {
		if len(caveat.VerificationId) != 0 {
			continue
		}
		condition, rest, found := strings.Cut(string(caveat.Id), " ")
		if !found || condition != customCaveatPrefix {
			continue
		}
		name, _, _ := strings.Cut(rest, " ")
		if !n.middlewareLiveFor(name) {
			return status.Errorf(codes.Unknown,
				"unknown custom caveat condition used in macaroon: %s", name)
		}
	}
	return nil
}

func (n *Node) middlewareLiveFor(name string) bool {
	n.middleware.mu.Lock()
	defer n.middleware.mu.Unlock()
	if n.middleware.live == 0 {
		return false
	}
	for _, registration := range n.middleware.registrations {
		if registration.GetCustomMacaroonCaveatName() == name {
			return true
		}
	}
	return false
}

func (n *Node) GetInfo(ctx context.Context, _ *lnrpc.GetInfoRequest) (*lnrpc.GetInfoResponse, error) {
	if err := n.authorise(ctx); err != nil {
		return nil, err
	}
	return &lnrpc.GetInfoResponse{Alias: "fake-node", SyncedToChain: true, IdentityPubkey: "02aaaa"}, nil
}

func (n *Node) AddInvoice(ctx context.Context, in *lnrpc.Invoice) (*lnrpc.AddInvoiceResponse, error) {
	if err := n.authorise(ctx); err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.invoiceRequests = append(n.invoiceRequests, in)
	index := len(n.invoiceRequests)
	n.mu.Unlock()
	// A distinct hash per invoice, so a test can look up what it just minted
	// and two invoices in one test do not collide on one row.
	hash := invoiceHash(index)
	return &lnrpc.AddInvoiceResponse{
		RHash:          hash,
		PaymentRequest: fmt.Sprintf("lnbcrt%dn1%x", in.ValueMsat, hash[:4]),
		AddIndex:       uint64(index),
	}, nil
}

// SetDecoded scripts what DecodePayReq answers for one bolt11 (d24.4).
func (n *Node) SetDecoded(bolt11 string, req *lnrpc.PayReq) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.decoded == nil {
		n.decoded = map[string]*lnrpc.PayReq{}
	}
	n.decoded[bolt11] = req
}

// SetDecodeError makes DecodePayReq refuse one bolt11, which is what a real node
// does with a malformed one.
func (n *Node) SetDecodeError(bolt11 string, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.decodeErrors == nil {
		n.decodeErrors = map[string]error{}
	}
	n.decodeErrors[bolt11] = err
}

// DecodePayReq answers from the script, and refuses anything unscripted — an
// invoice a test did not set up is a test asking about something it did not
// mean to.
func (n *Node) DecodePayReq(ctx context.Context, in *lnrpc.PayReqString) (*lnrpc.PayReq, error) {
	if err := n.authorise(ctx); err != nil {
		return nil, err
	}
	// OUTSIDE the lock, and before the answer is read: the hook is how a test
	// holds several callers inside this RPC at once, which is the only way to
	// make a race between them happen rather than hope for it.
	n.mu.Lock()
	hook := n.onDecode
	n.mu.Unlock()
	if hook != nil {
		hook()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.decodeErrors[in.PayReq]; err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	req, ok := n.decoded[in.PayReq]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "lndtest: no decoded invoice scripted for %q", in.PayReq)
	}
	return req, nil
}

// SetOnDecodePayReq runs fn during every DecodePayReq call, before the answer
// is read and with no lock held, so fn may block or call back into this node.
func (n *Node) SetOnDecodePayReq(fn func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onDecode = fn
}

// InvoiceRequests is every AddInvoice the node was asked for, in order — so a
// test can assert what was actually sent, including description_hash and expiry.
func (n *Node) InvoiceRequests() []*lnrpc.Invoice {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]*lnrpc.Invoice(nil), n.invoiceRequests...)
}

// MintedHashes is the payment hash this node answered with for each invoice,
// hex-encoded, in order.
//
// The convention is this file's, so it stays here: a test that re-derived it
// would keep compiling after the formula changed and would then look up rows
// that do not exist — turning every "nothing was minted" assertion into one
// that passes because nothing could be found.
func (n *Node) MintedHashes() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]string, len(n.invoiceRequests))
	for i := range n.invoiceRequests {
		out[i] = hex.EncodeToString(invoiceHash(i + 1))
	}
	return out
}

// invoiceHash gives each invoice a distinct payment hash, so two in one test do
// not collide on one row.
func invoiceHash(index int) []byte {
	sum := sha256.Sum256(fmt.Appendf(nil, "invoice-%d", index))
	return sum[:]
}

// LookupInvoice answers from the ledger. Implemented so a test that tells this
// node to refuse actually sees the refusal: an unimplemented method returns
// codes.Unimplemented, which every classifier treats as benign, and a test
// asserting "no re-bake" would pass without exercising anything.
func (n *Node) LookupInvoice(ctx context.Context, in *lnrpc.PaymentHash) (*lnrpc.Invoice, error) {
	if err := n.authorise(ctx); err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, invoice := range n.ledger {
		if string(invoice.RHash) == string(in.RHash) {
			return invoice, nil
		}
	}
	return nil, status.Error(codes.NotFound, "unable to locate invoice")
}

// ChannelBalance reports what the node can send. Implemented for the same
// reason as LookupInvoice above.
func (n *Node) ChannelBalance(ctx context.Context, _ *lnrpc.ChannelBalanceRequest) (*lnrpc.ChannelBalanceResponse, error) {
	if err := n.authorise(ctx); err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return &lnrpc.ChannelBalanceResponse{
		LocalBalance: &lnrpc.Amount{Msat: uint64(n.localBalanceMsat)},
	}, nil
}

// SetLocalBalance sets what ChannelBalance reports.
func (n *Node) SetLocalBalance(msat int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.localBalanceMsat = msat
}

func (n *Node) BakeMacaroon(ctx context.Context, in *lnrpc.BakeMacaroonRequest) (*lnrpc.BakeMacaroonResponse, error) {
	if err := n.authorise(ctx); err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.bakeRequests = append(n.bakeRequests, in)
	if in.RootKeyId != 0 {
		n.rootKeyIDs = append(n.rootKeyIDs, in.RootKeyId)
	}
	baked, fixed := n.baked, n.bakedIsFixed
	n.mu.Unlock()
	if !fixed {
		// A macaroon really baked under a different root key has different
		// bytes, and a fake that returned the same ones would let "the
		// credential was replaced" pass without anything being replaced.
		var err error
		if baked, err = macaroonUnder(in.RootKeyId); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	return &lnrpc.BakeMacaroonResponse{Macaroon: hex.EncodeToString(baked)}, nil
}

func (n *Node) ListMacaroonIDs(ctx context.Context, _ *lnrpc.ListMacaroonIDsRequest) (*lnrpc.ListMacaroonIDsResponse, error) {
	if err := n.authorise(ctx); err != nil {
		return nil, err
	}
	// OUTSIDE the lock, and before the answer is read: the hook exists so a test
	// can make something else happen while this call is in flight, and that
	// something else usually talks to this node.
	n.mu.Lock()
	hook := n.onListIDs
	n.mu.Unlock()
	if hook != nil {
		hook()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.listIDsErr != nil {
		return nil, status.Error(codes.Unavailable, n.listIDsErr.Error())
	}
	return &lnrpc.ListMacaroonIDsResponse{RootKeyIds: append([]uint64(nil), n.rootKeyIDs...)}, nil
}

// ForgetRootKeys drops every root key the node is listing, WITHOUT recording a
// deletion — which is what an operator revoking with lncli, or a macaroon
// rotation, looks like from the guard's side: the keys are simply not there any
// more and nothing the guard did explains it.
func (n *Node) ForgetRootKeys() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.rootKeyIDs = nil
}

// SetOnListMacaroonIDs runs fn during every ListMacaroonIDs call, before the
// answer is read.
//
// The window between "the guard asks the node about a root key" and "the guard
// acts on the reply" is where a decision taken from a stale snapshot goes wrong,
// and it cannot be reached from outside without a hook. fn runs with no lock
// held, so it may call back into this node.
func (n *Node) SetOnListMacaroonIDs(fn func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onListIDs = fn
}

// SetListMacaroonIDsError makes the one question "does the node still honour
// this key" fail, without failing every other RPC.
//
// Targeted rather than SetReject, because the distinction is the whole of the
// test that uses it: "the node says the key is gone" and "the node cannot be
// asked" must produce opposite behaviour, and a fake that took the whole
// connection down would be testing the first while claiming the second.
func (n *Node) SetListMacaroonIDsError(err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.listIDsErr = err
}

func (n *Node) DeleteMacaroonID(ctx context.Context, in *lnrpc.DeleteMacaroonIDRequest) (*lnrpc.DeleteMacaroonIDResponse, error) {
	if err := n.authorise(ctx); err != nil {
		return nil, err
	}
	n.mu.Lock()
	onDelete := n.onDelete
	refuse := n.deleteErrors[in.RootKeyId]
	n.mu.Unlock()
	if refuse != nil {
		// Not recorded in deletedRootKeyIDs: the node did not delete it, and a
		// test asserting "this id was revoked" must not be satisfied by an
		// attempt that failed.
		return nil, status.Error(codes.Unavailable, refuse.Error())
	}
	n.mu.Lock()
	n.deletedRootKeyIDs = append(n.deletedRootKeyIDs, in.RootKeyId)
	n.mu.Unlock()
	if onDelete != nil {
		// Called with the lock released and BEFORE the answer, so a test can
		// observe the world as it is at the moment of revocation — which is how
		// "bake, write, THEN revoke" is asserted rather than assumed.
		onDelete(in.RootKeyId)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	deleted := slices.Contains(n.rootKeyIDs, in.RootKeyId)
	n.rootKeyIDs = slices.DeleteFunc(n.rootKeyIDs, func(id uint64) bool { return id == in.RootKeyId })
	return &lnrpc.DeleteMacaroonIDResponse{Deleted: deleted}, nil
}

// AddRootKeyForTest gives the node a root key the guard did not bake: another
// app's credential on the same box. It is what makes "revokes only what the
// guard recorded" an assertion rather than a claim.
func (n *Node) AddRootKeyForTest(rootKeyID uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !slices.Contains(n.rootKeyIDs, rootKeyID) {
		n.rootKeyIDs = append(n.rootKeyIDs, rootKeyID)
	}
}

// DeleteRootKeyForTest makes the node forget a root key without the guard
// asking — what LND's macaroon rotation does.
func (n *Node) DeleteRootKeyForTest(rootKeyID uint64) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	had := slices.Contains(n.rootKeyIDs, rootKeyID)
	n.rootKeyIDs = slices.DeleteFunc(n.rootKeyIDs, func(id uint64) bool { return id == rootKeyID })
	return had, nil
}

// SetDeleteMacaroonIDError makes the node refuse to delete ONE root key.
//
// Per-id rather than a blanket switch, so a sweep can run normally around the
// one revocation that fails — which is the shape d24.10 is about: the main
// revocation succeeds and an orphan's does not.
func (n *Node) SetDeleteMacaroonIDError(rootKeyID uint64, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.deleteErrors == nil {
		n.deleteErrors = map[uint64]error{}
	}
	if err == nil {
		delete(n.deleteErrors, rootKeyID)
		return
	}
	n.deleteErrors[rootKeyID] = err
}

// SetOnDeleteMacaroonID runs fn when a revocation arrives.
func (n *Node) SetOnDeleteMacaroonID(fn func(rootKeyID uint64)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onDelete = fn
}

// ListedRootKeyIDs is what the node currently honours.
func (n *Node) ListedRootKeyIDs() []uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]uint64(nil), n.rootKeyIDs...)
}

// DeletedRootKeyIDs is every revocation the node was asked for, in order — the
// assertion that a re-bake actually revoked its predecessor.
func (n *Node) DeletedRootKeyIDs() []uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]uint64(nil), n.deletedRootKeyIDs...)
}

func (n *Node) SubscribeInvoices(req *lnrpc.InvoiceSubscription, stream lnrpc.Lightning_SubscribeInvoicesServer) error {
	if err := n.authorise(stream.Context()); err != nil {
		return err
	}
	n.mu.Lock()
	n.subscriptions = append(n.subscriptions, req.SettleIndex)
	ledger := append([]*lnrpc.Invoice(nil), n.ledger...)
	breakAfter := n.breakAfter
	n.mu.Unlock()

	sent := 0
	for _, invoice := range ledger {
		// LND's documented semantics: strictly greater than the requested index.
		if invoice.SettleIndex <= req.SettleIndex {
			continue
		}
		if breakAfter > 0 && sent == breakAfter {
			return status.Error(codes.Unavailable, "transport closing")
		}
		if err := stream.Send(invoice); err != nil {
			return err
		}
		sent++
	}
	// Hold the stream open like a real node until the client goes away.
	<-stream.Context().Done()
	return stream.Context().Err()
}

// SettledInvoice builds a settled invoice for a ledger.
func SettledInvoice(paymentHash string, settleIndex uint64, amountMsat int64) *lnrpc.Invoice {
	return &lnrpc.Invoice{
		RHash:       []byte(paymentHash),
		RPreimage:   []byte("preimage-" + paymentHash),
		State:       lnrpc.Invoice_SETTLED,
		SettleIndex: settleIndex,
		AmtPaidMsat: amountMsat,
	}
}

// WaitFor polls cond until it holds, or fails the test. Shared because both
// the lnd and guard suites drive asynchronous loops — a stream reconnecting, a
// socket coming up — and neither should invent its own deadline.
func WaitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// ShortDir is a temp directory short enough to hold a unix socket path.
// sun_path is capped at around 104 bytes and the testing framework's temp
// directories are longer than that on macOS. The deployed path,
// /credentials/guard.sock, is nowhere near the limit.
func ShortDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "bz")
	if err != nil {
		t.Fatalf("creating a short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func selfSignedCert(t testing.TB) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake-lnd"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
