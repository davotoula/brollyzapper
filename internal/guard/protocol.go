package guard

import (
	"errors"
	"time"

	"github.com/davotoula/brollyzapper/internal/logging"
)

// Op is one of the guard's operations.
type Op string

// The whole socket API (spec §6). The narrowness of this list is the security
// boundary: there is deliberately no "bake with these permissions" call,
// because the permission lists are compiled into this package.
//
// IT WAS FOUR OPERATIONS UNTIL `06v`, and the two that joined them are the
// operator's ceremony rather than a widening of what the server may ask for.
// `06v` established that umbrelOS offers no settings surface at all — no
// `settings`/`config`/`env` key in any of 391 app manifests, and `exports.sh` is
// package content an update overwrites — so the three guard controls had no
// operator route, and the Sending page named one that did not exist. The repair
// could not be "let the server set them": the server is what the design defends
// against. It is "let the operator authorise a loosening through a channel the
// server cannot forge", and that needs two calls — ask, and redeem.
//
// WHAT DID NOT CHANGE is the property the count was standing in for: no
// operation takes a parameter that grants capability. See Request.
const (
	OpStatus      Op = "status"
	OpBakeReceive Op = "bake_receive"
	OpBakeSpend   Op = "bake_spend"
	OpRevokeSpend Op = "revoke_spend"
	// OpRequestAuthorisation asks the guard to issue a one-time grant for a
	// loosening and write it where only the operator can read it.
	OpRequestAuthorisation Op = "request_authorisation"
	// OpApplyChange moves one operator control. A tightening applies with no
	// code; a loosening needs the code from the guard's own file.
	OpApplyChange Op = "apply_change"
)

// Ops is the entire API surface. A seventh entry is a design change, not an
// implementation detail — see the test that pins this list.
var Ops = []Op{
	OpStatus, OpBakeReceive, OpBakeSpend, OpRevokeSpend,
	OpRequestAuthorisation, OpApplyChange,
}

// Request is everything the server may say to the guard.
//
// NO FIELD HERE GRANTS ANYTHING. That is the rule, and it is what the older
// "carries the operation and nothing else" was protecting: no permission list,
// no URI, no caveat, and in particular no root key id — a caller-supplied id
// would turn RevokeSpend into DeleteMacaroonID pointed at any app's key on the
// box, a destructive cross-app primitive hiding inside a safe-looking call (§6).
//
// The two fields `06v` added are of a different kind, and the difference is the
// whole argument for adding them:
//
//   - Change names one of THREE compiled-in controls and a value. It cannot name
//     a fourth, and it does not say which DIRECTION it moves — the guard
//     computes that against its own stored state, because the direction is
//     exactly what a compromised server would lie about (State.loosens).
//   - Code is checked against a secret the guard wrote into a volume the server
//     has no mount for. A server supplying it is relaying, not asserting.
//
// A field that let the server say "this is a tightening", or name a control by
// free-form string, or supply the authorisation itself, would be the widening
// d46.8 refused. The test that pins this type spells that difference out.
type Request struct {
	Op Op `json:"op"`
	// Change is set for OpRequestAuthorisation and OpApplyChange.
	Change *Change `json:"change,omitempty"`
	// Code is the operator's, read from the guard's own file and typed into the
	// page. Never logged, and never returned by any response.
	Code string `json:"code,omitempty"`
}

// Response is the guard's answer. Error is set when the operation failed;
// Status is set only for OpStatus.
//
// Events rides on EVERY response, whatever the operation and whether or not it
// succeeded. It is not a fifth operation and not a widening of Request: §6
// makes the narrowness of that API the security boundary, and this asks the
// guard for nothing — it is the guard telling the server what it already
// decided to say (§12, d46.18).
type Response struct {
	Error  string  `json:"error,omitempty"`
	Status *Status `json:"status,omitempty"`
	// Events is the guard's recent security events, for the server to write to
	// the durable trail. The guard has no mount for the server's database and
	// must not have one (§16), so this is the only way §12's trail can hold
	// them. They are re-reported until they fall out of retention, because the
	// guard cannot learn whether one was stored; the server dedups by id.
	Events []logging.RelayedEvent `json:"events,omitempty"`
}

// Status is what the server is allowed to learn about its own credentials.
// It carries no macaroon: the server learns presence, expiry and revocation
// state, never the credential itself (§6).
type Status struct {
	ReceiveMacaroonPresent bool      `json:"receive_macaroon_present"`
	SpendMacaroonPresent   bool      `json:"spend_macaroon_present"`
	ReceiveExpiry          time.Time `json:"receive_expiry,omitempty"`
	SpendExpiry            time.Time `json:"spend_expiry,omitempty"`
	SpendRootKeyListed     bool      `json:"spend_root_key_listed"`
	// SpendRootKeyRecorded reports whether the guard HAS a root key id for the
	// spend macaroon — it records one at bake time and forgets it at revoke.
	//
	// Three states, not two, and §11 needs all three: no id recorded (a spend
	// macaroon on disk that this guard did not bake, or baked and then revoked —
	// which is a stolen or stale copy either way), an id the node still lists,
	// and an id it does not.
	SpendRootKeyRecorded bool `json:"spend_root_key_recorded"`
	// SpendRootKeyChecked reports whether the node was actually ASKED.
	//
	// Without it, "the node does not list this key" and "we could not ask the
	// node" are the same false — and since d24.6 that difference refuses a
	// payment: a transient RPC error would tell the operator their macaroon "has
	// already been revoked", which is a diagnosis pointing at the wrong repair.
	SpendRootKeyChecked bool `json:"spend_root_key_checked"`
	// SendingPermitted is whether this install may mint spend authority at all:
	// the DEPLOYMENT ceiling and the OPERATOR's latch, together (tna.4, `06v`).
	//
	// Two facts behind one bool because the page needs one answer to one
	// question — "will the guard bake if asked?" — and reports the two halves
	// separately below when it needs to explain a no.
	//
	// THE SERVER LEARNS IT HERE AND NOWHERE ELSE, and that is a rule rather than
	// a convenience. The server could read its own environment for a copy of the
	// flag, and then the PAGE and the ENFORCEMENT would have separate sources
	// that can disagree — an operator would be offered a button that the guard
	// refuses, which teaches them the app is broken. Only the guard knows what
	// the guard will do.
	SendingPermitted bool `json:"sending_permitted"`
	// SendingAllowedByDeployment is GUARD_ALLOW_SENDING alone (`06v`, Ruling 4).
	//
	// It reports a ceiling the app cannot lift by any means: an operator on a
	// deployment that set it false has no in-app remedy, and the page must say
	// that rather than offering the ceremony. The two off-states are different
	// sentences with different remedies, which is the same rule tna.4 set for
	// the pair that existed then.
	SendingAllowedByDeployment bool `json:"sending_allowed_by_deployment"`
	// SendingLatched is the OPERATOR's stored intent alone. On with no spend
	// macaroon present means an enable whose bake failed — one click to retry,
	// no second ceremony, because the ceremony authorised the transition and the
	// transition happened.
	SendingLatched bool `json:"sending_latched"`
	// AuthorisationPending reports that a grant is outstanding, and
	// AuthorisationExpiresAt when it dies. The CODE is never here: the server
	// relays a code it must not be able to read (`06v`, Ruling 3).
	AuthorisationPending   bool      `json:"authorisation_pending"`
	AuthorisationExpiresAt time.Time `json:"authorisation_expires_at,omitempty"`
	// AuthorisationChange is the guard's own sentence about the pending change,
	// so the page can show the operator what they are being asked to confirm
	// WITHOUT composing it. The authoritative copy is the file; this is the
	// page's echo of it, and if the two disagree the operator believes the file.
	AuthorisationChange string `json:"authorisation_change,omitempty"`
	// AuthorisationControl and AuthorisationMsat are the pending change in the
	// form the page needs to re-submit it: which control, and what value.
	//
	// NOT SECRET, and carrying them costs nothing — the operator is reading both
	// in the guard's file. What they buy is a code form that posts the SAME
	// change the grant was issued for: without them the page would have to
	// remember it across a redirect, and a page that guessed wrong would offer a
	// correct code against a change the guard refuses, leaving the operator with
	// a working code and a page that cannot use it.
	AuthorisationControl string `json:"authorisation_control,omitempty"`
	AuthorisationMsat    int64  `json:"authorisation_msat,omitempty"`
	// AuthorisationLocation is where the operator will find the file, in the
	// deployment's own words — GUARD_AUTHORISATION_LOCATION.
	//
	// §19 forbids the generic app assuming deployment-specific paths, and this
	// is how both halves of that are satisfied: the PACKAGE knows the string
	// ("Files → Apps → brollyzapper → data → guard"), the guard relays it, and
	// the page renders what it is given. Nothing in internal/api or the
	// templates knows an umbrelOS path.
	AuthorisationLocation string `json:"authorisation_location,omitempty"`
	// MaxPaymentMsat is the per-payment cap as the operator has it now. The
	// window cap is SpendLimitMsat below, which predates this.
	MaxPaymentMsat int64 `json:"max_payment_msat,omitempty"`
	// MiddlewareRegistered is whether LND has accepted the guard's RPC
	// middleware registration (§14, tna.1).
	//
	// §11's Tier 2 blocks sending while it is false, and the reason is not that
	// the cap would be unenforced — it is that the spend macaroon does not WORK:
	// a custom caveat with no middleware behind it is rejected by LND outright.
	// Saying so here is the difference between "sending is broken" and a page
	// that names the cause.
	MiddlewareRegistered bool `json:"middleware_registered"`
	// SpendUsedMsat is what the rolling 24 h window currently holds, and
	// SpendLimitMsat is the limit it is measured against — zero meaning no
	// limit is configured. The server may LEARN them; it cannot change them
	// (§6, §16).
	SpendUsedMsat  int64 `json:"spend_used_msat,omitempty"`
	SpendLimitMsat int64 `json:"spend_limit_msat,omitempty"`
	LNDReachable   bool  `json:"lnd_reachable"`
}

// ErrMacaroonRotated is returned by Serve when the node stopped accepting
// admin.macaroon. A single-file bind mount follows the inode, so the guard
// cannot re-read the replaced file in-process; the recovery is a bounded exit
// and a container restart (§6).
var ErrMacaroonRotated = errors.New("guard: lnd rejected admin.macaroon; the mount needs re-resolving")

// ReceivePermissions are the five RPC methods a complete zap receiver needs,
// and the only five the receive macaroon grants (§6). URI-scoped: entity:action
// would grant far more — `invoices:write` alone covers every invoice-mutating
// RPC, `offchain:read` around thirty methods.
var ReceivePermissions = []string{
	"/lnrpc.Lightning/GetInfo",
	"/lnrpc.Lightning/AddInvoice",
	"/lnrpc.Lightning/LookupInvoice",
	"/lnrpc.Lightning/SubscribeInvoices",
	"/lnrpc.Lightning/ChannelBalance",
}

// The constraints every credential carries are NOT listed here as data.
//
// They were, once, as SpendCaveats and an empty ReceiveCaveats — and two lists
// are what let the two credentials drift apart until the receive macaroon had
// no caveats at all (§6, d46.26). The policy is now one function,
// Guard.credentialCaveats, applied to both, and lnd.RequireHardening is the one
// statement of what a hardened credential must carry.

// SendPaymentMethod is the one RPC that moves money, named ONCE.
//
// It is both a permission the spend macaroon grants and the method the hard cap
// prices (tna.1). Those were separate string literals for an afternoon, under a
// comment forbidding exactly that: if the URI ever moves, a second copy means
// the credential still grants it while the cap silently stops pricing it, and
// nothing fails. The drift §6 spent d46.26 removing, in one line.
const SendPaymentMethod = "/routerrpc.Router/SendPaymentV2"

// SpendPermissions are the three methods the spend macaroon grants (d24.1,
// widened by one in d24.4).
//
// TrackPaymentV2 is the crash-recovery path, so resolving an in-flight payment
// never depends on which macaroon happens to be loaded (§6).
//
// DecodePayReq joined them because §8's rejection ladder has to read an invoice
// BEFORE it reserves anything — the amount is what the budget and the ceiling
// are checked against, and malformed, expired and amountless invoices are all
// refused before a reservation exists. It is a pure function of its argument: it
// reveals nothing about the node, changes nothing, and grants no capability the
// two above do not already imply. A credential that may SEND a payment but may
// not read the invoice it is paying is not a line worth drawing — and the
// alternative was a second bolt11 parser in this repo, which would be a second
// opinion about where money goes (ADR 0001 keeps the LND module out of go.mod).
var SpendPermissions = []string{
	SendPaymentMethod,
	"/routerrpc.Router/TrackPaymentV2",
	"/lnrpc.Lightning/DecodePayReq",
}
