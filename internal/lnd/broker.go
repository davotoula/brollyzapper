package lnd

import (
	"context"
	"time"
)

// CredentialBroker is what this package needs from the guard: a way to ask for
// a fresh receive macaroon when the node stops accepting the current one.
//
// It is declared here, by the consumer, on purpose. internal/guard supplies the
// implementation and cmd/brollyzapper wires the two together; internal/lnd must
// never import internal/guard, because the dependency runs the other way (§3).
type CredentialBroker interface {
	// RequestReceiveBake asks the guard to bake the receive-only macaroon and
	// write it to the credential volume.
	RequestReceiveBake(ctx context.Context) error
	// Status is what the server knows about its own credentials — the guard
	// holds admin, so anything needing macaroon:read is answered here (§6).
	Status(ctx context.Context) (BrokerStatus, error)
}

// BrokerStatus is the guard's answer to Status. It carries no macaroon: the
// server learns expiry and revocation state, never the credential itself (§6).
type BrokerStatus struct {
	ReceiveMacaroonPresent bool
	SpendMacaroonPresent   bool
	ReceiveExpiry          time.Time // zero when unknown or unset
	SpendExpiry            time.Time
	// SpendRootKeyRecorded reports whether the guard holds a root key id for the
	// spend macaroon at all. A macaroon on disk with no id behind it was not
	// baked by this guard, or was baked and revoked — a stale or stolen copy.
	SpendRootKeyRecorded bool
	// SpendRootKeyChecked reports whether the node was asked at all. Without it,
	// "not listed" and "could not ask" are the same false — and since d24.6 that
	// difference refuses a payment.
	SpendRootKeyChecked bool
	// SpendRootKeyListed reports whether the node still honours the root key
	// the spend macaroon was baked under. §6: this needs macaroon:read, which
	// the server's own macaroons deliberately do not have, so it arrives here.
	SpendRootKeyListed bool
	// SendingPermitted is whether the guard will mint spend authority on this
	// install if asked (tna.4, `06v`): the deployment ceiling and the operator's
	// stored latch, ANDed. The server learns it here rather than reading a copy
	// of its own environment — two sources for one fact means the page can offer
	// a button the guard will refuse.
	SendingPermitted bool
	// SendingAllowedByDeployment and SendingLatched are the two halves, for a
	// page that has to EXPLAIN a no. They are different sentences with different
	// remedies: the latch is an in-app ceremony, the ceiling is not fixable in
	// the app at all.
	SendingAllowedByDeployment bool
	SendingLatched             bool
	// AuthorisationPending, AuthorisationExpiresAt and AuthorisationChange are
	// the outstanding one-time grant (`06v`, Ruling 3). AuthorisationChange is
	// the GUARD's own sentence about the pending change, echoed so the page can
	// show what is being confirmed without composing it.
	//
	// THERE IS NO CODE HERE, and there must never be. The whole property is that
	// the server relays a code it cannot read; a field for it on this struct
	// would end that in one line.
	AuthorisationPending   bool
	AuthorisationExpiresAt time.Time
	AuthorisationChange    string
	// AuthorisationControl and AuthorisationMsat are the pending change in the
	// form the page needs to re-submit it. Neither is secret — the operator is
	// reading both in the guard's own file.
	AuthorisationControl string
	AuthorisationMsat    int64
	// AuthorisationLocation is where the DEPLOYMENT says the operator will find
	// the guard's file. §19 forbids the generic app assuming a deployment path,
	// so it arrives from the guard and is rendered as given.
	AuthorisationLocation string
	// MaxPaymentMsat is §6's per-payment cap as the operator has it now. The
	// window cap is SpendLimitMsat below.
	MaxPaymentMsat int64
	// MiddlewareRegistered is whether the guard is registered with LND as an RPC
	// middleware (tna.1). While it is false the spend macaroon does not work at
	// all — LND rejects a custom caveat with no middleware behind it — so §11
	// blocks sending and the page says why.
	MiddlewareRegistered bool
	// SpendUsedMsat and SpendLimitMsat are §6's rolling 24 h window as the guard
	// sees it. The server may display them; it cannot change them.
	SpendUsedMsat  int64
	SpendLimitMsat int64
	LNDReachable   bool
}
