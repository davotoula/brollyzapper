package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/logging"
)

// SocketClient is the server's side of the socket. It implements
// lnd.CredentialBroker, which is the consumer-defined interface internal/lnd
// declares — the dependency runs server -> guard, and internal/lnd never
// imports this package (§3).
type SocketClient struct {
	path  string
	relay AuditRelay
}

// AuditRelay carries the guard's security events to whoever writes the durable
// trail.
//
// It is a callback rather than a store handle because internal/guard must not
// import internal/store — the guard writes to nothing the server owns, and an
// arch rule enforces it. The consumer-declared-interface convention pointed the
// same way: this file runs in the SERVER, and the only thing it needs is
// somewhere to put what the guard said (§12, §16, d46.18).
type AuditRelay func(ctx context.Context, events []logging.RelayedEvent)

// DiscardEvents throws the guard's security events away.
//
// It exists so that doing so is something a caller has to write down. Silently
// discarding them is not a degenerate case — it is exactly what d46.18 was, and
// a dependency that can be omitted by accident is the shape that produced it.
// Only tests driving the socket operations directly should use this.
func DiscardEvents(context.Context, []logging.RelayedEvent) {}

// NewSocketClient addresses the guard's socket in the shared credential volume.
// relay is required; pass DiscardEvents to discard deliberately.
func NewSocketClient(socketPath string, relay AuditRelay) *SocketClient {
	if relay == nil {
		relay = DiscardEvents
	}
	return &SocketClient{path: socketPath, relay: relay}
}

// RequestReceiveBake asks the guard to bake the receive-only macaroon.
func (c *SocketClient) RequestReceiveBake(ctx context.Context) error {
	_, err := c.call(ctx, Request{Op: OpBakeReceive})
	return err
}

// RequestSpendBake asks the guard to bake the spend macaroon — the second half
// of "Enable sending". The permission list is compiled into the guard; this
// says which operation to run and nothing else (§6).
//
// IT CONSULTS THE LATCH, NOT THE ENVIRONMENT (`06v`). On a fresh install the
// guard refuses this until the operator has thrown the latch through the
// ceremony above, so a compromised server calling it directly gets nowhere.
func (c *SocketClient) RequestSpendBake(ctx context.Context) error {
	_, err := c.call(ctx, Request{Op: OpBakeSpend})
	return err
}

// RequestSpendRevoke asks the guard to revoke the spend macaroon — "Disable
// sending". It carries no root key id, deliberately: the guard revokes only
// what it recorded at bake time, so a compromised server cannot point
// DeleteMacaroonID at another app's key (§6).
func (c *SocketClient) RequestSpendRevoke(ctx context.Context) error {
	_, err := c.call(ctx, Request{Op: OpRevokeSpend})
	return err
}

// RequestAuthorisation asks the guard to issue a one-time grant for a loosening
// and write it where only the operator can read it (`06v`, Ruling 3).
//
// IT RETURNS NO CODE, and cannot: the guard writes the code into a volume this
// container has no mount for, and a return value would be the easiest possible
// way to hand it back to the thing it is meant to keep out. What comes back is
// success or a refusal — a change that is not a loosening is refused here rather
// than granted a ceremony it does not need.
func (c *SocketClient) RequestAuthorisation(ctx context.Context, change Change) error {
	_, err := c.call(ctx, Request{Op: OpRequestAuthorisation, Change: &change})
	return err
}

// ApplyChange moves one operator control, relaying the operator's code.
//
// The SERVER DOES NOT DECIDE whether a code is needed. It passes what it has —
// empty when the operator has not been asked for one — and the guard refuses
// with ErrAuthorisationRequired if the change turns out to be a loosening.
// Deciding here would be a compromised server deciding, and every one of its own
// changes would be a tightening.
func (c *SocketClient) ApplyChange(ctx context.Context, change Change, code string) error {
	_, err := c.call(ctx, Request{Op: OpApplyChange, Change: &change, Code: code})
	return err
}

// Status reports what the guard knows about the server's credentials.
func (c *SocketClient) Status(ctx context.Context) (lnd.BrokerStatus, error) {
	resp, err := c.call(ctx, Request{Op: OpStatus})
	if err != nil {
		return lnd.BrokerStatus{}, err
	}
	if resp.Status == nil {
		return lnd.BrokerStatus{}, errors.New("guard: status response carried no status")
	}
	return lnd.BrokerStatus{
		ReceiveMacaroonPresent:     resp.Status.ReceiveMacaroonPresent,
		SpendMacaroonPresent:       resp.Status.SpendMacaroonPresent,
		ReceiveExpiry:              resp.Status.ReceiveExpiry,
		SpendExpiry:                resp.Status.SpendExpiry,
		SpendRootKeyListed:         resp.Status.SpendRootKeyListed,
		SpendRootKeyChecked:        resp.Status.SpendRootKeyChecked,
		SpendRootKeyRecorded:       resp.Status.SpendRootKeyRecorded,
		SendingPermitted:           resp.Status.SendingPermitted,
		SendingAllowedByDeployment: resp.Status.SendingAllowedByDeployment,
		SendingLatched:             resp.Status.SendingLatched,
		AuthorisationPending:       resp.Status.AuthorisationPending,
		AuthorisationExpiresAt:     resp.Status.AuthorisationExpiresAt,
		AuthorisationChange:        resp.Status.AuthorisationChange,
		AuthorisationControl:       resp.Status.AuthorisationControl,
		AuthorisationMsat:          resp.Status.AuthorisationMsat,
		AuthorisationLocation:      resp.Status.AuthorisationLocation,
		MaxPaymentMsat:             resp.Status.MaxPaymentMsat,
		MiddlewareRegistered:       resp.Status.MiddlewareRegistered,
		SpendUsedMsat:              resp.Status.SpendUsedMsat,
		SpendLimitMsat:             resp.Status.SpendLimitMsat,
		LNDReachable:               resp.Status.LNDReachable,
	}, nil
}

func (c *SocketClient) call(ctx context.Context, req Request) (Response, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", c.path)
	if err != nil {
		return Response{}, fmt.Errorf("guard: dialling %s: %w", c.path, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(socketTimeout))
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, fmt.Errorf("guard: sending %s: %w", req.Op, err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("guard: reading the answer to %s: %w", req.Op, err)
	}
	// Before the error check: the guard reports its events on every answer, and
	// a failed operation is exactly when the trail matters most.
	if len(resp.Events) > 0 {
		c.relay(ctx, resp.Events)
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}
