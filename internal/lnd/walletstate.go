package lnd

import (
	"context"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
)

// WalletState is the stage LND reports itself in, as its State service names it.
//
// A VALUE, carried to the Node page as one — never a sentence (the rule `20i.3`
// set for CredentialAddress). The names are LND's own enum names, so a state
// this build has never heard of still arrives as something an operator can look
// up, and AdmitsCalls reads it as "not ready".
type WalletState string

// The values LND v0.21.2-beta defines (stateservice.proto). The empty string is
// "not asked, or could not ask".
const (
	WalletNonExisting    WalletState = "NON_EXISTING"
	WalletLocked         WalletState = "LOCKED"
	WalletUnlocked       WalletState = "UNLOCKED"
	WalletRPCActive      WalletState = "RPC_ACTIVE"
	WalletServerActive   WalletState = "SERVER_ACTIVE"
	WalletWaitingToStart WalletState = "WAITING_TO_START"
)

// AdmitsCalls reports whether a node in this state lets a Lightning RPC through
// to the macaroon check at all.
//
// This is what makes a refusal countable (dqd). LND's state interceptor runs
// BEFORE its macaroon interceptor and answers every other stage with a plain
// error — code Unknown, exactly the code it rejects a macaroon with — so a
// locked wallet and a rotated macaroon are the same answer on the wire, and only
// the node's stage tells them apart. The two admitted states are the ones
// checkRPCState passes (rpcperms/interceptor.go, v0.21.2-beta); RPC_ACTIVE
// counts as well as SERVER_ACTIVE because a node in it answers GetInfo and
// rejects a bad macaroon like any other.
//
// Would change if LND adds a stage that admits calls; until this build knows its
// name, such a node reads as not ready and a rotation during it is not counted.
func (s WalletState) AdmitsCalls() bool {
	return s == WalletRPCActive || s == WalletServerActive
}

// GetState asks the node which stage it is in.
//
// OVER ITS OWN CONNECTION, with no macaroon: LND exempts the State service from
// both the macaroon check and the state check (rpcperms/interceptor.go,
// macaroonWhitelist and checkRPCState), so it answers in every stage and
// whatever the macaroon file holds. The main connection could not ask it — its
// per-RPC credential reads the macaroon for every call and fails the call
// client-side when the file is absent, which is precisely the case the question
// has to be answerable in.
//
// It moves no connection state: the node's stage is not an answer about the
// credential.
func (c *Client) GetState(ctx context.Context) (WalletState, error) {
	conn, err := c.stateConnection()
	if err != nil {
		return "", err
	}
	resp, err := lnrpc.NewStateClient(conn).GetState(ctx, &lnrpc.GetStateRequest{})
	if err != nil {
		return "", err
	}
	return WalletState(resp.GetState().String()), nil
}
