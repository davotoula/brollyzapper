package lnd

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
)

// uriEntity is LND's PermissionEntityCustomURI: a permission that grants
// exactly one RPC method rather than the whole set an entity:action pair
// covers. Spec §6 — `invoices:write` alone grants every invoice-mutating RPC
// and `offchain:read` around thirty methods; five explicit URIs grant five.
const uriEntity = "uri"

// URIPermission builds the URI-scoped permission for one RPC method.
func URIPermission(method string) *lnrpc.MacaroonPermission {
	return &lnrpc.MacaroonPermission{Entity: uriEntity, Action: method}
}

// URIPermissions builds the permission list for a set of RPC methods.
func URIPermissions(methods []string) []*lnrpc.MacaroonPermission {
	permissions := make([]*lnrpc.MacaroonPermission, 0, len(methods))
	for _, method := range methods {
		permissions = append(permissions, URIPermission(method))
	}
	return permissions
}

// BakeMacaroon asks the node for a macaroon granting exactly permissions,
// under rootKeyID. It returns the serialised macaroon.
//
// Only the guard may call this: it is the one operation that needs
// admin.macaroon, and §3 puts admin only in the guard.
func (c *Client) BakeMacaroon(ctx context.Context, permissions []*lnrpc.MacaroonPermission, rootKeyID uint64) ([]byte, error) {
	client, err := c.lightning()
	if err != nil {
		return nil, c.observe(err)
	}
	baked, err := client.BakeMacaroon(ctx, &lnrpc.BakeMacaroonRequest{
		Permissions: permissions,
		RootKeyId:   rootKeyID,
	})
	if err := c.observe(err); err != nil {
		return nil, err
	}
	// LND returns the macaroon hex-encoded; the credential volume holds the
	// same binary form LND's own .macaroon files use.
	raw, err := hex.DecodeString(baked.Macaroon)
	if err != nil {
		return nil, fmt.Errorf("decoding the baked macaroon: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("the node returned an empty macaroon")
	}
	return raw, nil
}

// ListMacaroonIDs reports which root key ids the node still honours. It needs
// macaroon:read, which only the guard's admin credential has — the server
// learns this through the guard's Status call (§6).
func (c *Client) ListMacaroonIDs(ctx context.Context) ([]uint64, error) {
	client, err := c.lightning()
	if err != nil {
		return nil, c.observe(err)
	}
	ids, err := client.ListMacaroonIDs(ctx, &lnrpc.ListMacaroonIDsRequest{})
	if err := c.observe(err); err != nil {
		return nil, err
	}
	return ids.RootKeyIds, nil
}

// DeleteMacaroonID invalidates every macaroon baked under rootKeyID, instantly
// and permanently, regardless of who holds a copy. This is §6's kill switch.
func (c *Client) DeleteMacaroonID(ctx context.Context, rootKeyID uint64) (bool, error) {
	client, err := c.lightning()
	if err != nil {
		return false, c.observe(err)
	}
	deleted, err := client.DeleteMacaroonID(ctx, &lnrpc.DeleteMacaroonIDRequest{RootKeyId: rootKeyID})
	if err := c.observe(err); err != nil {
		return false, err
	}
	return deleted.Deleted, nil
}
