package guard

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"slices"
)

// rootKeyAttempts bounds the search for an unused root key id. The space is
// 2^64 and the node holds a handful of ids, so a collision is a curiosity —
// but §18 says the namespace is empty TODAY, which is not a reason to assume it
// stays so, and an id that silently reused another app's key would make our
// revoke take their credential with it.
const rootKeyAttempts = 8

// newRootKeyID picks a root key id the node is not already using.
//
// Never 0: that is LND's default, shared by every macaroon the node ships with,
// and deleting it would revoke admin.macaroon along with ours — which is the
// whole reason the receive credential needed its own key.
func (g *Guard) newRootKeyID(ctx context.Context) (uint64, error) {
	inUse, err := g.node.ListMacaroonIDs(ctx)
	if err != nil {
		// Reading the list is what makes a collision detectable; without it the
		// safe answer is to fail rather than guess.
		return 0, fmt.Errorf("guard: reading the node's root key ids: %w", err)
	}
	for range rootKeyAttempts {
		id, err := randomRootKeyID()
		if err != nil {
			return 0, err
		}
		if !slices.Contains(inUse, id) {
			return id, nil
		}
	}
	return 0, fmt.Errorf("guard: could not find an unused root key id in %d attempts",
		rootKeyAttempts)
}

func randomRootKeyID() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("guard: generating a root key id: %w", err)
	}
	id := binary.BigEndian.Uint64(buf[:])
	if id == 0 {
		// Astronomically unlikely, and the one value that must never be used.
		id = 1
	}
	return id, nil
}
