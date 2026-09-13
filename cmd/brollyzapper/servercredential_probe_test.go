package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
)

// A credential the guard has not written — or that went away — is "no credential
// yet", never "the node refused it" (simplify review, `20i.21`).
//
// ONCE THE CONNECTION IS CACHED the sentinel stops arriving: grpc-go stringifies
// the per-RPC credential's error into an Unauthenticated status, which is exactly
// the code the server-credential row reads as a refusal. recordState asks the
// credential source for this reason; the probe must too, or a volume emptied by a
// restore tells the operator their node is refusing the app.
func TestAnAbsentReceiveMacaroonIsNotLinkedEvenOnACachedConnection(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, lndtest.Macaroon(t))
	creds := lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon)
	client := lnd.New(node.Address(), creds, lnd.Options{})
	t.Cleanup(func() { _ = client.Close() })
	probe := serverCredentialProbe(client, creds)

	if err := probe(t.Context()); err != nil {
		t.Fatalf("the first probe, with the credential present: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, lnd.ReceiveMacaroon)); err != nil {
		t.Fatal(err)
	}
	err := probe(t.Context())
	if !errors.Is(err, lnd.ErrNotLinked) {
		t.Errorf("with the receive macaroon gone the probe returned %v (auth failure: %v), want "+
			"ErrNotLinked — the row would tell the operator the node refused a credential that "+
			"does not exist", err, lnd.IsAuthFailure(err))
	}
}
