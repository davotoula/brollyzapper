package lnd_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/davotoula/brollyzapper/internal/lnd"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
	"github.com/davotoula/brollyzapper/internal/lnd/lnrpc"
)

// dqd: the guard asks the node's State service which stage it is in before it
// counts a refusal as a rejected credential, so the question has to be
// answerable in exactly the cases a credential question is not — the macaroon
// file missing, empty, or wrong.
//
// "GetState over the existing connection" is the wrong mechanism this pins: the
// dial-level per-RPC credential reads the macaroon for EVERY call on that
// connection and fails the call client-side when it cannot, so the probe would
// read "unknown" for the very case (ErrNotLinked) where the old trigger fired.
func TestGetStateAnswersWhateverTheMacaroonFileHolds(t *testing.T) {
	for name, write := range map[string]func(t *testing.T, path string){
		"absent": func(*testing.T, string) {},
		"empty":  func(t *testing.T, path string) { lndtest.WriteFile(t, path, nil) },
		"wrong":  func(t *testing.T, path string) { lndtest.WriteFile(t, path, []byte{0xad, 0xba, 0xd0}) },
	} {
		t.Run(name, func(t *testing.T) {
			node := lndtest.Start(t)
			node.SetRejectLikeLND(true)
			node.SetWalletState(lnrpc.WalletState_LOCKED)
			dir := t.TempDir()
			node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, nil)
			macaroon := filepath.Join(dir, "admin.macaroon")
			write(t, macaroon)
			client := lnd.New(node.Address(), lnd.FileCredentials(filepath.Join(dir, lnd.CertFile), macaroon),
				testOptions(nil))
			defer client.Close()

			got, err := client.GetState(t.Context())
			if err != nil {
				t.Fatalf("GetState with the macaroon file %s = %v; the State service needs no "+
					"macaroon, and a probe that cannot ask it cannot tell a locked wallet from a "+
					"rotation", name, err)
			}
			if got != lnd.WalletLocked {
				t.Errorf("GetState = %q, want %q", got, lnd.WalletLocked)
			}
			calls, withMacaroon := node.StateCalls()
			if calls != 1 || withMacaroon != 0 {
				t.Errorf("the node saw %d State calls, %d carrying a macaroon; want 1 and 0 — "+
					"the admin macaroon has no business on a call that does not need it",
					calls, withMacaroon)
			}
		})
	}
}

// Asking the node's stage is not an answer about the credential, so it must not
// move the state the Node page shows. A GetState that succeeded while the
// macaroon is absent would otherwise read as "ready".
func TestGetStateMovesNoConnectionState(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, nil)
	client := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), testOptions(nil))
	defer client.Close()

	if _, err := client.GetState(t.Context()); err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if got := client.State(); got != lnd.StateNotLinked {
		t.Errorf("State = %q after a GetState with no macaroon, want %q", got, lnd.StateNotLinked)
	}
}

// A node that is not there is a transport failure, not a state — the caller
// must be able to tell "could not ask" from any answer.
func TestGetStateAgainstNoNodeIsAnError(t *testing.T) {
	node := lndtest.Start(t)
	dir := t.TempDir()
	node.WriteCredentialVolume(t, dir, lnd.ReceiveMacaroon, nil)
	client := lnd.New("127.0.0.1:1", lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), testOptions(nil))
	defer client.Close()

	got, err := client.GetState(t.Context())
	if err == nil {
		t.Fatalf("GetState against nothing = %q, nil; want an error", got)
	}
	if lnd.IsCredentialRejected(err) {
		t.Errorf("GetState's failure to reach a node reads as a credential rejection: %v", err)
	}
	// And an unreadable certificate is an error too, never a state.
	if err := os.Remove(filepath.Join(dir, lnd.CertFile)); err != nil {
		t.Fatal(err)
	}
	fresh := lnd.New(node.Address(), lnd.VolumeCredentials(dir, lnd.ReceiveMacaroon), testOptions(nil))
	defer fresh.Close()
	if _, err := fresh.GetState(t.Context()); err == nil || errors.Is(err, lnd.ErrNotLinked) {
		t.Errorf("GetState with no tls.cert = %v; want the certificate error", err)
	}
}

// Only the two stages LND's state interceptor lets a Lightning RPC through in
// may count a refusal (rpcperms/interceptor.go, checkRPCState, v0.21.2-beta).
// Every other value — including one this build has never heard of — is a node
// that could not have looked at the macaroon.
func TestOnlyTheActiveStatesAdmitLightningCalls(t *testing.T) {
	for state, want := range map[lnd.WalletState]bool{
		lnd.WalletServerActive:   true,
		lnd.WalletRPCActive:      true,
		lnd.WalletLocked:         false,
		lnd.WalletUnlocked:       false,
		lnd.WalletNonExisting:    false,
		lnd.WalletWaitingToStart: false,
		lnd.WalletState("7"):     false,
		lnd.WalletState(""):      false,
	} {
		if got := state.AdmitsCalls(); got != want {
			t.Errorf("WalletState(%q).AdmitsCalls() = %v, want %v", state, got, want)
		}
	}
}
