package lnd

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Spec §11 and ADR 0001: the macaroon travels as a per-RPC credential, and this
// method is the only thing stopping gRPC from handing it to a plaintext
// connection. Returning false is a one-word change with no visible symptom, so
// it gets its own assertion.
func TestMacaroonCredentialRequiresTransportSecurity(t *testing.T) {
	cred := macaroonCredential{source: VolumeCredentials(t.TempDir(), ReceiveMacaroon)}
	if !cred.RequireTransportSecurity() {
		t.Error("RequireTransportSecurity() = false; the macaroon could then be sent in the clear")
	}
}

func TestMacaroonCredentialSendsHexUnderTheMacaroonKey(t *testing.T) {
	dir := t.TempDir()
	raw := []byte{0x02, 0x01, 0x03, 0xff, 0x00}
	if err := os.WriteFile(filepath.Join(dir, ReceiveMacaroon), raw, 0o600); err != nil {
		t.Fatalf("writing macaroon: %v", err)
	}
	cred := macaroonCredential{source: VolumeCredentials(dir, ReceiveMacaroon)}

	md, err := cred.GetRequestMetadata(t.Context())
	if err != nil {
		t.Fatalf("GetRequestMetadata: %v", err)
	}
	if len(md) != 1 {
		t.Errorf("metadata = %v, want exactly one entry", md)
	}
	if got := md["macaroon"]; got != hex.EncodeToString(raw) {
		t.Errorf("metadata[macaroon] = %q, want %q", got, hex.EncodeToString(raw))
	}
}

func TestMacaroonCredentialReportsNotLinkedRatherThanSendingNothing(t *testing.T) {
	cred := macaroonCredential{source: VolumeCredentials(t.TempDir(), ReceiveMacaroon)}
	if _, err := cred.GetRequestMetadata(t.Context()); !errors.Is(err, ErrNotLinked) {
		t.Errorf("GetRequestMetadata with no macaroon = %v, want ErrNotLinked", err)
	}
}

// An empty file is a half-written credential, not a credential.
func TestAnEmptyMacaroonIsNotLinked(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ReceiveMacaroon), nil, 0o600); err != nil {
		t.Fatalf("writing macaroon: %v", err)
	}
	vol := VolumeCredentials(dir, ReceiveMacaroon)
	if _, err := vol.Macaroon(); !errors.Is(err, ErrNotLinked) {
		t.Errorf("read of an empty macaroon = %v, want ErrNotLinked", err)
	}
}

func TestBackoffDoublesAndCaps(t *testing.T) {
	const min, max = 1, 8
	want := []int{1, 2, 4, 8, 8, 8}
	for attempt, expected := range want {
		if got := backoffDelay(attempt, min, max); int(got) != expected {
			t.Errorf("backoffDelay(%d) = %d, want %d", attempt, got, expected)
		}
	}
}
