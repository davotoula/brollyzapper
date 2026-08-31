package lnd

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// The credential volume's contents, written by the guard (spec §6).
const (
	CertFile        = "tls.cert"
	ReceiveMacaroon = "recv.macaroon"
	SpendMacaroon   = "spend.macaroon"
)

// ErrNotLinked means the guard has not written the credentials yet. It is a
// state, not a failure: the guard starts first via depends_on, but ordering is
// not a guarantee, and the server must never exit over it (§6, §11).
var ErrNotLinked = errors.New("lnd: node credentials are not present yet")

// CredentialSource is where a client gets its TLS certificate and its macaroon.
//
// There are two: the server reads a credential volume the guard writes, and the
// guard reads the two files bind-mounted from LND's data directory. The dial
// path is identical, which is the point — TLS verification and the per-RPC
// credential must not have two implementations that can drift apart.
type CredentialSource interface {
	// CertPath is the file TLS is verified against.
	CertPath() string
	// Macaroon is the serialised macaroon, or ErrNotLinked if it is not there
	// yet.
	Macaroon() ([]byte, error)
	// Ready reports whether both are present.
	Ready() bool
}

// VolumeCredentials reads a named macaroon out of the credential volume the
// guard writes (spec §6). Every read goes to disk: the files are under a
// kilobyte, the guard rewrites them by rename, and reading them fresh is what
// makes "reloads on change" true by construction rather than by
// cache-invalidation logic.
func VolumeCredentials(dir, macaroonName string) CredentialSource {
	return fileCredentials{certPath: filepath.Join(dir, CertFile), macaroonPath: filepath.Join(dir, macaroonName)}
}

// FileCredentials names the two files directly. The guard uses it for its
// single-file bind mounts of tls.cert and admin.macaroon (spec §6, §20).
func FileCredentials(certPath, macaroonPath string) CredentialSource {
	return fileCredentials{certPath: certPath, macaroonPath: macaroonPath}
}

// fileCredentials names the two files. Both fields are paths, not values —
// hence the suffixes, which are also what keeps them out of the arch rule that
// requires anything holding a secret to be a secret.String.
type fileCredentials struct {
	certPath     string
	macaroonPath string
}

func (c fileCredentials) CertPath() string { return c.certPath }

func (c fileCredentials) Macaroon() ([]byte, error) { return readCredential(c.macaroonPath) }

func (c fileCredentials) Ready() bool {
	if _, err := readCredential(c.certPath); err != nil {
		return false
	}
	_, err := c.Macaroon()
	return err == nil
}

func readCredential(path string) ([]byte, error) {
	name := filepath.Base(path)
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%s: %w", name, ErrNotLinked)
	case err != nil:
		return nil, fmt.Errorf("reading %s: %w", name, err)
	case len(data) == 0:
		return nil, fmt.Errorf("%s is empty: %w", name, ErrNotLinked)
	}
	return data, nil
}

// macaroonCredential attaches the macaroon to every RPC as gRPC per-call
// metadata.
//
// ADR 0001 means lnd's own macaroons package is unavailable, so this is our
// implementation of the same contract: metadata key "macaroon", value the hex
// encoding of the serialised macaroon.
type macaroonCredential struct {
	source CredentialSource
}

func (m macaroonCredential) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	raw, err := m.source.Macaroon()
	if err != nil {
		return nil, err
	}
	return map[string]string{"macaroon": hex.EncodeToString(raw)}, nil
}

// RequireTransportSecurity reports true, and must keep reporting true. It is
// the only thing stopping the macaroon from being handed to a plaintext
// connection, and returning false is a one-word change with no visible symptom.
func (m macaroonCredential) RequireTransportSecurity() bool { return true }
