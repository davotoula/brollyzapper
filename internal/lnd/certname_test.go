package lnd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCert writes a self-signed certificate naming exactly what it is given,
// and returns its path. The point of the helper is that a certificate which
// does NOT name the dial host is one argument away.
func writeCert(t *testing.T, dnsNames []string, ips []string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	var addrs []net.IP
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("%q is not an IP; the fixture would name something else than intended", ip)
		}
		addrs = append(addrs, parsed)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake-lnd"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
		IPAddresses:           addrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	path := filepath.Join(t.TempDir(), CertFile)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing certificate: %v", err)
	}
	return path
}

// `20i.3` criterion 1. The operator's whole remedy is two lines of lnd.conf, and
// this is what puts it in front of them instead of a TLS handshake message.
func TestACertificateThatDoesNotNameTheDialledHostIsRefusedWithTheFix(t *testing.T) {
	t.Parallel()
	// The `20i.2` reproduction's shape: the node's certificate predates the
	// bridge, so it names the node's own address and not the one we dial.
	cert := writeCert(t, []string{"localhost", "lnd"}, []string{"127.0.0.1", "10.30.0.3"})

	err := verifyCertificateNames(cert, "10.61.7.2:10009")
	if err == nil {
		t.Fatal("a certificate naming neither the dialled address nor anything like it passed")
	}
	var nameErr *CertificateNameError
	if !errors.As(err, &nameErr) {
		t.Fatalf("error %v is not a *CertificateNameError; the hint is typed or it is not built", err)
	}
	if nameErr.Dialled != "10.61.7.2" {
		t.Errorf("Dialled = %q, want the host without the port", nameErr.Dialled)
	}
	for _, want := range []string{
		"10.61.7.2",                            // what was dialled
		"localhost, lnd, 127.0.0.1, 10.30.0.3", // what the certificate does name
		"tlsextraip=10.61.7.2",                 // the directive for an ADDRESS
		"delete tls.cert and tls.key",
		"restart LND",
		"restart the guard",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the hint does not carry %q, so the operator is missing a step:\n%s", want, err)
		}
	}
	// The pair it must NOT offer: a name directive for an address.
	if strings.Contains(err.Error(), "tlsextradomain") {
		t.Errorf("the hint offers tlsextradomain for an IP address, which LND will not "+
			"accept — it should name the one directive that applies:\n%s", err)
	}
}

// A certificate naming NOTHING is the degenerate case, and the sentence has to
// stay readable: "it names " with an empty list reads as a truncation, so the
// fallback says so in a word. Reachable — LND will not produce such a
// certificate, but a hand-made or truncated one is what an operator debugging
// this most plausibly has.
func TestACertificateNamingNothingSaysSo(t *testing.T) {
	t.Parallel()
	err := verifyCertificateNames(writeCert(t, nil, nil), "10.61.7.2:10009")
	if err == nil {
		t.Fatal("a certificate naming nothing at all verified against an address")
	}
	if !strings.Contains(err.Error(), "it names nothing") {
		t.Errorf("the hint reads as truncated rather than saying the certificate names "+
			"nothing:\n%s", err)
	}
}

// A HOSTNAME gets the other directive. Two fixtures, because the whole value of
// choosing for the operator is lost if it chooses the same one every time.
func TestADialledNameGetsTheDomainDirective(t *testing.T) {
	t.Parallel()
	cert := writeCert(t, []string{"localhost"}, []string{"127.0.0.1"})

	err := verifyCertificateNames(cert, "lnd.example.internal:10009")
	if err == nil {
		t.Fatal("a certificate naming neither the dialled name nor a wildcard passed")
	}
	if !strings.Contains(err.Error(), "tlsextradomain=lnd.example.internal") {
		t.Errorf("the hint does not name tlsextradomain for a hostname:\n%s", err)
	}
	if strings.Contains(err.Error(), "tlsextraip") {
		t.Errorf("the hint offers tlsextraip for a hostname:\n%s", err)
	}
}

// `20i.3` criterion 2, in both the shapes LND's own certificate uses.
func TestACertificateThatNamesTheHostPasses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, address string }{
		{"by IP", "10.30.0.3:10009"},
		{"by DNS name", "lnd:10009"},
		{"by loopback", "127.0.0.1:10009"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cert := writeCert(t, []string{"localhost", "lnd"}, []string{"127.0.0.1", "10.30.0.3"})
			if err := verifyCertificateNames(cert, tc.address); err != nil {
				t.Errorf("a certificate that names %s was refused: %v", tc.address, err)
			}
		})
	}
}

// The preflight decides nothing it cannot decide. Each of these is a DIFFERENT
// failure with its own diagnosis elsewhere, and a confident wrong hint is worse
// than none — so each must pass rather than invent a certificate-name verdict.
//
// ONLY THE FIRST ROW IS REACHABLE FROM connection(): credentials.NewClientTLSFromFile
// runs one line earlier and returns "loading %s" for an absent, non-PEM or
// non-DER file, so those three never reach here in the running process. They are
// kept as the FUNCTION's contract rather than the caller's, because the ordering
// that makes them unreachable is one line in another file — and if it ever moves,
// this is what says what the answer should be.
func TestThePreflightDeclinesWhatItCannotRead(t *testing.T) {
	t.Parallel()
	good := writeCert(t, []string{"localhost"}, []string{"127.0.0.1"})
	notPEM := filepath.Join(t.TempDir(), CertFile)
	if err := os.WriteFile(notPEM, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	badDER := filepath.Join(t.TempDir(), CertFile)
	if err := os.WriteFile(badDER,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, cert, address string }{
		{"an address with no port", good, "10.61.7.2"},
		{"a certificate file that is not there", filepath.Join(t.TempDir(), "absent"), "10.61.7.2:10009"},
		{"a file that is not PEM", notPEM, "10.61.7.2:10009"},
		{"PEM that is not a certificate", badDER, "10.61.7.2:10009"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := verifyCertificateNames(tc.cert, tc.address); err != nil {
				t.Errorf("the preflight produced a certificate-name verdict from %s, which "+
					"it cannot read: %v", tc.name, err)
			}
		})
	}
}

// `20i.3` criterion 1's load-bearing clause: BEFORE ANY RPC.
//
// This is the assertion the whole mechanism rests on, and the one a plant has
// to be able to break. grpc.NewClient does no I/O and verifies nothing, so
// without the preflight connection() returns a healthy *ClientConn for a
// certificate that can never verify, and the operator learns about it one RPC
// later as a flattened Unavailable status. Remove the preflight from
// connection() and this test goes red while every other test in this file
// still passes — they exercise verifyCertificateNames directly.
func TestTheDialIsRefusedBeforeAnythingConnects(t *testing.T) {
	t.Parallel()
	// NO LISTENER, and that is the point rather than a shortcut: grpc.NewClient
	// does no I/O at all, so a test that watched a socket for connections would
	// see none WITH the preflight and none without it — an observer that cannot
	// observe the thing it is named for. What distinguishes the two worlds is
	// whether connection() hands back a usable *grpc.ClientConn for a
	// certificate that can never verify, and that is what is asserted here.
	client := newTestClient(t, writeCert(t, []string{"lnd"}, nil), "127.0.0.1:1")

	conn, err := client.connection()
	if conn != nil {
		t.Error("connection() handed back a *grpc.ClientConn for a certificate that cannot " +
			"verify against the address it will be used with")
	}
	var nameErr *CertificateNameError
	if !errors.As(err, &nameErr) {
		t.Fatalf("connection() = %v, want a *CertificateNameError. grpc.NewClient verifies "+
			"nothing at construction, so without the preflight this returns nil and the "+
			"mismatch surfaces at the first RPC as an untyped status string", err)
	}
}

// newTestClient is a Client with real credential FILES, so Ready() is true and
// the paths under test are the ones a running process takes.
func newTestClient(t *testing.T, certPath, address string) *Client {
	t.Helper()
	macaroon := filepath.Join(t.TempDir(), "admin.macaroon")
	if err := os.WriteFile(macaroon, []byte("not-a-real-macaroon"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := New(address, FileCredentials(certPath, macaroon), Options{})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// The verdict is remembered for the life of the connection, and forgotten with
// it.
//
// A refused connection never populates c.conn, so without this every later RPC
// re-reads and re-parses tls.cert — on the public LNURL callback, in a state
// that lasts until the operator edits lnd.conf. Caching it must not cost the
// property the check was put in connection() for: a regenerated certificate is
// still picked up, at the next reconnect and no later.
func TestTheCertificateVerdictIsCachedUntilTheConnectionIsDropped(t *testing.T) {
	t.Parallel()
	certPath := writeCert(t, []string{"lnd"}, nil)
	client := newTestClient(t, certPath, "127.0.0.1:1")

	if _, err := client.connection(); err == nil {
		t.Fatal("the mismatched certificate was accepted; this test needs the refusal")
	}
	// Repair the file in place, as LND regenerating its certificate would.
	replaceCert(t, certPath, writeCert(t, nil, []string{"127.0.0.1"}))

	if _, err := client.connection(); err == nil {
		t.Error("the repaired certificate was picked up without a reconnect; the verdict is " +
			"supposed to last as long as the connection attempt it was made for, or every " +
			"RPC pays for a fresh read")
	}
	// reconnect() is what the stream's backoff calls, and it is what makes the
	// repair take effect.
	client.reconnect()
	if _, err := client.connection(); err != nil {
		t.Errorf("a repaired certificate was still refused after a reconnect, so fixing "+
			"lnd.conf would need a restart of the process: %v", err)
	}
}

// replaceCert overwrites dst with src's bytes, in place.
func replaceCert(t *testing.T, dst, src string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// And the state must not move to relink, because a re-bake cannot fix a
// certificate. recordState is what asks the guard to bake again, and an
// operator whose Node page said "relink" would press a button for ever.
func TestACertificateMismatchDoesNotAskForAReBake(t *testing.T) {
	t.Parallel()
	// REAL CREDENTIAL FILES. With absent ones, recordState takes its
	// !creds.Ready() branch and returns false before it ever looks at the error
	// — so this passed for any error at all, including one with nothing to do
	// with certificates, and would have gone on passing if the switch were
	// reordered so IsAuthFailure caught this first.
	client := newTestClient(t, writeCert(t, nil, []string{"127.0.0.1"}), "127.0.0.1:1")
	if !client.creds.Ready() {
		t.Fatal("the fixture's credentials are not Ready, so recordState would short-circuit " +
			"and this test would assert nothing about the error it is named for")
	}
	if got := client.recordState(&CertificateNameError{Dialled: "10.61.7.2"}); got {
		t.Error("a certificate-name mismatch asked the guard to re-bake; a fresh macaroon " +
			"carries the same caveats and cannot change what the certificate names")
	}
	if got := client.State(); got == StateRelink {
		t.Errorf("State = %q after a certificate-name mismatch; the Node page would offer "+
			"Re-link for a problem re-linking cannot fix", got)
	}
}
