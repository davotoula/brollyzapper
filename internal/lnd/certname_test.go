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
	path := filepath.Join(t.TempDir(), "tls.cert")
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
func TestThePreflightDeclinesWhatItCannotRead(t *testing.T) {
	t.Parallel()
	good := writeCert(t, []string{"localhost"}, []string{"127.0.0.1"})
	notPEM := filepath.Join(t.TempDir(), "tls.cert")
	if err := os.WriteFile(notPEM, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	badDER := filepath.Join(t.TempDir(), "tls.cert")
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
	// A REAL listener, so "nothing connected" is a measurement rather than the
	// absence of a service. It accepts in the background and counts.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer listener.Close()
	connected := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connected <- struct{}{}
			conn.Close()
		}
	}()

	dir := t.TempDir()
	macaroon := filepath.Join(dir, "admin.macaroon")
	if err := os.WriteFile(macaroon, []byte("not-a-real-macaroon"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 127.0.0.1 is what we dial; the certificate names only a name, so the
	// address is absent from it.
	cert := writeCert(t, []string{"lnd"}, nil)
	client := New(listener.Addr().String(), FileCredentials(cert, macaroon), Options{})
	t.Cleanup(func() { _ = client.Close() })

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

	select {
	case <-connected:
		t.Error("something connected to the node before the certificate was checked; the " +
			"preflight is meant to run before any I/O")
	case <-time.After(100 * time.Millisecond):
	}
}

// And the state must not move to relink, because a re-bake cannot fix a
// certificate. recordState is what asks the guard to bake again, and an
// operator whose Node page said "relink" would press a button for ever.
func TestACertificateMismatchDoesNotAskForAReBake(t *testing.T) {
	t.Parallel()
	client := New("10.61.7.2:10009", FileCredentials("/nonexistent", "/nonexistent"), Options{})
	if got := client.recordState(&CertificateNameError{Dialled: "10.61.7.2"}); got {
		t.Error("a certificate-name mismatch asked the guard to re-bake; a fresh macaroon " +
			"carries the same caveats and cannot change what the certificate names")
	}
	if got := client.State(); got == StateRelink {
		t.Errorf("State = %q after a certificate-name mismatch; the Node page would offer "+
			"Re-link for a problem re-linking cannot fix", got)
	}
}
