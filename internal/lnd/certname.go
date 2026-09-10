package lnd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

// CertificateNameError is the dial address being absent from LND's certificate.
//
// WHY THIS IS CHECKED HERE AND NOT LEFT TO gRPC. grpc.NewClient is LAZY: it
// verifies nothing at construction, so the mismatch surfaces at the first RPC —
// and by then it is a codes.Unavailable status whose message is a flattened
// string, with the typed *x509.HostnameError long gone. Matching on that string
// is the thing this package must never do, and the operator meanwhile has an
// error that names a TLS handshake for a problem whose remedy is two lines of
// lnd.conf.
//
// So the certificate is verified against the dial host BEFORE the connection is
// built, where the answer is still typed. This is a PREFLIGHT, not a
// replacement: gRPC's own verification still runs on every connection, and a
// certificate that passes here can still fail there for any other reason.
type CertificateNameError struct {
	// Dialled is the host out of LND_ADDRESS, without the port.
	Dialled string
	// Names is what the certificate does name — its DNS names and IP addresses,
	// in the order x509 holds them. Reported because it is the half an operator
	// cannot see without openssl, and it is what tells them whether the address
	// they chose was ever going to work.
	Names []string
}

func (e *CertificateNameError) Error() string {
	names := "nothing"
	if len(e.Names) > 0 {
		names = strings.Join(e.Names, ", ")
	}
	// ONE DIRECTIVE, NOT A CHOICE. tlsextraip takes an address and
	// tlsextradomain takes a name, and which one the operator needs is decided
	// by what they put in LND_ADDRESS — so it is decided here rather than
	// offered as a pair for them to pick from at the moment they are least able
	// to.
	directive := "tlsextradomain"
	if _, err := netip.ParseAddr(e.Dialled); err == nil {
		directive = "tlsextraip"
	}
	return fmt.Sprintf("lnd: the node's certificate does not name %s; it names %s. "+
		"Add %s=%s to lnd.conf, delete tls.cert and tls.key so LND regenerates them, "+
		"restart LND, then restart the guard", e.Dialled, names, directive, e.Dialled)
}

// certificateNames is the DNS names and IP addresses a certificate carries.
func certificateNames(cert *x509.Certificate) []string {
	names := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	names = append(names, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	return names
}

// verifyCertificateNames reports whether certPath names the host in address.
//
// It returns nil for anything it cannot decide — an unreadable file, a
// malformed address — because those are OTHER failures with their own
// diagnoses, and the one thing worse than no hint is a confident wrong one.
// gRPC and the existing "loading %s" error still report them.
func verifyCertificateNames(certPath, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// internal/config parses LND_ADDRESS as host:port and refuses anything
		// else, so this is unreachable from a configured process. A test or a
		// future caller that passes a bare host gets no preflight rather than a
		// diagnosis drawn from a shape this cannot read.
		return nil
	}
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil // connection() reports this itself, with the path
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	if err := cert.VerifyHostname(host); err != nil {
		return &CertificateNameError{Dialled: host, Names: certificateNames(cert)}
	}
	return nil
}
