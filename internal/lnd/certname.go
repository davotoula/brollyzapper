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
//
// ITS MESSAGE NAMES INTERNAL ADDRESSES — the dial host and every name in the
// node's certificate — so it is for the operator's log and the operator's log
// only. Nothing renders Error() on a page, and the public LNURL callback cannot:
// it shows a reason only for *lnurl.Rejection, and everything else takes the
// branch whose comment reads "the caller learns that it failed, never why".
// A future author reaching for this text on a page is the thing to stop.
//
// THE ADMIN PANEL READS THE FIELDS, NOT THE SENTENCE (`20i.11`).
// internal/preflight's certificate row writes its own copy from Dialled and
// Directive, behind the sign-in, and never shows Names: the edit is the part an
// operator acts on, and the certificate's contents are the part a log is for.
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
	return fmt.Sprintf("lnd: the node's certificate does not name %s; it names %s. "+
		"Add %s to lnd.conf, delete tls.cert and tls.key so LND regenerates them, "+
		"restart LND, then restart the guard", e.Dialled, names, e.Directive())
}

// Directive is the lnd.conf line that makes the certificate name the dial host:
// tlsextraip for an address, tlsextradomain for a name.
//
// A METHOD, so the log's sentence and the Security panel's copy cannot choose
// differently — the choice is the part an operator could get wrong, and two
// copies of it is how one of them would.
func (e *CertificateNameError) Directive() string {
	if _, err := netip.ParseAddr(e.Dialled); err == nil {
		return "tlsextraip=" + e.Dialled
	}
	return "tlsextradomain=" + e.Dialled
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

// verifyCertificateNames is CertificateNamesMatch as an error, for connection().
//
// NOT a plain `return CertificateNamesMatch(...)`: a nil *CertificateNameError
// in an error interface is not a nil error, and connection() would then refuse
// every certificate that passed.
func verifyCertificateNames(certPath, address string) error {
	if err := CertificateNamesMatch(certPath, address); err != nil {
		return err
	}
	return nil
}

// CertificateNamesMatch reports whether certPath names the host in address, as
// nil or the typed mismatch.
//
// connection() asks it before every dial, as the fail-fast; internal/preflight
// asks it for the Security panel (`20i.11`), which is the surface — one
// decision, read twice, rather than a second check that could come to disagree.
//
// It returns nil for anything it cannot decide — an unreadable file, a
// malformed address — because those are OTHER failures with their own
// diagnoses, and the one thing worse than no hint is a confident wrong one.
// gRPC and the existing "loading %s" error still report them.
func CertificateNamesMatch(certPath, address string) *CertificateNameError {
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
	// THE FIRST BLOCK, and LND's tls.cert is a single self-signed leaf, so that
	// is the leaf. Were it ever a chain, the first block might not be the leaf
	// and the HINT could name the wrong certificate's SANs — it could not
	// weaken anything, because gRPC verifies the real chain either way, but it
	// could send an operator looking in the wrong place. If LND starts shipping
	// a chain here, this needs to pick the leaf rather than the first block.
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
