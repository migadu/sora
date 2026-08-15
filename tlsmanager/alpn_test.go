package tlsmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// acme.ALPNProto is advertised so a tls-alpn-01 validation can be answered, but it
// shares the listener with every mail client. It is safe only because the server's
// NextProtos is a preference list consulted in order and acme-tls/1 sits last: a
// client offering "imap" must still get "imap". Reordering the list would negotiate
// acme-tls/1 with real clients and break every connection, so the ordering is pinned
// here by handshaking against the lists the manager actually installs.

func negotiate(t *testing.T, serverProtos, clientProtos []string) string {
	t.Helper()

	cert := selfSignedCert(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   serverProtos,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Drive the handshake, then drop it; the client reads the result.
		_ = conn.(*tls.Conn).Handshake()
		conn.Close()
	}()

	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, // self-signed fixture; this test is about ALPN, not trust
		MinVersion:         tls.VersionTLS12,
		NextProtos:         clientProtos,
	})
	if err != nil {
		t.Fatalf("dial with client protocols %v: %v", clientProtos, err)
	}
	defer client.Close()

	state := client.ConnectionState()
	<-done
	return state.NegotiatedProtocol
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mail.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestACMEProtocolNeverWinsOverAClientProtocol is the regression guard: every protocol
// Sora serves must still be chosen on a listener that also advertises acme-tls/1.
func TestACMEProtocolNeverWinsOverAClientProtocol(t *testing.T) {
	for _, clientProto := range applicationProtocols {
		t.Run(clientProto, func(t *testing.T) {
			got := negotiate(t, acmeCapableProtocols(), []string{clientProto})
			if got != clientProto {
				t.Errorf("client offering %q negotiated %q: acme-tls/1 must never win over a protocol "+
					"Sora serves, or real clients get an ACME validation connection", clientProto, got)
			}
		})
	}
}

// TestACMEProtocolLosesToAClientProtocolWhenBothAreOffered is where the ordering
// actually bites. Go matches the server's preference list against the client's, so a
// client offering a single protocol gets it whatever the order. A client offering
// acme-tls/1 AND a real protocol is the case order decides - and no legitimate client
// does that, which is precisely why it must lose: negotiating acme-tls/1 hands out the
// tls-alpn-01 validation certificate to anything that asks for it.
func TestACMEProtocolLosesToAClientProtocolWhenBothAreOffered(t *testing.T) {
	for _, clientProto := range applicationProtocols {
		t.Run(clientProto, func(t *testing.T) {
			got := negotiate(t, acmeCapableProtocols(), []string{acme.ALPNProto, clientProto})
			if got != clientProto {
				t.Errorf("client offering [%q %q] negotiated %q, want %q: a client that names a real "+
					"protocol must never be answered with the ACME validation certificate",
					acme.ALPNProto, clientProto, got, clientProto)
			}
		})
	}
}

// TestACMEProtocolIsReachableForAValidator covers the other half: the ACME validator
// offers acme-tls/1 alone, and must be able to negotiate it or tls-alpn-01 can never
// succeed and every issuance burns a failed validation against the per-hostname limit.
func TestACMEProtocolIsReachableForAValidator(t *testing.T) {
	got := negotiate(t, acmeCapableProtocols(), []string{acme.ALPNProto})
	if got != acme.ALPNProto {
		t.Errorf("validator offering only %q negotiated %q, want %q", acme.ALPNProto, got, acme.ALPNProto)
	}
}

// TestACMEProtocolIsOrderedLast pins the property the two tests above depend on, so a
// reordering is reported as itself rather than as a puzzling negotiation failure.
func TestACMEProtocolIsOrderedLast(t *testing.T) {
	protocols := acmeCapableProtocols()
	if last := protocols[len(protocols)-1]; last != acme.ALPNProto {
		t.Errorf("last advertised protocol = %q, want %q: acme-tls/1 must be the least preferred entry", last, acme.ALPNProto)
	}
	for _, proto := range protocols[:len(protocols)-1] {
		if proto == acme.ALPNProto {
			t.Errorf("%q appears before the end of the preference list", acme.ALPNProto)
		}
	}
}

// TestFileProviderDoesNotAdvertiseACME keeps acme-tls/1 off listeners that never run an
// ACME validation: advertising it there is a protocol a client could select for nothing.
func TestFileProviderDoesNotAdvertiseACME(t *testing.T) {
	for _, proto := range applicationProtocols {
		if proto == acme.ALPNProto {
			t.Fatalf("applicationProtocols contains %q; the file provider serves no ACME validation", acme.ALPNProto)
		}
	}
}
