package imap

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

const globalTLSTestCN = "global-tls-manager.test"

// globalTLSTestConfig stands in for the config the global [tls] manager hands
// to a server: a certificate recognizable by its common name.
func globalTLSTestConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: globalTLSTestCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
}

func newGlobalTLSTestServer(t *testing.T, opts IMAPServerOptions) (*IMAPServer, string, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	opts.AppendLimit = DefaultAppendLimit
	opts.MaxConnections = 10
	opts.Config = &config.Config{}
	srv, err := New(ctx, "global-tls", "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, opts)
	return srv, addr, err
}

// dialImplicitTLS expects an implicit-TLS listener and returns the common
// name of the certificate it presented.
func dialImplicitTLS(t *testing.T, addr string) string {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls = true must listen with TLS, but the TLS handshake failed: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if line, err := bufio.NewReader(conn).ReadString('\n'); err != nil || !strings.HasPrefix(line, "* OK") {
		t.Fatalf("greeting over TLS = %q, %v", line, err)
	}
	return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
}

// tls = true with no per-server certificate files uses the global [tls]
// manager's config, as config.toml.example documents (#224).
func TestGlobalTLSConfig_ImplicitTLS(t *testing.T) {
	srv, addr, err := newGlobalTLSTestServer(t, IMAPServerOptions{
		TLS:       true,
		TLSConfig: globalTLSTestConfig(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serveReloadTestServer(t, srv, addr)

	if cn := dialImplicitTLS(t, addr); cn != globalTLSTestCN {
		t.Errorf("served certificate CN = %q, want the global one %q", cn, globalTLSTestCN)
	}
}

// With the global [tls] manager enabled, per-server certificate files are
// ignored, as config.toml.example documents (#224).
func TestGlobalTLSConfig_PreferredOverServerFiles(t *testing.T) {
	srv, addr, err := newGlobalTLSTestServer(t, IMAPServerOptions{
		TLS:         true,
		TLSConfig:   globalTLSTestConfig(t),
		TLSCertFile: "../../testdata/sora.crt",
		TLSKeyFile:  "../../testdata/sora.key",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serveReloadTestServer(t, srv, addr)

	if cn := dialImplicitTLS(t, addr); cn != globalTLSTestCN {
		t.Errorf("served certificate CN = %q, want the global one %q", cn, globalTLSTestCN)
	}
}

// The global config also backs a STARTTLS listener (#224).
func TestGlobalTLSConfig_StartTLS(t *testing.T) {
	srv, addr, err := newGlobalTLSTestServer(t, IMAPServerOptions{
		TLS:            true,
		TLSUseStartTLS: true,
		TLSConfig:      globalTLSTestConfig(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serveReloadTestServer(t, srv, addr)

	tlsConn, _ := dialSTARTTLS(t, addr)
	if cn := tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != globalTLSTestCN {
		t.Errorf("served certificate CN = %q, want the global one %q", cn, globalTLSTestCN)
	}
}

// The global config is not used by a server that did not ask for TLS.
func TestGlobalTLSConfig_IgnoredWithoutTLS(t *testing.T) {
	srv, addr, err := newGlobalTLSTestServer(t, IMAPServerOptions{TLSConfig: globalTLSTestConfig(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serveReloadTestServer(t, srv, addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "* OK") {
		t.Fatalf("plaintext greeting = %q, %v", line, err)
	}
	if caps := capabilities(t, conn, reader, "a"); strings.Contains(caps, "STARTTLS") {
		t.Errorf("tls = false must not offer STARTTLS, got %q", caps)
	}
}

// tls = true that resolves to no certificate must fail startup instead of
// listening in plaintext on the port meant for TLS (#224).
func TestTLSWithoutCertificate_FailsStartup(t *testing.T) {
	for name, opts := range map[string]IMAPServerOptions{
		"no files, no global config": {TLS: true},
		"starttls, no certificate":   {TLS: true, TLSUseStartTLS: true},
		"cert file without key file": {TLS: true, TLSCertFile: "../../testdata/sora.crt"},
		"key file without cert file": {TLS: true, TLSKeyFile: "../../testdata/sora.key"},
	} {
		t.Run(name, func(t *testing.T) {
			srv, _, err := newGlobalTLSTestServer(t, opts)
			if err == nil {
				srv.Close()
				t.Fatal("New succeeded with tls = true and no certificate; the server would listen in plaintext")
			}
			if !strings.Contains(err.Error(), "TLS") {
				t.Errorf("error does not name the TLS misconfiguration: %v", err)
			}
		})
	}
}
