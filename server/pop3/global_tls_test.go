package pop3

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

func newGlobalTLSTestServer(t *testing.T, opts POP3ServerOptions) (*POP3Server, string, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	opts.CommandTimeout = time.Minute
	opts.MaxConnections = 100
	opts.Config = &config.Config{}
	s, err := New(ctx, "global-tls", "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, opts)
	return s, addr, err
}

// startGlobalTLSTestServer starts the server through Start and waits until
// its listener accepts.
func startGlobalTLSTestServer(t *testing.T, opts POP3ServerOptions) string {
	t.Helper()
	s, addr, err := newGlobalTLSTestServer(t, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	errChan := make(chan error, 1)
	go s.Start(errChan)
	t.Cleanup(s.Close)
	for deadline := time.Now().Add(3 * time.Second); ; {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
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
	if line, err := bufio.NewReader(conn).ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("greeting over TLS = %q, %v", line, err)
	}
	return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
}

// tls = true with no per-server certificate files uses the global [tls]
// manager's config, as config.toml.example documents (#224).
func TestGlobalTLSConfig_ImplicitTLS(t *testing.T) {
	addr := startGlobalTLSTestServer(t, POP3ServerOptions{
		TLS:       true,
		TLSConfig: globalTLSTestConfig(t),
	})

	if cn := dialImplicitTLS(t, addr); cn != globalTLSTestCN {
		t.Errorf("served certificate CN = %q, want the global one %q", cn, globalTLSTestCN)
	}
}

// With the global [tls] manager enabled, per-server certificate files are
// ignored, as config.toml.example documents (#224).
func TestGlobalTLSConfig_PreferredOverServerFiles(t *testing.T) {
	addr := startGlobalTLSTestServer(t, POP3ServerOptions{
		TLS:         true,
		TLSConfig:   globalTLSTestConfig(t),
		TLSCertFile: "../../testdata/sora.crt",
		TLSKeyFile:  "../../testdata/sora.key",
	})

	if cn := dialImplicitTLS(t, addr); cn != globalTLSTestCN {
		t.Errorf("served certificate CN = %q, want the global one %q", cn, globalTLSTestCN)
	}
}

// The global config also backs an STLS listener (#224).
func TestGlobalTLSConfig_StartTLS(t *testing.T) {
	addr := startGlobalTLSTestServer(t, POP3ServerOptions{
		TLS:            true,
		TLSUseStartTLS: true,
		TLSConfig:      globalTLSTestConfig(t),
	})

	tlsConn, _ := dialSTLS(t, addr)
	if cn := tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != globalTLSTestCN {
		t.Errorf("served certificate CN = %q, want the global one %q", cn, globalTLSTestCN)
	}
}

// The global config is not used by a server that did not ask for TLS.
func TestGlobalTLSConfig_IgnoredWithoutTLS(t *testing.T) {
	addr := startGlobalTLSTestServer(t, POP3ServerOptions{TLSConfig: globalTLSTestConfig(t)})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("plaintext greeting = %q, %v", line, err)
	}
	if caps := readCapa(t, conn, reader); strings.Contains(caps, "STLS") {
		t.Errorf("tls = false must not offer STLS, got:\n%s", caps)
	}
}

// tls = true that resolves to no certificate must fail startup instead of
// listening in plaintext on the port meant for TLS (#224).
func TestTLSWithoutCertificate_FailsStartup(t *testing.T) {
	for name, opts := range map[string]POP3ServerOptions{
		"no files, no global config": {TLS: true},
		"starttls, no certificate":   {TLS: true, TLSUseStartTLS: true},
		"cert file without key file": {TLS: true, TLSCertFile: "../../testdata/sora.crt"},
		"key file without cert file": {TLS: true, TLSKeyFile: "../../testdata/sora.key"},
	} {
		t.Run(name, func(t *testing.T) {
			s, _, err := newGlobalTLSTestServer(t, opts)
			if err == nil {
				s.Close()
				t.Fatal("New succeeded with tls = true and no certificate; the server would listen in plaintext")
			}
			if !strings.Contains(err.Error(), "TLS") {
				t.Errorf("error does not name the TLS misconfiguration: %v", err)
			}
		})
	}
}
