//go:build integration

package tls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/imapproxy"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	lmtpproxy "github.com/migadu/sora/server/lmtpproxy"
	managesieveserver "github.com/migadu/sora/server/managesieve"
	managesieveproxy "github.com/migadu/sora/server/managesieveproxy"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/server/pop3proxy"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/server/userapi"
	"github.com/migadu/sora/server/userapiproxy"
	"github.com/migadu/sora/storage"
)

// listenerTLS is a [[server]] block's TLS settings plus the global [tls]
// manager's config, as cmd/sora hands them to every listener type.
type listenerTLS struct {
	certFile, keyFile string      // tls_cert_file, tls_key_file
	verify            bool        // tls_verify
	global            *tls.Config // the global [tls] manager's config; nil when [tls] is disabled
}

const (
	globalTLSCN = "global-tls.example.com" // the global [tls] certificate
	filesTLSCN  = "sora-test"              // the listener's own files (common.GenerateTestTLSCert)
	unusedPeer  = "127.0.0.1:1"            // a proxy's backend; never dialed, no client logs in
	testSecret  = "listener-tls-test-secret-0123456789abcdef"
)

// startListener starts one implicit-TLS listener of a type on addr. A start
// that fails sends its error on errc.
type startListener func(t *testing.T, name, addr string, l listenerTLS, errc chan error)

// tlsListenerTypes lists every [[server]] type that accepts TLS.
var tlsListenerTypes = []struct {
	typ   string
	start startListener
}{
	{"imap", func(t *testing.T, name, addr string, l listenerTLS, errc chan error) {
		srv, err := imap.New(testContext(t), name, "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, imap.IMAPServerOptions{
			TLS: true, TLSCertFile: l.certFile, TLSKeyFile: l.keyFile, TLSVerify: l.verify, TLSConfig: l.global,
			AppendLimit: imap.DefaultAppendLimit, MaxConnections: 10, Config: &config.Config{},
		})
		if err != nil {
			errc <- err
			return
		}
		t.Cleanup(srv.Close)
		go func() { errc <- srv.Serve(addr) }()
	}},
	{"pop3", func(t *testing.T, name, addr string, l listenerTLS, errc chan error) {
		srv, err := pop3.New(testContext(t), name, "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, pop3.POP3ServerOptions{
			TLS: true, TLSCertFile: l.certFile, TLSKeyFile: l.keyFile, TLSVerify: l.verify, TLSConfig: l.global,
			CommandTimeout: time.Minute, MaxConnections: 10, Config: &config.Config{},
		})
		if err != nil {
			errc <- err
			return
		}
		t.Cleanup(srv.Close)
		go srv.Start(errc)
	}},
	{"lmtp", func(t *testing.T, name, addr string, l listenerTLS, errc chan error) {
		srv, err := lmtpserver.New(testContext(t), name, "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, lmtpserver.LMTPServerOptions{
			TLS: true, TLSCertFile: l.certFile, TLSKeyFile: l.keyFile, TLSVerify: l.verify, TLSConfig: l.global,
			MaxConnections: 10,
		})
		if err != nil {
			errc <- err
			return
		}
		t.Cleanup(func() { srv.Close() })
		go srv.Start(errc)
	}},
	{"managesieve", func(t *testing.T, name, addr string, l listenerTLS, errc chan error) {
		srv, err := managesieveserver.New(testContext(t), name, "localhost", addr, &resilient.ResilientDatabase{}, managesieveserver.ManageSieveServerOptions{
			TLS: true, TLSCertFile: l.certFile, TLSKeyFile: l.keyFile, TLSVerify: l.verify, TLSConfig: l.global,
			MaxConnections: 10, Config: &config.Config{},
		})
		if err != nil {
			errc <- err
			return
		}
		t.Cleanup(srv.Close)
		go srv.Start(errc)
	}},
	{"imap_proxy", func(t *testing.T, name, addr string, l listenerTLS, errc chan error) {
		srv, err := imapproxy.New(testContext(t), &resilient.ResilientDatabase{}, "localhost", imapproxy.ServerOptions{
			Name: name, Addr: addr, RemoteAddrs: []string{unusedPeer},
			TLS: true, TLSCertFile: l.certFile, TLSKeyFile: l.keyFile, TLSVerify: l.verify, TLSConfig: l.global,
		})
		if err != nil {
			errc <- err
			return
		}
		t.Cleanup(func() { srv.Stop() })
		go func() { errc <- srv.Start() }()
	}},
	{"pop3_proxy", func(t *testing.T, name, addr string, l listenerTLS, errc chan error) {
		srv, err := pop3proxy.New(testContext(t), "localhost", addr, &resilient.ResilientDatabase{}, pop3proxy.POP3ProxyServerOptions{
			Name: name, RemoteAddrs: []string{unusedPeer},
			TLS: true, TLSCertFile: l.certFile, TLSKeyFile: l.keyFile, TLSVerify: l.verify, TLSConfig: l.global,
		})
		if err != nil {
			errc <- err
			return
		}
		t.Cleanup(func() { srv.Stop() })
		go func() { errc <- srv.Start() }()
	}},
	{"managesieve_proxy", func(t *testing.T, name, addr string, l listenerTLS, errc chan error) {
		srv, err := managesieveproxy.New(testContext(t), &resilient.ResilientDatabase{}, "localhost", managesieveproxy.ServerOptions{
			Name: name, Addr: addr, RemoteAddrs: []string{unusedPeer},
			TLS: true, TLSCertFile: l.certFile, TLSKeyFile: l.keyFile, TLSVerify: l.verify, TLSConfig: l.global,
		})
		if err != nil {
			errc <- err
			return
		}
		t.Cleanup(func() { srv.Stop() })
		go func() { errc <- srv.Start() }()
	}},
	{"lmtp_proxy", func(t *testing.T, name, addr string, l listenerTLS, errc chan error) {
		// The LMTP proxy accepts connections from trusted_proxies only.
		srv, err := lmtpproxy.New(testContext(t), &resilient.ResilientDatabase{}, "localhost", lmtpproxy.ServerOptions{
			Name: name, Addr: addr, RemoteAddrs: []string{unusedPeer}, TrustedProxies: []string{"127.0.0.0/8"},
			TLS: true, TLSCertFile: l.certFile, TLSKeyFile: l.keyFile, TLSVerify: l.verify, TLSConfig: l.global,
		})
		if err != nil {
			errc <- err
			return
		}
		t.Cleanup(func() { srv.Stop() })
		go func() { errc <- srv.Start() }()
	}},
	{"user_api_proxy", func(t *testing.T, name, addr string, l listenerTLS, errc chan error) {
		srv, err := userapiproxy.New(testContext(t), &resilient.ResilientDatabase{}, userapiproxy.ServerOptions{
			Name: name, Addr: addr, RemoteAddrs: []string{unusedPeer}, JWTSecret: testSecret,
			TLS: true, TLSCertFile: l.certFile, TLSKeyFile: l.keyFile, TLSVerify: l.verify, TLSConfig: l.global,
		})
		if err != nil {
			errc <- err
			return
		}
		t.Cleanup(func() { srv.Stop() })
		go func() { errc <- srv.Start() }()
	}},
	{"http_admin_api", func(t *testing.T, name, addr string, l listenerTLS, errc chan error) {
		srv, err := adminapi.New(&resilient.ResilientDatabase{}, adminapi.ServerOptions{
			Name: name, Addr: addr, APIKey: testSecret, Hostname: "localhost",
			TLS: true, TLSCertFile: l.certFile, TLSKeyFile: l.keyFile, TLSVerify: l.verify, TLSConfig: l.global,
		})
		if err != nil {
			errc <- err
			return
		}
		srv.Serve(testContext(t), errc)
	}},
	{"http_user_api", func(t *testing.T, name, addr string, l listenerTLS, errc chan error) {
		userapi.Start(testContext(t), &resilient.ResilientDatabase{}, userapi.ServerOptions{
			Name: name, Addr: addr, JWTSecret: testSecret,
			TLS: true, TLSCertFile: l.certFile, TLSKeyFile: l.keyFile, TLSVerify: l.verify, TLSConfig: l.global,
		}, errc)
	}},
}

// Every listener type that accepts TLS resolves its certificate source and
// tls_verify by the same rule (#416):
//   - with the global [tls] manager enabled, its certificate; the listener's
//     tls_cert_file/tls_key_file are then ignored, with a startup warning;
//   - otherwise the listener's own files;
//   - tls_verify = true requires a client certificate, whichever of the two
//     supplied the server's.
func TestListenerTLSSourceAndClientCertificates(t *testing.T) {
	certFile, keyFile, _ := common.GenerateTestTLSCert(t, nil, nil)
	global := globalTLSManagerConfig(t)
	files := listenerTLS{certFile: certFile, keyFile: keyFile}
	withVerify := func(l listenerTLS) listenerTLS { l.verify = true; return l }
	both := listenerTLS{certFile: certFile, keyFile: keyFile, global: global}

	cases := []struct {
		name           string
		tls            listenerTLS
		wantCN         string
		wantClientCert bool // tls_verify: a client without a certificate is refused
		wantWarning    bool // the ignored files are named at startup
	}{
		{name: "global", tls: listenerTLS{global: global}, wantCN: globalTLSCN},
		{name: "global+tls_verify", tls: listenerTLS{global: global, verify: true}, wantCN: globalTLSCN, wantClientCert: true},
		{name: "files", tls: files, wantCN: filesTLSCN},
		{name: "files+tls_verify", tls: withVerify(files), wantCN: filesTLSCN, wantClientCert: true},
		{name: "global+files", tls: both, wantCN: globalTLSCN, wantWarning: true},
		{name: "global+files+tls_verify", tls: withVerify(both), wantCN: globalTLSCN, wantClientCert: true, wantWarning: true},
	}

	for _, lt := range tlsListenerTypes {
		for _, tc := range cases {
			t.Run(lt.typ+"/"+tc.name, func(t *testing.T) {
				logs := common.CaptureLogs(t)
				name := "tls416-" + lt.typ
				addr := common.GetRandomAddress(t)
				errc := make(chan error, 4)
				lt.start(t, name, addr, tc.tls, errc)
				waitListening(t, addr, errc)

				cn, askedForCert, err := probeTLS(addr)
				if cn != tc.wantCN {
					t.Errorf("served certificate CN = %q, want %q", cn, tc.wantCN)
				}
				switch {
				case tc.wantClientCert && !askedForCert:
					t.Errorf("tls_verify = true: the listener did not ask for a client certificate")
				case tc.wantClientCert && err == nil:
					t.Errorf("tls_verify = true: a client without a certificate was accepted")
				case !tc.wantClientCert && askedForCert:
					t.Errorf("tls_verify = false: the listener asked for a client certificate")
				case !tc.wantClientCert && err != nil:
					t.Errorf("tls_verify = false: TLS handshake failed: %v", err)
				}
				if tc.wantWarning {
					logs.WaitForLine(t, "tls_cert_file/tls_key_file ignored", name)
				}
			})
		}
	}
}

// probeTLS connects without a client certificate. It returns the CN of the
// certificate the listener presented, whether the listener asked for a client
// certificate, and the error that refused the connection, if any. In TLS 1.3
// the server judges the client's certificate after the client has finished its
// side of the handshake, so a refusal can arrive as an alert on the first read.
func probeTLS(addr string) (cn string, askedForCert bool, err error) {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 {
				cn = cs.PeerCertificates[0].Subject.CommonName
			}
			return nil
		},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			askedForCert = true
			return &tls.Certificate{}, nil // none
		},
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return cn, askedForCert, err
	}
	defer conn.Close()
	if !askedForCert {
		return cn, false, nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return cn, true, nil // the server is waiting for the client: accepted
		}
		return cn, true, err
	}
	return cn, true, nil
}

// waitListening waits until addr accepts TCP connections, failing the test
// with the start error if the listener gave up first.
func waitListening(t *testing.T, addr string, errc <-chan error) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		select {
		case err := <-errc:
			if err != nil {
				t.Fatalf("listener did not start: %v", err)
			}
		default:
		}
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing listens on %s", addr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

// globalTLSManagerConfig stands in for the config the global [tls] manager
// (file provider) hands to every listener.
func globalTLSManagerConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(416),
		Subject:      pkix.Name{CommonName: globalTLSCN},
		DNSNames:     []string{globalTLSCN},
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
