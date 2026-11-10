package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// testCA is a private CA: its PEM file is what a pool's remote_tls_ca_file names.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	file string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pools test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, file: file}
}

// leaf is a server certificate signed by the CA for exactly these names and addresses.
func (ca *testCA) leaf(t *testing.T, dnsNames []string, ips []net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "backend"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsBackendOnEveryAddress serves TLS with cert on a port open on every local address, so a
// name like "localhost" reaches it whichever address family it resolves to.
func tlsBackendOnEveryAddress(t *testing.T, cert tls.Certificate, hooks ...func(*tls.ClientHelloInfo) (*tls.Config, error)) int {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	if len(hooks) > 0 {
		cfg.GetConfigForClient = hooks[0]
	}
	tl := tls.NewListener(ln, cfg)
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

var loopbackIPs = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

// hostnamePool is a manager over one pool whose backend is configured by hostname
// ("localhost:port") and verified against ca, resolved as the proxies resolve it.
func hostnamePool(t *testing.T, ca *testCA, port int) (*ConnectionManager, RouteResult) {
	t.Helper()
	cm := newPoolsCM(t, []PoolSpec{{Name: "named", Backends: []string{net.JoinHostPort("localhost", strconv.Itoa(port))}, Default: true,
		Settings: BackendSettings{TLS: true, TLSVerify: true, TLSCAFile: ca.file}}})
	if err := cm.ResolveAddresses(); err != nil {
		t.Fatalf("ResolveAddresses: %v", err)
	}
	res, err := routeFor(t, cm, &UserRoutingInfo{PoolName: "named"}, nil)
	if err != nil {
		t.Fatalf("DetermineRoute: %v", err)
	}
	if host, _, _ := net.SplitHostPort(res.PreferredAddr); net.ParseIP(host) == nil {
		t.Fatalf("setup: the pool was not resolved to addresses (%q)", res.PreferredAddr)
	}
	return cm, res
}

// A backend configured by hostname is dialed at an address the name resolved to, but it
// is the name its certificate is issued for: verification checks the name (and still
// accepts a certificate issued for the address), on the implicit-TLS dial and on a
// STARTTLS upgrade alike.
func TestPools_HostnameBackendIsVerifiedByItsName(t *testing.T) {
	ca := newTestCA(t)
	for _, c := range []struct {
		name  string
		dns   []string
		ips   []net.IP
		valid bool
	}{
		{"certificate for the configured name", []string{"localhost"}, nil, true},
		{"certificate for the address dialed", nil, loopbackIPs, true},
		{"certificate for another name", []string{"other.example"}, nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			port := tlsBackendOnEveryAddress(t, ca.leaf(t, c.dns, c.ips))
			cm, res := hostnamePool(t, ca, port)

			conn, _, err := cm.ConnectWithProxy(context.Background(), res.PreferredAddr, "", 0, "", 0, res.RoutingInfo)
			if conn != nil {
				conn.Close()
			}
			if (err == nil) != c.valid {
				t.Fatalf("implicit TLS to %s: err = %v, want valid = %v", res.PreferredAddr, err, c.valid)
			}

			cfg := cm.BackendClientTLS(true, res.PreferredAddr)
			tc, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", res.PreferredAddr, cfg)
			if tc != nil {
				tc.Close()
			}
			if (err == nil) != c.valid {
				t.Fatalf("STARTTLS config for %s: err = %v, want valid = %v", res.PreferredAddr, err, c.valid)
			}
		})
	}
}

// The same holds for a flat remote_addrs list configured by hostname.
func TestPools_FlatListHostnameBackendIsVerifiedByItsName(t *testing.T) {
	ca := newTestCA(t)
	port := tlsBackendOnEveryAddress(t, ca.leaf(t, []string{"localhost"}, nil))
	cm, err := NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck([]string{net.JoinHostPort("localhost", strconv.Itoa(port))}, 143, true, false, true, false, 2*time.Second, nil, "flat", true)
	if err != nil {
		t.Fatal(err)
	}
	cm.SetRemoteTLSRootCAs(mustPool(t, ca.file))
	if err := cm.ResolveAddresses(); err != nil {
		t.Fatal(err)
	}
	conn, addr, err := cm.ConnectWithProxy(context.Background(), "", "", 0, "", 0, nil)
	if err != nil {
		t.Fatalf("flat list, hostname backend: %v", err)
	}
	conn.Close()
	if host, _, _ := net.SplitHostPort(addr); net.ParseIP(host) == nil {
		t.Fatalf("setup: dialed %q, not a resolved address", addr)
	}
}

// A backend's certificate belongs to the host, not to the route that reached it: a lookup
// pin to a member of a pool with its own CA file is verified against that CA.
func TestPools_PinToAPoolMemberUsesThePoolCA(t *testing.T) {
	ca := newTestCA(t)
	port := tlsBackendOnEveryAddress(t, ca.leaf(t, nil, loopbackIPs))
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	cm := newPoolsCM(t, []PoolSpec{{Name: "private", Backends: []string{addr}, Default: true,
		Settings: BackendSettings{TLS: true, TLSVerify: true, TLSCAFile: ca.file}}})
	pin := &UserRoutingInfo{ServerAddress: addr, IsRemoteLookupAccount: true, RemoteTLS: true, RemoteTLSVerify: true}
	conn, _, err := cm.ConnectWithProxy(context.Background(), addr, "", 0, "", 0, pin)
	if err != nil {
		t.Fatalf("pin to a member of a pool with its own CA: %v", err)
	}
	conn.Close()
}
