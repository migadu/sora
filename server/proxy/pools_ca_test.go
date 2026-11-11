package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// privateCABackend is a TLS backend whose certificate no system root trusts, and a PEM
// file holding that certificate (its own CA, for a private-CA deployment).
func privateCABackend(t *testing.T) (addr, caFile string) {
	t.Helper()
	b := httptest.NewUnstartedServer(http.NotFoundHandler())
	b.StartTLS()
	t.Cleanup(b.Close)
	caFile = filepath.Join(t.TempDir(), "backend-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return b.Listener.Addr().String(), caFile
}

func dialPool(t *testing.T, cm *ConnectionManager, pool string) error {
	t.Helper()
	res, err := routeFor(t, cm, &UserRoutingInfo{PoolName: pool}, nil)
	if err != nil {
		t.Fatalf("DetermineRoute: %v", err)
	}
	conn, _, err := cm.ConnectWithProxy(context.Background(), res.PreferredAddr, "", 0, "", 0, res.RoutingInfo)
	if err == nil {
		conn.Close()
	}
	return err
}

// A pool's remote_tls_ca_file is what its backends' certificates are verified against, on
// the implicit-TLS dial and on a STARTTLS upgrade alike; with verification on (the pool
// default) a private-CA backend is reachable without turning verification off. A pool
// without its own CA file uses the system roots: nothing is inherited from the [[server]]
// block, not even POP3's remote_tls_ca_file.
func TestPools_PoolCAFileVerifiesItsBackends(t *testing.T) {
	addr, caFile := privateCABackend(t)

	withCA := newPoolsCM(t, []PoolSpec{{Name: "private", Backends: []string{addr}, Default: true,
		Settings: BackendSettings{TLS: true, TLSVerify: true, TLSCAFile: caFile}}})
	if err := dialPool(t, withCA, "private"); err != nil {
		t.Fatalf("pool with its CA file: %v", err)
	}

	// STARTTLS (LMTP, ManageSieve): the session upgrades with the manager's config for
	// the route, which must trust the route's pool CA.
	res, _ := routeFor(t, withCA, &UserRoutingInfo{PoolName: "private"}, nil)
	cfg := withCA.BackendClientTLS(true, res.PreferredAddr)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		t.Fatalf("STARTTLS config for the pool route does not trust the pool's CA: %v", err)
	}
	conn.Close()

	noCA := newPoolsCM(t, []PoolSpec{{Name: "public", Backends: []string{addr}, Default: true,
		Settings: BackendSettings{TLS: true, TLSVerify: true}}})
	noCA.SetRemoteTLSRootCAs(mustPool(t, caFile)) // POP3's [[server]] remote_tls_ca_file
	if err := dialPool(t, noCA, "public"); err == nil {
		t.Fatal("a pool without a CA file trusted the [[server]] block's CA")
	}
}

// The [[server]] block's CA still verifies a lookup pin, which is not a pool route.
func TestPools_ServerCAFileStillVerifiesPins(t *testing.T) {
	addr, caFile := privateCABackend(t)
	cm, err := NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck([]string{"10.0.0.1:143"}, 143, true, false, true, false, 2*time.Second, nil, "pins", true)
	if err != nil {
		t.Fatal(err)
	}
	cm.SetRemoteTLSRootCAs(mustPool(t, caFile))
	pin := &UserRoutingInfo{ServerAddress: addr, IsRemoteLookupAccount: true, RemoteTLS: true, RemoteTLSVerify: true}
	conn, _, err := cm.ConnectWithProxy(context.Background(), addr, "", 0, "", 0, pin)
	if err != nil {
		t.Fatalf("pin verified against the server's CA file: %v", err)
	}
	conn.Close()
}

// An unreadable or empty CA file is a startup error, never a silent fallback to the system
// roots.
func TestPools_BadPoolCAFileFailsConstruction(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{filepath.Join(t.TempDir(), "missing.pem"), empty} {
		_, err := NewConnectionManagerWithPools([]PoolSpec{{Name: "p", Backends: []string{"10.0.0.1"}, Default: true,
			Settings: BackendSettings{TLS: true, TLSVerify: true, TLSCAFile: file}}}, 143, time.Second, nil, "ca", true)
		if err == nil {
			t.Errorf("CA file %s accepted", file)
		}
	}
}

func mustPool(t *testing.T, file string) *x509.CertPool {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(data) {
		t.Fatal("no certificate in PEM")
	}
	return p
}
