//go:build integration

package pop3proxy_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/server/pop3proxy"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/storage"
)

// TestPOP3ProxyPoolTLSModes: one [[pool]] block serves every protocol, and the POP3 proxy
// honours its remote_tls_use_starttls like LMTP and ManageSieve. Against a backend that
// only speaks implicit TLS, a pool with remote_tls logs in over TLS from the first byte,
// and one that adds remote_tls_use_starttls dials plaintext for its STLS, never gets the
// greeting the backend only sends inside TLS, and refuses the login as a temporary
// failure: it never falls back to sending the master credentials in the clear.
func TestPOP3ProxyPoolTLSModes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	backendAddr := common.GetRandomAddress(t)
	backendCert, backendKey, _ := common.GenerateTestTLSCert(t, nil, nil)

	backend, err := pop3.New(context.Background(), "test-backend-pool-tls", "localhost", backendAddr,
		&storage.S3Storage{}, rdb, nil, nil, pop3.POP3ServerOptions{
			TLS:                true,
			TLSCertFile:        backendCert,
			TLSKeyFile:         backendKey,
			MasterSASLUsername: "proxyuser",
			MasterSASLPassword: "proxypass",
		})
	if err != nil {
		t.Fatalf("Failed to create TLS backend: %v", err)
	}
	go func() { backend.Start(make(chan error, 1)) }()
	defer backend.Close()
	time.Sleep(200 * time.Millisecond)

	for _, c := range []struct {
		name     string
		settings proxy.BackendSettings
		wantOK   bool
	}{
		{"remote_tls", proxy.BackendSettings{TLS: true}, true},
		{"remote_tls_use_starttls", proxy.BackendSettings{TLS: true, TLSUseStartTLS: true}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			proxyAddr := common.GetRandomAddress(t)
			p, err := pop3proxy.New(context.Background(), "localhost", proxyAddr, rdb, pop3proxy.POP3ProxyServerOptions{
				Name:               "test-proxy-pool-tls",
				Pools:              []proxy.PoolSpec{{Name: "tls", Backends: []string{backendAddr}, Default: true, Settings: c.settings}},
				MasterSASLUsername: "proxyuser",
				MasterSASLPassword: "proxypass",
				InsecureAuth:       true,
				ConnectTimeout:     3 * time.Second,
			})
			if err != nil {
				t.Fatalf("pop3proxy.New: %v", err)
			}
			go func() { p.Start() }()
			defer p.Stop()
			time.Sleep(200 * time.Millisecond)

			resp := pop3Login(t, proxyAddr, account)
			if c.wantOK && !strings.HasPrefix(resp, "+OK") {
				t.Fatalf("PASS through the pool's implicit-TLS backend leg: %q", resp)
			}
			if !c.wantOK && !strings.HasPrefix(resp, "-ERR [SYS/TEMP]") {
				t.Fatalf("PASS through a STLS pool whose backend only speaks implicit TLS = %q, want a temporary failure", resp)
			}
		})
	}
}
