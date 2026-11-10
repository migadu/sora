//go:build integration

package imapproxy_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestIMAPProxyPoolTLSModes: one [[pool]] block serves every protocol, and the IMAP proxy
// honours its remote_tls_use_starttls like LMTP and ManageSieve. Against a backend that
// only speaks implicit TLS, a pool with remote_tls logs in over TLS from the first byte,
// and one that adds remote_tls_use_starttls dials plaintext for its STARTTLS, never gets
// the greeting the backend only sends inside TLS, and refuses the login as a temporary
// failure: it never falls back to sending the master credentials in the clear.
func TestIMAPProxyPoolTLSModes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	user := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("pool-tls-%d@example.com", time.Now().UnixNano()), "pw")

	uploadWorker, err := uploader.New(context.Background(), t.TempDir(), 10, 1, 3, time.Second, 0, "test-instance", rdb, &storage.S3Storage{}, nil, make(chan error, 1))
	if err != nil {
		t.Fatalf("uploader: %v", err)
	}
	certFile, keyFile, _ := common.GenerateTestTLSCert(t, nil, nil)
	backendAddr := common.GetRandomAddress(t)
	backend, err := imap.New(context.Background(), "test-backend-pool-tls", "localhost", backendAddr,
		&storage.S3Storage{}, rdb, uploadWorker, nil, imap.IMAPServerOptions{
			TLS:                true,
			TLSCertFile:        certFile,
			TLSKeyFile:         keyFile,
			MasterSASLUsername: []byte("proxyuser"),
			MasterSASLPassword: []byte("proxypass"),
		})
	if err != nil {
		t.Fatalf("imap.New: %v", err)
	}
	go func() {
		if err := backend.Serve(backendAddr); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP backend: %v", err)
		}
	}()
	defer backend.Close()
	time.Sleep(200 * time.Millisecond)

	lookup, lookupURL := newPoolLookup(t)
	lookup.set(user.Email, answer(t, user, "tls"))

	t.Run("remote_tls", func(t *testing.T) {
		proxyAddr := setupIMAPProxy(t, rdb, []proxy.PoolSpec{{Name: "tls", Backends: []string{backendAddr},
			Settings: proxy.BackendSettings{TLS: true, TLSVerify: false}}}, lookupURL, nil)
		if err := imapLogin(t, proxyAddr, user); err != nil {
			t.Fatalf("login through the pool's implicit-TLS backend leg: %v", err)
		}
	})
	t.Run("remote_tls_use_starttls", func(t *testing.T) {
		proxyAddr := setupIMAPProxy(t, rdb, []proxy.PoolSpec{{Name: "tls", Backends: []string{backendAddr},
			Settings: proxy.BackendSettings{TLS: true, TLSUseStartTLS: true, TLSVerify: false}}}, lookupURL, nil)
		err := imapLogin(t, proxyAddr, user)
		if err == nil || !strings.Contains(err.Error(), "UNAVAILABLE") {
			t.Fatalf("login through a STARTTLS pool whose backend only speaks implicit TLS = %v, want a temporary failure", err)
		}
	})
}
