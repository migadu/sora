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

// TestIMAPProxyPoolTLSIsImplicitTLS: one [[pool]] block serves every protocol, so a pool
// that sets remote_tls_use_starttls for LMTP and ManageSieve also sets it for IMAP. IMAP
// cannot STARTTLS to a backend: for it remote_tls still means TLS from the first byte. A
// TLS-only backend proves it, since a plaintext leg would wait forever for a greeting the
// backend only sends inside TLS (and would carry the master credentials in the clear).
func TestIMAPProxyPoolTLSIsImplicitTLS(t *testing.T) {
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
	proxyAddr := setupIMAPProxy(t, rdb, []proxy.PoolSpec{{Name: "tls", Backends: []string{backendAddr},
		Settings: proxy.BackendSettings{TLS: true, TLSUseStartTLS: true, TLSVerify: false}}}, lookupURL, nil)

	if err := imapLogin(t, proxyAddr, user); err != nil {
		t.Fatalf("login through the pool's TLS backend leg: %v (a plaintext leg never gets the backend's greeting)", err)
	}
}
