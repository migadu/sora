//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// countingAuthLimiter implements server.AuthLimiter + server.AuthDelayHelper and
// counts how many times the authentication gate methods are invoked. It never
// blocks (GetAuthenticationDelay returns 0, CanAttempt* returns nil) so auth
// proceeds normally; the test asserts each gate runs exactly once per command.
type countingAuthLimiter struct {
	delayCalls      atomic.Int64 // GetAuthenticationDelay
	canAttemptCalls atomic.Int64 // CanAttemptAuthWithProxy
}

func (c *countingAuthLimiter) GetAuthenticationDelay(net.Addr) time.Duration {
	c.delayCalls.Add(1)
	return 0
}

func (c *countingAuthLimiter) CanAttemptAuthWithProxy(context.Context, net.Conn, *server.ProxyProtocolInfo, string) error {
	c.canAttemptCalls.Add(1)
	return nil
}

func (c *countingAuthLimiter) CanAttemptAuth(context.Context, net.Addr, string) error { return nil }
func (c *countingAuthLimiter) RecordAuthAttempt(context.Context, net.Addr, string, bool) {
}
func (c *countingAuthLimiter) RecordAuthAttemptWithProxy(context.Context, net.Conn, *server.ProxyProtocolInfo, string, bool) {
}
func (c *countingAuthLimiter) IsIPBlocked(net.Addr) bool { return false }
func (c *countingAuthLimiter) IsIPBlockedWithProxy(net.Conn, *server.ProxyProtocolInfo) bool {
	return false
}
func (c *countingAuthLimiter) GetStats(context.Context, time.Duration) map[string]any { return nil }
func (c *countingAuthLimiter) Stop()                                                  {}

func (c *countingAuthLimiter) snapshot() (delay, canAttempt int64) {
	return c.delayCalls.Load(), c.canAttemptCalls.Load()
}

func (c *countingAuthLimiter) reset() {
	c.delayCalls.Store(0)
	c.canAttemptCalls.Store(0)
}

func setupIMAPServerWithLimiter(t *testing.T, limiter server.AuthLimiter) (*common.TestServer, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	tempDir, err := os.MkdirTemp("", "sora-test-upload-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	errCh := make(chan error, 1)
	uploadWorker, err := uploader.New(
		context.Background(), tempDir, 10, 1, 3, time.Second, 0,
		"test-instance", rdb, &storage.S3Storage{}, nil, errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	srv, err := imap.New(
		context.Background(), "test", "localhost", address,
		&storage.S3Storage{}, rdb, uploadWorker, nil,
		imap.IMAPServerOptions{
			InsecureAuth:        true,
			Config:              &config.Config{},
			AuthLimiterOverride: limiter,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := srv.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP server error: %w", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	t.Cleanup(func() {
		srv.Close()
		os.RemoveAll(tempDir)
	})

	return &common.TestServer{Address: address, Server: srv, ResilientDB: rdb}, account
}

// TestIMAP_SASLGateAppliedOnce asserts that a single AUTHENTICATE PLAIN applies
// the progressive auth delay and rate-limit check exactly once — the same as a
// single LOGIN. Before the fix the SASL PLAIN handler gated once and then called
// s.Login, which gated again, so AUTHENTICATE double-applied both (RED: counts=2).
func TestIMAP_SASLGateAppliedOnce(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	limiter := &countingAuthLimiter{}
	server, account := setupIMAPServerWithLimiter(t, limiter)
	defer server.Close()

	// AUTHENTICATE PLAIN (regular user, no impersonation).
	limiter.reset()
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	if err := c1.Authenticate(sasl.NewPlainClient("", account.Email, account.Password)); err != nil {
		t.Fatalf("AUTHENTICATE PLAIN failed: %v", err)
	}
	authDelay, authCan := limiter.snapshot()
	c1.Logout()

	if authDelay != 1 {
		t.Errorf("AUTHENTICATE applied the auth delay %d times, want exactly 1 (double-gate regression)", authDelay)
	}
	if authCan != 1 {
		t.Errorf("AUTHENTICATE ran the rate-limit check %d times, want exactly 1 (double-gate regression)", authCan)
	}

	// LOGIN, for parity: it must apply each gate exactly once too.
	limiter.reset()
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	if err := c2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("LOGIN failed: %v", err)
	}
	loginDelay, loginCan := limiter.snapshot()
	c2.Logout()

	if loginDelay != 1 {
		t.Errorf("LOGIN applied the auth delay %d times, want exactly 1", loginDelay)
	}
	if loginCan != 1 {
		t.Errorf("LOGIN ran the rate-limit check %d times, want exactly 1", loginCan)
	}
}
