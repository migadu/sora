package imapproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// fakeAuthLimiter implements server.AuthLimiter for tests. It applies no
// delays (does not implement AuthDelayHelper) and returns canErr from the
// CanAttemptAuth* methods.
type fakeAuthLimiter struct {
	canErr error
}

func (f *fakeAuthLimiter) CanAttemptAuth(ctx context.Context, remoteAddr net.Addr, username string) error {
	return f.canErr
}

func (f *fakeAuthLimiter) RecordAuthAttempt(ctx context.Context, remoteAddr net.Addr, username string, success bool) {
}

func (f *fakeAuthLimiter) CanAttemptAuthWithProxy(ctx context.Context, conn net.Conn, proxyInfo *server.ProxyProtocolInfo, username string) error {
	return f.canErr
}

func (f *fakeAuthLimiter) RecordAuthAttemptWithProxy(ctx context.Context, conn net.Conn, proxyInfo *server.ProxyProtocolInfo, username string, success bool) {
}

func (f *fakeAuthLimiter) IsIPBlocked(remoteAddr net.Addr) bool { return false }

func (f *fakeAuthLimiter) IsIPBlockedWithProxy(c net.Conn, p *server.ProxyProtocolInfo) bool {
	return false
}

func (f *fakeAuthLimiter) GetStats(ctx context.Context, windowDuration time.Duration) map[string]any {
	return nil
}

func (f *fakeAuthLimiter) Stop() {}

func newTestConnManager(t *testing.T, addr string) *proxy.ConnectionManager {
	t.Helper()
	cm, err := proxy.NewConnectionManager([]string{addr}, 143, false, false, false, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}
	return cm
}

func newTestLookupCache(t *testing.T) *lookupcache.LookupCache {
	t.Helper()
	c := lookupcache.New(5*time.Minute, 1*time.Minute, 100, 5*time.Minute, 30*time.Second)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Stop(ctx)
	})
	return c
}
