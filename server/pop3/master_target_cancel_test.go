//go:build integration

package pop3_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3server"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// failureRecorder records the failed attempts the session reports to the auth rate
// limiter, and never blocks.
type failureRecorder struct {
	mu       sync.Mutex
	failures []string
}

func (r *failureRecorder) RecordAuthAttemptWithProxy(_ context.Context, _ net.Conn, _ *server.ProxyProtocolInfo, key string, success bool) {
	if success {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = append(r.failures, key)
}

func (r *failureRecorder) drain() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.failures
	r.failures = nil
	return out
}

func (r *failureRecorder) GetAuthenticationDelay(net.Addr) time.Duration { return 0 }
func (r *failureRecorder) CanAttemptAuthWithProxy(context.Context, net.Conn, *server.ProxyProtocolInfo, string) error {
	return nil
}
func (r *failureRecorder) CanAttemptAuth(context.Context, net.Addr, string) error    { return nil }
func (r *failureRecorder) RecordAuthAttempt(context.Context, net.Addr, string, bool) {}
func (r *failureRecorder) IsIPBlocked(net.Addr) bool                                 { return false }
func (r *failureRecorder) IsIPBlockedWithProxy(net.Conn, *server.ProxyProtocolInfo) bool {
	return false
}
func (r *failureRecorder) GetStats(context.Context, time.Duration) map[string]any { return nil }
func (r *failureRecorder) Stop()                                                  {}

// TestPOP3_MasterTargetLookupCancelledIsTemporary: when the impersonation target lookup
// of a master login ends because the command's context was cancelled (the server is
// shutting down, or the client went away), nothing is known about the credentials. The
// login is answered -ERR [SYS/TEMP] (RFC 3206 section 4), not [AUTH], and it is neither
// recorded by the auth rate limiter nor counted as a failed login, as on the regular
// login path. The target exists; only the cancelled context stops the lookup.
func TestPOP3_MasterTargetLookupCancelledIsTemporary(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	const (
		name           = "test-master-target-cancelled"
		masterUser     = "support"
		masterPass     = "master-secret"
		masterSASLUser = "proxyuser"
		masterSASLPass = "master-sasl-secret"
	)
	limiter := &failureRecorder{}
	srv, err := pop3.New(context.Background(), name, "localhost", common.GetRandomAddress(t),
		&storage.S3Storage{}, rdb, nil, nil,
		pop3.POP3ServerOptions{
			InsecureAuth:        true,
			Config:              &config.Config{},
			MasterUsername:      masterUser,
			MasterPassword:      masterPass,
			MasterSASLUsername:  masterSASLUser,
			MasterSASLPassword:  masterSASLPass,
			AuthLimiterOverride: limiter,
		})
	if err != nil {
		t.Fatalf("Failed to create POP3 server: %v", err)
	}
	t.Cleanup(srv.Close)

	failures := func() float64 {
		return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("pop3", name, "localhost", "failure"))
	}

	logins := []struct {
		name  string
		login func(s *pop3.POP3Session, ctx context.Context) error
	}{
		{"master_SASL", func(s *pop3.POP3Session, ctx context.Context) error {
			return s.AuthenticatePlain(ctx, account.Email, masterSASLUser, masterSASLPass)
		}},
		{"master_username", func(s *pop3.POP3Session, ctx context.Context) error {
			return s.Login(ctx, account.Email+"@"+masterUser, masterPass)
		}},
	}

	for _, tc := range logins {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()
			session := pop3.NewSessionForTest(srv, c1)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			before := failures()
			err := tc.login(session, ctx)

			var reply *pop3server.Error
			if !errors.As(err, &reply) || reply.Code != "SYS/TEMP" {
				t.Errorf("login whose target lookup was cancelled: %v, want -ERR [SYS/TEMP] ...", err)
			}
			if recorded := limiter.drain(); len(recorded) != 0 {
				t.Errorf("a cancelled target lookup was recorded as a failed login under %q", recorded)
			}
			if grew := failures() - before; grew != 0 {
				t.Errorf("sora_authentication_attempts_total{result=\"failure\"} grew by %v, want 0", grew)
			}
		})
	}
}
