package managesieve

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"golang.org/x/crypto/bcrypt"
)

type authLockLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *authLockLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *authLockLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestCompleteAuthenticationWriteLockTimeoutLogsAddressAndMethod verifies that if
// ManageSieveSession.completeAuthentication fails to acquire the session write lock
// before s.User is populated, the warning log includes address and method.
func TestCompleteAuthenticationWriteLockTimeoutLogsAddressAndMethod(t *testing.T) {
	hashed, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv, err := New(ctx, "test-ms-lock-timeout", "localhost", "127.0.0.1:0", &resilient.ResilientDatabase{}, ManageSieveServerOptions{
		Config:      &config.Config{},
		LookupCache: &config.LookupCacheConfig{Enabled: true},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(srv.Close)
	srv.lookupCache.SetSuccess("alice@example.com", 42, string(hashed), "correct-password")

	for _, tc := range []struct {
		name string
		auth func(ctx context.Context, s *ManageSieveSession) error
	}{
		{
			name: "Login",
			auth: func(ctx context.Context, s *ManageSieveSession) error {
				return s.Login(ctx, "alice@example.com", "correct-password")
			},
		},
		{
			name: "AuthenticatePlain",
			auth: func(ctx context.Context, s *ManageSieveSession) error {
				return s.AuthenticatePlain(ctx, "", "alice@example.com", "correct-password")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &authLockLogBuffer{}
			prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
			t.Cleanup(func() { logger.Swap(prev) })

			c1, c2 := net.Pipe()
			t.Cleanup(func() {
				_ = c1.Close()
				_ = c2.Close()
			})
			sctx, scancel := context.WithCancel(context.Background())
			t.Cleanup(scancel)
			sess := &ManageSieveSession{
				server:    srv,
				conn:      c1,
				ctx:       sctx,
				cancel:    scancel,
				startTime: time.Now(),
			}
			sess.Protocol = "ManageSieve"
			sess.RemoteIP = "127.0.0.1"
			sess.Id = "sess-lock-timeout"
			sess.Stats = srv
			sess.mutexHelper = server.NewMutexTimeoutHelper(&sess.mutex, sctx, "MANAGESIEVE", func(string, ...any) {})

			// Hold the session write lock so completeAuthentication times out before s.User is set.
			sess.mutex.Lock()
			unlocked := false
			t.Cleanup(func() {
				if !unlocked {
					sess.mutex.Unlock()
				}
			})

			cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cmdCancel()

			err := tc.auth(cmdCtx, sess)
			sess.mutex.Unlock()
			unlocked = true

			if !errors.Is(err, errServerBusy) {
				t.Fatalf("%s err = %v, want errServerBusy", tc.name, err)
			}

			wantParts := []string{
				"level=WARN",
				`msg="failed to acquire write lock"`,
				"operation=authenticate",
				"address=alice@example.com",
				"method=cache",
				"session=sess-lock-timeout",
			}
			var matched bool
			for _, line := range strings.Split(logs.String(), "\n") {
				ok := true
				for _, p := range wantParts {
					if !strings.Contains(line, p) {
						ok = false
						break
					}
				}
				if ok {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("%s log missing %q:\n%s", tc.name, wantParts, logs.String())
			}
		})
	}
}
