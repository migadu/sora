package pop3

import (
	"bufio"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3server"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// delayingLimiter is an auth limiter that allows every attempt and asks for a
// progressive delay long enough to hold a delay slot for the whole test.
type delayingLimiter struct {
	unparseableLoginLimiter
}

func (l *delayingLimiter) GetAuthenticationDelay(net.Addr) time.Duration { return time.Hour }

// TestAuthDelayQueueFullIsTemporaryFailure: a login refused because the client
// address already has a full queue of delayed logins is answered -ERR [SYS/TEMP]
// (RFC 3206 section 4). The credentials were never checked, so the reply must not be
// [IN-USE], which RFC 2449 section 8.1.2 reserves for "the authentication was
// successful, but the user's maildrop is currently in use".
func TestAuthDelayQueueFullIsTemporaryFailure(t *testing.T) {
	const ip = "192.0.2.137"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limiter := &delayingLimiter{}
	srv, err := New(ctx, "delay-queue-full", "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, POP3ServerOptions{
		InsecureAuth:        true,
		Config:              &config.Config{},
		AuthLimiterOverride: limiter,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(srv.Close)

	// Hold delay slots for ip until one more is refused: the queue is full.
	holdCtx, release := context.WithCancel(ctx)
	holders := make(chan error, 64)
	started := 0
	defer func() {
		release()
		for ; started > 0; started-- {
			<-holders
		}
	}()
	fill := func() bool {
		for started < cap(holders) {
			started++
			go func() {
				holders <- serverPkg.ApplyAuthenticationDelay(holdCtx, limiter, &serverPkg.StringAddr{Addr: ip}, "pop3")
			}()
			select {
			case err := <-holders:
				started--
				if !errors.Is(err, serverPkg.ErrDelayQueueFull) {
					t.Fatalf("holding a delay slot: %v", err)
				}
				return true
			case <-time.After(20 * time.Millisecond):
				// Still delaying: it holds a slot.
			}
		}
		return false
	}
	if !fill() {
		t.Fatalf("the delay queue for %s did not fill with %d delayed logins", ip, cap(holders))
	}

	logins := []struct {
		name  string
		login func(s *POP3Session) error
	}{
		{"USER_PASS", func(s *POP3Session) error {
			return s.Login(ctx, "user@example.com", "wrong-password")
		}},
		{"AUTH_PLAIN", func(s *POP3Session) error {
			return s.AuthenticatePlain(ctx, "", "user@example.com", "wrong-password")
		}},
	}
	for _, tc := range logins {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()
			sctx, scancel := context.WithCancel(ctx)
			defer scancel()
			s := &POP3Session{server: srv, conn: c1, deleted: make(map[int]bool), ctx: sctx, cancel: scancel}
			s.Protocol = "POP3"
			s.ServerName = srv.name
			s.HostName = srv.hostname
			s.RemoteIP = ip
			s.mutexHelper = serverPkg.NewMutexTimeoutHelper(&s.mutex, sctx, "POP3", s.InfoLog)

			err := tc.login(s)
			if reply, ok := err.(*pop3server.Error); !ok || reply.Code != "SYS/TEMP" {
				t.Errorf("login with a full delay queue: %#v, want -ERR [SYS/TEMP] ...", err)
			}
			if n := limiter.checks.Load(); n != 0 {
				t.Errorf("the auth rate limiter was consulted %d times, want 0 (refused before the credentials)", n)
			}
		})
	}
}

// TestTimeoutNoticesCarryNoResponseCode: the notice written before a connection is
// closed for a timeout answers no command and carries no response code. [IN-USE]
// (RFC 2449 section 8.1.2) says a login succeeded with the maildrop locked, and no
// RFC 2449 or RFC 3206 code describes a timeout.
func TestTimeoutNoticesCarryNoResponseCode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := New(ctx, "timeout-notice", "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, POP3ServerOptions{
		MinBytesPerMinute: 1024,
		Config:            &config.Config{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(srv.Close)

	for _, tc := range []struct{ reason, want string }{
		{"slow_throughput", "-ERR Connection too slow, please reconnect\r\n"},
		{"idle", "-ERR Connection timeout, please reconnect\r\n"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()
			go srv.connConfig().OnTimeout(c1, tc.reason)
			_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
			line, err := bufio.NewReader(c2).ReadString('\n')
			if err != nil {
				t.Fatalf("reading the %s notice: %v", tc.reason, err)
			}
			if line != tc.want {
				t.Errorf("%s notice = %q, want %q", tc.reason, line, tc.want)
			}
		})
	}
}
