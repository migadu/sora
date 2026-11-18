package pop3

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// addressRecordingLimiter is the real auth rate limiter, noting the client address
// each of its calls charged: the progressive delay, the rate-limit check and the
// failure counters. The check and the counters resolve it as the real limiter does.
type addressRecordingLimiter struct {
	*serverPkg.AuthRateLimiter
	mu                     sync.Mutex
	delay, check, recorded []string
}

func (l *addressRecordingLimiter) note(list *[]string, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	*list = append(*list, ip)
}

func (l *addressRecordingLimiter) GetAuthenticationDelay(remoteAddr net.Addr) time.Duration {
	l.note(&l.delay, remoteAddr.String())
	return l.AuthRateLimiter.GetAuthenticationDelay(remoteAddr)
}

func (l *addressRecordingLimiter) CanAttemptAuthWithProxy(ctx context.Context, conn net.Conn, proxyInfo *serverPkg.ProxyProtocolInfo, username string) error {
	ip, _ := serverPkg.GetConnectionIPs(conn, proxyInfo)
	l.note(&l.check, ip)
	return l.AuthRateLimiter.CanAttemptAuthWithProxy(ctx, conn, proxyInfo, username)
}

func (l *addressRecordingLimiter) RecordAuthAttemptWithProxy(ctx context.Context, conn net.Conn, proxyInfo *serverPkg.ProxyProtocolInfo, username string, success bool) {
	ip, _ := serverPkg.GetConnectionIPs(conn, proxyInfo)
	l.note(&l.recorded, ip)
	l.AuthRateLimiter.RecordAuthAttemptWithProxy(ctx, conn, proxyInfo, username, success)
}

// peerConn is a connection whose socket peer is the given address.
type peerConn struct {
	net.Conn
	peer net.Addr
}

func (c peerConn) RemoteAddr() net.Addr { return c.peer }

// TestXCLIENTClientAddressKeysTheWholeAuthAttempt: once XCLIENT ADDR from a trusted
// peer has replaced the client address, the progressive delay, the rate-limit check
// and the failure counters of a login all use that address. With a bare XCLIENT
// (no PROXY header, no proxy-source-ip) the check and the counters used the socket
// peer, the forwarder, while the delay looked up the client: the failures landed on
// the forwarder, which trusted_networks also exempts, so the client was never
// delayed. The proxy-source-ip form a pop3_proxy sends is the control.
func TestXCLIENTClientAddressKeysTheWholeAuthAttempt(t *testing.T) {
	const (
		forwarder = "10.0.0.5"
		client    = "192.0.2.10"
		exempt    = "198.51.100.7" // a forwarded client in exempt_networks
	)
	bare := "ADDR=" + client
	soraProxy := (&serverPkg.ForwardingParams{
		OriginatingIP: client,
		ProxyTTL:      5,
		Variables:     map[string]string{"proxy-source-ip": forwarder},
	}).ToPOP3XCLIENT()

	cases := []struct {
		name      string
		xclient   string
		clientIP  string
		wantDelay bool // whether the client's failures move its progressive delay
	}{
		{"bare_XCLIENT_ADDR", bare, client, true},
		{"XCLIENT_with_proxy-source-ip", soraProxy, client, true},
		{"exempt_forwarded_client", "ADDR=" + exempt, exempt, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			limitConfig := serverPkg.DefaultAuthRateLimiterConfig()
			limitConfig.Enabled = true
			limitConfig.DelayStartThreshold = 1
			limitConfig.InitialDelay = time.Millisecond
			limitConfig.MaxDelay = 5 * time.Millisecond
			// The forwarder is exempt, as trusted_networks makes it by default.
			limitConfig.ExemptNetworks = []string{"10.0.0.0/24", "198.51.100.0/24"}
			limiter := &addressRecordingLimiter{
				AuthRateLimiter: serverPkg.NewAuthRateLimiter("POP3", "xclient-auth-limit", "localhost", limitConfig),
			}
			t.Cleanup(limiter.Stop)

			srv, err := New(ctx, "xclient-auth-limit", "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, POP3ServerOptions{
				InsecureAuth:        true,
				Config:              &config.Config{},
				TrustedNetworks:     []string{"10.0.0.0/24"},
				AuthLimiterOverride: limiter,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(srv.Close)

			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()
			sctx, scancel := context.WithCancel(ctx)
			defer scancel()
			conn := peerConn{Conn: c1, peer: &net.TCPAddr{IP: net.ParseIP(forwarder), Port: 40000}}
			s := &POP3Session{server: srv, conn: conn, deleted: make(map[int]bool), ctx: sctx, cancel: scancel}
			s.Protocol = "POP3"
			s.ServerName = srv.name
			s.HostName = srv.hostname
			s.RemoteIP = forwarder // as the accept path sets it without a PROXY header
			s.mutexHelper = serverPkg.NewMutexTimeoutHelper(&s.mutex, sctx, "POP3", s.InfoLog)

			if ok, msg := s.handleXCLIENT(tc.xclient); !ok {
				t.Fatalf("XCLIENT %s refused: %s", tc.xclient, msg)
			}

			// An unparseable username fails without a database.
			if err := s.Login(ctx, "not-an-address", "secret"); err == nil {
				t.Fatal("login with an unparseable username succeeded")
			}

			limiter.mu.Lock()
			for _, call := range []struct {
				what string
				ips  []string
			}{
				{"progressive delay", limiter.delay},
				{"rate-limit check", limiter.check},
				{"failure record", limiter.recorded},
			} {
				if len(call.ips) != 1 || call.ips[0] != tc.clientIP {
					t.Errorf("%s charged %v, want [%s] (the XCLIENT client address)", call.what, call.ips, tc.clientIP)
				}
			}
			limiter.mu.Unlock()

			clientDelay := limiter.AuthRateLimiter.GetAuthenticationDelay(&serverPkg.StringAddr{Addr: tc.clientIP})
			if tc.wantDelay && clientDelay == 0 {
				t.Errorf("after a failed login the progressive delay of %s is 0: the failure was not counted against the client", tc.clientIP)
			}
			if !tc.wantDelay && clientDelay != 0 {
				t.Errorf("progressive delay of exempt client %s is %v, want 0", tc.clientIP, clientDelay)
			}
			if d := limiter.AuthRateLimiter.GetAuthenticationDelay(&serverPkg.StringAddr{Addr: forwarder}); d != 0 {
				t.Errorf("progressive delay of the forwarder %s is %v, want 0", forwarder, d)
			}
		})
	}
}
