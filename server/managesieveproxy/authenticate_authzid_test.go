package managesieveproxy

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestAuthenticatePlainRefusesOtherAuthorizationIdentity: the proxy must not log a
// client in as its authentication identity when it asked to act as somebody else.
// RFC 4616 section 2: "the server will verify the presented (in the message)
// authentication identity (authcid) and password (passwd) with the system
// authentication database, and it will verify that the authentication credentials
// permit the client to act as the (presented or derived) authorization identity
// (authzid). If both steps succeed, the user is authenticated." These credentials
// permit acting only as the account they log in to, so another authorization
// identity is refused with the backend's reply, and only once the credentials
// checked out. An authorization identity that names the account logged in to, as
// the authentication identity or as the address the login resolved to (the master
// username form's target), is accepted.
func TestAuthenticatePlainRefusesOtherAuthorizationIdentity(t *testing.T) {
	const refused = `NO "Proxy authentication requires master credentials"`
	cases := []struct {
		name                       string
		authzid, authcid, password string
		want                       string
		backendAs                  string // the identity the backend logs in; "" for none
	}{
		{name: "other identity", authzid: "other@example.com", authcid: sieveTestUser, password: sieveTestPassword, want: refused},
		{name: "other identity, wrong password", authzid: "other@example.com", authcid: sieveTestUser, password: "wrong", want: `NO "Authentication failed"`},
		{name: "no authorization identity", authcid: sieveTestUser, password: sieveTestPassword, want: `OK "Authenticated"`, backendAs: sieveTestUser},
		{name: "own identity", authzid: sieveTestUser, authcid: sieveTestUser, password: sieveTestPassword, want: `OK "Authenticated"`, backendAs: sieveTestUser},
		{name: "master username form", authcid: sieveTestUser + "@admin", password: "master-secret", want: `OK "Authenticated"`, backendAs: sieveTestUser},
		{name: "master username form, its target", authzid: sieveTestUser, authcid: sieveTestUser + "@admin", password: "master-secret", want: `OK "Authenticated"`, backendAs: sieveTestUser},
		{name: "master username form, other identity", authzid: "other@example.com", authcid: sieveTestUser + "@admin", password: "master-secret", want: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backendAddr, commands := fakeSieveBackend{}.start(t)
			lookupSrv := httptest.NewServer(acceptingSieveLookup(t))
			t.Cleanup(lookupSrv.Close)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr().String()
			ln.Close()
			// No database: the remote lookup answers every login (proxy-only mode).
			srv, err := New(context.Background(), nil, "localhost", ServerOptions{
				Name:               "authzid",
				Addr:               addr,
				RemoteAddrs:        []string{backendAddr},
				ConnectTimeout:     2 * time.Second,
				InsecureAuth:       true,
				MasterUsername:     "admin",
				MasterPassword:     "master-secret",
				MasterSASLUsername: "proxy-master",
				MasterSASLPassword: "proxy-master-secret",
				RemoteLookup:       &config.RemoteLookupConfig{Enabled: true, URL: lookupSrv.URL + "/lookup?email=$email", Timeout: "5s"},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			srv.authLimiter.Stop()
			limiter := &failureCountingLimiter{}
			srv.authLimiter = limiter
			go func() { _ = srv.Start() }()
			t.Cleanup(func() { srv.Stop() })

			conn, r := dialTest(t, addr)
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			readReply := func() string {
				t.Helper()
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						t.Fatalf("read reply: %v", err)
					}
					if strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "NO") || strings.HasPrefix(line, "BYE") {
						return strings.TrimRight(line, "\r\n")
					}
				}
			}
			authenticate := func(authzid, authcid, password string) string {
				t.Helper()
				msg := base64.StdEncoding.EncodeToString([]byte(authzid + "\x00" + authcid + "\x00" + password))
				if _, err := io.WriteString(conn, `AUTHENTICATE "PLAIN" "`+msg+"\"\r\n"); err != nil {
					t.Fatalf("send AUTHENTICATE: %v", err)
				}
				return readReply()
			}
			if greeting := readReply(); !strings.HasPrefix(greeting, "OK") {
				t.Fatalf("greeting: %q", greeting)
			}

			if got := authenticate(tc.authzid, tc.authcid, tc.password); got != tc.want {
				t.Fatalf("AUTHENTICATE PLAIN %q/%q: reply %q, want %q", tc.authzid, tc.authcid, got, tc.want)
			}
			wantFailures := int32(0)
			if tc.password == "wrong" {
				wantFailures = 1
			}
			if got := limiter.failures.Load(); got != wantFailures {
				t.Fatalf("failed-login charges = %d, want %d", got, wantFailures)
			}
			wantBackend := tc.backendAs
			if wantBackend == "" {
				if tc.want == refused {
					for range 4 {
						if got := authenticate(tc.authzid, tc.authcid, tc.password); got != refused {
							t.Fatalf("repeated authorization refusal: %q", got)
						}
					}
					if got := limiter.failures.Load(); got != 0 {
						t.Fatalf("authorization refusals charged %d failed logins", got)
					}
				}
				// The refusal leaves the session in the not authenticated state, ready for
				// another attempt, which is the only one the backend may see.
				if got := authenticate("", sieveTestUser, sieveTestPassword); got != `OK "Authenticated"` {
					t.Fatalf("AUTHENTICATE after the refusal: reply %q, want OK", got)
				}
				wantBackend = sieveTestUser
			}
			conn.Close()

			var loggedInAs []string
			for _, cmd := range commands() {
				args, ok := strings.CutPrefix(cmd, `AUTHENTICATE "PLAIN" "`)
				if !ok {
					continue
				}
				decoded, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(args, `"`))
				if err != nil {
					t.Fatalf("backend AUTHENTICATE %q: %v", cmd, err)
				}
				authzid, _, _ := strings.Cut(string(decoded), "\x00")
				loggedInAs = append(loggedInAs, authzid)
			}
			if len(loggedInAs) != 1 || loggedInAs[0] != wantBackend {
				t.Errorf("the proxy logged in to the backend as %q, want only %q", loggedInAs, wantBackend)
			}
		})
	}
}

type authzSieveClientConn struct {
	net.Conn
	remote   net.Addr
	mu       sync.Mutex
	username string
}

func (c *authzSieveClientConn) RemoteAddr() net.Addr { return c.remote }

func (c *authzSieveClientConn) SetUsername(u string) {
	c.mu.Lock()
	c.username = u
	c.mu.Unlock()
}

func (c *authzSieveClientConn) Username() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.username
}

type authzSieveRoutingLookup struct {
	actualEmail string
}

func (l authzSieveRoutingLookup) LookupUserRoute(context.Context, string, string) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return &proxy.UserRoutingInfo{AccountID: 42, ActualEmail: l.actualEmail, IsRemoteLookupAccount: true}, proxy.AuthSuccess, nil
}

func (l authzSieveRoutingLookup) LookupUserRouteWithOptions(context.Context, string, string, bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return &proxy.UserRoutingInfo{AccountID: 42, ActualEmail: l.actualEmail, IsRemoteLookupAccount: true}, proxy.AuthSuccess, nil
}

func (l authzSieveRoutingLookup) LookupUserRouteWithClientIP(context.Context, string, string, string, bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return &proxy.UserRoutingInfo{AccountID: 42, ActualEmail: l.actualEmail, IsRemoteLookupAccount: true}, proxy.AuthSuccess, nil
}

func (l authzSieveRoutingLookup) Close() error { return nil }

// TestAuthenticatePlainRefusalAccountingAndSessionHygiene verifies that a SASL PLAIN
// attempt whose credentials check out but whose authorization identity is refused
// counts no successful login, domain connection, or per-user connection, does not
// clear prior rate-limiter failure tracking, logs "authorization failed" (with
// address, authzid, and method) without logging "authentication successful", and
// leaves the unauthenticated session and connection clean.
func TestAuthenticatePlainRefusalAccountingAndSessionHygiene(t *testing.T) {
	enable, domainEnabled, threshold, maxUsers, hashNames := metrics.EnableUserMetrics, metrics.EnableDomainMetrics, metrics.UserMetricsThreshold, metrics.MaxTrackedUsers, metrics.HashUsernames
	metrics.Configure(true, true, 1, 1000, false)
	t.Cleanup(func() { metrics.Configure(enable, domainEnabled, threshold, maxUsers, hashNames) })

	origCost := db.BcryptCost
	db.BcryptCost = 4
	t.Cleanup(func() { db.BcryptCost = origCost })
	hash, err := db.GenerateBcryptHash("secret")
	if err != nil {
		t.Fatalf("GenerateBcryptHash: %v", err)
	}

	cases := []struct {
		name       string
		domain     string
		useMaster  bool
		wantMethod string
	}{
		{name: "cache", domain: "sieve-authz-cache.example", wantMethod: "cache"},
		{name: "remotelookup", domain: "sieve-authz-lookup.example", wantMethod: "remotelookup"},
		{name: "main_db", domain: "sieve-authz-db.example", wantMethod: "main_db"},
		{name: "master", domain: "sieve-authz-master.example", useMaster: true, wantMethod: "master"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			userEmail := "user@" + tc.domain
			authcid, password := userEmail, "secret"
			if tc.useMaster {
				authcid = userEmail + "@admin"
				password = "master-secret"
			}
			srvName := "sieve-authz-hygiene-" + tc.name
			const srvHost = "test-host"
			const clientIP = "203.0.113.43"
			clientAddr := &net.TCPAddr{IP: net.ParseIP(clientIP), Port: 54321}

			limiter := server.NewAuthRateLimiter("managesieve_proxy", srvName, srvHost, server.AuthRateLimiterConfig{
				Enabled:          true,
				MaxAttemptsPerIP: 3,
				IPBlockDuration:  time.Hour,
				IPWindowDuration: time.Hour,
				CleanupInterval:  time.Hour,
			})
			t.Cleanup(limiter.Stop)
			// Pre-record 2 failed attempts from clientIP (1 short of the 3-attempt IP block).
			limiter.RecordAuthAttempt(ctx, clientAddr, "guess1@"+tc.domain, false)
			limiter.RecordAuthAttempt(ctx, clientAddr, "guess2@"+tc.domain, false)

			cache := newMSTestLookupCache(t)
			var cm *proxy.ConnectionManager
			var rdb *resilient.ResilientDatabase
			switch tc.wantMethod {
			case "cache":
				var cmErr error
				cm, cmErr = proxy.NewConnectionManager([]string{"127.0.0.1:1"}, 4190, false, false, false, 200*time.Millisecond)
				if cmErr != nil {
					t.Fatalf("NewConnectionManager: %v", cmErr)
				}
				cache.Set(srvName, authcid, &lookupcache.CacheEntry{
					AccountID:      42,
					PasswordDigest: lookupcache.NewPasswordDigest(password),
					Result:         lookupcache.AuthSuccess,
				})
			case "remotelookup", "master":
				var cmErr error
				cm, cmErr = proxy.NewConnectionManagerWithRouting([]string{"127.0.0.1:1"}, 4190, false, false, false, 200*time.Millisecond, authzSieveRoutingLookup{actualEmail: userEmail}, srvName)
				if cmErr != nil {
					t.Fatalf("NewConnectionManagerWithRouting: %v", cmErr)
				}
			case "main_db":
				var cmErr error
				cm, cmErr = proxy.NewConnectionManager([]string{"127.0.0.1:1"}, 4190, false, false, false, 200*time.Millisecond)
				if cmErr != nil {
					t.Fatalf("NewConnectionManager: %v", cmErr)
				}
				rdb = &resilient.ResilientDatabase{}
				rdb.SetAuthCache(&replayAuthCache{hash: hash})
			}

			srv := &Server{
				name:                       srvName,
				hostname:                   srvHost,
				ctx:                        ctx,
				cancel:                     cancel,
				activeSessions:             make(map[*Session]struct{}),
				connManager:                cm,
				lookupCache:                cache,
				authLimiter:                limiter,
				rdb:                        rdb,
				positiveRevalidationWindow: 30 * time.Second,
				masterUsername:             []byte("admin"),
				masterPassword:             []byte("master-secret"),
				insecureAuth:               true,
			}
			srv.settings.Store(&reloadableSettings{
				authIdleTimeout: 5 * time.Second,
			})

			logs := &logBuffer{}
			prev := logger.Swap(slog.New(slog.NewTextHandler(logs, nil)))
			t.Cleanup(func() { logger.Swap(prev) })

			successBefore := testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", srvName, srvHost, "success"))
			failureBefore := testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", srvName, srvHost, "failure"))
			domainBefore := testutil.ToFloat64(metrics.DomainConnectionCount.WithLabelValues("managesieve_proxy", tc.domain))
			userBefore := testutil.ToFloat64(metrics.HeavyUserOperations.WithLabelValues("managesieve_proxy", userEmail, "connection"))

			rawServer, remote := net.Pipe()
			defer remote.Close()
			clientConn := &authzSieveClientConn{Conn: rawServer, remote: clientAddr}
			sessCtx, sessCancel := context.WithCancel(ctx)
			sess := &Session{
				server:       srv,
				settings:     srv.loadSettings(),
				clientConn:   clientConn,
				listenerConn: clientConn,
				clientAddr:   clientIP,
				ctx:          sessCtx,
				cancel:       sessCancel,
				startTime:    time.Now(),
				sessionID:    "test-session",
			}

			authErr := sess.AuthenticatePlain(sessCtx, "other@"+tc.domain, authcid, password)
			if authErr == nil || !strings.Contains(authErr.Error(), "Proxy authentication requires master credentials") {
				t.Fatalf("AuthenticatePlain error = %v, want authorization failure", authErr)
			}
			if err := sess.Close(); err != nil {
				t.Fatalf("sess.Close: %v", err)
			}

			if d := testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", srvName, srvHost, "success")) - successBefore; d != 0 {
				t.Errorf("AuthenticationAttempts{result=success} grew by %v on refused authzID, want 0", d)
			}
			if d := testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", srvName, srvHost, "failure")) - failureBefore; d != 0 {
				t.Errorf("AuthenticationAttempts{result=failure} grew by %v on refused authzID, want 0", d)
			}
			if d := testutil.ToFloat64(metrics.DomainConnectionCount.WithLabelValues("managesieve_proxy", tc.domain)) - domainBefore; d != 0 {
				t.Errorf("DomainConnectionCount grew by %v on refused authzID, want 0", d)
			}
			if d := testutil.ToFloat64(metrics.HeavyUserOperations.WithLabelValues("managesieve_proxy", userEmail, "connection")) - userBefore; d != 0 {
				t.Errorf("HeavyUserOperations{operation=connection} grew by %v on refused authzID, want 0", d)
			}

			// A 3rd wrong-password attempt from the same IP must block it (2 prior + 1 = 3).
			limiter.RecordAuthAttempt(ctx, clientAddr, "guess3@"+tc.domain, false)
			if !limiter.IsIPBlocked(clientAddr) {
				t.Errorf("refused authzID cleared prior rate-limiter failure tracking for %s", clientIP)
			}

			if sess.username != "" || sess.accountID != 0 || sess.routingInfo != nil || sess.isRemoteLookupAccount {
				t.Errorf("unauthenticated session left dirty after refused authzID: username=%q accountID=%d routingInfo=%v isRemoteLookupAccount=%v",
					sess.username, sess.accountID, sess.routingInfo, sess.isRemoteLookupAccount)
			}
			if got := clientConn.Username(); got != "" {
				t.Errorf("listenerConn username = %q on unauthenticated session, want empty", got)
			}

			logOut := logs.String()
			if strings.Contains(logOut, `msg="authentication successful"`) {
				t.Errorf("refused authzID logged authentication successful:\n%s", logOut)
			}
			var authzLine, disconnectLine string
			for _, line := range strings.Split(logOut, "\n") {
				if strings.Contains(line, `msg="authorization failed"`) {
					authzLine = line
				}
				if strings.Contains(line, `msg=disconnected`) {
					disconnectLine = line
				}
			}
			if authzLine == "" {
				t.Errorf("missing authorization failed log line:\n%s", logOut)
			} else {
				for _, want := range []string{
					"address=" + userEmail,
					"authzid=other@" + tc.domain,
					"method=" + tc.wantMethod,
					"account_id=0",
				} {
					if !strings.Contains(authzLine, want) {
						t.Errorf("authorization failed log %q missing %q", authzLine, want)
					}
				}
			}
			if disconnectLine == "" {
				t.Errorf("missing disconnected log line:\n%s", logOut)
			} else {
				for _, want := range []string{`user=""`, "account_id=0"} {
					if !strings.Contains(disconnectLine, want) {
						t.Errorf("unauthenticated disconnect log %q missing %q", disconnectLine, want)
					}
				}
			}
		})
	}
}
