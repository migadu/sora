package imapproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// authzBackend serves IMAP backend connections that accept every AUTHENTICATE PLAIN
// and reports, for each, the authorization identity the proxy logged in as.
func authzBackend(t *testing.T) (addr string, loggedInAs <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	identities := make(chan string, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				io.WriteString(conn, "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] fake backend ready\r\n")
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					fields := strings.Fields(line)
					if len(fields) == 4 && strings.EqualFold(fields[1], "AUTHENTICATE") {
						decoded, _ := base64.StdEncoding.DecodeString(fields[3])
						authzid, _, _ := strings.Cut(string(decoded), "\x00")
						identities <- authzid
						io.WriteString(conn, fields[0]+" OK logged in\r\n")
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), identities
}

// TestAuthenticatePlainRefusesOtherAuthorizationIdentity: the proxy must not log a
// client in as its authentication identity when it asked to act as somebody else.
// RFC 4616 section 2: "the server will verify the presented (in the message)
// authentication identity (authcid) and password (passwd) with the system
// authentication database, and it will verify that the authentication credentials
// permit the client to act as the (presented or derived) authorization identity
// (authzid). If both steps succeed, the user is authenticated." These credentials
// permit acting only as the account they log in to, so another authorization
// identity is refused with AUTHORIZATIONFAILED (RFC 5530 section 3), as the backend
// refuses it, and only once the credentials checked out. An authorization identity
// that names the account logged in to, as the authentication identity or as the
// address the login resolved to (the master username form's target), is accepted.
func TestAuthenticatePlainRefusesOtherAuthorizationIdentity(t *testing.T) {
	const refused = "a1 NO [AUTHORIZATIONFAILED] Proxy login not permitted for this user."
	cases := []struct {
		name                       string
		authzid, authcid, password string
		want                       string // the tagged reply, or its prefix for an OK
		backendAs                  string // the identity the backend logs in; "" for none
	}{
		{name: "other identity", authzid: "other@example.com", authcid: "user@example.com", password: "secret", want: refused},
		{name: "other identity, wrong password", authzid: "other@example.com", authcid: "user@example.com", password: "wrong", want: "a1 NO Authentication failed"},
		{name: "no authorization identity", authcid: "user@example.com", password: "secret", want: "a1 OK", backendAs: "user@example.com"},
		{name: "own identity", authzid: "user@example.com", authcid: "user@example.com", password: "secret", want: "a1 OK", backendAs: "user@example.com"},
		{name: "own identity, +detail", authzid: "user+tag@example.com", authcid: "user+tag@example.com", password: "secret", want: "a1 OK", backendAs: "user@example.com"},
		{name: "resolved identity for +detail", authzid: "user@example.com", authcid: "user+tag@example.com", password: "secret", want: "a1 OK", backendAs: "user@example.com"},
		{name: "resolved cached token identity", authzid: "user@example.com", authcid: "user@TOKEN", password: "secret", want: "a1 OK", backendAs: "user@example.com"},
		{name: "cached token, other identity", authzid: "other@example.com", authcid: "user@TOKEN", password: "secret", want: refused},
		{name: "master username form", authcid: "user@example.com@admin", password: "master-secret", want: "a1 OK", backendAs: "user@example.com"},
		{name: "master username form, its target", authzid: "user@example.com", authcid: "user@example.com@admin", password: "master-secret", want: "a1 OK", backendAs: "user@example.com"},
		{name: "master username form, other identity", authzid: "other@example.com", authcid: "user@example.com@admin", password: "master-secret", want: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backendAddr, loggedInAs := authzBackend(t)
			cm, err := proxy.NewConnectionManagerFromOptions(proxy.ManagerOptions{
				RemoteAddrs:        []string{backendAddr},
				RemotePort:         143,
				ConnectTimeout:     2 * time.Second,
				ServerName:         "test",
				DisableHealthCheck: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cache := newTestLookupCache(t)
			limiter := &failureCountingLimiter{}
			srv := &Server{
				name:                       "test",
				hostname:                   "test-host",
				ctx:                        ctx,
				cancel:                     cancel,
				activeSessions:             make(map[*Session]struct{}),
				connManager:                cm,
				lookupCache:                cache,
				authLimiter:                limiter,
				positiveRevalidationWindow: 30 * time.Second,
				masterUsername:             []byte("admin"),
				masterPassword:             []byte("master-secret"),
				insecureAuth:               true,
			}
			srv.settings.Store(&reloadableSettings{
				maxAuthErrors:      3,
				authIdleTimeout:    5 * time.Second,
				masterSASLUsername: []byte("proxy"),
				masterSASLPassword: []byte("proxy-secret"),
			})
			// The entries earlier logins left behind, so no database is needed.
			for _, login := range []struct{ username, password string }{
				{"user@example.com", "secret"},
				{"user+tag@example.com", "secret"},
				{"user@example.com@admin", "master-secret"},
			} {
				cache.Set("test", login.username, &lookupcache.CacheEntry{
					AccountID:      42,
					PasswordDigest: lookupcache.NewPasswordDigest(login.password),
					Result:         lookupcache.AuthSuccess,
				})
			}
			cache.Set("test", "user@TOKEN", &lookupcache.CacheEntry{
				AccountID: 42, ActualEmail: "user@example.com",
				PasswordDigest: lookupcache.NewPasswordDigest("secret"), Result: lookupcache.AuthSuccess,
			})

			client, remote := net.Pipe()
			sess := newSession(srv, client)
			done := make(chan struct{})
			go func() {
				defer close(done)
				sess.handleConnection()
			}()
			defer func() {
				remote.Close()
				<-done
			}()
			remote.SetDeadline(time.Now().Add(10 * time.Second))
			r := bufio.NewReader(remote)
			if _, err := r.ReadString('\n'); err != nil {
				t.Fatalf("greeting: %v", err)
			}

			authenticate := func(tag, authzid, authcid, password string) string {
				t.Helper()
				msg := base64.StdEncoding.EncodeToString([]byte(authzid + "\x00" + authcid + "\x00" + password))
				if _, err := io.WriteString(remote, tag+" AUTHENTICATE PLAIN "+msg+"\r\n"); err != nil {
					t.Fatalf("send AUTHENTICATE: %v", err)
				}
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						t.Fatalf("read AUTHENTICATE reply: %v", err)
					}
					if strings.HasPrefix(line, tag+" ") {
						return strings.TrimRight(line, "\r\n")
					}
				}
			}

			got := authenticate("a1", tc.authzid, tc.authcid, tc.password)
			if got != tc.want && !(tc.want == "a1 OK" && strings.HasPrefix(got, "a1 OK ")) {
				t.Fatalf("AUTHENTICATE PLAIN %q/%q: reply %q, want %q", tc.authzid, tc.authcid, got, tc.want)
			}
			wantFailures := int32(0)
			if tc.password == "wrong" {
				wantFailures = 1
			}
			if got := limiter.failures.Load(); got != wantFailures {
				t.Fatalf("failed-login charges = %d, want %d", got, wantFailures)
			}
			if tc.backendAs != "" {
				select {
				case as := <-loggedInAs:
					if as != tc.backendAs {
						t.Errorf("the proxy logged in to the backend as %q, want %q", as, tc.backendAs)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("the proxy did not log in to the backend")
				}
				return
			}
			select {
			case as := <-loggedInAs:
				t.Fatalf("a refused login logged in to the backend as %q", as)
			default:
			}
			if tc.want == refused {
				// More refusals than maxAuthErrors must still permit a later login:
				// proven credentials plus refused authorization is no command error.
				for range 4 {
					if got := authenticate("a1", tc.authzid, tc.authcid, tc.password); got != refused {
						t.Fatalf("repeated authorization refusal: %q", got)
					}
				}
				if got := limiter.failures.Load(); got != 0 {
					t.Fatalf("authorization refusals charged %d failed logins", got)
				}
			}

			// The refusal leaves the session in the not authenticated state, ready for
			// another attempt.
			if got := authenticate("a2", "", "user@example.com", "secret"); !strings.HasPrefix(got, "a2 OK ") {
				t.Fatalf("AUTHENTICATE after the refusal: reply %q, want a2 OK", got)
			}
			select {
			case as := <-loggedInAs:
				if as != "user@example.com" {
					t.Errorf("after the refusal the proxy logged in to the backend as %q, want user@example.com", as)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("after the refusal the proxy did not log in to the backend")
			}
		})
	}
}

type authzClientConn struct {
	net.Conn
	remote   net.Addr
	mu       sync.Mutex
	username string
}

func (c *authzClientConn) RemoteAddr() net.Addr { return c.remote }

func (c *authzClientConn) SetUsername(u string) {
	c.mu.Lock()
	c.username = u
	c.mu.Unlock()
}

func (c *authzClientConn) Username() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.username
}

type authzRoutingLookup struct {
	actualEmail string
}

func (l authzRoutingLookup) LookupUserRoute(context.Context, string, string) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return &proxy.UserRoutingInfo{AccountID: 42, ActualEmail: l.actualEmail, IsRemoteLookupAccount: true}, proxy.AuthSuccess, nil
}

func (l authzRoutingLookup) LookupUserRouteWithOptions(context.Context, string, string, bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return &proxy.UserRoutingInfo{AccountID: 42, ActualEmail: l.actualEmail, IsRemoteLookupAccount: true}, proxy.AuthSuccess, nil
}

func (l authzRoutingLookup) LookupUserRouteWithClientIP(context.Context, string, string, string, bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return &proxy.UserRoutingInfo{AccountID: 42, ActualEmail: l.actualEmail, IsRemoteLookupAccount: true}, proxy.AuthSuccess, nil
}

func (l authzRoutingLookup) Close() error { return nil }

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
		{name: "cache", domain: "authz-cache.example", wantMethod: "cache"},
		{name: "remotelookup", domain: "authz-lookup.example", wantMethod: "remotelookup"},
		{name: "main_db", domain: "authz-db.example", wantMethod: "main_db"},
		{name: "master", domain: "authz-master.example", useMaster: true, wantMethod: "master"},
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
			srvName := "authz-hygiene-" + tc.name
			const srvHost = "test-host"
			const clientIP = "203.0.113.42"
			clientAddr := &net.TCPAddr{IP: net.ParseIP(clientIP), Port: 54321}

			limiter := server.NewAuthRateLimiter("imap_proxy", srvName, srvHost, server.AuthRateLimiterConfig{
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

			cache := newTestLookupCache(t)
			var cm *proxy.ConnectionManager
			var rdb *resilient.ResilientDatabase
			switch tc.wantMethod {
			case "cache":
				cm = newTestConnManager(t, "127.0.0.1:1")
				cache.Set(srvName, authcid, &lookupcache.CacheEntry{
					AccountID:      42,
					PasswordDigest: lookupcache.NewPasswordDigest(password),
					Result:         lookupcache.AuthSuccess,
				})
			case "remotelookup", "master":
				var cmErr error
				cm, cmErr = proxy.NewConnectionManagerWithRouting([]string{"127.0.0.1:1"}, 143, false, false, false, 200*time.Millisecond, authzRoutingLookup{actualEmail: userEmail}, srvName)
				if cmErr != nil {
					t.Fatalf("NewConnectionManagerWithRouting: %v", cmErr)
				}
			case "main_db":
				cm = newTestConnManager(t, "127.0.0.1:1")
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
				maxAuthErrors:   3,
				authIdleTimeout: 5 * time.Second,
			})

			logs := &lockedBuffer{}
			prev := logger.Swap(slog.New(slog.NewTextHandler(logs, nil)))
			t.Cleanup(func() { logger.Swap(prev) })

			successBefore := testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", srvName, srvHost, "success"))
			failureBefore := testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", srvName, srvHost, "failure"))
			domainBefore := testutil.ToFloat64(metrics.DomainConnectionCount.WithLabelValues("imap_proxy", tc.domain))
			userBefore := testutil.ToFloat64(metrics.HeavyUserOperations.WithLabelValues("imap_proxy", userEmail, "connection"))

			rawServer, remote := net.Pipe()
			clientConn := &authzClientConn{Conn: rawServer, remote: clientAddr}
			sess := newSession(srv, clientConn)
			done := make(chan struct{})
			go func() {
				defer close(done)
				sess.handleConnection()
			}()
			defer func() {
				remote.Close()
				<-done
			}()

			remote.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(remote)
			if _, err := r.ReadString('\n'); err != nil {
				t.Fatalf("greeting: %v", err)
			}

			msg := base64.StdEncoding.EncodeToString([]byte("other@" + tc.domain + "\x00" + authcid + "\x00" + password))
			if _, err := io.WriteString(remote, "a1 AUTHENTICATE PLAIN "+msg+"\r\n"); err != nil {
				t.Fatalf("send AUTHENTICATE: %v", err)
			}
			reply, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("read AUTHENTICATE reply: %v", err)
			}
			const wantReply = "a1 NO [AUTHORIZATIONFAILED] Proxy login not permitted for this user."
			if got := strings.TrimRight(reply, "\r\n"); got != wantReply {
				t.Fatalf("AUTHENTICATE PLAIN reply = %q, want %q", got, wantReply)
			}

			// Disconnect cleanly while still unauthenticated so close() runs and
			// session fields can be inspected without racing handleConnection().
			if _, err := io.WriteString(remote, "a2 LOGOUT\r\n"); err != nil {
				t.Fatalf("send LOGOUT: %v", err)
			}
			for {
				line, err := r.ReadString('\n')
				if err != nil || strings.HasPrefix(line, "a2 ") {
					break
				}
			}
			remote.Close()
			<-done

			if d := testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", srvName, srvHost, "success")) - successBefore; d != 0 {
				t.Errorf("AuthenticationAttempts{result=success} grew by %v on refused authzID, want 0", d)
			}
			if d := testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", srvName, srvHost, "failure")) - failureBefore; d != 0 {
				t.Errorf("AuthenticationAttempts{result=failure} grew by %v on refused authzID, want 0", d)
			}
			if d := testutil.ToFloat64(metrics.DomainConnectionCount.WithLabelValues("imap_proxy", tc.domain)) - domainBefore; d != 0 {
				t.Errorf("DomainConnectionCount grew by %v on refused authzID, want 0", d)
			}
			if d := testutil.ToFloat64(metrics.HeavyUserOperations.WithLabelValues("imap_proxy", userEmail, "connection")) - userBefore; d != 0 {
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
