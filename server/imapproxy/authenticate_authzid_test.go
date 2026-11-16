package imapproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server/proxy"
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
			srv := &Server{
				name:                       "test",
				hostname:                   "test-host",
				ctx:                        ctx,
				cancel:                     cancel,
				activeSessions:             make(map[*Session]struct{}),
				connManager:                cm,
				lookupCache:                cache,
				authLimiter:                &fakeAuthLimiter{},
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
