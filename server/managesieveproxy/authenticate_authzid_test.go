package managesieveproxy

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
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
