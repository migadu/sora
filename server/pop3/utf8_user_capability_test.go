package pop3

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// startUTF8TestServer starts a database-less POP3 backend with plaintext login
// allowed and the counting auth limiter, and waits until it accepts.
func startUTF8TestServer(t *testing.T, limiter *unparseableLoginLimiter) string {
	t.Helper()
	s, addr := newReloadTestServer(t, POP3ServerOptions{
		InsecureAuth:        true,
		CommandTimeout:      time.Minute,
		AuthLimiterOverride: limiter,
	})
	errChan := make(chan error, 1)
	go s.Start(errChan)
	t.Cleanup(s.Close)
	for deadline := time.Now().Add(3 * time.Second); ; {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func dialUTF8TestServer(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)
	if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("greeting = %q, %v", line, err)
	}
	return conn, r
}

// TestCAPAAdvertisesUTF8User: Sora accepts UTF-8 user names and passwords, so its
// UTF8 capability must carry the USER argument. RFC 6856 section 2.2: "If the USER
// argument is included with this capability, it indicates that the server accepts
// UTF-8 usernames and passwords. [...] Clients MUST NOT use UTF-8 characters when
// authenticating if the server did not include the USER argument in the UTF8
// capability response." (#1934)
func TestCAPAAdvertisesUTF8User(t *testing.T) {
	addr := startUTF8TestServer(t, &unparseableLoginLimiter{})
	conn, r := dialUTF8TestServer(t, addr)

	caps := strings.Split(readCapa(t, conn, r), "\n")
	var utf8Lines []string
	for _, c := range caps {
		if strings.EqualFold(strings.Fields(c)[0], "UTF8") {
			utf8Lines = append(utf8Lines, c)
		}
	}
	if len(utf8Lines) != 1 || utf8Lines[0] != "UTF8 USER" {
		t.Fatalf("CAPA UTF8 lines = %q, want exactly [\"UTF8 USER\"]; full CAPA:\n%s", utf8Lines, strings.Join(caps, "\n"))
	}
}

// TestLoginWithInvalidUTF8IsRefusedBeforeCredentialCheck: RFC 6856 section 2.2:
// "The server MUST reject UTF-8 usernames or passwords that fail to comply with the
// formal syntax in UTF-8 [RFC3629]." Such a login is refused with the bad-credential
// reply before anything looks the credentials up (this server has no database), as a
// failed login recorded by the auth limiter (#1987). The session stays usable.
// (#1934)
func TestLoginWithInvalidUTF8IsRefusedBeforeCredentialCheck(t *testing.T) {
	cases := []struct{ name, user, pass string }{
		{"password, stray continuation byte", "user@example.com", "secret\x80"},
		{"password, Latin-1 e-acute", "user@example.com", "caf\xe9"},
		{"user name, Latin-1 e-acute", "jos\xe9@example.com", "secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			limiter := &unparseableLoginLimiter{}
			addr := startUTF8TestServer(t, limiter)
			conn, r := dialUTF8TestServer(t, addr)

			fmt.Fprintf(conn, "USER %s\r\n", tc.user)
			if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
				t.Fatalf("USER = %q, %v", line, err)
			}
			fmt.Fprintf(conn, "PASS %s\r\n", tc.pass)
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("PASS: no reply: %v", err)
			}
			if got := strings.TrimRight(line, "\r\n"); got != "-ERR [AUTH] Authentication failed" {
				t.Fatalf("PASS reply = %q, want -ERR [AUTH] Authentication failed", got)
			}
			if n := limiter.failures.Load(); n != 1 {
				t.Errorf("the auth limiter recorded %d failed attempts, want 1", n)
			}

			// The connection is still served.
			readCapa(t, conn, r)
		})
	}
}
