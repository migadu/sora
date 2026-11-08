package lmtp

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

// Server.Close logs every open connection's session out from the closing goroutine. When it
// lands while re-LHLO, XCLIENT or STARTTLS is replacing a connection's session, each session
// must still be logged out once (migadu/go-smtp#17): Logout gives back the session's share of
// activeConnections and the ConnectionsCurrent gauge, so a second Logout leaves both one short.
// A transaction open on the replaced session must still end, or DrainSessions never reaches 0.

// stallingSession counts the Logouts it started and the ones that returned. When stall is set,
// the first Logout waits for release before it logs the session out, so the test can close the
// server while that Logout runs.
type stallingSession struct {
	*LMTPSession
	logouts  atomic.Int32
	returned atomic.Int32
	stall    bool
	inLogout chan struct{}
	release  chan struct{}
}

func (s *stallingSession) Logout() error {
	defer s.returned.Add(1)
	if s.logouts.Add(1) == 1 && s.stall {
		close(s.inLogout)
		<-s.release
	}
	return s.LMTPSession.Logout()
}

func TestEverySessionLoggedOutOnceWhenServerClosesDuringReplacement(t *testing.T) {
	cert := selfSignedTestCert(t)
	for _, tc := range []struct {
		name string
		// openTransactions is what DrainSessions reports while the first session's Logout runs.
		openTransactions int64
		// replace sends the command that makes go-smtp log the first session out.
		replace func(t *testing.T, c net.Conn, r *bufio.Reader)
	}{
		{"re-LHLO", 1, func(t *testing.T, c net.Conn, r *bufio.Reader) {
			// A repeated LHLO may come mid-transaction; XCLIENT and STARTTLS may not.
			io.WriteString(c, "MAIL FROM:<sender@example.com>\r\n")
			if line := readReplyLine(t, r); !strings.HasPrefix(line, "250 ") {
				t.Fatalf("MAIL: %q", line)
			}
			io.WriteString(c, "LHLO proxy.example.com\r\n")
		}},
		{"XCLIENT", 0, func(t *testing.T, c net.Conn, _ *bufio.Reader) {
			io.WriteString(c, "XCLIENT ADDR=192.0.2.1\r\n")
		}},
		{"STARTTLS", 0, func(t *testing.T, c net.Conn, r *bufio.Reader) {
			io.WriteString(c, "STARTTLS\r\n")
			if line := readReplyLine(t, r); !strings.HasPrefix(line, "220 ") {
				t.Fatalf("STARTTLS: %q", line)
			}
			// go-smtp logs the session out once the handshake completes.
			go tls.Client(c, &tls.Config{InsecureSkipVerify: true}).Handshake()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trusted := mustParseNets(t, []string{"127.0.0.0/8"})
			b := &LMTPServerBackend{
				name:               "test",
				hostname:           "test",
				trustedNetworks:    trusted,
				xclientTrustedNets: trusted,
			}

			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseFirst := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseFirst()

			var mu sync.Mutex
			var sessions []*stallingSession
			srv := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
				s, err := b.NewSession(c)
				if err != nil {
					return nil, err
				}
				mu.Lock()
				defer mu.Unlock()
				ss := &stallingSession{
					LMTPSession: s.(*LMTPSession),
					stall:       len(sessions) == 0,
					inLogout:    make(chan struct{}),
					release:     release,
				}
				sessions = append(sessions, ss)
				return ss, nil
			}))
			srv.LMTP = true
			srv.Domain = "test"
			srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
			srv.EnableXCLIENT = true
			srv.XCLIENTTrustedNets = trusted

			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			go srv.Serve(l)
			defer srv.Close()

			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			r := bufio.NewReader(c)
			readReplyLine(t, r) // greeting
			io.WriteString(c, "LHLO proxy.example.com\r\n")
			for !strings.HasPrefix(readReplyLine(t, r), "250 ") {
			}
			mu.Lock()
			first := sessions[0]
			mu.Unlock()

			tc.replace(t, c, r)
			select {
			case <-first.inLogout:
			case <-time.After(5 * time.Second):
				t.Fatal("go-smtp did not log the first session out")
			}
			if n := b.DrainSessions(); n != tc.openTransactions {
				t.Fatalf("DrainSessions() = %d while the first session's Logout runs, want %d", n, tc.openTransactions)
			}

			// Close the server while that Logout runs, then let it finish.
			closed := make(chan struct{})
			go func() { defer close(closed); srv.Close() }()
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("Server.Close did not return")
			}
			releaseFirst()

			// The connection's goroutine logs out whatever session it still holds once it sees
			// the closed connection; wait until every session was logged out and no Logout runs.
			allLoggedOut := func() bool {
				mu.Lock()
				defer mu.Unlock()
				for _, s := range sessions {
					if n := s.returned.Load(); n == 0 || n != s.logouts.Load() {
						return false
					}
				}
				return true
			}
			for deadline := time.Now().Add(5 * time.Second); !allLoggedOut() && time.Now().Before(deadline); {
				time.Sleep(time.Millisecond)
			}

			mu.Lock()
			defer mu.Unlock()
			for i, s := range sessions {
				if n := s.logouts.Load(); n != 1 {
					t.Errorf("session %d was logged out %d times, want 1", i, n)
				}
			}
			if n := b.activeConnections.Load(); n != 0 {
				t.Errorf("activeConnections = %d after every session ended, want 0", n)
			}
			if n := b.DrainSessions(); n != 0 {
				t.Errorf("DrainSessions() = %d after every session ended, want 0", n)
			}
		})
	}
}

func readReplyLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("reading reply: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

func selfSignedTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
