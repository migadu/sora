package pop3proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server"
)

// statusBackend serves one plaintext connection: a greeting, then for each command the
// proxy sends the reply replies names for it, if any. It ends when the proxy closes.
func statusBackend(t *testing.T, replies map[string]string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(conn, "+OK fake backend ready\r\n")
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			command, _, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
			if reply, ok := replies[command]; ok {
				io.WriteString(conn, reply+"\r\n")
			}
		}
	}()
	return ln.Addr().String()
}

// statusTestSession is a session whose backend leg goes to addr, with debug logging on.
func statusTestSession(t *testing.T, addr string) *POP3ProxySession {
	t.Helper()
	clientA, clientB := net.Pipe()
	t.Cleanup(func() { clientA.Close(); clientB.Close() })
	srv := &POP3ProxyServer{
		name:        "test",
		hostname:    "test-host",
		connManager: newPOP3TestConnManager(t, addr, 2*time.Second),
	}
	srv.settings.Store(&reloadableSettings{debug: true})
	return &POP3ProxySession{
		server:       srv,
		clientConn:   clientA,
		listenerConn: clientA,
		ctx:          context.Background(),
		username:     "user@example.com",
	}
}

// connectLogged runs connectToBackend with the global logger captured at DEBUG and
// returns what it logged and its error.
func connectLogged(t *testing.T, sess *POP3ProxySession) (string, error) {
	t.Helper()
	var mu sync.Mutex
	var buf bytes.Buffer
	w := writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	})
	prev := logger.Swap(slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})))
	err := sess.connectToBackend()
	logger.Swap(prev)
	if sess.backendConn != nil {
		sess.backendConn.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	return buf.String(), err
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// The status indicator of a backend reply is matched as a whole and in any case: RFC
// 2449 section 3, single-line = status [SP text] CRLF, status = "+OK" / "-ERR", whose
// ABNF strings are case-insensitive (RFC 2234 section 2.3). So +ok is the +OK status
// and +OKAY is no status at all, at the AUTH, UTF8 and XCLIENT replies as at the
// greeting and STLS ones.

func TestConnectToBackendAuthReplyStatus(t *testing.T) {
	for _, tc := range []struct {
		reply   string
		wantErr bool
	}{
		{"+OK Logged in", false},
		{"+OK", false},
		{"+ok Logged in", false},
		{"+oK", false},
		{"+OKAY", true},
		{"+OKLogged in", true},
		{"+OK-Logged in", true},
		{"-ERR [AUTH] Authentication failed", true},
		{"-ERR", true},
	} {
		t.Run(tc.reply, func(t *testing.T) {
			sess := statusTestSession(t, statusBackend(t, map[string]string{"AUTH": tc.reply}))

			_, err := connectLogged(t, sess)

			if tc.wantErr && !errors.Is(err, server.ErrBackendAuthFailed) {
				t.Errorf("connectToBackend = %v, want a backend login failure", err)
			} else if !tc.wantErr && err != nil {
				t.Errorf("connectToBackend: %v", err)
			}
		})
	}
}

func TestConnectToBackendUTF8ReplyStatus(t *testing.T) {
	const rejected = "backend rejected UTF8 mode"
	for _, tc := range []struct {
		reply        string
		wantAccepted bool
	}{
		{"+OK UTF8 enabled", true},
		{"+OK", true},
		{"+ok UTF8 enabled", true},
		{"+OKAY", false},
		{"+OKUTF8 enabled", false},
		{"-ERR Unknown command: UTF8", false},
	} {
		t.Run(tc.reply, func(t *testing.T) {
			sess := statusTestSession(t, statusBackend(t, map[string]string{"UTF8": tc.reply, "AUTH": "+OK logged in"}))
			sess.server.remoteUseUTF8 = true
			sess.utf8Requested = true

			logs, err := connectLogged(t, sess)

			if err != nil {
				t.Fatalf("connectToBackend: %v", err)
			}
			if accepted := !strings.Contains(logs, rejected); accepted != tc.wantAccepted {
				t.Errorf("UTF8 reply %q taken as accepted = %v, want %v; logs:\n%s", tc.reply, accepted, tc.wantAccepted, logs)
			}
		})
	}
}

func TestConnectToBackendXCLIENTReplyStatus(t *testing.T) {
	outcomes := map[string]string{
		"accepted":   "XCLIENT forwarding completed successfully",
		"refused":    "Failed to send forwarding parameters to backend",
		"unexpected": "unexpected XCLIENT response from backend",
	}
	for _, tc := range []struct {
		reply string
		want  string
	}{
		{"+OK XCLIENT accepted", "accepted"},
		{"+OK", "accepted"},
		{"+ok XCLIENT accepted", "accepted"},
		{"+OKAY", "unexpected"},
		{"+OKXCLIENT accepted", "unexpected"},
		{"-ERR XCLIENT not permitted", "refused"},
		{"-ERR", "refused"},
		{"-err XCLIENT not permitted", "refused"},
		{"-ERRx", "unexpected"},
		{"-ERROR not permitted", "unexpected"},
	} {
		t.Run(tc.reply, func(t *testing.T) {
			sess := statusTestSession(t, statusBackend(t, map[string]string{"XCLIENT": tc.reply, "AUTH": "+OK logged in"}))
			sess.server.remoteUseXCLIENT = true

			logs, err := connectLogged(t, sess)

			// The reply was read whatever it says, so the login goes on.
			if err != nil {
				t.Fatalf("connectToBackend: %v", err)
			}
			for outcome, msg := range outcomes {
				if got := strings.Contains(logs, msg); got != (outcome == tc.want) {
					t.Errorf("XCLIENT reply %q: logged %q = %v, want the reply %s; logs:\n%s", tc.reply, msg, got, tc.want, logs)
				}
			}
		})
	}
}
