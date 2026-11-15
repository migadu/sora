package pop3proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// xclientBackend serves one plaintext connection: a greeting, then xclientReply
// xclientDelay after XCLIENT, and authReply at once to AUTH. commands waits for the
// connection to end and returns the command names the backend read, in order.
func xclientBackend(t *testing.T, xclientDelay time.Duration, xclientReply, authReply string) (addr string, commands func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got []string
	done := make(chan struct{})
	go func() {
		defer close(done)
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
			mu.Lock()
			got = append(got, command)
			mu.Unlock()
			switch command {
			case "XCLIENT":
				time.Sleep(xclientDelay)
				io.WriteString(conn, xclientReply+"\r\n")
			case "AUTH":
				io.WriteString(conn, authReply+"\r\n")
			}
		}
	}()
	return ln.Addr().String(), func() []string {
		t.Helper()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("the fake backend connection did not end")
		}
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// An XCLIENT whose reply was not read by the deadline leaves the backend leg at an
// unknown point in its stream: POP3 replies carry no tag, so the late +OK to XCLIENT
// would be read as the reply to AUTH, and the backend's real AUTH reply would reach the
// client as the reply to its next command. The proxy must not log in on that leg. It
// fails the connect, which the client sees as a temporary backend failure. An XCLIENT
// the backend answered (accepted or refused) was read, so the login goes on.
func TestConnectToBackendXCLIENTReplyNotRead(t *testing.T) {
	const connectTimeout = 500 * time.Millisecond
	for _, tc := range []struct {
		name         string
		xclientDelay time.Duration
		xclientReply string
		authReply    string
		wantErr      bool
		wantSent     []string
	}{
		{"XCLIENT answered after the deadline", connectTimeout + 200*time.Millisecond, "+OK XCLIENT accepted",
			"-ERR [AUTH] Authentication failed", true, []string{"XCLIENT"}},
		{"XCLIENT accepted", 0, "+OK XCLIENT accepted", "+OK logged in", false, []string{"XCLIENT", "AUTH"}},
		{"XCLIENT refused", 0, "-ERR XCLIENT not permitted", "+OK logged in", false, []string{"XCLIENT", "AUTH"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, commands := xclientBackend(t, tc.xclientDelay, tc.xclientReply, tc.authReply)
			clientA, clientB := net.Pipe()
			t.Cleanup(func() { clientA.Close(); clientB.Close() })
			sess := &POP3ProxySession{
				server: &POP3ProxyServer{
					name:             "test",
					hostname:         "test-host",
					connManager:      newPOP3TestConnManager(t, addr, connectTimeout),
					remoteUseXCLIENT: true,
				},
				clientConn:   clientA,
				listenerConn: clientA,
				ctx:          context.Background(),
				username:     "user@example.com",
			}

			err := sess.connectToBackend()
			if sess.backendConn != nil {
				sess.backendConn.Close() // ends the fake backend's connection on success too
			}
			sent := commands()

			if tc.wantErr {
				if !errors.Is(err, server.ErrBackendConnectionFailed) {
					t.Errorf("connectToBackend = %v, want a backend connect failure", err)
				}
			} else if err != nil {
				t.Errorf("connectToBackend: %v", err)
			}
			if strings.Join(sent, " ") != strings.Join(tc.wantSent, " ") {
				t.Errorf("the backend read %q, want %q", sent, tc.wantSent)
			}
		})
	}
}
