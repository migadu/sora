package imapproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// idForwardingBackend serves one plaintext connection: a greeting, then the ID response
// (an untagged ID and the tagged idStatus) idDelay after the ID command, and an OK at once
// to AUTHENTICATE. commands waits for the connection to end and returns the command names
// the backend read, in order.
func idForwardingBackend(t *testing.T, idDelay time.Duration, idStatus string) (addr string, commands func() []string) {
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
		io.WriteString(conn, "* OK ready\r\n")
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			tag, rest, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
			command, _, _ := strings.Cut(rest, " ")
			mu.Lock()
			got = append(got, command)
			mu.Unlock()
			switch command {
			case "ID":
				time.Sleep(idDelay)
				io.WriteString(conn, "* ID (\"name\" \"fake\")\r\n"+tag+" "+idStatus+"\r\n")
			case "AUTHENTICATE":
				io.WriteString(conn, tag+" OK Logged in\r\n")
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

// A forwarded ID whose tagged reply was not read by the deadline leaves the backend leg
// at an unknown point in its stream: the reply is still on its way, and AUTHENTICATE
// would read it as its own. The proxy must not log in on that leg. It fails the login the
// way it fails a backend connect, as a temporary backend failure. An ID the backend
// answered (accepted or refused) was read up to its tagged reply, so the login goes on.
func TestPostAuthenticationSetupIDReplyNotRead(t *testing.T) {
	const connectTimeout = 500 * time.Millisecond // newTestConnManager
	for _, tc := range []struct {
		name      string
		idDelay   time.Duration
		idStatus  string
		wantOK    bool
		wantReply string
		wantSent  []string
	}{
		{"ID answered after the deadline", connectTimeout + 200*time.Millisecond, "OK ID completed", false,
			"A1 NO [UNAVAILABLE] Backend server temporarily unavailable", []string{"ID"}},
		{"ID refused after the deadline", connectTimeout + 200*time.Millisecond, "NO ID refused", false,
			"A1 NO [UNAVAILABLE] Backend server temporarily unavailable", []string{"ID"}},
		{"ID accepted", 0, "OK ID completed", true, "A1 OK Logged in", []string{"ID", "AUTHENTICATE"}},
		{"ID refused", 0, "NO ID refused", true, "A1 OK Logged in", []string{"ID", "AUTHENTICATE"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, commands := idForwardingBackend(t, tc.idDelay, tc.idStatus)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			srv := &Server{
				name:               "test",
				hostname:           "test-host",
				ctx:                ctx,
				cancel:             cancel,
				activeSessions:     make(map[*Session]struct{}),
				connManager:        newTestConnManager(t, addr),
				authLimiter:        &fakeAuthLimiter{},
				remoteUseIDCommand: true,
			}
			client, remote := net.Pipe()
			t.Cleanup(func() { client.Close(); remote.Close() })
			replies := make(chan string, 8)
			go func() {
				r := bufio.NewReader(remote)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					replies <- strings.TrimRight(line, "\r\n")
				}
			}()
			sess := newSession(srv, client)
			sess.username = "user@example.com"

			ok := sess.postAuthenticationSetup("A1", time.Now())
			if sess.backendConn != nil {
				sess.backendConn.Close() // ends the fake backend's connection on success too
			}
			var reply string
			select {
			case reply = <-replies:
			case <-time.After(5 * time.Second):
				t.Fatal("no reply to the client's login")
			}
			sent := commands()

			if ok != tc.wantOK {
				t.Errorf("postAuthenticationSetup = %v, want %v", ok, tc.wantOK)
			}
			if reply != tc.wantReply {
				t.Errorf("the client got %q, want %q", reply, tc.wantReply)
			}
			if strings.Join(sent, " ") != strings.Join(tc.wantSent, " ") {
				t.Errorf("the backend read %q, want %q", sent, tc.wantSent)
			}
		})
	}
}
