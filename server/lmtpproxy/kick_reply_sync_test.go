package lmtpproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

func newTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	acceptedCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		acceptedCh <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case serverEnd := <-acceptedCh:
		t.Cleanup(func() {
			client.Close()
			serverEnd.Close()
		})
		return client, serverEnd
	case err := <-errCh:
		client.Close()
		t.Fatal(err)
		return nil, nil
	}
}

func newKickTestProxy(t *testing.T, backendAddr string) (*Server, *server.ConnectionTracker) {
	t.Helper()
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
	}))
	t.Cleanup(lookup.Close)

	srv, err := New(context.Background(), nil, "test-host", ServerOptions{
		Name:           "kick-sync",
		RemoteAddrs:    []string{backendAddr},
		RemotePort:     24,
		ConnectTimeout: 2 * time.Second,
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled: true,
			URL:     lookup.URL + "?email=$email",
			Timeout: "1s",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	tracker := server.NewConnectionTracker("LMTP", "", "", "test-instance", nil, 0, 0, 1000, false)
	t.Cleanup(tracker.Stop)
	srv.SetConnectionTracker(tracker)
	return srv, tracker
}

type kickInterceptConn struct {
	net.Conn
	mu             sync.Mutex
	sawKick421     bool
	writesAfter421 []string
	releaseBackend chan struct{}
	releaseOnce    sync.Once
	post421WriteCh chan struct{}
	post421Once    sync.Once
}

func (c *kickInterceptConn) Unwrap() net.Conn { return c.Conn }

func (c *kickInterceptConn) Write(p []byte) (int, error) {
	s := string(p)
	c.mu.Lock()
	isKick := !c.sawKick421 && strings.HasPrefix(s, "421 ")
	if isKick {
		c.sawKick421 = true
	} else if c.sawKick421 {
		c.writesAfter421 = append(c.writesAfter421, s)
	}
	c.mu.Unlock()

	n, err := c.Conn.Write(p)
	if isKick {
		c.releaseOnce.Do(func() { close(c.releaseBackend) })
		select {
		case <-c.post421WriteCh:
		case <-time.After(30 * time.Millisecond):
		}
	} else {
		c.mu.Lock()
		after := c.sawKick421
		c.mu.Unlock()
		if after {
			c.post421Once.Do(func() { close(c.post421WriteCh) })
		}
	}
	return n, err
}

func (c *kickInterceptConn) post421Writes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.writesAfter421...)
}

// TestKickDuringMultiRecipientDataDoesNotShiftReplies proves RFC 2033 §4.2 safety when an
// account kick fires during a multi-recipient DATA transaction:
//
//   - Recipient 1 (first@example.com) is accepted on the backend (250 2.0.0 Delivered first).
//   - Recipient 2 (second@example.com) is REJECTED on the backend (552 5.2.2 Over quota) and
//     never stored.
//
// In LMTP, go-smtp's (*DataCommand).CloseWithLMTPResponse reads one status line per accepted
// RCPT TO strictly by position: a 421 on slot 0 is recorded as an *SMTPError for first@example.com
// and the client keeps reading slot 1 for second@example.com. If relayMessageData flushes
// first@example.com's "250 2.0.0 Delivered first" AFTER watchKick has already written
// "421 4.3.2 Service closing connection", the MTA attributes 250 OK to second@example.com and
// permanently drops the undelivered message.
func TestKickDuringMultiRecipientDataDoesNotShiftReplies(t *testing.T) {
	dotReceived := make(chan struct{})
	var dotOnce sync.Once
	releaseBackend := make(chan struct{})

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
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(conn, "220 backend ready\r\n")
		reader := bufio.NewReader(conn)
		inData := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if !inData {
				upper := strings.ToUpper(strings.TrimSpace(line))
				switch {
				case strings.HasPrefix(upper, "LHLO"):
					_, _ = io.WriteString(conn, "250 backend\r\n")
				case strings.HasPrefix(upper, "MAIL FROM:"):
					_, _ = io.WriteString(conn, "250 2.1.0 Ok\r\n")
				case strings.HasPrefix(upper, "RCPT TO:"):
					_, _ = io.WriteString(conn, "250 2.1.5 Ok\r\n")
				case upper == "DATA":
					inData = true
					_, _ = io.WriteString(conn, "354 Start mail input\r\n")
				default:
					_, _ = io.WriteString(conn, "250 Ok\r\n")
				}
				continue
			}
			if line == ".\r\n" {
				dotOnce.Do(func() { close(dotReceived) })
				<-releaseBackend
				_, _ = io.WriteString(conn, "250 2.0.0 Delivered first\r\n552 5.2.2 Over quota\r\n")
				return
			}
		}
	}()

	srv, tracker := newKickTestProxy(t, ln.Addr().String())
	front, accepted := newTCPPair(t)
	intercept := &kickInterceptConn{
		Conn:           accepted,
		releaseBackend: releaseBackend,
		post421WriteCh: make(chan struct{}),
	}

	sess := newSession(srv, intercept, nil)
	sessDone := make(chan struct{})
	go func() {
		defer close(sessDone)
		sess.handleConnection()
	}()
	t.Cleanup(func() {
		front.Close()
		<-sessDone
	})

	_ = front.SetDeadline(time.Now().Add(5 * time.Second))
	client := smtp.NewClientLMTP(front)
	client.SubmissionTimeout = 5 * time.Second

	if err := client.Hello("mta.example.com"); err != nil {
		t.Fatalf("Hello: %v", err)
	}
	if err := client.Mail("sender@example.com", nil); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	if err := client.Rcpt("first@example.com", nil); err != nil {
		t.Fatalf("Rcpt first: %v", err)
	}
	if err := client.Rcpt("second@example.com", nil); err != nil {
		t.Fatalf("Rcpt second: %v", err)
	}

	dataWriter, err := client.Data()
	if err != nil {
		t.Fatalf("Data: %v", err)
	}
	if _, err := io.WriteString(dataWriter, "Subject: shift test\r\n\r\nBody\r\n"); err != nil {
		t.Fatalf("WriteString body: %v", err)
	}

	type lmtpResult struct {
		resp map[string]*smtp.DataResponse
		err  error
	}
	resCh := make(chan lmtpResult, 1)
	go func() {
		resp, err := dataWriter.CloseWithLMTPResponse()
		resCh <- lmtpResult{resp: resp, err: err}
	}()

	select {
	case <-dotReceived:
	case <-time.After(3 * time.Second):
		t.Fatal("backend did not receive end-of-data marker")
	}

	if err := tracker.KickUser(proxy.DeriveAccountIDFromEmail("first@example.com"), "LMTP"); err != nil {
		t.Fatalf("KickUser: %v", err)
	}

	var res lmtpResult
	select {
	case res = <-resCh:
	case <-time.After(5 * time.Second):
		t.Fatal("CloseWithLMTPResponse did not finish")
	}

	if after := intercept.post421Writes(); len(after) > 0 {
		t.Errorf("session wrote %q to client after closing 421 notice", after)
	}
	if got := res.resp["second@example.com"]; got != nil {
		t.Fatalf("silent mail loss: rejected recipient second@example.com (backend 552) was reported as 250 delivered (%q)", got.StatusText)
	}
	if got := res.resp["first@example.com"]; got != nil {
		t.Fatalf("first@example.com reported as delivered (%q) after closing 421", got.StatusText)
	}
	if res.err == nil {
		t.Fatal("CloseWithLMTPResponse succeeded, want error after kick 421 and connection close")
	}
}

type lhloKickConn struct {
	net.Conn
	mu        sync.Mutex
	lhloCount int
	onSecond  func()
	firedOnce sync.Once
	kick421Ch chan struct{}
	kickOnce  sync.Once
}

func (c *lhloKickConn) Unwrap() net.Conn { return c.Conn }

func (c *lhloKickConn) Write(p []byte) (int, error) {
	s := string(p)
	trigger := false
	is421 := strings.HasPrefix(s, "421 ")
	c.mu.Lock()
	if strings.HasPrefix(s, "250-test-host\r\n") {
		c.lhloCount++
		if c.lhloCount == 2 {
			trigger = true
		}
	}
	c.mu.Unlock()

	n, err := c.Conn.Write(p)
	if is421 {
		c.kickOnce.Do(func() { close(c.kick421Ch) })
	}
	if trigger {
		c.firedOnce.Do(func() {
			c.onSecond()
			select {
			case <-c.kick421Ch:
			case <-time.After(30 * time.Millisecond):
			}
		})
	}
	return n, err
}

type contNotifyConn struct {
	net.Conn
	contFlushed chan struct{}
	once        sync.Once
}

func (c *contNotifyConn) Unwrap() net.Conn { return c.Conn }

func (c *contNotifyConn) Write(p []byte) (int, error) {
	if strings.HasPrefix(string(p), "250-2.0.0") {
		c.once.Do(func() { close(c.contFlushed) })
	}
	return c.Conn.Write(p)
}

// TestKickDoesNotInjectMidMultilineReplyOrEmitDuplicate421 verifies that asynchronous
// closing notices (watchKick and sendGracefulShutdownMessage) serialize cleanly with
// multi-line replies and with each other:
//  1. A kick during LHLO never injects 421 between 250- continuation lines and the final 250 line.
//  2. A kick during a multi-line end-of-data reply never leaves an orphaned 250- continuation
//     line followed by 421.
//  3. Concurrent kick + graceful shutdown / context cancellation emits at most one 421 notice.
func TestKickDoesNotInjectMidMultilineReplyOrEmitDuplicate421(t *testing.T) {
	t.Run("LHLO_multiline_not_split_by_kick", func(t *testing.T) {
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
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.WriteString(conn, "220 backend ready\r\n")
			r := bufio.NewReader(conn)
			for {
				if _, err := r.ReadString('\n'); err != nil {
					return
				}
				_, _ = io.WriteString(conn, "250 Ok\r\n")
			}
		}()

		srv, tracker := newKickTestProxy(t, ln.Addr().String())
		front, accepted := newTCPPair(t)
		wrapped := &lhloKickConn{
			Conn:      accepted,
			kick421Ch: make(chan struct{}),
			onSecond: func() {
				go func() {
					_ = tracker.KickUser(proxy.DeriveAccountIDFromEmail("first@example.com"), "LMTP")
				}()
			},
		}

		sess := newSession(srv, wrapped, nil)
		sessDone := make(chan struct{})
		go func() {
			defer close(sessDone)
			sess.handleConnection()
		}()
		t.Cleanup(func() {
			front.Close()
			<-sessDone
		})

		_ = front.SetDeadline(time.Now().Add(5 * time.Second))
		tp := textproto.NewReader(bufio.NewReader(front))

		if _, _, err := tp.ReadResponse(220); err != nil {
			t.Fatalf("greeting: %v", err)
		}
		sendCmd := func(cmd string, expect int) string {
			t.Helper()
			if _, err := fmt.Fprintf(front, "%s\r\n", cmd); err != nil {
				t.Fatalf("%s write: %v", cmd, err)
			}
			_, msg, err := tp.ReadResponse(expect)
			if err != nil {
				t.Fatalf("%s response: %v", cmd, err)
			}
			return msg
		}

		sendCmd("LHLO mta.example.com", 250)
		sendCmd("MAIL FROM:<sender@example.com>", 250)
		sendCmd("RCPT TO:<first@example.com>", 250)
		sendCmd("RSET", 250)

		if _, err := fmt.Fprintf(front, "LHLO mta.example.com\r\n"); err != nil {
			t.Fatalf("second LHLO write: %v", err)
		}
		var lhloWireLines []string
		for {
			line, lerr := tp.ReadLine()
			if lerr != nil {
				break
			}
			lhloWireLines = append(lhloWireLines, line)
		}
		if len(lhloWireLines) == 0 {
			t.Fatal("expected LHLO and/or 421 lines, got none")
		}
		for i, line := range lhloWireLines {
			if len(line) >= 4 && line[3] == '-' {
				if i+1 >= len(lhloWireLines) || !strings.HasPrefix(lhloWireLines[i+1], line[:3]) {
					t.Fatalf("421 kick notice split multiline LHLO reply on wire: %q", lhloWireLines)
				}
			}
			if strings.HasPrefix(line, "421 ") && i != len(lhloWireLines)-1 {
				t.Fatalf("lines written after closing 421 during LHLO: %q", lhloWireLines)
			}
		}
		if !strings.HasPrefix(lhloWireLines[len(lhloWireLines)-1], "421 ") {
			t.Fatalf("expected final wire line to be 421 closing notice, got %q", lhloWireLines)
		}
	})

	t.Run("end_of_data_multiline_not_split_by_kick", func(t *testing.T) {
		dotReceived := make(chan struct{})
		releaseFinalLine := make(chan struct{})

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
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.WriteString(conn, "220 backend ready\r\n")
			r := bufio.NewReader(conn)
			inData := false
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if !inData {
					upper := strings.ToUpper(strings.TrimSpace(line))
					if upper == "DATA" {
						inData = true
						_, _ = io.WriteString(conn, "354 Start mail input\r\n")
					} else {
						_, _ = io.WriteString(conn, "250 Ok\r\n")
					}
					continue
				}
				if line == ".\r\n" {
					_, _ = io.WriteString(conn, "250-2.0.0 Accepted line 1\r\n")
					close(dotReceived)
					<-releaseFinalLine
					_, _ = io.WriteString(conn, "250 2.0.0 Accepted line 2\r\n")
					return
				}
			}
		}()

		srv, tracker := newKickTestProxy(t, ln.Addr().String())
		front, accepted := newTCPPair(t)
		notify := &contNotifyConn{Conn: accepted, contFlushed: make(chan struct{})}

		sess := newSession(srv, notify, nil)
		sessDone := make(chan struct{})
		go func() {
			defer close(sessDone)
			sess.handleConnection()
		}()
		t.Cleanup(func() {
			close(releaseFinalLine)
			front.Close()
			<-sessDone
		})

		_ = front.SetDeadline(time.Now().Add(5 * time.Second))
		tp := textproto.NewReader(bufio.NewReader(front))
		if _, _, err := tp.ReadResponse(220); err != nil {
			t.Fatalf("greeting: %v", err)
		}
		for _, cmd := range []string{
			"LHLO mta.example.com",
			"MAIL FROM:<sender@example.com>",
			"RCPT TO:<first@example.com>",
		} {
			if _, err := fmt.Fprintf(front, "%s\r\n", cmd); err != nil {
				t.Fatal(err)
			}
			if _, _, err := tp.ReadResponse(250); err != nil {
				t.Fatalf("%s: %v", cmd, err)
			}
		}
		if _, err := fmt.Fprintf(front, "DATA\r\n"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := tp.ReadResponse(354); err != nil {
			t.Fatalf("DATA: %v", err)
		}
		if _, err := fmt.Fprintf(front, "Subject: multiline\r\n\r\nBody\r\n.\r\n"); err != nil {
			t.Fatal(err)
		}

		select {
		case <-dotReceived:
		case <-time.After(3 * time.Second):
			t.Fatal("backend did not receive end-of-data")
		}
		select {
		case <-notify.contFlushed:
		case <-time.After(15 * time.Millisecond):
		}

		if err := tracker.KickUser(proxy.DeriveAccountIDFromEmail("first@example.com"), "LMTP"); err != nil {
			t.Fatalf("KickUser: %v", err)
		}

		var postDataLines []string
		for {
			line, err := tp.ReadLine()
			if err != nil {
				break
			}
			postDataLines = append(postDataLines, line)
		}
		if len(postDataLines) == 0 {
			t.Fatal("expected closing 421 line after DATA, got none")
		}
		for i, line := range postDataLines {
			if len(line) >= 4 && line[3] == '-' {
				if i+1 >= len(postDataLines) || !strings.HasPrefix(postDataLines[i+1], line[:3]) {
					t.Fatalf("interleaved/orphaned multiline reply before 421: %q", postDataLines)
				}
			}
			if strings.HasPrefix(line, "421 ") && i != len(postDataLines)-1 {
				t.Fatalf("lines written after closing 421: %q", postDataLines)
			}
		}
	})

	t.Run("kick_and_shutdown_emit_at_most_one_421", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		srv := &Server{
			name:           "test",
			hostname:       "test-host",
			ctx:            ctx,
			cancel:         cancel,
			activeSessions: make(map[*Session]struct{}),
		}

		front, accepted := newTCPPair(t)
		sess := newSession(srv, accepted, nil)
		sess.greeted = true
		srv.registerSession(sess)

		kick := make(chan struct{})
		kickDone := make(chan struct{})
		go func() {
			defer close(kickDone)
			sess.watchKick(42, kick)
		}()
		close(kick)
		<-kickDone

		// Before unregisterSession runs on handleConnection teardown, a concurrent server
		// shutdown iterates activeSessions and attempts sendGracefulShutdownMessage.
		srv.sendGracefulShutdownMessage()
		// Also verify command-loop context-cancel fallback cannot emit another 421.
		_ = sess.sendResponse("421 4.3.2 Service closing connection")
		accepted.Close()

		_ = front.SetReadDeadline(time.Now().Add(2 * time.Second))
		raw, err := io.ReadAll(front)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		lines := strings.Split(strings.TrimSuffix(string(raw), "\r\n"), "\r\n")
		if len(lines) != 1 || !strings.HasPrefix(lines[0], "421 ") {
			t.Fatalf("expected exactly one 421 closing line, got %d lines: %q", len(lines), string(raw))
		}
	})
}
