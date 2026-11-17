package lmtpproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// TestRevocationFence_InFlightRCPTClosesWith421 verifies that when an account's
// sessions are revoked while RCPT TO is in flight — via EndLocalSessions,
// KickUser, or EndAllLocalSessions across fresh remotelookup or cached
// lookupCache hits — lmtpproxy fences registration with
// RegisterSessionIfGeneration, answers 421 instead of 250, drops any pipelined
// DATA without forwarding it to the backend, and leaves connection counts intact.
func TestRevocationFence_InFlightRCPTClosesWith421(t *testing.T) {
	const victimEmail = "victim@example.com"
	victimID := proxy.DeriveAccountIDFromEmail(victimEmail)

	for _, tc := range []struct {
		name            string
		warmCache       bool
		revokeInLookup  bool
		withPostSession bool
		revoke          func(t *testing.T, tracker *server.ConnectionTracker)
	}{
		{
			name:            "EndLocalSessions_during_backend_RCPT_after_remotelookup",
			withPostSession: true,
			revoke: func(t *testing.T, tracker *server.ConnectionTracker) {
				t.Helper()
				tracker.EndLocalSessions(victimID)
			},
		},
		{
			name:           "KickUser_during_remotelookup",
			revokeInLookup: true,
			revoke: func(t *testing.T, tracker *server.ConnectionTracker) {
				t.Helper()
				if err := tracker.KickUser(victimID, "LMTP"); err != nil {
					t.Fatalf("KickUser: %v", err)
				}
			},
		},
		{
			name:      "EndAllLocalSessions_during_backend_RCPT_from_lookupCache",
			warmCache: true,
			revoke: func(t *testing.T, tracker *server.ConnectionTracker) {
				t.Helper()
				tracker.EndAllLocalSessions()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				gateBackendRCPT atomic.Bool
				backendSawData  atomic.Bool
				enteredBackend  = make(chan struct{})
				releaseBackend  = make(chan struct{})
				backendOnce     sync.Once
			)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })

			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						_ = c.SetDeadline(time.Now().Add(10 * time.Second))
						_, _ = io.WriteString(c, "220 backend ready\r\n")
						r := bufio.NewReader(c)
						inData := false
						for {
							line, err := r.ReadString('\n')
							if err != nil {
								return
							}
							if inData {
								if line == ".\r\n" {
									_, _ = io.WriteString(c, "250 2.0.0 Delivered\r\n")
									inData = false
								}
								continue
							}
							upper := strings.ToUpper(strings.TrimSpace(line))
							switch {
							case strings.HasPrefix(upper, "LHLO"):
								_, _ = io.WriteString(c, "250 backend\r\n")
							case strings.HasPrefix(upper, "MAIL FROM:"):
								_, _ = io.WriteString(c, "250 2.1.0 Ok\r\n")
							case strings.HasPrefix(upper, "RCPT TO:"):
								if gateBackendRCPT.Load() {
									backendOnce.Do(func() { close(enteredBackend) })
									<-releaseBackend
								}
								_, _ = io.WriteString(c, "250 2.1.5 Ok\r\n")
							case upper == "DATA":
								backendSawData.Store(true)
								inData = true
								_, _ = io.WriteString(c, "354 Start mail input\r\n")
							default:
								_, _ = io.WriteString(c, "250 2.0.0 Ok\r\n")
							}
						}
					}(conn)
				}
			}()

			var (
				gateLookup     atomic.Bool
				lookupCalls    atomic.Int32
				enteredLookup  = make(chan struct{})
				releaseLookup  = make(chan struct{})
				lookupGateOnce sync.Once
			)
			lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				lookupCalls.Add(1)
				if gateLookup.Load() {
					lookupGateOnce.Do(func() { close(enteredLookup) })
					<-releaseLookup
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
			}))
			t.Cleanup(lookup.Close)

			srv, err := New(context.Background(), nil, "test-host", ServerOptions{
				Name:           "revocation-fence-" + tc.name,
				RemoteAddrs:    []string{ln.Addr().String()},
				RemotePort:     24,
				ConnectTimeout: 2 * time.Second,
				RemoteLookup: &config.RemoteLookupConfig{
					Enabled: true,
					URL:     lookup.URL + "?email=$email",
					Timeout: "2s",
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = srv.Stop() })

			tracker := server.NewConnectionTracker("LMTP", srv.name, "test-host", "test-instance", nil, 0, 0, 1000, false)
			t.Cleanup(tracker.Stop)
			srv.SetConnectionTracker(tracker)

			readReply := func(t *testing.T, r *bufio.Reader) string {
				t.Helper()
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						t.Fatalf("readReply failed: %v", err)
					}
					if len(line) < 4 || line[3] != '-' {
						return strings.TrimRight(line, "\r\n")
					}
				}
			}

			if tc.warmCache {
				warmFront, warmAccepted := newTCPPair(t)
				warmSess := newSession(srv, warmAccepted, nil)
				warmDone := make(chan struct{})
				go func() {
					defer close(warmDone)
					warmSess.handleConnection()
				}()
				_ = warmFront.SetDeadline(time.Now().Add(5 * time.Second))
				warmReader := bufio.NewReader(warmFront)
				if got := readReply(t, warmReader); !strings.HasPrefix(got, "220 ") {
					t.Fatalf("warm greeting = %q, want 220", got)
				}
				for _, step := range []struct {
					cmd  string
					want string
				}{
					{"LHLO mta.example.com", "250"},
					{"MAIL FROM:<sender@example.com>", "250"},
					{"RCPT TO:<" + victimEmail + ">", "250"},
					{"QUIT", "221"},
				} {
					if _, err := fmt.Fprintf(warmFront, "%s\r\n", step.cmd); err != nil {
						t.Fatalf("warm write %s: %v", step.cmd, err)
					}
					if got := readReply(t, warmReader); !strings.HasPrefix(got, step.want) {
						t.Fatalf("warm %s = %q, want %s", step.cmd, got, step.want)
					}
				}
				warmFront.Close()
				select {
				case <-warmDone:
				case <-time.After(3 * time.Second):
					t.Fatal("warm session did not exit")
				}
				if got := lookupCalls.Load(); got != 1 {
					t.Fatalf("warm lookupCalls = %d, want 1", got)
				}
			}

			if tc.revokeInLookup {
				gateLookup.Store(true)
			} else {
				gateBackendRCPT.Store(true)
			}

			front, accepted := newTCPPair(t)
			sess := newSession(srv, accepted, nil)
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
			reader := bufio.NewReader(front)
			if got := readReply(t, reader); !strings.HasPrefix(got, "220 ") {
				t.Fatalf("greeting = %q, want 220", got)
			}
			for _, cmd := range []string{"LHLO mta.example.com", "MAIL FROM:<sender@example.com>"} {
				if _, err := fmt.Fprintf(front, "%s\r\n", cmd); err != nil {
					t.Fatalf("write %s: %v", cmd, err)
				}
				if got := readReply(t, reader); !strings.HasPrefix(got, "250") {
					t.Fatalf("%s = %q, want 250", cmd, got)
				}
			}

			// Pipeline RCPT TO followed immediately by DATA + body, as an LMTP
			// PIPELINING MTA may do. A fenced RCPT must answer 421 and close
			// without ever forwarding DATA to the backend.
			pipelined := "RCPT TO:<" + victimEmail + ">\r\nDATA\r\nSubject: revoked\r\n\r\nBody\r\n.\r\n"
			if _, err := io.WriteString(front, pipelined); err != nil {
				t.Fatalf("write pipelined RCPT+DATA: %v", err)
			}

			var postRevokeKick <-chan struct{}
			if tc.revokeInLookup {
				select {
				case <-enteredLookup:
				case <-time.After(3 * time.Second):
					t.Fatal("remotelookup was not entered")
				}
				tc.revoke(t, tracker)
				close(releaseLookup)
			} else {
				select {
				case <-enteredBackend:
				case <-time.After(3 * time.Second):
					t.Fatal("backend RCPT TO was not entered")
				}
				if tc.warmCache && lookupCalls.Load() != 1 {
					t.Fatalf("cached RCPT unexpectedly hit remotelookup (calls=%d, want 1)", lookupCalls.Load())
				}
				tc.revoke(t, tracker)
				if tc.withPostSession {
					// Simulate a new session admitted after revocation completed;
					// teardown of the fenced session must not erode its count or kick channel.
					postGen := tracker.SessionGeneration()
					postRevokeKick = tracker.RegisterSessionIfGeneration(victimID, postGen)
					if err := tracker.RegisterConnection(context.Background(), victimID, victimEmail, "LMTP", "198.51.100.77"); err != nil {
						t.Fatalf("RegisterConnection post-revocation: %v", err)
					}
					t.Cleanup(func() {
						tracker.UnregisterSession(victimID, postRevokeKick)
						_ = tracker.UnregisterConnection(context.Background(), victimID, "LMTP", "198.51.100.77")
					})
				}
				close(releaseBackend)
			}

			firstLine, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read reply after in-flight revocation: %v", err)
			}
			if !strings.HasPrefix(firstLine, "421 4.3.2 ") {
				t.Fatalf("client received %q (backendSawData=%v) after in-flight revocation, want 421 4.3.2 closing notice", strings.TrimRight(firstLine, "\r\n"), backendSawData.Load())
			}
			rawRest, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("ReadAll after 421: %v", err)
			}
			if len(rawRest) != 0 {
				t.Fatalf("unexpected bytes written after 421 closing notice: %q", string(rawRest))
			}

			select {
			case <-sessDone:
			case <-time.After(3 * time.Second):
				t.Fatal("fenced session did not exit after 421")
			}

			if backendSawData.Load() {
				t.Fatal("fenced session forwarded pipelined DATA to backend after revocation")
			}

			wantCount := 0
			if tc.withPostSession {
				wantCount = 1
				select {
				case <-postRevokeKick:
					t.Fatal("post-revocation session kick channel was unexpectedly closed")
				default:
				}
			}
			if got := tracker.GetLocalConnectionCount(victimID); got != wantCount {
				t.Fatalf("local connection count for victim = %d, want %d", got, wantCount)
			}
		})
	}
}

// TestRevocationFence_UnrelatedAccountRevocationDoesNotFenceInFlightRCPT verifies
// that revoking an unrelated account while RCPT TO is in flight does not fence
// delivery for an account in another revocation slot.
func TestRevocationFence_UnrelatedAccountRevocationDoesNotFenceInFlightRCPT(t *testing.T) {
	const (
		aliceEmail = "alice@example.com"
		bobEmail   = "bob@example.com"
	)
	aliceID := proxy.DeriveAccountIDFromEmail(aliceEmail)
	bobID := proxy.DeriveAccountIDFromEmail(bobEmail)
	if uint64(aliceID)%1024 == uint64(bobID)%1024 {
		t.Fatalf("test emails unexpectedly share revocation slot: alice=%d bob=%d", aliceID, bobID)
	}

	enteredBackend := make(chan struct{})
	releaseBackend := make(chan struct{})
	var backendOnce sync.Once

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
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.WriteString(conn, "220 backend ready\r\n")
		r := bufio.NewReader(conn)
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					_, _ = io.WriteString(conn, "250 2.0.0 Delivered\r\n")
					inData = false
				}
				continue
			}
			upper := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(upper, "LHLO"):
				_, _ = io.WriteString(conn, "250 backend\r\n")
			case strings.HasPrefix(upper, "MAIL FROM:"):
				_, _ = io.WriteString(conn, "250 2.1.0 Ok\r\n")
			case strings.HasPrefix(upper, "RCPT TO:"):
				backendOnce.Do(func() { close(enteredBackend) })
				<-releaseBackend
				_, _ = io.WriteString(conn, "250 2.1.5 Ok\r\n")
			case upper == "DATA":
				inData = true
				_, _ = io.WriteString(conn, "354 Start mail input\r\n")
			default:
				_, _ = io.WriteString(conn, "250 2.0.0 Ok\r\n")
			}
		}
	}()

	srv, tracker := newKickTestProxy(t, ln.Addr().String())
	front, accepted := newTCPPair(t)
	sess := newSession(srv, accepted, nil)
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
	reader := bufio.NewReader(front)
	readReply := func() string {
		t.Helper()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("readReply: %v", err)
			}
			if len(line) < 4 || line[3] != '-' {
				return strings.TrimRight(line, "\r\n")
			}
		}
	}
	if got := readReply(); !strings.HasPrefix(got, "220 ") {
		t.Fatalf("greeting = %q, want 220", got)
	}
	for _, cmd := range []string{"LHLO mta.example.com", "MAIL FROM:<sender@example.com>"} {
		if _, err := fmt.Fprintf(front, "%s\r\n", cmd); err != nil {
			t.Fatal(err)
		}
		if got := readReply(); !strings.HasPrefix(got, "250") {
			t.Fatalf("%s = %q, want 250", cmd, got)
		}
	}

	if _, err := fmt.Fprintf(front, "RCPT TO:<%s>\r\n", aliceEmail); err != nil {
		t.Fatal(err)
	}
	select {
	case <-enteredBackend:
	case <-time.After(3 * time.Second):
		t.Fatal("backend RCPT TO not entered")
	}

	// Revoke an unrelated account while Alice's RCPT TO is in flight.
	tracker.EndLocalSessions(bobID)
	if err := tracker.KickUser(bobID, "LMTP"); err != nil {
		t.Fatalf("KickUser(bob): %v", err)
	}
	close(releaseBackend)

	if got := readReply(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("Alice RCPT TO reply = %q, want 250", got)
	}
	if got := tracker.GetLocalConnectionCount(aliceID); got != 1 {
		t.Fatalf("Alice connection count = %d, want 1", got)
	}

	if _, err := io.WriteString(front, "DATA\r\n"); err != nil {
		t.Fatal(err)
	}
	if got := readReply(); !strings.HasPrefix(got, "354") {
		t.Fatalf("DATA = %q, want 354", got)
	}
	if _, err := io.WriteString(front, "Subject: ok\r\n\r\nHello\r\n.\r\n"); err != nil {
		t.Fatal(err)
	}
	if got := readReply(); !strings.HasPrefix(got, "250") {
		t.Fatalf("end-of-data = %q, want 250", got)
	}
	if _, err := io.WriteString(front, "QUIT\r\n"); err != nil {
		t.Fatal(err)
	}
	if got := readReply(); !strings.HasPrefix(got, "221") {
		t.Fatalf("QUIT = %q, want 221", got)
	}
	select {
	case <-sessDone:
	case <-time.After(3 * time.Second):
		t.Fatal("session did not exit after QUIT")
	}
	if got := tracker.GetLocalConnectionCount(aliceID); got != 0 {
		t.Fatalf("Alice connection count after QUIT = %d, want 0", got)
	}
}

// TestRevocationFence_AlreadySubscribedAccountRevokedDuringSecondRCPT verifies
// that when an already-subscribed account's kick channel closes right as a
// subsequent RCPT TO reaches registerConnection/forwardRCPT, the session
// synchronously emits 421 and closes without racing watchKick to write 250 first.
func TestRevocationFence_AlreadySubscribedAccountRevokedDuringSecondRCPT(t *testing.T) {
	t.Run("unit_closed_subscription_blocks_250", func(t *testing.T) {
		const victimEmail = "victim@example.com"
		const victimID = int64(77)

		tracker := server.NewConnectionTracker("LMTP", "test", "test-host", "test-instance", nil, 0, 0, 1000, false)
		defer tracker.Stop()

		front, accepted := newTCPPair(t)
		backendClient, backendServer := newTCPPair(t)
		go func() {
			r := bufio.NewReader(backendServer)
			if _, err := r.ReadString('\n'); err != nil {
				return
			}
			_, _ = io.WriteString(backendServer, "250 2.1.5 Ok\r\n")
		}()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		toAddr, err := server.NewAddress(victimEmail)
		if err != nil {
			t.Fatal(err)
		}

		closedKick := make(chan struct{})
		close(closedKick)

		sess := &Session{
			server:        &Server{name: "test", hostname: "test-host", connTracker: tracker},
			clientConn:    accepted,
			listenerConn:  accepted,
			clientReader:  bufio.NewReader(accepted),
			clientWriter:  bufio.NewWriter(accepted),
			backendConn:   backendClient,
			backendReader: bufio.NewReader(backendClient),
			backendWriter: bufio.NewWriter(backendClient),
			clientAddr:    "192.0.2.55:12345",
			greeted:       true,
			ctx:           ctx,
			cancel:        cancel,
			startTime:     time.Now(),
			to:            victimEmail,
			toAddress:     &toAddr,
			username:      victimEmail,
			accountID:     victimID,
			registeredAccountIDs: map[int64]accountRegistration{
				victimID: {kick: closedKick, counted: true},
			},
		}

		if err := sess.registerConnection(); !errors.Is(err, errSessionClosing) {
			t.Errorf("registerConnection() = %v, want errSessionClosing when subscription kick channel is already closed", err)
		}

		// Also verify forwardRCPT never emits 250 on a fresh session whose
		// existing subscription kick channel has closed before watchKick runs.
		front2, accepted2 := newTCPPair(t)
		backendClient2, backendServer2 := newTCPPair(t)
		go func() {
			r := bufio.NewReader(backendServer2)
			if _, err := r.ReadString('\n'); err != nil {
				return
			}
			_, _ = io.WriteString(backendServer2, "250 2.1.5 Ok\r\n")
		}()
		ctx2, cancel2 := context.WithCancel(context.Background())
		defer cancel2()
		sess2 := &Session{
			server: &Server{
				name:        "test",
				hostname:    "test-host",
				connTracker: tracker,
				connManager: newLMTPTestConnManager(t, "127.0.0.1:24", time.Second),
			},
			clientConn:    accepted2,
			listenerConn:  accepted2,
			clientReader:  bufio.NewReader(accepted2),
			clientWriter:  bufio.NewWriter(accepted2),
			backendConn:   backendClient2,
			backendReader: bufio.NewReader(backendClient2),
			backendWriter: bufio.NewWriter(backendClient2),
			clientAddr:    "192.0.2.56:12345",
			greeted:       true,
			ctx:           ctx2,
			cancel:        cancel2,
			startTime:     time.Now(),
			to:            victimEmail,
			toAddress:     &toAddr,
			username:      victimEmail,
			accountID:     victimID,
			registeredAccountIDs: map[int64]accountRegistration{
				victimID: {kick: closedKick, counted: true},
			},
		}
		sess2.forwardRCPT("RCPT TO:<" + victimEmail + ">")
		accepted2.Close()
		front.Close()

		_ = front2.SetReadDeadline(time.Now().Add(2 * time.Second))
		raw, err := io.ReadAll(front2)
		if err != nil {
			t.Fatalf("ReadAll(front2): %v", err)
		}
		if !strings.HasPrefix(string(raw), "421 4.3.2 ") || strings.Contains(string(raw), "250") {
			t.Fatalf("forwardRCPT wrote %q on closed subscription, want single 421 without 250", string(raw))
		}
	})

	t.Run("wire_second_transaction_revoked_in_flight", func(t *testing.T) {
		const victimEmail = "victim@example.com"
		victimID := proxy.DeriveAccountIDFromEmail(victimEmail)

		var (
			rcptCount      atomic.Int32
			backendSawData atomic.Bool
		)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })

		srv, tracker := newKickTestProxy(t, ln.Addr().String())

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = io.WriteString(conn, "220 backend ready\r\n")
			r := bufio.NewReader(conn)
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				upper := strings.ToUpper(strings.TrimSpace(line))
				switch {
				case strings.HasPrefix(upper, "LHLO"):
					_, _ = io.WriteString(conn, "250 backend\r\n")
				case strings.HasPrefix(upper, "MAIL FROM:"):
					_, _ = io.WriteString(conn, "250 2.1.0 Ok\r\n")
				case strings.HasPrefix(upper, "RCPT TO:"):
					if rcptCount.Add(1) == 2 {
						tracker.EndLocalSessions(victimID)
					}
					_, _ = io.WriteString(conn, "250 2.1.5 Ok\r\n")
				case upper == "DATA":
					backendSawData.Store(true)
					_, _ = io.WriteString(conn, "354 Start mail input\r\n")
				default:
					_, _ = io.WriteString(conn, "250 2.0.0 Ok\r\n")
				}
			}
		}()

		front, accepted := newTCPPair(t)
		sess := newSession(srv, accepted, nil)
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
		reader := bufio.NewReader(front)
		readReply := func() string {
			t.Helper()
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					t.Fatalf("readReply: %v", err)
				}
				if len(line) < 4 || line[3] != '-' {
					return strings.TrimRight(line, "\r\n")
				}
			}
		}

		if got := readReply(); !strings.HasPrefix(got, "220 ") {
			t.Fatalf("greeting = %q, want 220", got)
		}
		for _, cmd := range []string{
			"LHLO mta.example.com",
			"MAIL FROM:<sender@example.com>",
			"RCPT TO:<" + victimEmail + ">",
			"RSET",
			"MAIL FROM:<sender@example.com>",
		} {
			if _, err := fmt.Fprintf(front, "%s\r\n", cmd); err != nil {
				t.Fatalf("write %s: %v", cmd, err)
			}
			if got := readReply(); !strings.HasPrefix(got, "250") {
				t.Fatalf("%s = %q, want 250", cmd, got)
			}
		}

		if _, err := io.WriteString(front, "RCPT TO:<"+victimEmail+">\r\nDATA\r\nSubject: tx2\r\n\r\nBody\r\n.\r\n"); err != nil {
			t.Fatal(err)
		}

		raw, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		wire := strings.TrimSuffix(string(raw), "\r\n")
		lines := strings.Split(wire, "\r\n")
		if len(lines) != 1 || !strings.HasPrefix(lines[0], "421 4.3.2 ") {
			t.Fatalf("second RCPT after revocation wrote %q, want single 421 4.3.2 closing notice", string(raw))
		}

		select {
		case <-sessDone:
		case <-time.After(3 * time.Second):
			t.Fatal("session did not exit after 421")
		}
		if backendSawData.Load() {
			t.Fatal("pipelined DATA was forwarded after second RCPT revocation")
		}
		if got := tracker.GetLocalConnectionCount(victimID); got != 0 {
			t.Fatalf("connection count after session close = %d, want 0", got)
		}
	})
}
