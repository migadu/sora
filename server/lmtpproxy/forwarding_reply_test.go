package lmtpproxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// lmtpStep is a fake backend's reply to one command, sent delay after the command.
type lmtpStep struct {
	delay time.Duration
	reply string
}

// scriptedLMTPBackend serves one plaintext connection: a greeting, then the n-th time a
// command comes, script[command][n] (the last step once they run out). commands waits for
// the connection to end and returns the command names the backend read, in order.
func scriptedLMTPBackend(t *testing.T, script map[string][]lmtpStep) (addr string, commands func() []string) {
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
		io.WriteString(conn, "220 fake LMTP backend ready\r\n")
		r := bufio.NewReader(conn)
		seen := map[string]int{}
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			command, _, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
			mu.Lock()
			got = append(got, command)
			mu.Unlock()
			steps := script[command]
			if len(steps) == 0 {
				io.WriteString(conn, "502 5.5.1 unexpected command\r\n")
				continue
			}
			step := steps[min(seen[command], len(steps)-1)]
			seen[command]++
			time.Sleep(step.delay)
			io.WriteString(conn, step.reply+"\r\n")
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

// An XCLIENT exchange whose reply was not read by the deadline leaves the backend leg at
// an unknown point in its stream: the late reply would be read as the reply to MAIL FROM,
// and every reply after it would be one behind. The proxy must not go on with that leg.
// The exchange is the XCLIENT reply and, when the backend answers XCLIENT with a new
// greeting (220), the reply to the LHLO the proxy sends after it. An XCLIENT the backend
// answered (accepted or refused) was read, so the transaction goes on.
func TestConnectToBackendXCLIENTReplyNotRead(t *testing.T) {
	const connectTimeout = 500 * time.Millisecond
	late := connectTimeout + 200*time.Millisecond
	lhlo := lmtpStep{0, "250 fake"}
	mailRejected := lmtpStep{0, "550 5.7.1 sender rejected"}
	mailAccepted := lmtpStep{0, "250 2.1.0 OK"}
	for _, tc := range []struct {
		name     string
		script   map[string][]lmtpStep
		wantErr  bool
		wantSent []string
	}{
		{"XCLIENT answered after the deadline", map[string][]lmtpStep{
			"LHLO": {lhlo}, "XCLIENT": {{late, "250 2.0.0 XCLIENT accepted"}}, "MAIL": {mailRejected},
		}, true, []string{"LHLO", "XCLIENT"}},
		{"LHLO after XCLIENT answered after the deadline", map[string][]lmtpStep{
			"LHLO": {lhlo, {late, "250 fake"}}, "XCLIENT": {{0, "220 fake LMTP backend ready"}}, "MAIL": {mailRejected},
		}, true, []string{"LHLO", "XCLIENT", "LHLO"}},
		{"XCLIENT accepted", map[string][]lmtpStep{
			"LHLO": {lhlo}, "XCLIENT": {{0, "250 2.0.0 XCLIENT accepted"}}, "MAIL": {mailAccepted},
		}, false, []string{"LHLO", "XCLIENT", "MAIL"}},
		{"XCLIENT accepted with a new greeting", map[string][]lmtpStep{
			"LHLO": {lhlo}, "XCLIENT": {{0, "220 fake LMTP backend ready"}}, "MAIL": {mailAccepted},
		}, false, []string{"LHLO", "XCLIENT", "LHLO", "MAIL"}},
		{"XCLIENT refused", map[string][]lmtpStep{
			"LHLO": {lhlo}, "XCLIENT": {{0, "550 5.7.0 XCLIENT not permitted"}}, "MAIL": {mailAccepted},
		}, false, []string{"LHLO", "XCLIENT", "MAIL"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, commands := scriptedLMTPBackend(t, tc.script)
			clientA, clientB := net.Pipe()
			t.Cleanup(func() { clientA.Close(); clientB.Close() })
			sess := &Session{
				server: &Server{
					name:             "test",
					hostname:         "test-host",
					connManager:      newLMTPTestConnManager(t, addr, connectTimeout),
					remoteUseXCLIENT: true,
				},
				clientConn:       clientA,
				originalAddress:  "user@example.com",
				ctx:              context.Background(),
				mailFromReceived: true,
				sender:           "sender@example.org",
			}

			err := sess.connectToBackend()
			if sess.backendConn != nil {
				sess.backendConn.Close() // ends the fake backend's connection on success too
			}
			sent := commands()

			if tc.wantErr && err == nil {
				t.Errorf("connectToBackend = <nil>, want the backend connection failed")
			} else if !tc.wantErr && err != nil {
				t.Errorf("connectToBackend: %v", err)
			}
			if strings.Join(sent, " ") != strings.Join(tc.wantSent, " ") {
				t.Errorf("the backend read %q, want %q", sent, tc.wantSent)
			}
		})
	}
}

// scriptedLMTPBackendLines is scriptedLMTPBackend returning full trimmed command lines.
func scriptedLMTPBackendLines(t *testing.T, script map[string][]lmtpStep) (addr string, lines func() []string) {
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
		io.WriteString(conn, "220 fake LMTP backend ready\r\n")
		r := bufio.NewReader(conn)
		seen := map[string]int{}
		for {
			raw, err := r.ReadString('\n')
			if err != nil {
				return
			}
			trimmed := strings.TrimRight(raw, "\r\n")
			command, _, _ := strings.Cut(trimmed, " ")
			mu.Lock()
			got = append(got, trimmed)
			mu.Unlock()
			steps := script[command]
			if len(steps) == 0 {
				io.WriteString(conn, "502 5.5.1 unexpected command\r\n")
				continue
			}
			step := steps[min(seen[command], len(steps)-1)]
			seen[command]++
			time.Sleep(step.delay)
			io.WriteString(conn, step.reply+"\r\n")
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

// TestConnectToBackendXCLIENTMultilineAndStatus verifies that sendForwardingParametersToBackend
// drains full multiline XCLIENT replies (250, 220 session-reset greeting, 5xx/non-421 4xx
// refusals), validates SMTP status code boundaries and continuation code consistency, and
// treats 421 or malformed/unexpected replies as fatal handshake errors rather than leaving
// unread lines in backendReader or continuing on a closing connection.
func TestConnectToBackendXCLIENTMultilineAndStatus(t *testing.T) {
	const connectTimeout = time.Second
	lhlo := lmtpStep{0, "250-fake\r\n250 PIPELINING"}
	mailAccepted := lmtpStep{0, "250 2.1.0 OK"}
	mailRejected := lmtpStep{0, "550 5.7.1 sender rejected"}

	for _, tc := range []struct {
		name     string
		script   map[string][]lmtpStep
		wantErr  bool
		wantSent []string
	}{
		{
			name: "multiline 250 acceptance does not mask rejected MAIL",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo},
				"XCLIENT": {{0, "250-2.0.0 XCLIENT accepted\r\n250 2.0.0 Session updated"}},
				"MAIL":    {mailRejected},
			},
			wantErr:  true,
			wantSent: []string{"LHLO", "XCLIENT", "MAIL"},
		},
		{
			name: "multiline 220 session-reset greeting does not mask rejected MAIL",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo, lhlo},
				"XCLIENT": {{0, "220-fake LMTP backend\r\n220 ready after reset"}},
				"MAIL":    {mailRejected},
			},
			wantErr:  true,
			wantSent: []string{"LHLO", "XCLIENT", "LHLO", "MAIL"},
		},
		{
			name: "multiline 550 refusal continues cleanly with MAIL",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo},
				"XCLIENT": {{0, "550-5.7.0 XCLIENT not permitted\r\n550 5.7.0 Check trusted_networks"}},
				"MAIL":    {mailAccepted},
			},
			wantErr:  false,
			wantSent: []string{"LHLO", "XCLIENT", "MAIL"},
		},
		{
			name: "single-line 451 command refusal continues cleanly with MAIL",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo},
				"XCLIENT": {{0, "451 4.0.0 XCLIENT denied"}},
				"MAIL":    {mailAccepted},
			},
			wantErr:  false,
			wantSent: []string{"LHLO", "XCLIENT", "MAIL"},
		},
		{
			name: "multiline 451 command refusal continues cleanly with MAIL",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo},
				"XCLIENT": {{0, "451-4.0.0 XCLIENT temporarily unavailable\r\n451 4.0.0 Continuing without forwarding"}},
				"MAIL":    {mailAccepted},
			},
			wantErr:  false,
			wantSent: []string{"LHLO", "XCLIENT", "MAIL"},
		},
		{
			name: "bare 3-digit 250 acceptance succeeds",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo},
				"XCLIENT": {{0, "250"}},
				"MAIL":    {mailAccepted},
			},
			wantErr:  false,
			wantSent: []string{"LHLO", "XCLIENT", "MAIL"},
		},
		{
			name: "bare 3-digit 220 greeting and bare 250 LHLO succeed",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo, {0, "250"}},
				"XCLIENT": {{0, "220"}},
				"MAIL":    {mailAccepted},
			},
			wantErr:  false,
			wantSent: []string{"LHLO", "XCLIENT", "LHLO", "MAIL"},
		},
		{
			name: "bare 3-digit 550 refusal continues cleanly with MAIL",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo},
				"XCLIENT": {{0, "550"}},
				"MAIL":    {mailAccepted},
			},
			wantErr:  false,
			wantSent: []string{"LHLO", "XCLIENT", "MAIL"},
		},
		{
			name: "421 service shutting down on XCLIENT fails connection",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo},
				"XCLIENT": {{0, "421 4.3.2 Service shutting down"}},
				"MAIL":    {mailAccepted},
			},
			wantErr:  true,
			wantSent: []string{"LHLO", "XCLIENT"},
		},
		{
			name: "multiline 421 on XCLIENT fails connection",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo},
				"XCLIENT": {{0, "421-4.3.2 Service shutting down\r\n421 4.3.2 Closing channel"}},
				"MAIL":    {mailAccepted},
			},
			wantErr:  true,
			wantSent: []string{"LHLO", "XCLIENT"},
		},
		{
			name: "unexpected 354 status on XCLIENT fails connection",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo},
				"XCLIENT": {{0, "354 Start mail input"}},
				"MAIL":    {mailAccepted},
			},
			wantErr:  true,
			wantSent: []string{"LHLO", "XCLIENT"},
		},
		{
			name: "non-SMTP garbage reply on XCLIENT fails connection",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo},
				"XCLIENT": {{0, "ERROR invalid command"}},
				"MAIL":    {mailAccepted},
			},
			wantErr:  true,
			wantSent: []string{"LHLO", "XCLIENT"},
		},
		{
			name: "4-digit 2500 status boundary violation on XCLIENT fails connection",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo},
				"XCLIENT": {{0, "2500 bogus status"}},
				"MAIL":    {mailAccepted},
			},
			wantErr:  true,
			wantSent: []string{"LHLO", "XCLIENT"},
		},
		{
			name: "220X status boundary violation on XCLIENT fails connection",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo},
				"XCLIENT": {{0, "220X bogus greeting"}},
				"MAIL":    {mailAccepted},
			},
			wantErr:  true,
			wantSent: []string{"LHLO", "XCLIENT"},
		},
		{
			name: "short 2-digit reply on XCLIENT fails connection",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo},
				"XCLIENT": {{0, "25"}},
				"MAIL":    {mailAccepted},
			},
			wantErr:  true,
			wantSent: []string{"LHLO", "XCLIENT"},
		},
		{
			name: "mismatched multiline continuation code on XCLIENT fails connection",
			script: map[string][]lmtpStep{
				"LHLO":    {lhlo},
				"XCLIENT": {{0, "250-first line\r\n421 4.3.2 Closing channel"}},
				"MAIL":    {mailAccepted},
			},
			wantErr:  true,
			wantSent: []string{"LHLO", "XCLIENT"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, commands := scriptedLMTPBackend(t, tc.script)
			clientA, clientB := net.Pipe()
			t.Cleanup(func() { clientA.Close(); clientB.Close() })
			sess := &Session{
				server: &Server{
					name:             "test",
					hostname:         "test-host",
					connManager:      newLMTPTestConnManager(t, addr, connectTimeout),
					remoteUseXCLIENT: true,
				},
				clientConn:       clientA,
				originalAddress:  "user@example.com",
				ctx:              context.Background(),
				mailFromReceived: true,
				sender:           "sender@example.org",
			}

			err := sess.connectToBackend()
			if sess.backendConn != nil {
				sess.backendConn.Close()
			}
			sent := commands()

			if tc.wantErr && err == nil {
				t.Errorf("connectToBackend = <nil>, want error")
			} else if !tc.wantErr && err != nil {
				t.Errorf("connectToBackend = %v, want <nil>", err)
			}
			if strings.Join(sent, " ") != strings.Join(tc.wantSent, " ") {
				t.Errorf("the backend read %q, want %q", sent, tc.wantSent)
			}
		})
	}
}

// TestConnectToBackendXCLIENTMultilineDoesNotMaskRejectedRCPT proves that after a
// multiline 250 or multiline 220 XCLIENT reply and an accepted MAIL FROM, forwardRCPT
// reads the actual RCPT TO reply (550 rejected) rather than a leftover 250 line from
// XCLIENT or post-XCLIENT LHLO.
func TestConnectToBackendXCLIENTMultilineDoesNotMaskRejectedRCPT(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script map[string][]lmtpStep
	}{
		{
			name: "multiline 250 XCLIENT followed by accepted MAIL and 550 RCPT",
			script: map[string][]lmtpStep{
				"LHLO":    {{0, "250-fake\r\n250 PIPELINING"}},
				"XCLIENT": {{0, "250-2.0.0 XCLIENT accepted\r\n250 2.0.0 Client updated"}},
				"MAIL":    {{0, "250 2.1.0 Sender OK"}},
				"RCPT":    {{0, "550 5.1.1 User unknown"}},
			},
		},
		{
			name: "multiline 220 XCLIENT greeting followed by multiline LHLO, accepted MAIL, and 550 RCPT",
			script: map[string][]lmtpStep{
				"LHLO":    {{0, "250-fake\r\n250 PIPELINING"}, {0, "250-fake\r\n250 PIPELINING"}},
				"XCLIENT": {{0, "220-fake LMTP backend\r\n220 session reset"}},
				"MAIL":    {{0, "250 2.1.0 Sender OK"}},
				"RCPT":    {{0, "550 5.1.1 User unknown"}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, commands := scriptedLMTPBackend(t, tc.script)
			clientA, clientB := net.Pipe()
			t.Cleanup(func() { clientA.Close(); clientB.Close() })
			var clientOut bytes.Buffer
			toAddr, err := server.NewAddress("user@example.com")
			if err != nil {
				t.Fatal(err)
			}
			sess := &Session{
				server: &Server{
					name:             "test",
					hostname:         "test-host",
					connManager:      newLMTPTestConnManager(t, addr, time.Second),
					remoteUseXCLIENT: true,
				},
				clientConn:       clientA,
				clientWriter:     bufio.NewWriter(&clientOut),
				originalAddress:  "user@example.com",
				to:               "user@example.com",
				toAddress:        &toAddr,
				username:         toAddr.BaseAddress(),
				ctx:              context.Background(),
				mailFromReceived: true,
				sender:           "sender@example.org",
			}

			if err := sess.connectToBackend(); err != nil {
				t.Fatalf("connectToBackend: %v", err)
			}
			sess.forwardRCPT("RCPT TO:<user@example.com>")
			if sess.backendConn != nil {
				sess.backendConn.Close()
			}
			_ = commands()

			reply := strings.TrimRight(clientOut.String(), "\r\n")
			if strings.HasPrefix(reply, "250") {
				t.Fatalf("forwardRCPT answered %q (acceptedRcpts=%d) when backend rejected RCPT with 550", reply, sess.acceptedRcpts)
			}
			if !strings.HasPrefix(reply, "451 ") {
				t.Errorf("forwardRCPT answered %q, want 451 temporary failure on backend 550", reply)
			}
			if sess.acceptedRcpts != 0 {
				t.Errorf("acceptedRcpts = %d, want 0", sess.acceptedRcpts)
			}
		})
	}
}

// TestConnectToBackendXCLIENTPostResetLHLO verifies that after a 220 session-reset reply
// to XCLIENT, the re-sent LHLO must succeed with 250 (failing on 5xx/421 or malformed
// lines) and must refresh s.backendSMTPUTF8 and s.backendSIZE from the post-reset LHLO
// capabilities rather than keeping stale pre-reset flags.
func TestConnectToBackendXCLIENTPostResetLHLO(t *testing.T) {
	t.Run("non-250 post-XCLIENT LHLO fails connection", func(t *testing.T) {
		for _, lhloReply := range []string{
			"501 5.5.4 Invalid domain",
			"550-5.7.1 Access denied\r\n550 5.7.1 Goodbye",
			"421 4.3.2 Service shutting down",
			"2500 bogus status",
		} {
			addr, commands := scriptedLMTPBackend(t, map[string][]lmtpStep{
				"LHLO":    {{0, "250 fake"}, {0, lhloReply}},
				"XCLIENT": {{0, "220 fake LMTP backend ready"}},
				"MAIL":    {{0, "250 2.1.0 OK"}},
			})
			clientA, clientB := net.Pipe()
			t.Cleanup(func() { clientA.Close(); clientB.Close() })
			sess := &Session{
				server: &Server{
					name:             "test",
					hostname:         "test-host",
					connManager:      newLMTPTestConnManager(t, addr, time.Second),
					remoteUseXCLIENT: true,
				},
				clientConn:       clientA,
				originalAddress:  "user@example.com",
				ctx:              context.Background(),
				mailFromReceived: true,
				sender:           "sender@example.org",
			}

			err := sess.connectToBackend()
			if sess.backendConn != nil {
				sess.backendConn.Close()
			}
			sent := commands()

			if err == nil {
				t.Errorf("post-XCLIENT LHLO %q: connectToBackend = <nil>, want error", lhloReply)
			}
			wantSent := []string{"LHLO", "XCLIENT", "LHLO"}
			if !slices.Equal(sent, wantSent) {
				t.Errorf("post-XCLIENT LHLO %q: backend read %q, want %q", lhloReply, sent, wantSent)
			}
		}
	})

	t.Run("post-XCLIENT LHLO refreshes SMTPUTF8 and SIZE capabilities", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			firstLHLO   string
			secondLHLO  string
			wantUTF8    bool
			wantSIZE    bool
			wantMailCmd string
		}{
			{
				name:        "capabilities advertised only after XCLIENT reset are picked up",
				firstLHLO:   "250 fake",
				secondLHLO:  "250-fake\r\n250-SIZE 52428800\r\n250 SMTPUTF8",
				wantUTF8:    true,
				wantSIZE:    true,
				wantMailCmd: "MAIL FROM:<josé@example.org> SIZE=1024 SMTPUTF8",
			},
			{
				name:        "capabilities absent after XCLIENT reset are cleared",
				firstLHLO:   "250-fake\r\n250-SIZE 52428800\r\n250 SMTPUTF8",
				secondLHLO:  "250-fake\r\n250 PIPELINING",
				wantUTF8:    false,
				wantSIZE:    false,
				wantMailCmd: "MAIL FROM:<josé@example.org>",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				addr, lines := scriptedLMTPBackendLines(t, map[string][]lmtpStep{
					"LHLO":    {{0, tc.firstLHLO}, {0, tc.secondLHLO}},
					"XCLIENT": {{0, "220-fake LMTP backend\r\n220 session reset"}},
					"MAIL":    {{0, "250 2.1.0 OK"}},
				})
				clientA, clientB := net.Pipe()
				t.Cleanup(func() { clientA.Close(); clientB.Close() })
				sess := &Session{
					server: &Server{
						name:             "test",
						hostname:         "test-host",
						connManager:      newLMTPTestConnManager(t, addr, time.Second),
						remoteUseXCLIENT: true,
					},
					clientConn:       clientA,
					originalAddress:  "user@example.com",
					ctx:              context.Background(),
					mailFromReceived: true,
					sender:           "josé@example.org",
					smtputf8:         true,
					declaredSize:     "1024",
				}

				if err := sess.connectToBackend(); err != nil {
					t.Fatalf("connectToBackend: %v", err)
				}
				if sess.backendConn != nil {
					sess.backendConn.Close()
				}
				gotLines := lines()

				if sess.backendSMTPUTF8 != tc.wantUTF8 {
					t.Errorf("backendSMTPUTF8 = %v, want %v", sess.backendSMTPUTF8, tc.wantUTF8)
				}
				if sess.backendSIZE != tc.wantSIZE {
					t.Errorf("backendSIZE = %v, want %v", sess.backendSIZE, tc.wantSIZE)
				}
				if len(gotLines) != 4 || gotLines[3] != tc.wantMailCmd {
					t.Errorf("backend commands = %q, want 4th command %q", gotLines, tc.wantMailCmd)
				}
			})
		}
	})
}
