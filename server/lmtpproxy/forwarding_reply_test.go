package lmtpproxy

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
