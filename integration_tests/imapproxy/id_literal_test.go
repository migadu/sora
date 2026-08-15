//go:build integration

package imapproxy_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAPProxyIDWithLiterals covers the pre-auth ID command carrying string
// literals (RFC 2971 nstring values). IMAP4rev2 clients — notably Microsoft
// Outlook — send them as non-synchronizing {N+} literals. Before the fix the
// proxy answered ID from the first physical line only and then read the
// literal payload back as commands: every payload line burned one pre-auth
// error strike, so an ID with two literal values (Outlook's shape) exhausted
// the default budget and the proxy sent "* BYE Too many invalid commands"
// before the client's LOGIN was ever read.
func TestIMAPProxyIDWithLiterals(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	time.Sleep(300 * time.Millisecond)

	email, password := account.Email, account.Password

	// run sends the payload as-is (single write) and reads until the tagged
	// LOGIN reply. It fails on any BYE and counts continuation requests.
	run := func(t *testing.T, payload string, expectContinuations int) []string {
		t.Helper()
		conn, err := net.Dial("tcp", proxyAddress)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		reader := bufio.NewReader(conn)

		if g, _ := reader.ReadString('\n'); !strings.HasPrefix(g, "* OK") {
			t.Fatalf("bad greeting: %q", g)
		}
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatalf("write: %v", err)
		}

		var lines []string
		continuations := 0
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read (so far %v): %v", lines, err)
			}
			lines = append(lines, strings.TrimSpace(line))
			if strings.HasPrefix(line, "+") {
				continuations++
				continue
			}
			if strings.HasPrefix(line, "* BYE") {
				t.Fatalf("proxy dropped the session: %v", lines)
			}
			if strings.HasPrefix(line, "A2 ") {
				break
			}
			if len(lines) > 12 {
				t.Fatalf("too many lines: %v", lines)
			}
		}
		if continuations != expectContinuations {
			t.Fatalf("expected %d continuation(s), got %d: %v", expectContinuations, continuations, lines)
		}
		return lines
	}

	assertIDThenLoginOK := func(t *testing.T, lines []string) {
		t.Helper()
		var sawIDOK, sawLoginOK bool
		for _, l := range lines {
			if strings.HasPrefix(l, "A1 OK") {
				sawIDOK = true
			}
			if strings.HasPrefix(l, "A2 OK") {
				sawLoginOK = true
			}
			if strings.Contains(l, "Command not supported before authentication") ||
				strings.Contains(l, "Command is missing") {
				t.Fatalf("literal payload was read as a command: %v", lines)
			}
		}
		if !sawIDOK || !sawLoginOK {
			t.Fatalf("expected A1 OK (ID) and A2 OK (LOGIN), got: %v", lines)
		}
	}

	t.Run("outlook_shape_two_nonsync_literals", func(t *testing.T) {
		payload := fmt.Sprintf(
			"A1 ID (\"name\" {23+}\r\nMicrosoft.Exchange.Imap \"version\" {6+}\r\n16.0.0)\r\n"+
				"A2 LOGIN \"%s\" \"%s\"\r\n", email, escapeForIMAP(password))
		assertIDThenLoginOK(t, run(t, payload, 0))
	})

	t.Run("single_nonsync_literal_value", func(t *testing.T) {
		payload := fmt.Sprintf(
			"A1 ID (\"name\" {7+}\r\nOutlook \"version\" \"1.0\")\r\n"+
				"A2 LOGIN \"%s\" \"%s\"\r\n", email, escapeForIMAP(password))
		assertIDThenLoginOK(t, run(t, payload, 0))
	})

	t.Run("synchronizing_literal_gets_continuation", func(t *testing.T) {
		// A {N} literal requires the proxy to send "+ " before the client
		// transmits the bytes; a well-behaved client waits for it. We send
		// everything in one write anyway (the bytes are buffered client-side
		// either way) and assert exactly one continuation was emitted.
		payload := fmt.Sprintf(
			"A1 ID (\"name\" {7}\r\nOutlook \"version\" \"1.0\")\r\n"+
				"A2 LOGIN \"%s\" \"%s\"\r\n", email, escapeForIMAP(password))
		assertIDThenLoginOK(t, run(t, payload, 1))
	})

	t.Run("plain_quoted_id_unchanged", func(t *testing.T) {
		payload := fmt.Sprintf(
			"A1 ID (\"name\" \"Outlook\" \"version\" \"1.0\")\r\n"+
				"A2 LOGIN \"%s\" \"%s\"\r\n", email, escapeForIMAP(password))
		assertIDThenLoginOK(t, run(t, payload, 0))
	})

	t.Run("id_nil_unchanged", func(t *testing.T) {
		payload := fmt.Sprintf("A1 ID NIL\r\nA2 LOGIN \"%s\" \"%s\"\r\n", email, escapeForIMAP(password))
		assertIDThenLoginOK(t, run(t, payload, 0))
	})

	t.Run("oversized_literal_rejected_without_hang", func(t *testing.T) {
		conn, err := net.Dial("tcp", proxyAddress)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		reader := bufio.NewReader(conn)
		reader.ReadString('\n') // greeting
		conn.Write([]byte("A1 ID (\"name\" {999999+}\r\n"))
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !strings.HasPrefix(line, "A1 BAD") {
			t.Fatalf("expected A1 BAD for oversized literal, got %q", line)
		}
	})
}
