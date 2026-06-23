//go:build integration

package pop3_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestPOP3_MissingArgument_NoCrash is a regression test for the unauthenticated
// process-crash bug where `USER`/`PASS` with no argument indexed parts[1] out of
// range and panicked. The session goroutine had no recover(), so the panic took
// down the entire server process (every connection, all protocols).
//
// Because the test server runs in-process, the old behavior would panic the test
// binary itself ("index out of range [1]"). With the fix the server returns -ERR
// and keeps serving, which we assert on both the same connection and a fresh one.
func TestPOP3_MissingArgument_NoCrash(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()

	// readGreeting consumes the initial +OK banner.
	readGreeting := func(r *bufio.Reader) {
		if _, err := r.ReadString('\n'); err != nil {
			t.Fatalf("Failed to read greeting: %v", err)
		}
	}

	// assertServerAlive opens a fresh connection and confirms the process is still
	// accepting connections and greeting clients. If the malformed command had
	// crashed the process, this dial/greeting would fail.
	assertServerAlive := func() {
		conn, err := net.Dial("tcp", server.Address)
		if err != nil {
			t.Fatalf("Server appears to have crashed (dial failed): %v", err)
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatalf("Server appears to have crashed (no greeting): %v", err)
		}
		if !strings.HasPrefix(strings.TrimSpace(line), "+OK") {
			t.Fatalf("Expected +OK greeting from live server, got: %q", line)
		}
	}

	t.Run("USER without argument", func(t *testing.T) {
		conn, err := net.Dial("tcp", server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		readGreeting(reader)

		fmt.Fprintf(conn, "USER\r\n")
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Expected -ERR response to bare USER, got read error: %v", err)
		}
		if !strings.HasPrefix(strings.TrimSpace(line), "-ERR") {
			t.Errorf("Expected -ERR for USER with no argument, got: %q", line)
		}

		// The session must survive and remain usable after the rejected command.
		fmt.Fprintf(conn, "CAPA\r\n")
		line, err = reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(strings.TrimSpace(line), "+OK") {
			t.Errorf("Session not usable after bare USER (CAPA got %q, err=%v)", line, err)
		}

		assertServerAlive()
	})

	t.Run("PASS without argument", func(t *testing.T) {
		conn, err := net.Dial("tcp", server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		readGreeting(reader)

		// A well-formed USER first so we reach the PASS argument parsing.
		fmt.Fprintf(conn, "USER %s\r\n", account.Email)
		if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(strings.TrimSpace(line), "+OK") {
			t.Fatalf("USER setup failed (got %q, err=%v)", line, err)
		}

		fmt.Fprintf(conn, "PASS\r\n")
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Expected -ERR response to bare PASS, got read error: %v", err)
		}
		if !strings.HasPrefix(strings.TrimSpace(line), "-ERR") {
			t.Errorf("Expected -ERR for PASS with no argument, got: %q", line)
		}

		assertServerAlive()
	})
}
