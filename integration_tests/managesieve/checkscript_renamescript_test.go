//go:build integration

package managesieve

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// msReadResp reads a full ManageSieve response: it accumulates lines until a
// terminal status line (OK / NO / BYE) and returns everything read. This handles
// both single-line responses and multi-line ones like LISTSCRIPTS/GETSCRIPT.
func msReadResp(t *testing.T, conn net.Conn, r *bufio.Reader) string {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	var sb strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read response failed (so far: %q): %v", sb.String(), err)
		}
		sb.WriteString(line)
		up := strings.ToUpper(strings.TrimSpace(line))
		if strings.HasPrefix(up, "OK") || strings.HasPrefix(up, "NO") || strings.HasPrefix(up, "BYE") {
			return sb.String()
		}
	}
}

// msReadLine reads a single raw line (used for the "+" literal continuation).
func msReadLine(t *testing.T, conn net.Conn, r *bufio.Reader) string {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read line failed: %v", err)
	}
	return line
}

func msConnectAndAuth(t *testing.T, server *common.TestServer, account common.TestAccount) (net.Conn, *bufio.Reader, *bufio.Writer) {
	t.Helper()
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	// Consume the capability greeting (ends with an OK line).
	msReadResp(t, conn, r)

	creds := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)))
	fmt.Fprintf(w, "AUTHENTICATE \"PLAIN\" {%d+}\r\n%s\r\n", len(creds), creds)
	w.Flush()
	if resp := msReadResp(t, conn, r); !strings.HasPrefix(strings.TrimSpace(resp), "OK") {
		t.Fatalf("Authentication failed: %q", resp)
	}
	return conn, r, w
}

// TestCheckScriptLiteral exercises the CHECKSCRIPT literal-parsing dispatch path
// over a real connection: non-synchronizing literal, synchronizing literal (with
// "+" continuation), syntax rejection, and pre-read MAXSCRIPTSIZE rejection.
func TestCheckScriptLiteral(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()

	t.Run("NonSyncLiteralValid", func(t *testing.T) {
		body := "require [\"fileinto\"];\r\nfileinto \"INBOX\";"
		fmt.Fprintf(w, "CHECKSCRIPT {%d+}\r\n%s\r\n", len(body), body)
		w.Flush()
		resp := msReadResp(t, conn, r)
		if !strings.HasPrefix(strings.TrimSpace(resp), "OK") {
			t.Errorf("expected OK for valid script, got: %q", resp)
		}
	})

	t.Run("NonSyncLiteralInvalid", func(t *testing.T) {
		body := "invalid_command;"
		fmt.Fprintf(w, "CHECKSCRIPT {%d+}\r\n%s\r\n", len(body), body)
		w.Flush()
		resp := msReadResp(t, conn, r)
		if !strings.HasPrefix(strings.TrimSpace(resp), "NO") {
			t.Errorf("expected NO for invalid script, got: %q", resp)
		}
	})

	t.Run("SynchronizingLiteralContinuation", func(t *testing.T) {
		body := "keep;"
		// No '+': server must send a continuation "+" before we send the data.
		fmt.Fprintf(w, "CHECKSCRIPT {%d}\r\n", len(body))
		w.Flush()

		cont := msReadLine(t, conn, r)
		if !strings.HasPrefix(strings.TrimSpace(cont), "+") {
			t.Fatalf("expected '+' continuation, got: %q", cont)
		}

		fmt.Fprintf(w, "%s\r\n", body)
		w.Flush()
		resp := msReadResp(t, conn, r)
		if !strings.HasPrefix(strings.TrimSpace(resp), "OK") {
			t.Errorf("expected OK after synchronizing literal, got: %q", resp)
		}
	})

	t.Run("OversizeRejectedBeforeRead", func(t *testing.T) {
		// Default maxScriptSize is 16KB; declare a larger literal. The server must
		// reject with MAXSCRIPTSIZE WITHOUT reading the body, so we send no data.
		fmt.Fprint(w, "CHECKSCRIPT {20000+}\r\n")
		w.Flush()
		resp := msReadResp(t, conn, r)
		if !strings.Contains(resp, "NO") || !strings.Contains(resp, "MAXSCRIPTSIZE") {
			t.Errorf("expected NO (MAXSCRIPTSIZE), got: %q", resp)
		}
	})
}

// TestRenameScriptProtocol exercises RENAMESCRIPT end-to-end, including the
// NONEXISTENT and ALREADYEXISTS response codes.
func TestRenameScriptProtocol(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()

	put := func(name, body string) {
		t.Helper()
		fmt.Fprintf(w, "PUTSCRIPT \"%s\" {%d+}\r\n%s\r\n", name, len(body), body)
		w.Flush()
		if resp := msReadResp(t, conn, r); !strings.HasPrefix(strings.TrimSpace(resp), "OK") {
			t.Fatalf("PUTSCRIPT %q failed: %q", name, resp)
		}
	}

	put("orig", "keep;")
	put("second", "discard;")

	t.Run("SuccessfulRename", func(t *testing.T) {
		fmt.Fprint(w, "RENAMESCRIPT \"orig\" \"renamed\"\r\n")
		w.Flush()
		if resp := msReadResp(t, conn, r); !strings.HasPrefix(strings.TrimSpace(resp), "OK") {
			t.Fatalf("expected OK, got: %q", resp)
		}

		// Old name must be gone.
		fmt.Fprint(w, "GETSCRIPT \"orig\"\r\n")
		w.Flush()
		if resp := msReadResp(t, conn, r); !strings.HasPrefix(strings.TrimSpace(resp), "NO") {
			t.Errorf("expected NO for old name after rename, got: %q", resp)
		}

		// New name must be listed.
		fmt.Fprint(w, "LISTSCRIPTS\r\n")
		w.Flush()
		resp := msReadResp(t, conn, r)
		if !strings.Contains(resp, "\"renamed\"") {
			t.Errorf("expected LISTSCRIPTS to contain \"renamed\", got: %q", resp)
		}
		if strings.Contains(resp, "\"orig\"") {
			t.Errorf("LISTSCRIPTS should not contain \"orig\" after rename, got: %q", resp)
		}
	})

	t.Run("NonexistentSource", func(t *testing.T) {
		fmt.Fprint(w, "RENAMESCRIPT \"ghost\" \"whatever\"\r\n")
		w.Flush()
		resp := msReadResp(t, conn, r)
		if !strings.Contains(resp, "NO") || !strings.Contains(resp, "NONEXISTENT") {
			t.Errorf("expected NO (NONEXISTENT), got: %q", resp)
		}
	})

	t.Run("TargetAlreadyExists", func(t *testing.T) {
		// "renamed" and "second" both exist now; renaming one onto the other must fail.
		fmt.Fprint(w, "RENAMESCRIPT \"renamed\" \"second\"\r\n")
		w.Flush()
		resp := msReadResp(t, conn, r)
		if !strings.Contains(resp, "NO") || !strings.Contains(resp, "ALREADYEXISTS") {
			t.Errorf("expected NO (ALREADYEXISTS), got: %q", resp)
		}
	})
}

// TestHaveSpaceProtocol exercises HAVESPACE end-to-end.
func TestHaveSpaceProtocol(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()

	t.Run("WithinLimit", func(t *testing.T) {
		fmt.Fprint(w, "HAVESPACE \"draft\" 100\r\n")
		w.Flush()
		if resp := msReadResp(t, conn, r); !strings.HasPrefix(strings.TrimSpace(resp), "OK") {
			t.Errorf("expected OK, got: %q", resp)
		}
	})

	t.Run("ExceedsLimit", func(t *testing.T) {
		fmt.Fprint(w, "HAVESPACE \"draft\" 20000\r\n")
		w.Flush()
		resp := msReadResp(t, conn, r)
		if !strings.Contains(resp, "NO") || !strings.Contains(resp, "MAXSCRIPTSIZE") {
			t.Errorf("expected NO (MAXSCRIPTSIZE), got: %q", resp)
		}
	})
}
