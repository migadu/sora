//go:build integration

package managesieve

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestDeleteActiveScriptRejected verifies RFC 5804 §2.10 (audit M4): DELETESCRIPT of
// the active script is refused with NO (ACTIVE); after deactivation it succeeds.
func TestDeleteActiveScriptRejected(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupManageSieveServer(t)

	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()

	// Upload and activate a script.
	body := "keep;"
	fmt.Fprintf(w, "PUTSCRIPT \"active_one\" {%d+}\r\n%s\r\n", len(body), body)
	w.Flush()
	if resp := msReadResp(t, conn, r); !strings.HasPrefix(strings.TrimSpace(resp), "OK") {
		t.Fatalf("PUTSCRIPT failed: %q", resp)
	}
	fmt.Fprint(w, "SETACTIVE \"active_one\"\r\n")
	w.Flush()
	if resp := msReadResp(t, conn, r); !strings.HasPrefix(strings.TrimSpace(resp), "OK") {
		t.Fatalf("SETACTIVE failed: %q", resp)
	}

	// DELETESCRIPT of the active script MUST be refused.
	fmt.Fprint(w, "DELETESCRIPT \"active_one\"\r\n")
	w.Flush()
	resp := strings.TrimSpace(msReadResp(t, conn, r))
	if !strings.HasPrefix(resp, "NO") {
		t.Fatalf("expected NO deleting active script, got: %q", resp)
	}
	if !strings.Contains(strings.ToUpper(resp), "ACTIVE") {
		t.Errorf("expected (ACTIVE) response code, got: %q", resp)
	}
	t.Logf("✓ DELETESCRIPT of active script refused: %q", resp)

	// After deactivation (SETACTIVE ""), deletion must succeed.
	fmt.Fprint(w, "SETACTIVE \"\"\r\n")
	w.Flush()
	if resp := msReadResp(t, conn, r); !strings.HasPrefix(strings.TrimSpace(resp), "OK") {
		t.Fatalf("SETACTIVE \"\" (deactivate) failed: %q", resp)
	}
	fmt.Fprint(w, "DELETESCRIPT \"active_one\"\r\n")
	w.Flush()
	if resp := msReadResp(t, conn, r); !strings.HasPrefix(strings.TrimSpace(resp), "OK") {
		t.Errorf("expected OK deleting deactivated script, got: %q", resp)
	}
}

// TestReauthenticationRejected verifies the RFC 5804 state machine / audit M1:
// AUTHENTICATE on an already-authenticated connection is rejected.
func TestReauthenticationRejected(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupManageSieveServer(t)

	conn, r, w := msConnectAndAuth(t, server, account) // leaves the session authenticated
	defer conn.Close()

	creds := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)))
	fmt.Fprintf(w, "AUTHENTICATE \"PLAIN\" {%d+}\r\n%s\r\n", len(creds), creds)
	w.Flush()

	resp := strings.TrimSpace(msReadResp(t, conn, r))
	if !strings.HasPrefix(resp, "NO") {
		t.Fatalf("expected NO for re-authentication, got: %q", resp)
	}
	if !strings.Contains(strings.ToLower(resp), "already authenticated") {
		t.Errorf("expected 'already authenticated' message, got: %q", resp)
	}
	t.Logf("✓ Re-authentication rejected: %q", resp)
}

// TestInvalidScriptErrorIsQuoted verifies audit M3: SIEVE validation errors are
// returned as a quoted string (NO "..."), not interpolated raw, so attacker-controlled
// script tokens containing CRLF/quotes cannot inject a forged response line.
func TestInvalidScriptErrorIsQuoted(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupManageSieveServer(t)

	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()

	// require of an unsupported extension → deterministic validation failure.
	bad := "require [\"a_definitely_unsupported_extension_xyz\"];\r\nkeep;\r\n"
	fmt.Fprintf(w, "PUTSCRIPT \"bad\" {%d+}\r\n%s\r\n", len(bad), bad)
	w.Flush()

	resp := strings.TrimSpace(msReadResp(t, conn, r))
	if !strings.HasPrefix(resp, "NO") {
		t.Fatalf("expected NO for invalid script, got: %q", resp)
	}
	// The human-readable text must be a quoted string per RFC 5804 framing.
	if !strings.HasPrefix(resp, "NO \"") {
		t.Errorf("expected quoted error string after NO (M3), got: %q", resp)
	}
	t.Logf("✓ Invalid-script error returned quoted: %q", resp)
}
