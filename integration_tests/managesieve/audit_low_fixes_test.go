//go:build integration

package managesieve

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/managesieve"
)

// TestNonexistentScriptResponseCode verifies audit L2: GETSCRIPT/SETACTIVE/DELETESCRIPT
// on a missing script return the machine-readable (NONEXISTENT) response code.
func TestNonexistentScriptResponseCode(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupManageSieveServer(t)

	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()

	for _, cmd := range []string{
		`GETSCRIPT "does_not_exist"`,
		`SETACTIVE "does_not_exist"`,
		`DELETESCRIPT "does_not_exist"`,
	} {
		fmt.Fprintf(w, "%s\r\n", cmd)
		w.Flush()
		resp := strings.TrimSpace(msReadResp(t, conn, r))
		if !strings.HasPrefix(resp, "NO") {
			t.Errorf("%s: expected NO, got %q", cmd, resp)
		}
		if !strings.Contains(strings.ToUpper(resp), "NONEXISTENT") {
			t.Errorf("%s: expected (NONEXISTENT) response code, got %q", cmd, resp)
		}
	}
	t.Log("✓ GET/SET/DELETE of missing script return (NONEXISTENT)")
}

// TestScriptNameControlCharsRejected verifies audit L5: control characters in a script
// name are rejected, while a normal (spaces/unicode) name is still accepted.
func TestScriptNameControlCharsRejected(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupManageSieveServer(t)

	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()

	body := "keep;"

	// Control character (SOH, 0x01) in the name must be refused. The non-synchronizing
	// literal is still read by the server (protocol stays in sync), then the name is
	// rejected.
	fmt.Fprintf(w, "PUTSCRIPT \"bad\x01name\" {%d+}\r\n%s\r\n", len(body), body)
	w.Flush()
	if resp := strings.TrimSpace(msReadResp(t, conn, r)); !strings.HasPrefix(resp, "NO") {
		t.Errorf("expected NO for control-char script name, got %q", resp)
	} else {
		t.Logf("✓ control-char name rejected: %q", resp)
	}

	// A valid unicode name with spaces must still be accepted.
	name := "Ünïcödé script"
	fmt.Fprintf(w, "PUTSCRIPT \"%s\" {%d+}\r\n%s\r\n", name, len(body), body)
	w.Flush()
	if resp := strings.TrimSpace(msReadResp(t, conn, r)); !strings.HasPrefix(resp, "OK") {
		t.Errorf("expected OK for valid unicode script name, got %q", resp)
	}
}

// TestStartTLSAfterAuthRejected verifies audit L1: STARTTLS on an already-authenticated
// connection is rejected (rather than silently upgrading without resetting state).
func TestStartTLSAfterAuthRejected(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	server, err := managesieve.New(
		context.Background(),
		"test-starttls-after-auth",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth:   true, // allow plaintext auth so we can authenticate before STARTTLS
			TLS:            true,
			TLSUseStartTLS: true,
			TLSCertFile:    "../../testdata/sora.crt",
			TLSKeyFile:     "../../testdata/sora.key",
		},
	)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	errChan := make(chan error, 1)
	go func() { server.Start(errChan) }()
	defer server.Close()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	// Consume greeting.
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("greeting: %v", err)
		}
		if strings.HasPrefix(strings.TrimSpace(line), "OK") {
			break
		}
	}

	// Authenticate over the plaintext connection (insecure_auth=true).
	creds := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)))
	fmt.Fprintf(w, "AUTHENTICATE \"PLAIN\" {%d+}\r\n%s\r\n", len(creds), creds)
	w.Flush()
	if resp, _ := r.ReadString('\n'); !strings.HasPrefix(strings.TrimSpace(resp), "OK") {
		t.Fatalf("auth failed: %q", resp)
	}

	// STARTTLS after authentication must be refused.
	fmt.Fprint(w, "STARTTLS\r\n")
	w.Flush()
	resp, _ := r.ReadString('\n')
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "NO") {
		t.Errorf("expected NO for STARTTLS after auth, got %q", resp)
	}
	if !strings.Contains(strings.ToLower(resp), "authentication") {
		t.Errorf("expected 'after authentication' message, got %q", resp)
	}
	t.Logf("✓ STARTTLS after auth rejected: %q", resp)
}
