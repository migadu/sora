//go:build integration

package managesieve

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/managesieve"
)

// TestInsecureAuthDisabled tests that authentication is rejected over non-TLS
// connections when insecure_auth = false (secure by default)
func TestInsecureAuthDisabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	// Create ManageSieve server with insecure_auth = false and STARTTLS support
	server, err := managesieve.New(
		context.Background(),
		"test-insecure-auth-disabled",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth:        false, // Reject auth over non-TLS (secure by default)
			TLS:                 true,
			TLSUseStartTLS:      true,
			TLSCertFile:         "../../testdata/sora.crt",
			TLSKeyFile:          "../../testdata/sora.key",
			SupportedExtensions: []string{"fileinto", "vacation"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()
	defer server.Close()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Connect to the server (non-TLS initially)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	var greetingLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting line: %v", err)
		}
		line = strings.TrimSpace(line)
		greetingLines = append(greetingLines, line)
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	// Verify STARTTLS capability is advertised (since we're not over TLS yet)
	foundStartTLS := false
	foundSASLPlain := false
	foundEmptySASL := false
	for _, line := range greetingLines {
		if strings.Contains(line, `"STARTTLS"`) {
			foundStartTLS = true
		}
		// SASL PLAIN should NOT be advertised when !isTLS && !insecureAuth
		// Instead, empty SASL should be advertised (RFC 5804 security requirement)
		if strings.Contains(line, `"SASL" "PLAIN"`) {
			foundSASLPlain = true
		}
		if strings.Contains(line, `"SASL" ""`) {
			foundEmptySASL = true
		}
	}

	if !foundStartTLS {
		t.Errorf("Expected STARTTLS capability in greeting when not over TLS")
	}
	if foundSASLPlain {
		t.Errorf("Did not expect SASL PLAIN capability in greeting when !isTLS && !insecureAuth")
	}
	if !foundEmptySASL {
		t.Errorf("Expected empty SASL capability before STARTTLS (RFC 5804 requirement)")
	}

	// Try to authenticate without STARTTLS - should be rejected
	authzID := ""
	authnID := account.Email
	password := account.Password
	saslPlain := fmt.Sprintf("%s\x00%s\x00%s", authzID, authnID, password)
	encoded := base64.StdEncoding.EncodeToString([]byte(saslPlain))

	writer.WriteString(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"\r\n", encoded))
	writer.Flush()

	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read AUTHENTICATE response: %v", err)
	}
	response = strings.TrimSpace(response)

	// Should receive NO response rejecting authentication
	if !strings.HasPrefix(response, "NO") {
		t.Errorf("Expected NO response for authentication over non-TLS, got: %s", response)
	}
	if !strings.Contains(response, "insecure connection") && !strings.Contains(response, "STARTTLS") {
		t.Errorf("Expected error message about insecure connection or STARTTLS, got: %s", response)
	}

	t.Logf("✓ Authentication correctly rejected over non-TLS connection: %s", response)
}

// TestInsecureAuthEnabled tests that authentication is allowed over non-TLS
// connections when insecure_auth = true
func TestInsecureAuthEnabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	// Create ManageSieve server with insecure_auth = true
	server, err := managesieve.New(
		context.Background(),
		"test-insecure-auth-enabled",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth:        true, // Allow auth over non-TLS (for testing/legacy clients)
			SupportedExtensions: []string{"fileinto", "vacation"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()
	defer server.Close()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Connect to the server (non-TLS)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	var greetingLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting line: %v", err)
		}
		line = strings.TrimSpace(line)
		greetingLines = append(greetingLines, line)
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	// Verify SASL PLAIN capability IS advertised (since insecure_auth = true)
	foundSASLPlain := false
	for _, line := range greetingLines {
		if strings.Contains(line, `"SASL" "PLAIN"`) {
			foundSASLPlain = true
		}
	}

	if !foundSASLPlain {
		t.Errorf("Expected SASL PLAIN capability in greeting when insecure_auth=true, got: %v", greetingLines)
	}

	// Authenticate without TLS - should succeed
	authzID := ""
	authnID := account.Email
	password := account.Password
	saslPlain := fmt.Sprintf("%s\x00%s\x00%s", authzID, authnID, password)
	encoded := base64.StdEncoding.EncodeToString([]byte(saslPlain))

	writer.WriteString(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"\r\n", encoded))
	writer.Flush()

	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read AUTHENTICATE response: %v", err)
	}
	response = strings.TrimSpace(response)

	// Should receive OK response
	if !strings.HasPrefix(response, "OK") {
		t.Errorf("Expected OK response for authentication over non-TLS when insecure_auth=true, got: %s", response)
	}

	t.Logf("✓ Authentication succeeded over non-TLS connection with insecure_auth=true: %s", response)
}

// TestInsecureAuthWithSTARTTLS tests that authentication works after STARTTLS
// even when insecure_auth = false
func TestInsecureAuthWithSTARTTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	// Create ManageSieve server with insecure_auth = false but STARTTLS enabled
	server, err := managesieve.New(
		context.Background(),
		"test-insecure-auth-starttls",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth:        false, // Reject auth over non-TLS
			TLS:                 true,
			TLSUseStartTLS:      true,
			TLSCertFile:         "../../testdata/sora.crt",
			TLSKeyFile:          "../../testdata/sora.key",
			SupportedExtensions: []string{"fileinto", "vacation"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()
	defer server.Close()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Connect to the server (non-TLS initially)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	var greetingLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting line: %v", err)
		}
		line = strings.TrimSpace(line)
		greetingLines = append(greetingLines, line)
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	// Verify STARTTLS capability is advertised
	foundStartTLS := false
	for _, line := range greetingLines {
		if strings.Contains(line, `"STARTTLS"`) {
			foundStartTLS = true
		}
	}

	if !foundStartTLS {
		t.Fatalf("Expected STARTTLS capability in greeting")
	}

	// Send STARTTLS command
	writer.WriteString("STARTTLS\r\n")
	writer.Flush()

	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read STARTTLS response: %v", err)
	}
	response = strings.TrimSpace(response)

	if !strings.HasPrefix(response, "OK") {
		t.Fatalf("Expected OK response for STARTTLS, got: %s", response)
	}

	t.Logf("✓ STARTTLS initiated successfully")

	// Upgrade connection to TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Skip verification for test certificate
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Update reader and writer to use TLS connection
	reader = bufio.NewReader(tlsConn)
	writer = bufio.NewWriter(tlsConn)

	t.Logf("✓ TLS handshake completed")

	// After STARTTLS, the server does NOT automatically resend capabilities per RFC 5804.
	// The server just continues in the command loop, now over TLS.
	// We can directly send AUTH command now since we're over TLS.

	// Give the server a moment to release any locks from STARTTLS processing
	// Note: The server uses deferred lock releases which may take a moment to complete
	time.Sleep(500 * time.Millisecond)

	// Now authenticate - should succeed since we're over TLS
	authzID := ""
	authnID := account.Email
	password := account.Password
	saslPlain := fmt.Sprintf("%s\x00%s\x00%s", authzID, authnID, password)
	encoded := base64.StdEncoding.EncodeToString([]byte(saslPlain))

	writer.WriteString(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"\r\n", encoded))
	writer.Flush()

	authResponse, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read AUTHENTICATE response: %v", err)
	}
	authResponse = strings.TrimSpace(authResponse)

	// Should receive OK response
	if !strings.HasPrefix(authResponse, "OK") {
		t.Errorf("Expected OK response for authentication over TLS after STARTTLS, got: %s", authResponse)
	}

	t.Logf("✓ Authentication succeeded over TLS after STARTTLS: %s", authResponse)
}

// TestInsecureAuthWithImplicitTLS tests that authentication works with implicit TLS
// even when insecure_auth = false
func TestInsecureAuthWithImplicitTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	// Create ManageSieve server with insecure_auth = false and implicit TLS
	server, err := managesieve.New(
		context.Background(),
		"test-insecure-auth-implicit-tls",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth:        false, // Reject auth over non-TLS
			TLS:                 true,
			TLSUseStartTLS:      false, // Implicit TLS (not STARTTLS)
			TLSCertFile:         "../../testdata/sora.crt",
			TLSKeyFile:          "../../testdata/sora.key",
			SupportedExtensions: []string{"fileinto", "vacation"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()
	defer server.Close()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Connect with TLS from the start
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Skip verification for test certificate
	}
	conn, err := tls.Dial("tcp", address, tlsConfig)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server with TLS: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	var greetingLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting line: %v", err)
		}
		line = strings.TrimSpace(line)
		greetingLines = append(greetingLines, line)
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	// Verify STARTTLS is NOT advertised (since we're already over TLS)
	// Note: SASL PLAIN IS advertised in capabilities when over TLS, per RFC 5804.
	foundStartTLS := false
	foundSASLPlain := false
	for _, line := range greetingLines {
		if strings.Contains(line, `"STARTTLS"`) {
			foundStartTLS = true
		}
		if strings.Contains(line, `"SASL" "PLAIN"`) {
			foundSASLPlain = true
		}
	}

	if foundStartTLS {
		t.Errorf("Did not expect STARTTLS capability when already using implicit TLS")
	}
	if !foundSASLPlain {
		t.Errorf("Expected SASL PLAIN capability when over TLS (RFC 5804 requirement), got: %v", greetingLines)
	}

	// Authenticate - should succeed since we're over TLS
	authzID := ""
	authnID := account.Email
	password := account.Password
	saslPlain := fmt.Sprintf("%s\x00%s\x00%s", authzID, authnID, password)
	encoded := base64.StdEncoding.EncodeToString([]byte(saslPlain))

	writer.WriteString(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"\r\n", encoded))
	writer.Flush()

	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read AUTHENTICATE response: %v", err)
	}
	response = strings.TrimSpace(response)

	// Should receive OK response
	if !strings.HasPrefix(response, "OK") {
		t.Errorf("Expected OK response for authentication over implicit TLS, got: %s", response)
	}

	t.Logf("✓ Authentication succeeded over implicit TLS: %s", response)
}
