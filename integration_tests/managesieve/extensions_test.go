//go:build integration

package managesieve

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/managesieve"
)

func TestManageSieveConfigurableExtensions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Builtin extensions that are always present
	builtinExtensions := []string{
		"fileinto", "reject", "envelope", "encoded-character", "subaddress",
		"comparator-i;ascii-numeric", "relational", "imap4flags", "copy",
		"include", "variables", "body", "enotify", "environment", "mailbox",
		"date", "index", "ihave", "duplicate", "mime", "foreverypart", "extracttext",
	}

	// Test 1: Default extensions (no additional configured, just builtins)
	t.Run("DefaultExtensions", func(t *testing.T) {
		testExtensions(t, nil, builtinExtensions)
	})

	// Test 2: Custom additional extensions (vacation added to builtins)
	t.Run("CustomExtensions", func(t *testing.T) {
		additionalExtensions := []string{"vacation"}
		expectedExtensions := append(builtinExtensions, additionalExtensions...)
		testExtensions(t, additionalExtensions, expectedExtensions)
	})

	// Test 3: Multiple additional extensions
	t.Run("MultipleAdditionalExtensions", func(t *testing.T) {
		additionalExtensions := []string{"vacation", "regex"}
		expectedExtensions := append(builtinExtensions, additionalExtensions...)
		testExtensions(t, additionalExtensions, expectedExtensions)
	})
}

func testExtensions(t *testing.T, configuredExtensions []string, expectedExtensions []string) {
	t.Helper()

	// Create test database and account
	rdb := common.SetupTestDatabase(t)
	_ = common.CreateTestAccount(t, rdb) // Create account for database setup
	address := common.GetRandomAddress(t)

	// Create ManageSieve server with specific extensions
	options := managesieve.ManageSieveServerOptions{
		InsecureAuth: true, // Enable PLAIN auth for testing
	}
	if configuredExtensions != nil {
		options.SupportedExtensions = configuredExtensions
	}

	server, err := managesieve.New(
		context.Background(),
		"test",
		"localhost",
		address,
		rdb,
		options,
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	defer func() {
		server.Close()
		select {
		case <-errChan:
		default:
		}
	}()

	// Connect to the server
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting and check capabilities
	greeting := readResponse(t, reader)
	t.Logf("Server greeting: %s", strings.TrimSpace(greeting))

	// Send CAPABILITY command
	sendCommand(t, writer, "CAPABILITY")
	capabilityResponse := readResponse(t, reader)
	t.Logf("CAPABILITY response: %s", strings.TrimSpace(capabilityResponse))

	// Check that the response contains the expected extensions
	expectedExtensionsStr := strings.Join(expectedExtensions, " ")
	if !strings.Contains(capabilityResponse, expectedExtensionsStr) {
		t.Errorf("CAPABILITY response should contain '%s', but got: %s", expectedExtensionsStr, capabilityResponse)
	}

	// Verify each individual extension is listed
	for _, ext := range expectedExtensions {
		if !strings.Contains(capabilityResponse, ext) {
			t.Errorf("Extension '%s' should be listed in capabilities, but was not found in: %s", ext, capabilityResponse)
		}
	}

	t.Logf("Successfully verified extensions: %v", expectedExtensions)
}
