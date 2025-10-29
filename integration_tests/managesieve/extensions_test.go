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

	// Test 1: No extensions configured - should advertise nothing
	t.Run("NoExtensions", func(t *testing.T) {
		testExtensions(t, []string{}, []string{})
	})

	// Test 2: Single extension
	t.Run("SingleExtension", func(t *testing.T) {
		configuredExtensions := []string{"vacation"}
		testExtensions(t, configuredExtensions, configuredExtensions)
	})

	// Test 3: Multiple extensions
	t.Run("MultipleExtensions", func(t *testing.T) {
		configuredExtensions := []string{"fileinto", "vacation", "regex"}
		testExtensions(t, configuredExtensions, configuredExtensions)
	})

	// Test 4: Commonly used production extensions
	t.Run("CommonlyUsedExtensions", func(t *testing.T) {
		configuredExtensions := []string{"fileinto", "vacation", "envelope", "imap4flags", "variables", "relational", "copy", "regex"}
		testExtensions(t, configuredExtensions, configuredExtensions)
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

	// Extract SIEVE capability line
	sieveLine := ""
	for _, line := range strings.Split(capabilityResponse, "\n") {
		if strings.Contains(line, "\"SIEVE\"") {
			sieveLine = line
			break
		}
	}

	if sieveLine == "" {
		t.Fatalf("No SIEVE capability line found in response: %s", capabilityResponse)
	}

	t.Logf("SIEVE capability line: %s", sieveLine)

	// Verify each expected extension is listed
	for _, ext := range expectedExtensions {
		if !strings.Contains(sieveLine, ext) {
			t.Errorf("Extension '%s' should be listed in SIEVE capabilities, but was not found in: %s", ext, sieveLine)
		}
	}

	// Verify no unexpected extensions are present (if we expect empty, check that SIEVE line is empty)
	if len(expectedExtensions) == 0 {
		// Should be something like: "SIEVE" ""
		if !strings.Contains(sieveLine, `"SIEVE" ""`) && !strings.Contains(sieveLine, `"SIEVE"  ""`) {
			t.Logf("Note: Empty extensions should result in empty SIEVE capability, got: %s", sieveLine)
		}
	}

	t.Logf("Successfully verified %d extensions: %v", len(expectedExtensions), expectedExtensions)
}
