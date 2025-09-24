//go:build integration

package managesieve

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/managesieve"
)

func TestManageSieveConfigurableExtensions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Test 1: Default extensions
	t.Run("DefaultExtensions", func(t *testing.T) {
		testExtensions(t, nil, []string{"fileinto", "vacation"})
	})

	// Test 2: Custom extensions
	t.Run("CustomExtensions", func(t *testing.T) {
		customExtensions := []string{"fileinto", "vacation", "envelope", "variables", "relational"}
		testExtensions(t, customExtensions, customExtensions)
	})

	// Test 3: Minimal extensions
	t.Run("MinimalExtensions", func(t *testing.T) {
		minimalExtensions := []string{"fileinto"}
		testExtensions(t, minimalExtensions, minimalExtensions)
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
