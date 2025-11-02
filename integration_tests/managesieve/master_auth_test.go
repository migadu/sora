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

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/managesieve"
)

const (
	masterUsername     = "admin"
	masterPassword     = "master_secret_123"
	masterSASLUsername = "sasl_admin"
	masterSASLPassword = "sasl_secret_456"
)

// setupManageSieveServerWithMasterAuth creates a ManageSieve server with master authentication configured
func setupManageSieveServerWithMasterAuth(t *testing.T) (*common.TestServer, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	testConfig := &config.Config{}

	server, err := managesieve.New(
		context.Background(),
		"test",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			Config:             testConfig,
			MasterUsername:     masterUsername,
			MasterPassword:     masterPassword,
			MasterSASLUsername: masterSASLUsername,
			MasterSASLPassword: masterSASLPassword,
			InsecureAuth:       true, // Allow authentication over non-TLS connection for testing
		},
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

	cleanup := func() {
		server.Close()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("ManageSieve server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
	}

	ts := &common.TestServer{
		Address:     address,
		Server:      server,
		ResilientDB: rdb,
	}
	t.Cleanup(cleanup)

	return ts, account
}

// ManageSieveClient provides a simple ManageSieve client for testing
type ManageSieveClient struct {
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
}

func NewManageSieveClient(address string) (*ManageSieveClient, error) {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, err
	}

	client := &ManageSieveClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
		writer: bufio.NewWriter(conn),
	}

	// Read greeting (capabilities followed by OK)
	for {
		line, err := client.reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read greeting: %w", err)
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	return client, nil
}

func (c *ManageSieveClient) SendCommand(cmd string) error {
	_, err := fmt.Fprintf(c.writer, "%s\r\n", cmd)
	if err != nil {
		return err
	}
	return c.writer.Flush()
}

func (c *ManageSieveClient) ReadResponse() (string, error) {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (c *ManageSieveClient) Close() error {
	// Try to send LOGOUT gracefully
	c.SendCommand("LOGOUT")
	return c.conn.Close()
}

// TestManageSieve_MasterUsernameAuthentication tests AUTH PLAIN with MasterUsername
func TestManageSieve_MasterUsernameAuthentication(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupManageSieveServerWithMasterAuth(t)
	defer server.Close()

	t.Run("AUTHENTICATE PLAIN with MasterUsername suffix", func(t *testing.T) {
		client, err := NewManageSieveClient(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve server: %v", err)
		}
		defer client.Close()

		// AUTHENTICATE PLAIN with master username suffix
		// Format: authorization-id \0 authentication-id \0 password
		// For master username, we use: "" \0 user@domain.com@admin \0 master_secret_123
		username := account.Email + "@" + masterUsername
		authString := "\x00" + username + "\x00" + masterPassword
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded)); err != nil {
			t.Fatalf("AUTHENTICATE command failed: %v", err)
		}

		response, err := client.ReadResponse()
		if err != nil || !strings.HasPrefix(response, "OK") {
			t.Fatalf("Authentication failed: %s (err: %v)", response, err)
		}
		t.Log("✓ Successfully authenticated with AUTHENTICATE PLAIN master username")

		// Verify we can use LISTSCRIPTS command
		if err := client.SendCommand("LISTSCRIPTS"); err != nil {
			t.Fatalf("LISTSCRIPTS command failed: %v", err)
		}

		// Read LISTSCRIPTS response (may have script lines, then OK)
		for {
			response, err := client.ReadResponse()
			if err != nil {
				t.Fatalf("Failed to read LISTSCRIPTS response: %v", err)
			}
			if response == "OK" {
				break
			}
		}
		t.Log("✓ LISTSCRIPTS successful")
	})

	t.Run("AUTHENTICATE with wrong MasterUsername suffix", func(t *testing.T) {
		client, err := NewManageSieveClient(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve server: %v", err)
		}
		defer client.Close()

		username := account.Email + "@wrongmaster"
		authString := "\x00" + username + "\x00" + masterPassword
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded))
		response, _ := client.ReadResponse()
		if strings.HasPrefix(response, "OK") {
			t.Fatal("Expected authentication to fail with wrong master username")
		}
		t.Logf("✓ Authentication correctly failed with wrong master username: %s", response)
	})

	t.Run("AUTHENTICATE with wrong MasterPassword", func(t *testing.T) {
		client, err := NewManageSieveClient(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve server: %v", err)
		}
		defer client.Close()

		username := account.Email + "@" + masterUsername
		authString := "\x00" + username + "\x00" + "wrong_password"
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded))
		response, _ := client.ReadResponse()
		if strings.HasPrefix(response, "OK") {
			t.Fatal("Expected authentication to fail with wrong master password")
		}
		t.Logf("✓ Authentication correctly failed with wrong master password: %s", response)
	})
}

// TestManageSieve_MasterSASLAuthentication tests AUTH PLAIN with MasterSASLUsername
func TestManageSieve_MasterSASLAuthentication(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupManageSieveServerWithMasterAuth(t)
	defer server.Close()

	t.Run("AUTHENTICATE PLAIN with MasterSASLUsername impersonation", func(t *testing.T) {
		client, err := NewManageSieveClient(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve server: %v", err)
		}
		defer client.Close()

		// SASL PLAIN with authorization identity (impersonation)
		// Format: authorization-id \0 authentication-id \0 password
		authString := account.Email + "\x00" + masterSASLUsername + "\x00" + masterSASLPassword
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded)); err != nil {
			t.Fatalf("AUTHENTICATE command failed: %v", err)
		}

		response, err := client.ReadResponse()
		if err != nil || !strings.HasPrefix(response, "OK") {
			t.Fatalf("Authentication failed: %s (err: %v)", response, err)
		}
		t.Log("✓ Successfully authenticated with AUTHENTICATE PLAIN master SASL username")

		// Verify we can use LISTSCRIPTS command
		if err := client.SendCommand("LISTSCRIPTS"); err != nil {
			t.Fatalf("LISTSCRIPTS command failed: %v", err)
		}

		// Read LISTSCRIPTS response
		for {
			response, err := client.ReadResponse()
			if err != nil {
				t.Fatalf("Failed to read LISTSCRIPTS response: %v", err)
			}
			if response == "OK" {
				break
			}
		}
		t.Log("✓ LISTSCRIPTS successful")
	})
}

// TestManageSieve_MasterAuthenticationPriority tests authentication priority
func TestManageSieve_MasterAuthenticationPriority(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupManageSieveServerWithMasterAuth(t)
	defer server.Close()

	t.Run("Master username overrides regular auth", func(t *testing.T) {
		client, err := NewManageSieveClient(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve server: %v", err)
		}
		defer client.Close()

		// Try master username suffix with account password (should fail)
		username := account.Email + "@" + masterUsername
		authString := "\x00" + username + "\x00" + account.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded))
		response, _ := client.ReadResponse()
		if strings.HasPrefix(response, "OK") {
			t.Fatal("Expected authentication to fail when using account password with master username suffix")
		}
		t.Log("✓ Correctly rejected account password when master username suffix is present")
	})

	t.Run("Regular auth still works without suffix", func(t *testing.T) {
		client, err := NewManageSieveClient(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve server: %v", err)
		}
		defer client.Close()

		// Regular authentication should work
		authString := "\x00" + account.Email + "\x00" + account.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded)); err != nil {
			t.Fatalf("AUTHENTICATE command failed: %v", err)
		}

		response, err := client.ReadResponse()
		if err != nil || !strings.HasPrefix(response, "OK") {
			t.Fatalf("Regular authentication failed: %s", response)
		}
		t.Log("✓ Regular authentication still works without master suffix")

		// Verify LISTSCRIPTS works
		client.SendCommand("LISTSCRIPTS")
		for {
			response, err := client.ReadResponse()
			if err != nil {
				t.Fatalf("Failed to read response: %v", err)
			}
			if response == "OK" {
				break
			}
		}
		t.Log("✓ LISTSCRIPTS successful")
	})
}

// TestManageSieve_MasterAuthenticationMultipleAccounts tests master auth with different accounts
func TestManageSieve_MasterAuthenticationMultipleAccounts(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := setupManageSieveServerWithMasterAuth(t)
	defer server.Close()

	// Create a second account
	account2 := common.CreateTestAccount(t, server.ResilientDB)

	t.Run("Master credentials work for different accounts", func(t *testing.T) {
		// Test with account 1
		client1, err := NewManageSieveClient(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve server: %v", err)
		}
		defer client1.Close()

		username1 := account1.Email + "@" + masterUsername
		authString1 := "\x00" + username1 + "\x00" + masterPassword
		encoded1 := base64.StdEncoding.EncodeToString([]byte(authString1))

		if err := client1.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded1)); err != nil {
			t.Fatalf("AUTHENTICATE failed for account1: %v", err)
		}
		response, err := client1.ReadResponse()
		if err != nil || !strings.HasPrefix(response, "OK") {
			t.Fatalf("Authentication failed for account1: %s", response)
		}
		t.Logf("✓ Master auth successful for account1: %s", account1.Email)

		// Test with account 2
		client2, err := NewManageSieveClient(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve server: %v", err)
		}
		defer client2.Close()

		username2 := account2.Email + "@" + masterUsername
		authString2 := "\x00" + username2 + "\x00" + masterPassword
		encoded2 := base64.StdEncoding.EncodeToString([]byte(authString2))

		if err := client2.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded2)); err != nil {
			t.Fatalf("AUTHENTICATE failed for account2: %v", err)
		}
		response, err = client2.ReadResponse()
		if err != nil || !strings.HasPrefix(response, "OK") {
			t.Fatalf("Authentication failed for account2: %s", response)
		}
		t.Logf("✓ Master auth successful for account2: %s", account2.Email)

		// Verify both can access their accounts
		client1.SendCommand("LISTSCRIPTS")
		for {
			response, _ := client1.ReadResponse()
			if response == "OK" {
				break
			}
		}
		t.Log("✓ Account1 LISTSCRIPTS successful")

		client2.SendCommand("LISTSCRIPTS")
		for {
			response, _ := client2.ReadResponse()
			if response == "OK" {
				break
			}
		}
		t.Log("✓ Account2 LISTSCRIPTS successful")
	})
}
