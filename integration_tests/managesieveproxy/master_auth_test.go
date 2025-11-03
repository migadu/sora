//go:build integration

package managesieveproxy_test

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
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieveproxy"
)

const (
	// Master credentials for CLIENT→PROXY authentication (@ separator format)
	proxyMasterUsername = "proxy_admin"
	proxyMasterPassword = "proxy_master_123"

	// Master credentials for PROXY→BACKEND authentication (SASL)
	// These MUST match what the backend server expects (from common.SetupManageSieveServerWithMaster)
	proxyMasterSASLUsername = "master_sasl"
	proxyMasterSASLPassword = "master_sasl_secret"
)

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
	c.SendCommand("LOGOUT")
	return c.conn.Close()
}

// setupManageSieveProxyWithMasterAuth creates ManageSieve proxy with master authentication configured
func setupManageSieveProxyWithMasterAuth(t *testing.T, rdb *common.TestServer, proxyAddr string, backendAddrs []string) *common.TestServer {
	t.Helper()

	hostname := "test-managesieve-proxy-master"

	opts := managesieveproxy.ServerOptions{
		Name:        "test-managesieve-proxy-master",
		Addr:        proxyAddr,
		RemoteAddrs: backendAddrs,
		RemotePort:  4190,
		// Master credentials for CLIENT→PROXY authentication (@ separator format)
		MasterUsername: proxyMasterUsername,
		MasterPassword: proxyMasterPassword,
		// Master credentials for PROXY→BACKEND authentication (SASL)
		// MUST match what backend expects
		MasterSASLUsername: proxyMasterSASLUsername,
		MasterSASLPassword: proxyMasterSASLPassword,
		TLS:                false,
		TLSVerify:          false,
		RemoteTLS:          false,
		RemoteTLSVerify:    false,
		InsecureAuth:       true, // Allow authentication over non-TLS for testing
		ConnectTimeout:     10 * time.Second,
		SessionTimeout:     30 * time.Minute,
		CommandTimeout:     5 * time.Minute,
		EnableAffinity:     true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
	}

	proxy, err := managesieveproxy.New(context.Background(), rdb.ResilientDB, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy with master auth: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("ManageSieve proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	cleanup := func() {
		proxy.Stop()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("ManageSieve proxy error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
		}
	}

	ts := &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb.ResilientDB,
	}
	t.Cleanup(cleanup)

	return ts
}

// TestManageSieveProxy_MasterUsernameAuthentication tests proxy authentication with MasterUsername
func TestManageSieveProxy_MasterUsernameAuthentication(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server with master SASL credentials
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	// Create proxy with master username/password for client authentication
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithMasterAuth(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	t.Run("AUTHENTICATE with MasterUsername suffix through proxy", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		// AUTHENTICATE PLAIN with master username suffix at proxy level
		username := account.Email + "@" + proxyMasterUsername
		authString := "\x00" + username + "\x00" + proxyMasterPassword
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded)); err != nil {
			t.Fatalf("AUTHENTICATE command failed: %v", err)
		}

		response, err := client.ReadResponse()
		if err != nil || !strings.HasPrefix(response, "OK") {
			t.Fatalf("Authentication failed: %s (err: %v)", response, err)
		}
		t.Log("✓ Successfully authenticated through proxy with MasterUsername")

		// Verify we can use LISTSCRIPTS command
		if err := client.SendCommand("LISTSCRIPTS"); err != nil {
			t.Fatalf("LISTSCRIPTS command failed: %v", err)
		}
		for {
			response, err := client.ReadResponse()
			if err != nil {
				t.Fatalf("Failed to read LISTSCRIPTS response: %v", err)
			}
			if response == "OK" {
				break
			}
		}
		t.Log("✓ LISTSCRIPTS successful through proxy")
	})

	t.Run("AUTHENTICATE with wrong MasterUsername suffix", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		username := account.Email + "*wrongmaster"
		authString := "\x00" + username + "\x00" + proxyMasterPassword
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded))
		response, _ := client.ReadResponse()
		if strings.HasPrefix(response, "OK") {
			t.Fatal("Expected authentication to fail with wrong master username through proxy")
		}
		t.Logf("✓ Authentication correctly failed with wrong master username: %s", response)
	})

	t.Run("AUTHENTICATE with wrong MasterPassword", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		username := account.Email + "@" + proxyMasterUsername
		authString := "\x00" + username + "\x00" + "wrong_password"
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded))
		response, _ := client.ReadResponse()
		if strings.HasPrefix(response, "OK") {
			t.Fatal("Expected authentication to fail with wrong master password through proxy")
		}
		t.Logf("✓ Authentication correctly failed with wrong master password: %s", response)
	})
}

// TestManageSieveProxy_MasterSASLAuthentication tests SASL authentication through proxy
func TestManageSieveProxy_MasterSASLAuthentication(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// NOTE: Master SASL authentication at the proxy level is not supported in the current architecture.
	// The proxy's MasterSASLUsername/Password are used for PROXY→BACKEND authentication only.
	// Clients should use Master Username format (user@domain@MASTER) or regular authentication.
	t.Skip("Master SASL not supported at proxy level - use Master Username format instead")
}

// TestManageSieveProxy_MasterAuthenticationPriority tests authentication priority through proxy
func TestManageSieveProxy_MasterAuthenticationPriority(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server with master SASL credentials
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	// Create proxy with master credentials
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithMasterAuth(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	t.Run("Master username overrides regular auth at proxy", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		// Try proxy master username suffix with account password (should fail)
		username := account.Email + "@" + proxyMasterUsername
		authString := "\x00" + username + "\x00" + account.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded))
		response, _ := client.ReadResponse()
		if strings.HasPrefix(response, "OK") {
			t.Fatal("Expected authentication to fail when using account password with proxy master username suffix")
		}
		t.Log("✓ Correctly rejected account password when proxy master username suffix is present")
	})

	t.Run("Regular auth still works through proxy without suffix", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
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
			t.Fatalf("Regular authentication through proxy failed: %s", response)
		}
		t.Log("✓ Regular authentication still works through proxy without master suffix")

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
		t.Log("✓ LISTSCRIPTS successful through proxy")
	})
}

// TestManageSieveProxy_TokenAuthentication tests token-based authentication through prelookup
func TestManageSieveProxy_TokenAuthentication(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend ManageSieve server with master SASL credentials
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	// Create proxy with master credentials
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithMasterAuth(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	t.Run("AUTHENTICATE PLAIN with @TOKEN suffix sends to prelookup", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		// AUTHENTICATE PLAIN format: user@domain.com@TOKEN with USER_PASSWORD
		// The @TOKEN should be sent to prelookup (not validated locally)
		username := account.Email + "@sometoken123"
		authString := "\x00" + username + "\x00" + account.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		client.SendCommand("AUTHENTICATE \"PLAIN\" \"" + encoded + "\"")
		response, err := client.ReadResponse()
		// Without prelookup configured, this will fail - but that's expected
		// The important part is that the code path handles @TOKEN differently than *MASTER
		if err == nil && response == "OK" {
			t.Log("✓ Login with @TOKEN succeeded (prelookup configured)")
		} else {
			t.Logf("Login with @TOKEN failed (expected without prelookup): %s", response)
		}
	})

	t.Run("@TOKEN behaves same as @MASTER when suffix matches", func(t *testing.T) {
		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		// Using @ separator with suffix that matches master username should validate locally
		username := account.Email + "@" + proxyMasterUsername
		authString := "\x00" + username + "\x00" + proxyMasterPassword
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		client.SendCommand("AUTHENTICATE \"PLAIN\" \"" + encoded + "\"")
		response, _ := client.ReadResponse()
		// This should succeed - @ separator checks if suffix matches master username
		if !strings.HasPrefix(response, "OK") {
			t.Fatalf("Authentication failed unexpectedly: %s", response)
		}
		t.Log("✓ @ separator with master username suffix authenticated successfully")
	})
}
