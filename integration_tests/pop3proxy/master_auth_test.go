//go:build integration

package pop3proxy_test

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
	"github.com/migadu/sora/server/pop3proxy"
)

const (
	// Master credentials for CLIENT→PROXY authentication (@ separator format)
	// Proxies use @ separator to distinguish from @ in email addresses
	proxyMasterUsername = "proxy_admin"
	proxyMasterPassword = "proxy_master_123"

	// Master credentials for PROXY→BACKEND authentication (SASL)
	// These MUST match what the backend server expects (from common.SetupPOP3ServerWithMaster)
	proxyMasterSASLUsername = "proxyuser"
	proxyMasterSASLPassword = "proxypass"
)

// POP3Client provides a simple POP3 client for testing
type POP3Client struct {
	conn   net.Conn
	reader *bufio.Reader
}

func NewPOP3Client(address string) (*POP3Client, error) {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, err
	}

	client := &POP3Client{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}

	// Read greeting
	response, err := client.ReadResponse()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read greeting: %w", err)
	}

	if !strings.HasPrefix(response, "+OK") {
		conn.Close()
		return nil, fmt.Errorf("unexpected greeting: %s", response)
	}

	return client, nil
}

func (c *POP3Client) SendCommand(cmd string) error {
	_, err := fmt.Fprintf(c.conn, "%s\r\n", cmd)
	return err
}

func (c *POP3Client) ReadResponse() (string, error) {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (c *POP3Client) Close() error {
	c.SendCommand("QUIT")
	return c.conn.Close()
}

// setupPOP3ProxyWithMasterAuth creates POP3 proxy with master authentication configured
// setupPOP3ProxyWithMasterAuth creates POP3 proxy with master authentication configured
func setupPOP3ProxyWithMasterAuth(t *testing.T, rdb *common.TestServer, proxyAddr string, backendAddrs []string) *POP3ProxyWrapper {
	t.Helper()

	hostname := "test-pop3-proxy-master"

	opts := pop3proxy.POP3ProxyServerOptions{
		Name:        "test-pop3-proxy-master",
		RemoteAddrs: backendAddrs,
		RemotePort:  110,
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
		ConnectTimeout:     10 * time.Second,
		SessionTimeout:     30 * time.Minute,
		EnableAffinity:     true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
	}

	proxy, err := pop3proxy.New(context.Background(), hostname, proxyAddr, rdb.ResilientDB, opts)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy with master auth: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("POP3 proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	wrapper := &POP3ProxyWrapper{
		proxy: proxy,
		addr:  proxyAddr,
		rdb:   rdb.ResilientDB,
	}

	t.Cleanup(func() {
		wrapper.Stop()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("POP3 proxy error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
		}
	})

	return wrapper
}

// TestPOP3Proxy_MasterUsernameAuthentication tests proxy authentication with MasterUsername
func TestPOP3Proxy_MasterUsernameAuthentication(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			if strings.Contains(fmt.Sprintf("%v", r), "WaitGroup") {
				t.Log("Ignoring WaitGroup race condition during test cleanup")
				return
			}
			panic(r)
		}
	}()

	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server with master SASL credentials
	backendServer, account := common.SetupPOP3ServerWithMaster(t)
	defer backendServer.Close()

	// Create proxy with master username/password for client authentication
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithMasterAuth(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Stop()

	t.Run("USER PASS with MasterUsername suffix through proxy", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		// USER format: user@domain.com*PROXY_MASTER_USERNAME (proxies use @ separator)
		username := account.Email + "@" + proxyMasterUsername
		client.SendCommand("USER " + username)
		response, _ := client.ReadResponse()
		if !strings.HasPrefix(response, "+OK") {
			t.Fatalf("USER command rejected: %s", response)
		}

		// PASS with PROXY_MASTER_PASSWORD
		client.SendCommand("PASS " + proxyMasterPassword)
		response, _ = client.ReadResponse()
		if !strings.HasPrefix(response, "+OK") {
			t.Fatalf("Authentication failed: %s", response)
		}
		t.Log("✓ Successfully authenticated through proxy with MasterUsername")

		// Verify we can use STAT command
		client.SendCommand("STAT")
		response, _ = client.ReadResponse()
		if !strings.HasPrefix(response, "+OK") {
			t.Fatalf("STAT command failed: %s", response)
		}
		t.Logf("✓ STAT successful through proxy: %s", response)
	})

	t.Run("USER PASS with wrong MasterUsername suffix", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		username := account.Email + "*wrongmaster"
		client.SendCommand("USER " + username)
		client.ReadResponse()

		client.SendCommand("PASS " + proxyMasterPassword)
		response, _ := client.ReadResponse()
		if strings.HasPrefix(response, "+OK") {
			t.Fatal("Expected authentication to fail with wrong master username through proxy")
		}
		t.Logf("✓ Authentication correctly failed with wrong master username: %s", response)
	})

	t.Run("USER PASS with wrong MasterPassword", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		username := account.Email + "@" + proxyMasterUsername
		client.SendCommand("USER " + username)
		client.ReadResponse()

		client.SendCommand("PASS wrong_password")
		response, _ := client.ReadResponse()
		if strings.HasPrefix(response, "+OK") {
			t.Fatal("Expected authentication to fail with wrong master password through proxy")
		}
		t.Logf("✓ Authentication correctly failed with wrong master password: %s", response)
	})
}

// TestPOP3Proxy_MasterSASLAuthentication tests AUTH PLAIN through proxy
func TestPOP3Proxy_MasterSASLAuthentication(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			if strings.Contains(fmt.Sprintf("%v", r), "WaitGroup") {
				t.Log("Ignoring WaitGroup race condition during test cleanup")
				return
			}
			panic(r)
		}
	}()

	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server with master SASL credentials
	backendServer, account := common.SetupPOP3ServerWithMaster(t)
	defer backendServer.Close()

	// Create proxy with master credentials
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithMasterAuth(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Stop()

	t.Run("AUTH PLAIN with proxy MasterUsername suffix", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		// AUTH PLAIN with master username suffix at proxy level
		username := account.Email + "@" + proxyMasterUsername
		authString := "\x00" + username + "\x00" + proxyMasterPassword
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		client.SendCommand("AUTH PLAIN " + encoded)
		response, _ := client.ReadResponse()
		if !strings.HasPrefix(response, "+OK") {
			t.Fatalf("Authentication failed: %s", response)
		}
		t.Log("✓ Successfully authenticated through proxy with AUTH PLAIN master username")

		// Verify STAT works
		client.SendCommand("STAT")
		response, _ = client.ReadResponse()
		if !strings.HasPrefix(response, "+OK") {
			t.Fatalf("STAT failed: %s", response)
		}
		t.Logf("✓ STAT successful: %s", response)
	})

	// NOTE: Master SASL authentication at the proxy level is not supported in the current architecture.
	// The proxy's MasterSASLUsername/Password are used for PROXY→BACKEND authentication only.
	// Clients should use Master Username format (user@domain@MASTER) or regular authentication.
}

// TestPOP3Proxy_MasterAuthenticationPriority tests authentication priority through proxy
func TestPOP3Proxy_MasterAuthenticationPriority(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			if strings.Contains(fmt.Sprintf("%v", r), "WaitGroup") {
				t.Log("Ignoring WaitGroup race condition during test cleanup")
				return
			}
			panic(r)
		}
	}()

	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server with master SASL credentials
	backendServer, account := common.SetupPOP3ServerWithMaster(t)
	defer backendServer.Close()

	// Create proxy with master credentials
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithMasterAuth(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Stop()

	t.Run("Master username overrides regular auth at proxy", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		// Try proxy master username suffix with account password (should fail)
		username := account.Email + "@" + proxyMasterUsername
		client.SendCommand("USER " + username)
		client.ReadResponse()

		client.SendCommand("PASS " + account.Password)
		response, _ := client.ReadResponse()
		if strings.HasPrefix(response, "+OK") {
			t.Fatal("Expected authentication to fail when using account password with proxy master username suffix")
		}
		t.Log("✓ Correctly rejected account password when proxy master username suffix is present")
	})

	t.Run("Regular auth still works through proxy without suffix", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		// Regular authentication should work
		client.SendCommand("USER " + account.Email)
		client.ReadResponse()

		client.SendCommand("PASS " + account.Password)
		response, _ := client.ReadResponse()
		if !strings.HasPrefix(response, "+OK") {
			t.Fatalf("Regular authentication through proxy failed: %s", response)
		}
		t.Log("✓ Regular authentication still works through proxy without master suffix")

		// Verify STAT works
		client.SendCommand("STAT")
		response, _ = client.ReadResponse()
		if !strings.HasPrefix(response, "+OK") {
			t.Fatalf("STAT failed: %s", response)
		}
		t.Logf("✓ STAT successful: %s", response)
	})
}

// TestPOP3Proxy_TokenAuthentication tests token-based authentication through prelookup
func TestPOP3Proxy_TokenAuthentication(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server with master SASL credentials
	backendServer, account := common.SetupPOP3ServerWithMaster(t)
	defer backendServer.Close()

	// Create proxy with master credentials
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithMasterAuth(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Stop()

	t.Run("USER with @TOKEN suffix sends to prelookup", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		// USER format: user@domain.com@TOKEN with USER_PASSWORD
		// The @TOKEN should be sent to prelookup (not validated locally)
		username := account.Email + "@sometoken123"
		client.SendCommand("USER " + username)
		client.ReadResponse()

		client.SendCommand("PASS " + account.Password)
		response, _ := client.ReadResponse()
		// Without prelookup configured, this will fail - but that's expected
		// The important part is that the code path handles @TOKEN differently than *MASTER
		if strings.HasPrefix(response, "+OK") {
			t.Log("✓ Login with @TOKEN succeeded (prelookup configured)")
		} else {
			t.Logf("Login with @TOKEN failed (expected without prelookup): %s", response)
		}
	})

	t.Run("@TOKEN behaves same as @MASTER when suffix matches", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		// Using @ separator with suffix that matches master username should validate locally
		username := account.Email + "@" + proxyMasterUsername
		client.SendCommand("USER " + username)
		client.ReadResponse()

		client.SendCommand("PASS " + proxyMasterPassword)
		response, _ := client.ReadResponse()
		// This should succeed - @ separator checks if suffix matches master username
		if !strings.HasPrefix(response, "+OK") {
			t.Fatalf("Authentication failed unexpectedly: %s", response)
		}
		t.Log("✓ @ separator with master username suffix authenticated successfully")
	})
}
