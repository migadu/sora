//go:build integration

package lmtpproxy_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtpproxy"
)

// TestLMTPProxy_UserNotFoundResponse_Reject tests the default "reject" behavior
// When user is not found in remote_lookup and lookup_local_users=false,
// the proxy should return 550 (permanent failure)
func TestLMTPProxy_UserNotFoundResponse_Reject(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup mock remote lookup that returns 404 for all users
	lookupAddr := common.GetRandomAddress(t)
	lookupListener, err := net.Listen("tcp", lookupAddr)
	if err != nil {
		t.Fatalf("Failed to listen lookup: %v", err)
	}
	defer lookupListener.Close()

	go func() {
		for {
			conn, err := lookupListener.Accept()
			if err != nil {
				return
			}
			go handleUserNotFoundLookup(conn, "404")
		}
	}()

	lookupURL := fmt.Sprintf("http://%s/lookup?email=$email", lookupAddr)

	// Setup proxy with default (reject) behavior
	rdb := common.SetupTestDatabase(t)
	proxyAddr := common.GetRandomAddress(t)

	server, err := lmtpproxy.New(
		context.Background(),
		rdb,
		"localhost",
		lmtpproxy.ServerOptions{
			Name:           "test-proxy-reject",
			Addr:           proxyAddr,
			RemoteAddrs:    []string{"backend.example.com:25"},
			TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
			RemoteLookup: &config.RemoteLookupConfig{
				Enabled:              true,
				URL:                  lookupURL,
				Timeout:              "5s",
				LookupLocalUsers:     false,
				UserNotFoundResponse: "reject", // Explicit reject (default)
			},
			AuthIdleTimeout: 5 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	go func() {
		server.Start()
	}()
	time.Sleep(100 * time.Millisecond)
	defer server.Stop()

	// Test client
	client, err := NewLMTPClient(proxyAddr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer client.Close()

	// LHLO
	client.SendCommand("LHLO localhost")
	client.ReadMultilineResponse()

	// MAIL FROM
	client.SendCommand("MAIL FROM:<sender@example.com>")
	resp, _ := client.ReadResponse()
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("MAIL FROM failed: %s", resp)
	}

	// RCPT TO - should get 550 (permanent failure)
	client.SendCommand("RCPT TO:<unknown@example.com>")
	resp, _ = client.ReadResponse()

	if !strings.HasPrefix(resp, "550") {
		t.Errorf("Expected 550 (reject) for unknown user, got: %s", resp)
	}
	if !strings.Contains(resp, "User unknown") {
		t.Errorf("Expected 'User unknown' in response, got: %s", resp)
	}
}

// TestLMTPProxy_UserNotFoundResponse_TempFail tests the "tempfail" behavior
// When user is not found, proxy should return 450 (temporary failure)
func TestLMTPProxy_UserNotFoundResponse_TempFail(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup mock remote lookup that returns 404 for all users
	lookupAddr := common.GetRandomAddress(t)
	lookupListener, err := net.Listen("tcp", lookupAddr)
	if err != nil {
		t.Fatalf("Failed to listen lookup: %v", err)
	}
	defer lookupListener.Close()

	go func() {
		for {
			conn, err := lookupListener.Accept()
			if err != nil {
				return
			}
			go handleUserNotFoundLookup(conn, "404")
		}
	}()

	lookupURL := fmt.Sprintf("http://%s/lookup?email=$email", lookupAddr)

	// Setup proxy with tempfail behavior
	rdb := common.SetupTestDatabase(t)
	proxyAddr := common.GetRandomAddress(t)

	server, err := lmtpproxy.New(
		context.Background(),
		rdb,
		"localhost",
		lmtpproxy.ServerOptions{
			Name:           "test-proxy-tempfail",
			Addr:           proxyAddr,
			RemoteAddrs:    []string{"backend.example.com:25"},
			TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
			RemoteLookup: &config.RemoteLookupConfig{
				Enabled:              true,
				URL:                  lookupURL,
				Timeout:              "5s",
				LookupLocalUsers:     false,
				UserNotFoundResponse: "tempfail", // Temporary failure
			},
			AuthIdleTimeout: 5 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	go func() {
		server.Start()
	}()
	time.Sleep(100 * time.Millisecond)
	defer server.Stop()

	// Test client
	client, err := NewLMTPClient(proxyAddr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer client.Close()

	// LHLO
	client.SendCommand("LHLO localhost")
	client.ReadMultilineResponse()

	// MAIL FROM
	client.SendCommand("MAIL FROM:<sender@example.com>")
	resp, _ := client.ReadResponse()
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("MAIL FROM failed: %s", resp)
	}

	// RCPT TO - should get 450 (temporary failure)
	client.SendCommand("RCPT TO:<unknown@example.com>")
	resp, _ = client.ReadResponse()

	if !strings.HasPrefix(resp, "450") {
		t.Errorf("Expected 450 (tempfail) for unknown user, got: %s", resp)
	}
	if !strings.Contains(resp, "User unknown") && !strings.Contains(resp, "temporary") {
		t.Errorf("Expected 'User unknown' or 'temporary' in response, got: %s", resp)
	}
}

// TestLMTPProxy_UserNotFoundResponse_Default tests that omitting the setting
// defaults to "reject" behavior
func TestLMTPProxy_UserNotFoundResponse_Default(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup mock remote lookup that returns 404 for all users
	lookupAddr := common.GetRandomAddress(t)
	lookupListener, err := net.Listen("tcp", lookupAddr)
	if err != nil {
		t.Fatalf("Failed to listen lookup: %v", err)
	}
	defer lookupListener.Close()

	go func() {
		for {
			conn, err := lookupListener.Accept()
			if err != nil {
				return
			}
			go handleUserNotFoundLookup(conn, "404")
		}
	}()

	lookupURL := fmt.Sprintf("http://%s/lookup?email=$email", lookupAddr)

	// Setup proxy WITHOUT UserNotFoundResponse setting (should default to "reject")
	rdb := common.SetupTestDatabase(t)
	proxyAddr := common.GetRandomAddress(t)

	server, err := lmtpproxy.New(
		context.Background(),
		rdb,
		"localhost",
		lmtpproxy.ServerOptions{
			Name:           "test-proxy-default",
			Addr:           proxyAddr,
			RemoteAddrs:    []string{"backend.example.com:25"},
			TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
			RemoteLookup: &config.RemoteLookupConfig{
				Enabled:          true,
				URL:              lookupURL,
				Timeout:          "5s",
				LookupLocalUsers: false,
				// UserNotFoundResponse not set - should default to "reject"
			},
			AuthIdleTimeout: 5 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	go func() {
		server.Start()
	}()
	time.Sleep(100 * time.Millisecond)
	defer server.Stop()

	// Test client
	client, err := NewLMTPClient(proxyAddr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer client.Close()

	// LHLO
	client.SendCommand("LHLO localhost")
	client.ReadMultilineResponse()

	// MAIL FROM
	client.SendCommand("MAIL FROM:<sender@example.com>")
	resp, _ := client.ReadResponse()
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("MAIL FROM failed: %s", resp)
	}

	// RCPT TO - should get 550 (default reject)
	client.SendCommand("RCPT TO:<unknown@example.com>")
	resp, _ = client.ReadResponse()

	if !strings.HasPrefix(resp, "550") {
		t.Errorf("Expected 550 (default reject) for unknown user, got: %s", resp)
	}
}

// handleUserNotFoundLookup is a mock HTTP handler that always returns user not found
func handleUserNotFoundLookup(conn net.Conn, statusCode string) {
	defer conn.Close()
	rd := bufio.NewReader(conn)
	wr := bufio.NewWriter(conn)

	// Read HTTP request
	_, _ = rd.ReadString('\n')

	// Return 404 Not Found
	wr.WriteString("HTTP/1.1 404 Not Found\r\n")
	wr.WriteString("Content-Type: application/json\r\n\r\n")
	wr.WriteString("{}\r\n")
	wr.Flush()
}
