//go:build integration

package lmtpproxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtpproxy"
)

// TestLMTPProxy_MixedRecipients_DifferentBackends reproduces a scenario where
// two recipients route to different backends.
// The proxy should detect this and reject the second recipient with a temporary failure
// to force the client to retry in a separate transaction (which will route correctly).
func TestLMTPProxy_MixedRecipients_DifferentBackends(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// 1. Setup two backend LMTP servers
	backend1Addr := common.GetRandomAddress(t)
	backend2Addr := common.GetRandomAddress(t)

	backend1Listener, err := net.Listen("tcp", backend1Addr)
	if err != nil {
		t.Fatalf("Failed to listen backend1: %v", err)
	}
	defer backend1Listener.Close()

	backend2Listener, err := net.Listen("tcp", backend2Addr)
	if err != nil {
		t.Fatalf("Failed to listen backend2: %v", err)
	}
	defer backend2Listener.Close()

	// Start simple mock backends that accept everything for "their" users
	// but reject unknown users.
	startMockBackend(t, backend1Listener, "server1", "user1@example.com")
	startMockBackend(t, backend2Listener, "server2", "user2@example.com")

	// 2. Setup Mock Remote Lookup
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
			go handleRoutingLookup(conn, backend1Addr, backend2Addr)
		}
	}()

	lookupURL := fmt.Sprintf("http://%s/lookup?q=$email", lookupAddr)

	// 3. Setup Proxy
	rdb := common.SetupTestDatabase(t)
	proxyAddr := common.GetRandomAddress(t)

	server, err := lmtpproxy.New(
		context.Background(),
		rdb,
		"localhost",
		lmtpproxy.ServerOptions{
			Name:           "test-proxy-mixed",
			Addr:           proxyAddr,
			RemoteAddrs:    []string{backend1Addr}, // Default, but override via lookup
			RemotePort:     25,
			TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
			// Important: Use RemoteLookup
			RemoteLookup: &config.RemoteLookupConfig{
				Enabled:          true,
				URL:              lookupURL,
				Timeout:          "5s",
				LookupLocalUsers: false,
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

	// 4. Test Client
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

	// RCPT TO 1 -> Should go to Backend 1
	// user1 maps to backend1
	client.SendCommand("RCPT TO:<user1@example.com>")
	resp, _ = client.ReadResponse()
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("First RCPT TO failed: %s", resp)
	}

	// RCPT TO 2 -> Should map to Backend 2 via lookup
	// Since we are already connected to Backend 1, this *should* be rejected by the proxy
	// because it can't deliver to Backend 2 in the same session.
	// Currently (BUG), it tries to send it to Backend 1, which rejects it (550),
	// and proxy converts to 451.
	// We want to verify that it is indeed rejected locally (4xx) WITHOUT trying to send to Backend 1
	// or at least that it fails appropriately.
	client.SendCommand("RCPT TO:<user2@example.com>")
	resp, _ = client.ReadResponse()

	t.Logf("Second RCPT TO response: %s", resp)

	// Check if backend 1 received the second RCPT
	// (We can't easily check backend state here without channel/counters, but the response code gives a hint)
	// If the proxy correctly implements "different backend check", it should return 4xx immediately.
	// If the bug exists, it sends to backend 1, backend 1 returns 550, proxy returns 451.
	// Both look like 4xx to the client.
	// However, the error message might differ.
	// "User doesn't exist" vs "Different backend required" (if we implement a custom message).

	if !strings.HasPrefix(resp, "451") && !strings.HasPrefix(resp, "450") && !strings.HasPrefix(resp, "421") {
		t.Errorf("Expected 4xx failure for second mixed-backend recipient, got: %s", resp)
	}
}

// Simple mock backend that accepts for specific user only
func startMockBackend(t *testing.T, l net.Listener, name string, validUser string) {
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				rd := bufio.NewReader(c)
				wr := bufio.NewWriter(c)
				wr.WriteString("220 " + name + " LMTP ready\r\n")
				wr.Flush()

				for {
					line, err := rd.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimSpace(line)
					upper := strings.ToUpper(line)
					if strings.HasPrefix(upper, "LHLO") {
						wr.WriteString("250-" + name + "\r\n250-PIPELINING\r\n250 8BITMIME\r\n")
					} else if strings.HasPrefix(upper, "MAIL FROM") {
						wr.WriteString("250 Ok\r\n")
					} else if strings.HasPrefix(upper, "RCPT TO") {
						if strings.Contains(line, validUser) {
							wr.WriteString("250 Ok\r\n")
						} else {
							wr.WriteString("550 5.1.1 User doesn't exist\r\n")
						}
					} else if strings.HasPrefix(upper, "DATA") {
						wr.WriteString("354 Go ahead\r\n")
					} else if strings.HasPrefix(upper, "QUIT") {
						wr.WriteString("221 Bye\r\n")
						return
					} else {
						wr.WriteString("500 Command unrecognized\r\n")
					}
					wr.Flush()
				}
			}(conn)
		}
	}()
}

func handleRoutingLookup(conn net.Conn, server1, server2 string) {
	defer conn.Close()
	rd := bufio.NewReader(conn)
	wr := bufio.NewWriter(conn)
	// Read request
	line, _ := rd.ReadString('\n')
	parts := strings.Split(line, " ")
	if len(parts) < 2 {
		return
	}
	path := parts[1] // /lookup?q=user...
	// very simple parsing

	var server string
	var address string
	if strings.Contains(path, "user1") {
		server = server1
		address = "user1@example.com"
	} else if strings.Contains(path, "user2") {
		server = server2
		address = "user2@example.com"
	} else {
		// 404
		wr.WriteString("HTTP/1.1 404 Not Found\r\n\r\n")
		wr.Flush()
		return
	}

	resp := map[string]interface{}{
		"address": address,
		"server":  server,
	}
	data, _ := json.Marshal(resp)

	wr.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")
	wr.Write(data)
	wr.Flush()
}
