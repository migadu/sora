package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"
)

// TestJA4TLSWithRealCertificates tests JA4 capture with real TLS handshake using test certificates
func TestJA4TLSWithRealCertificates(t *testing.T) {
	// Load test certificates
	cert, err := tls.LoadX509KeyPair("../testdata/sora.crt", "../testdata/sora.key")
	if err != nil {
		t.Skipf("Skipping test: test certificates not available: %v", err)
	}

	// Create TLS config for server
	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Create a listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	t.Logf("Test server listening on %s", addr)

	// Channel to communicate JA4 fingerprint from server to test
	ja4Channel := make(chan string, 1)

	// Wrap listener with SoraTLSListener for JA4 capture
	connConfig := SoraConnConfig{
		Protocol:             "test",
		EnableTimeoutChecker: false,
	}
	ja4Listener := NewSoraTLSListener(listener, serverTLSConfig, connConfig)

	// Start server
	go func() {
		conn, err := ja4Listener.Accept()
		if err != nil {
			t.Logf("Accept failed: %v", err)
			return
		}
		defer conn.Close()

		// Perform explicit TLS handshake (deferred from Accept)
		if tlsConn, ok := conn.(interface{ PerformHandshake() error }); ok {
			if err := tlsConn.PerformHandshake(); err != nil {
				t.Logf("TLS handshake failed: %v", err)
				return
			}
		}

		// Keep connection open briefly and read data
		buf := make([]byte, 100)
		conn.Read(buf)

		// Give a small delay for GetConfigForClient callback to complete storing JA4
		time.Sleep(50 * time.Millisecond)

		// Extract JA4 fingerprint
		if ja4Conn, ok := conn.(interface{ GetJA4Fingerprint() (string, error) }); ok {
			fingerprint, err := ja4Conn.GetJA4Fingerprint()
			if err != nil {
				t.Logf("Failed to get JA4 fingerprint: %v", err)
				return
			}

			if fingerprint != "" {
				t.Logf("Server captured JA4 fingerprint: %s", fingerprint)
				ja4Channel <- fingerprint
			} else {
				t.Log("Warning: JA4 fingerprint is empty after handshake")
				ja4Channel <- ""
			}
		} else {
			t.Log("Warning: Connection does not support JA4 fingerprint extraction")
			ja4Channel <- ""
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect as client with TLS
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true, // Test certificates
		MinVersion:         tls.VersionTLS12,
	}

	clientConn, err := tls.Dial("tcp", addr, clientTLSConfig)
	if err != nil {
		t.Fatalf("Client TLS dial failed: %v", err)
	}
	defer clientConn.Close()

	// Send some data to ensure handshake completes
	clientConn.Write([]byte("HELLO\r\n"))

	// Wait for JA4 fingerprint capture
	select {
	case ja4 := <-ja4Channel:
		if ja4 == "" {
			t.Error("JA4 fingerprint is empty")
		} else {
			t.Logf("✓ JA4 fingerprint captured from real TLS handshake: %s", ja4)
			// Verify it looks like a JA4 fingerprint (format: partA_partB_partC)
			if len(ja4) < 20 {
				t.Errorf("JA4 fingerprint seems too short: %s", ja4)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for JA4 fingerprint")
	}
}

// TestJA4ProxyV2WithRealTLS tests the complete flow with real TLS handshake
func TestJA4ProxyV2WithRealTLS(t *testing.T) {
	// Load test certificates
	cert, err := tls.LoadX509KeyPair("../testdata/sora.crt", "../testdata/sora.key")
	if err != nil {
		t.Skipf("Skipping test: test certificates not available: %v", err)
	}

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Create listener and wrap with JA4 capture
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	connConfig := SoraConnConfig{
		Protocol:             "test",
		EnableTimeoutChecker: false,
	}
	ja4Listener := NewSoraTLSListener(listener, serverTLSConfig, connConfig)

	// Channels for results
	ja4Chan := make(chan string, 1)
	proxyInfoChan := make(chan *ProxyProtocolInfo, 1)

	// Start server that captures JA4 and simulates forwarding via PROXY v2
	go func() {
		conn, err := ja4Listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Perform explicit TLS handshake
		if tlsConn, ok := conn.(interface{ PerformHandshake() error }); ok {
			if err := tlsConn.PerformHandshake(); err != nil {
				t.Logf("Handshake failed: %v", err)
				return
			}
		}

		// Read data
		buf := make([]byte, 100)
		conn.Read(buf)

		// Give time for GetConfigForClient to store JA4
		time.Sleep(50 * time.Millisecond)

		// Extract JA4
		var ja4 string
		if ja4Conn, ok := conn.(interface{ GetJA4Fingerprint() (string, error) }); ok {
			ja4, _ = ja4Conn.GetJA4Fingerprint()
			ja4Chan <- ja4
			t.Logf("Captured JA4: %s", ja4)
		}

		// Simulate PROXY v2 forwarding
		var tlvs map[byte][]byte
		if ja4 != "" {
			tlvs = map[byte][]byte{
				TLVTypeJA4Fingerprint: []byte(ja4),
			}
		}

		// Generate PROXY v2 header
		header, err := GenerateProxyV2HeaderWithTLVs(
			"192.168.1.100", 54321,
			"10.0.0.1", 143,
			"TCP", tlvs,
		)
		if err != nil {
			t.Logf("Failed to generate PROXY v2: %v", err)
			return
		}

		// Parse it (simulating backend receiving it)
		reader := bufio.NewReader(bytes.NewReader(header))
		config := ProxyProtocolConfig{
			Enabled:        true,
			TrustedProxies: []string{"0.0.0.0/0"},
		}
		proxyReader, _ := NewProxyProtocolReader("test", config)
		info, err := proxyReader.parseProxyV2(reader)
		if err != nil {
			t.Logf("Failed to parse PROXY v2: %v", err)
			return
		}

		proxyInfoChan <- info

		// Connection stays alive until deferred Close()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect as client
	clientConn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("Client dial failed: %v", err)
	}
	defer clientConn.Close()

	clientConn.Write([]byte("TEST\r\n"))

	// Wait for JA4 capture
	var capturedJA4 string
	select {
	case capturedJA4 = <-ja4Chan:
		if capturedJA4 == "" {
			t.Error("JA4 fingerprint is empty")
		} else {
			t.Logf("✓ JA4 captured from TLS: %s", capturedJA4)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for JA4")
	}

	// Wait for PROXY v2 parsing
	select {
	case proxyInfo := <-proxyInfoChan:
		if proxyInfo.JA4Fingerprint != capturedJA4 {
			t.Errorf("JA4 mismatch: captured=%s, proxy=%s", capturedJA4, proxyInfo.JA4Fingerprint)
		} else {
			t.Logf("✓ JA4 successfully transmitted via PROXY v2 TLV: %s", proxyInfo.JA4Fingerprint)
		}

		// Verify TLV
		if ja4Bytes, ok := proxyInfo.TLVs[TLVTypeJA4Fingerprint]; !ok {
			t.Error("JA4 TLV not found in PROXY v2")
		} else {
			t.Logf("✓ JA4 TLV present: %s", string(ja4Bytes))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for PROXY v2 info")
	}
}

// TestJA4ConsistencyAcrossConnections verifies JA4 is consistent for same client
func TestJA4ConsistencyAcrossConnections(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("../testdata/sora.crt", "../testdata/sora.key")
	if err != nil {
		t.Skipf("Skipping test: test certificates not available: %v", err)
	}

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	numConnections := 3
	ja4Fingerprints := make([]string, numConnections)

	for i := 0; i < numConnections; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to create listener: %v", err)
		}

		addr := listener.Addr().String()
		connConfig := SoraConnConfig{
			Protocol:             "test",
			EnableTimeoutChecker: false,
		}
		ja4Listener := NewSoraTLSListener(listener, serverTLSConfig, connConfig)

		ja4Chan := make(chan string, 1)

		// Server
		go func(l net.Listener) {
			defer l.Close()
			conn, err := ja4Listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// Perform explicit TLS handshake
			if tlsConn, ok := conn.(interface{ PerformHandshake() error }); ok {
				tlsConn.PerformHandshake()
			}

			// Read data first
			buf := make([]byte, 100)
			conn.Read(buf)

			// Give time for JA4 capture
			time.Sleep(50 * time.Millisecond)

			if ja4Conn, ok := conn.(interface{ GetJA4Fingerprint() (string, error) }); ok {
				ja4, _ := ja4Conn.GetJA4Fingerprint()
				ja4Chan <- ja4
			}
		}(listener)

		time.Sleep(50 * time.Millisecond)

		// Client
		clientConn, err := tls.Dial("tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		})
		if err != nil {
			t.Fatalf("Connection %d failed: %v", i, err)
		}

		clientConn.Write([]byte(fmt.Sprintf("TEST%d\r\n", i)))

		select {
		case ja4 := <-ja4Chan:
			ja4Fingerprints[i] = ja4
			t.Logf("Connection %d JA4: %s", i, ja4)
		case <-time.After(2 * time.Second):
			t.Errorf("Connection %d timeout", i)
		}

		clientConn.Close()
		time.Sleep(50 * time.Millisecond)
	}

	// Verify consistency
	if ja4Fingerprints[0] == "" {
		t.Error("First JA4 is empty")
		return
	}

	allSame := true
	for i := 1; i < numConnections; i++ {
		if ja4Fingerprints[i] != ja4Fingerprints[0] {
			allSame = false
			t.Errorf("JA4 mismatch: conn0=%s, conn%d=%s",
				ja4Fingerprints[0], i, ja4Fingerprints[i])
		}
	}

	if allSame {
		t.Logf("✓ All %d connections have consistent JA4: %s", numConnections, ja4Fingerprints[0])
	}
}
