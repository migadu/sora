package server

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// TestSoraConnBasicFunctionality tests basic read/write and metadata operations
func TestSoraConnBasicFunctionality(t *testing.T) {
	// Create a pair of connected pipes
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Wrap server side with SoraConn
	config := SoraConnConfig{
		Protocol:             "test",
		IdleTimeout:          5 * time.Second,
		AbsoluteTimeout:      10 * time.Second,
		MinBytesPerMinute:    0,     // Disable for this test
		EnableTimeoutChecker: false, // Disable for controlled testing
	}
	soraConn := NewSoraConn(serverConn, config)
	defer soraConn.Close()

	// Test metadata
	if soraConn.GetProtocol() != "test" {
		t.Errorf("Expected protocol 'test', got %s", soraConn.GetProtocol())
	}

	soraConn.SetUsername("testuser@example.com")
	if soraConn.GetUsername() != "testuser@example.com" {
		t.Errorf("Expected username 'testuser@example.com', got %s", soraConn.GetUsername())
	}

	// Test Read/Write with proper synchronization for net.Pipe
	readDone := make(chan bool)
	writeDone := make(chan bool)

	// Client writes, then reads
	go func() {
		defer close(writeDone)
		// Write to server
		_, err := clientConn.Write([]byte("hello"))
		if err != nil {
			t.Errorf("Client write failed: %v", err)
			return
		}
		// Wait for server to read
		<-readDone
		// Read from server
		buf2 := make([]byte, 100)
		n2, err := clientConn.Read(buf2)
		if err != nil {
			t.Errorf("Client read failed: %v", err)
			return
		}
		if string(buf2[:n2]) != "world" {
			t.Errorf("Expected 'world', got %s", string(buf2[:n2]))
		}
	}()

	// Server reads
	buf := make([]byte, 100)
	n, err := soraConn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("Expected 'hello', got %s", string(buf[:n]))
	}
	close(readDone)

	// Server writes
	n, err = soraConn.Write([]byte("world"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != 5 {
		t.Errorf("Expected to write 5 bytes, wrote %d", n)
	}

	// Wait for client to finish
	<-writeDone

	t.Log("✓ Basic read/write and metadata operations work correctly")
}

// TestSoraConnJA4Fingerprint tests JA4 fingerprint storage and retrieval
func TestSoraConnJA4Fingerprint(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	config := SoraConnConfig{
		Protocol:             "imap",
		InitialJA4:           "t13d411100_6be44479b708_d41ae481755e",
		EnableTimeoutChecker: false,
	}
	soraConn := NewSoraConn(serverConn, config)
	defer soraConn.Close()

	// Test initial JA4
	ja4, err := soraConn.GetJA4Fingerprint()
	if err != nil {
		t.Fatalf("GetJA4Fingerprint failed: %v", err)
	}
	if ja4 != "t13d411100_6be44479b708_d41ae481755e" {
		t.Errorf("Expected initial JA4, got %s", ja4)
	}

	// Test updating JA4
	soraConn.SetJA4Fingerprint("t13d2014ip_a09f3c656075_e42f34c56612")
	ja4, err = soraConn.GetJA4Fingerprint()
	if err != nil {
		t.Fatalf("GetJA4Fingerprint failed after update: %v", err)
	}
	if ja4 != "t13d2014ip_a09f3c656075_e42f34c56612" {
		t.Errorf("Expected updated JA4, got %s", ja4)
	}

	t.Log("✓ JA4 fingerprint storage and retrieval work correctly")
}

// TestSoraConnProxyInfo tests PROXY protocol info storage and retrieval
func TestSoraConnProxyInfo(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	proxyInfo := &ProxyProtocolInfo{
		SrcIP:          "192.168.1.100",
		SrcPort:        12345,
		DstIP:          "10.0.0.1",
		DstPort:        8080,
		JA4Fingerprint: "t13d411100_test",
	}

	config := SoraConnConfig{
		Protocol:             "imap",
		InitialProxyInfo:     proxyInfo,
		EnableTimeoutChecker: false,
	}
	soraConn := NewSoraConn(serverConn, config)
	defer soraConn.Close()

	// Test initial proxy info
	info := soraConn.GetProxyInfo()
	if info == nil {
		t.Fatal("Expected proxy info, got nil")
	}
	if info.SrcIP != "192.168.1.100" {
		t.Errorf("Expected source IP 192.168.1.100, got %s", info.SrcIP)
	}
	if info.DstIP != "10.0.0.1" {
		t.Errorf("Expected dest IP 10.0.0.1, got %s", info.DstIP)
	}

	// Test updating proxy info
	newProxyInfo := &ProxyProtocolInfo{
		SrcIP:   "10.20.30.40",
		SrcPort: 54321,
	}
	soraConn.SetProxyInfo(newProxyInfo)

	info = soraConn.GetProxyInfo()
	if info.SrcIP != "10.20.30.40" {
		t.Errorf("Expected updated source IP 10.20.30.40, got %s", info.SrcIP)
	}

	t.Log("✓ PROXY protocol info storage and retrieval work correctly")
}

// TestSoraConnUnwrap tests the Unwrap method for compatibility
func TestSoraConnUnwrap(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	config := SoraConnConfig{
		Protocol:             "test",
		EnableTimeoutChecker: false,
	}
	soraConn := NewSoraConn(serverConn, config)
	defer soraConn.Close()

	// Test unwrapping
	unwrapped := soraConn.Unwrap()
	if unwrapped != serverConn {
		t.Error("Unwrap did not return the underlying connection")
	}

	t.Log("✓ Unwrap method works correctly")
}

// TestSoraConnActivityTracking tests that read/write updates activity timestamps
func TestSoraConnActivityTracking(t *testing.T) {
	// Create a TCP listener for real connection
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Accept in background
	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Logf("Accept error: %v", err)
			close(acceptDone)
			return
		}
		acceptDone <- conn
	}()

	// Connect client
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	// Get server connection
	serverConn := <-acceptDone
	if serverConn == nil {
		t.Fatal("Server failed to accept connection")
	}

	config := SoraConnConfig{
		Protocol:             "test",
		IdleTimeout:          100 * time.Millisecond,
		EnableTimeoutChecker: false, // Manual testing
	}
	soraConn := NewSoraConn(serverConn, config)
	defer soraConn.Close()

	// Record initial activity time
	soraConn.mu.RLock()
	initialActivity := soraConn.lastActivity
	soraConn.mu.RUnlock()

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Perform a write and read to ensure activity is tracked
	go func() {
		soraConn.Write([]byte("test"))
	}()

	buf := make([]byte, 100)
	_, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("Client read failed: %v", err)
	}

	// Check that activity was updated
	soraConn.mu.RLock()
	newActivity := soraConn.lastActivity
	soraConn.mu.RUnlock()

	if !newActivity.After(initialActivity) {
		t.Error("Activity timestamp was not updated after write")
	}

	t.Log("✓ Activity tracking works correctly")
}

// TestSoraConnIdleTimeout tests idle timeout enforcement
func TestSoraConnIdleTimeout(t *testing.T) {
	// Create a TCP listener for real connection
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Accept in background
	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Logf("Accept error: %v", err)
			close(acceptDone)
			return
		}
		acceptDone <- conn
	}()

	// Connect client
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	// Get server connection
	serverConn := <-acceptDone
	if serverConn == nil {
		t.Fatal("Server failed to accept connection")
	}

	config := SoraConnConfig{
		Protocol:             "test",
		IdleTimeout:          200 * time.Millisecond,
		AbsoluteTimeout:      0, // Disable
		MinBytesPerMinute:    0, // Disable
		EnableTimeoutChecker: true,
	}
	soraConn := NewSoraConn(serverConn, config)
	defer soraConn.Close()

	// Don't perform any I/O - connection should timeout

	// Wait for timeout to trigger (timeout + grace period)
	time.Sleep(400 * time.Millisecond)

	// Try to read - should fail because connection was closed
	buf := make([]byte, 100)
	_, err = soraConn.Read(buf)
	if err == nil {
		t.Error("Expected error after idle timeout, got nil")
	}

	t.Log("✓ Idle timeout enforcement works correctly")
}

// TestSoraConnAbsoluteTimeout tests absolute session timeout
func TestSoraConnAbsoluteTimeout(t *testing.T) {
	// Create a TCP listener for real connection
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Accept in background
	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Logf("Accept error: %v", err)
			close(acceptDone)
			return
		}
		acceptDone <- conn
	}()

	// Connect client
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	// Get server connection
	serverConn := <-acceptDone
	if serverConn == nil {
		t.Fatal("Server failed to accept connection")
	}

	config := SoraConnConfig{
		Protocol:             "test",
		IdleTimeout:          0, // Disable
		AbsoluteTimeout:      200 * time.Millisecond,
		MinBytesPerMinute:    0, // Disable
		EnableTimeoutChecker: true,
	}
	soraConn := NewSoraConn(serverConn, config)
	defer soraConn.Close()

	// Keep connection active but let absolute timeout trigger
	stopWriting := make(chan struct{})
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				soraConn.Write([]byte("x"))
			case <-stopWriting:
				return
			}
		}
	}()
	defer close(stopWriting)

	// Drain reads
	go func() {
		buf := make([]byte, 100)
		for {
			_, err := clientConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Wait for absolute timeout
	time.Sleep(400 * time.Millisecond)

	// Connection should be closed
	soraConn.closeMutex.Lock()
	closed := soraConn.closed
	soraConn.closeMutex.Unlock()

	if !closed {
		t.Error("Expected connection to be closed after absolute timeout")
	}

	t.Log("✓ Absolute timeout enforcement works correctly")
}

// TestSoraConnConcurrentAccess tests thread-safety
func TestSoraConnConcurrentAccess(t *testing.T) {
	// Create a TCP listener for real connection
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Accept in background
	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Logf("Accept error: %v", err)
			close(acceptDone)
			return
		}
		acceptDone <- conn
	}()

	// Connect client
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	// Get server connection
	serverConn := <-acceptDone
	if serverConn == nil {
		t.Fatal("Server failed to accept connection")
	}

	config := SoraConnConfig{
		Protocol:             "test",
		EnableTimeoutChecker: false,
	}
	soraConn := NewSoraConn(serverConn, config)
	defer soraConn.Close()

	// Concurrent goroutines accessing different methods
	done := make(chan bool, 4)

	go func() {
		for i := 0; i < 100; i++ {
			soraConn.SetJA4Fingerprint("test" + string(rune(i)))
			soraConn.GetJA4Fingerprint()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			soraConn.SetUsername("user" + string(rune(i)))
			soraConn.GetUsername()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			info := &ProxyProtocolInfo{SrcIP: "192.168.1." + string(rune(i))}
			soraConn.SetProxyInfo(info)
			soraConn.GetProxyInfo()
		}
		done <- true
	}()

	// Background goroutine to drain client reads
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := clientConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		for i := 0; i < 100; i++ {
			clientConn.Write([]byte("x"))
			buf := make([]byte, 1)
			soraConn.Read(buf)
		}
		done <- true
	}()

	// Wait for all goroutines
	for i := 0; i < 4; i++ {
		<-done
	}

	t.Log("✓ Concurrent access is thread-safe")
}

// TestSoraListener tests the SoraListener wrapper
func TestSoraListener(t *testing.T) {
	// Create a TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	config := SoraConnConfig{
		Protocol:             "test",
		EnableTimeoutChecker: false,
	}
	soraListener := NewSoraListener(listener, config)

	// Connect a client in background
	addr := listener.Addr().String()
	clientDone := make(chan net.Conn, 1)
	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Logf("Client connection failed: %v", err)
			close(clientDone)
			return
		}
		clientDone <- conn
	}()

	// Accept connection
	conn, err := soraListener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	defer conn.Close()

	// Get client connection
	clientConn := <-clientDone
	if clientConn != nil {
		defer clientConn.Close()
	}

	// Verify it's a SoraConn
	soraConn, ok := conn.(*SoraConn)
	if !ok {
		t.Fatalf("Expected *SoraConn, got %T", conn)
	}

	if soraConn.GetProtocol() != "test" {
		t.Errorf("Expected protocol 'test', got %s", soraConn.GetProtocol())
	}

	t.Log("✓ SoraListener wraps connections correctly")
}

// TestSoraTLSListenerWithRealCerts tests TLS+JA4 capture with real certificates
func TestSoraTLSListenerWithRealCerts(t *testing.T) {
	// Load test certificates
	cert, err := tls.LoadX509KeyPair("../testdata/sora.crt", "../testdata/sora.key")
	if err != nil {
		t.Skipf("Skipping test: test certificates not available: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Create TCP listener
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create TCP listener: %v", err)
	}
	defer tcpListener.Close()

	connConfig := SoraConnConfig{
		Protocol:             "imap",
		EnableTimeoutChecker: false,
	}

	soraListener := NewSoraTLSListener(tcpListener, tlsConfig, connConfig)
	addr := tcpListener.Addr().String()

	// Accept in background
	acceptDone := make(chan net.Conn)
	go func() {
		conn, err := soraListener.Accept()
		if err != nil {
			t.Logf("Accept error: %v", err)
			close(acceptDone)
			return
		}
		acceptDone <- conn
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Connect client with TLS
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	clientConn, err := tls.Dial("tcp", addr, clientTLSConfig)
	if err != nil {
		t.Fatalf("Client failed to connect: %v", err)
	}
	defer clientConn.Close()

	// Write some data to complete handshake
	clientConn.Write([]byte("test\r\n"))

	// Get server connection
	serverConn := <-acceptDone
	if serverConn == nil {
		t.Fatal("Server failed to accept connection")
	}
	defer serverConn.Close()

	// Verify it's a SoraConn
	soraConn, ok := serverConn.(*SoraConn)
	if !ok {
		t.Fatalf("Expected *SoraConn, got %T", serverConn)
	}

	// Read the data to ensure handshake completed
	buf := make([]byte, 100)
	soraConn.Read(buf)

	// Give time for JA4 callback to complete
	time.Sleep(100 * time.Millisecond)

	// Check JA4 was captured
	ja4, err := soraConn.GetJA4Fingerprint()
	if err != nil {
		t.Fatalf("GetJA4Fingerprint failed: %v", err)
	}

	if ja4 == "" {
		t.Error("Expected JA4 fingerprint to be captured, got empty string")
	}

	if len(ja4) < 20 {
		t.Errorf("JA4 fingerprint seems too short: %q", ja4)
	}

	t.Logf("✓ SoraTLSListener captured JA4 fingerprint: %s", ja4)
}
