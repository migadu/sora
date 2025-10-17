package server

import (
	"net"
	"testing"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	net.Conn
}

func (m *mockConn) Close() error        { return nil }
func (m *mockConn) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 143} }
func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (m *mockConn) Read(b []byte) (n int, err error)  { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error) { return len(b), nil }

// TestSoraConnProxyInfoAccess tests direct access to PROXY protocol info via SoraConn
func TestSoraConnProxyInfoAccess(t *testing.T) {
	expectedProxyInfo := &ProxyProtocolInfo{
		Version:  2,
		Command:  "PROXY",
		SrcIP:    "192.168.1.100",
		DstIP:    "10.0.0.1",
		SrcPort:  54321,
		DstPort:  143,
		Protocol: "TCP4",
	}

	baseConn := &mockConn{}
	connConfig := SoraConnConfig{
		Protocol:             "test",
		EnableTimeoutChecker: false,
	}
	soraConn := NewSoraConn(baseConn, connConfig)

	// Set proxy info
	soraConn.SetProxyInfo(expectedProxyInfo)

	// Test direct access (no unwrapping needed!)
	foundProxyInfo := soraConn.GetProxyInfo()

	if foundProxyInfo == nil {
		t.Fatal("Expected proxy info, got nil")
	}

	if foundProxyInfo.SrcIP != expectedProxyInfo.SrcIP {
		t.Errorf("Expected SrcIP %q, got %q", expectedProxyInfo.SrcIP, foundProxyInfo.SrcIP)
	}

	if foundProxyInfo.SrcPort != expectedProxyInfo.SrcPort {
		t.Errorf("Expected SrcPort %d, got %d", expectedProxyInfo.SrcPort, foundProxyInfo.SrcPort)
	}

	t.Log("✓ SoraConn provides direct access to PROXY protocol info")
}

// TestSoraConnJA4AndProxyInfo tests that SoraConn can hold both JA4 and PROXY info
func TestSoraConnJA4AndProxyInfo(t *testing.T) {
	baseConn := &mockConn{}
	connConfig := SoraConnConfig{
		Protocol:             "test",
		EnableTimeoutChecker: false,
	}
	soraConn := NewSoraConn(baseConn, connConfig)

	// Set both JA4 and PROXY info
	ja4Fingerprint := "t13d1516h2_8daaf6152771_b0da82dd1658"
	proxyInfo := &ProxyProtocolInfo{
		SrcIP:   "192.168.1.100",
		DstIP:   "10.0.0.1",
		SrcPort: 54321,
		DstPort: 143,
	}

	soraConn.SetJA4Fingerprint(ja4Fingerprint)
	soraConn.SetProxyInfo(proxyInfo)

	// Retrieve both
	retrievedJA4, err := soraConn.GetJA4Fingerprint()
	if err != nil {
		t.Fatalf("GetJA4Fingerprint failed: %v", err)
	}

	retrievedProxyInfo := soraConn.GetProxyInfo()

	// Verify
	if retrievedJA4 != ja4Fingerprint {
		t.Errorf("Expected JA4 %q, got %q", ja4Fingerprint, retrievedJA4)
	}

	if retrievedProxyInfo == nil {
		t.Fatal("Expected proxy info, got nil")
	}

	if retrievedProxyInfo.SrcIP != proxyInfo.SrcIP {
		t.Errorf("Expected SrcIP %q, got %q", proxyInfo.SrcIP, retrievedProxyInfo.SrcIP)
	}

	t.Log("✓ SoraConn can store and retrieve both JA4 fingerprint and PROXY protocol info")
}

// mockWrapper simulates an additional wrapper layer
type mockWrapper struct {
	net.Conn
}

func (m *mockWrapper) Unwrap() net.Conn {
	return m.Conn
}

// TestSoraConnThroughWrappers tests accessing SoraConn through additional wrapper layers
func TestSoraConnThroughWrappers(t *testing.T) {
	baseConn := &mockConn{}
	connConfig := SoraConnConfig{
		Protocol:             "test",
		EnableTimeoutChecker: false,
	}
	soraConn := NewSoraConn(baseConn, connConfig)

	// Set data
	ja4Fingerprint := "t13d1516h2_8daaf6152771_b0da82dd1658"
	proxyInfo := &ProxyProtocolInfo{
		SrcIP:   "192.168.1.100",
		SrcPort: 54321,
	}
	soraConn.SetJA4Fingerprint(ja4Fingerprint)
	soraConn.SetProxyInfo(proxyInfo)

	// Wrap SoraConn with additional layers
	wrapped := &mockWrapper{Conn: soraConn}

	// Unwrap to find SoraConn
	currentConn := net.Conn(wrapped)
	var foundSoraConn *SoraConn

	for currentConn != nil {
		if sc, ok := currentConn.(*SoraConn); ok {
			foundSoraConn = sc
			break
		}
		if wrapper, ok := currentConn.(interface{ Unwrap() net.Conn }); ok {
			currentConn = wrapper.Unwrap()
		} else {
			break
		}
	}

	if foundSoraConn == nil {
		t.Fatal("Failed to find SoraConn through wrapper")
	}

	// Verify data is accessible
	retrievedJA4, err := foundSoraConn.GetJA4Fingerprint()
	if err != nil {
		t.Fatalf("GetJA4Fingerprint failed: %v", err)
	}

	if retrievedJA4 != ja4Fingerprint {
		t.Errorf("Expected JA4 %q, got %q", ja4Fingerprint, retrievedJA4)
	}

	retrievedProxyInfo := foundSoraConn.GetProxyInfo()
	if retrievedProxyInfo == nil {
		t.Fatal("Expected proxy info, got nil")
	}

	if retrievedProxyInfo.SrcIP != proxyInfo.SrcIP {
		t.Errorf("Expected SrcIP %q, got %q", proxyInfo.SrcIP, retrievedProxyInfo.SrcIP)
	}

	t.Log("✓ SoraConn accessible through wrapper layers via Unwrap()")
}
