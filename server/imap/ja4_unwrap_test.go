package imap

import (
	"net"
	"testing"

	serverPkg "github.com/migadu/sora/server"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	net.Conn
}

func (m *mockConn) Close() error        { return nil }
func (m *mockConn) LocalAddr() net.Addr { return nil }
func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (m *mockConn) Read(b []byte) (n int, err error)  { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error) { return len(b), nil }

// TestSoraConnJA4Access tests that SoraConn provides direct access to JA4 fingerprint
func TestSoraConnJA4Access(t *testing.T) {
	baseConn := &mockConn{}

	connConfig := serverPkg.SoraConnConfig{
		Protocol:             "test",
		EnableTimeoutChecker: false,
	}

	soraConn := serverPkg.NewSoraConn(baseConn, connConfig)

	// Set a JA4 fingerprint
	expectedFingerprint := "t13d1516h2_8daaf6152771_b0da82dd1658"
	soraConn.SetJA4Fingerprint(expectedFingerprint)

	// Test direct access to JA4 fingerprint (no unwrapping needed!)
	fingerprint, err := soraConn.GetJA4Fingerprint()
	if err != nil {
		t.Fatalf("GetJA4Fingerprint failed: %v", err)
	}

	if fingerprint != expectedFingerprint {
		t.Errorf("Expected fingerprint %q, got %q", expectedFingerprint, fingerprint)
	}

	t.Log("✓ SoraConn provides direct access to JA4 fingerprint without unwrapping")
}

// TestSoraConnWithWrappers tests that even when SoraConn is wrapped, we can still access JA4
func TestSoraConnWithWrappers(t *testing.T) {
	baseConn := &mockConn{}

	connConfig := serverPkg.SoraConnConfig{
		Protocol:             "test",
		EnableTimeoutChecker: false,
	}

	soraConn := serverPkg.NewSoraConn(baseConn, connConfig)
	soraConn.SetJA4Fingerprint("t13d1516h2_8daaf6152771_b0da82dd1658")

	// Wrap SoraConn with PROXY protocol and connection limiting
	proxyWrapped := &proxyProtocolConn{
		Conn:      soraConn,
		proxyInfo: nil,
	}

	limitingWrapped := &connectionLimitingConn{
		Conn:        proxyWrapped,
		releaseFunc: func() {},
		proxyInfo:   nil,
	}

	// Try to find JA4 through the wrappers
	currentConn := net.Conn(limitingWrapped)
	var foundJA4 interface{ GetJA4Fingerprint() (string, error) }

	for currentConn != nil {
		if jc, ok := currentConn.(interface{ GetJA4Fingerprint() (string, error) }); ok {
			foundJA4 = jc
			break
		}
		if wrapper, ok := currentConn.(interface{ Unwrap() net.Conn }); ok {
			currentConn = wrapper.Unwrap()
		} else {
			break
		}
	}

	if foundJA4 == nil {
		t.Fatal("Failed to find JA4 connection through wrappers")
	}

	fingerprint, err := foundJA4.GetJA4Fingerprint()
	if err != nil {
		t.Fatalf("GetJA4Fingerprint failed: %v", err)
	}

	expectedFingerprint := "t13d1516h2_8daaf6152771_b0da82dd1658"
	if fingerprint != expectedFingerprint {
		t.Errorf("Expected fingerprint %q, got %q", expectedFingerprint, fingerprint)
	}

	t.Log("✓ SoraConn JA4 accessible even when wrapped with other connection types")
}

// TestSoraConnProxyInfo tests PROXY protocol info access
func TestSoraConnProxyInfo(t *testing.T) {
	baseConn := &mockConn{}

	connConfig := serverPkg.SoraConnConfig{
		Protocol:             "test",
		EnableTimeoutChecker: false,
	}

	soraConn := serverPkg.NewSoraConn(baseConn, connConfig)

	// Set proxy info
	proxyInfo := &serverPkg.ProxyProtocolInfo{
		SrcIP:   "192.168.1.100",
		SrcPort: 54321,
		DstIP:   "10.0.0.1",
		DstPort: 143,
	}
	soraConn.SetProxyInfo(proxyInfo)

	// Get proxy info
	retrieved := soraConn.GetProxyInfo()
	if retrieved == nil {
		t.Fatal("Expected proxy info, got nil")
	}

	if retrieved.SrcIP != "192.168.1.100" {
		t.Errorf("Expected SrcIP %q, got %q", "192.168.1.100", retrieved.SrcIP)
	}

	t.Log("✓ SoraConn provides direct access to PROXY protocol info")
}

// TestSoraConnUnwrap tests that SoraConn implements Unwrap()
func TestSoraConnUnwrap(t *testing.T) {
	baseConn := &mockConn{}

	connConfig := serverPkg.SoraConnConfig{
		Protocol:             "test",
		EnableTimeoutChecker: false,
	}

	soraConn := serverPkg.NewSoraConn(baseConn, connConfig)

	// Verify SoraConn implements Unwrap
	if unwrapper, ok := any(soraConn).(interface{ Unwrap() net.Conn }); ok {
		unwrapped := unwrapper.Unwrap()
		if unwrapped != baseConn {
			t.Error("SoraConn.Unwrap() should return the base connection")
		}
	} else {
		t.Error("SoraConn must implement Unwrap() method")
	}

	t.Log("✓ SoraConn implements Unwrap() for compatibility")
}
