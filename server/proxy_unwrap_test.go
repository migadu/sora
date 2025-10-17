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

// mockProxyProtocolConn simulates a connection with PROXY protocol info
type mockProxyProtocolConn struct {
	net.Conn
	proxyInfo *ProxyProtocolInfo
}

func (m *mockProxyProtocolConn) GetProxyInfo() *ProxyProtocolInfo {
	return m.proxyInfo
}

func (m *mockProxyProtocolConn) Unwrap() net.Conn {
	return m.Conn
}

// mockTimeoutConn simulates timeout wrapper
type mockTimeoutConn struct {
	net.Conn
}

func (m *mockTimeoutConn) Unwrap() net.Conn {
	return m.Conn
}

// mockConnectionLimitingConn simulates connection limiting wrapper
type mockConnectionLimitingConn struct {
	net.Conn
	proxyInfo *ProxyProtocolInfo
}

func (m *mockConnectionLimitingConn) GetProxyInfo() *ProxyProtocolInfo {
	return m.proxyInfo
}

func (m *mockConnectionLimitingConn) Unwrap() net.Conn {
	return m.Conn
}

// TestProxyInfoUnwrapping_SingleLayer tests unwrapping through one layer
func TestProxyInfoUnwrapping_SingleLayer(t *testing.T) {
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
	proxyConn := &mockProxyProtocolConn{
		Conn:      baseConn,
		proxyInfo: expectedProxyInfo,
	}

	// Wrap with timeout layer
	wrapped := &mockTimeoutConn{
		Conn: proxyConn,
	}

	// Test unwrapping (simulates what server code does)
	var foundProxyInfo *ProxyProtocolInfo
	currentConn := net.Conn(wrapped)

	for currentConn != nil {
		if pc, ok := currentConn.(interface{ GetProxyInfo() *ProxyProtocolInfo }); ok {
			foundProxyInfo = pc.GetProxyInfo()
			if foundProxyInfo != nil {
				break
			}
		}
		// Try to unwrap the connection
		if wrapper, ok := currentConn.(interface{ Unwrap() net.Conn }); ok {
			currentConn = wrapper.Unwrap()
		} else {
			break
		}
	}

	if foundProxyInfo == nil {
		t.Fatal("Failed to find proxy info after unwrapping single layer")
	}

	if foundProxyInfo.SrcIP != expectedProxyInfo.SrcIP {
		t.Errorf("Expected SrcIP %q, got %q", expectedProxyInfo.SrcIP, foundProxyInfo.SrcIP)
	}
	if foundProxyInfo.DstIP != expectedProxyInfo.DstIP {
		t.Errorf("Expected DstIP %q, got %q", expectedProxyInfo.DstIP, foundProxyInfo.DstIP)
	}
}

// TestProxyInfoUnwrapping_MultipleLayers tests unwrapping through all connection layers
// This simulates: timeoutConn -> connectionLimitingConn -> proxyProtocolConn
func TestProxyInfoUnwrapping_MultipleLayers(t *testing.T) {
	expectedProxyInfo := &ProxyProtocolInfo{
		Version:  2,
		Command:  "PROXY",
		SrcIP:    "2001:db8::1",
		DstIP:    "2001:db8::2",
		SrcPort:  60000,
		DstPort:  143,
		Protocol: "TCP6",
	}

	baseConn := &mockConn{}

	// Layer 3: proxyProtocolConn (innermost, has the info we need)
	proxyConn := &mockProxyProtocolConn{
		Conn:      baseConn,
		proxyInfo: expectedProxyInfo,
	}

	// Layer 2: connectionLimitingConn
	limitingConn := &mockConnectionLimitingConn{
		Conn:      proxyConn,
		proxyInfo: nil, // No proxy info here
	}

	// Layer 1: timeoutConn (outermost)
	timeoutConn := &mockTimeoutConn{
		Conn: limitingConn,
	}

	// Test unwrapping (this is what all server implementations should do)
	var foundProxyInfo *ProxyProtocolInfo
	currentConn := net.Conn(timeoutConn)
	layersUnwrapped := 0

	for currentConn != nil {
		if pc, ok := currentConn.(interface{ GetProxyInfo() *ProxyProtocolInfo }); ok {
			info := pc.GetProxyInfo()
			if info != nil {
				foundProxyInfo = info
				break
			}
		}
		// Try to unwrap the connection
		if wrapper, ok := currentConn.(interface{ Unwrap() net.Conn }); ok {
			currentConn = wrapper.Unwrap()
			layersUnwrapped++
		} else {
			break
		}
	}

	if foundProxyInfo == nil {
		t.Fatalf("Failed to find proxy info after unwrapping %d layers", layersUnwrapped)
	}

	if layersUnwrapped != 2 {
		t.Errorf("Expected to unwrap 2 layers (timeout, limiting), unwrapped %d", layersUnwrapped)
	}

	if foundProxyInfo.SrcIP != expectedProxyInfo.SrcIP {
		t.Errorf("Expected SrcIP %q, got %q", expectedProxyInfo.SrcIP, foundProxyInfo.SrcIP)
	}
	if foundProxyInfo.Protocol != expectedProxyInfo.Protocol {
		t.Errorf("Expected Protocol %q, got %q", expectedProxyInfo.Protocol, foundProxyInfo.Protocol)
	}
}

// TestProxyInfoUnwrapping_NoProxyLayer tests behavior when proxy layer is missing
func TestProxyInfoUnwrapping_NoProxyLayer(t *testing.T) {
	baseConn := &mockConn{}

	// Create stack without proxy layer
	limitingConn := &mockConnectionLimitingConn{
		Conn:      baseConn,
		proxyInfo: nil,
	}

	timeoutConn := &mockTimeoutConn{
		Conn: limitingConn,
	}

	// Test unwrapping
	var foundProxyInfo *ProxyProtocolInfo
	currentConn := net.Conn(timeoutConn)

	for currentConn != nil {
		if pc, ok := currentConn.(interface{ GetProxyInfo() *ProxyProtocolInfo }); ok {
			info := pc.GetProxyInfo()
			if info != nil {
				foundProxyInfo = info
				break
			}
		}
		// Try to unwrap the connection
		if wrapper, ok := currentConn.(interface{ Unwrap() net.Conn }); ok {
			currentConn = wrapper.Unwrap()
		} else {
			break
		}
	}

	if foundProxyInfo != nil {
		t.Error("Should not find proxy info when proxy layer is missing")
	}
}

// TestProxyInfoUnwrapping_WithoutUnwrapMethod documents the bug when Unwrap is missing
func TestProxyInfoUnwrapping_WithoutUnwrapMethod(t *testing.T) {
	expectedProxyInfo := &ProxyProtocolInfo{
		Version: 2,
		SrcIP:   "192.168.1.100",
		DstIP:   "10.0.0.1",
	}

	baseConn := &mockConn{}
	proxyConn := &mockProxyProtocolConn{
		Conn:      baseConn,
		proxyInfo: expectedProxyInfo,
	}

	// Create a wrapper WITHOUT Unwrap() method (simulates the bug)
	type brokenWrapper struct {
		net.Conn
	}
	brokenWrapped := &brokenWrapper{Conn: proxyConn}

	// Test unwrapping
	var foundProxyInfo *ProxyProtocolInfo
	currentConn := net.Conn(brokenWrapped)

	for currentConn != nil {
		if pc, ok := currentConn.(interface{ GetProxyInfo() *ProxyProtocolInfo }); ok {
			info := pc.GetProxyInfo()
			if info != nil {
				foundProxyInfo = info
				break
			}
		}
		// Try to unwrap the connection
		if wrapper, ok := currentConn.(interface{ Unwrap() net.Conn }); ok {
			currentConn = wrapper.Unwrap()
		} else {
			// This is where it stops without Unwrap method
			break
		}
	}

	if foundProxyInfo != nil {
		t.Error("Should NOT find proxy info when wrapper lacks Unwrap() method - this documents the bug we fixed")
	}
}

// TestProxyInfoUnwrapping_RealScenarios simulates real server scenarios
func TestProxyInfoUnwrapping_RealScenarios(t *testing.T) {
	tests := []struct {
		name                string
		buildConnectionFunc func() net.Conn
		expectedSrcIP       string
		expectedDstIP       string
		shouldFind          bool
	}{
		{
			name: "IMAP/POP3/LMTP with timeout + limiting + proxy",
			buildConnectionFunc: func() net.Conn {
				proxy := &mockProxyProtocolConn{
					Conn: &mockConn{},
					proxyInfo: &ProxyProtocolInfo{
						Version:  2,
						SrcIP:    "192.168.1.50",
						DstIP:    "10.0.0.5",
						Protocol: "TCP4",
					},
				}
				limiting := &mockConnectionLimitingConn{Conn: proxy}
				timeout := &mockTimeoutConn{Conn: limiting}
				return timeout
			},
			expectedSrcIP: "192.168.1.50",
			expectedDstIP: "10.0.0.5",
			shouldFind:    true,
		},
		{
			name: "Direct connection (no proxy)",
			buildConnectionFunc: func() net.Conn {
				base := &mockConn{}
				timeout := &mockTimeoutConn{Conn: base}
				return timeout
			},
			expectedSrcIP: "",
			expectedDstIP: "",
			shouldFind:    false,
		},
		{
			name: "Proxy info in connectionLimitingConn",
			buildConnectionFunc: func() net.Conn {
				limiting := &mockConnectionLimitingConn{
					Conn: &mockConn{},
					proxyInfo: &ProxyProtocolInfo{
						Version: 2,
						SrcIP:   "172.16.0.1",
						DstIP:   "172.16.0.2",
					},
				}
				timeout := &mockTimeoutConn{Conn: limiting}
				return timeout
			},
			expectedSrcIP: "172.16.0.1",
			expectedDstIP: "172.16.0.2",
			shouldFind:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := tt.buildConnectionFunc()

			// This is the exact unwrapping logic that should be in ALL servers
			// (IMAP, POP3, LMTP, ManageSieve)
			var proxyInfo *ProxyProtocolInfo
			currentConn := conn
			for currentConn != nil {
				if pc, ok := currentConn.(interface{ GetProxyInfo() *ProxyProtocolInfo }); ok {
					if info := pc.GetProxyInfo(); info != nil {
						proxyInfo = info
						break
					}
				}
				// Try to unwrap the connection
				if wrapper, ok := currentConn.(interface{ Unwrap() net.Conn }); ok {
					currentConn = wrapper.Unwrap()
				} else {
					break
				}
			}

			if tt.shouldFind {
				if proxyInfo == nil {
					t.Fatal("Expected to find proxy info but didn't")
				}
				if proxyInfo.SrcIP != tt.expectedSrcIP {
					t.Errorf("Expected SrcIP %q, got %q", tt.expectedSrcIP, proxyInfo.SrcIP)
				}
				if proxyInfo.DstIP != tt.expectedDstIP {
					t.Errorf("Expected DstIP %q, got %q", tt.expectedDstIP, proxyInfo.DstIP)
				}
			} else {
				if proxyInfo != nil {
					t.Error("Should not find proxy info when not present")
				}
			}
		})
	}
}

// TestGetConnectionIPs_WithProxyInfo tests the GetConnectionIPs helper function
func TestGetConnectionIPs_WithProxyInfo(t *testing.T) {
	tests := []struct {
		name             string
		proxyInfo        *ProxyProtocolInfo
		expectedClientIP string
		expectedProxyIP  string
	}{
		{
			name: "With proxy info",
			proxyInfo: &ProxyProtocolInfo{
				SrcIP: "192.168.1.100",
			},
			expectedClientIP: "192.168.1.100",
			expectedProxyIP:  "127.0.0.1", // From mockConn.RemoteAddr()
		},
		{
			name:             "Without proxy info",
			proxyInfo:        nil,
			expectedClientIP: "127.0.0.1", // From mockConn.RemoteAddr()
			expectedProxyIP:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{}
			clientIP, proxyIP := GetConnectionIPs(conn, tt.proxyInfo)

			if clientIP != tt.expectedClientIP {
				t.Errorf("Expected clientIP %q, got %q", tt.expectedClientIP, clientIP)
			}
			if proxyIP != tt.expectedProxyIP {
				t.Errorf("Expected proxyIP %q, got %q", tt.expectedProxyIP, proxyIP)
			}
		})
	}
}
