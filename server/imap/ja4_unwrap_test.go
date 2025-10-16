package imap

import (
	"crypto/tls"
	"net"
	"testing"
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

// mockJA4Conn simulates a JA4 capture connection with GetJA4Fingerprint method
type mockJA4Conn struct {
	net.Conn
	fingerprint string
}

func (m *mockJA4Conn) GetJA4Fingerprint() (string, error) {
	return m.fingerprint, nil
}

func (m *mockJA4Conn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{}
}

// TestConnectionUnwrapping_SingleLayer tests unwrapping a single-layer wrapped connection
func TestConnectionUnwrapping_SingleLayer(t *testing.T) {
	baseConn := &mockConn{}
	ja4Conn := &mockJA4Conn{
		Conn:        baseConn,
		fingerprint: "t13d1516h2_8daaf6152771_b0da82dd1658",
	}

	// Wrap with timeout
	wrapped := &timeoutConn{
		Conn: ja4Conn,
	}

	// Test unwrapping
	var foundJA4 interface{ GetJA4Fingerprint() (string, error) }
	currentConn := net.Conn(wrapped)

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
		t.Fatal("Failed to find JA4 connection after unwrapping single layer")
	}

	fingerprint, err := foundJA4.GetJA4Fingerprint()
	if err != nil {
		t.Fatalf("GetJA4Fingerprint failed: %v", err)
	}

	expectedFingerprint := "t13d1516h2_8daaf6152771_b0da82dd1658"
	if fingerprint != expectedFingerprint {
		t.Errorf("Expected fingerprint %q, got %q", expectedFingerprint, fingerprint)
	}
}

// TestConnectionUnwrapping_MultipleLayers tests unwrapping through all connection layers
func TestConnectionUnwrapping_MultipleLayers(t *testing.T) {
	baseConn := &mockConn{}
	ja4Conn := &mockJA4Conn{
		Conn:        baseConn,
		fingerprint: "t13d1516h2_8daaf6152771_b0da82dd1658",
	}

	// Simulate the full connection stack: timeout → limiting → proxy → ja4
	proxyWrapped := &proxyProtocolConn{
		Conn:      ja4Conn,
		proxyInfo: nil,
	}

	limitingWrapped := &connectionLimitingConn{
		Conn:        proxyWrapped,
		releaseFunc: func() {},
		proxyInfo:   nil,
	}

	timeoutWrapped := &timeoutConn{
		Conn: limitingWrapped,
	}

	// Test unwrapping through all layers
	var foundJA4 interface{ GetJA4Fingerprint() (string, error) }
	currentConn := net.Conn(timeoutWrapped)
	layersUnwrapped := 0

	for currentConn != nil {
		if jc, ok := currentConn.(interface{ GetJA4Fingerprint() (string, error) }); ok {
			foundJA4 = jc
			break
		}
		if wrapper, ok := currentConn.(interface{ Unwrap() net.Conn }); ok {
			currentConn = wrapper.Unwrap()
			layersUnwrapped++
		} else {
			break
		}
	}

	if foundJA4 == nil {
		t.Fatalf("Failed to find JA4 connection after unwrapping %d layers", layersUnwrapped)
	}

	if layersUnwrapped != 3 {
		t.Errorf("Expected to unwrap 3 layers (timeout, limiting, proxy), unwrapped %d", layersUnwrapped)
	}

	fingerprint, err := foundJA4.GetJA4Fingerprint()
	if err != nil {
		t.Fatalf("GetJA4Fingerprint failed: %v", err)
	}

	expectedFingerprint := "t13d1516h2_8daaf6152771_b0da82dd1658"
	if fingerprint != expectedFingerprint {
		t.Errorf("Expected fingerprint %q, got %q", expectedFingerprint, fingerprint)
	}
}

// TestConnectionUnwrapping_NoJA4Layer tests behavior when JA4 layer is missing
func TestConnectionUnwrapping_NoJA4Layer(t *testing.T) {
	baseConn := &mockConn{}

	// Create stack without JA4 layer
	limitingWrapped := &connectionLimitingConn{
		Conn:        baseConn,
		releaseFunc: func() {},
		proxyInfo:   nil,
	}

	timeoutWrapped := &timeoutConn{
		Conn: limitingWrapped,
	}

	// Test unwrapping
	var foundJA4 interface{ GetJA4Fingerprint() (string, error) }
	currentConn := net.Conn(timeoutWrapped)

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

	if foundJA4 != nil {
		t.Error("Should not find JA4 connection when JA4 layer is missing")
	}
}

// TestConnectionUnwrapping_WithoutUnwrapMethod tests the failure case when Unwrap is missing
func TestConnectionUnwrapping_WithoutUnwrapMethod(t *testing.T) {
	// This test documents what happens if we forget to add Unwrap() method
	baseConn := &mockConn{}
	ja4Conn := &mockJA4Conn{
		Conn:        baseConn,
		fingerprint: "t13d1516h2_8daaf6152771_b0da82dd1658",
	}

	// Create a wrapper WITHOUT Unwrap() method
	type brokenWrapper struct {
		net.Conn
	}
	brokenWrapped := &brokenWrapper{Conn: ja4Conn}

	// Test unwrapping
	var foundJA4 interface{ GetJA4Fingerprint() (string, error) }
	currentConn := net.Conn(brokenWrapped)

	for currentConn != nil {
		if jc, ok := currentConn.(interface{ GetJA4Fingerprint() (string, error) }); ok {
			foundJA4 = jc
			break
		}
		if wrapper, ok := currentConn.(interface{ Unwrap() net.Conn }); ok {
			currentConn = wrapper.Unwrap()
		} else {
			// This is where it will stop without Unwrap method
			break
		}
	}

	if foundJA4 != nil {
		t.Error("Should NOT find JA4 connection when wrapper lacks Unwrap() method - this documents the bug we fixed")
	}
}

// TestAllWrapperTypesHaveUnwrap verifies all wrapper types implement Unwrap()
func TestAllWrapperTypesHaveUnwrap(t *testing.T) {
	baseConn := &mockConn{}

	// Test timeoutConn
	tc := &timeoutConn{Conn: baseConn}
	if _, ok := interface{}(tc).(interface{ Unwrap() net.Conn }); !ok {
		t.Error("timeoutConn must implement Unwrap() method")
	}
	if unwrapped := tc.Unwrap(); unwrapped != baseConn {
		t.Error("timeoutConn.Unwrap() should return the wrapped connection")
	}

	// Test connectionLimitingConn
	lc := &connectionLimitingConn{Conn: baseConn}
	if _, ok := interface{}(lc).(interface{ Unwrap() net.Conn }); !ok {
		t.Error("connectionLimitingConn must implement Unwrap() method")
	}
	if unwrapped := lc.Unwrap(); unwrapped != baseConn {
		t.Error("connectionLimitingConn.Unwrap() should return the wrapped connection")
	}

	// Test proxyProtocolConn
	pc := &proxyProtocolConn{Conn: baseConn}
	if _, ok := interface{}(pc).(interface{ Unwrap() net.Conn }); !ok {
		t.Error("proxyProtocolConn must implement Unwrap() method")
	}
	if unwrapped := pc.Unwrap(); unwrapped != baseConn {
		t.Error("proxyProtocolConn.Unwrap() should return the wrapped connection")
	}
}

// TestJA4FingerprintExtraction_RealScenario simulates the real newSession flow
func TestJA4FingerprintExtraction_RealScenario(t *testing.T) {
	// This test simulates what happens in newSession() when a connection arrives
	tests := []struct {
		name                string
		buildConnectionFunc func() net.Conn
		expectedFingerprint string
		shouldFind          bool
	}{
		{
			name: "Full stack with JA4",
			buildConnectionFunc: func() net.Conn {
				ja4 := &mockJA4Conn{
					Conn:        &mockConn{},
					fingerprint: "t13d1516h2_8daaf6152771_b0da82dd1658",
				}
				proxy := &proxyProtocolConn{Conn: ja4}
				limiting := &connectionLimitingConn{Conn: proxy}
				timeout := &timeoutConn{Conn: limiting}
				return timeout
			},
			expectedFingerprint: "t13d1516h2_8daaf6152771_b0da82dd1658",
			shouldFind:          true,
		},
		{
			name: "Without proxy layer",
			buildConnectionFunc: func() net.Conn {
				ja4 := &mockJA4Conn{
					Conn:        &mockConn{},
					fingerprint: "t13d1516h2_8daaf6152771_different",
				}
				limiting := &connectionLimitingConn{Conn: ja4}
				timeout := &timeoutConn{Conn: limiting}
				return timeout
			},
			expectedFingerprint: "t13d1516h2_8daaf6152771_different",
			shouldFind:          true,
		},
		{
			name: "No JA4 layer (non-TLS connection)",
			buildConnectionFunc: func() net.Conn {
				base := &mockConn{}
				timeout := &timeoutConn{Conn: base}
				return timeout
			},
			expectedFingerprint: "",
			shouldFind:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := tt.buildConnectionFunc()

			// This is the exact unwrapping logic from server.go:594-613
			var ja4Conn interface{ GetJA4Fingerprint() (string, error) }
			currentConn := conn
			for currentConn != nil {
				if jc, ok := currentConn.(interface{ GetJA4Fingerprint() (string, error) }); ok {
					ja4Conn = jc
					break
				}
				if wrapper, ok := currentConn.(interface{ Unwrap() net.Conn }); ok {
					currentConn = wrapper.Unwrap()
				} else if proxy, ok := currentConn.(*proxyProtocolConn); ok {
					currentConn = proxy.Conn
				} else if limiting, ok := currentConn.(*connectionLimitingConn); ok {
					currentConn = limiting.Conn
				} else {
					break
				}
			}

			if tt.shouldFind {
				if ja4Conn == nil {
					t.Fatal("Expected to find JA4 connection but didn't")
				}
				fingerprint, err := ja4Conn.GetJA4Fingerprint()
				if err != nil {
					t.Fatalf("GetJA4Fingerprint failed: %v", err)
				}
				if fingerprint != tt.expectedFingerprint {
					t.Errorf("Expected fingerprint %q, got %q", tt.expectedFingerprint, fingerprint)
				}
			} else {
				if ja4Conn != nil {
					t.Error("Should not find JA4 connection when not present")
				}
			}
		})
	}
}
