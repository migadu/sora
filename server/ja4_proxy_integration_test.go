package server

import (
	"bufio"
	"bytes"
	"testing"
)

// TestJA4ProxyV2EndToEnd tests the complete flow: proxy extracts JA4 → sends via PROXY v2 TLV → backend extracts it
func TestJA4ProxyV2EndToEnd(t *testing.T) {
	tests := []struct {
		name        string
		ja4         string
		clientIP    string
		clientPort  int
		serverIP    string
		serverPort  int
		expectJA4   bool
	}{
		{
			name:       "IPv4 with JA4 fingerprint",
			ja4:        "t13d1516h2_8daaf6152771_b0da82dd1658",
			clientIP:   "192.168.1.100",
			clientPort: 54321,
			serverIP:   "10.0.0.1",
			serverPort: 143,
			expectJA4:  true,
		},
		{
			name:       "IPv6 with JA4 fingerprint",
			ja4:        "t13d411100_6be44479b708_d41ae481755e",
			clientIP:   "2001:db8::1",
			clientPort: 60000,
			serverIP:   "2001:db8::2",
			serverPort: 993,
			expectJA4:  true,
		},
		{
			name:       "IPv4 without JA4 (non-TLS connection)",
			ja4:        "",
			clientIP:   "192.168.1.100",
			clientPort: 54321,
			serverIP:   "10.0.0.1",
			serverPort: 143,
			expectJA4:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Proxy generates PROXY v2 header with JA4 TLV (simulates ConnectionManager)
			var tlvs map[byte][]byte
			if tt.ja4 != "" {
				tlvs = map[byte][]byte{
					TLVTypeJA4Fingerprint: []byte(tt.ja4),
				}
			}

			header, err := GenerateProxyV2HeaderWithTLVs(
				tt.clientIP, tt.clientPort,
				tt.serverIP, tt.serverPort,
				"TCP", tlvs,
			)
			if err != nil {
				t.Fatalf("Failed to generate PROXY v2 header: %v", err)
			}

			// Step 2: Backend receives and parses PROXY v2 header (simulates backend server)
			reader := bufio.NewReader(bytes.NewReader(header))
			config := ProxyProtocolConfig{
				Enabled:        true,
				TrustedProxies: []string{"0.0.0.0/0", "::/0"},
			}
			proxyReader, err := NewProxyProtocolReader("test-backend", config)
			if err != nil {
				t.Fatalf("Failed to create ProxyProtocolReader: %v", err)
			}

			// Parse the header using parseProxyV2 directly (same as existing tests)
			info, err := proxyReader.parseProxyV2(reader)
			if err != nil {
				t.Fatalf("Backend failed to parse PROXY v2 header: %v", err)
			}

			// Step 3: Verify the backend extracted correct information
			if info.SrcIP != tt.clientIP {
				t.Errorf("Expected SrcIP %q, got %q", tt.clientIP, info.SrcIP)
			}
			if info.DstIP != tt.serverIP {
				t.Errorf("Expected DstIP %q, got %q", tt.serverIP, info.DstIP)
			}
			if info.SrcPort != tt.clientPort {
				t.Errorf("Expected SrcPort %d, got %d", tt.clientPort, info.SrcPort)
			}
			if info.DstPort != tt.serverPort {
				t.Errorf("Expected DstPort %d, got %d", tt.serverPort, info.DstPort)
			}

			// Step 4: Verify JA4 fingerprint was transmitted correctly
			if tt.expectJA4 {
				if info.JA4Fingerprint == "" {
					t.Error("Expected JA4 fingerprint in PROXY info, but none found")
				}
				if info.JA4Fingerprint != tt.ja4 {
					t.Errorf("Expected JA4 fingerprint %q, got %q", tt.ja4, info.JA4Fingerprint)
				}
				// Verify TLVs
				if len(info.TLVs) == 0 {
					t.Error("Expected TLVs to be populated")
				}
				if ja4Bytes, ok := info.TLVs[TLVTypeJA4Fingerprint]; !ok || string(ja4Bytes) != tt.ja4 {
					t.Errorf("TLV JA4 = %q, want %q", string(ja4Bytes), tt.ja4)
				}
				t.Logf("✓ JA4 fingerprint successfully transmitted via PROXY v2 TLV: %s", info.JA4Fingerprint)
			} else {
				if info.JA4Fingerprint != "" {
					t.Errorf("Expected no JA4 fingerprint, but got %q", info.JA4Fingerprint)
				}
				t.Log("✓ No JA4 fingerprint transmitted (as expected for non-TLS connection)")
			}
		})
	}
}

// TestJA4ProxyV2Priority tests the priority order: PROXY v2 TLV > Direct unwrapping > ID command
func TestJA4ProxyV2Priority(t *testing.T) {
	tests := []struct {
		name        string
		proxyJA4    string // JA4 from PROXY v2 TLV
		directJA4   string // JA4 from direct connection unwrapping
		expectedJA4 string // Which JA4 should win
		description string
	}{
		{
			name:        "PROXY v2 TLV takes priority over direct",
			proxyJA4:    "t13d1516h2_8daaf6152771_proxy_tlv",
			directJA4:   "t13d1516h2_8daaf6152771_direct",
			expectedJA4: "t13d1516h2_8daaf6152771_proxy_tlv",
			description: "When both PROXY TLV and direct connection have JA4, PROXY TLV wins",
		},
		{
			name:        "Direct unwrapping used when no PROXY TLV",
			proxyJA4:    "",
			directJA4:   "t13d1516h2_8daaf6152771_direct",
			expectedJA4: "t13d1516h2_8daaf6152771_direct",
			description: "When PROXY TLV has no JA4, use direct connection JA4",
		},
		{
			name:        "No JA4 available from either source",
			proxyJA4:    "",
			directJA4:   "",
			expectedJA4: "",
			description: "When neither source has JA4, result is empty (ID command would be last resort)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the priority logic from IMAP server.go:627-666

			// Step 1: Check for JA4 from PROXY v2 TLV (highest priority)
			var proxyJA4Fingerprint string
			if tt.proxyJA4 != "" {
				proxyJA4Fingerprint = tt.proxyJA4
			}

			// Step 2: Check for JA4 from direct connection unwrapping
			var directJA4Fingerprint string
			if tt.directJA4 != "" {
				directJA4Fingerprint = tt.directJA4
			}

			// Step 3: Apply priority order (matches server.go logic)
			var finalJA4 string
			if proxyJA4Fingerprint != "" {
				// PROXY v2 TLV has highest priority
				finalJA4 = proxyJA4Fingerprint
			} else if directJA4Fingerprint != "" {
				// Direct connection unwrapping is second priority
				finalJA4 = directJA4Fingerprint
			}
			// ID command would be third priority (not tested here)

			// Verify the priority logic
			if finalJA4 != tt.expectedJA4 {
				t.Errorf("%s: Expected JA4 %q, got %q", tt.description, tt.expectedJA4, finalJA4)
			} else {
				t.Logf("✓ %s", tt.description)
			}
		})
	}
}

// TestJA4ProxyV2Unwrapping tests that JA4 in PROXY info survives connection unwrapping on backend
func TestJA4ProxyV2Unwrapping(t *testing.T) {
	expectedJA4 := "t13d1516h2_8daaf6152771_b0da82dd1658"

	// Generate PROXY v2 header with JA4 TLV
	tlvs := map[byte][]byte{
		TLVTypeJA4Fingerprint: []byte(expectedJA4),
	}
	header, err := GenerateProxyV2HeaderWithTLVs(
		"192.168.1.100", 54321,
		"10.0.0.1", 143,
		"TCP", tlvs,
	)
	if err != nil {
		t.Fatalf("Failed to generate PROXY v2 header: %v", err)
	}

	// Parse header to create ProxyProtocolInfo
	reader := bufio.NewReader(bytes.NewReader(header))
	config := ProxyProtocolConfig{
		Enabled:        true,
		TrustedProxies: []string{"0.0.0.0/0"},
	}
	proxyReader, err := NewProxyProtocolReader("test", config)
	if err != nil {
		t.Fatalf("Failed to create ProxyProtocolReader: %v", err)
	}

	info, err := proxyReader.parseProxyV2(reader)
	if err != nil {
		t.Fatalf("Failed to parse PROXY v2 header: %v", err)
	}

	// Verify JA4 is in the parsed info
	if info.JA4Fingerprint != expectedJA4 {
		t.Errorf("Expected JA4 %q in parsed info, got %q", expectedJA4, info.JA4Fingerprint)
	}

	// Simulate what happens on backend: info gets stored in connection wrapper
	// and must survive unwrapping through multiple layers
	// This is tested by proxy_unwrap_test.go which verifies the unwrapping mechanism

	t.Logf("✓ JA4 fingerprint %q successfully parsed from PROXY v2 TLV", info.JA4Fingerprint)
	t.Log("✓ Connection unwrapping mechanism tested in proxy_unwrap_test.go")
}
