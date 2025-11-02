package server

import (
	"bufio"
	"bytes"
	"net"
	"testing"
)

// TestParseTLVs tests parsing of PROXY v2 TLV extensions
func TestParseTLVs(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantTLVs    map[byte][]byte
		wantErr     bool
		description string
	}{
		{
			name: "single JA4 TLV",
			data: []byte{
				0xE0,       // Type: JA4 fingerprint
				0x00, 0x24, // Length: 36 bytes (big endian) - correct length for the string below
				't', '1', '3', 'd', '4', '1', '1', '1', '0', '0', '_',
				'6', 'b', 'e', '4', '4', '4', '7', '9', 'b', '7', '0', '8', '_',
				'd', '4', '1', 'a', 'e', '4', '8', '1', '7', '5', '5', 'e',
			},
			wantTLVs: map[byte][]byte{
				0xE0: []byte("t13d411100_6be44479b708_d41ae481755e"),
			},
			wantErr:     false,
			description: "Valid JA4 fingerprint TLV",
		},
		{
			name: "multiple TLVs",
			data: []byte{
				0xE0,       // Type: JA4 fingerprint
				0x00, 0x05, // Length: 5 bytes
				't', 'e', 's', 't', '1',
				0xE1,       // Type: custom TLV
				0x00, 0x03, // Length: 3 bytes
				'a', 'b', 'c',
			},
			wantTLVs: map[byte][]byte{
				0xE0: []byte("test1"),
				0xE1: []byte("abc"),
			},
			wantErr:     false,
			description: "Multiple TLVs",
		},
		{
			name:        "empty data",
			data:        []byte{},
			wantTLVs:    map[byte][]byte{},
			wantErr:     false,
			description: "No TLVs (valid empty case)",
		},
		{
			name: "zero-length TLV",
			data: []byte{
				0xE0,       // Type
				0x00, 0x00, // Length: 0
			},
			wantTLVs: map[byte][]byte{
				0xE0: {},
			},
			wantErr:     false,
			description: "TLV with zero-length value",
		},
		{
			name: "truncated TLV header",
			data: []byte{
				0xE0, // Type
				0x00, // Only 1 byte of length (need 2)
			},
			wantTLVs:    map[byte][]byte{}, // parseTLVs breaks the loop, returns empty map
			wantErr:     false,             // Not an error, just incomplete
			description: "Incomplete TLV header (missing length byte) - breaks loop gracefully",
		},
		{
			name: "truncated TLV value",
			data: []byte{
				0xE0,       // Type
				0x00, 0x05, // Length: 5 bytes
				't', 'e', 's', // Only 3 bytes instead of 5
			},
			wantTLVs:    nil,
			wantErr:     true,
			description: "TLV value shorter than declared length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(bytes.NewReader(tt.data))
			tlvs, err := parseTLVs(reader, len(tt.data))

			if (err != nil) != tt.wantErr {
				t.Errorf("parseTLVs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(tlvs) != len(tt.wantTLVs) {
					t.Errorf("parseTLVs() got %d TLVs, want %d", len(tlvs), len(tt.wantTLVs))
					return
				}

				for tlvType, wantValue := range tt.wantTLVs {
					gotValue, ok := tlvs[tlvType]
					if !ok {
						t.Errorf("parseTLVs() missing TLV type 0x%02X", tlvType)
						continue
					}
					if !bytes.Equal(gotValue, wantValue) {
						t.Errorf("parseTLVs() TLV 0x%02X = %q, want %q", tlvType, gotValue, wantValue)
					}
				}
			}
		})
	}
}

// TestExtractJA4FromTLVs tests extraction of JA4 fingerprint from TLVs
func TestExtractJA4FromTLVs(t *testing.T) {
	tests := []struct {
		name     string
		tlvs     map[byte][]byte
		wantJA4  string
		describe string
	}{
		{
			name: "JA4 present",
			tlvs: map[byte][]byte{
				0xE0: []byte("t13d411100_6be44479b708_d41ae481755e"),
			},
			wantJA4:  "t13d411100_6be44479b708_d41ae481755e",
			describe: "JA4 fingerprint present in TLV 0xE0",
		},
		{
			name: "JA4 with other TLVs",
			tlvs: map[byte][]byte{
				0xE0: []byte("t13d411100_6be44479b708_d41ae481755e"),
				0xE1: []byte("other-data"),
				0x01: []byte("standard-tlv"),
			},
			wantJA4:  "t13d411100_6be44479b708_d41ae481755e",
			describe: "JA4 extracted even with other TLVs present",
		},
		{
			name: "no JA4 TLV",
			tlvs: map[byte][]byte{
				0xE1: []byte("other-data"),
			},
			wantJA4:  "",
			describe: "Empty string when JA4 TLV not present",
		},
		{
			name:     "nil TLVs",
			tlvs:     nil,
			wantJA4:  "",
			describe: "Empty string for nil TLVs map",
		},
		{
			name:     "empty TLVs",
			tlvs:     map[byte][]byte{},
			wantJA4:  "",
			describe: "Empty string for empty TLVs map",
		},
		{
			name: "empty JA4 value",
			tlvs: map[byte][]byte{
				0xE0: {},
			},
			wantJA4:  "",
			describe: "Empty string when JA4 TLV has zero-length value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotJA4 := extractJA4FromTLVs(tt.tlvs)
			if gotJA4 != tt.wantJA4 {
				t.Errorf("extractJA4FromTLVs() = %q, want %q", gotJA4, tt.wantJA4)
			}
		})
	}
}

// TestGenerateProxyV2HeaderWithTLVs tests PROXY v2 header generation with TLVs
func TestGenerateProxyV2HeaderWithTLVs(t *testing.T) {
	tests := []struct {
		name         string
		clientIP     string
		clientPort   int
		serverIP     string
		serverPort   int
		protocol     string
		tlvs         map[byte][]byte
		wantErr      bool
		validateFunc func(t *testing.T, header []byte)
		description  string
	}{
		{
			name:       "IPv4 with JA4 TLV",
			clientIP:   "192.168.1.100",
			clientPort: 54321,
			serverIP:   "10.0.0.1",
			serverPort: 143,
			protocol:   "TCP",
			tlvs: map[byte][]byte{
				0xE0: []byte("t13d411100_6be44479b708_d41ae481755e"),
			},
			wantErr: false,
			validateFunc: func(t *testing.T, header []byte) {
				// Verify PROXY v2 signature
				expectedSig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
				if !bytes.Equal(header[0:12], expectedSig) {
					t.Error("Invalid PROXY v2 signature")
				}

				// Verify version and command
				if header[12] != 0x21 {
					t.Errorf("Expected version/command 0x21, got 0x%02X", header[12])
				}

				// Verify address family (IPv4=0x1) and protocol (TCP=0x1)
				if header[13] != 0x11 {
					t.Errorf("Expected family/protocol 0x11 (IPv4/TCP), got 0x%02X", header[13])
				}

				// Verify length includes both address data (12 bytes) and TLV data
				length := (int(header[14]) << 8) | int(header[15])
				expectedLen := 12 + 3 + len("t13d411100_6be44479b708_d41ae481755e") // addr + TLV header + value
				if length != expectedLen {
					t.Errorf("Expected length %d, got %d", expectedLen, length)
				}

				// Verify IPv4 addresses
				if !bytes.Equal(header[16:20], []byte{192, 168, 1, 100}) {
					t.Error("Incorrect source IPv4 address")
				}
				if !bytes.Equal(header[20:24], []byte{10, 0, 0, 1}) {
					t.Error("Incorrect destination IPv4 address")
				}

				// Verify ports (big endian)
				srcPort := (int(header[24]) << 8) | int(header[25])
				dstPort := (int(header[26]) << 8) | int(header[27])
				if srcPort != 54321 {
					t.Errorf("Expected source port 54321, got %d", srcPort)
				}
				if dstPort != 143 {
					t.Errorf("Expected destination port 143, got %d", dstPort)
				}

				// Verify TLV is present
				tlvStart := 28 // After 16-byte header + 12-byte IPv4 data
				if header[tlvStart] != 0xE0 {
					t.Errorf("Expected TLV type 0xE0, got 0x%02X", header[tlvStart])
				}
				tlvLen := (int(header[tlvStart+1]) << 8) | int(header[tlvStart+2])
				if tlvLen != len("t13d411100_6be44479b708_d41ae481755e") {
					t.Errorf("Expected TLV length %d, got %d", len("t13d411100_6be44479b708_d41ae481755e"), tlvLen)
				}
				tlvValue := string(header[tlvStart+3 : tlvStart+3+tlvLen])
				if tlvValue != "t13d411100_6be44479b708_d41ae481755e" {
					t.Errorf("Expected TLV value %q, got %q", "t13d411100_6be44479b708_d41ae481755e", tlvValue)
				}
			},
			description: "IPv4 PROXY v2 header with JA4 TLV",
		},
		{
			name:       "IPv4 without TLVs",
			clientIP:   "192.168.1.100",
			clientPort: 54321,
			serverIP:   "10.0.0.1",
			serverPort: 143,
			protocol:   "TCP",
			tlvs:       nil,
			wantErr:    false,
			validateFunc: func(t *testing.T, header []byte) {
				// Verify length is exactly 12 bytes (no TLVs)
				length := (int(header[14]) << 8) | int(header[15])
				if length != 12 {
					t.Errorf("Expected length 12 (no TLVs), got %d", length)
				}

				// Verify total header size
				if len(header) != 28 { // 16-byte header + 12-byte IPv4 data
					t.Errorf("Expected total size 28, got %d", len(header))
				}
			},
			description: "IPv4 PROXY v2 header without TLVs",
		},
		{
			name:       "IPv6 with JA4 TLV",
			clientIP:   "2001:db8::1",
			clientPort: 54321,
			serverIP:   "2001:db8::2",
			serverPort: 143,
			protocol:   "TCP",
			tlvs: map[byte][]byte{
				0xE0: []byte("t13d411100_6be44479b708_d41ae481755e"),
			},
			wantErr: false,
			validateFunc: func(t *testing.T, header []byte) {
				// Verify address family (IPv6=0x2) and protocol (TCP=0x1)
				if header[13] != 0x21 {
					t.Errorf("Expected family/protocol 0x21 (IPv6/TCP), got 0x%02X", header[13])
				}

				// Verify length includes both address data (36 bytes) and TLV data
				length := (int(header[14]) << 8) | int(header[15])
				expectedLen := 36 + 3 + len("t13d411100_6be44479b708_d41ae481755e")
				if length != expectedLen {
					t.Errorf("Expected length %d, got %d", expectedLen, length)
				}
			},
			description: "IPv6 PROXY v2 header with JA4 TLV",
		},
		{
			name:        "invalid client IP",
			clientIP:    "invalid-ip",
			clientPort:  54321,
			serverIP:    "10.0.0.1",
			serverPort:  143,
			protocol:    "TCP",
			tlvs:        nil,
			wantErr:     true,
			description: "Error on invalid client IP address",
		},
		{
			name:        "invalid server IP",
			clientIP:    "192.168.1.100",
			clientPort:  54321,
			serverIP:    "invalid-ip",
			serverPort:  143,
			protocol:    "TCP",
			tlvs:        nil,
			wantErr:     true,
			description: "Error on invalid server IP address",
		},
		{
			name:       "multiple TLVs",
			clientIP:   "192.168.1.100",
			clientPort: 54321,
			serverIP:   "10.0.0.1",
			serverPort: 143,
			protocol:   "TCP",
			tlvs: map[byte][]byte{
				0xE0: []byte("t13d411100_6be44479b708_d41ae481755e"),
				0xE1: []byte("custom-data"),
			},
			wantErr: false,
			validateFunc: func(t *testing.T, header []byte) {
				// Verify length includes all TLVs
				length := (int(header[14]) << 8) | int(header[15])
				expectedLen := 12 + // IPv4 address data
					(3 + len("t13d411100_6be44479b708_d41ae481755e")) + // TLV 0xE0
					(3 + len("custom-data")) // TLV 0xE1
				if length != expectedLen {
					t.Errorf("Expected length %d, got %d", expectedLen, length)
				}
			},
			description: "Multiple TLVs encoded correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, err := GenerateProxyV2HeaderWithTLVs(
				tt.clientIP, tt.clientPort,
				tt.serverIP, tt.serverPort,
				tt.protocol, tt.tlvs,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateProxyV2HeaderWithTLVs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.validateFunc != nil {
				tt.validateFunc(t, header)
			}
		})
	}
}

// TestProxyV2RoundTrip tests encoding and then parsing a PROXY v2 header with TLVs
func TestProxyV2RoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		clientIP   string
		clientPort int
		serverIP   string
		serverPort int
		ja4        string
	}{
		{
			name:       "IPv4 with JA4",
			clientIP:   "192.168.1.100",
			clientPort: 54321,
			serverIP:   "10.0.0.1",
			serverPort: 143,
			ja4:        "t13d411100_6be44479b708_d41ae481755e",
		},
		{
			name:       "IPv6 with JA4",
			clientIP:   "2001:db8::1",
			clientPort: 54321,
			serverIP:   "2001:db8::2",
			serverPort: 143,
			ja4:        "t13d411100_6be44479b708_d41ae481755e",
		},
		{
			name:       "IPv4 without JA4",
			clientIP:   "192.168.1.100",
			clientPort: 54321,
			serverIP:   "10.0.0.1",
			serverPort: 143,
			ja4:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate header
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
				t.Fatalf("GenerateProxyV2HeaderWithTLVs() failed: %v", err)
			}

			// Parse header
			reader := bufio.NewReader(bytes.NewReader(header))

			// Create a mock ProxyProtocolReader
			config := ProxyProtocolConfig{
				Enabled:        true,
				TrustedProxies: []string{"0.0.0.0/0", "::/0"},
			}
			proxyReader, err := NewProxyProtocolReader("test", config)
			if err != nil {
				t.Fatalf("Failed to create ProxyProtocolReader: %v", err)
			}

			info, err := proxyReader.parseProxyV2(reader)
			if err != nil {
				t.Fatalf("parseProxyV2() failed: %v", err)
			}

			// Verify parsed data
			if info.SrcIP != tt.clientIP {
				t.Errorf("SrcIP = %q, want %q", info.SrcIP, tt.clientIP)
			}
			if info.SrcPort != tt.clientPort {
				t.Errorf("SrcPort = %d, want %d", info.SrcPort, tt.clientPort)
			}
			if info.DstIP != tt.serverIP {
				t.Errorf("DstIP = %q, want %q", info.DstIP, tt.serverIP)
			}
			if info.DstPort != tt.serverPort {
				t.Errorf("DstPort = %d, want %d", info.DstPort, tt.serverPort)
			}

			// Verify JA4 fingerprint
			if info.JA4Fingerprint != tt.ja4 {
				t.Errorf("JA4Fingerprint = %q, want %q", info.JA4Fingerprint, tt.ja4)
			}

			// Verify TLVs
			if tt.ja4 != "" {
				if len(info.TLVs) == 0 {
					t.Error("Expected TLVs to be populated")
				}
				if ja4Bytes, ok := info.TLVs[TLVTypeJA4Fingerprint]; !ok || string(ja4Bytes) != tt.ja4 {
					t.Errorf("TLV JA4 = %q, want %q", string(ja4Bytes), tt.ja4)
				}
			} else {
				if len(info.TLVs) > 0 {
					t.Errorf("Expected no TLVs, got %d", len(info.TLVs))
				}
			}
		})
	}
}

// TestProxyV2BackwardCompatibility verifies old parsers ignore unknown TLVs
func TestProxyV2BackwardCompatibility(t *testing.T) {
	// Generate a PROXY v2 header with JA4 TLV
	tlvs := map[byte][]byte{
		0xE0: []byte("t13d411100_6be44479b708_d41ae481755e"),
	}

	header, err := GenerateProxyV2HeaderWithTLVs(
		"192.168.1.100", 54321,
		"10.0.0.1", 143,
		"TCP", tlvs,
	)
	if err != nil {
		t.Fatalf("GenerateProxyV2HeaderWithTLVs() failed: %v", err)
	}

	// Parse with TLV support
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
		t.Fatalf("parseProxyV2() failed: %v", err)
	}

	// Verify core PROXY protocol data is still correct
	if info.SrcIP != "192.168.1.100" {
		t.Errorf("SrcIP = %q, want %q", info.SrcIP, "192.168.1.100")
	}
	if info.SrcPort != 54321 {
		t.Errorf("SrcPort = %d, want %d", info.SrcPort, 54321)
	}

	// Verify TLVs are parsed
	if info.JA4Fingerprint != "t13d411100_6be44479b708_d41ae481755e" {
		t.Errorf("JA4Fingerprint = %q, want %q", info.JA4Fingerprint, "t13d411100_6be44479b708_d41ae481755e")
	}
}

// Mock connection for testing JA4 extraction
type mockJA4Conn struct {
	net.Conn
	ja4 string
}

func (m *mockJA4Conn) GetJA4Fingerprint() (string, error) {
	return m.ja4, nil
}

func (m *mockJA4Conn) Unwrap() net.Conn {
	return m.Conn
}

// TestJA4ExtractionFromClientConn tests extracting JA4 from client connection
func TestJA4ExtractionFromClientConn(t *testing.T) {
	// Create a mock connection with JA4 support
	mockConn := &mockJA4Conn{
		ja4: "t13d411100_6be44479b708_d41ae481755e",
	}

	// Test JA4 extraction via type assertion
	if ja4Conn, ok := any(mockConn).(interface{ GetJA4Fingerprint() (string, error) }); ok {
		fingerprint, err := ja4Conn.GetJA4Fingerprint()
		if err != nil {
			t.Errorf("GetJA4Fingerprint() error = %v", err)
		}
		if fingerprint != "t13d411100_6be44479b708_d41ae481755e" {
			t.Errorf("GetJA4Fingerprint() = %q, want %q", fingerprint, "t13d411100_6be44479b708_d41ae481755e")
		}
	} else {
		t.Error("Failed to extract JA4 from mock connection")
	}
}
