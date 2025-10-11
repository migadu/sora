package managesieveproxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// TestParseLiteralStringAuthenticate tests parsing of literal string syntax in AUTHENTICATE command
func TestParseLiteralStringAuthenticate(t *testing.T) {
	tests := []struct {
		name          string
		command       string
		literalData   string
		expectedAuth  string // Expected decoded authentication data
		shouldSucceed bool
	}{
		{
			name:          "Literal string with + (non-synchronizing)",
			command:       `AUTHENTICATE "PLAIN" {40+}`,
			literalData:   "AGRlamFuQG1pZ2FkdS5jb20AY2gxYXIxU1MxbUA=",
			expectedAuth:  "\x00dejan@migadu.com\x00ch1ar1SS1m@",
			shouldSucceed: true,
		},
		{
			name:          "Literal string without + (synchronizing)",
			command:       `AUTHENTICATE "PLAIN" {40}`,
			literalData:   "AGRlamFuQG1pZ2FkdS5jb20AY2gxYXIxU1MxbUA=",
			expectedAuth:  "\x00dejan@migadu.com\x00ch1ar1SS1m@",
			shouldSucceed: true,
		},
		{
			name:          "Small literal string",
			command:       `AUTHENTICATE "PLAIN" {24+}`,
			literalData:   "AHRlc3QAdGVzdHBhc3N3b3Jk",
			expectedAuth:  "\x00test\x00testpassword",
			shouldSucceed: true,
		},
		{
			name:          "Quoted string (not literal)",
			command:       `AUTHENTICATE "PLAIN" "AHRlc3QAdGVzdHBhc3N3b3Jk"`,
			literalData:   "",
			expectedAuth:  "\x00test\x00testpassword",
			shouldSucceed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the command line
			parts := strings.Fields(tt.command)
			if len(parts) < 2 {
				t.Fatalf("Invalid command: %s", tt.command)
			}

			// Simulate what the session code does
			var saslLine string

			if len(parts) >= 3 {
				arg2 := strings.Trim(parts[2], `"`)

				// Check if it's a literal string {number+} or {number}
				if strings.HasPrefix(arg2, "{") && (strings.HasSuffix(arg2, "}") || strings.HasSuffix(arg2, "+}")) {
					// Literal string - in real code this would read from the stream
					// For testing, we use the provided literalData
					var literalSize int
					literalStr := strings.TrimPrefix(arg2, "{")
					literalStr = strings.TrimSuffix(literalStr, "}")
					literalStr = strings.TrimSuffix(literalStr, "+")

					_, err := fmt.Sscanf(literalStr, "%d", &literalSize)
					if err != nil || literalSize < 0 || literalSize > 8192 {
						if tt.shouldSucceed {
							t.Errorf("Invalid literal size: %s", arg2)
						}
						return
					}

					if len(tt.literalData) != literalSize {
						t.Errorf("Literal data length mismatch: expected %d, got %d", literalSize, len(tt.literalData))
						return
					}

					saslLine = tt.literalData
				} else {
					// Quoted string or bare string
					saslLine = strings.Trim(arg2, `"`)
				}
			}

			// Decode base64
			decoded, err := base64.StdEncoding.DecodeString(saslLine)
			if err != nil {
				if tt.shouldSucceed {
					t.Errorf("Failed to decode base64: %v", err)
				}
				return
			}

			// Verify the decoded data matches expected
			if string(decoded) != tt.expectedAuth {
				t.Errorf("Decoded auth data mismatch:\nExpected: %q\nGot:      %q", tt.expectedAuth, string(decoded))
			}

			// Parse SASL PLAIN format
			parts = strings.Split(string(decoded), "\x00")
			if len(parts) != 3 {
				t.Errorf("Invalid SASL PLAIN format: expected 3 parts, got %d", len(parts))
				return
			}

			t.Logf("Success: authzID=%q, authnID=%q, password=%q", parts[0], parts[1], parts[2])
		})
	}
}

// TestLiteralStringSize tests various literal string sizes
func TestLiteralStringSize(t *testing.T) {
	tests := []struct {
		name        string
		literalSpec string
		wantSize    int
		wantValid   bool
	}{
		{"Valid small literal", "{10+}", 10, true},
		{"Valid medium literal", "{100}", 100, true},
		{"Valid large literal", "{8192}", 8192, true},
		{"Too large literal", "{8193}", 8193, false},
		{"Negative literal", "{-1}", -1, false},
		{"Zero literal", "{0}", 0, true},
		{"Invalid format", "{abc}", 0, false},
		{"Missing brace", "10+}", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var literalSize int

			// Check format first - must have { and }
			if !strings.HasPrefix(tt.literalSpec, "{") ||
				!(strings.HasSuffix(tt.literalSpec, "}") || strings.HasSuffix(tt.literalSpec, "+}")) {
				valid := false
				if valid != tt.wantValid {
					t.Errorf("Validity mismatch: expected %v, got %v (invalid format)", tt.wantValid, valid)
				}
				return
			}

			literalStr := strings.TrimPrefix(tt.literalSpec, "{")
			literalStr = strings.TrimSuffix(literalStr, "}")
			literalStr = strings.TrimSuffix(literalStr, "+")

			_, err := fmt.Sscanf(literalStr, "%d", &literalSize)
			valid := err == nil && literalSize >= 0 && literalSize <= 8192

			if valid != tt.wantValid {
				t.Errorf("Validity mismatch: expected %v, got %v (size=%d, err=%v)", tt.wantValid, valid, literalSize, err)
			}

			if valid && literalSize != tt.wantSize {
				t.Errorf("Size mismatch: expected %d, got %d", tt.wantSize, literalSize)
			}
		})
	}
}

// TestLiteralStringReading simulates reading literal data from a stream
func TestLiteralStringReading(t *testing.T) {
	tests := []struct {
		name         string
		streamData   string
		literalSpec  string
		expectedData string
		shouldError  bool
	}{
		{
			name:         "Read exact size",
			streamData:   "Hello, World!\r\n",
			literalSpec:  "{13+}",
			expectedData: "Hello, World!",
			shouldError:  false,
		},
		{
			name:         "Read with trailing data",
			streamData:   "Test data\r\nExtra line\r\n",
			literalSpec:  "{9+}",
			expectedData: "Test data",
			shouldError:  false,
		},
		{
			name:         "Empty literal",
			streamData:   "\r\n",
			literalSpec:  "{0+}",
			expectedData: "",
			shouldError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse literal size
			var literalSize int
			literalStr := strings.TrimPrefix(tt.literalSpec, "{")
			literalStr = strings.TrimSuffix(literalStr, "}")
			literalStr = strings.TrimSuffix(literalStr, "+")

			_, err := fmt.Sscanf(literalStr, "%d", &literalSize)
			if err != nil {
				t.Fatalf("Failed to parse literal size: %v", err)
			}

			// Simulate reading from stream
			reader := bufio.NewReader(strings.NewReader(tt.streamData))
			literalData := make([]byte, literalSize)

			n, err := reader.Read(literalData)
			if err != nil && !tt.shouldError {
				t.Errorf("Unexpected error reading literal: %v", err)
				return
			}

			if n != literalSize {
				t.Errorf("Read size mismatch: expected %d, got %d", literalSize, n)
				return
			}

			if string(literalData) != tt.expectedData {
				t.Errorf("Data mismatch:\nExpected: %q\nGot:      %q", tt.expectedData, string(literalData))
			}
		})
	}
}
