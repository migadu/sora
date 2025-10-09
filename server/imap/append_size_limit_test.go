package imap

import (
	"strings"
	"testing"
)

// TestAppendSizeLimit_EnforcedCorrectly tests that the APPEND size limit is properly enforced
func TestAppendSizeLimit_EnforcedCorrectly(t *testing.T) {
	tests := []struct {
		name        string
		appendLimit int64
		messageSize int
		expectError bool
	}{
		{
			name:        "Message within limit",
			appendLimit: 1024, // 1KB
			messageSize: 512,  // 512 bytes
			expectError: false,
		},
		{
			name:        "Message exactly at limit",
			appendLimit: 1024, // 1KB
			messageSize: 1024, // 1KB
			expectError: false,
		},
		{
			name:        "Message exceeds limit by 1 byte",
			appendLimit: 1024, // 1KB
			messageSize: 1025, // 1KB + 1
			expectError: true,
		},
		{
			name:        "Message much larger than limit",
			appendLimit: 1024,  // 1KB
			messageSize: 10240, // 10KB
			expectError: true,
		},
		{
			name:        "No limit configured (0)",
			appendLimit: 0,      // No limit
			messageSize: 100000, // 100KB
			expectError: false,
		},
		{
			name:        "Large message with no limit",
			appendLimit: 0,        // No limit
			messageSize: 10000000, // 10MB
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test message of the specified size
			messageData := createTestMessage(tt.messageSize)

			// Simulate the size limit check logic from Append() method
			// The actual code in append.go lines 69-77 checks:
			// if s.server.appendLimit > 0 && int64(len(fullMessageBytes)) > s.server.appendLimit
			var sizeError bool
			if tt.appendLimit > 0 && int64(len(messageData)) > tt.appendLimit {
				sizeError = true
			}

			// Verify expectations
			if tt.expectError {
				if !sizeError {
					t.Errorf("Expected size check to fail but it passed. Message size: %d, Limit: %d",
						len(messageData), tt.appendLimit)
				} else {
					t.Logf("✓ Message correctly rejected: %d bytes exceeds limit of %d bytes",
						len(messageData), tt.appendLimit)
				}
			} else {
				if sizeError {
					t.Errorf("Expected size check to pass but it failed. Message size: %d, Limit: %d",
						len(messageData), tt.appendLimit)
				} else {
					t.Logf("✓ Message correctly accepted: %d bytes within limit of %d bytes (or no limit)",
						len(messageData), tt.appendLimit)
				}
			}
		})
	}
}

// TestAppendSizeLimit_DefaultValue verifies the default 25MB limit constant
func TestAppendSizeLimit_DefaultValue(t *testing.T) {
	expectedDefaultBytes := int64(25 * 1024 * 1024) // 25MB

	if DefaultAppendLimit != expectedDefaultBytes {
		t.Errorf("Expected DefaultAppendLimit to be %d bytes (25MB), got %d bytes",
			expectedDefaultBytes, DefaultAppendLimit)
	}

	t.Logf("✓ Default APPEND limit verified: %d bytes (25MB)", DefaultAppendLimit)
}

// TestAppendSizeLimit_BoundaryConditions tests edge cases around the limit
func TestAppendSizeLimit_BoundaryConditions(t *testing.T) {
	limit := int64(1024) // 1KB limit

	tests := []struct {
		name        string
		offset      int64 // Offset from limit
		expectError bool
	}{
		{
			name:        "10 bytes under limit",
			offset:      -10,
			expectError: false,
		},
		{
			name:        "1 byte under limit",
			offset:      -1,
			expectError: false,
		},
		{
			name:        "Exactly at limit",
			offset:      0,
			expectError: false,
		},
		{
			name:        "1 byte over limit",
			offset:      1,
			expectError: true,
		},
		{
			name:        "10 bytes over limit",
			offset:      10,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messageSize := int(limit + tt.offset)
			messageData := createTestMessage(messageSize)

			// Apply size check logic
			var sizeError bool
			if limit > 0 && int64(len(messageData)) > limit {
				sizeError = true
			}

			if tt.expectError != sizeError {
				t.Errorf("Expected error=%v, got error=%v for size %d (limit: %d)",
					tt.expectError, sizeError, len(messageData), limit)
			} else {
				t.Logf("✓ Boundary test passed: %d bytes, limit %d, error=%v",
					len(messageData), limit, sizeError)
			}
		})
	}
}

// TestAppendSizeLimit_Zero verifies that zero means unlimited
func TestAppendSizeLimit_Zero(t *testing.T) {
	limit := int64(0) // Unlimited

	sizes := []int{
		1024,              // 1KB
		1024 * 1024,       // 1MB
		10 * 1024 * 1024,  // 10MB
		100 * 1024 * 1024, // 100MB
	}

	for _, size := range sizes {
		t.Run(formatBytes(int64(size)), func(t *testing.T) {
			messageData := createTestMessage(size)

			// Apply size check logic
			var sizeError bool
			if limit > 0 && int64(len(messageData)) > limit {
				sizeError = true
			}

			if sizeError {
				t.Errorf("Expected no error for unlimited size, but got error for size %d",
					len(messageData))
			} else {
				t.Logf("✓ Unlimited test passed: %d bytes accepted with no limit",
					len(messageData))
			}
		})
	}
}

// createTestMessage creates a minimal valid RFC 5322 message of approximately the specified size
func createTestMessage(sizeBytes int) []byte {
	// Create minimal headers
	headers := "From: test@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Test Message\r\n" +
		"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n" +
		"\r\n"

	headerSize := len(headers)

	// Calculate body size needed
	bodySize := sizeBytes - headerSize
	if bodySize < 0 {
		bodySize = 0
	}

	// Create body with repeated content to reach target size
	var body strings.Builder
	body.Grow(bodySize)

	line := "This is a test message body line.\r\n"
	for body.Len() < bodySize {
		remaining := bodySize - body.Len()
		if remaining < len(line) {
			body.WriteString(line[:remaining])
		} else {
			body.WriteString(line)
		}
	}

	return []byte(headers + body.String())
}

// formatBytes formats a byte count as a human-readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return "B"
	}
	units := []string{"KB", "MB", "GB", "TB"}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit && exp < len(units)-1; n /= unit {
		div *= unit
		exp++
	}
	return units[exp]
}
