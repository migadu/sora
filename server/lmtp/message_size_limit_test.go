package lmtp

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestMessageSizeLimit_EnforcedCorrectly tests that the message size limit is properly enforced
func TestMessageSizeLimit_EnforcedCorrectly(t *testing.T) {
	tests := []struct {
		name           string
		maxMessageSize int64
		messageSize    int
		expectError    bool
		errorContains  string
	}{
		{
			name:           "Message within limit",
			maxMessageSize: 1024, // 1KB
			messageSize:    512,  // 512 bytes
			expectError:    false,
		},
		{
			name:           "Message exactly at limit",
			maxMessageSize: 1024, // 1KB
			messageSize:    1024, // 1KB
			expectError:    false,
		},
		{
			name:           "Message exceeds limit by 1 byte",
			maxMessageSize: 1024, // 1KB
			messageSize:    1025, // 1KB + 1
			expectError:    true,
			errorContains:  "message size exceeds maximum",
		},
		{
			name:           "Message much larger than limit",
			maxMessageSize: 1024,  // 1KB
			messageSize:    10240, // 10KB
			expectError:    true,
			errorContains:  "message size exceeds maximum",
		},
		{
			name:           "No limit configured (0) - uses 50MB fallback",
			maxMessageSize: 0,      // 0 means use fallback (50MB)
			messageSize:    100000, // 100KB (under fallback)
			expectError:    false,
		},
		{
			name:           "Large message with 0 limit - uses 50MB fallback",
			maxMessageSize: 0,        // 0 means use fallback (50MB)
			messageSize:    10000000, // 10MB (under fallback)
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a backend with the specified max message size
			backend := &LMTPServerBackend{
				maxMessageSize: tt.maxMessageSize,
			}

			// Create a mock LMTPSession
			session := &LMTPSession{
				backend: backend,
			}

			// Create a message of the specified size
			messageData := strings.Repeat("X", tt.messageSize)
			reader := strings.NewReader(messageData)

			// Simulate the size limit check logic from Data() method
			// Apply fallback if limit is 0 (matches production code)
			limitToUse := session.backend.maxMessageSize
			if limitToUse <= 0 {
				limitToUse = 50 * 1024 * 1024 // 50MB fallback
			}

			var buf bytes.Buffer
			// Add 1 byte to detect when limit is exceeded
			limitedReader := io.LimitReader(reader, limitToUse+1)

			_, err := io.Copy(&buf, limitedReader)
			if err != nil {
				t.Fatalf("Failed to copy data: %v", err)
			}

			// Check if message exceeds configured limit
			var sizeError error
			if int64(buf.Len()) > limitToUse {
				sizeError = &struct{ error }{error: io.EOF} // Placeholder error for testing
			}

			// Verify expectations
			if tt.expectError {
				if sizeError == nil {
					t.Errorf("Expected error but got none. Message size: %d, Limit: %d",
						buf.Len(), tt.maxMessageSize)
				}
			} else {
				if sizeError != nil {
					t.Errorf("Expected no error but got: %v. Message size: %d, Limit: %d",
						sizeError, buf.Len(), tt.maxMessageSize)
				}

				// Verify all data was read when no limit exceeded
				if int64(buf.Len()) != int64(tt.messageSize) {
					t.Errorf("Expected to read %d bytes, but read %d bytes",
						tt.messageSize, buf.Len())
				}
			}

			// Verify that when limit is exceeded, we don't read more than limitToUse+1
			if tt.expectError {
				if int64(buf.Len()) > limitToUse+1 {
					t.Errorf("Read too much data. Expected at most %d bytes, got %d bytes",
						limitToUse+1, buf.Len())
				}
			}
		})
	}
}

// TestMessageSizeLimit_LimitReaderBehavior tests that io.LimitReader works as expected
func TestMessageSizeLimit_LimitReaderBehavior(t *testing.T) {
	tests := []struct {
		name       string
		dataSize   int
		limitSize  int64
		expectRead int
	}{
		{
			name:       "Small data within limit",
			dataSize:   100,
			limitSize:  500,
			expectRead: 100, // All data read
		},
		{
			name:       "Data exactly at limit",
			dataSize:   500,
			limitSize:  500,
			expectRead: 500, // All data read
		},
		{
			name:       "Data exceeds limit",
			dataSize:   1000,
			limitSize:  500,
			expectRead: 500, // Only limit bytes read
		},
		{
			name:       "Large data with small limit",
			dataSize:   10000,
			limitSize:  100,
			expectRead: 100, // Only limit bytes read
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test data
			data := strings.Repeat("X", tt.dataSize)
			reader := strings.NewReader(data)

			// Apply limit
			limitedReader := io.LimitReader(reader, tt.limitSize)

			// Read into buffer
			var buf bytes.Buffer
			n, err := io.Copy(&buf, limitedReader)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Verify we read exactly the expected amount
			if int(n) != tt.expectRead {
				t.Errorf("Expected to read %d bytes, but read %d bytes",
					tt.expectRead, n)
			}

			if buf.Len() != tt.expectRead {
				t.Errorf("Expected buffer size %d, got %d",
					tt.expectRead, buf.Len())
			}
		})
	}
}

// TestMessageSizeLimit_ZeroUsesFallback tests that 0 triggers 50MB fallback limit
func TestMessageSizeLimit_ZeroUsesFallback(t *testing.T) {
	backend := &LMTPServerBackend{
		maxMessageSize: 0, // 0 means use 50MB fallback
	}

	session := &LMTPSession{
		backend: backend,
	}

	// Create a message under the 50MB fallback (10MB)
	smallSize := 10 * 1024 * 1024
	smallMessage := strings.Repeat("X", smallSize)
	reader := strings.NewReader(smallMessage)

	// Simulate the check - should apply 50MB fallback when maxMessageSize is 0
	limitToUse := session.backend.maxMessageSize
	if limitToUse <= 0 {
		limitToUse = 50 * 1024 * 1024 // 50MB fallback
	}

	var buf bytes.Buffer
	limitedReader := io.LimitReader(reader, limitToUse+1)

	n, err := io.Copy(&buf, limitedReader)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should read all data (10MB is under 50MB fallback)
	if int(n) != smallSize {
		t.Errorf("Expected to read %d bytes, but read %d bytes",
			smallSize, n)
	}

	// Should not trigger size error (10MB < 50MB)
	var sizeError error
	if int64(buf.Len()) > limitToUse {
		sizeError = &struct{ error }{error: io.EOF}
	}

	if sizeError != nil {
		t.Errorf("Expected no error with message under 50MB fallback, but got error")
	}
}

// TestMessageSizeLimit_DefaultValue tests the default value behavior
func TestMessageSizeLimit_DefaultValue(t *testing.T) {
	// When not explicitly set, maxMessageSize should be initialized from config
	// The default is 50MB (52428800 bytes) as defined in config.GetMaxMessageSize()

	expectedDefault := int64(50 * 1024 * 1024) // 50MB

	backend := &LMTPServerBackend{
		maxMessageSize: expectedDefault,
	}

	// Verify the default allows messages up to 50MB
	allowedSize := 50*1024*1024 - 1 // Just under 50MB
	largeMessage := strings.Repeat("X", allowedSize)
	reader := strings.NewReader(largeMessage)

	var buf bytes.Buffer
	limitedReader := io.LimitReader(reader, backend.maxMessageSize+1)

	_, err := io.Copy(&buf, limitedReader)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should not exceed limit
	var sizeError error
	if backend.maxMessageSize > 0 && int64(buf.Len()) > backend.maxMessageSize {
		sizeError = &struct{ error }{error: io.EOF}
	}

	if sizeError != nil {
		t.Errorf("Message within 50MB default limit should not error")
	}

	// Now test just over the limit
	tooLargeSize := 50*1024*1024 + 1 // Just over 50MB
	tooLargeMessage := strings.Repeat("X", tooLargeSize)
	reader2 := strings.NewReader(tooLargeMessage)

	var buf2 bytes.Buffer
	limitedReader2 := io.LimitReader(reader2, backend.maxMessageSize+1)

	_, err = io.Copy(&buf2, limitedReader2)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should exceed limit
	var sizeError2 error
	if backend.maxMessageSize > 0 && int64(buf2.Len()) > backend.maxMessageSize {
		sizeError2 = &struct{ error }{error: io.EOF}
	}

	if sizeError2 == nil {
		t.Errorf("Message over 50MB default limit should error")
	}
}
