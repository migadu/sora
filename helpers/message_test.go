package helpers

import (
	"strings"
	"testing"

	"github.com/emersion/go-message"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
)

func TestValidateBodyStructure(t *testing.T) {
	tests := []struct {
		name    string
		bs      imap.BodyStructure
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid single part",
			bs: &imap.BodyStructureSinglePart{
				Type:    "text",
				Subtype: "plain",
			},
			wantErr: false,
		},
		{
			name: "valid multipart with children",
			bs: &imap.BodyStructureMultiPart{
				Subtype: "mixed",
				Children: []imap.BodyStructure{
					&imap.BodyStructureSinglePart{
						Type:    "text",
						Subtype: "plain",
					},
					&imap.BodyStructureSinglePart{
						Type:    "text",
						Subtype: "html",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid multipart with no children (go-imap cannot serialize this)",
			bs: &imap.BodyStructureMultiPart{
				Subtype:  "report",
				Children: []imap.BodyStructure{},
			},
			wantErr: true,
			errMsg:  "multipart structure has no children",
		},
		{
			name: "valid nested multipart",
			bs: &imap.BodyStructureMultiPart{
				Subtype: "alternative",
				Children: []imap.BodyStructure{
					&imap.BodyStructureMultiPart{
						Subtype: "mixed",
						Children: []imap.BodyStructure{
							&imap.BodyStructureSinglePart{
								Type:    "text",
								Subtype: "plain",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid nested multipart with empty child (go-imap cannot serialize this)",
			bs: &imap.BodyStructureMultiPart{
				Subtype: "alternative",
				Children: []imap.BodyStructure{
					&imap.BodyStructureMultiPart{
						Subtype:  "mixed",
						Children: []imap.BodyStructure{}, // Invalid - go-imap panics
					},
				},
			},
			wantErr: true,
			errMsg:  "multipart structure has no children",
		},
		{
			name: "valid message/rfc822",
			bs: &imap.BodyStructureSinglePart{
				Type:    "message",
				Subtype: "rfc822",
				MessageRFC822: &imap.BodyStructureMessageRFC822{
					BodyStructure: &imap.BodyStructureSinglePart{
						Type:    "text",
						Subtype: "plain",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBodyStructure(&tt.bs)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateBodyStructure() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateBodyStructure() error = %v, should contain %q", err, tt.errMsg)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && stringContains(s, substr))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestStripBase64DataURIs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "HTML with embedded base64 image",
			input:    `<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==" alt="test">`,
			expected: `<img src="[embedded-image]" alt="test">`,
		},
		{
			name:     "Multiple embedded images",
			input:    `<img src="data:image/jpeg;base64,` + strings.Repeat("A", 200) + `"> <img src="data:image/gif;base64,` + strings.Repeat("B", 150) + `">`,
			expected: `<img src="[embedded-image]"> <img src="[embedded-image]">`,
		},
		{
			name:     "Short base64 not stripped (< 50 chars)",
			input:    `<img src="data:image/png;base64,ABC123">`,
			expected: `<img src="data:image/png;base64,ABC123">`,
		},
		{
			name:     "No base64 data URIs",
			input:    `<img src="https://example.com/image.png">`,
			expected: `<img src="https://example.com/image.png">`,
		},
		{
			name:     "Mixed content",
			input:    `<p>Hello</p><img src="data:image/png;base64,` + strings.Repeat("C", 500) + `"><p>World</p>`,
			expected: `<p>Hello</p><img src="[embedded-image]"><p>World</p>`,
		},
		{
			name:     "Very large base64 (simulating newsletter)",
			input:    `<html><body><img src="data:image/png;base64,` + strings.Repeat("X", 100000) + `"></body></html>`,
			expected: `<html><body><img src="[embedded-image]"></body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripBase64DataURIs(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStripBase64DataURIs_SizeReduction(t *testing.T) {
	// Test that stripping actually reduces size significantly
	largeBase64 := strings.Repeat("A", 1000000) // 1 MB of base64
	input := `<img src="data:image/png;base64,` + largeBase64 + `">`

	result := stripBase64DataURIs(input)

	// Original should be > 1MB, result should be < 100 bytes
	assert.Greater(t, len(input), 1000000)
	assert.Less(t, len(result), 100)
	assert.Contains(t, result, "[embedded-image]")
}

func TestStripBase64DataURIs_VariousFormats(t *testing.T) {
	tests := []struct {
		name     string
		mimeType string
	}{
		{"PNG", "data:image/png;base64,"},
		{"JPEG", "data:image/jpeg;base64,"},
		{"GIF", "data:image/gif;base64,"},
		{"SVG", "data:image/svg+xml;base64,"},
		{"WebP", "data:image/webp;base64,"},
		{"PDF", "data:application/pdf;base64,"},
		{"Any type", "data:foo/bar;base64,"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base64Data := strings.Repeat("A", 200) // Long enough to match regex
			input := tt.mimeType + base64Data
			result := stripBase64DataURIs(input)

			assert.NotContains(t, result, base64Data, "Base64 data should be stripped")
			assert.Contains(t, result, "[embedded-image]")
		})
	}
}

func TestExtractPlaintextBody_MalformedContentTransferEncoding(t *testing.T) {
	// Test that malformed Content-Transfer-Encoding headers don't crash parsing.
	// Real-world example: "Content-Transfer-Encoding: 7bit <center>" from buggy email clients.
	tests := []struct {
		name       string
		rawMessage string
		expectBody bool
	}{
		{
			name: "multipart with malformed encoding in second part",
			rawMessage: "From: sender@example.com\r\n" +
				"To: receiver@example.com\r\n" +
				"Subject: Test\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: multipart/alternative; boundary=\"boundary123\"\r\n" +
				"\r\n" +
				"--boundary123\r\n" +
				"Content-Type: text/plain; charset=utf-8\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"First part is fine.\r\n" +
				"--boundary123\r\n" +
				"Content-Type: text/html; charset=utf-8\r\n" +
				"Content-Transfer-Encoding: 7bit <center>\r\n" + // MALFORMED!
				"\r\n" +
				"<html><body>This part has malformed encoding</body></html>\r\n" +
				"--boundary123--\r\n",
			expectBody: true, // Should return the first (good) part
		},
		{
			name: "single part with malformed encoding returns degraded entity",
			rawMessage: "From: sender@example.com\r\n" +
				"To: receiver@example.com\r\n" +
				"Subject: Test\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: text/plain; charset=utf-8\r\n" +
				"Content-Transfer-Encoding: 7bit <garbage>\r\n" + // MALFORMED!
				"\r\n" +
				"Body text here.\r\n",
			expectBody: false, // message.Read returns degraded entity but body is not decodable
		},
		{
			name: "multipart with malformed Content-Type media parameter",
			rawMessage: "From: sender@example.com\r\n" +
				"To: receiver@example.com\r\n" +
				"Subject: Test\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: multipart/alternative; boundary=\"boundary456\"\r\n" +
				"\r\n" +
				"--boundary456\r\n" +
				"Content-Type: text/plain; charset=utf-8\r\n" +
				"\r\n" +
				"Good text part.\r\n" +
				"--boundary456\r\n" +
				"Content-Type: text/html; charset=utf-8; invalid-param\r\n" + // MALFORMED media parameter!
				"\r\n" +
				"<html><body>HTML with bad Content-Type</body></html>\r\n" +
				"--boundary456--\r\n",
			expectBody: true, // Should return the first (good) part
		},
		{
			name: "multipart with truncated part (unexpected EOF)",
			rawMessage: "From: sender@example.com\r\n" +
				"To: receiver@example.com\r\n" +
				"Subject: Test\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: multipart/alternative; boundary=\"boundary789\"\r\n" +
				"\r\n" +
				"--boundary789\r\n" +
				"Content-Type: text/plain; charset=utf-8\r\n" +
				"\r\n" +
				"Good text part.\r\n" +
				"--boundary789\r\n" +
				"Content-Type: text/html; charset=utf-8\r\n" +
				"Content-Transfer-Encoding: base64\r\n" +
				"\r\n" +
				"TRUNCATED==", // Truncated base64 - will cause read error
			expectBody: true, // Should return the first (good) part
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse message using go-message (same as server.ParseMessage does).
			// For unknown encodings, message.Read returns BOTH a degraded entity AND an error.
			// IsUnknownEncoding(err) would be true — server.ParseMessage handles this.
			messageContent, err := message.Read(strings.NewReader(tt.rawMessage))
			if err != nil && !message.IsUnknownEncoding(err) {
				t.Fatalf("message.Read() failed with unexpected error: %v", err)
			}
			if messageContent == nil {
				t.Fatal("message.Read() returned nil entity")
			}

			// Extract plaintext body - should not crash even with malformed encoding
			result, extractErr := ExtractPlaintextBody(messageContent)

			if tt.expectBody {
				assert.NotNil(t, result)
				assert.NotEmpty(t, *result)
				// May or may not have an error depending on whether parts were skipped
				// If error is present, it should describe skipped parts
				if extractErr != nil {
					assert.Contains(t, extractErr.Error(), "skipped part")
					t.Logf("Extraction succeeded with warnings: %v", extractErr)
				}
			} else {
				// For degraded entities, we may get nil result but no crash
				if extractErr != nil {
					t.Logf("Extraction failed as expected: %v", extractErr)
				}
			}
		})
	}
}
