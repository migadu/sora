package helpers

import (
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
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
			name: "invalid multipart with no children",
			bs: &imap.BodyStructureMultiPart{
				Subtype:  "mixed",
				Children: []imap.BodyStructure{},
			},
			wantErr: true,
			errMsg:  "no children",
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
			name: "invalid nested multipart with empty child",
			bs: &imap.BodyStructureMultiPart{
				Subtype: "alternative",
				Children: []imap.BodyStructure{
					&imap.BodyStructureMultiPart{
						Subtype:  "mixed",
						Children: []imap.BodyStructure{}, // Invalid!
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid child 0",
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
