package helpers

import (
	"testing"

	"github.com/emersion/go-imap/v2"
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
