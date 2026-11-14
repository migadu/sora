package helpers

import (
	"testing"
)

func TestDecodeModifiedUTF7(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		// Basic ASCII - no encoding needed
		{"plain ascii", "INBOX", "INBOX", false},
		{"plain with slash", "Folder/Subfolder", "Folder/Subfolder", false},
		{"empty string", "", "", false},

		// Ampersand escape
		{"ampersand escape", "&-", "&", false},
		{"ampersand in text", "Tom &- Jerry", "Tom & Jerry", false},

		// Common non-ASCII mailbox names from Dovecot
		{"german umlaut o", "&APY-bersicht", "öbersicht", false},
		{"german umlaut u", "&APw-bersicht", "übersicht", false},
		{"french accents", "R&AOk-pertoire", "Répertoire", false},
		{"sent french", "&AMk-l&AOk-ments envoy&AOk-s", "Éléments envoyés", false},
		{"japanese", "&ZeVnLIqe-", "日本語", false},
		{"taipei", "&U,BTFw-", "台北", false},

		// Mixed ASCII and encoded
		{"mixed", "&APw- und &APY-", "ü und ö", false},
		{"folder with encoded part", ".R&AOk-pertoire", ".Répertoire", false},

		// Surrogate pairs (emoji)
		{"emoji smiley", "&2D3eCg-", "\U0001f60a", false},

		// Error cases
		{"unterminated shift", "&abc", "", true},
		{"unterminated shift 2", "folder&abc", "", true},
		{"lone surrogate", "&2AA-", "", true},

		// Edge cases
		{"just ampersand-dash", "&-", "&", false},
		{"multiple ampersand escapes", "&-&-&-", "&&&", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeModifiedUTF7(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeModifiedUTF7(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("DecodeModifiedUTF7(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEncodeModifiedUTF7(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain ascii", "INBOX", "INBOX"},
		{"plain with slash", "Folder/Subfolder", "Folder/Subfolder"},
		{"empty string", "", ""},
		{"ampersand", "&", "&-"},
		{"multiple ampersands", "&&&", "&-&-&-"},
		{"ampersand in text", "Tom & Jerry", "Tom &- Jerry"},
		{"ampersand resembling shift", "R&D25-Notes", "R&-D25-Notes"},
		{"german umlaut o", "öbersicht", "&APY-bersicht"},
		{"german umlaut u", "übersicht", "&APw-bersicht"},
		{"french accents", "Répertoire", "R&AOk-pertoire"},
		{"sent french", "Éléments envoyés", "&AMk-l&AOk-ments envoy&AOk-s"},
		{"hierarchical non-ascii", "Données/Q1", "Donn&AOk-es/Q1"},
		{"japanese", "日本語", "&ZeVnLIqe-"},
		{"taipei comma alphabet", "台北", "&U,BTFw-"},
		{"mixed with ampersand", "ö&ü", "&APY-&-&APw-"},
		{"emoji smiley surrogate pair", "\U0001f60a", "&2D3eCg-"},
		{"del 0x7f", "a\x7fb", "a&AH8-b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeModifiedUTF7(tt.input)
			if got != tt.want {
				t.Errorf("EncodeModifiedUTF7(%q) = %q, want %q", tt.input, got, tt.want)
			}
			decoded, err := DecodeModifiedUTF7(got)
			if err != nil {
				t.Fatalf("DecodeModifiedUTF7(%q) error = %v", got, err)
			}
			if decoded != tt.input {
				t.Errorf("round-trip DecodeModifiedUTF7(EncodeModifiedUTF7(%q)) = %q", tt.input, decoded)
			}
		})
	}
}
