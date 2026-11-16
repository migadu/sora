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

		// RFC 3501 §5.1.3: modified BASE64 MUST NOT represent a printable
		// US-ASCII character (0x20-0x7e). "&" has its own form, "&-".
		{"encoded delimiter", "a&AC8-b", "", true},
		{"encoded letter", "&AGE-", "", true},
		{"encoded space", "&ACA-", "", true},
		{"encoded tilde", "&AH4-", "", true},
		{"encoded ampersand", "&ACY-", "", true},
		{"delimiter after non-ascii in one shift", "&AOkALw-", "", true},
		{"letter after non-ascii in one shift", "x&AOkAYQ-", "", true},

		// Control characters and DEL cannot represent themselves, so BASE64 is their form.
		{"encoded unit separator 0x1f", "&AB8-", "\x1f", false},
		{"encoded del 0x7f", "&AH8-", "\x7f", false},

		// RFC 3501 §5.1.3 / RFC 9051 §A.1: when Modified UTF-7 shifts ('&') are present,
		// octets outside printable US-ASCII (0x20..0x7e) must not appear literally.
		{"raw utf8 with shift", "Café &AOk-", "", true},
		{"raw utf8 with ampersand escape", "Café &- Thé", "", true},
		{"raw unit separator 0x1f outside shift", "\x1f&AOk-", "", true},
		{"raw nul 0x00 outside shift", "\x00&-", "", true},
		{"raw del 0x7f outside shift", "\x7f&-", "", true},
		{"raw 0xff after ampersand escape", "&-\xff", "", true},
		{"boundary space 0x20 outside shift", " &AOk-", " é", false},
		{"boundary tilde 0x7e outside shift", "~&AOk-", "~é", false},
		{"utf8 without ampersand fast path", "Café", "Café", false},

		// RFC 3501 §5.1.3: null shifts ("-&" while in BASE64) are not permitted.
		// "&U,BTFw-&ZeVnLIqe-" is the RFC's own example of a superfluous shift.
		{"null shift", "&AOk-&AOk-", "", true},
		{"null shift rfc example", "&U,BTFw-&ZeVnLIqe-", "", true},
		{"superfluous shift corrected", "&U,BTF2XlZyyKng-", "台北日本語", false},
		{"escaped ampersand between shifts", "&AOk-&-&AOk-", "é&é", false},
		{"ascii between shifts", "&AOk-a&AOk-", "éaé", false},

		// RFC 9051 §A.1: only the modified base64 alphabet is permitted in modified
		// base64 text; RFC 2152 omits the "=" pad character.
		{"pad in segment", "&AOk=-", "", true},
		{"pads after surrogate pair", "&2D3eCg==-", "", true},
		{"crlf in segment", "&AO\r\n\r\nk-", "", true},
		{"lf in segment", "&A\n\n\n\nOk-", "", true},
		{"standard base64 slash", "&U/BTFw-", "", true},

		// RFC 2152: discarded bits at the end of the segment must be zero.
		{"non-zero 2 discarded bits", "&AOl-", "", true},
		{"non-zero 2 discarded bits 2", "&AOn-", "", true},
		{"non-zero 4 discarded bits", "&AOkA6R-", "", true},
		{"zero 4 discarded bits", "&AOkA6Q-", "éé", false},

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
