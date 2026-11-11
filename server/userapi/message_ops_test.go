package userapi

import (
	"strings"
	"testing"
)

func TestIsValidFlag(t *testing.T) {
	tests := []struct {
		flag  string
		valid bool
	}{
		{"\\Seen", true},
		{"\\Answered", true},
		{"\\Flagged", true},
		{"\\Deleted", true},
		{"\\Draft", true},
		// IMAP flag names are case-insensitive, and db.UpdateMessageFlags folds them.
		{"\\seen", true},
		{"\\FLAGGED", true},
		// \Recent cannot be changed by any client (RFC 3501 §2.3.2).
		{"\\Recent", false},
		{"\\recent", false},
		{"\\Unknown", false},
		{"\\", false},
		// Keywords.
		{"$Forwarded", true},
		{"Work", true},
		{"$MailFlagBit0", true},
		// A system flag name without its backslash is a client that meant the
		// system flag, not a keyword.
		{"Seen", false},
		{"flagged", false},
		{"Draft", false},
		{"Recent", true}, // not a settable system flag, so an ordinary keyword
		{"has space", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isValidFlag(tt.flag); got != tt.valid {
			t.Errorf("isValidFlag(%q) = %v, want %v", tt.flag, got, tt.valid)
		}
	}
}

func TestInvalidFlagMessage(t *testing.T) {
	if got := invalidFlagMessage("Seen"); !strings.Contains(got, `\Seen`) {
		t.Errorf("invalidFlagMessage(%q) = %q, want a pointer to \\Seen", "Seen", got)
	}
	if got := invalidFlagMessage("\\Recent"); got != `Invalid flag: \Recent` {
		t.Errorf("invalidFlagMessage(%q) = %q", "\\Recent", got)
	}
}
