package helpers

import (
	"errors"
	"testing"

	"github.com/migadu/sora/consts"
)

func TestMailboxNameHasTraversal(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		// Safe names
		{"INBOX", false},
		{"Sent", false},
		{"Archive/2024", false},
		{"Foo.Bar", false}, // dot inside a segment is fine
		{"..foo", false},   // ".." prefix, not a bare ".." segment
		{"foo..", false},   // ".." suffix, not a bare ".." segment
		{"a/b/c/d", false}, // deep but contained
		{"", false},        // empty maps to root, not traversal
		// Traversal names
		{"..", true},
		{".", true},
		{"../etc", true},
		{"../../etc/passwd", true},
		{"foo/../bar", true},
		{"foo/..", true},
		{"foo/./bar", true},
		{"Archive/../../secret", true},
	}

	for _, tt := range tests {
		if got := MailboxNameHasTraversal(tt.name); got != tt.want {
			t.Errorf("MailboxNameHasTraversal(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestMailboxNameToCreate(t *testing.T) {
	tests := []struct {
		name  string
		want  string
		valid bool
	}{
		{"INBOX", "INBOX", true},
		{"Archive/2024", "Archive/2024", true},
		{"Foo.Bar/..baz", "Foo.Bar/..baz", true}, // dots inside a level are fine
		{"Foo/", "Foo", true},                    // RFC 3501 §6.3.3: no trailing delimiter
		{"Foo/Bar//", "Foo/Bar", true},
		{"", "", false},
		{"/", "", false},
		{"//", "", false},
		{"/Foo", "", false},   // empty first level
		{"x//y", "", false},   // empty middle level
		{"x//y/", "", false},  // still empty after the trailing delimiter goes
		{"a/../b", "", false}, // traversal levels
		{"a/./b", "", false},
		{"..", "", false},
		{"Foo/.", "", false},
	}
	for _, tt := range tests {
		got, err := MailboxNameToCreate(tt.name)
		if tt.valid {
			if err != nil || got != tt.want {
				t.Errorf("MailboxNameToCreate(%q) = %q, %v; want %q, nil", tt.name, got, err, tt.want)
			}
		} else if !errors.Is(err, consts.ErrMailboxInvalidName) {
			t.Errorf("MailboxNameToCreate(%q) = %q, %v; want ErrMailboxInvalidName", tt.name, got, err)
		}
	}
}
