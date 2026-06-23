package helpers

import "testing"

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
