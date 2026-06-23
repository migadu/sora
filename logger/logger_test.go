package logger

import "testing"

// TestSanitizeSyslogLine verifies CR/LF are collapsed so attacker-controlled fields
// cannot inject forged syslog lines (audit M6).
func TestSanitizeSyslogLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"normal message", "normal message"},
		{"line1\nline2", "line1\\nline2"},
		{"a\r\nb", "a\\r\\nb"},
		{"user=admin\nlevel=INFO msg=\"forged audit line\"", "user=admin\\nlevel=INFO msg=\"forged audit line\""},
		{"trailing\r", "trailing\\r"},
	}
	for _, c := range cases {
		if got := sanitizeSyslogLine(c.in); got != c.want {
			t.Errorf("sanitizeSyslogLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
