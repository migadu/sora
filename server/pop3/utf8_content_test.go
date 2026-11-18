package pop3

import "testing"

// TestHeaderHasNonASCII: only an octet above 0x7F before the first empty line
// counts, with CRLF or bare LF line ends (strict_utf8_content, RFC 6856 §2.1).
func TestHeaderHasNonASCII(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want bool
	}{
		{"ascii", "From: a@example.com\r\nSubject: Hi\r\n\r\nBody\r\n", false},
		{"utf8 subject", "From: a@example.com\r\nSubject: Grüße\r\n\r\nBody\r\n", true},
		{"utf8 subject, bare LF", "From: a@example.com\nSubject: Grüße\n\nBody\n", true},
		{"8bit body only", "From: a@example.com\r\nSubject: Hi\r\n\r\nGrüße\r\n", false},
		{"8bit body only, bare LF", "From: a@example.com\nSubject: Hi\n\nGrüße\n", false},
		{"no empty line", "From: a@example.com\r\nSubject: Grüße", true},
		{"latin-1 header", "Subject: Gr\xfc\xdfe\r\n\r\n", true},
		{"empty", "", false},
	}
	for _, tc := range cases {
		if got := headerHasNonASCII([]byte(tc.msg)); got != tc.want {
			t.Errorf("%s: headerHasNonASCII = %v, want %v", tc.name, got, tc.want)
		}
	}
}
