package delivery

import "testing"

func TestSMTPUTF8Required(t *testing.T) {
	for _, tc := range []struct {
		name, from, to, message string
		want                    bool
	}{
		{"ASCII", "sender@example.com", "recipient@example.com", "Subject: Hello\r\n\r\nHello", false},
		{"Unicode sender", "josé@example.com", "recipient@example.com", "Subject: Hello\r\n\r\nHello", true},
		{"Unicode recipient", "sender@example.com", "josé@example.com", "Subject: Hello\r\n\r\nHello", true},
		{"Unicode header", "sender@example.com", "recipient@example.com", "X-Redirected-By: josé@example.com\r\n\r\nAway", true},
		{"folded Unicode header", "sender@example.com", "recipient@example.com", "X-Redirected-By:\r\n\tjosé@example.com\r\n\r\nAway", true},
		{"LF Unicode header", "sender@example.com", "recipient@example.com", "X-Redirected-By: josé@example.com\n\nAway", true},
		{"encoded header", "sender@example.com", "recipient@example.com", "Subject: =?UTF-8?Q?Caf=C3=A9?=\r\n\r\nAway", false},
		{"8-bit body", "sender@example.com", "recipient@example.com", "Subject: Hello\r\n\r\nX-Redirected-By: josé@example.com\r\n", false},
		{"LF 8-bit body", "sender@example.com", "recipient@example.com", "Subject: Hello\n\nX-Redirected-By: josé@example.com\n", false},
		{"empty headers", "sender@example.com", "recipient@example.com", "\r\nCafé", false},
		{"header only", "sender@example.com", "recipient@example.com", "X-Redirected-By: josé@example.com", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := smtpUTF8Required(tc.from, tc.to, []byte(tc.message)); got != tc.want {
				t.Errorf("smtpUTF8Required = %t, want %t", got, tc.want)
			}
		})
	}
}
