package delivery

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-message"
)

func TestVacationMIMETransferWireLimits(t *testing.T) {
	for _, tc := range []struct {
		name, encoding, body string
		valid                bool
	}{
		{"base64 76 columns", "base64", strings.Repeat("A", 76) + "\r\nAAAA", true},
		{"base64 80 columns", "base64", strings.Repeat("A", 80), false},
		{"base64 bare LF", "base64", "QXdheQ==\n", false},
		{"base64 bare CR", "base64", "QXdheQ==\r", false},
		{"7bit 998 columns", "7bit", strings.Repeat("a", 998) + "\r\nend", true},
		{"7bit 999 columns", "7bit", strings.Repeat("a", 999), false},
		{"7bit high byte", "7bit", "caf\xe9", false},
		{"default high byte", "", "caf\xe9", false},
		{"7bit DEL permitted", "7bit", "a\x7f", true},
		{"7bit NUL", "7bit", "a\x00b", false},
		{"7bit bare CR", "7bit", "a\rb", false},
		{"7bit bare LF", "7bit", "a\nb", false},
		{"8bit high byte", "8bit", "caf\xe9", true},
		{"8bit 998 columns", "8bit", strings.Repeat("\xff", 998) + "\r\nend", true},
		{"8bit 999 columns", "8bit", strings.Repeat("\xff", 999), false},
		{"8bit NUL", "8bit", "a\x00b", false},
		{"8bit bare CR", "8bit", "a\rb", false},
		{"8bit bare LF", "8bit", "a\nb", false},
		{"binary arbitrary bytes and long line", "binary", strings.Repeat("\xff", 4096) + "\x00\r\n\n\r", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason := "Content-Type: application/octet-stream\r\n"
			if tc.encoding != "" {
				reason += "Content-Transfer-Encoding: " + tc.encoding + "\r\n"
			}
			reason += "\r\n" + tc.body
			assertVacationMIMEWire(t, reason, tc.valid)
		})
	}
}

func TestVacationMIMEContainerTransferLimits(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		valid        bool
	}{
		{"7bit multipart cannot carry binary high byte", "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Transfer-Encoding: binary\r\n\r\ncaf\xe9\r\n--b--\r\n", false},
		{"8bit multipart cannot carry binary NUL", "Content-Type: multipart/mixed; boundary=b\r\nContent-Transfer-Encoding: 8bit\r\n\r\n--b\r\nContent-Transfer-Encoding: binary\r\n\r\na\x00b\r\n--b--\r\n", false},
		{"7bit embedded message cannot carry high byte", "Content-Type: message/rfc822\r\n\r\nSubject: Away\r\nContent-Transfer-Encoding: 8bit\r\n\r\ncaf\xe9", false},
		{"7bit multipart epilogue cannot carry high byte", "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nAway\r\n--b--\r\ncaf\xe9", false},
		{"binary multipart carries binary child", "Content-Type: multipart/mixed; boundary=b\r\nContent-Transfer-Encoding: binary\r\n\r\n--b\r\nContent-Transfer-Encoding: binary\r\n\r\na\x00b\xff\r\n--b--\r\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) { assertVacationMIMEWire(t, tc.reason, tc.valid) })
	}
}

func TestVacationMIMEBoundarySyntax(t *testing.T) {
	for _, tc := range []struct {
		boundary string
		valid    bool
	}{
		{strings.Repeat("b", 70), true},
		{"A 09'()+_,-./:=?Z", true},
		{strings.Repeat("b", 71), false},
		{"b ", false},
		{"b\tb", false},
		{"b[b", false},
		{"b!b", false},
	} {
		t.Run(tc.boundary, func(t *testing.T) {
			reason := fmt.Sprintf("Content-Type: multipart/mixed; boundary=%q\r\n\r\n--%s\r\n\r\nAway\r\n--%s--\r\n", tc.boundary, tc.boundary, tc.boundary)
			assertVacationMIMEWire(t, reason, tc.valid)
		})
	}
}

func TestVacationMIMELargeValidBodies(t *testing.T) {
	for _, tc := range []struct{ encoding, body string }{
		{"binary", strings.Repeat("\x00\xff", 1<<19)},
		{"7bit", strings.Repeat(strings.Repeat("x", 998)+"\r\n", 1100)},
		{"base64", strings.Repeat(strings.Repeat("A", 76)+"\r\n", 14000)},
	} {
		t.Run(tc.encoding, func(t *testing.T) {
			reason := "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: " + tc.encoding + "\r\n\r\n" + tc.body
			assertVacationMIMEWire(t, reason, true)
		})
	}
}

func assertVacationMIMEWire(t *testing.T, reason string, valid bool) {
	t.Helper()
	var wire bytes.Buffer
	err := writeVacationMIME(&wire, message.Header{}, reason)
	if valid {
		if err != nil {
			t.Fatalf("valid MIME rejected: %v", err)
		}
		got := strings.SplitN(wire.String(), "\r\n\r\n", 2)[1]
		want := strings.SplitN(reason, "\r\n\r\n", 2)[1]
		if got != want {
			t.Fatal("encoded source body changed")
		}
	} else if err == nil || wire.Len() != 0 {
		t.Fatalf("invalid MIME: error=%v, emitted=%d bytes", err, wire.Len())
	}
}
