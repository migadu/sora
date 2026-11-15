//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

func binaryDecodeTestMessage(subject, contentType, cte, body string) string {
	return "From: a@example.com\r\nTo: b@example.com\r\nSubject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: " + contentType + "\r\nContent-Transfer-Encoding: " + cte + "\r\n" +
		"\r\n" + body
}

// TestIMAP_FetchBinaryDecodesTransferEncodingOnly covers what FETCH BINARY
// and BINARY.SIZE send for a section (#893, #1056):
//
// RFC 9051 §7.5.2: "If the server does not know how to decode the section's
// Content-Transfer-Encoding, it MUST fail the request and issue a "NO"
// response that contains the "UNKNOWN-CTE" response code." (Said for BINARY
// and for BINARY.SIZE alike, as in RFC 3516 §4.3.)
//
// RFC 9051 §7.5.2: "When sending data in a BINARY[...] FETCH data item,
// servers MUST ensure that textual line-oriented sections are always
// transmitted using the IMAP CRLF line termination syntax, regardless of the
// underlying storage representation of the data on the server."
//
// RFC 9051 §6.4.5: BINARY "Requests that the specified section be transmitted
// after performing decoding of the section's Content-Transfer-Encoding", so a
// text part keeps the charset its Content-Type declares.
func TestIMAP_FetchBinaryDecodesTransferEncodingOnly(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account, _ := common.SetupIMAPServerWithRealS3(t)
	t.Cleanup(server.Close)

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set connection deadline: %v", err)
	}
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("read greeting failed: %v", err)
	}
	tagN := 0
	do := func(t *testing.T, cmd string) (resp, tagged string) {
		t.Helper()
		tagN++
		tag := fmt.Sprintf("b%d", tagN)
		if _, err := fmt.Fprintf(conn, "%s %s\r\n", tag, cmd); err != nil {
			t.Fatalf("write %q failed: %v", cmd, err)
		}
		resp = h3ReadTagged(t, r, tag)
		lines := strings.Split(strings.TrimSuffix(resp, "\r\n"), "\r\n")
		return resp, lines[len(lines)-1]
	}
	mustOK := func(t *testing.T, cmd string) string {
		t.Helper()
		resp, tagged := do(t, cmd)
		if !strings.Contains(tagged, " OK ") {
			t.Fatalf("%s not OK:\n%s", cmd, resp)
		}
		return resp
	}

	mustOK(t, fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
	for i, msg := range []string{
		// 1: "line1\nline2\n"
		binaryDecodeTestMessage("lf", "text/plain", "base64", "bGluZTEKbGluZTIK\r\n"),
		// 2: a transfer encoding the server cannot decode
		binaryDecodeTestMessage("cte", "text/plain", "x-uuencode", "begin 644 a.txt\r\n#86)C\r\n`\r\nend\r\n"),
		// 3: "café" in iso-8859-1
		binaryDecodeTestMessage("latin1", "text/plain; charset=iso-8859-1", "quoted-printable", "caf=E9\r\n"),
		// 4: message 1 with a comment in its Content-Transfer-Encoding
		binaryDecodeTestMessage("comment", "text/plain", "base64 (encoded)", "bGluZTEKbGluZTIK\r\n"),
		// 5: "\x00\x01\xffa"
		binaryDecodeTestMessage("nul", "application/octet-stream", "base64", "AAH/YQ==\r\n"),
	} {
		tag := fmt.Sprintf("a%d", i+1)
		if _, err := fmt.Fprintf(conn, "%s APPEND INBOX {%d+}\r\n%s\r\n", tag, len(msg), msg); err != nil {
			t.Fatalf("write APPEND failed: %v", err)
		}
		if resp := h3ReadTagged(t, r, tag); !strings.Contains(resp, tag+" OK ") {
			t.Fatalf("APPEND %d not OK:\n%s", i+1, resp)
		}
	}
	mustOK(t, "SELECT INBOX")

	t.Run("unknown CTE", func(t *testing.T) {
		for _, cmd := range []string{
			"FETCH 2 (BINARY.PEEK[1] BINARY.SIZE[1])",
			"FETCH 2 (BINARY.PEEK[1])",
			"FETCH 2 (BINARY.SIZE[1])",
			"FETCH 2 (FLAGS BINARY.PEEK[1]<0.4>)",
			"UID FETCH 2 (BINARY.PEEK[1])",
		} {
			resp, tagged := do(t, cmd)
			if !strings.Contains(tagged, " NO [UNKNOWN-CTE] ") {
				t.Errorf("%s: want NO [UNKNOWN-CTE], got:\n%s", cmd, resp)
			}
			// The refusal leaves no FETCH response for the message behind,
			// least of all an empty "* 2 FETCH ()".
			if strings.Contains(resp, "* 2 FETCH") {
				t.Errorf("%s: untagged FETCH for the refused message:\n%s", cmd, resp)
			}
		}

		// The request fails at the message that cannot be decoded.
		resp, tagged := do(t, "FETCH 1:3 (BINARY.SIZE[1])")
		if !strings.Contains(tagged, " NO [UNKNOWN-CTE] ") || strings.Contains(resp, "* 2 FETCH") || strings.Contains(resp, "* 3 FETCH") {
			t.Errorf("FETCH 1:3 (BINARY.SIZE[1]): want NO [UNKNOWN-CTE] at message 2, got:\n%s", resp)
		}
	})

	t.Run("text sent with CRLF", func(t *testing.T) {
		const want = "BINARY[1] {14}\r\nline1\r\nline2\r\n BINARY.SIZE[1] 14)"
		for _, cmd := range []string{"FETCH 1 (BINARY.PEEK[1] BINARY.SIZE[1])", "UID FETCH 1 (BINARY.PEEK[1] BINARY.SIZE[1])"} {
			if resp := mustOK(t, cmd); !strings.Contains(resp, want) {
				t.Errorf("%s: want %q in:\n%q", cmd, want, resp)
			}
		}
	})

	// RFC 2045 §1: MIME fields "can include RFC 822 comments, which have no
	// semantic content and should be ignored during MIME processing", so the
	// server knows how to decode "base64 (encoded)".
	t.Run("comment in CTE ignored", func(t *testing.T) {
		const want = "BINARY[1] {14}\r\nline1\r\nline2\r\n BINARY.SIZE[1] 14)"
		if resp := mustOK(t, "FETCH 4 (BINARY.PEEK[1] BINARY.SIZE[1])"); !strings.Contains(resp, want) {
			t.Errorf("want %q in:\n%q", want, resp)
		}
	})

	// RFC 9051 §7.5.2: "If the domain of the decoded data is "8bit" and the
	// data does not contain the NUL octet, the server SHOULD return the data
	// in a <string> instead of a <literal8>" (RFC 3516 §4.3 likewise). A
	// literal carries any octet but NUL, so only a NUL needs a literal8 (#1077).
	t.Run("literal8 only with a NUL", func(t *testing.T) {
		for _, tc := range []struct{ cmd, want string }{
			{"FETCH 1 (BINARY.PEEK[1])", "BINARY[1] {14}\r\nline1\r\nline2\r\n)"},
			{"FETCH 1 (BINARY.PEEK[1]<5.2>)", "BINARY[1]<5> {2}\r\n\r\n)"},
			{"FETCH 5 (BINARY.PEEK[1] BINARY.SIZE[1])", "BINARY[1] ~{4}\r\n\x00\x01\xffa BINARY.SIZE[1] 4)"},
			{"FETCH 5 (BINARY.PEEK[1]<0.2>)", "BINARY[1]<0> ~{2}\r\n\x00\x01)"},
			{"FETCH 5 (BINARY.PEEK[1]<1.3>)", "BINARY[1]<1> {3}\r\n\x01\xffa)"},
			{"FETCH 5 (BINARY.PEEK[1]<4.1>)", "BINARY[1]<4> {0}\r\n)"},
		} {
			if resp := mustOK(t, tc.cmd); !strings.Contains(resp, tc.want) {
				t.Errorf("%s: want %q in:\n%q", tc.cmd, tc.want, resp)
			}
		}
	})

	t.Run("charset kept", func(t *testing.T) {
		const want = "BINARY[1] {6}\r\ncaf\xe9\r\n BINARY.SIZE[1] 6)"
		if resp := mustOK(t, "FETCH 3 (BINARY.PEEK[1] BINARY.SIZE[1])"); !strings.Contains(resp, want) {
			t.Errorf("want %q in:\n%q", want, resp)
		}
	})
}
