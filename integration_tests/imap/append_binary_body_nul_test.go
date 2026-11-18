//go:build integration

package imap_test

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// bodyLiteral returns the payload of the "<item> {n}" ordinary literal in a FETCH
// response, failing when the item is missing or was sent as a literal8.
func bodyLiteral(t *testing.T, resp, item string) []byte {
	t.Helper()
	if strings.Contains(resp, item+" ~{") {
		t.Fatalf("%s sent as a literal8, which only BINARY[] may use:\n%q", item, resp)
	}
	m := regexp.MustCompile(regexp.QuoteMeta(item) + ` \{(\d+)\}\r\n`).FindStringSubmatchIndex(resp)
	if m == nil {
		t.Fatalf("no %s literal in:\n%q", item, resp)
	}
	n, err := strconv.Atoi(resp[m[2]:m[3]])
	if err != nil || m[1]+n > len(resp) {
		t.Fatalf("bad %s literal size in:\n%q", item, resp)
	}
	return []byte(resp[m[1] : m[1]+n])
}

// TestIMAP_BinaryAppendBodyFetchHasNoNUL is imaptest's append-binary scenario
// (dovecot/imaptest src/tests/append-binary, #2011): a literal8 APPEND of a
// "Content-Transfer-Encoding: binary" part holding a NUL, then an ordinary FETCH
// BODY[1] of that part.
//
// RFC 3501 §4.3 / RFC 9051 §4.3: "unencoded binary strings are not permitted"
// outside BINARY[] (a "binary string" is any string with NUL characters), and
// a literal is "*CHAR8", CHAR8 = %x01-ff. RFC 3516 §4.4: on a literal8 APPEND
// "The server MAY modify the CTE of the appended data, however any such
// transformation MUST NOT result in a loss of data." RFC 3516 §6: "the results
// of a FETCH BODY MUST return the message body content in the format described
// by the corresponding FETCH BODYSTRUCTURE response."
func TestIMAP_BinaryAppendBodyFetchHasNoNUL(t *testing.T) {
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
	mustOK := func(t *testing.T, cmd string) string {
		t.Helper()
		tagN++
		tag := fmt.Sprintf("b%d", tagN)
		if _, err := fmt.Fprintf(conn, "%s %s\r\n", tag, cmd); err != nil {
			t.Fatalf("write %q failed: %v", cmd, err)
		}
		resp := h3ReadTagged(t, r, tag)
		if !strings.Contains(resp, "\r\n"+tag+" OK ") && !strings.HasPrefix(resp, tag+" OK ") {
			t.Fatalf("%s not OK:\n%q", cmd, resp)
		}
		return resp
	}

	mustOK(t, fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))

	// The fixture's message: 00 2d e4 0a 0d 0a 0a is the whole body.
	const binaryBody = "\x00-\xe4\n\r\n\n"
	msg := "From: user@domain.org\r\n" +
		"Date: Sat, 24 Mar 2007 23:00:00 +0200\r\n" +
		"Mime-Version: 1.0\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: binary\r\n" +
		"\r\n" + binaryBody
	if _, err := fmt.Fprintf(conn, "a1 APPEND INBOX ~{%d}\r\n", len(msg)); err != nil {
		t.Fatalf("write APPEND failed: %v", err)
	}
	if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+") {
		t.Fatalf("APPEND literal8 not accepted: %q, %v", line, err)
	}
	if _, err := fmt.Fprintf(conn, "%s\r\n", msg); err != nil {
		t.Fatalf("write APPEND literal failed: %v", err)
	}
	if resp := h3ReadTagged(t, r, "a1"); !strings.Contains(resp, "a1 OK ") {
		t.Fatalf("APPEND not OK:\n%q", resp)
	}
	mustOK(t, "SELECT INBOX")

	t.Run("BODY[1] is NUL-free and decodes per BODYSTRUCTURE", func(t *testing.T) {
		resp := mustOK(t, "FETCH 1 (BODY.PEEK[1] BODYSTRUCTURE)")
		part := bodyLiteral(t, resp, "BODY[1]")
		if bytes.IndexByte(part, 0) >= 0 {
			t.Fatalf("BODY[1] after binary APPEND contains NUL: %q", part)
		}
		m := regexp.MustCompile(`(?i)BODYSTRUCTURE \("application" "octet-stream" \S+ \S+ \S+ "([^"]+)"`).FindStringSubmatch(resp)
		if m == nil {
			t.Fatalf("no single-part BODYSTRUCTURE with an encoding in:\n%q", resp)
		}
		var decoded []byte
		switch strings.ToUpper(m[1]) {
		case "BASE64":
			decoded, err = base64.StdEncoding.DecodeString(strings.NewReplacer("\r", "", "\n", "").Replace(string(part)))
		case "QUOTED-PRINTABLE":
			decoded, err = io.ReadAll(quotedprintable.NewReader(bytes.NewReader(part)))
		default:
			t.Fatalf("BODYSTRUCTURE encoding %q cannot carry the NUL-bearing part", m[1])
		}
		if err != nil {
			t.Fatalf("BODY[1] does not decode as %s: %v (%q)", m[1], err, part)
		}
		if string(decoded) != binaryBody {
			t.Fatalf("BODY[1] decodes to %q, want %q (the transformation lost data)", decoded, binaryBody)
		}
	})

	t.Run("BODY[] is NUL-free", func(t *testing.T) {
		if whole := bodyLiteral(t, mustOK(t, "FETCH 1 (BODY.PEEK[])"), "BODY[]"); bytes.IndexByte(whole, 0) >= 0 {
			t.Fatalf("BODY[] after binary APPEND contains NUL: %q", whole)
		}
	})

	// The fixture's last step: BINARY gives back the appended octets.
	t.Run("BINARY[1] returns the appended octets", func(t *testing.T) {
		resp := mustOK(t, "FETCH 1 (BINARY.SIZE[1] BINARY.PEEK[1])")
		if want := "BINARY.SIZE[1] 7"; !strings.Contains(resp, want) {
			t.Errorf("want %q in:\n%q", want, resp)
		}
		if want := "BINARY[1] ~{7}\r\n" + binaryBody; !strings.Contains(resp, want) {
			t.Errorf("want %q in:\n%q", want, resp)
		}
	})
}
