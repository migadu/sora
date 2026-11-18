//go:build integration

package lmtp_test

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_NULPartBodyFetchHasNoNUL delivers a "Content-Transfer-Encoding:
// binary" part holding a NUL over LMTP, then FETCHes it over IMAP (#2051, the
// delivery side of #2011). An ordinary literal is "*CHAR8" (CHAR8 = %x01-ff) and
// "unencoded binary strings are not permitted" outside BINARY[] (RFC 9051 §4.3),
// so BODY[1] and BODY[] must not carry the NUL, and BINARY[1] must give the
// delivered octets back.
func TestLMTP_NULPartBodyFetchHasNoNUL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	t.Cleanup(imapSrv.Close)
	lmtpAddr := common.StartLMTPServerWithS3(t, imapSrv.ResilientDB, fake)

	const binaryBody = "\x00-\xe4\r\nabc"
	msg := "From: user@example.org\r\n" +
		"Date: Sat, 24 Mar 2007 23:00:00 +0200\r\n" +
		"Mime-Version: 1.0\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: binary\r\n" +
		"\r\n" + binaryBody
	if resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, msg); !strings.HasPrefix(resp, "250") {
		t.Fatalf("LMTP delivery not accepted: %q", resp)
	}
	// runLMTPMailData ends the data with CRLF "."; the CRLF is the message's.
	const delivered = binaryBody + "\r\n"

	conn, err := net.Dial("tcp", imapSrv.Address)
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
		var sb strings.Builder
		for {
			line, err := r.ReadString('\n')
			sb.WriteString(line)
			if err != nil {
				t.Fatalf("read %q failed: %v (partial %q)", cmd, err, sb.String())
			}
			if strings.HasPrefix(line, tag+" ") {
				if !strings.HasPrefix(line, tag+" OK ") {
					t.Fatalf("%s not OK:\n%q", cmd, sb.String())
				}
				return sb.String()
			}
		}
	}
	literal := func(t *testing.T, resp, item string) []byte {
		t.Helper()
		if strings.Contains(resp, item+" ~{") {
			t.Fatalf("%s sent as a literal8, which only BINARY[] may use:\n%q", item, resp)
		}
		m := regexp.MustCompile(regexp.QuoteMeta(item) + ` \{(\d+)\}\r\n`).FindStringSubmatchIndex(resp)
		if m == nil {
			t.Fatalf("no %s literal in:\n%q", item, resp)
		}
		n, _ := strconv.Atoi(resp[m[2]:m[3]])
		return []byte(resp[m[1] : m[1]+n])
	}

	mustOK(t, fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
	mustOK(t, "SELECT INBOX")

	resp := mustOK(t, "FETCH 1 (BODY.PEEK[1] BODY.PEEK[])")
	if part := literal(t, resp, "BODY[1]"); bytes.IndexByte(part, 0) >= 0 {
		t.Errorf("BODY[1] after LMTP delivery contains NUL: %q", part)
	}
	if whole := literal(t, resp, "BODY[]"); bytes.IndexByte(whole, 0) >= 0 {
		t.Errorf("BODY[] after LMTP delivery contains NUL: %q", whole)
	}

	resp = mustOK(t, "FETCH 1 (BINARY.SIZE[1] BINARY.PEEK[1])")
	if want := fmt.Sprintf("BINARY.SIZE[1] %d", len(delivered)); !strings.Contains(resp, want) {
		t.Errorf("want %q in:\n%q", want, resp)
	}
	if want := fmt.Sprintf("BINARY[1] ~{%d}\r\n%s", len(delivered), delivered); !strings.Contains(resp, want) {
		t.Errorf("want %q in:\n%q", want, resp)
	}
}
