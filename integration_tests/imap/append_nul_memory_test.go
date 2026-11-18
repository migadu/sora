//go:build integration

package imap_test

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	imapServer "github.com/migadu/sora/server/imap"
)

// TestIMAP_AppendNULEncodingFitsSessionMemory: an ordinary-literal APPEND whose
// NUL-bearing part is stored base64-encoded holds the literal AND the encoded
// copy at once, so both must fit the session memory budget before the encoded
// copy is allocated. A message whose literal fits but whose encoded copy does not
// fit beside it is refused with the usual memory-limit reply, stores nothing, and
// leaves the budget as it was (a later APPEND that fits is accepted).
func TestIMAP_AppendNULEncodingFitsSessionMemory(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// 3000 body octets, each line holding NUL: the literal is ~3.1 KB, its
	// base64 form ~4.1 KB, so literal + encoded copy is ~7.2 KB.
	body := bytes.Repeat([]byte("\x00\xe4abcdefghijklmnopqrstuvwxyz\r\n"), 100)
	msg := "From: user@example.com\r\n" +
		"Subject: NUL part under a tight memory budget\r\n" +
		"Mime-Version: 1.0\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: binary\r\n" +
		"\r\n" + string(body)
	const budget = 6000 // fits the literal, not the literal plus its encoded copy
	if len(msg) >= budget || len(msg)*2 <= budget {
		t.Fatalf("fixture of %d octets does not straddle the %d-byte budget", len(msg), budget)
	}

	server, account, _ := common.SetupIMAPServerWithRealS3Options(t, func(o *imapServer.IMAPServerOptions) {
		o.SessionMemoryLimit = budget
	})
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
	run := func(tag, cmd string) string {
		t.Helper()
		if _, err := fmt.Fprintf(conn, "%s %s\r\n", tag, cmd); err != nil {
			t.Fatalf("write %q failed: %v", cmd, err)
		}
		return h3ReadTagged(t, r, tag)
	}
	appendLiteral := func(tag, data string) string {
		t.Helper()
		if _, err := fmt.Fprintf(conn, "%s APPEND INBOX {%d}\r\n", tag, len(data)); err != nil {
			t.Fatalf("write APPEND failed: %v", err)
		}
		if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+") {
			t.Fatalf("APPEND literal not accepted: %q, %v", line, err)
		}
		if _, err := fmt.Fprintf(conn, "%s\r\n", data); err != nil {
			t.Fatalf("write literal failed: %v", err)
		}
		return h3ReadTagged(t, r, tag)
	}

	if resp := run("l", fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)); !strings.Contains(resp, "l OK") {
		t.Fatalf("LOGIN failed:\n%q", resp)
	}

	resp := appendLiteral("a1", msg)
	if !strings.Contains(resp, "a1 NO [UNAVAILABLE] Session memory limit reached") {
		t.Fatalf("APPEND whose encoded copy does not fit beside the literal was not refused for memory:\n%q", resp)
	}
	if resp := run("s1", "STATUS INBOX (MESSAGES)"); !strings.Contains(resp, "(MESSAGES 0)") {
		t.Fatalf("refused APPEND stored a message:\n%q", resp)
	}

	// The refusal must release everything it reserved: a small NUL-bearing
	// message whose literal and encoded copy fit together is accepted.
	small := "From: user@example.com\r\nSubject: small\r\nContent-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: binary\r\n\r\n\x00small\r\n"
	if resp := appendLiteral("a2", small); !strings.Contains(resp, "a2 OK") {
		t.Fatalf("APPEND that fits the budget after a refusal was not accepted:\n%q", resp)
	}
	if resp := run("s2", "STATUS INBOX (MESSAGES)"); !strings.Contains(resp, "(MESSAGES 1)") {
		t.Fatalf("APPEND that fits the budget did not store one message:\n%q", resp)
	}
}
