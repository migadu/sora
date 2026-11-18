//go:build integration

package imap_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/uploader"
)

// TestIMAP_FetchBodyOfStoredNULHasNoNUL covers a message whose stored bytes
// hold a NUL in a "Content-Transfer-Encoding: binary" part, as builds before
// APPEND re-encoded such parts stored it (#2073). An ordinary literal is
// "*CHAR8" (CHAR8 = %x01-ff, RFC 9051 §9), and BODY[] takes only an nstring,
// never a literal8, so BODY[...] (and RFC822) must not send the NUL. As Dovecot
// does (imap-msgpart.c, i_stream_create_nonuls), each NUL is sent as 0x80,
// which keeps every size and partial offset. BINARY[] sends the stored octets.
func TestIMAP_FetchBodyOfStoredNULHasNoNUL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// The upload worker never runs, so the body FETCH reads is the staged file.
	server, account := common.SetupIMAPServerForUploadRace(t)
	t.Cleanup(server.Close)

	const stored = "From: user@example.org\r\nMime-Version: 1.0\r\n" +
		"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n" +
		"\x00-\xe4\n\r\nab\x00c"
	// APPEND the same message with \x01 for each NUL, so the metadata is what an
	// older build stored for it, then put the NUL-bearing bytes in its place.
	placeholder := strings.ReplaceAll(stored, "\x00", "\x01")

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
	literal := func(t *testing.T, resp, item string) string {
		t.Helper()
		if strings.Contains(resp, item+" ~{") {
			t.Fatalf("%s sent as a literal8, which only BINARY[] may use:\n%q", item, resp)
		}
		m := regexp.MustCompile(regexp.QuoteMeta(item) + ` \{(\d+)\}\r\n`).FindStringSubmatchIndex(resp)
		if m == nil {
			t.Fatalf("no %s literal in:\n%q", item, resp)
		}
		n, _ := strconv.Atoi(resp[m[2]:m[3]])
		return resp[m[1] : m[1]+n]
	}

	mustOK(t, fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
	mustOK(t, fmt.Sprintf("APPEND INBOX {%d+}\r\n%s", len(placeholder), placeholder))

	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("account ID: %v", err)
	}
	spool := uploader.StagingFilePath(server.UploadPath, helpers.HashContent([]byte(placeholder)), accountID)
	if _, err := os.Stat(spool); err != nil {
		t.Fatalf("staged file of the APPEND: %v", err)
	}
	if err := os.WriteFile(spool, []byte(stored), 0o600); err != nil {
		t.Fatalf("plant the NUL-bearing body: %v", err)
	}
	mustOK(t, "SELECT INBOX")

	const sent = "\x80-\xe4\n\r\nab\x80c" // the part, each NUL sent as 0x80
	resp := mustOK(t, "FETCH 1 (BODY.PEEK[1] BODY.PEEK[] BODY.PEEK[1]<0.3> RFC822.SIZE)")
	for _, tc := range []struct{ item, want string }{
		{"BODY[1]", sent},
		{"BODY[]", strings.ReplaceAll(stored, "\x00", "\x80")},
		{"BODY[1]<0>", sent[:3]},
	} {
		got := literal(t, resp, tc.item)
		if strings.IndexByte(got, 0) >= 0 {
			t.Errorf("%s of a stored NUL-bearing message contains NUL: %q", tc.item, got)
		} else if got != tc.want {
			t.Errorf("%s = %q, want %q", tc.item, got, tc.want)
		}
	}
	if want := fmt.Sprintf("RFC822.SIZE %d", len(stored)); !strings.Contains(resp, want) {
		t.Errorf("want %q in:\n%q", want, resp)
	}

	// BINARY[] may carry NUL, in a literal8, and gets the stored octets.
	resp = mustOK(t, "FETCH 1 (BINARY.PEEK[1])")
	if want := "BINARY[1] ~{10}\r\n\x00-\xe4\n\r\nab\x00c"; !strings.Contains(resp, want) {
		t.Errorf("want %q in:\n%q", want, resp)
	}
	if bytes.Count([]byte(resp), []byte{0}) != 2 {
		t.Errorf("BINARY[1] lost its NULs:\n%q", resp)
	}
}
