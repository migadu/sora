//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
)

// metadataLimitConn logs in over a raw connection to a server with the given
// [metadata] limits.
func metadataLimitConn(t *testing.T, configure func(*imapserver.IMAPServerOptions)) (conn net.Conn, r *bufio.Reader, nextTag func() string) {
	t.Helper()
	server, account, _ := common.SetupIMAPServerWithRealS3Options(t, configure)
	t.Cleanup(server.Close)

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	r = bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("read greeting failed: %v", err)
	}
	n := 0
	nextTag = func() string { n++; return fmt.Sprintf("m%d", n) }
	tag := nextTag()
	fmt.Fprintf(conn, "%s LOGIN \"%s\" \"%s\"\r\n", tag, account.Email, account.Password)
	if resp := h3ReadTagged(t, r, tag); !strings.Contains(resp, tag+" OK ") {
		t.Fatalf("LOGIN not OK:\n%s", resp)
	}
	return conn, r, nextTag
}

// setMetadataLiteral sends SETMETADATA with a synchronizing literal value and
// returns the tagged response. The value is only sent if the server asks for
// it; continued reports whether it did.
func setMetadataLiteral(t *testing.T, conn net.Conn, r *bufio.Reader, tag string, size int) (tagged string, continued bool) {
	t.Helper()
	fmt.Fprintf(conn, "%s SETMETADATA \"\" (/private/comment {%d}\r\n", tag, size)
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read SETMETADATA response failed: %v", err)
	}
	if strings.HasPrefix(line, "+") {
		fmt.Fprintf(conn, "%s)\r\n", strings.Repeat("x", size))
		resp := h3ReadTagged(t, r, tag)
		return resp[strings.LastIndex(strings.TrimRight(resp, "\r\n"), "\n")+1:], true
	}
	return line, false
}

// RFC 5464 §4.3: SETMETADATA fails with "[METADATA MAXSIZE NNN]" for a value
// that is too large, NNN being the largest the server accepts, and with
// "[METADATA TOOMANY]" when the number of annotations is at its limit. sora
// answered [TOOBIG] and [TOOMANY] (#339).
func TestIMAP_SetMetadataLimitResponseCodes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	conn, r, nextTag := metadataLimitConn(t, func(o *imapserver.IMAPServerOptions) {
		o.MetadataMaxEntrySize = 1024
		o.MetadataMaxEntriesPerServer = 50
		o.MetadataMaxEntriesPerMailbox = 100
		o.MetadataMaxTotalSize = 1 << 20
	})
	do := func(cmd string) string {
		t.Helper()
		tag := nextTag()
		fmt.Fprintf(conn, "%s %s\r\n", tag, cmd)
		resp := h3ReadTagged(t, r, tag)
		return resp[strings.LastIndex(strings.TrimRight(resp, "\r\n"), "\n")+1:]
	}

	t.Run("literal over max_entry_size", func(t *testing.T) {
		tag := nextTag()
		tagged, _ := setMetadataLiteral(t, conn, r, tag, 2000)
		if !strings.HasPrefix(tagged, tag+" NO [METADATA MAXSIZE 1024] ") {
			t.Errorf("got %q, want NO [METADATA MAXSIZE 1024]", strings.TrimRight(tagged, "\r\n"))
		}
	})

	t.Run("quoted value over max_entry_size", func(t *testing.T) {
		tagged := do(`SETMETADATA "" (/private/comment "` + strings.Repeat("x", 2000) + `")`)
		if !strings.Contains(tagged, " NO [METADATA MAXSIZE 1024] ") {
			t.Errorf("got %q, want NO [METADATA MAXSIZE 1024]", strings.TrimRight(tagged, "\r\n"))
		}
	})

	t.Run("too many entries", func(t *testing.T) {
		var sb strings.Builder
		for i := 1; i <= 51; i++ {
			fmt.Fprintf(&sb, " /private/e%d \"x\"", i)
		}
		tagged := do(`SETMETADATA "" (` + strings.TrimPrefix(sb.String(), " ") + `)`)
		if !strings.Contains(tagged, " NO [METADATA TOOMANY] ") {
			t.Errorf("got %q, want NO [METADATA TOOMANY]", strings.TrimRight(tagged, "\r\n"))
		}
	})

	t.Run("literal within max_entry_size", func(t *testing.T) {
		tag := nextTag()
		tagged, continued := setMetadataLiteral(t, conn, r, tag, 1000)
		if !continued || !strings.HasPrefix(tagged, tag+" OK ") {
			t.Errorf("got %q (continued %v), want OK", strings.TrimRight(tagged, "\r\n"), continued)
		}
	})
}

// With the default max_entry_size of 64 KiB, a value literal over 4096 octets
// was refused by go-imap's bound for buffered literals before sora saw it.
func TestIMAP_SetMetadataLiteralAbove4096(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	conn, r, nextTag := metadataLimitConn(t, func(o *imapserver.IMAPServerOptions) {
		o.MetadataMaxEntrySize = 64 * 1024
		o.MetadataMaxTotalSize = 1 << 20
	})

	tag := nextTag()
	tagged, continued := setMetadataLiteral(t, conn, r, tag, 5000)
	if !continued || !strings.HasPrefix(tagged, tag+" OK ") {
		t.Fatalf("SETMETADATA with a 5000-octet literal: got %q (continued %v), want a continuation request and OK", strings.TrimRight(tagged, "\r\n"), continued)
	}

	tag = nextTag()
	fmt.Fprintf(conn, "%s GETMETADATA \"\" /private/comment\r\n", tag)
	if resp := h3ReadTagged(t, r, tag); !strings.Contains(resp, "{5000}") {
		t.Errorf("GETMETADATA did not return the 5000-octet value:\n%.300s", resp)
	}
}

// RFC 5464 has no code for an account's total metadata size; RFC 5530's
// OVERQUOTA says "The user would be over quota after the operation". [TOOMANY]
// claimed the number of annotations was at its limit.
func TestIMAP_SetMetadataTotalSizeOverQuota(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	conn, r, nextTag := metadataLimitConn(t, func(o *imapserver.IMAPServerOptions) {
		o.MetadataMaxEntrySize = 1024
		o.MetadataMaxTotalSize = 1500
	})
	do := func(cmd string) string {
		t.Helper()
		tag := nextTag()
		fmt.Fprintf(conn, "%s %s\r\n", tag, cmd)
		return h3ReadTagged(t, r, tag)
	}
	value := strings.Repeat("x", 1000)
	if resp := do(`SETMETADATA "" (/private/a "` + value + `")`); !strings.Contains(resp, " OK ") {
		t.Fatalf("first SETMETADATA not OK:\n%s", resp)
	}
	if resp := do(`SETMETADATA "" (/private/b "` + value + `")`); !strings.Contains(resp, " NO [OVERQUOTA] ") {
		t.Errorf("SETMETADATA over max_total_size: got %q, want NO [OVERQUOTA]", strings.TrimRight(resp, "\r\n"))
	}
}
