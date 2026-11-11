//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/imap"
)

// previewConn is a raw connection, logged in with INBOX selected. FETCH PREVIEW
// is driven by hand: the response forms (NIL versus "") are what is under test.
type previewConn struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	tag  int
}

func dialPreview(t *testing.T, address string, account common.TestAccount) *previewConn {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &previewConn{t: t, conn: conn, r: bufio.NewReader(conn)}
	if _, err := c.r.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	c.ok(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	c.ok("SELECT INBOX")
	return c
}

// run sends a command and returns its untagged lines and tagged reply.
func (c *previewConn) run(command string) (string, string) {
	c.t.Helper()
	c.tag++
	tag := fmt.Sprintf("P%03d", c.tag)
	fmt.Fprintf(c.conn, "%s %s\r\n", tag, command)
	var lines []string
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("%s: %v (read so far %q)", command, err, lines)
		}
		line = strings.TrimRight(line, "\r\n")
		if rest, ok := strings.CutPrefix(line, tag+" "); ok {
			return strings.Join(lines, "\n"), rest
		}
		lines = append(lines, line)
	}
}

func (c *previewConn) ok(command string) string {
	c.t.Helper()
	untagged, tagged := c.run(command)
	if !strings.HasPrefix(tagged, "OK") {
		c.t.Fatalf("%s: %s", command, tagged)
	}
	return untagged
}

func (c *previewConn) appendMessage(msg string) {
	c.t.Helper()
	msg = strings.ReplaceAll(msg, "\n", "\r\n")
	c.ok(fmt.Sprintf("APPEND INBOX {%d+}\r\n%s", len(msg), msg))
}

// TestIMAP_FetchPreview runs FETCH PREVIEW end to end against messages whose
// bodies are still in this node's staging spool (the test server never uploads),
// which is where PREVIEW (LAZY) can answer from.
func TestIMAP_FetchPreview(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{
		Preview: imap.PreviewOptions{Enabled: true},
	})
	defer server.Close()
	c := dialPreview(t, server.Address, account)

	if caps := c.ok("CAPABILITY"); !strings.Contains(caps, " PREVIEW") {
		t.Fatalf("CAPABILITY = %q, want PREVIEW", caps)
	}

	c.appendMessage("From: alice@example.com\nTo: bob@example.com\nSubject: lunch\nContent-Type: text/plain\n\nLunch at noon?\n\n> earlier mail\n")
	c.appendMessage("From: news@example.com\nTo: bob@example.com\nSubject: news\nContent-Type: text/html\n\n<html><head><style>p{}</style></head><body><p>This week's <b>news</b></p></body></html>\n")

	t.Run("LAZY listing", func(t *testing.T) {
		untagged := c.ok("FETCH 1:* (UID PREVIEW (LAZY))")
		for _, want := range []string{`PREVIEW "Lunch at noon?"`, `PREVIEW "This week's news"`} {
			if !strings.Contains(untagged, want) {
				t.Errorf("FETCH 1:* (UID PREVIEW (LAZY)) = %q, want %s", untagged, want)
			}
		}
	})

	t.Run("without LAZY", func(t *testing.T) {
		if untagged := c.ok("UID FETCH 1:* PREVIEW"); !strings.Contains(untagged, `PREVIEW "Lunch at noon?"`) {
			t.Errorf("UID FETCH 1:* PREVIEW = %q", untagged)
		}
	})

	t.Run("not requested", func(t *testing.T) {
		if untagged := c.ok("FETCH 1:* (UID FLAGS)"); strings.Contains(untagged, "PREVIEW") {
			t.Errorf("FETCH 1:* (UID FLAGS) = %q, want no PREVIEW", untagged)
		}
	})

	t.Run("does not mark the message seen", func(t *testing.T) {
		if untagged := c.ok("FETCH 1 (PREVIEW FLAGS)"); strings.Contains(untagged, `\Seen`) {
			t.Errorf("FETCH 1 (PREVIEW FLAGS) = %q, want no \\Seen", untagged)
		}
	})
}

func TestIMAP_FetchPreviewDisabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{})
	defer server.Close()
	c := dialPreview(t, server.Address, account)
	c.appendMessage("From: alice@example.com\nSubject: hi\n\nHello\n")

	if caps := c.ok("CAPABILITY"); strings.Contains(caps, "PREVIEW") {
		t.Errorf("CAPABILITY = %q, want no PREVIEW", caps)
	}
	if _, tagged := c.run("FETCH 1 PREVIEW"); !strings.HasPrefix(tagged, "BAD") {
		t.Errorf("FETCH 1 PREVIEW = %q, want BAD", tagged)
	}
	c.ok("NOOP")
}
