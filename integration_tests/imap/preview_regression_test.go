//go:build integration

package imap_test

import (
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/imap"
)

func TestIMAP_FetchPreviewAdversarialMIME(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{
		Preview: imap.PreviewOptions{Enabled: true},
	})
	defer server.Close()
	c := dialPreview(t, server.Address, account)
	// The malformed HTML previously needed about 28 seconds per preview.
	// Bound a regression's protocol wait, with ample room for normal CI runs.
	if err := c.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}

	c.appendMessage("From: alice@example.com\nSubject: multipart attachment\nContent-Type: multipart/mixed; boundary=outer\n\n" +
		"--outer\nContent-Type: multipart/alternative; boundary=attached\nContent-Disposition: attachment\n\n" +
		"--attached\nContent-Type: text/plain\nContent-Disposition: inline\n\nAttached secret\n--attached--\n" +
		"--outer\nContent-Type: text/plain\n\nActual message\n--outer--\n")
	if got := c.ok("FETCH 1 (PREVIEW (LAZY))"); !strings.Contains(got, `PREVIEW "Actual message"`) || strings.Contains(got, "Attached secret") {
		t.Fatalf("attachment contents used as preview: %q", got)
	}

	// A blank plain alternative keeps ingestion cheap while forcing preview
	// generation to use the HTML alternative, including on the loaded-body path.
	c.appendMessage("From: alice@example.com\nSubject: malformed HTML\nContent-Type: multipart/alternative; boundary=b\n\n" +
		"--b\nContent-Type: text/plain\n\n \n" +
		"--b\nContent-Type: text/html\n\n<" + strings.Repeat(">", 256<<10) + "\n--b--\n")
	want := `PREVIEW "<` + strings.Repeat(">", helpers.PreviewMaxChars-1) + `"`
	for _, command := range []string{
		"FETCH 2 (BODY.PEEK[] PREVIEW (LAZY))",
		"FETCH 2 (BODY.PEEK[] PREVIEW)",
		"FETCH 2 (PREVIEW (LAZY))",
	} {
		if got := c.ok(command); !strings.Contains(got, want) {
			t.Fatalf("%s did not return the expected preview", command)
		}
	}
	c.ok("NOOP")
}
