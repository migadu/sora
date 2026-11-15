//go:build integration

package imap_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// fetchSeqRe extracts the sequence number of an untagged FETCH response.
var fetchSeqRe = regexp.MustCompile(`^\* (\d+) FETCH `)

// TestIMAP_FetchFailingPartWaySetsSeenOnlyOnAnswered: RFC 9051 §6.4.5
// (BODY[<section>]): "The \Seen flag is implicitly set; if this causes the
// flags to change, they SHOULD be included as part of the FETCH responses."
// The flag comes from fetching the body. A FETCH that fails part way sets it
// on the messages it answered, not on the message it fails at, nor on the
// messages after it, whose bodies it never sent (#1222).
func TestIMAP_FetchFailingPartWaySetsSeenOnlyOnAnswered(t *testing.T) {
	// BINARY[] of a section whose Content-Transfer-Encoding the server cannot
	// decode fails with NO [UNKNOWN-CTE] (RFC 9051 §7.5.2).
	t.Run("UNKNOWN-CTE", func(t *testing.T) {
		common.SkipIfDatabaseUnavailable(t)
		server, account := common.SetupIMAPServer(t)
		defer server.Close()

		c := dialRawIMAP(t, server.Address)
		c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
		c.appendMsg("INBOX", binaryDecodeTestMessage("one", "text/plain", "base64", "aGVsbG8gd29ybGQ=\r\n"))
		c.appendMsg("INBOX", binaryDecodeTestMessage("two", "text/plain", "x-uuencode", "begin 644 a.txt\r\n#86)C\r\n`\r\nend\r\n"))
		c.appendMsg("INBOX", binaryDecodeTestMessage("three", "text/plain", "base64", "aGVsbG8gd29ybGQ=\r\n"))
		c.do("SELECT INBOX")

		requireFetchFailsAtSecond(t, c, "FETCH 1:3 (BINARY[1])", " NO [UNKNOWN-CTE] ")
	})

	// BODY[] of a message whose body cannot be read right now fails with
	// NO [UNAVAILABLE]: the staged copy is gone and the harness S3 fails GETs.
	t.Run("UNAVAILABLE", func(t *testing.T) {
		common.SkipIfDatabaseUnavailable(t)
		server, account := common.SetupIMAPServer(t)
		defer server.Close()

		c := dialRawIMAP(t, server.Address)
		c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
		var second string
		for i, subject := range []string{"one", "two", "three"} {
			before := stagedFiles(t, server.UploadPath)
			c.appendMsg("INBOX", binaryDecodeTestMessage(subject, "text/plain", "7bit", "body "+subject+"\r\n"))
			if i == 1 {
				for path := range stagedFiles(t, server.UploadPath) {
					if !before[path] {
						second = path
					}
				}
			}
		}
		server.WaitForUploads(t)
		if second == "" {
			t.Fatal("no staged file for the second message")
		}
		if err := os.Remove(second); err != nil {
			t.Fatalf("remove staged file %s: %v", second, err)
		}
		c.do("SELECT INBOX")

		requireFetchFailsAtSecond(t, c, "FETCH 1:3 (BODY[])", " NO [UNAVAILABLE] ")
	})
}

// requireFetchFailsAtSecond runs a non-PEEK FETCH of messages 1:3 that fails at
// message 2 and asserts that it answered message 1 only, and that only message
// 1 is \Seen afterwards.
func requireFetchFailsAtSecond(t *testing.T, c *rawIMAP, command, wantStatus string) {
	t.Helper()
	untagged, tagged := c.read(c.send(command), command)
	if !strings.Contains(tagged, wantStatus) {
		t.Fatalf("%s: want%s, got %s", command, wantStatus, tagged)
	}
	answered := map[int]bool{}
	for _, resp := range splitUntaggedResponses(untagged) {
		if m := fetchSeqRe.FindStringSubmatch(resp); m != nil {
			seq, _ := strconv.Atoi(m[1])
			answered[seq] = true
		}
	}
	if !answered[1] || answered[2] || answered[3] {
		t.Errorf("%s: want a FETCH response for message 1 only, got:\n%s", command, strings.Join(untagged, "\r\n"))
	}

	c.do("NOOP")
	untagged, _ = c.do("FETCH 1:3 (FLAGS)")
	seen := map[int]bool{}
	for _, resp := range splitUntaggedResponses(untagged) {
		if m := fetchSeqRe.FindStringSubmatch(resp); m != nil {
			seq, _ := strconv.Atoi(m[1])
			seen[seq] = seenFlagsRe.MatchString(resp)
		}
	}
	for seq, want := range map[int]bool{1: true, 2: false, 3: false} {
		if seen[seq] != want {
			t.Errorf("after %s: message %d \\Seen = %v, want %v (FLAGS: %q)", command, seq, seen[seq], want, untagged)
		}
	}
}

// stagedFiles returns the set of files under the upload staging directory.
func stagedFiles(t *testing.T, root string) map[string]bool {
	t.Helper()
	files := map[string]bool{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files[p] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk upload dir %s: %v", root, err)
	}
	return files
}
