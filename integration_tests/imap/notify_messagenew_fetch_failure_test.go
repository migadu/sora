//go:build integration

package imap_test

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// RFC 5465 §5.2: "If the new/appended message is in the selected mailbox, the
// server notifies the client by sending an unsolicited EXISTS response,
// followed by an unsolicited FETCH response containing the information
// requested by the client." A message whose fetch-atts the server cannot
// answer must not cost the client the FETCH responses of the messages that
// arrived with it, nor its own once it can be answered (#1255).

const (
	notifyUUEncodedMessage = "From: a@example.com\r\nTo: b@example.com\r\nSubject: uuencoded\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: x-uuencode\r\n" +
		"\r\nbegin 644 a.txt\r\n#86)C\r\n`\r\nend\r\n"
	notifyBase64Message = "From: a@example.com\r\nTo: b@example.com\r\nSubject: base64\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n" +
		"\r\naGVsbG8gd29ybGQ=\r\n"
)

// TestNotifyMessageNewFetchPassesOverUnknownCTE: BINARY of a section whose
// Content-Transfer-Encoding the server cannot decode fails with NO
// [UNKNOWN-CTE] (RFC 9051 §7.5.2), which no later tick can change. The
// message that cannot be answered gets no FETCH; the one after it still does.
func TestNotifyMessageNewFetchPassesOverUnknownCTE(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	login := fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)

	watcher := dialRawIMAP(t, server.Address)
	watcher.do(login)
	watcher.do("SELECT INBOX")
	watcher.do("NOTIFY SET (SELECTED (MessageNew (UID BINARY.PEEK[1]) MessageExpunge))")

	other := dialRawIMAP(t, server.Address)
	other.do(login)
	other.do("CREATE Staging")
	other.appendMsg("Staging", notifyUUEncodedMessage)
	other.appendMsg("Staging", notifyBase64Message)
	other.do("SELECT Staging")
	// One COPY: both messages are new to the watcher in the same tick.
	other.do("COPY 1:2 INBOX")

	got := readNotifyUntil(t, watcher, 10*time.Second, func(resps []string) bool {
		return countFetches(resps, 2) > 0
	})
	got = append(got, notifyNoop(t, watcher)...)
	if fetch := findFetch(got, 2); !strings.Contains(fetch, "BINARY[1] ") || !strings.Contains(fetch, "hello world") {
		t.Errorf("MessageNew FETCH for message 2: want the decoded BINARY[1], got:\n%s", strings.Join(got, "\r\n"))
	}
	if n := countFetches(got, 1); n != 0 {
		t.Errorf("message 1 cannot be answered with BINARY[1], want no FETCH for it, got %d:\n%s", n, strings.Join(got, "\r\n"))
	}
	if n := countFetches(got, 2); n != 1 {
		t.Errorf("want one MessageNew FETCH for message 2, got %d:\n%s", n, strings.Join(got, "\r\n"))
	}
}

// TestNotifyMessageNewFetchRetriesUnavailableBody: a body that cannot be read
// right now (NO [UNAVAILABLE]), for example one delivered on another backend
// whose upload has not landed yet, is retried on a later tick, and the FETCH
// responses come once it can be read, each once. A body that stays
// unavailable is given up after a few ticks, and the messages after it are
// still answered.
func TestNotifyMessageNewFetchRetriesUnavailableBody(t *testing.T) {
	for _, tc := range []struct {
		name    string
		restore bool // the body becomes readable after the first failed attempt
	}{
		{name: "body becomes readable", restore: true},
		{name: "body stays unavailable", restore: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			logs := common.CaptureLogs(t)
			server, account := common.SetupIMAPServer(t)
			defer server.Close()
			login := fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)

			watcher := dialRawIMAP(t, server.Address)
			watcher.do(login)
			watcher.do("SELECT INBOX")
			watcher.do("NOTIFY SET (SELECTED (MessageNew (UID BODY.PEEK[HEADER.FIELDS (SUBJECT)]) MessageExpunge))")

			other := dialRawIMAP(t, server.Address)
			other.do(login)
			other.do("CREATE Staging")
			before := stagedFiles(t, server.UploadPath)
			other.appendMsg("Staging", binaryDecodeTestMessage("first", "text/plain", "7bit", "body first\r\n"))
			var staged string
			for path := range stagedFiles(t, server.UploadPath) {
				if !before[path] {
					staged = path
				}
			}
			other.appendMsg("Staging", binaryDecodeTestMessage("second", "text/plain", "7bit", "body second\r\n"))
			server.WaitForUploads(t)
			if staged == "" {
				t.Fatal("no staged file for the first message")
			}
			// The harness S3 fails GETs, so without its staged copy the first
			// body cannot be read: NO [UNAVAILABLE].
			body, err := os.ReadFile(staged)
			if err != nil {
				t.Fatalf("read staged file: %v", err)
			}
			if err := os.Remove(staged); err != nil {
				t.Fatalf("remove staged file: %v", err)
			}
			other.do("SELECT Staging")
			other.do("COPY 1:2 INBOX")

			var got []string
			if tc.restore {
				logs.WaitForLine(t, "message body not yet available")
				if err := os.WriteFile(staged, body, 0o600); err != nil {
					t.Fatalf("restore staged file: %v", err)
				}
				got = readNotifyUntil(t, watcher, 10*time.Second, func(resps []string) bool {
					return countFetches(resps, 1) > 0 && countFetches(resps, 2) > 0
				})
			} else {
				got = readNotifyUntil(t, watcher, 15*time.Second, func(resps []string) bool {
					return countFetches(resps, 2) > 0
				})
			}
			got = append(got, notifyNoop(t, watcher)...)

			want := map[uint32]string{1: "Subject: first", 2: "Subject: second"}
			if !tc.restore {
				want = map[uint32]string{2: "Subject: second"}
			}
			for seq := uint32(1); seq <= 2; seq++ {
				subject, ok := want[seq]
				n := countFetches(got, seq)
				switch {
				case !ok && n != 0:
					t.Errorf("message %d: its body stayed unavailable, want no FETCH, got %d:\n%s", seq, n, strings.Join(got, "\r\n"))
				case ok && n != 1:
					t.Errorf("message %d: want one MessageNew FETCH, got %d:\n%s", seq, n, strings.Join(got, "\r\n"))
				case ok && !strings.Contains(findFetch(got, seq), subject):
					t.Errorf("message %d: want %q in its MessageNew FETCH, got:\n%s", seq, subject, strings.Join(got, "\r\n"))
				}
			}
		})
	}
}

// readNotifyUntil reads the unsolicited responses of a NOTIFY session until
// done reports true for what it has read, failing after timeout. A response
// is read whole, literals included.
func readNotifyUntil(t *testing.T, c *rawIMAP, timeout time.Duration, done func(resps []string) bool) []string {
	t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	defer func() {
		if err := c.conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
	}()
	var resps []string
	for !done(resps) {
		var resp strings.Builder
		for {
			line, err := c.r.ReadString('\n')
			resp.WriteString(line)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					t.Fatalf("timed out waiting for MessageNew FETCH responses, got:\n%s%s", strings.Join(resps, "\r\n"), resp.String())
				}
				t.Fatalf("read: %v, got:\n%s%s", err, strings.Join(resps, "\r\n"), resp.String())
			}
			m := notifyLiteralRe.FindStringSubmatch(line)
			if m == nil {
				break
			}
			literal := make([]byte, mustAtoi(t, m[1]))
			if _, err := io.ReadFull(c.r, literal); err != nil {
				t.Fatalf("read literal: %v, got:\n%s%s", err, strings.Join(resps, "\r\n"), resp.String())
			}
			resp.Write(literal)
		}
		resps = append(resps, strings.TrimRight(resp.String(), "\r\n"))
	}
	return resps
}

// notifyLiteralRe matches a line that ends in a literal's length.
var notifyLiteralRe = regexp.MustCompile(`~?\{(\d+)\+?\}\r\n$`)

// notifyNoop runs a NOOP and returns the responses that came with it.
func notifyNoop(t *testing.T, c *rawIMAP) []string {
	t.Helper()
	untagged, _ := c.do("NOOP")
	return splitUntaggedResponses(untagged)
}

// countFetches counts the FETCH responses for message seq.
func countFetches(resps []string, seq uint32) int {
	n := 0
	for _, resp := range resps {
		if strings.HasPrefix(resp, fmt.Sprintf("* %d FETCH ", seq)) {
			n++
		}
	}
	return n
}

// findFetch returns the first FETCH response for message seq.
func findFetch(resps []string, seq uint32) string {
	for _, resp := range resps {
		if strings.HasPrefix(resp, fmt.Sprintf("* %d FETCH ", seq)) {
			return resp
		}
	}
	return ""
}
