//go:build integration

package imap_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	imapsrv "github.com/migadu/sora/server/imap"
)

// The unit test proves one extraction per retained section; this wire control
// checks large binary/body chunks and their echoed origins through actual
// APPEND, storage, FETCH encoding and the client parser.
func TestIMAP_LargeSectionSpillWire(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()
	c, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("0123456789abcdef"), (9<<20)/16)
	encoded := base64.StdEncoding.EncodeToString(payload)
	raw := "From: a@example.com\r\nSubject: spill wire\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n" + encoded + "\r\n"
	appendRaw(t, c, "INBOX", raw, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	for _, binary := range []bool{true, false} {
		for _, offset := range []int64{0, 65536} {
			partial := &imap.SectionPartial{Offset: offset, Size: 65536}
			opts := &imap.FetchOptions{}
			if binary {
				opts.BinarySection = []*imap.FetchItemBinarySection{{Part: []int{1}, Peek: true, Partial: partial}}
			} else {
				opts.BodySection = []*imap.FetchItemBodySection{{Part: []int{1}, Peek: true, Partial: partial}}
			}
			msgs, err := c.Fetch(imap.SeqSetNum(1), opts).Collect()
			if err != nil || len(msgs) != 1 {
				t.Fatalf("binary=%v offset=%d: messages=%d err=%v", binary, offset, len(msgs), err)
			}
			var got, want []byte
			var origin *imap.SectionPartial
			if binary {
				if len(msgs[0].BinarySection) != 1 {
					t.Fatal("missing BINARY section")
				}
				got, origin = msgs[0].BinarySection[0].Bytes, msgs[0].BinarySection[0].Section.Partial
				want = payload[offset : offset+65536]
			} else {
				if len(msgs[0].BodySection) != 1 {
					t.Fatal("missing BODY section")
				}
				got, origin = msgs[0].BodySection[0].Bytes, msgs[0].BodySection[0].Section.Partial
				want = []byte(encoded[offset : offset+65536])
			}
			if !bytes.Equal(got, want) || origin == nil || origin.Offset != offset {
				t.Fatalf("binary=%v offset=%d: bytes=%d origin=%v", binary, offset, len(got), origin)
			}
		}
	}
}

// Background NOTIFY MessageNew unsolicited FETCH pushes with a <partial>
// fetch-att must neither evict an active client's retained/spilled section nor
// populate bodySectionCache across IDLE.
func TestNotifyMessageNewPartialDoesNotPopulateOrEvictSectionCache(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	for _, tc := range []struct {
		name     string
		partSize int
		binary   bool
	}{
		{name: "retained BODY", partSize: 64 << 10, binary: false},
		{name: "retained BINARY", partSize: 64 << 10, binary: true},
		{name: "spilled BODY", partSize: 9 << 20, binary: false},
		{name: "spilled BINARY", partSize: 9 << 20, binary: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imapsrv.SetNotifyPollIntervalForTests(50 * time.Millisecond)
			t.Cleanup(func() { imapsrv.SetNotifyPollIntervalForTests(notifyTestPollInterval) })

			srv, account := common.SetupIMAPServer(t)
			defer srv.Close()
			login := fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)

			msg1Raw, want1 := notifyMultipartBase64Fixture("msg-1", bytes.Repeat([]byte("A1B2C3D4E5F6G7H8"), tc.partSize/16), tc.binary)
			msg2Raw, _ := notifyMultipartBase64Fixture("msg-2", bytes.Repeat([]byte("J9K0L1M2N3P4Q5R6"), tc.partSize/16), tc.binary)
			msg3Raw, _ := notifyMultipartBase64Fixture("msg-3", bytes.Repeat([]byte("S7T8U9V0W1X2Y3Z4"), tc.partSize/16), tc.binary)

			other := dialRawIMAP(t, srv.Address)
			other.do(login)
			other.do("CREATE Staging")

			uid1, staged1 := appendAndCaptureStagedFile(t, other, srv.UploadPath, "INBOX", msg1Raw)
			_, _ = appendAndCaptureStagedFile(t, other, srv.UploadPath, "Staging", msg2Raw)
			_, staged3 := appendAndCaptureStagedFile(t, other, srv.UploadPath, "Staging", msg3Raw)

			itemSpec := "BODY.PEEK[2]"
			if tc.binary {
				itemSpec = "BINARY.PEEK[2]"
			}

			watcher := dialRawIMAP(t, srv.Address)
			watcher.do(login)
			watcher.do("SELECT INBOX")
			watcher.do(fmt.Sprintf("NOTIFY SET (SELECTED (MessageNew (UID FLAGS %s<0.512>) MessageExpunge))", itemSpec))

			// Prime watcher's section cache (in-memory or spilled) with chunk 0 of msg 1.
			lit0, status0 := rawFetchLiteral(t, watcher, fmt.Sprintf("UID FETCH %d (%s<0.512>)", uid1, itemSpec))
			if !strings.HasPrefix(status0, "OK") || !bytes.Equal(lit0, want1[:512]) {
				t.Fatalf("initial chunk status=%q len=%d, want OK with 512 matching bytes", status0, len(lit0))
			}

			// Remove msg 1's backing file so chunk 1 can ONLY succeed if msg 1's
			// retained/spilled section was not evicted from watcher's cache.
			if err := os.Remove(staged1); err != nil {
				t.Fatalf("remove staged1: %v", err)
			}

			// Deliver msg 2 to INBOX so NotifyPoll runs s.fetch(..., &progress) with <0.512>.
			other.do("SELECT Staging")
			other.do("COPY 1 INBOX")
			readNotifyUntil(t, watcher, 5*time.Second, func(resps []string) bool {
				return countFetches(resps, 2) > 0
			})

			lit1, status1 := rawFetchLiteral(t, watcher, fmt.Sprintf("UID FETCH %d (%s<512.512>)", uid1, itemSpec))
			if !strings.HasPrefix(status1, "OK") || !bytes.Equal(lit1, want1[512:1024]) {
				t.Errorf("second chunk after NOTIFY MessageNew: status=%q len=%d, want OK with 512 cached bytes (NOTIFY evicted active client section)",
					status1, len(lit1))
			}

			// Enter IDLE (which drops any client-retained section), deliver msg 3 so
			// NotifyPoll runs MessageNew <0.512> during IDLE, then remove msg 3's
			// backing file before leaving IDLE.
			idleTag := watcher.send("IDLE")
			cont, err := watcher.r.ReadString('\n')
			if err != nil || !strings.HasPrefix(cont, "+ ") {
				t.Fatalf("IDLE continuation = %q, err = %v", cont, err)
			}

			other.do("COPY 2 INBOX")
			readNotifyUntil(t, watcher, 5*time.Second, func(resps []string) bool {
				return countFetches(resps, 3) > 0
			})
			if err := os.Remove(staged3); err != nil {
				t.Fatalf("remove staged3: %v", err)
			}

			if _, err := fmt.Fprintf(watcher.conn, "DONE\r\n"); err != nil {
				t.Fatalf("write DONE: %v", err)
			}
			watcher.collect(idleTag, "IDLE DONE")

			// Because msg 3's backing file is gone and the client never issued a
			// chunked FETCH for msg 3, UID FETCH 3 must fail with NO [UNAVAILABLE]
			// rather than serving bytes retained/spilled by NOTIFY during IDLE.
			_, status3 := rawFetchLiteral(t, watcher, fmt.Sprintf("UID FETCH 3 (%s<512.512>)", itemSpec))
			if !strings.HasPrefix(status3, "NO [UNAVAILABLE]") {
				t.Fatalf("UID FETCH 3 after IDLE MessageNew = %q, want NO [UNAVAILABLE] (NOTIFY populated section cache during IDLE)", status3)
			}
		})
	}
}

func notifyMultipartBase64Fixture(subject string, payload []byte, wantBinary bool) (raw string, wantPart2 []byte) {
	encoded := base64.StdEncoding.EncodeToString(payload)
	var part2 strings.Builder
	for len(encoded) > 76 {
		part2.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	part2.WriteString(encoded)
	part2Raw := part2.String()

	var msg strings.Builder
	msg.WriteString("From: sender@example.com\r\n")
	msg.WriteString("To: rcpt@example.com\r\n")
	msg.WriteString("Subject: " + subject + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n")
	msg.WriteString("--B\r\nContent-Type: text/plain\r\n\r\ntext\r\n")
	msg.WriteString("--B\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	msg.WriteString(part2Raw + "\r\n--B--\r\n")
	if wantBinary {
		return msg.String(), payload
	}
	return msg.String(), []byte(part2Raw)
}

func appendAndCaptureStagedFile(t *testing.T, c *rawIMAP, uploadPath, mailbox, raw string) (imap.UID, string) {
	t.Helper()
	before := stagedFiles(t, uploadPath)
	uid := c.appendMsg(mailbox, raw)
	for path := range stagedFiles(t, uploadPath) {
		if !before[path] {
			return uid, path
		}
	}
	t.Fatalf("no new staged file in %s after APPEND to %s", uploadPath, mailbox)
	return 0, ""
}

func rawFetchLiteral(t *testing.T, c *rawIMAP, cmd string) (literal []byte, status string) {
	t.Helper()
	tag := c.send(cmd)
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			t.Fatalf("read (%s): %v", cmd, err)
		}
		if strings.HasPrefix(line, tag+" ") {
			return literal, strings.TrimRight(strings.TrimPrefix(line, tag+" "), "\r\n")
		}
		if m := notifyLiteralRe.FindStringSubmatch(line); m != nil {
			buf := make([]byte, mustAtoi(t, m[1]))
			if _, err := io.ReadFull(c.r, buf); err != nil {
				t.Fatalf("read literal (%s): %v", cmd, err)
			}
			literal = buf
		}
	}
}
