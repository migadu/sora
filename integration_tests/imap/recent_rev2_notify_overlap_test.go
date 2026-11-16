//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// A MessageNew body can be prepared while ENABLE changes the connection's
// revision. FLAGS must use the revision at response time, as MODSEQ already does.
func TestIMAP_RecentFlagsRespectRev2DuringNotifyBody(t *testing.T) {
	for _, enable := range []bool{false, true} {
		name := "rev1_control"
		if enable {
			name = "enable_while_body_loading"
		}
		t.Run(name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, account, fake := common.SetupIMAPServerWithRealS3(t)
			defer server.Close()
			c := dialRawIMAP(t, server.Address)
			require.NoError(t, c.conn.SetDeadline(time.Now().Add(15*time.Second)))
			c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
			c.do("SELECT INBOX")
			c.do("NOTIFY SET (SELECTED (MessageNew (UID FLAGS BINARY.PEEK[1]) MessageExpunge FlagChange))")
			entered, resume := make(chan struct{}), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(resume) }) }
			defer release()
			var gets atomic.Int32
			fake.OnGet(func(string) {
				if gets.Add(1) == 1 {
					close(entered)
					<-resume
				}
			})
			defer fake.OnGet(nil)
			other := dialRawIMAP(t, server.Address)
			other.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
			other.appendMsg("INBOX", binaryDecodeTestMessage("notify revision", "text/plain", "base64", "aGVsbG8=\r\n"))
			server.WaitForUploads(t)
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("notification did not pause before response")
			}
			var before, after []string
			if enable {
				tag := c.send("ENABLE IMAP4rev2")
				for {
					line, err := c.r.ReadString('\n')
					require.NoError(t, err)
					line = strings.TrimRight(line, "\r\n")
					before = append(before, line)
					if strings.HasPrefix(line, "* ENABLED ") {
						require.Contains(t, line, "IMAP4rev2")
						break
					}
				}
				release()
				after, _ = c.collect(tag, "ENABLE during notification")
			} else {
				release()
			}
			noop, _ := c.do("NOOP")
			after = append(after, noop...)
			responses := fetchResponsesForSeq(after, 1)
			require.NotEmpty(t, responses, "notification absent: before=%q after=%q", before, after)
			for _, response := range responses {
				require.Contains(t, response, "FLAGS (", "missing requested FLAGS: %q", after)
				require.Equal(t, !enable, strings.Contains(response, `\Recent`), "wrong revision FLAGS: before=%q after=%q", before, after)
			}
		})
	}
}
