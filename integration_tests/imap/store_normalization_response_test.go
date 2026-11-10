//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_Store_NormalizedNoopResponse(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	c.appendMsg("INBOX", "Subject: noop\r\n\r\nbody\r\n")
	c.do("SELECT INBOX")
	c.do(`STORE 1 FLAGS (\Seen)`)
	for _, tc := range []struct{ name, command string }{
		{"stripped color", `STORE 1 FLAGS (\Seen $MailFlagBit0)`},
		{"conflicting attachments add", `STORE 1 +FLAGS ($HasAttachment $HasNoAttachment)`},
		{"conflicting attachments set", `UID STORE 1 FLAGS (\Seen $HasAttachment $HasNoAttachment)`},
		{"unchanged flags", `STORE 1 FLAGS (\Seen)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines, _ := c.do(tc.command)
			var fetches []string
			for _, line := range lines {
				if strings.Contains(line, " FETCH ") {
					fetches = append(fetches, line)
				}
			}
			if len(fetches) != 1 {
				t.Fatalf("%s returned %d FETCH responses, want 1: %v", tc.command, len(fetches), lines)
			}
			if !strings.Contains(fetches[0], `FLAGS (\Seen)`) {
				t.Errorf("response = %s, want the actual normalized flags", fetches[0])
			}
		})
	}
	// UNCHANGEDSINCE failures must not be reintroduced as successful no-op replies.
	lines, _ := c.do(`STORE 1 (UNCHANGEDSINCE 0) FLAGS (\Seen $MailFlagBit0)`)
	for _, line := range lines {
		if strings.Contains(line, " FETCH ") {
			t.Errorf("failed UNCHANGEDSINCE returned FETCH: %s", line)
		}
	}
}
