//go:build integration

package imap_test

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// "$" holds UIDs of the selected mailbox only, so in a multimailbox search it
// names those messages there and no message in any other mailbox.
func TestIMAP_MultiSearch_SearchResStaysInSelectedMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	c.do("CREATE ResOther")
	for _, name := range []string{"INBOX", "ResOther"} {
		for i := 0; i < 3; i++ {
			c.appendMsg(name, fmt.Sprintf("Subject: %s %d\r\n\r\nbody\r\n", name, i))
		}
	}
	c.do("SELECT INBOX")
	c.do("UID SEARCH RETURN (SAVE) UID 2")

	allRe := regexp.MustCompile(`\bALL ([0-9:,]+)`)
	for _, tc := range []struct {
		source, criteria string
		want             map[string]string
	}{
		{"selected", "UID $", map[string]string{"INBOX": "2"}},
		{"mailboxes ResOther", "UID $", map[string]string{}},
		{"mailboxes ResOther", "$", map[string]string{}},
		{"mailboxes (INBOX ResOther)", "UID $", map[string]string{"INBOX": "2"}},
		{"mailboxes (INBOX ResOther)", "OR UID $ UID 3", map[string]string{"INBOX": "2:3", "ResOther": "3"}},
		{"mailboxes (INBOX ResOther)", "NOT UID $", map[string]string{"INBOX": "1,3", "ResOther": "1:3"}},
	} {
		t.Run(tc.source+"/"+tc.criteria, func(t *testing.T) {
			parentTest := c.t
			c.t = t
			defer func() { c.t = parentTest }()
			lines, _ := c.do(fmt.Sprintf("ESEARCH IN (%s) RETURN (ALL) %s", tc.source, tc.criteria))
			got := map[string]string{}
			for _, line := range lines {
				if !strings.HasPrefix(line, "* ESEARCH") {
					continue
				}
				mailbox := esearchLineRe.FindStringSubmatch(line)
				all := allRe.FindStringSubmatch(line)
				if mailbox == nil || all == nil {
					t.Fatalf("invalid ESEARCH response: %s", line)
				}
				name := mailbox[1]
				if name == "" {
					name = mailbox[2]
				}
				got[name] = all[1]
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ESEARCH IN (%s) %s = %v, want %v", tc.source, tc.criteria, got, tc.want)
			}
		})
	}
}
