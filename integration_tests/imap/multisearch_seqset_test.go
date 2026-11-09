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

func TestIMAP_MultiSearch_SequenceSetsPerMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	for _, name := range []string{"SeqA", "SeqB", "SeqEmpty"} {
		c.do("CREATE " + name)
	}
	for name, count := range map[string]int{"SeqA": 3, "SeqB": 1, "INBOX": 4} {
		for i := 0; i < count; i++ {
			c.appendMsg(name, fmt.Sprintf("Subject: %s %d\r\n\r\nbody\r\n", name, i))
		}
	}
	c.do("SELECT SeqA")
	c.do(`STORE 1 +FLAGS (\Deleted)`)
	c.do("EXPUNGE")
	c.do("UNSELECT")
	// SeqA has sequence 1=UID 2, sequence 2=UID 3. SeqB has sequence 1=UID 1.
	// The selected INBOX, when present, has a different highest sequence (4).
	allRe := regexp.MustCompile(`\bALL ([0-9:,]+)`)
	for _, selected := range []bool{false, true} {
		if selected {
			c.do("SELECT INBOX")
		}
		for _, tc := range []struct {
			criteria string
			want     map[string]string
		}{
			{"1", map[string]string{"SeqA": "2", "SeqB": "1"}},
			{"*", map[string]string{"SeqA": "3", "SeqB": "1"}},
			{"*:1", map[string]string{"SeqA": "2:3", "SeqB": "1"}},
			{"99:*", map[string]string{"SeqA": "3", "SeqB": "1"}},
			{"NOT 1", map[string]string{"SeqA": "3"}},
			{"OR 1 UID 99", map[string]string{"SeqA": "2", "SeqB": "1"}},
		} {
			t.Run(fmt.Sprintf("selected=%v/%s", selected, tc.criteria), func(t *testing.T) {
				parentTest := c.t
				c.t = t
				defer func() { c.t = parentTest }()
				lines, _ := c.do(`ESEARCH IN (mailboxes (SeqA SeqB SeqEmpty)) RETURN (ALL) ` + tc.criteria)
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
					t.Errorf("ESEARCH %s = %v, want %v", tc.criteria, got, tc.want)
				}
			})
		}
	}
}
