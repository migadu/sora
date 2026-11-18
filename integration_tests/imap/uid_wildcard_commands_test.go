//go:build integration

package imap_test

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// UID command sequence sets resolve '*' to the highest live UID, even when
// their other endpoint is UIDNEXT and the last allocated UID was expunged.
func TestIMAP_UIDWildcardCommands(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	for i, command := range []string{"FETCH", "STORE", "COPY", "MOVE", "EXPUNGE", "EXPUNGE star", "EXPUNGE mixed", "EXPUNGE undeleted tail"} {
		t.Run(command, func(t *testing.T) {
			c := dialRawIMAP(t, server.Address)
			c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
			box := fmt.Sprintf("UIDWildcard%d", i)
			c.do("CREATE " + box)
			var uids []imap.UID
			for n := 1; n <= 4; n++ {
				uids = append(uids, c.appendMsg(box, fmt.Sprintf("From: sender@example.com\r\nTo: recipient@example.com\r\nMessage-ID: <wildcard-%d@example.com>\r\nSubject: Wildcard message %d\r\n\r\nbody\r\n", n, n)))
			}
			c.do("SELECT " + box)
			c.do(fmt.Sprintf(`UID STORE %d +FLAGS.SILENT (\Deleted)`, uids[3]))
			c.do(fmt.Sprintf("UID EXPUNGE %d", uids[3]))
			lines, _ := c.do("STATUS " + box + " (UIDNEXT)")
			m := regexp.MustCompile(`UIDNEXT ([0-9]+)`).FindStringSubmatch(strings.Join(lines, " "))
			require.Len(t, m, 2)
			uidNext := mustAtoi(t, m[1])
			require.Greater(t, uidNext, int(uids[3]))
			set := fmt.Sprintf("%d:*", uidNext)
			last := uids[2]

			switch command {
			case "FETCH":
				for _, tc := range []struct {
					set  string
					want []imap.UID
				}{
					{set, []imap.UID{last}},
					{fmt.Sprintf("*:%d", uidNext), []imap.UID{last}},
					{"*", []imap.UID{last}},
					{fmt.Sprintf("%d,%s", uids[0], set), []imap.UID{uids[0], last}},
					{"1:*", uids[:3]},
					{fmt.Sprint(uidNext), nil},
				} {
					got := uidWildcardFetchUIDs(t, c, tc.set)
					if !slices.Equal(got, tc.want) {
						t.Errorf("UID FETCH %s = %v, want %v", tc.set, got, tc.want)
					}
				}
			case "STORE":
				c.do("UID STORE " + set + ` +FLAGS.SILENT (\Flagged)`)
				require.Equal(t, []imap.UID{last}, c.fetchFlaggedUIDs("1:*"))
			case "COPY", "MOVE":
				dest := box + "Dest"
				c.do("CREATE " + dest)
				c.do("UID " + command + " " + set + " " + dest)
				wantSource := uids[:3]
				if command == "MOVE" {
					wantSource = uids[:2]
				}
				require.True(t, slices.Equal(wantSource, uidWildcardFetchUIDs(t, c, "1:*")), "source mailbox has wrong UIDs after %s", command)
				c.do("SELECT " + dest)
				require.Len(t, uidWildcardFetchUIDs(t, c, "1:*"), 1)
				lines, _ := c.do(`UID SEARCH SUBJECT "Wildcard message 3"`)
				require.Contains(t, lines, "* SEARCH 1", "destination must contain the highest live source message")
			case "EXPUNGE", "EXPUNGE star", "EXPUNGE mixed":
				c.do(fmt.Sprintf(`UID STORE %d:%d +FLAGS.SILENT (\Deleted)`, uids[0], last))
				want := uids[:2]
				if command == "EXPUNGE star" {
					set = "*"
				} else if command == "EXPUNGE mixed" {
					// Resolving the final range moves its start before the
					// preceding nonexistent range; the result must stay sorted.
					set = fmt.Sprintf("%d,%d:%d,%d:*", uids[0], uids[3], uidNext, uidNext+100)
					want = []imap.UID{uids[1]}
				}
				c.do("UID EXPUNGE " + set)
				require.Equal(t, want, uidWildcardFetchUIDs(t, c, "1:*"))
			case "EXPUNGE undeleted tail":
				c.do(fmt.Sprintf(`UID STORE %d:%d +FLAGS.SILENT (\Deleted)`, uids[0], uids[1]))
				for _, target := range []string{set, "*"} {
					c.do("UID EXPUNGE " + target)
					require.Equal(t, uids[:3], uidWildcardFetchUIDs(t, c, "1:*"), "UID EXPUNGE %s must use the whole mailbox's tail", target)
				}
			}
		})
	}
}

func uidWildcardFetchUIDs(t *testing.T, c *rawIMAP, set string) []imap.UID {
	t.Helper()
	lines, _ := c.do("UID FETCH " + set + " UID")
	var uids []imap.UID
	for _, line := range lines {
		if !strings.Contains(line, " FETCH ") {
			continue
		}
		if m := uidRe.FindStringSubmatch(line); m != nil {
			uids = append(uids, imap.UID(mustAtoi(t, m[1])))
		}
	}
	slices.Sort(uids)
	return uids
}
