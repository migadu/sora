//go:build integration

package imap_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
)

// RFC 5465 §5.2: "A FETCH response SHOULD NOT be generated for a new message
// created by the client on this particular connection, for instance, as the
// result of an APPEND or COPY command to the selected mailbox performed by the
// client itself." The client has the new UIDs from APPENDUID and COPYUID
// (#1357).

var notifyCopyUIDRe = regexp.MustCompile(`COPYUID \d+ \S+ (\d+)\]`)

// TestNotifyMessageNewNoFetchForOwnMessages: a message this connection adds
// to the selected mailbox itself, by APPEND or by a MOVE within the mailbox,
// gets no MessageNew FETCH; one that another connection adds after it still
// does, once.
func TestNotifyMessageNewNoFetchForOwnMessages(t *testing.T) {
	for _, tc := range []struct {
		name string
		// own adds a message to the selected INBOX on the watching connection
		// and returns the command's untagged responses and the new UID.
		own func(t *testing.T, c *rawIMAP) ([]string, imap.UID)
	}{
		{
			name: "APPEND",
			own: func(t *testing.T, c *rawIMAP) ([]string, imap.UID) {
				tag := c.nextTag()
				if _, err := fmt.Fprintf(c.conn, "%s APPEND INBOX {%d+}\r\n%s\r\n", tag, len(notifyTestMessage), notifyTestMessage); err != nil {
					t.Fatalf("APPEND write: %v", err)
				}
				untagged, tagged := c.collect(tag, "APPEND INBOX")
				m := appendUIDRe.FindStringSubmatch(tagged)
				if m == nil {
					t.Fatalf("no APPENDUID in: %s", tagged)
				}
				return splitUntaggedResponses(untagged), imap.UID(mustAtoi(t, m[1]))
			},
		},
		{
			name: "MOVE within the selected mailbox",
			own: func(t *testing.T, c *rawIMAP) ([]string, imap.UID) {
				untagged, _ := c.do("UID MOVE 1 INBOX")
				for _, line := range untagged {
					if m := notifyCopyUIDRe.FindStringSubmatch(line); m != nil {
						return splitUntaggedResponses(untagged), imap.UID(mustAtoi(t, m[1]))
					}
				}
				t.Fatalf("no COPYUID in the MOVE responses:\n%s", strings.Join(untagged, "\r\n"))
				return nil, 0
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, account := common.SetupIMAPServer(t)
			defer server.Close()
			login := fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)

			watcher := dialRawIMAP(t, server.Address)
			watcher.do(login)
			watcher.appendMsg("INBOX", notifyTestMessage) // the MOVE's source
			watcher.do("SELECT INBOX")
			watcher.do("NOTIFY SET (SELECTED (MessageNew (UID FLAGS) MessageExpunge))")

			got, ownUID := tc.own(t, watcher)

			other := dialRawIMAP(t, server.Address)
			other.do(login)
			otherUID := other.appendMsg("INBOX", notifyTestMessage)

			// The FETCH for the other connection's message comes after any
			// for the own one: MessageNew fetches in UID order.
			got = append(got, readNotifyUntil(t, watcher, 10*time.Second, func(resps []string) bool {
				return countUIDFetches(resps, otherUID) > 0
			})...)
			got = append(got, notifyNoop(t, watcher)...)

			if n := countUIDFetches(got, ownUID); n != 0 {
				t.Errorf("UID %d was created on this connection, want no MessageNew FETCH for it, got %d:\n%s", ownUID, n, strings.Join(got, "\r\n"))
			}
			if n := countUIDFetches(got, otherUID); n != 1 {
				t.Errorf("want one MessageNew FETCH for UID %d from another connection, got %d:\n%s", otherUID, n, strings.Join(got, "\r\n"))
			}
		})
	}
}

// countUIDFetches counts the FETCH responses that carry UID uid.
func countUIDFetches(resps []string, uid imap.UID) int {
	re := regexp.MustCompile(fmt.Sprintf(`^\* \d+ FETCH \(.*[( ]UID %d[ )]`, uid))
	n := 0
	for _, resp := range resps {
		if re.MatchString(resp) {
			n++
		}
	}
	return n
}
