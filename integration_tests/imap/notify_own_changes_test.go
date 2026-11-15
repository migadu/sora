//go:build integration

package imap_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// RFC 5465 §5: "The server SHOULD omit notifying the client if the event is
// caused by this client. For example, if the client issues CREATE and has
// requested a MailboxName event that would cover the newly created mailbox,
// the server SHOULD NOT notify the client of the MailboxName change." (#1496)

// notifyEventRe matches an unsolicited LIST or STATUS response and captures
// its mailbox name, quoted or not.
var notifyEventRe = regexp.MustCompile(`^\* (LIST|STATUS) (?:\([^)]*\) "/" )?"?([^"( ]+)"?`)

// TestNotifyNoEventsForOwnChanges: the mailbox-tree changes a NOTIFY client
// makes itself (CREATE, RENAME, DELETE, SUBSCRIBE, UNSUBSCRIBE) get no LIST,
// and what it adds to other watched mailboxes (APPEND, COPY, MOVE, RENAME
// INBOX) no STATUS.
// The same kinds of change made by another connection afterwards are still
// reported.
func TestNotifyNoEventsForOwnChanges(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	login := fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)

	watcher := dialRawIMAP(t, server.Address)
	watcher.do(login)
	for _, name := range []string{"Appended", "Copied", "Moved", "Gone", "Old/Kid", "Subbed"} {
		watcher.do("CREATE " + name)
	}
	watcher.do("SUBSCRIBE Subbed")
	watcher.appendMsg("INBOX", notifyTestMessage) // UID 1, copied
	watcher.appendMsg("INBOX", notifyTestMessage) // UID 2, moved
	watcher.do("SELECT INBOX")
	watcher.do("NOTIFY SET (SELECTED (MessageNew MessageExpunge)) " +
		"(PERSONAL (MessageNew MessageExpunge MailboxName SubscriptionChange))")

	// The notifications the pump writes while a command runs come with that
	// command's responses.
	var got []string
	own := func(cmd string) {
		untagged, _ := watcher.do(cmd)
		got = append(got, splitUntaggedResponses(untagged)...)
	}
	ownAppend := func(mailbox string) {
		tag := watcher.nextTag()
		if _, err := fmt.Fprintf(watcher.conn, "%s APPEND %s {%d+}\r\n%s\r\n", tag, mailbox, len(notifyTestMessage), notifyTestMessage); err != nil {
			t.Fatalf("APPEND write: %v", err)
		}
		untagged, _ := watcher.collect(tag, "APPEND "+mailbox)
		got = append(got, splitUntaggedResponses(untagged)...)
	}

	own("CREATE Projects")
	own("SUBSCRIBE Projects")
	own("CREATE Parent/Child")  // creates Parent too
	own("RENAME Old Attic/Old") // creates Attic
	own("DELETE Gone")
	own("UNSUBSCRIBE Subbed")
	ownAppend("Appended")
	own("UID COPY 1 Copied")
	own("UID MOVE 2 Moved")
	own("RENAME INBOX Saved") // creates Saved and moves UID 1 there
	own("CREATE Fresh")
	ownAppend("Fresh")

	other := dialRawIMAP(t, server.Address)
	other.do(login)
	other.do("CREATE Marker")
	other.appendMsg("Appended", notifyTestMessage)

	// The pump reports the other connection's changes in the same tick as any
	// own ones it would report, or a later one.
	got = append(got, readNotifyUntil(t, watcher, 10*time.Second, func(resps []string) bool {
		var marker, appended bool
		for _, resp := range resps {
			if m := notifyEventRe.FindStringSubmatch(resp); m != nil {
				marker = marker || (m[1] == "LIST" && m[2] == "Marker")
				appended = appended || (m[1] == "STATUS" && m[2] == "Appended" && strings.Contains(resp, "MESSAGES 2"))
			}
		}
		return marker && appended
	})...)
	got = append(got, notifyNoop(t, watcher)...)

	var lists, statuses []string
	for _, resp := range got {
		m := notifyEventRe.FindStringSubmatch(resp)
		switch {
		case m == nil:
		case m[1] == "LIST" && m[2] != "Marker":
			lists = append(lists, resp)
		case m[1] == "STATUS" && (m[2] != "Appended" || !strings.Contains(resp, "MESSAGES 2")):
			statuses = append(statuses, resp)
		}
	}
	if len(lists) > 0 {
		t.Errorf("want no LIST for the mailbox-tree changes this connection made, got:\n%s", strings.Join(lists, "\r\n"))
	}
	if len(statuses) > 0 {
		t.Errorf("want no STATUS for the messages this connection added, only for the other connection's, got:\n%s", strings.Join(statuses, "\r\n"))
	}
	if t.Failed() {
		t.Logf("all responses:\n%s", strings.Join(got, "\r\n"))
	}
}
