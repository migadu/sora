//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
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

// TestNotifyOwnCreateBelowAnInvisibleLevel: a client creating a mailbox below
// another user's shared mailbox gets no LIST for its CREATE, and none for the
// namespace root above it either. The root is the owner's mailbox, which the
// client has no 'l' right on, so its account snapshot never shows it: nothing
// happened to it, and it must not be reported \NonExistent. What the owner
// creates there afterwards is still reported.
func TestNotifyOwnCreateBelowAnInvisibleLevel(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	member := fmt.Sprintf("member-%d@example.com", common.GetTimestamp())
	if _, err := server.ResilientDB.CreateAccountWithRetry(context.Background(), db.CreateAccountRequest{
		Email: member, Password: "password", HashType: "bcrypt", IsPrimary: true,
	}); err != nil {
		t.Fatalf("create member account: %v", err)
	}

	ownerConn := dialRawIMAP(t, server.Address)
	ownerConn.do(fmt.Sprintf(`LOGIN "%s" "%s"`, owner.Email, owner.Password))
	ownerConn.do("CREATE Shared/Team") // creates the owner's Shared too
	ownerConn.do(fmt.Sprintf(`SETACL Shared/Team "%s" lrk`, member))

	watcher := dialRawIMAP(t, server.Address)
	watcher.do(fmt.Sprintf(`LOGIN "%s" "password"`, member))
	watcher.do("NOTIFY SET (SUBTREE Shared (MailboxName SubscriptionChange))")
	untagged, _ := watcher.do("CREATE Shared/Team/Sub")
	got := splitUntaggedResponses(untagged)

	ownerConn.do("CREATE Shared/Team/Marker")
	got = append(got, readNotifyUntil(t, watcher, 10*time.Second, func(resps []string) bool {
		return slices.ContainsFunc(resps, func(resp string) bool { return strings.Contains(resp, "Shared/Team/Marker") })
	})...)
	got = append(got, notifyNoop(t, watcher)...)

	var lists []string
	for _, resp := range got {
		if m := notifyEventRe.FindStringSubmatch(resp); m != nil && m[1] == "LIST" {
			if m[2] == "Shared/Team/Marker" {
				continue
			}
			if m[2] == "Shared/Team" && !strings.Contains(resp, `\NonExistent`) {
				// The foreign Marker creation affects its visible direct parent
				// too (RFC 5465 §5.4). Neither is this connection's CREATE.
				continue
			}
			lists = append(lists, resp)
		}
	}
	if len(lists) > 0 {
		t.Errorf("want no LIST for the client's own CREATE, got:\n%s", strings.Join(lists, "\r\n"))
	}
}

// TestNotifyOwnRenameUnselectedInbox: RENAME INBOX moves INBOX's messages to
// the new mailbox and soft-expunges INBOX without requiring INBOX to be
// selected. When INBOX is watched as a non-selected mailbox, neither the new
// mailbox nor INBOX gets a STATUS for the client's own RENAME INBOX, while a
// later foreign delivery to INBOX still does.
func TestNotifyOwnRenameUnselectedInbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	for _, mode := range []string{"authenticated", "other_selected"} {
		t.Run(mode, func(t *testing.T) {
			server, account := common.SetupIMAPServer(t)
			defer server.Close()
			login := fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)

			watcher := dialRawIMAP(t, server.Address)
			watcher.do(login)
			watcher.do("CREATE MarkerBox")
			watcher.appendMsg("INBOX", notifyTestMessage)
			if mode == "other_selected" {
				watcher.do("CREATE Other")
				watcher.do("SELECT Other")
			}
			watcher.do("NOTIFY SET (PERSONAL (MessageNew MessageExpunge MailboxName SubscriptionChange))")

			untagged, _ := watcher.do("RENAME INBOX Saved")
			got := splitUntaggedResponses(untagged)

			other := dialRawIMAP(t, server.Address)
			other.do(login)
			other.appendMsg("MarkerBox", notifyTestMessage)

			got = append(got, readNotifyUntil(t, watcher, 10*time.Second, func(resps []string) bool {
				return slices.ContainsFunc(resps, func(resp string) bool {
					m := notifyEventRe.FindStringSubmatch(resp)
					return m != nil && m[1] == "STATUS" && m[2] == "MarkerBox"
				})
			})...)
			got = append(got, notifyNoop(t, watcher)...)

			var unexpected []string
			for _, resp := range got {
				m := notifyEventRe.FindStringSubmatch(resp)
				if m == nil {
					continue
				}
				if m[1] == "STATUS" && m[2] == "MarkerBox" {
					continue
				}
				unexpected = append(unexpected, resp)
			}
			if len(unexpected) > 0 {
				t.Errorf("want no NOTIFY event for own RENAME INBOX when INBOX is not selected, got:\n%s", strings.Join(unexpected, "\r\n"))
			}

			// A subsequent foreign delivery to INBOX must still be reported.
			other.appendMsg("INBOX", notifyTestMessage)
			afterForeign := readNotifyUntil(t, watcher, 10*time.Second, func(resps []string) bool {
				return slices.ContainsFunc(resps, func(resp string) bool {
					m := notifyEventRe.FindStringSubmatch(resp)
					return m != nil && m[1] == "STATUS" && m[2] == "INBOX" && strings.Contains(resp, "MESSAGES 1")
				})
			})
			if !slices.ContainsFunc(afterForeign, func(resp string) bool {
				m := notifyEventRe.FindStringSubmatch(resp)
				return m != nil && m[1] == "STATUS" && m[2] == "INBOX" && strings.Contains(resp, "MESSAGES 1")
			}) {
				t.Errorf("want STATUS INBOX (MESSAGES 1) for subsequent foreign delivery, got:\n%s", strings.Join(afterForeign, "\r\n"))
			}
		})
	}
}

// TestNotifyOwnCopyWithoutFlagRights: when a user holds 'lri' without full flag
// rights ('s', 't', 'w') on a watched shared mailbox, COPY strips disallowed
// source flags after inserting the copied messages. Those post-copy flag-strip
// updates are still part of the client's own COPY and must not emit a spurious
// STATUS, while a subsequent foreign write to the shared mailbox still does.
func TestNotifyOwnCopyWithoutFlagRights(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner, _ := common.SetupIMAPServerWithRealS3(t)
	defer server.Close()

	member := fmt.Sprintf("member-copy-%d@example.com", common.GetTimestamp())
	if _, err := server.ResilientDB.CreateAccountWithRetry(context.Background(), db.CreateAccountRequest{
		Email: member, Password: "password", HashType: "bcrypt", IsPrimary: true,
	}); err != nil {
		t.Fatalf("create member account: %v", err)
	}

	ownerConn := dialRawIMAP(t, server.Address)
	ownerConn.do(fmt.Sprintf(`LOGIN "%s" "%s"`, owner.Email, owner.Password))
	ownerConn.do("CREATE Shared/Team")
	ownerConn.do("CREATE Shared/MarkerBox")
	ownerConn.do(fmt.Sprintf(`SETACL Shared/Team "%s" lri`, member))
	ownerConn.do(fmt.Sprintf(`SETACL Shared/MarkerBox "%s" lr`, member))

	watcher := dialRawIMAP(t, server.Address)
	watcher.do(fmt.Sprintf(`LOGIN "%s" "password"`, member))
	watcher.appendMsg("INBOX", notifyTestMessage)
	watcher.do("SELECT INBOX")
	watcher.do(`UID STORE 1 +FLAGS (\Seen $Important)`)
	watcher.do("NOTIFY SET (SUBTREE Shared (MessageNew MessageExpunge FlagChange))")

	untagged, _ := watcher.do("UID COPY 1 Shared/Team")
	got := splitUntaggedResponses(untagged)

	ownerConn.appendMsg("Shared/MarkerBox", notifyTestMessage)
	got = append(got, readNotifyUntil(t, watcher, 10*time.Second, func(resps []string) bool {
		return slices.ContainsFunc(resps, func(resp string) bool {
			m := notifyEventRe.FindStringSubmatch(resp)
			return m != nil && m[1] == "STATUS" && m[2] == "Shared/MarkerBox"
		})
	})...)
	got = append(got, notifyNoop(t, watcher)...)

	var unexpected []string
	for _, resp := range got {
		m := notifyEventRe.FindStringSubmatch(resp)
		if m != nil && m[1] == "STATUS" && m[2] != "Shared/MarkerBox" {
			unexpected = append(unexpected, resp)
		}
	}
	if len(unexpected) > 0 {
		t.Errorf("want no STATUS for own COPY with flag stripping on Shared/Team, got:\n%s", strings.Join(unexpected, "\r\n"))
	}

	// A subsequent foreign delivery to Shared/Team must still emit STATUS.
	ownerConn.appendMsg("Shared/Team", notifyTestMessage)
	afterForeign := readNotifyUntil(t, watcher, 10*time.Second, func(resps []string) bool {
		return slices.ContainsFunc(resps, func(resp string) bool {
			m := notifyEventRe.FindStringSubmatch(resp)
			return m != nil && m[1] == "STATUS" && m[2] == "Shared/Team" && strings.Contains(resp, "MESSAGES 2")
		})
	})
	if !slices.ContainsFunc(afterForeign, func(resp string) bool {
		m := notifyEventRe.FindStringSubmatch(resp)
		return m != nil && m[1] == "STATUS" && m[2] == "Shared/Team" && strings.Contains(resp, "MESSAGES 2")
	}) {
		t.Errorf("want STATUS Shared/Team (MESSAGES 2) for subsequent foreign delivery, got:\n%s", strings.Join(afterForeign, "\r\n"))
	}
}

// TestNotifyOwnNonOwnerRenameSubscribedSharedMailbox: db.RenameMailbox only
// rewrites subscriptions owned by the mailbox owner, so when a non-owner
// holding 'lx' renames a subscribed shared mailbox (and its subscribed child),
// the new names are unsubscribed for the non-owner in the database. That
// change is caused by the non-owner's own RENAME and must not emit spurious
// SubscriptionChange LIST responses, while a subsequent foreign SUBSCRIBE on
// another connection of the non-owner is still reported.
func TestNotifyOwnNonOwnerRenameSubscribedSharedMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	member := fmt.Sprintf("member-rename-%d@example.com", common.GetTimestamp())
	if _, err := server.ResilientDB.CreateAccountWithRetry(context.Background(), db.CreateAccountRequest{
		Email: member, Password: "password", HashType: "bcrypt", IsPrimary: true,
	}); err != nil {
		t.Fatalf("create member account: %v", err)
	}

	ownerConn := dialRawIMAP(t, server.Address)
	ownerConn.do(fmt.Sprintf(`LOGIN "%s" "%s"`, owner.Email, owner.Password))
	ownerConn.do("CREATE Shared/Team")
	ownerConn.do("CREATE Shared/Team/Old")
	ownerConn.do("CREATE Shared/Team/Old/Kid")
	ownerConn.do(fmt.Sprintf(`SETACL Shared/Team "%s" lrkx`, member))
	ownerConn.do(fmt.Sprintf(`SETACL Shared/Team/Old "%s" lrkx`, member))
	ownerConn.do(fmt.Sprintf(`SETACL Shared/Team/Old/Kid "%s" lrkx`, member))

	memberLogin := fmt.Sprintf(`LOGIN "%s" "password"`, member)
	watcher := dialRawIMAP(t, server.Address)
	watcher.do(memberLogin)
	watcher.do("SUBSCRIBE Shared/Team/Old")
	watcher.do("SUBSCRIBE Shared/Team/Old/Kid")
	watcher.do("NOTIFY SET (SUBTREE Shared (MailboxName SubscriptionChange))")

	untagged, _ := watcher.do("RENAME Shared/Team/Old Shared/Team/New")
	got := splitUntaggedResponses(untagged)

	ownerConn.do("CREATE Shared/Team/Marker1")
	got = append(got, readNotifyUntil(t, watcher, 10*time.Second, func(resps []string) bool {
		return slices.ContainsFunc(resps, func(resp string) bool {
			return strings.Contains(resp, "Shared/Team/Marker1")
		})
	})...)
	got = append(got, notifyNoop(t, watcher)...)

	var unexpected []string
	for _, resp := range got {
		m := notifyEventRe.FindStringSubmatch(resp)
		if m == nil || m[1] != "LIST" {
			continue
		}
		if m[2] == "Shared/Team/Marker1" || (m[2] == "Shared/Team" && !strings.Contains(resp, `\NonExistent`)) {
			continue
		}
		unexpected = append(unexpected, resp)
	}
	if len(unexpected) > 0 {
		t.Errorf("want no LIST for non-owner's own RENAME of subscribed shared mailbox, got:\n%s", strings.Join(unexpected, "\r\n"))
	}

	// A subsequent SUBSCRIBE on another connection of the same non-owner must still emit LIST (\Subscribed).
	memberOther := dialRawIMAP(t, server.Address)
	memberOther.do(memberLogin)
	memberOther.do("SUBSCRIBE Shared/Team/New")
	ownerConn.do("CREATE Shared/Team/Marker2")

	afterSub := readNotifyUntil(t, watcher, 10*time.Second, func(resps []string) bool {
		var sawSub, sawMarker bool
		for _, resp := range resps {
			if m := notifyEventRe.FindStringSubmatch(resp); m != nil && m[1] == "LIST" {
				sawSub = sawSub || (m[2] == "Shared/Team/New" && strings.Contains(resp, `\Subscribed`))
				sawMarker = sawMarker || m[2] == "Shared/Team/Marker2"
			}
		}
		return sawSub && sawMarker
	})
	if !slices.ContainsFunc(afterSub, func(resp string) bool {
		m := notifyEventRe.FindStringSubmatch(resp)
		return m != nil && m[1] == "LIST" && m[2] == "Shared/Team/New" && strings.Contains(resp, `\Subscribed`)
	}) {
		t.Errorf("want SubscriptionChange LIST (\\Subscribed) for foreign SUBSCRIBE after non-owner RENAME, got:\n%s", strings.Join(afterSub, "\r\n"))
	}
}
