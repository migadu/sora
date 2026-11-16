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
// gets no unsolicited FETCH (neither from MessageNew nor from Poll's FlagChange
// path); one that another connection adds after it gets its MessageNew FETCH
// once, even when FlagChange is also watched (RFC 5465 §5.2).
func TestNotifyMessageNewNoFetchForOwnMessages(t *testing.T) {
	for _, watch := range []struct {
		name string
		cmd  string
	}{
		{
			name: "MessageNew and MessageExpunge",
			cmd:  "NOTIFY SET (SELECTED (MessageNew (UID FLAGS) MessageExpunge))",
		},
		{
			name: "MessageNew and MessageExpunge with FlagChange",
			cmd:  "NOTIFY SET (SELECTED (MessageNew (UID FLAGS) MessageExpunge FlagChange))",
		},
	} {
		t.Run(watch.name, func(t *testing.T) {
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
					watcher.do(watch.cmd)

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
						t.Errorf("UID %d was created on this connection, want no unsolicited FETCH for it, got %d:\n%s", ownUID, n, strings.Join(got, "\r\n"))
					}
					if n := countUIDFetches(got, otherUID); n != 1 {
						t.Errorf("want one MessageNew FETCH for UID %d from another connection, got %d:\n%s", otherUID, n, strings.Join(got, "\r\n"))
					}
				})
			}
		})
	}
}

// TestNotifyMessageNewWithoutFetchAttsNoFetchOnArrival: when MessageNew has no
// fetch-atts and FlagChange is watched, arriving messages (both own and from
// another connection) announce EXISTS only — never an unsolicited FlagChange
// FETCH — while a subsequent STORE on an existing message still delivers its
// FlagChange FETCH.
func TestNotifyMessageNewWithoutFetchAttsNoFetchOnArrival(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	login := fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)

	watcher := dialRawIMAP(t, server.Address)
	watcher.do(login)
	watcher.do("SELECT INBOX")
	watcher.do("NOTIFY SET (SELECTED (MessageNew MessageExpunge FlagChange))")

	tag := watcher.nextTag()
	if _, err := fmt.Fprintf(watcher.conn, "%s APPEND INBOX {%d+}\r\n%s\r\n", tag, len(notifyTestMessage), notifyTestMessage); err != nil {
		t.Fatalf("APPEND write: %v", err)
	}
	ownUntagged, ownTagged := watcher.collect(tag, "APPEND INBOX")
	if m := appendUIDRe.FindStringSubmatch(ownTagged); m == nil {
		t.Fatalf("no APPENDUID in: %s", ownTagged)
	}
	got := splitUntaggedResponses(ownUntagged)

	other := dialRawIMAP(t, server.Address)
	other.do(login)
	otherUID := other.appendMsg("INBOX", notifyTestMessage)

	got = append(got, readNotifyUntil(t, watcher, 10*time.Second, func(resps []string) bool {
		return hasLinePrefix(resps, "* 2 EXISTS")
	})...)
	got = append(got, notifyNoop(t, watcher)...)

	for _, resp := range got {
		if strings.Contains(resp, " FETCH ") {
			t.Errorf("want no unsolicited FETCH on new message arrival without MessageNew fetch-atts, got:\n%s", strings.Join(got, "\r\n"))
			break
		}
	}

	other.do("SELECT INBOX")
	other.do(fmt.Sprintf(`UID STORE %d +FLAGS (\Seen)`, otherUID))

	flagResps := readNotifyUntil(t, watcher, 10*time.Second, func(resps []string) bool {
		return countUIDFetches(resps, otherUID) > 0
	})
	flagResps = append(flagResps, notifyNoop(t, watcher)...)
	if n := countUIDFetches(flagResps, otherUID); n != 1 {
		t.Errorf("want 1 FlagChange FETCH for UID %d after STORE, got %d:\n%s", otherUID, n, strings.Join(flagResps, "\r\n"))
	}
	if !strings.Contains(strings.Join(flagResps, "\n"), `\Seen`) {
		t.Errorf("FlagChange FETCH for UID %d missing \\Seen:\n%s", otherUID, strings.Join(flagResps, "\r\n"))
	}
}

// TestNotifyMessageNewDoesNotLatchFilteredFlagChangeGap: when FlagChange is not
// watched, a newly arriving message is a MessageNew event rather than a
// filtered FlagChange, so Poll must not latch reportedModSeqGap and hold back
// the HIGHESTMODSEQ reported by the first CONDSTORE-enabling command.
func TestNotifyMessageNewDoesNotLatchFilteredFlagChangeGap(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	login := fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)

	watcher := dialRawIMAP(t, server.Address)
	watcher.do(login)
	watcher.appendMsg("INBOX", notifyTestMessage)
	baseline := selectHighestModSeq(t, watcher, "INBOX")
	watcher.do("NOTIFY SET (SELECTED (MessageNew (UID FLAGS) MessageExpunge))")

	other := dialRawIMAP(t, server.Address)
	other.do(login)
	otherUID := other.appendMsg("INBOX", notifyTestMessage)
	statusLines, _ := other.do("STATUS INBOX (HIGHESTMODSEQ)")
	var afterAppendModSeq uint64
	if m := regexp.MustCompile(`HIGHESTMODSEQ (\d+)`).FindStringSubmatch(strings.Join(statusLines, " ")); m != nil {
		afterAppendModSeq = uint64(mustAtoi(t, m[1]))
	}
	if afterAppendModSeq <= baseline {
		t.Fatalf("expected APPEND to advance HIGHESTMODSEQ past %d, got %d (%q)", baseline, afterAppendModSeq, statusLines)
	}

	readNotifyUntil(t, watcher, 10*time.Second, func(resps []string) bool {
		return countUIDFetches(resps, otherUID) > 0
	})
	notifyNoop(t, watcher)

	first, _ := watcher.do("ENABLE CONDSTORE")
	codes := highestModSeqCodes(t, first)
	if len(codes) != 1 {
		t.Fatalf("ENABLE CONDSTORE: want one HIGHESTMODSEQ response, got %q", first)
	}
	if codes[0] != afterAppendModSeq {
		t.Errorf("ENABLE CONDSTORE HIGHESTMODSEQ = %d, want %d (SELECT baseline was %d; no FlagChange occurred): %q",
			codes[0], afterAppendModSeq, baseline, first)
	}
}

// countUIDFetches counts the FETCH responses that carry UID uid, whether UID
// is their first item or a later one.
func countUIDFetches(resps []string, uid imap.UID) int {
	re := regexp.MustCompile(fmt.Sprintf(`^\* \d+ FETCH \((?:.*[( ])?UID %d[ )]`, uid))
	n := 0
	for _, resp := range resps {
		if re.MatchString(resp) {
			n++
		}
	}
	return n
}

// TestCountUIDFetches: the helper finds UID in any position of a FETCH, so a
// MessageNew FETCH for fetch-atts that put UID first, "(UID 3)", is not missed
// and the assertions above cannot pass for want of a match.
func TestCountUIDFetches(t *testing.T) {
	for _, tc := range []struct {
		resp string
		want int
	}{
		{`* 2 FETCH (UID 3)`, 1},
		{`* 2 FETCH (UID 3 FLAGS (\Seen))`, 1},
		{`* 2 FETCH (FLAGS ($hasnoattachment) UID 3)`, 1},
		{`* 2 FETCH (FLAGS (\Seen) UID 3 MODSEQ (7))`, 1},
		{`* 2 FETCH (UID 30)`, 0},
		{`* 2 FETCH (UID 13)`, 0},
		{`* 3 FETCH (FLAGS (\Seen))`, 0},
		{`* 3 EXISTS`, 0},
	} {
		if got := countUIDFetches([]string{tc.resp}, 3); got != tc.want {
			t.Errorf("countUIDFetches(%q, 3) = %d, want %d", tc.resp, got, tc.want)
		}
	}
}
