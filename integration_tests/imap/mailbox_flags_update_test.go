//go:build integration

package imap_test

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

var mailboxFlagsRe = regexp.MustCompile(`^\* FLAGS \(([^)]*)\)$`)

// mailboxFlagsLines returns the index and flags of every untagged "* FLAGS (...)"
// response in untagged.
func mailboxFlagsLines(untagged []string) (idx []int, lists [][]string) {
	for i, l := range untagged {
		if m := mailboxFlagsRe.FindStringSubmatch(l); m != nil {
			idx = append(idx, i)
			lists = append(lists, strings.Fields(m[1]))
		}
	}
	return idx, lists
}

// firstLineIndex returns the index of the first line in untagged that has
// prefix and contains substr, or -1.
func firstLineIndex(untagged []string, prefix, substr string) int {
	for i, l := range untagged {
		if strings.HasPrefix(l, prefix) && strings.Contains(l, substr) {
			return i
		}
	}
	return -1
}

// TestIMAP_NewKeywordAnnouncedInFlags covers #2042: once a keyword the mailbox
// has not used appears, a selected session is sent an updated untagged FLAGS
// response listing it before the tagged reply of the command that made it
// appear (RFC 3501 §5.2: a server may send unsolicited data at any time; §7.2.6:
// the client records the FLAGS update). The update keeps every flag announced
// before: a FLAGS response replaces the client's list, so dropping a keyword
// still on a message would tell the client it no longer exists.
func TestIMAP_NewKeywordAnnouncedInFlags(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	login := func(t *testing.T) *rawIMAP {
		t.Helper()
		c := dialRawIMAP(t, server.Address)
		c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
		return c
	}
	msg := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: kw\r\n\r\nbody\r\n"

	selectFlags := func(t *testing.T, c *rawIMAP, mailbox string) []string {
		t.Helper()
		untagged, _ := c.do("SELECT " + mailbox)
		_, lists := mailboxFlagsLines(untagged)
		if len(lists) != 1 {
			t.Fatalf("SELECT %s: want one FLAGS response, got %q", mailbox, untagged)
		}
		return lists[0]
	}

	// wantAnnounced checks that untagged carries exactly one FLAGS update, that
	// it lists keyword and every flag in before, and returns its index.
	wantAnnounced := func(t *testing.T, cmd string, untagged, before []string, keyword string) int {
		t.Helper()
		idx, lists := mailboxFlagsLines(untagged)
		if len(lists) != 1 {
			t.Fatalf("%s: want one untagged FLAGS announcing %s before the tagged reply, got %q", cmd, keyword, untagged)
		}
		if !slices.Contains(lists[0], keyword) {
			t.Errorf("%s: FLAGS update %q lacks %s", cmd, lists[0], keyword)
		}
		for _, f := range before {
			if !slices.Contains(lists[0], f) {
				t.Errorf("%s: FLAGS update %q dropped %s announced before", cmd, lists[0], f)
			}
		}
		return idx[0]
	}

	t.Run("STORE", func(t *testing.T) {
		c := login(t)
		c.do("CREATE KwStore")
		c.appendMsg("KwStore", msg)
		before := selectFlags(t, c, "KwStore")

		untagged, _ := c.do("STORE 1 +FLAGS ($NewKw2042)")
		wantAnnounced(t, "STORE +FLAGS ($NewKw2042)", untagged, before, "$NewKw2042")

		// A keyword already announced is not announced again.
		c.do("STORE 1 -FLAGS ($NewKw2042)")
		untagged, _ = c.do("STORE 1 +FLAGS ($NewKw2042)")
		if _, lists := mailboxFlagsLines(untagged); len(lists) != 0 {
			t.Errorf("re-adding an announced keyword sent FLAGS again: %q", untagged)
		}
	})

	t.Run("APPEND into selected mailbox", func(t *testing.T) {
		c := login(t)
		c.do("CREATE KwAppend")
		c.appendMsg("KwAppend", msg)
		before := selectFlags(t, c, "KwAppend")

		tag := c.nextTag()
		if _, err := fmt.Fprintf(c.conn, "%s APPEND KwAppend ($AppendKw2042) {%d+}\r\n%s\r\n", tag, len(msg), msg); err != nil {
			t.Fatalf("append write: %v", err)
		}
		untagged, _ := c.collect(tag, "APPEND ($AppendKw2042)")
		i := wantAnnounced(t, "APPEND ($AppendKw2042)", untagged, before, "$AppendKw2042")
		if exists := firstLineIndex(untagged, "* 2 EXISTS", ""); exists >= 0 && exists < i {
			t.Errorf("APPEND: EXISTS for the new message came before the FLAGS announcing its keyword: %q", untagged)
		}
	})

	t.Run("other session on its next poll", func(t *testing.T) {
		writer := login(t)
		writer.do("CREATE KwOther")
		writer.appendMsg("KwOther", msg)
		writer.do("SELECT KwOther")

		viewer := login(t)
		before := selectFlags(t, viewer, "KwOther")

		writer.do("STORE 1 +FLAGS ($OtherKw2042)")

		untagged, _ := viewer.do("NOOP")
		i := wantAnnounced(t, "NOOP after another session's STORE", untagged, before, "$OtherKw2042")
		if fetch := firstLineIndex(untagged, "* 1 FETCH ", "$OtherKw2042"); fetch < 0 {
			t.Errorf("NOOP: no FETCH reporting $OtherKw2042: %q", untagged)
		} else if fetch < i {
			t.Errorf("NOOP: FETCH using $OtherKw2042 came before the FLAGS announcing it: %q", untagged)
		}
	})
}

// TestIMAP_FetchAnnouncesNewKeywordFirst covers #2091: a FETCH that reads a
// keyword another session added after this session's last poll must announce
// it in an untagged FLAGS response before the FETCH response that shows it
// (RFC 3501 §7.2.6; imaptest: "Keyword used without being in FLAGS").
func TestIMAP_FetchAnnouncesNewKeywordFirst(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	login := func(t *testing.T) *rawIMAP {
		t.Helper()
		c := dialRawIMAP(t, server.Address)
		c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
		return c
	}
	msg := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: kw\r\n\r\nbody\r\n"

	writer := login(t)
	writer.do("CREATE KwFetch")
	writer.appendMsg("KwFetch", msg)
	writer.do("SELECT KwFetch")

	reader := login(t)
	reader.do("SELECT KwFetch")

	writer.do("STORE 1 +FLAGS ($FetchKw2091)")

	// No NOOP: the reader's FETCH is the first command to see the keyword.
	untagged, _ := reader.do("FETCH 1 FLAGS")
	fetch := firstLineIndex(untagged, "* 1 FETCH ", "$FetchKw2091")
	if fetch < 0 {
		t.Fatalf("FETCH 1 FLAGS does not show $FetchKw2091: %q", untagged)
	}
	idx, lists := mailboxFlagsLines(untagged)
	if len(lists) != 1 || !slices.Contains(lists[0], "$FetchKw2091") {
		t.Fatalf("want one untagged FLAGS announcing $FetchKw2091, got %q", untagged)
	}
	if idx[0] > fetch {
		t.Errorf("FETCH showed $FetchKw2091 before the FLAGS announcing it: %q", untagged)
	}

	// Announced once: the following poll does not repeat it.
	untagged, _ = reader.do("NOOP")
	if _, lists := mailboxFlagsLines(untagged); len(lists) != 0 {
		t.Errorf("NOOP announced the keyword again: %q", untagged)
	}
}
