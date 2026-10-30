//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SearchRes exercises the RFC 5182 / RFC 9051 §6.4.4.1 "$" saved search
// result variable (SEARCHRES).
//
// The go-imap typed client cannot emit "SEARCH RETURN (SAVE ...)" (its
// returnSearchOptions omits SAVE), and "$" is per-connection state, so the whole
// flow is driven over raw IMAP on a single connection per scenario.
//
// Semantics under test:
//   - SEARCH RETURN (SAVE ...) stores a per-session, per-selected-mailbox UID set.
//   - "$" is referenced by UID FETCH / STORE / COPY / MOVE / EXPUNGE and within a
//     subsequent SEARCH criteria.
//   - RFC 5182 §2.4 SAVE/MIN/MAX/ALL/COUNT combination rules.
//   - The saved set tracks EXPUNGE (UID-based) and resets on mailbox change.
func TestIMAP_SearchRes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// newConn returns a fresh authenticated raw connection.
	newConn := func(t *testing.T) *rawIMAP {
		t.Helper()
		c := dialRawIMAP(t, server.Address)
		c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
		return c
	}

	// setupMailbox creates a mailbox with 5 messages, marks seq 1,3,5 \Seen, and
	// selects it. Returns the 5 UIDs (index 0 == seq 1). The SEEN set is therefore
	// {uids[0], uids[2], uids[4]}.
	setupMailbox := func(t *testing.T, c *rawIMAP, mailbox string) []imap.UID {
		t.Helper()
		c.do("CREATE " + mailbox)
		var uids []imap.UID
		for i := 0; i < 5; i++ {
			msg := fmt.Sprintf("From: s%d@example.com\r\nTo: %s\r\nSubject: Msg %d\r\n\r\nBody %d\r\n",
				i, account.Email, i, i)
			uids = append(uids, c.appendMsg(mailbox, msg))
		}
		c.do("SELECT " + mailbox)
		c.do(`STORE 1,3,5 +FLAGS (\Seen)`)
		return uids
	}

	t.Run("SaveThenFetch", func(t *testing.T) {
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_SaveThenFetch")
		c.do(`SEARCH RETURN (SAVE) SEEN`)
		assertUIDs(t, "UID FETCH $", c.fetchDollarUIDs(), []imap.UID{uids[0], uids[2], uids[4]})
	})

	t.Run("SaveWithAll_ResponseAndDollarMatch", func(t *testing.T) {
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_SaveAll")
		want := []imap.UID{uids[0], uids[2], uids[4]}
		// UID SEARCH RETURN (SAVE ALL): the ESEARCH ALL set and "$" must agree.
		untagged, _ := c.do(`UID SEARCH RETURN (SAVE ALL) SEEN`)
		got := parseESearchAll(t, untagged)
		assertUIDs(t, "ESEARCH ALL", got, want)
		assertUIDs(t, "UID FETCH $", c.fetchDollarUIDs(), want)
	})

	t.Run("SaveMin", func(t *testing.T) {
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_SaveMin")
		// SAVE + MIN (no ALL) => save only the MIN matching message.
		c.do(`SEARCH RETURN (SAVE MIN) SEEN`)
		assertUIDs(t, "UID FETCH $", c.fetchDollarUIDs(), []imap.UID{uids[0]})
	})

	t.Run("SaveMax", func(t *testing.T) {
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_SaveMax")
		// SAVE + MAX (no ALL) => save only the MAX matching message.
		c.do(`SEARCH RETURN (SAVE MAX) SEEN`)
		assertUIDs(t, "UID FETCH $", c.fetchDollarUIDs(), []imap.UID{uids[4]})
	})

	t.Run("SaveMinMax", func(t *testing.T) {
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_SaveMinMax")
		// SAVE + MIN + MAX (no ALL) => save MIN and MAX only.
		c.do(`SEARCH RETURN (SAVE MIN MAX) SEEN`)
		assertUIDs(t, "UID FETCH $", c.fetchDollarUIDs(), []imap.UID{uids[0], uids[4]})
	})

	t.Run("SaveCount_SavesFullSet", func(t *testing.T) {
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_SaveCount")
		// SAVE + COUNT (no MIN/MAX/ALL) => COUNT does not restrict; save full set.
		c.do(`SEARCH RETURN (SAVE COUNT) SEEN`)
		assertUIDs(t, "UID FETCH $", c.fetchDollarUIDs(), []imap.UID{uids[0], uids[2], uids[4]})
	})

	t.Run("DollarBeforeSave_Empty", func(t *testing.T) {
		c := newConn(t)
		setupMailbox(t, c, "SR_NoSave")
		// No SEARCH ... SAVE issued yet: "$" must resolve to an empty set, not error.
		assertUIDs(t, "UID FETCH $ (no save)", c.fetchDollarUIDs(), nil)
	})

	t.Run("StoreOnDollar", func(t *testing.T) {
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_Store")
		saved := []imap.UID{uids[0], uids[2], uids[4]}
		c.do(`SEARCH RETURN (SAVE) SEEN`)
		// STORE +FLAGS (\Flagged) $ — should flag exactly the saved messages.
		c.do(`UID STORE $ +FLAGS (\Flagged)`)
		assertUIDs(t, "messages with \\Flagged", c.fetchFlaggedUIDs("1:*"), saved)
	})

	t.Run("CopyDollar", func(t *testing.T) {
		c := newConn(t)
		setupMailbox(t, c, "SR_CopySrc")
		c.do("CREATE SR_CopyDst")
		c.do(`SEARCH RETURN (SAVE) SEEN`)
		c.do("UID COPY $ SR_CopyDst")
		assertEqualInt(t, "SR_CopyDst MESSAGES", c.statusMessages("SR_CopyDst"), 3)
	})

	t.Run("MoveDollar", func(t *testing.T) {
		c := newConn(t)
		setupMailbox(t, c, "SR_MoveSrc")
		c.do("CREATE SR_MoveDst")
		c.do(`SEARCH RETURN (SAVE) SEEN`)
		c.do("UID MOVE $ SR_MoveDst")
		// 3 moved out of 5 -> source has 2, destination has 3.
		assertEqualInt(t, "SR_MoveSrc MESSAGES", c.statusMessages("SR_MoveSrc"), 2)
		assertEqualInt(t, "SR_MoveDst MESSAGES", c.statusMessages("SR_MoveDst"), 3)
	})

	t.Run("ExpungeMaintainsSavedSet", func(t *testing.T) {
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_Expunge")
		c.do(`SEARCH RETURN (SAVE) SEEN`)
		// Saved set is {uids[0], uids[2], uids[4]}. Expunge uids[2] and confirm the
		// saved set still resolves (UID-based) to the remaining two.
		c.do(fmt.Sprintf(`UID STORE %d +FLAGS (\Deleted)`, uids[2]))
		c.do(fmt.Sprintf("UID EXPUNGE %d", uids[2]))
		assertUIDs(t, "UID FETCH $ after expunge", c.fetchDollarUIDs(), []imap.UID{uids[0], uids[4]})
	})

	t.Run("MailboxChangeResetsSavedSet", func(t *testing.T) {
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_ResetA")
		c.do(`SEARCH RETURN (SAVE) SEEN`)
		assertUIDs(t, "UID FETCH $ in A", c.fetchDollarUIDs(), []imap.UID{uids[0], uids[2], uids[4]})

		// Switch mailboxes: the saved result is tied to the previously selected
		// mailbox and must be cleared.
		c.do("CREATE SR_ResetB")
		c.do("SELECT SR_ResetB")
		assertUIDs(t, "UID FETCH $ after reselect", c.fetchDollarUIDs(), nil)
	})

	t.Run("DollarInSearchCriteria", func(t *testing.T) {
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_Criteria")
		want := []imap.UID{uids[0], uids[2], uids[4]}
		c.do(`SEARCH RETURN (SAVE) SEEN`)
		// UID SEARCH $ — "$" used as a criterion should match the saved messages.
		untagged, _ := c.do("UID SEARCH $")
		assertUIDs(t, "UID SEARCH $", parseSearchUIDs(untagged), want)
	})

	t.Run("MultiSearchSelectedSave", func(t *testing.T) {
		// RFC 7377 §2.2: SAVE in an ESEARCH whose sole source is the selected
		// mailbox sets "$" as SEARCH RETURN (SAVE) does. go-imap refuses SAVE with
		// any other source.
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_MultiSave")
		c.do(fmt.Sprintf("UID SEARCH RETURN (SAVE) UID %d", uids[1])) // a stale "$" to replace

		untagged, _ := c.do("ESEARCH IN (SELECTED) RETURN (SAVE) SEEN")
		for _, l := range untagged {
			if strings.HasPrefix(l, "* ESEARCH") {
				t.Errorf("SAVE alone answered %q, want no result response (RFC 5182)", l)
			}
		}
		assertUIDs(t, "UID FETCH $ after ESEARCH SAVE", c.fetchDollarUIDs(), []imap.UID{uids[0], uids[2], uids[4]})

		c.do("ESEARCH IN (SELECTED) RETURN (SAVE MIN) SEEN")
		assertUIDs(t, "UID FETCH $ after ESEARCH SAVE MIN", c.fetchDollarUIDs(), []imap.UID{uids[0]})

		c.do("ESEARCH IN (SELECTED) RETURN (SAVE) SUBJECT no-such-subject")
		assertUIDs(t, "UID FETCH $ after an empty ESEARCH SAVE", c.fetchDollarUIDs(), nil)
	})

	// A selected-mailbox search as SEARCH and as ESEARCH; "$" follows both alike.
	searchCommands := []string{"UID SEARCH", "ESEARCH IN (SELECTED)"}

	t.Run("SaveCountWithMinMax_SavesFullSet", func(t *testing.T) {
		// RFC 5182 §2.4: with ALL and/or COUNT, "$" holds every match, MIN and MAX
		// notwithstanding.
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_SaveCountMinMax")
		want := []imap.UID{uids[0], uids[2], uids[4]}
		for _, cmd := range searchCommands {
			for _, opts := range []string{"SAVE MIN COUNT", "SAVE MAX COUNT", "SAVE MIN MAX COUNT"} {
				c.do(cmd + " RETURN (" + opts + ") SEEN")
				assertUIDs(t, "UID FETCH $ after "+cmd+" "+opts, c.fetchDollarUIDs(), want)
			}
		}
	})

	t.Run("FailedSaveEmptiesDollar", func(t *testing.T) {
		// RFC 5182 §2.1: a SAVE search that fails with NO sets "$" to the empty
		// sequence, whether sora refuses it (21 UID keys exceed the validator's
		// limit) or go-imap does before calling sora (an unsupported charset).
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_SaveNo")
		for _, failing := range []struct{ criteria, want string }{
			{strings.TrimSpace(strings.Repeat(fmt.Sprintf("UID %d ", uids[0]), 21)), "NO [SERVERLIMIT]"},
			{fmt.Sprintf("CHARSET ISO-8859-1 UID %d", uids[1]), "NO [BADCHARSET]"},
		} {
			for _, cmd := range searchCommands {
				c.do(`UID SEARCH RETURN (SAVE) SEEN`)
				if got := c.status(cmd + " RETURN (SAVE) " + failing.criteria); !strings.HasPrefix(got, failing.want) {
					t.Fatalf("%s RETURN (SAVE) %s: %s, want %s", cmd, failing.criteria, got, failing.want)
				}
				assertUIDs(t, "UID FETCH $ after "+failing.want+" to "+cmd, c.fetchDollarUIDs(), nil)
			}
		}
	})

	t.Run("RefusedSaveKeepsDollar", func(t *testing.T) {
		// RFC 5182 §2.1: a SAVE search refused with BAD leaves "$" as it was, whether
		// sora refuses it (an impossible size range) or go-imap does (an unknown key).
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_SaveBad")
		want := []imap.UID{uids[0], uids[2], uids[4]}
		c.do(`UID SEARCH RETURN (SAVE) SEEN`)
		for _, cmd := range searchCommands {
			for _, criteria := range []string{"LARGER 10 SMALLER 5", "NO-SUCH-KEY"} {
				if got := c.status(cmd + " RETURN (SAVE) " + criteria); !strings.HasPrefix(got, "BAD") {
					t.Fatalf("%s %s: %s, want BAD", cmd, criteria, got)
				}
				assertUIDs(t, "UID FETCH $ after a refused "+cmd+" "+criteria, c.fetchDollarUIDs(), want)
			}
		}
	})

	t.Run("RefusedLiteralInBadSaveKeepsDollar", func(t *testing.T) {
		// SAVE from a source other than the selected mailbox is BAD (RFC 7377
		// §2.2), and so keeps "$", even when go-imap refuses an oversized literal
		// in it before the command is fully read.
		c := newConn(t)
		uids := setupMailbox(t, c, "SR_SaveLiteralBad")
		want := []imap.UID{uids[0], uids[2], uids[4]}
		c.do(`UID SEARCH RETURN (SAVE) SEEN`)
		if got := c.status("ESEARCH IN (personal) RETURN (SAVE) TEXT {4097}"); !strings.HasPrefix(got, "BAD") {
			t.Fatalf("ESEARCH IN (personal) SAVE with an oversized literal: %s, want BAD", got)
		}
		assertUIDs(t, "UID FETCH $ after the refused literal", c.fetchDollarUIDs(), want)
	})
}

// TestIMAP_SearchRes_RateLimitedSaveEmptiesDollar: a SAVE search refused with
// NO [LIMIT] empties "$" (RFC 5182 §2.1), so a command pipelined behind it acts
// on no message rather than on the ones an earlier search saved.
func TestIMAP_SearchRes_RateLimitedSaveEmptiesDollar(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{
		SearchRateLimitPerMin: 1,
		SearchRateLimitWindow: time.Hour,
	})
	defer server.Close()

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	old := c.appendMsg("INBOX", "Subject: old result\r\n\r\nbody\r\n")
	wanted := c.appendMsg("INBOX", "Subject: intended result\r\n\r\nbody\r\n")
	c.do("SELECT INBOX")
	c.do("UID SEARCH BODY body") // spends the one search the limit allows

	for _, cmd := range []string{"UID SEARCH", "ESEARCH IN (SELECTED)"} {
		c.do(fmt.Sprintf("UID SEARCH RETURN (SAVE) UID %d", old)) // metadata only, so not charged
		search := c.send(fmt.Sprintf("%s RETURN (SAVE) UID %d BODY body", cmd, wanted))
		store := c.send(`UID STORE $ +FLAGS (\Flagged)`)
		if _, tagged := c.read(search, cmd); !strings.HasPrefix(tagged, search+" NO [LIMIT]") {
			t.Fatalf("%s: %s, want NO [LIMIT]", cmd, tagged)
		}
		c.collect(store, `UID STORE $`)
		assertUIDs(t, "flagged after a rate-limited "+cmd+" SAVE", c.fetchFlaggedUIDs("1:*"), nil)
	}
}

// --- raw IMAP helper -------------------------------------------------------

type rawIMAP struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	n    int
}

func dialRawIMAP(t *testing.T, addr string) *rawIMAP {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &rawIMAP{t: t, conn: conn, r: bufio.NewReader(conn)}
	if _, err := c.r.ReadString('\n'); err != nil { // greeting
		t.Fatalf("greeting: %v", err)
	}
	return c
}

func (c *rawIMAP) nextTag() string {
	c.n++
	return fmt.Sprintf("T%03d", c.n)
}

// read reads untagged lines until the tagged completion line, whatever its status.
func (c *rawIMAP) read(tag, ctx string) (untagged []string, tagged string) {
	c.t.Helper()
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("read (%s): %v", ctx, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, tag+" ") {
			return untagged, line
		}
		untagged = append(untagged, line)
	}
}

// collect reads untagged lines until the tagged completion line, asserting OK.
func (c *rawIMAP) collect(tag, ctx string) (untagged []string, tagged string) {
	c.t.Helper()
	untagged, tagged = c.read(tag, ctx)
	if !strings.HasPrefix(tagged, tag+" OK") {
		c.t.Fatalf("command %q failed: %s", ctx, tagged)
	}
	return untagged, tagged
}

// send writes a one-line command without waiting for its response.
func (c *rawIMAP) send(cmd string) (tag string) {
	c.t.Helper()
	tag = c.nextTag()
	if _, err := fmt.Fprintf(c.conn, "%s %s\r\n", tag, cmd); err != nil {
		c.t.Fatalf("write %q: %v", cmd, err)
	}
	return tag
}

// do sends a one-line command and returns its untagged + tagged responses.
func (c *rawIMAP) do(cmd string) (untagged []string, tagged string) {
	c.t.Helper()
	return c.collect(c.send(cmd), cmd)
}

// status sends a one-line command and returns its tagged status, without the tag.
func (c *rawIMAP) status(cmd string) string {
	c.t.Helper()
	tag := c.send(cmd)
	_, tagged := c.read(tag, cmd)
	return strings.TrimPrefix(tagged, tag+" ")
}

// appendMsg appends msg using a LITERAL+ literal and returns the assigned UID.
func (c *rawIMAP) appendMsg(mailbox, msg string) imap.UID {
	c.t.Helper()
	tag := c.nextTag()
	if _, err := fmt.Fprintf(c.conn, "%s APPEND %s {%d+}\r\n%s\r\n", tag, mailbox, len(msg), msg); err != nil {
		c.t.Fatalf("append write: %v", err)
	}
	_, tagged := c.collect(tag, "APPEND "+mailbox)
	m := appendUIDRe.FindStringSubmatch(tagged)
	if m == nil {
		c.t.Fatalf("no APPENDUID in: %s", tagged)
	}
	return imap.UID(mustAtoi(c.t, m[1]))
}

// fetchDollarUIDs runs "UID FETCH $ (UID)" and returns the resolved UIDs (sorted).
func (c *rawIMAP) fetchDollarUIDs() []imap.UID {
	untagged, _ := c.do("UID FETCH $ (UID)")
	var out []imap.UID
	for _, l := range untagged {
		if !strings.Contains(l, " FETCH ") {
			continue
		}
		if m := uidRe.FindStringSubmatch(l); m != nil {
			out = append(out, imap.UID(mustAtoi(c.t, m[1])))
		}
	}
	sortUIDs(out)
	return out
}

// fetchFlaggedUIDs returns the UIDs in the given set that carry the \Flagged flag.
func (c *rawIMAP) fetchFlaggedUIDs(set string) []imap.UID {
	untagged, _ := c.do("UID FETCH " + set + " (UID FLAGS)")
	var out []imap.UID
	for _, l := range untagged {
		if !strings.Contains(l, `\Flagged`) {
			continue
		}
		if m := uidRe.FindStringSubmatch(l); m != nil {
			out = append(out, imap.UID(mustAtoi(c.t, m[1])))
		}
	}
	sortUIDs(out)
	return out
}

// statusMessages returns MESSAGES from STATUS for the given mailbox.
func (c *rawIMAP) statusMessages(mailbox string) int {
	untagged, _ := c.do(fmt.Sprintf("STATUS %s (MESSAGES)", mailbox))
	for _, l := range untagged {
		if m := messagesRe.FindStringSubmatch(l); m != nil {
			return mustAtoi(c.t, m[1])
		}
	}
	c.t.Fatalf("no MESSAGES in STATUS %s response: %v", mailbox, untagged)
	return -1
}

// --- parsing helpers -------------------------------------------------------

var (
	uidRe       = regexp.MustCompile(`UID (\d+)`)
	appendUIDRe = regexp.MustCompile(`APPENDUID \d+ (\d+)`)
	messagesRe  = regexp.MustCompile(`MESSAGES (\d+)`)
	esearchRe   = regexp.MustCompile(`(?i)ALL ([\d:,]+)`)
)

// parseESearchAll extracts the ALL set from an "* ESEARCH ... ALL <set>" line.
func parseESearchAll(t *testing.T, untagged []string) []imap.UID {
	t.Helper()
	for _, l := range untagged {
		if !strings.HasPrefix(l, "* ESEARCH") {
			continue
		}
		if m := esearchRe.FindStringSubmatch(l); m != nil {
			return parseIMAPSet(t, m[1])
		}
	}
	t.Fatalf("no ESEARCH ALL in: %v", untagged)
	return nil
}

// parseSearchUIDs extracts numbers from a standard "* SEARCH n n n" response.
func parseSearchUIDs(untagged []string) []imap.UID {
	var out []imap.UID
	for _, l := range untagged {
		if !strings.HasPrefix(l, "* SEARCH") {
			continue
		}
		for _, f := range strings.Fields(strings.TrimPrefix(l, "* SEARCH")) {
			if n, err := strconv.Atoi(f); err == nil {
				out = append(out, imap.UID(n))
			}
		}
	}
	sortUIDs(out)
	return out
}

// parseIMAPSet parses an IMAP sequence-set string ("1,3,5" or "1:3" or mixes).
func parseIMAPSet(t *testing.T, s string) []imap.UID {
	t.Helper()
	var out []imap.UID
	for _, part := range strings.Split(s, ",") {
		if part == "" {
			continue
		}
		if i := strings.IndexByte(part, ':'); i >= 0 {
			a := mustAtoi(t, part[:i])
			b := mustAtoi(t, part[i+1:])
			if a > b {
				a, b = b, a
			}
			for v := a; v <= b; v++ {
				out = append(out, imap.UID(v))
			}
		} else {
			out = append(out, imap.UID(mustAtoi(t, part)))
		}
	}
	sortUIDs(out)
	return out
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		t.Fatalf("atoi %q: %v", s, err)
	}
	return n
}

// --- assertion helpers -----------------------------------------------------

func assertUIDs(t *testing.T, what string, got, want []imap.UID) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %v (%d), want %v (%d)", what, got, len(got), want, len(want))
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s: got %v, want %v", what, got, want)
			return
		}
	}
}

func assertEqualInt(t *testing.T, what string, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %d, want %d", what, got, want)
	}
}

func sortUIDs(uids []imap.UID) {
	sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
}
