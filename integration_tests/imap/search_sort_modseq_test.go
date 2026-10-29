//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// No message has a mod-sequence this high, so "MODSEQ msNever" matches nothing
// and "NOT MODSEQ msNever" matches everything.
const msNever = "9223372036854775807"

// msMailbox is a selected mailbox holding the three messages of
// msAppendFixture, read over a raw connection.
type msMailbox struct {
	conn net.Conn
	r    *bufio.Reader
	tagN int
	// modSeq of messages 1, 2, 3; message 2 has the highest, message 3 the next.
	m1, m2, m3 uint64
}

// msAppendFixture creates mailbox name with three messages whose UIDs and SUBJECT
// sort order are 1, 2, 3, then flags message 2 so that it has the highest
// mod-sequence: the shape of sora #117's fixture (mod-sequences 2, 5, 4).
func msAppendFixture(t *testing.T, addr string, account common.TestAccount, name string) (m1, m2, m3 uint64) {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if err := c.Create(name, nil).Wait(); err != nil {
		t.Fatalf("CREATE failed: %v", err)
	}
	for _, subject := range []string{"a", "b", "c"} {
		msg := fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nSubject: %s\r\n\r\nbody\r\n", account.Email, subject)
		ac := c.Append(name, int64(len(msg)), nil)
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := ac.Wait(); err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
	}
	if _, err := c.Select(name, nil).Wait(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}
	if err := c.Store(imap.SeqSetNum(2), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagFlagged}}, nil).Close(); err != nil {
		t.Fatalf("STORE failed: %v", err)
	}
	msgs, err := c.Fetch(imap.SeqSetNum(1, 2, 3), &imap.FetchOptions{ModSeq: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH MODSEQ failed: %v", err)
	}
	modSeq := map[uint32]uint64{}
	for _, msg := range msgs {
		modSeq[msg.SeqNum] = msg.ModSeq
	}
	m1, m2, m3 = modSeq[1], modSeq[2], modSeq[3]
	if !(m2 > m3 && m3 > m1 && m1 > 0) {
		t.Fatalf("mod-sequences %d, %d, %d: want message 2 highest, then 3, then 1", m1, m2, m3)
	}
	return m1, m2, m3
}

func msSelect(t *testing.T, addr string, account common.TestAccount, name string, preSelect ...string) *msMailbox {
	t.Helper()
	m1, m2, m3 := msAppendFixture(t, addr, account, name)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("raw dial failed: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	mb := &msMailbox{conn: conn, r: bufio.NewReader(conn), m1: m1, m2: m2, m3: m3}
	if _, err := mb.r.ReadString('\n'); err != nil {
		t.Fatalf("read greeting failed: %v", err)
	}
	for _, cmd := range append([]string{fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)}, preSelect...) {
		if resp := mb.do(t, cmd); !msTaggedOK.MatchString(resp) {
			t.Fatalf("%s not OK:\n%s", cmd, resp)
		}
	}
	if resp := mb.do(t, fmt.Sprintf(`SELECT "%s" (CONDSTORE)`, name)); !msTaggedOK.MatchString(resp) {
		t.Fatalf("SELECT not OK:\n%s", resp)
	}
	return mb
}

func (mb *msMailbox) do(t *testing.T, cmd string) string {
	t.Helper()
	mb.tagN++
	tag := fmt.Sprintf("m%d", mb.tagN)
	if _, err := fmt.Fprintf(mb.conn, "%s %s\r\n", tag, cmd); err != nil {
		t.Fatalf("write %q failed: %v", cmd, err)
	}
	return h3ReadTagged(t, mb.r, tag)
}

var (
	msTaggedOK  = regexp.MustCompile(`(?m)^m\d+ OK `)
	msUntagged  = regexp.MustCompile(`(?m)^\* (SEARCH|SORT|ESEARCH)(.*)\r$`)
	msPlainData = regexp.MustCompile(`^((?: \d+)*)(?: \(MODSEQ (\d+)\))?$`)
	msESearchMS = regexp.MustCompile(` MODSEQ (\d+)$`)
)

// result runs cmd and returns its untagged response's name, numbers (plain
// SEARCH and SORT only) and mod-sequence (0 if none). It fails unless there is
// exactly one such response and the command completed OK.
func (mb *msMailbox) result(t *testing.T, cmd string) (name, nums string, modSeq uint64) {
	t.Helper()
	resp := mb.do(t, cmd)
	untagged := msUntagged.FindAllStringSubmatch(resp, -1)
	if !msTaggedOK.MatchString(resp) || len(untagged) != 1 {
		t.Fatalf("%s: want one SEARCH, SORT or ESEARCH response and OK, got:\n%s", cmd, resp)
	}
	name, rest := untagged[0][1], untagged[0][2]
	var m []string
	if name == "ESEARCH" {
		m = msESearchMS.FindStringSubmatch(rest)
		if m != nil {
			m = []string{m[0], "", m[1]}
		}
	} else if m = msPlainData.FindStringSubmatch(rest); m == nil {
		t.Fatalf("%s: malformed %s response:\n%s", cmd, name, resp)
	}
	if m != nil && m[2] != "" {
		v, err := strconv.ParseUint(m[2], 10, 64)
		if err != nil {
			t.Fatalf("%s: bad MODSEQ in:\n%s", cmd, resp)
		}
		modSeq = v
	}
	if m != nil {
		nums = strings.TrimSpace(m[1])
	}
	return name, nums, modSeq
}

// expect runs cmd and checks the response form and its mod-sequence (0: none).
func (mb *msMailbox) expect(t *testing.T, cmd, wantName string, wantModSeq uint64) {
	t.Helper()
	name, _, modSeq := mb.result(t, cmd)
	if name != wantName || modSeq != wantModSeq {
		t.Errorf("%s: got %s with MODSEQ %d, want %s with MODSEQ %d (message mod-sequences %d, %d, %d)",
			cmd, name, modSeq, wantName, wantModSeq, mb.m1, mb.m2, mb.m3)
	}
}

// TestIMAP_SearchSortModSeqOfReturnedMessages checks the mod-sequence that SEARCH
// and SORT with a MODSEQ criterion report (sora #117): the highest of the
// messages returned (RFC 7162 §3.1.5, §3.1.9), narrowed for MIN and MAX without
// ALL or COUNT to the MIN and MAX messages (RFC 4731 §3.2; RFC 7162 §3.1.10 for
// SORT, where they are the first and last in sort order, RFC 5267 §3.1).
func TestIMAP_SearchSortModSeqOfReturnedMessages(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	mb := msSelect(t, server.Address, account, "MODSEQ-117")
	m1, m2, m3 := mb.m1, mb.m2, mb.m3

	// Guard the fixture: SUBJECT puts the messages in UID order 1, 2, 3.
	if _, nums, _ := mb.result(t, "SORT (SUBJECT) UTF-8 ALL"); nums != "1 2 3" {
		t.Fatalf("SORT (SUBJECT) gave %q, want 1 2 3", nums)
	}
	if _, nums, _ := mb.result(t, "SORT (REVERSE SUBJECT) UTF-8 ALL"); nums != "3 2 1" {
		t.Fatalf("SORT (REVERSE SUBJECT) gave %q, want 3 2 1", nums)
	}

	for _, tc := range []struct {
		ret                      string // RETURN options, "" for the plain command
		search, sortAsc, sortDsc uint64
	}{
		{"", m2, m2, m2},
		{"ALL", m2, m2, m2},
		{"MIN", m1, m1, m3},
		{"MAX", m3, m3, m1},
		{"MIN MAX", m3, m3, m3},
		{"COUNT", m2, m2, m2},
		{"MIN COUNT", m2, m2, m2},
		{"MAX COUNT", m2, m2, m2},
		{"MIN ALL", m2, m2, m2},
		{"MAX ALL", m2, m2, m2},
	} {
		ret, plainName, sortName := "", "SEARCH", "SORT"
		if tc.ret != "" {
			ret, plainName, sortName = " RETURN ("+tc.ret+")", "ESEARCH", "ESEARCH"
		}
		for _, uid := range []string{"", "UID "} {
			mb.expect(t, uid+"SEARCH"+ret+" MODSEQ 1", plainName, tc.search)
			mb.expect(t, uid+"SORT"+ret+" (SUBJECT) UTF-8 MODSEQ 1", sortName, tc.sortAsc)
			mb.expect(t, uid+"SORT"+ret+" (REVERSE SUBJECT) UTF-8 MODSEQ 1", sortName, tc.sortDsc)
		}
	}

	t.Run("subset leaves out the highest", func(t *testing.T) {
		// Messages 1 and 3: the mailbox's highest (message 2) is not returned.
		for _, uid := range []string{"", "UID "} {
			for _, ret := range []string{"", " RETURN (ALL)", " RETURN (COUNT)"} {
				name := "ESEARCH"
				if ret == "" {
					name = "SEARCH"
				}
				mb.expect(t, uid+"SEARCH"+ret+" MODSEQ 1 UNFLAGGED", name, m3)
				if ret == "" {
					name = "SORT"
				}
				mb.expect(t, uid+"SORT"+ret+" (SUBJECT) UTF-8 MODSEQ 1 UNFLAGGED", name, m3)
			}
		}
	})

	t.Run("MODSEQ under NOT and OR", func(t *testing.T) {
		for _, key := range []string{
			"NOT MODSEQ " + msNever,
			"OR SEEN NOT MODSEQ " + msNever,
			"OR SEEN (OR DRAFT (NOT MODSEQ " + msNever + "))",
		} {
			for _, uid := range []string{"", "UID "} {
				mb.expect(t, uid+"SEARCH "+key, "SEARCH", m2)
				mb.expect(t, uid+"SEARCH RETURN (MIN) "+key, "ESEARCH", m1)
				mb.expect(t, uid+"SORT (SUBJECT) UTF-8 "+key, "SORT", m2)
				mb.expect(t, uid+"SORT RETURN (MAX) (REVERSE SUBJECT) UTF-8 "+key, "ESEARCH", m1)
			}
		}
	})

	t.Run("no MODSEQ for an empty result", func(t *testing.T) {
		for _, uid := range []string{"", "UID "} {
			mb.expect(t, uid+"SEARCH MODSEQ "+msNever, "SEARCH", 0)
			mb.expect(t, uid+"SEARCH RETURN (ALL) MODSEQ "+msNever, "ESEARCH", 0)
			mb.expect(t, uid+"SEARCH RETURN (MIN MAX) MODSEQ "+msNever, "ESEARCH", 0)
			mb.expect(t, uid+"SORT (SUBJECT) UTF-8 MODSEQ "+msNever, "SORT", 0)
			mb.expect(t, uid+"SORT RETURN (ALL) (SUBJECT) UTF-8 MODSEQ "+msNever, "ESEARCH", 0)
		}
	})

	t.Run("no MODSEQ without a MODSEQ criterion", func(t *testing.T) {
		// CONDSTORE is enabled by SELECT (CONDSTORE); that alone does not add it.
		for _, uid := range []string{"", "UID "} {
			mb.expect(t, uid+"SEARCH ALL", "SEARCH", 0)
			mb.expect(t, uid+"SEARCH RETURN (MIN MAX COUNT) ALL", "ESEARCH", 0)
			mb.expect(t, uid+"SORT (SUBJECT) UTF-8 ALL", "SORT", 0)
			mb.expect(t, uid+"SORT RETURN (ALL) (SUBJECT) UTF-8 ALL", "ESEARCH", 0)
		}
	})
}

// TestIMAP_ESearchModSeqOfReturnedMessages is the RFC 7377 MULTISEARCH form: its
// ESEARCH response per mailbox carries the same mod-sequence as UID SEARCH.
func TestIMAP_ESearchModSeqOfReturnedMessages(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	mb := msSelect(t, server.Address, account, "MODSEQ-117-MULTI")
	m1, m2, m3 := mb.m1, mb.m2, mb.m3
	in := `ESEARCH IN (MAILBOXES "MODSEQ-117-MULTI")`

	for _, tc := range []struct {
		ret  string
		want uint64
	}{
		{"", m2},
		{" RETURN (MIN)", m1},
		{" RETURN (MAX)", m3},
		{" RETURN (MIN MAX)", m3},
		{" RETURN (MIN COUNT)", m2},
	} {
		mb.expect(t, in+tc.ret+" MODSEQ 1", "ESEARCH", tc.want)
	}
	mb.expect(t, in+" MODSEQ 1 UNFLAGGED", "ESEARCH", m3)
	mb.expect(t, in+" NOT MODSEQ "+msNever, "ESEARCH", m2)
	mb.expect(t, in+" ALL", "ESEARCH", 0)
}

// TestIMAP_SortRev2PlainSortKeepsSortResponse: IMAP4rev2 replaces SEARCH's answer
// with ESEARCH (RFC 9051 §6.4.4) but not SORT's. A plain SORT on a rev2 session
// still gets the SORT response of RFC 5256 §4; only RETURN options select ESEARCH
// (RFC 5267 §3.1). go-imap #74.
func TestIMAP_SortRev2PlainSortKeepsSortResponse(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	mb := msSelect(t, server.Address, account, "SORT-REV2", "ENABLE IMAP4rev2")

	if name, nums, _ := mb.result(t, "SORT (SUBJECT) UTF-8 ALL"); name != "SORT" || nums != "1 2 3" {
		t.Errorf("plain SORT on a rev2 session: got %s %q, want SORT \"1 2 3\"", name, nums)
	}
	mb.expect(t, "SORT (SUBJECT) UTF-8 MODSEQ 1", "SORT", mb.m2)
	mb.expect(t, "SORT RETURN (ALL) (SUBJECT) UTF-8 ALL", "ESEARCH", 0)
	// SEARCH, by contrast, is answered with ESEARCH under rev2.
	mb.expect(t, "SEARCH ALL", "ESEARCH", 0)
}
