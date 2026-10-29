//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
)

// filteredSession logs in over a raw connection as iOS Mail, whose capabilities
// disable removes (config.toml.example suggests ESEARCH for it), and selects
// INBOX, which holds two messages: the first \Seen, with subjects "filtered 0"
// and "filtered 1". It returns a function that runs one command, and the UIDs.
func filteredSession(t *testing.T, disable ...string) (do func(cmd string) string, uids []uint32) {
	t.Helper()
	server, account := setupIMAPServerWithCapabilityFilters(t, []config.ClientCapabilityFilter{{
		ClientName:    `com\.apple\.email\.maild`,
		ClientVersion: ".*",
		DisableCaps:   disable,
		Reason:        "iOS Apple Mail has ESEARCH parsing issues",
	}})
	t.Cleanup(server.Close)

	// This client sends no ID, so it is not filtered.
	setup, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	if err := setup.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	for i, flags := range [][]imap.Flag{{imap.FlagSeen}, nil} {
		msg := fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nSubject: filtered %d\r\n\r\nbody\r\n", account.Email, i)
		ac := setup.Append("INBOX", int64(len(msg)), &imap.AppendOptions{Flags: flags})
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		data, err := ac.Wait()
		if err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
		uids = append(uids, uint32(data.UID))
	}
	if err := setup.Create("Empty", nil).Wait(); err != nil {
		t.Fatalf("CREATE failed: %v", err)
	}
	setup.Logout()

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("raw dial failed: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil { // greeting
		t.Fatalf("read greeting failed: %v", err)
	}
	tagN := 0
	do = func(cmd string) string {
		t.Helper()
		tagN++
		tag := fmt.Sprintf("f%d", tagN)
		if _, err := fmt.Fprintf(conn, "%s %s\r\n", tag, cmd); err != nil {
			t.Fatalf("write %q failed: %v", cmd, err)
		}
		return h3ReadTagged(t, r, tag)
	}

	if resp := do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)); !strings.Contains(resp, " OK ") {
		t.Fatalf("LOGIN not OK:\n%s", resp)
	}
	do(`ID ("name" "com.apple.email.maild" "version" "3826.300.87.2.22" "os" "iOS")`)
	// Without this a test would pass against an unfiltered session.
	resp := do("CAPABILITY")
	for _, c := range disable {
		if strings.Contains(resp, " "+c+" ") || strings.Contains(resp, " "+c+"\r\n") {
			t.Fatalf("filter not applied, CAPABILITY still offers %s:\n%s", c, resp)
		}
	}
	if resp := do("SELECT INBOX"); !strings.Contains(resp, " OK ") {
		t.Fatalf("SELECT not OK:\n%s", resp)
	}
	return do, uids
}

// refusedAsClientBug checks that cmd is refused with BAD [CLIENTBUG]: the
// session lacks the extension whose syntax the client used (RFC 4466 §2.6.1).
func refusedAsClientBug(t *testing.T, do func(string) string, cmd string) {
	t.Helper()
	if resp := do(cmd); !strings.Contains(resp, " BAD [CLIENTBUG]") {
		t.Errorf("%s: want BAD [CLIENTBUG], got:\n%s", cmd, resp)
	}
}

// TestIMAP_ESearchFiltered_PlainSearchAnswered checks a client whose ESEARCH a
// client filter removed. Such a client was refused every SEARCH with NO
// [CLIENTBUG]: go-imap hands the session a SEARCH without RETURN as RETURN
// (ALL), and the session took that for the extended syntax.
//
// A plain SEARCH, and an empty RETURN (), must be answered with the SEARCH
// response of RFC 3501, the only form the session advertises. Any result option
// is refused, ALL included, also where the session would answer without
// searching (an empty mailbox). go-imap refuses them, since only it knows
// whether the client sent RETURN.
func TestIMAP_ESearchFiltered_PlainSearchAnswered(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	do, uids := filteredSession(t, "ESEARCH")
	// IMAP4rev2 includes ESEARCH, so the filter drops it too (applyCapabilityFilters).
	if resp := do("CAPABILITY"); strings.Contains(resp, " IMAP4rev2 ") {
		t.Fatalf("CAPABILITY still offers IMAP4rev2:\n%s", resp)
	}

	for _, tc := range []struct {
		cmd  string
		want []uint32
	}{
		{"SEARCH ALL", []uint32{1, 2}},
		{"SEARCH UNSEEN", []uint32{2}},
		{"UID SEARCH ALL", uids},
		{"UID SEARCH SEEN", uids[:1]},
		{"SEARCH CHARSET UTF-8 SUBJECT filtered", []uint32{1, 2}},
		{"SEARCH SUBJECT no-such-subject", nil},
		{"SEARCH RETURN () ALL", []uint32{1, 2}}, // RFC 4466: no option to refuse
	} {
		resp := do(tc.cmd)
		got, ok := searchResponseNums(resp)
		if !ok || !slices.Equal(got, tc.want) || strings.Contains(resp, "ESEARCH") {
			t.Errorf("%s: want * SEARCH %v and OK, got:\n%s", tc.cmd, tc.want, resp)
		}
	}

	for _, cmd := range []string{
		"SEARCH RETURN (ALL) ALL",
		"UID SEARCH RETURN (ALL) UID 1:*",
		"SEARCH RETURN (COUNT) ALL",
		"SEARCH RETURN (MIN MAX) ALL",
		"UID SEARCH RETURN (MAX) ALL",
		"SEARCH RETURN (SAVE) ALL",
	} {
		refusedAsClientBug(t, do, cmd)
	}

	// An empty mailbox answers a sequence-set search without querying; the
	// refusal must come first.
	if resp := do("SELECT Empty"); !strings.Contains(resp, " OK ") {
		t.Fatalf("SELECT Empty not OK:\n%s", resp)
	}
	refusedAsClientBug(t, do, "SEARCH RETURN (COUNT) 1:*")
	resp := do("SEARCH 1:*")
	if nums, ok := searchResponseNums(resp); !ok || len(nums) > 0 {
		t.Errorf("SEARCH 1:* in an empty mailbox: want a bare * SEARCH and OK, got:\n%s", resp)
	}
}

// TestIMAP_ESortFiltered_ExtendedSortRefused is the SORT side (sora #120): a
// client whose ESORT was filtered had SORT RETURN (COUNT) answered COUNT 0 and
// RETURN (MIN MAX) answered with neither. A plain SORT is answered; any RETURN
// is refused, since RFC 5256 defines no extension syntax for SORT.
func TestIMAP_ESortFiltered_ExtendedSortRefused(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	do, uids := filteredSession(t, "ESORT")

	if resp := do("SORT (SUBJECT) UTF-8 ALL"); !strings.Contains(resp, "* SORT 1 2\r\n") || strings.Contains(resp, "ESEARCH") {
		t.Errorf("plain SORT: want * SORT 1 2, got:\n%s", resp)
	}
	if want := fmt.Sprintf("* SORT %d %d\r\n", uids[1], uids[0]); !strings.Contains(do("UID SORT (REVERSE SUBJECT) UTF-8 ALL"), want) {
		t.Errorf("plain UID SORT: want %q", want)
	}
	for _, cmd := range []string{
		"SORT RETURN (COUNT) (SUBJECT) UTF-8 ALL",
		"SORT RETURN (MIN MAX) (SUBJECT) UTF-8 ALL",
		"SORT RETURN (ALL) (SUBJECT) UTF-8 ALL",
		"SORT RETURN () (SUBJECT) UTF-8 ALL",
		"UID SORT RETURN (COUNT) (SUBJECT) UTF-8 ALL",
	} {
		refusedAsClientBug(t, do, cmd)
	}
}

var (
	searchResponseLine = regexp.MustCompile(`(?m)^\* SEARCH((?: \d+)*)\r$`)
	taggedOKLine       = regexp.MustCompile(`^\S+ OK `)
)

// searchResponseNums returns the sorted numbers of the single untagged SEARCH
// response in resp, and whether resp holds exactly one and ends in a tagged OK.
func searchResponseNums(resp string) ([]uint32, bool) {
	lines := strings.Split(strings.TrimSuffix(resp, "\r\n"), "\r\n")
	if !taggedOKLine.MatchString(lines[len(lines)-1]) {
		return nil, false
	}
	m := searchResponseLine.FindAllStringSubmatch(resp, -1)
	if len(m) != 1 {
		return nil, false
	}
	var nums []uint32
	for _, f := range strings.Fields(m[0][1]) {
		n, err := strconv.ParseUint(f, 10, 32)
		if err != nil {
			return nil, false
		}
		nums = append(nums, uint32(n))
	}
	slices.Sort(nums)
	return nums, true
}
