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

// TestIMAP_ESearchFiltered_PlainSearchAnswered checks a client whose ESEARCH
// capability a client filter removed (config.toml.example suggests it for iOS
// Mail). Such a client was refused every SEARCH with NO [CLIENTBUG], because
// go-imap hands the session a SEARCH without RETURN as RETURN (ALL) and the
// session took that for the extended syntax.
//
// A plain SEARCH must be answered with the SEARCH response of RFC 3501, the only
// form the session advertises. A RETURN option that a SEARCH response cannot
// carry (MIN, MAX, COUNT) is still refused.
func TestIMAP_ESearchFiltered_PlainSearchAnswered(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupIMAPServerWithCapabilityFilters(t, []config.ClientCapabilityFilter{{
		ClientName:    `com\.apple\.email\.maild`,
		ClientVersion: ".*",
		DisableCaps:   []string{"ESEARCH"},
		Reason:        "iOS Apple Mail has ESEARCH parsing issues",
	}})
	defer server.Close()

	// Two messages, the first \Seen. This client sends no ID, so it is not filtered.
	setup, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	if err := setup.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	var uids []uint32
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
	setup.Logout()

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("raw dial failed: %v", err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil { // greeting
		t.Fatalf("read greeting failed: %v", err)
	}
	tagN := 0
	do := func(cmd string) string {
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
	// Without this the test would pass against an unfiltered session.
	if resp := do("CAPABILITY"); strings.Contains(resp, " ESEARCH") || strings.Contains(resp, " IMAP4rev2") {
		t.Fatalf("filter not applied, CAPABILITY still offers ESEARCH:\n%s", resp)
	}
	if resp := do("SELECT INBOX"); !strings.Contains(resp, " OK ") {
		t.Fatalf("SELECT not OK:\n%s", resp)
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
	} {
		resp := do(tc.cmd)
		got, ok := searchResponseNums(resp)
		if !ok || !slices.Equal(got, tc.want) || strings.Contains(resp, "ESEARCH") {
			t.Errorf("%s: want * SEARCH %v and OK, got:\n%s", tc.cmd, tc.want, resp)
		}
	}

	for _, cmd := range []string{
		"SEARCH RETURN (COUNT) ALL",
		"SEARCH RETURN (MIN MAX) ALL",
	} {
		if resp := do(cmd); !strings.Contains(resp, " NO [CLIENTBUG]") {
			t.Errorf("%s: want NO [CLIENTBUG], got:\n%s", cmd, resp)
		}
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
