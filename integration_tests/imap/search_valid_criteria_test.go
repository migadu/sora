//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SearchValidCriteriaAreAnswered: well-formed searches that match no
// message, or every message, are answered with OK. RFC 3501 §7.1.3 reserves BAD
// for "a protocol-level error in the client's command", and an empty string is a
// substring of every field (RFC 3501 §6.4.4). A date span over a year was refused
// with NO [SERVERLIMIT], a code that does not exist (#283).
func TestIMAP_SearchValidCriteriaAreAnswered(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	setup, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := setup.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	var all []uint32
	for i, date := range []time.Time{
		time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
		time.Date(2025, 2, 1, 12, 0, 0, 0, time.UTC),
	} {
		msg := fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nSubject: valid criteria %d\r\nDate: %s\r\n\r\nbody text %d\r\n",
			account.Email, i, date.Format(time.RFC1123Z), i)
		ac := setup.Append("INBOX", int64(len(msg)), &imap.AppendOptions{Time: date})
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND close: %v", err)
		}
		data, err := ac.Wait()
		if err != nil {
			t.Fatalf("APPEND: %v", err)
		}
		all = append(all, uint32(data.UID))
	}
	setup.Logout()

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	n := 0
	do := func(cmd string) string {
		t.Helper()
		n++
		tag := fmt.Sprintf("v%d", n)
		fmt.Fprintf(conn, "%s %s\r\n", tag, cmd)
		return h3ReadTagged(t, r, tag)
	}
	if resp := do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)); !strings.Contains(resp, " OK ") {
		t.Fatalf("LOGIN:\n%s", resp)
	}
	if resp := do("SELECT INBOX"); !strings.Contains(resp, " OK ") {
		t.Fatalf("SELECT:\n%s", resp)
	}

	for _, tc := range []struct {
		criteria string
		want     []uint32
	}{
		{"SINCE 1-Mar-2025 BEFORE 1-Jan-2025", nil},
		{"SENTSINCE 1-Mar-2025 SENTBEFORE 1-Jan-2025", nil},
		{"LARGER 5000 SMALLER 10", nil},
		{"LARGER 10 SMALLER 10", nil},
		{`BODY ""`, all},
		{`TEXT ""`, all},
		{`NOT BODY ""`, nil},
		{`OR BODY "" SUBJECT nomatch`, all},
		{"SINCE 1-Jan-2024 BEFORE 1-Mar-2025", all},
		{"SENTSINCE 1-Jan-2024 SENTBEFORE 1-Mar-2025", all},
		{`HEADER Message-ID "<` + strings.Repeat("x", 300) + `@example.com>"`, nil},
	} {
		resp := do("UID SEARCH " + tc.criteria)
		got, ok := searchResponseNums(resp)
		if !ok {
			t.Errorf("UID SEARCH %.60s: want OK with a SEARCH response, got:\n%s", tc.criteria, resp)
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("UID SEARCH %.60s = %v, want %v", tc.criteria, got, tc.want)
		}
	}
}
