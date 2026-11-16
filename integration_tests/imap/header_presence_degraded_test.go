//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_HeaderPresenceDegradedAppend reproduces remaining #661 false positives on
// newly APPENDed mail when server.ParseMessage fails:
//  1. A message with a malformed header line (no colon), including headers after it.
//  2. A message with a malformed MIME Content-Type (multipart/mixed with no boundary),
//     whose RFC 5322 header lines are otherwise valid.
//
// Previously, APPEND stored NULL header_presence whenever server.ParseMessage failed,
// causing UID SEARCH HEADER Cc "" / CC "" / HEADER To "" / TO "" to falsely match
// those messages even though they lack Cc/To headers.
func TestIMAP_HeaderPresenceDegradedAppend(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()

	c, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatal(err)
	}

	raws := []string{
		// UID 1: malformed header line (no colon) before Subject; From + Subject present, To + Cc absent,
		// and body contains "Cc: not-a-header@example.com" after the blank line.
		"From: sender@example.com\r\nMalformedLineWithoutColon\r\nSubject: degraded\r\n\r\nCc: not-a-header@example.com\r\n",
		// UID 2: malformed MIME Content-Type (missing boundary); From + empty Cc: present, To + Subject absent.
		"From: sender@example.com\r\nCc:\r\nContent-Type: multipart/mixed\r\n\r\nbody 2\r\n",
		// UID 3: well-formed control; From + populated Cc + present-empty Subject: present, To absent.
		"From: sender@example.com\r\nCc: copy@example.com\r\nSubject:\r\n\r\nbody 3\r\n",
	}
	for _, raw := range raws {
		cmd := c.Append("INBOX", int64(len(raw)), nil)
		if _, err := cmd.Write([]byte(raw)); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.Logout().Wait()
	c.Close()

	conn, err := net.Dial("tcp", srv.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	command := func(tag, line string) []string {
		t.Helper()
		if _, err := fmt.Fprintf(conn, "%s %s\r\n", tag, line); err != nil {
			t.Fatal(err)
		}
		var lines []string
		for {
			s, err := r.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			s = strings.TrimSpace(s)
			lines = append(lines, s)
			if strings.HasPrefix(s, tag+" ") {
				if !strings.HasPrefix(s, tag+" OK") {
					t.Fatalf("%s: %v", line, lines)
				}
				return lines
			}
		}
	}

	command("l", fmt.Sprintf("LOGIN %q %q", account.Email, account.Password))
	command("s", "SELECT INBOX")

	serial := 0
	search := func(line string) []int {
		t.Helper()
		serial++
		lines := command(fmt.Sprintf("q%d", serial), "UID SEARCH "+line)
		got := []int{}
		for _, s := range lines {
			if strings.HasPrefix(s, "* SEARCH") {
				for _, n := range strings.Fields(strings.TrimPrefix(s, "* SEARCH")) {
					u, err := strconv.Atoi(n)
					if err != nil {
						t.Fatal(err)
					}
					got = append(got, u)
				}
			}
		}
		slices.Sort(got)
		return got
	}

	cases := []struct {
		query string
		want  []int
	}{
		{`HEADER From ""`, []int{1, 2, 3}},
		{`NOT HEADER From ""`, []int{}},
		{`HEADER Cc ""`, []int{2, 3}},
		{`NOT HEADER Cc ""`, []int{1}},
		{`HEADER To ""`, []int{}},
		{`NOT HEADER To ""`, []int{1, 2, 3}},
		{`CC ""`, []int{3}},
		{`NOT CC ""`, []int{1, 2}},
		{`TO ""`, []int{}},
		{`NOT TO ""`, []int{1, 2, 3}},
		{`HEADER Subject ""`, []int{1, 3}},
		{`NOT HEADER Subject ""`, []int{2}},
	}
	for _, tc := range cases {
		if got := search(tc.query); !slices.Equal(got, tc.want) {
			t.Errorf("UID SEARCH %s = %v, want %v", tc.query, got, tc.want)
		}
	}
}
