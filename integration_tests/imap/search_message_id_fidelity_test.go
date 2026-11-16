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

// TestIMAP_HeaderMessageIDFieldTextFidelity reproduces the RFC 9051 §6.4.4 HEADER
// Message-ID field-text cases in #529:
//  1. Surrounding CFWS / comments: Message-ID: (NeedleComment) <comm@example.com>
//  2. Present-empty field: Message-ID:
//  3. Unparseable field: Message-ID: malformed
//  4. Nested angle-brackets inside domain-literal: Message-ID: <outer@[<inner@example.com>]>
//  5. Obsolete quoted id-left (RFC 5322 §4.5.4): Message-ID: <"<inner"@example.com>
//  6. Absent Message-ID control
func TestIMAP_HeaderMessageIDFieldTextFidelity(t *testing.T) {
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
		// UID 1: comment before msg-id
		"From: a@example.com\r\nSubject: comment\r\nMessage-ID: (NeedleComment) <comm@example.com>\r\n\r\nbody 1\r\n",
		// UID 2: present but empty
		"From: a@example.com\r\nSubject: empty\r\nMessage-ID:\r\n\r\nbody 2\r\n",
		// UID 3: malformed
		"From: a@example.com\r\nSubject: malformed\r\nMessage-ID: malformed\r\n\r\nbody 3\r\n",
		// UID 4: bracketed substring inside domain-literal
		"From: a@example.com\r\nSubject: domlit\r\nMessage-ID: <outer@[<inner@example.com>]>\r\n\r\nbody 4\r\n",
		// UID 5: quoted id-left (obs-id-left)
		"From: a@example.com\r\nSubject: quoted\r\nMessage-ID: <\"<inner\"@example.com>\r\n\r\nbody 5\r\n",
		// UID 6: absent Message-ID control
		"From: a@example.com\r\nSubject: absent\r\n\r\nbody 6\r\n",
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
		{`HEADER Message-ID "NeedleComment"`, []int{1}},
		{`HEADER Message-ID "needlecomment"`, []int{1}},
		{`NOT HEADER Message-ID "NeedleComment"`, []int{2, 3, 4, 5, 6}},
		{`HEADER Message-ID "<comm@example.com>"`, []int{1}},
		{`HEADER Message-ID ""`, []int{1, 2, 3, 4, 5}},
		{`NOT HEADER Message-ID ""`, []int{6}},
		{`HEADER Message-ID "malformed"`, []int{3}},
		{`NOT HEADER Message-ID "malformed"`, []int{1, 2, 4, 5, 6}},
		{`HEADER Message-ID "<inner@example.com>"`, []int{4}},
		{`NOT HEADER Message-ID "<inner@example.com>"`, []int{1, 2, 3, 5, 6}},
		{"HEADER Message-ID {22}\r\n<\"<inner\"@example.com>", []int{5}},
		{"HEADER Message-ID {8}\r\n\"<inner\"", []int{5}},
		{`HEADER Message-ID "example.com"`, []int{1, 4, 5}},
	}
	for _, tc := range cases {
		if got := search(tc.query); !slices.Equal(got, tc.want) {
			t.Errorf("UID SEARCH %q = %v, want %v", tc.query, got, tc.want)
		}
	}

	// Verify COPY preserves raw Message-ID search semantics in the destination mailbox.
	command("cm", `CREATE "CopyDest"`)
	command("cp", `UID COPY 1:6 "CopyDest"`)
	command("sa", `SELECT "CopyDest"`)
	for _, tc := range cases {
		if got := search(tc.query); !slices.Equal(got, tc.want) {
			t.Errorf("CopyDest after COPY: UID SEARCH %q = %v, want %v", tc.query, got, tc.want)
		}
	}
}
