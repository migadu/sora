//go:build integration

package imap_test

import (
	"bufio"
	"context"
	"fmt"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIMAP_HeaderPresenceForwardOnlyRawSyntax(t *testing.T) {
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
		"From: undisclosed:;\r\nTo: undisclosed:;\r\nCc: undisclosed:;\r\n\r\ngroup",
		"From:\r\nTo:\r\nCc:\r\n\r\nempty",
		"Subject: absent addresses\r\n\r\nabsent",
		"From: a@example.com\r\nTo: b@example.com\r\nCc: c@example.com\r\n\r\nvalid",
		"Subject: legacy unknown\r\n\r\nlegacy",
		"From: this is not an address\r\nTo: invalid list\r\nCc: invalid list\r\n\r\ninvalid",
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
	if err := c.Logout().Wait(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	// Model one legacy/old-writer row; no body lookup/backfill should fill it.
	accountID, err := srv.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatal(err)
	}
	_, err = srv.ResilientDB.GetOperationalDatabase().GetWritePool().Exec(context.Background(), "UPDATE messages SET header_presence=NULL WHERE account_id=$1 AND uid=5", accountID)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", srv.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
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
					u, e := strconv.Atoi(n)
					if e != nil {
						t.Fatal(e)
					}
					got = append(got, u)
				}
			}
		}
		slices.Sort(got)
		return got
	}
	for _, key := range []string{"From", "To", "Cc"} {
		for _, tc := range []struct {
			line string
			want []int
		}{{"HEADER " + key + ` ""`, []int{1, 2, 4, 5, 6}}, {"NOT HEADER " + key + ` ""`, []int{3}}, {strings.ToUpper(key) + ` ""`, []int{4, 5}}, {"NOT " + strings.ToUpper(key) + ` ""`, []int{1, 2, 3, 6}}} {
			if got := search(tc.line); !slices.Equal(got, tc.want) {
				t.Errorf("%s=%v want%v", tc.line, got, tc.want)
			}
		}
	}
	if got := search(`OR HEADER Cc "" NOT HEADER From ""`); !slices.Equal(got, []int{1, 2, 3, 4, 5, 6}) {
		t.Errorf("OR=%v", got)
	}
	for _, tc := range []struct {
		line string
		want []int
	}{
		{`HEADER Subject ""`, []int{3, 5}},
		{`NOT HEADER Subject ""`, []int{1, 2, 4, 6}},
		{`SUBJECT ""`, []int{3, 5}},
		{`NOT SUBJECT ""`, []int{1, 2, 4, 6}},
	} {
		if got := search(tc.line); !slices.Equal(got, tc.want) {
			t.Errorf("%s=%v want%v", tc.line, got, tc.want)
		}
	}
	var unknown bool
	if err := srv.ResilientDB.GetOperationalDatabase().GetWritePool().QueryRow(context.Background(), "SELECT header_presence IS NULL FROM messages WHERE account_id=$1 AND uid=5", accountID).Scan(&unknown); err != nil || !unknown {
		t.Fatalf("search mutated legacy metadata: unknown=%v err=%v", unknown, err)
	}
}

func TestIMAP_SubjectEmptySearchPresenceAndEnvelope(t *testing.T) {
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
		"From: a@example.com\r\nMessage-ID: <s1@example.com>\r\n\r\nabsent subject\r\n",
		"From: a@example.com\r\nSubject:\r\nMessage-ID: <s2@example.com>\r\n\r\nempty subject\r\n",
		"From: a@example.com\r\nSubject: hello world\r\nMessage-ID: <s3@example.com>\r\n\r\nnon-empty subject\r\n",
		"From: a@example.com\r\nMessage-ID: <s4@example.com>\r\n\r\nlegacy absent subject\r\n",
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
	if err := c.Logout().Wait(); err != nil {
		t.Fatal(err)
	}
	c.Close()

	// Model UID 4 as a pre-migration70 row with unknown header_presence.
	accountID, err := srv.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatal(err)
	}
	_, err = srv.ResilientDB.GetOperationalDatabase().GetWritePool().Exec(
		context.Background(),
		"UPDATE messages SET header_presence = NULL WHERE account_id = $1 AND uid = 4",
		accountID,
	)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", srv.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
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

	// Verify ENVELOPE on UID 1 (no Date:, no Subject:) emits NIL for env-subject,
	// while UID 3 emits "hello world".
	env1 := strings.Join(command("f1", "UID FETCH 1 (ENVELOPE)"), "\n")
	if !strings.Contains(env1, "ENVELOPE (NIL NIL ") {
		t.Fatalf("expected UID 1 ENVELOPE to have NIL date and NIL subject, got:\n%s", env1)
	}
	env3 := strings.Join(command("f3", "UID FETCH 3 (ENVELOPE)"), "\n")
	if !strings.Contains(env3, `ENVELOPE (NIL "hello world" `) {
		t.Fatalf("expected UID 3 ENVELOPE to have subject %q, got:\n%s", "hello world", env3)
	}

	serial := 0
	search := func(line string) []int {
		t.Helper()
		serial++
		lines := command(fmt.Sprintf("q%d", serial), "UID SEARCH "+line)
		got := []int{}
		for _, s := range lines {
			if strings.HasPrefix(s, "* SEARCH") {
				for _, n := range strings.Fields(strings.TrimPrefix(s, "* SEARCH")) {
					u, e := strconv.Atoi(n)
					if e != nil {
						t.Fatal(e)
					}
					got = append(got, u)
				}
			}
		}
		slices.Sort(got)
		return got
	}

	for _, tc := range []struct {
		line string
		want []int
	}{
		{`SUBJECT ""`, []int{2, 3, 4}},
		{`NOT SUBJECT ""`, []int{1}},
		{`HEADER Subject ""`, []int{2, 3, 4}},
		{`NOT HEADER Subject ""`, []int{1}},
		{`SUBJECT "hello"`, []int{3}},
		{`NOT SUBJECT "hello"`, []int{1, 2, 4}},
	} {
		if got := search(tc.line); !slices.Equal(got, tc.want) {
			t.Errorf("UID SEARCH %s = %v, want %v", tc.line, got, tc.want)
		}
	}

	esearchOut := strings.Join(command("es1", `UID SEARCH RETURN (ALL COUNT) SUBJECT ""`), "\n")
	if !strings.Contains(esearchOut, "COUNT 3") || !strings.Contains(esearchOut, "ALL 2:4") {
		t.Errorf("UID SEARCH RETURN (ALL COUNT) SUBJECT \"\" unexpected output:\n%s", esearchOut)
	}

	sortOut := strings.Join(command("so1", `UID SORT (ARRIVAL) UTF-8 SUBJECT ""`), "\n")
	if !strings.Contains(sortOut, "* SORT 2 3 4") {
		t.Errorf("UID SORT (ARRIVAL) UTF-8 SUBJECT \"\" unexpected output:\n%s", sortOut)
	}

	threadOut := strings.Join(command("th1", `UID THREAD REFERENCES UTF-8 SUBJECT ""`), "\n")
	if !strings.Contains(threadOut, "* THREAD (2)(3)(4)") {
		t.Errorf("UID THREAD REFERENCES UTF-8 SUBJECT \"\" unexpected output:\n%s", threadOut)
	}

	var unknown bool
	if err := srv.ResilientDB.GetOperationalDatabase().GetWritePool().QueryRow(
		context.Background(),
		"SELECT header_presence IS NULL FROM messages WHERE account_id = $1 AND uid = 4",
		accountID,
	).Scan(&unknown); err != nil || !unknown {
		t.Fatalf("search mutated legacy metadata: unknown=%v err=%v", unknown, err)
	}
}
