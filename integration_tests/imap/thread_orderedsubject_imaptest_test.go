//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_Thread_OrderedSubject_Imaptest runs Dovecot imaptest's
// thread-orderedsubject case (src/tests/thread-orderedsubject{,.mbox} at
// 0682be5f3617149e55cb6a2f4de4b23be8092c53): fifteen messages with one sent date,
// whose subjects exercise RFC 5256 section 2.1 base-subject extraction.
//
// Messages 9 (no Subject) and 10 (an encoded-word that decodes to a space) both
// have the empty base subject, so ORDEREDSUBJECT (RFC 5256 section 3) puts them in
// one thread: "each thread containing messages with the same base subject text".
func TestIMAP_Thread_OrderedSubject_Imaptest(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// The fixture's messages, in order. "" is message 9, which has no Subject.
	messages := []string{
		"Subject: a\r\n\r\n1\r\n",
		"Subject: C\r\n\r\n2\r\n",
		"Subject: b\r\n\r\n3\r\n",
		"Subject: _\r\n\r\n4\r\n",
		"Subject: [foo] Fwd: [bar] Re: fw: b (fWd)  (fwd)\r\n\r\n55\r\n",
		"Subject: b (a)\r\n\r\n66\r\n",
		"Subject: Re: [FWD: c]\r\n\r\n77\r\n",
		"Subject: [xyz]\r\n\r\n88\r\n",
		"\r\n9\r\n",
		"Subject: =?iso-8859-1?q?_?=\r\n\r\n10\r\n",
		"Subject: Re: =?utf-8?q?b?=\r\n\r\n11\r\n" + strings.Repeat("x", 64) + "\r\n",
		"Subject: =?iso-8859-1?q?RE:_C?=\r\n\r\n12\r\n" + strings.Repeat(strings.Repeat("x", 64)+"\r\n", 2),
		"Subject: =?us-ascii?b?UmU6IGM=?=\r\n\r\n13\r\n\r\nThe subject is 'Re: c'.\r\n" + strings.Repeat(strings.Repeat("x", 64)+"\r\n", 3),
		"Subject: Ad: Re: Ad: Re: Ad: x\r\n\r\n14\r\n",
		"Subject: re: [fwd: [fwd: re: [fwd: babylon]]]\r\n\r\n15\r\n",
	}
	date := time.Date(2008, time.February, 22, 23, 0, 0, 0, time.FixedZone("", 2*60*60))
	for i, body := range messages {
		appendCmd := c.Append("INBOX", int64(len(body)), &imap.AppendOptions{Time: date})
		if _, err := appendCmd.Write([]byte(body)); err != nil {
			t.Fatalf("Append %d write failed: %v", i+1, err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("Append %d close failed: %v", i+1, err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("Append %d failed: %v", i+1, err)
		}
	}

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(conn)

	// command sends one command and returns its untagged lines, failing the
	// test unless it completes with OK.
	n := 0
	command := func(cmd string) []string {
		t.Helper()
		n++
		tag := fmt.Sprintf("T%03d", n)
		fmt.Fprintf(conn, "%s %s\r\n", tag, cmd)
		var untagged []string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("%s: reading response: %v", cmd, err)
			}
			if strings.HasPrefix(line, tag+" ") {
				if !strings.HasPrefix(line, tag+" OK") {
					t.Fatalf("%s: %s", cmd, strings.TrimSpace(line))
				}
				return untagged
			}
			untagged = append(untagged, line)
		}
	}

	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	command(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	command("SELECT INBOX")

	var got []string
	for _, line := range command("THREAD ORDEREDSUBJECT US-ASCII ALL") {
		if strings.HasPrefix(line, "* THREAD") {
			got = append(got, line)
		}
	}
	want := "* THREAD (1)(2 (7)(12)(13))(3 (5)(11))(4)(6)(8)(9 10)(14)(15)\r\n"
	if len(got) != 1 || got[0] != want {
		t.Errorf("THREAD response = %q, want [%q]", got, want)
	}
}
