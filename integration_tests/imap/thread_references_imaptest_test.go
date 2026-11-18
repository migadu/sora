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

// Dovecot imaptest's thread3 and thread4 cases (src/tests/thread{3,4}{,.mbox} at
// 0682be5f3617149e55cb6a2f4de4b23be8092c53): a reply that no reference links to
// the message it answers is merged into it by subject. RFC 5256 section 3,
// REFERENCES step 5.C: "If the current message is a reply or forward and the
// message in the subject table is not, make the current message a child of the
// message in the subject table". Neither message has a Date, so the sent date
// is the INTERNALDATE (RFC 5256 section 2.2).

// TestIMAP_Thread_References_DuplicateMessageID is thread3: the reply repeats the
// original's Message-ID, so step 1.A gives it a unique one and only the subject
// can thread it.
func TestIMAP_Thread_References_DuplicateMessageID(t *testing.T) {
	got := threadImaptestMessages(t, "THREAD REFERENCES US-ASCII ALL",
		"Message-Id: <a@b>\r\nSubject: foo\r\n\r\nbody\r\n",
		"Message-Id: <a@b>\r\nSubject: Re: foo\r\n\r\nbody\r\n",
	)
	if want := "* THREAD (1 2)\r\n"; got != want {
		t.Errorf("THREAD response = %q, want %q", got, want)
	}
}

// TestIMAP_Thread_References_MissingReference is thread4: the reply references a
// message that is not in the mailbox; step 3 prunes that dummy, leaving the reply
// a root of its own for step 5 to merge.
func TestIMAP_Thread_References_MissingReference(t *testing.T) {
	got := threadImaptestMessages(t, "THREAD REFERENCES US-ASCII ALL",
		"Message-Id: <a@b>\r\nSubject: foo\r\n\r\nbody\r\n",
		"Message-Id: <b@b>\r\nReferences: <c@b>\r\nSubject: Re: foo\r\n\r\nbody\r\n",
	)
	if want := "* THREAD (1 2)\r\n"; got != want {
		t.Errorf("THREAD response = %q, want %q", got, want)
	}
}

// threadImaptestMessages APPENDs messages to a fresh INBOX one second apart from
// 22-Feb-2008 15:06:23 +0000, as the imaptest mbox envelopes date them, and
// returns the THREAD response cmd gets, read off the wire.
func threadImaptestMessages(t *testing.T, cmd string, messages ...string) string {
	t.Helper()
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	t.Cleanup(server.Close)

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	base := time.Date(2008, time.February, 22, 15, 6, 23, 0, time.UTC)
	for i, body := range messages {
		appendCmd := c.Append("INBOX", int64(len(body)), &imap.AppendOptions{Time: base.Add(time.Duration(i) * time.Second)})
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
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}

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
	command(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	command("SELECT INBOX")

	var got []string
	for _, line := range command(cmd) {
		if strings.HasPrefix(line, "* THREAD") {
			got = append(got, line)
		}
	}
	if len(got) != 1 {
		t.Fatalf("%s: want one THREAD response, got %q", cmd, got)
	}
	return got[0]
}
