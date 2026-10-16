//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_Thread_WireFormat reads the THREAD response off the wire, as
// Roundcube does, and checks it against RFC 5256 section 4: one SP after
// THREAD, then the thread-lists back to back.
//
// The go-imap client cannot catch a separating SP, because its decoder accepts
// both forms. Roundcube can: it reads the response by matching parentheses and,
// after an SP between threads, keeps the first thread and drops the rest, so
// its threaded view showed one conversation per folder.
func TestIMAP_Thread_WireFormat(t *testing.T) {
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

	// UID 2 replies to UID 1; UIDs 3 and 4 stand alone. Sent date, arrival and
	// UID all rise together, so every algorithm orders the threads the same way.
	base := time.Now().Add(-4 * time.Hour).Truncate(time.Second)
	messages := []string{
		"Message-ID: <alpha@example.com>\r\nSubject: Alpha\r\n",
		"Message-ID: <alpha-re@example.com>\r\nIn-Reply-To: <alpha@example.com>\r\nReferences: <alpha@example.com>\r\nSubject: Re: Alpha\r\n",
		"Message-ID: <bravo@example.com>\r\nSubject: Bravo\r\n",
		"Message-ID: <charlie@example.com>\r\nSubject: Charlie\r\n",
	}
	for i, headers := range messages {
		date := base.Add(time.Duration(i) * time.Hour)
		body := headers + "Date: " + date.Format(time.RFC1123Z) + "\r\n\r\nbody\r\n"
		appendCmd := c.Append("INBOX", int64(len(body)), &imap.AppendOptions{Time: date})
		if _, err := appendCmd.Write([]byte(body)); err != nil {
			t.Fatalf("Append write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("Append close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("Append failed: %v", err)
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

	// Roundcube's command: UID THREAD <algorithm> US-ASCII ALL UNDELETED.
	for _, alg := range []string{"REFS", "REFERENCES", "ORDEREDSUBJECT"} {
		t.Run(alg, func(t *testing.T) {
			var got []string
			for _, line := range command("UID THREAD " + alg + " US-ASCII ALL UNDELETED") {
				if strings.HasPrefix(line, "* THREAD") {
					got = append(got, line)
				}
			}
			want := "* THREAD (1 2)(3)(4)\r\n"
			if len(got) != 1 || got[0] != want {
				t.Errorf("THREAD response = %q, want [%q]", got, want)
			}
		})
	}
}
