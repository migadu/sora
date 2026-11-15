//go:build integration

package imap_test

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	imapServer "github.com/migadu/sora/server/imap"
	"github.com/stretchr/testify/require"
)

func TestIMAP_FetchSeenNotOvertakenByInFlightNotifyFetch(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	require.NoError(t, c.conn.SetDeadline(time.Now().Add(10*time.Second)))
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	c.do("SELECT INBOX")
	c.do("NOTIFY SET (SELECTED (MessageNew (FLAGS BINARY.PEEK[1]) MessageExpunge FlagChange))")
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer release()
	var gets atomic.Int32
	fake.OnGet(func(string) {
		if gets.Add(1) == 1 {
			close(entered)
			<-resume
		}
	})
	defer fake.OnGet(nil)
	other := dialRawIMAP(t, server.Address)
	other.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	other.appendMsg("INBOX", binaryDecodeTestMessage("notify overlap", "text/plain", "base64", "aGVsbG8gd29ybGQ=\r\n"))
	server.WaitForUploads(t)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("notification did not reach body decode")
	}
	// Notification FLAGS were read before this command. Its body decode is
	// paused before CreateMessage, leaving the encoder free for the command.
	tag := c.send("UID FETCH 1 BODY[TEXT]")
	var lines []string
	for {
		line, err := c.r.ReadString('\n')
		require.NoError(t, err)
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if line == ")" {
			break
		}
	}
	var seen bool
	for _, line := range lines {
		seen = seen || seenFlagsRe.MatchString(line)
	}
	require.True(t, seen, "command did not answer its Seen change: %q", lines)
	// The post-command poll waits for the in-flight notification's sequence
	// read lock, so it will run after that older notification response.
	require.NoError(t, c.conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	line, err := c.r.ReadString('\n')
	var ne net.Error
	require.ErrorAs(t, err, &ne, "command completed before notification released: %q", line)
	require.True(t, ne.Timeout())
	require.NoError(t, c.conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	release()
	remaining, _ := c.collect(tag, "overlapped FETCH")
	lines = append(lines, remaining...)
	noop, _ := c.do("NOOP")
	lines = append(lines, noop...)
	var last string
	for _, response := range fetchResponsesForSeq(lines, 1) {
		if strings.Contains(response, "FLAGS (") {
			last = response
		}
	}
	t.Logf("responses=%q", lines)
	require.Regexp(t, seenFlagsRe, last, "stale notification overtook Seen; the final poll must repair it")
}

// A dropped body download must release the batch's Seen lock and the command's
// snapshot before the waiting NOTIFY pump and session teardown can finish.
func TestIMAP_FetchSeenDisconnectReleasesNotifySession(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	require.NoError(t, c.conn.SetDeadline(time.Now().Add(10*time.Second)))
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	for range 3 {
		c.appendMsg("INBOX", binaryDecodeTestMessage("disconnect", "text/plain", "base64", "aGVsbG8gd29ybGQ=\r\n"))
	}
	server.WaitForUploads(t)
	c.do("SELECT INBOX")
	c.do("NOTIFY SET (SELECTED (MessageNew MessageExpunge FlagChange))")
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer release()
	var gets atomic.Int32
	fake.OnGet(func(string) {
		if gets.Add(1) == 1 {
			close(entered)
			<-resume
		}
	})
	defer fake.OnGet(nil)
	c.send("FETCH 1:* BODY[]")
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("FETCH did not reach body download")
	}
	tcp := c.conn.(*net.TCPConn)
	require.NoError(t, tcp.SetLinger(0))
	require.NoError(t, tcp.Close())
	release()
	backend := server.Server.(*imapServer.IMAPServer)
	require.Eventually(t, func() bool { return backend.GetTotalConnections() == 0 }, 5*time.Second, 10*time.Millisecond,
		"disconnected Seen FETCH left its session or NOTIFY pump blocked")
	require.Equal(t, int32(1), gets.Load(), "FETCH continued downloading bodies after disconnect")
}
