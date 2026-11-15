//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestNotifyMessageNewFetchConcurrentFirstCondStoreCommand(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	require.NoError(t, c.conn.SetDeadline(time.Now().Add(15*time.Second)))
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	c.appendMsg("INBOX", binaryDecodeTestMessage("initial", "text/plain", "base64", "aGVsbG8=\r\n"))
	server.WaitForUploads(t)
	c.do("SELECT INBOX")
	c.do("NOTIFY SET (SELECTED (MessageNew (UID BINARY.PEEK[1]) MessageExpunge))")
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
	other.appendMsg("INBOX", binaryDecodeTestMessage("notification", "text/plain", "base64", "aGVsbG8gd29ybGQ=\r\n"))
	server.WaitForUploads(t)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("notification did not pause before opening its response")
	}
	// This valid first enabling command can answer while the notification's
	// body is loading. Its post-command Poll waits for the notification.
	tag := c.send("FETCH 1 (MODSEQ)")
	var before []string
	for {
		line, err := c.r.ReadString('\n')
		require.NoError(t, err)
		line = strings.TrimRight(line, "\r\n")
		before = append(before, line)
		if strings.HasPrefix(line, "* 1 FETCH ") {
			require.Contains(t, line, "MODSEQ (")
			break
		}
	}
	release()
	after, _ := c.collect(tag, "first enabling FETCH")
	responses := fetchResponsesForSeq(after, 2)
	require.NotEmpty(t, responses, "notification absent: before=%q after=%q", before, after)
	for _, response := range responses {
		require.Contains(t, response, "MODSEQ (", "notification followed the first enabling response but lost MODSEQ: before=%q after=%q", before, after)
	}
}
