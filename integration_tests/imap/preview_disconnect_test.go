//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/server/imap"
)

// PREVIEW has no literal writes: its first socket error can surface only when
// the buffered message response closes. That error must stop the mailbox stream.
func TestIMAP_FetchPreviewDisconnectStopsDownloads(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account, fake := common.SetupIMAPServerWithRealS3Options(t, func(o *imap.IMAPServerOptions) {
		o.Preview = imap.PreviewOptions{Enabled: true}
	})
	defer server.Close()
	c := dialPreview(t, server.Address, account)
	if err := c.conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		c.appendMessage(fmt.Sprintf("From: alice@example.com\nSubject: disconnect %d\n\nPreview body %d.\n", i, i))
	}
	server.WaitForUploads(t)
	if n := fake.GetCount(); n != 0 {
		t.Fatalf("setup downloaded %d bodies before FETCH", n)
	}

	firstGet := make(chan struct{})
	releaseGet := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseGet) }) }
	defer release() // unblock the handler before server cleanup on an early failure
	var firstOnce sync.Once
	fake.OnGet(func(_ string) {
		firstOnce.Do(func() {
			close(firstGet)
			<-releaseGet
		})
	})
	defer fake.OnGet(nil)
	if _, err := fmt.Fprint(c.conn, "D001 FETCH 1:* (UID PREVIEW)\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstGet:
	case <-time.After(5 * time.Second):
		t.Fatal("FETCH never requested the first S3 body")
	}

	// Reset the client while the first GET is held. Releasing its response
	// then forces the PREVIEW writer's first flush to observe the disconnect.
	tcp, ok := c.conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("raw preview connection is %T, want TCP", c.conn)
	}
	if err := tcp.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := tcp.Close(); err != nil {
		t.Fatal(err)
	}
	release()

	backend := server.Server.(*imap.IMAPServer)
	deadline := time.Now().Add(5 * time.Second)
	for backend.GetTotalConnections() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("disconnected FETCH did not release its session")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := fake.GetCount(); n != 1 {
		t.Fatalf("disconnected FETCH downloaded %d bodies, want only the first", n)
	}
}

// A streaming FETCH callback can fail while flushing to a disconnected client.
// That is not a database failure, even when several clients disconnect at once.
func TestIMAP_FetchPreviewDisconnectPreservesDatabaseBreaker(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account, fake := common.SetupIMAPServerWithRealS3Options(t, func(o *imap.IMAPServerOptions) {
		o.Preview = imap.PreviewOptions{Enabled: true}
	})
	defer server.Close()

	const clientCount = 8
	clients := make([]*previewConn, clientCount)
	for i := range clients {
		clients[i] = dialPreview(t, server.Address, account)
		if err := clients[i].conn.SetDeadline(time.Now().Add(45 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	clients[0].appendMessage("From: alice@example.com\nSubject: disconnect breaker\n\nThe body in storage.\n")
	server.WaitForUploads(t)
	accountID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(context.Background(), accountID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if n := fake.GetCount(); n != 0 {
		t.Fatalf("setup downloaded %d bodies before FETCH", n)
	}

	// The query breaker uses a 15-second window. Let setup and authentication
	// successes expire so they cannot mask callback errors counted as failures.
	time.Sleep(16 * time.Second)

	entered := make(chan struct{}, clientCount)
	releaseGet := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseGet) }) }
	defer release() // unblock handlers before server cleanup on an early failure
	fake.OnGet(func(_ string) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-releaseGet
	})
	defer fake.OnGet(nil)
	for _, c := range clients {
		if _, err := fmt.Fprint(c.conn, "D001 FETCH 1 (UID PREVIEW)\r\n"); err != nil {
			t.Fatal(err)
		}
	}
	wait := time.NewTimer(5 * time.Second)
	defer wait.Stop()
	for range clientCount {
		select {
		case <-entered:
		case <-wait.C:
			t.Fatalf("only %d of %d FETCHes reached S3", fake.GetCount(), clientCount)
		}
	}
	for _, c := range clients {
		tcp, ok := c.conn.(*net.TCPConn)
		if !ok {
			t.Fatalf("raw preview connection is %T, want TCP", c.conn)
		}
		if err := tcp.SetLinger(0); err != nil {
			t.Fatal(err)
		}
		if err := tcp.Close(); err != nil {
			t.Fatal(err)
		}
	}
	release()

	backend := server.Server.(*imap.IMAPServer)
	deadline := time.Now().Add(5 * time.Second)
	for backend.GetTotalConnections() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("disconnected FETCHes did not release their sessions")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := fake.GetCount(); n != clientCount {
		t.Errorf("disconnected FETCHes downloaded %d bodies, want %d", n, clientCount)
	}
	if state := server.ResilientDB.GetQueryBreakerState(); state != circuitbreaker.StateClosed {
		t.Errorf("client disconnects changed the database query breaker to %s", state)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := server.ResilientDB.GetMailboxSummaryWithRetry(ctx, mailbox.ID); err != nil {
		t.Fatalf("healthy database read after client disconnects: %v", err)
	}
}
