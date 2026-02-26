//go:build integration

package imap_test

import (
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_SessionSummary_Append(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Start log capture
	logCapture := NewLogCapture()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Append 3 messages
	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest body\r\n"
	for i := 0; i < 3; i++ {
		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		appendCmd.Write([]byte(msg))
		appendCmd.Close()
		appendCmd.Wait()
	}

	// Logout to trigger session close
	c.Logout()
	c.Close()

	// Wait for log to be written
	time.Sleep(300 * time.Millisecond)

	// Stop log capture and check output
	logs := logCapture.Stop()
	if !strings.Contains(logs, "session summary") {
		t.Errorf("Expected 'session summary' in logs")
	}
	if !strings.Contains(logs, "appended=3") {
		t.Errorf("Expected 'appended=3' in logs, got:\n%s", logs)
	}
	if !strings.Contains(logs, "duration=") {
		t.Errorf("Expected 'duration=' in logs")
	}
}

func TestIMAP_SessionSummary_Expunge(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Append 2 messages
	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest body\r\n"
	for i := 0; i < 2; i++ {
		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		appendCmd.Write([]byte(msg))
		appendCmd.Close()
		appendCmd.Wait()
	}

	// Select INBOX
	c.Select("INBOX", nil).Wait()

	// Mark messages as deleted
	seqSet := imap.SeqSetNum(1, 2)
	storeCmd := c.Store(seqSet, &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil)
	storeCmd.Close()

	// Start log capture before expunge
	logCapture := NewLogCapture()

	// Expunge messages
	expungeCmd := c.Expunge()
	expungeCmd.Close()

	// Logout
	c.Logout()
	c.Close()

	// Wait for log
	time.Sleep(300 * time.Millisecond)

	// Check log output
	logs := logCapture.Stop()
	if !strings.Contains(logs, "session summary") {
		t.Errorf("Expected 'session summary' in logs")
	}
	if !strings.Contains(logs, "expunged=2") {
		t.Errorf("Expected 'expunged=2' in logs, got:\n%s", logs)
	}
}

func TestIMAP_SessionSummary_Move(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Append message
	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest body\r\n"
	appendCmd := c.Append("INBOX", int64(len(msg)), nil)
	appendCmd.Write([]byte(msg))
	appendCmd.Close()
	appendCmd.Wait()

	// Select INBOX
	c.Select("INBOX", nil).Wait()

	// Start log capture before move
	logCapture := NewLogCapture()

	// Move to Trash
	uidSet := imap.UIDSet{}
	uidSet.AddNum(1)
	moveCmd := c.Move(uidSet, "Trash")
	moveCmd.Wait()

	// Logout
	c.Logout()
	c.Close()

	// Wait for log
	time.Sleep(300 * time.Millisecond)

	// Check log output
	logs := logCapture.Stop()
	if !strings.Contains(logs, "session summary") {
		t.Errorf("Expected 'session summary' in logs")
	}
	if !strings.Contains(logs, "moved=1") {
		t.Errorf("Expected 'moved=1' in logs, got:\n%s", logs)
	}
}

func TestIMAP_SessionSummary_Copy(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Append message
	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest body\r\n"
	appendCmd := c.Append("INBOX", int64(len(msg)), nil)
	appendCmd.Write([]byte(msg))
	appendCmd.Close()
	appendCmd.Wait()

	// Select INBOX
	c.Select("INBOX", nil).Wait()

	// Start log capture before copy
	logCapture := NewLogCapture()

	// Copy to Drafts
	uidSet := imap.UIDSet{}
	uidSet.AddNum(1)
	copyCmd := c.Copy(uidSet, "Drafts")
	copyCmd.Wait()

	// Logout
	c.Logout()
	c.Close()

	// Wait for log
	time.Sleep(300 * time.Millisecond)

	// Check log output
	logs := logCapture.Stop()
	if !strings.Contains(logs, "session summary") {
		t.Errorf("Expected 'session summary' in logs")
	}
	if !strings.Contains(logs, "copied=1") {
		t.Errorf("Expected 'copied=1' in logs, got:\n%s", logs)
	}
}

func TestIMAP_SessionSummary_Combined(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Start log capture from the beginning to capture all operations
	logCapture := NewLogCapture()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		logCapture.Stop()
		t.Fatalf("Failed to dial: %v", err)
	}

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		logCapture.Stop()
		t.Fatalf("Login failed: %v", err)
	}

	// Append 2 messages
	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest body\r\n"
	for i := 0; i < 2; i++ {
		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		appendCmd.Write([]byte(msg))
		appendCmd.Close()
		appendCmd.Wait()
	}

	// Select INBOX
	c.Select("INBOX", nil).Wait()

	// Copy first message to Drafts
	uidSet := imap.UIDSet{}
	uidSet.AddNum(1)
	copyCmd := c.Copy(uidSet, "Drafts")
	copyCmd.Wait()

	// Delete second message
	seqSet := imap.SeqSetNum(2)
	storeCmd := c.Store(seqSet, &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil)
	storeCmd.Close()

	// Expunge
	expungeCmd := c.Expunge()
	expungeCmd.Close()

	// Logout
	c.Logout()
	c.Close()

	// Wait for log
	time.Sleep(300 * time.Millisecond)

	// Check log output contains all counters
	logs := logCapture.Stop()
	if !strings.Contains(logs, "session summary") {
		t.Errorf("Expected 'session summary' in logs")
	}
	if !strings.Contains(logs, "appended=2") {
		t.Errorf("Expected 'appended=2' in logs, got:\n%s", logs)
	}
	if !strings.Contains(logs, "copied=1") {
		t.Errorf("Expected 'copied=1' in logs, got:\n%s", logs)
	}
	if !strings.Contains(logs, "expunged=1") {
		t.Errorf("Expected 'expunged=1' in logs, got:\n%s", logs)
	}
}

func TestIMAP_SessionSummary_NoOps(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Start log capture
	logCapture := NewLogCapture()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		logCapture.Stop()
		t.Fatalf("Failed to dial: %v", err)
	}

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		logCapture.Stop()
		t.Fatalf("Login failed: %v", err)
	}

	// Just select a mailbox, no operations
	c.Select("INBOX", nil).Wait()

	// Logout
	c.Logout()
	c.Close()

	// Wait for log
	time.Sleep(300 * time.Millisecond)

	// Check log output - should NOT contain session summary (no operations)
	logs := logCapture.Stop()
	if strings.Contains(logs, "session summary") {
		t.Errorf("Expected NO 'session summary' for idle session, got:\n%s", logs)
	}
}
