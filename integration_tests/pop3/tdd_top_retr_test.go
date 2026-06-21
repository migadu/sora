//go:build integration

package pop3_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

type TDDTestServer struct {
	TestServer *common.TestServer
	POP3Server *pop3.POP3Server
	Uploader   *uploader.UploadWorker
	TempDir    string
}

func (s *TDDTestServer) Close() {
	if s.POP3Server != nil {
		s.POP3Server.Close()
	}
	if s.Uploader != nil {
		s.Uploader.Stop()
	}
	if s.TempDir != "" {
		os.RemoveAll(s.TempDir)
	}
	if s.TestServer != nil {
		s.TestServer.Close()
	}
}

func SetupPOP3ServerWithUploader(t *testing.T) (*TDDTestServer, common.TestAccount) {
	t.Helper()

	// 1. Set up the baseline POP3 server (sets up DB and account)
	baseServer, account := common.SetupPOP3Server(t)

	// Close the baseline POP3 server so we can listen on the same port
	if basePOP3, ok := baseServer.Server.(*pop3.POP3Server); ok {
		basePOP3.Close()
	} else {
		t.Fatalf("baseServer.Server is not *pop3.POP3Server")
	}

	// 2. Create the temporary directory for the uploader
	tempDir, err := os.MkdirTemp("", "sora-pop3-tdd-upload-*")
	if err != nil {
		baseServer.Close()
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	errCh := make(chan error, 1)

	// 3. Create a working upload worker with the correct instance ID ("test-instance")
	uploadWorker, err := uploader.NewWithS3Interface(
		tempDir,
		10,
		1,
		3,
		time.Second,
		0,
		"test-instance", // MUST match appendMessageDirectly's PendingUpload InstanceID
		baseServer.ResilientDB,
		&common.NoopUploaderS3{},
		&common.NoopUploaderCache{},
		errCh,
	)
	if err != nil {
		os.RemoveAll(tempDir)
		baseServer.Close()
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	uploadWorker.EnableSyncUpload()
	if err := uploadWorker.Start(context.Background()); err != nil {
		uploadWorker.Stop()
		os.RemoveAll(tempDir)
		baseServer.Close()
		t.Fatalf("Failed to start upload worker: %v", err)
	}

	// 4. Create the new POP3 server configured with the uploader
	server, err := pop3.New(
		context.Background(),
		"test",
		"localhost",
		baseServer.Address,
		&storage.S3Storage{},
		baseServer.ResilientDB,
		uploadWorker,
		nil,
		pop3.POP3ServerOptions{InsecureAuth: true},
	)
	if err != nil {
		uploadWorker.Stop()
		os.RemoveAll(tempDir)
		baseServer.Close()
		t.Fatalf("Failed to create POP3 server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()

	time.Sleep(100 * time.Millisecond)

	// Replace the server instance in baseServer
	baseServer.Server = server

	return &TDDTestServer{
		TestServer: baseServer,
		POP3Server: server,
		Uploader:   uploadWorker,
		TempDir:    tempDir,
	}, account
}

func tddAppendMessage(t *testing.T, server *TDDTestServer, email, msg string) {
	t.Helper()

	accountID, err := server.TestServer.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	inbox, err := server.TestServer.ResilientDB.GetMailboxByNameWithRetry(context.Background(), accountID, "INBOX")
	if err != nil {
		t.Fatalf("Failed to get INBOX: %v", err)
	}

	// Generate a valid 64-character content hash
	contentHash := fmt.Sprintf("%064x", time.Now().UnixNano())

	// Store message body locally in the uploader's staging area
	_, err = server.Uploader.StoreLocally(contentHash, accountID, []byte(msg))
	if err != nil {
		t.Fatalf("Failed to store message body locally: %v", err)
	}

	// Insert message directly into the DB
	_, _, err = server.TestServer.ResilientDB.InsertMessageWithRetry(context.Background(),
		&db.InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     inbox.ID,
			S3Domain:      "example.com",
			S3Localpart:   "test",
			MailboxName:   "INBOX",
			ContentHash:   contentHash,
			MessageID:     fmt.Sprintf("<%d@test.com>", time.Now().UnixNano()),
			Flags:         []imap.Flag{},
			InternalDate:  time.Now(),
			Size:          int64(len(msg)),
			Subject:       "Test",
			PlaintextBody: msg,
			SentDate:      time.Now(),
		},
		db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  "test-instance",
			Size:        int64(len(msg)),
			AccountID:   accountID,
		})
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	// Notify the uploader to process the pending upload synchronously
	server.Uploader.NotifyUploadQueued()
}

func loginClient(t *testing.T, conn net.Conn, email, password string) (*bufio.Reader, *bufio.Writer) {
	t.Helper()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Greeting failed: %s", greeting)
	}

	// USER
	fmt.Fprintf(writer, "USER %s\r\n", email)
	writer.Flush()
	resp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("USER failed: %s", resp)
	}

	// PASS
	fmt.Fprintf(writer, "PASS %s\r\n", password)
	writer.Flush()
	resp, _ = reader.ReadString('\n')
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS failed: %s", resp)
	}

	return reader, writer
}

func readEntireMultilineResponse(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	var sb strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response line: %v", err)
		}
		sb.WriteString(line)
		if line == ".\r\n" {
			break
		}
	}
	return sb.String()
}

func TestTDD_TOP_Lines0(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := SetupPOP3ServerWithUploader(t)
	defer server.Close()

	// Append a message with 2 body lines
	msgContent := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hello\r\n\r\nFirst line of body\r\nSecond line of body\r\n"
	tddAppendMessage(t, server, account.Email, msgContent)

	conn, err := net.Dial("tcp", server.TestServer.Address)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	reader, writer := loginClient(t, conn, account.Email, account.Password)

	// Send TOP 1 0
	fmt.Fprintf(writer, "TOP 1 0\r\n")
	writer.Flush()

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read TOP status: %v", err)
	}
	if !strings.HasPrefix(statusLine, "+OK") {
		t.Fatalf("TOP failed: %s", statusLine)
	}

	multiLineContent := readEntireMultilineResponse(t, reader)

	// For TOP 1 0, we expect exactly:
	// headers\r\n
	// \r\n (separating blank line)
	// .\r\n
	expectedContent := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hello\r\n\r\n.\r\n"
	if multiLineContent != expectedContent {
		t.Errorf("Expected content:\n%q\nGot:\n%q", expectedContent, multiLineContent)
	}
}

func TestTDD_TOP_LinesLarge(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := SetupPOP3ServerWithUploader(t)
	defer server.Close()

	// Append a message with 2 body lines
	msgContent := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hello\r\n\r\nFirst line of body\r\nSecond line of body\r\n"
	tddAppendMessage(t, server, account.Email, msgContent)

	conn, err := net.Dial("tcp", server.TestServer.Address)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	reader, writer := loginClient(t, conn, account.Email, account.Password)

	// Send TOP 1 100
	fmt.Fprintf(writer, "TOP 1 100\r\n")
	writer.Flush()

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read TOP status: %v", err)
	}
	if !strings.HasPrefix(statusLine, "+OK") {
		t.Fatalf("TOP failed: %s", statusLine)
	}

	multiLineContent := readEntireMultilineResponse(t, reader)

	// We expect the whole message body, but terminated cleanly:
	// headers\r\n
	// \r\n
	// First line of body\r\n
	// Second line of body\r\n
	// .\r\n
	expectedContent := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hello\r\n\r\nFirst line of body\r\nSecond line of body\r\n.\r\n"
	if multiLineContent != expectedContent {
		t.Errorf("Expected content:\n%q\nGot:\n%q", expectedContent, multiLineContent)
	}
}

func TestTDD_RETR(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := SetupPOP3ServerWithUploader(t)
	defer server.Close()

	msgContent := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hello\r\n\r\nBody line\r\n"
	tddAppendMessage(t, server, account.Email, msgContent)

	conn, err := net.Dial("tcp", server.TestServer.Address)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	reader, writer := loginClient(t, conn, account.Email, account.Password)

	fmt.Fprintf(writer, "RETR 1\r\n")
	writer.Flush()

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read RETR status: %v", err)
	}
	if !strings.HasPrefix(statusLine, "+OK") {
		t.Fatalf("RETR failed: %s", statusLine)
	}

	multiLineContent := readEntireMultilineResponse(t, reader)

	// We expect the original message ending with CRLF and then directly followed by .\r\n
	expectedContent := msgContent + ".\r\n"
	if multiLineContent != expectedContent {
		t.Errorf("Expected content:\n%q\nGot:\n%q", expectedContent, multiLineContent)
	}
}

func TestTDD_AuthStateConstraints(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := SetupPOP3ServerWithUploader(t)
	defer server.Close()

	// Send TRANSACTION commands before authenticating and verify they return -ERR Not authenticated
	cmds := []string{
		"STAT",
		"LIST",
		"UIDL",
		"NOOP",
		"RSET",
		"DELE",
		"DELE abc",
		"TOP",
		"TOP abc def",
		"RETR",
		"RETR abc",
	}

	for _, cmd := range cmds {
		conn, err := net.Dial("tcp", server.TestServer.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}

		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)

		// Read greeting
		if _, err := reader.ReadString('\n'); err != nil {
			conn.Close()
			t.Fatalf("Failed to read greeting: %v", err)
		}

		fmt.Fprintf(writer, "%s\r\n", cmd)
		writer.Flush()

		resp, err := reader.ReadString('\n')
		conn.Close()
		if err != nil {
			t.Fatalf("Failed to read response to %q: %v", cmd, err)
		}

		if !strings.HasPrefix(resp, "-ERR") {
			t.Errorf("Command %q returned non-error response: %s", cmd, resp)
		}
		if !strings.Contains(resp, "Not authenticated") && !strings.Contains(resp, "not authenticated") {
			t.Errorf("Command %q did not return 'Not authenticated' error, got: %s", cmd, resp)
		}
	}
}
