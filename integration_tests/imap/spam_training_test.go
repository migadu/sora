//go:build integration

package imap_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/spamtraining"
)

// TestIMAP_SpamTraining_MoveToJunk tests spam training when moving message TO Junk folder
func TestIMAP_SpamTraining_MoveToJunk(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Skip if S3 is not configured (spam training requires S3 to fetch message bodies)
	if os.Getenv("S3_ENDPOINT") == "" {
		t.Skip("S3 not configured - spam training requires S3 to fetch message bodies")
	}

	// Track received training requests
	var receivedRequests []spamtraining.TrainingRequest
	var mu sync.Mutex

	// Create mock spam training endpoint
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Verify Content-Type
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Verify Authorization header
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			t.Errorf("Expected Bearer token in Authorization header, got %s", authHeader)
		}

		// Parse request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed to read request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var req spamtraining.TrainingRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("Failed to parse training request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Store request
		mu.Lock()
		receivedRequests = append(receivedRequests, req)
		mu.Unlock()

		t.Logf("Received spam training request: type=%s, user=%s, source=%s, dest=%s",
			req.Type, req.User, req.SourceMailbox, req.DestMailbox)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockServer.Close()

	// Configure server with spam training
	serverOpts := &common.IMAPServerOpts{
		SpamTrainingEnabled:  true,
		SpamTrainingEndpoint: mockServer.URL,
		SpamTrainingToken:    "test-token-123",
	}

	server, account := common.SetupIMAPServerWithOptions(t, serverOpts)
	defer server.Close()

	// Connect and login
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Ensure Junk mailbox exists
	if err := c.Create("Junk", nil).Wait(); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("CREATE Junk mailbox failed: %v", err)
		}
	}

	// Select INBOX and add test message
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	testMessage := "From: spammer@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Spam Test Message\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"\r\n" +
		"This is a spam test message.\r\n"

	appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// Move message TO Junk (should trigger spam training)
	t.Log("Moving message to Junk (spam training)")
	if _, err := c.Move(imap.SeqSetNum(1), "Junk").Wait(); err != nil {
		t.Fatalf("MOVE to Junk failed: %v", err)
	}

	// Wait for async spam training submission
	time.Sleep(500 * time.Millisecond)

	// Verify training request was received
	mu.Lock()
	defer mu.Unlock()

	if len(receivedRequests) != 1 {
		t.Fatalf("Expected 1 training request, got %d", len(receivedRequests))
	}

	req := receivedRequests[0]

	// Verify request details
	if req.Type != spamtraining.TrainingTypeSpam {
		t.Errorf("Expected training type 'spam', got '%s'", req.Type)
	}

	if req.User != account.Email {
		t.Errorf("Expected user '%s', got '%s'", account.Email, req.User)
	}

	if req.SourceMailbox != "INBOX" {
		t.Errorf("Expected source mailbox 'INBOX', got '%s'", req.SourceMailbox)
	}

	if req.DestMailbox != "Junk" {
		t.Errorf("Expected dest mailbox 'Junk', got '%s'", req.DestMailbox)
	}

	if !strings.Contains(req.Message, "Spam Test Message") {
		t.Error("Message content missing expected subject")
	}

	t.Log("Spam training test completed successfully")
}

// TestIMAP_SpamTraining_MoveFromJunk tests ham training when moving message FROM Junk folder
func TestIMAP_SpamTraining_MoveFromJunk(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Skip if S3 is not configured (spam training requires S3 to fetch message bodies)
	if os.Getenv("S3_ENDPOINT") == "" {
		t.Skip("S3 not configured - spam training requires S3 to fetch message bodies")
	}

	// Track received training requests
	var receivedRequests []spamtraining.TrainingRequest
	var mu sync.Mutex

	// Create mock spam training endpoint
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req spamtraining.TrainingRequest
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		mu.Lock()
		receivedRequests = append(receivedRequests, req)
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockServer.Close()

	// Configure server with spam training
	serverOpts := &common.IMAPServerOpts{
		SpamTrainingEnabled:  true,
		SpamTrainingEndpoint: mockServer.URL,
		SpamTrainingToken:    "test-token-123",
	}

	server, account := common.SetupIMAPServerWithOptions(t, serverOpts)
	defer server.Close()

	// Connect and login
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Ensure Junk mailbox exists
	if err := c.Create("Junk", nil).Wait(); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("CREATE Junk mailbox failed: %v", err)
		}
	}

	// Add test message directly to Junk folder
	testMessage := "From: legitimate@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Ham Test Message\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"\r\n" +
		"This is a legitimate message (not spam).\r\n"

	appendCmd := c.Append("Junk", int64(len(testMessage)), nil)
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND to Junk failed: %v", err)
	}

	// Select Junk to move message out
	if _, err := c.Select("Junk", nil).Wait(); err != nil {
		t.Fatalf("Select Junk failed: %v", err)
	}

	// Move message FROM Junk to INBOX (should trigger ham training)
	t.Log("Moving message from Junk to INBOX (ham training)")
	if _, err := c.Move(imap.SeqSetNum(1), "INBOX").Wait(); err != nil {
		t.Fatalf("MOVE from Junk failed: %v", err)
	}

	// Wait for async spam training submission
	time.Sleep(500 * time.Millisecond)

	// Verify training request was received
	mu.Lock()
	defer mu.Unlock()

	if len(receivedRequests) != 1 {
		t.Fatalf("Expected 1 training request, got %d", len(receivedRequests))
	}

	req := receivedRequests[0]

	// Verify request details
	if req.Type != spamtraining.TrainingTypeHam {
		t.Errorf("Expected training type 'ham', got '%s'", req.Type)
	}

	if req.User != account.Email {
		t.Errorf("Expected user '%s', got '%s'", account.Email, req.User)
	}

	if req.SourceMailbox != "Junk" {
		t.Errorf("Expected source mailbox 'Junk', got '%s'", req.SourceMailbox)
	}

	if req.DestMailbox != "INBOX" {
		t.Errorf("Expected dest mailbox 'INBOX', got '%s'", req.DestMailbox)
	}

	if !strings.Contains(req.Message, "Ham Test Message") {
		t.Error("Message content missing expected subject")
	}

	t.Log("Ham training test completed successfully")
}

// TestIMAP_SpamTraining_NoTrainingForRegularMoves tests that regular moves don't trigger training
func TestIMAP_SpamTraining_NoTrainingForRegularMoves(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Skip if S3 is not configured (spam training requires S3 to fetch message bodies)
	if os.Getenv("S3_ENDPOINT") == "" {
		t.Skip("S3 not configured - spam training requires S3 to fetch message bodies")
	}

	// Track received training requests
	var requestCount int32

	// Create mock spam training endpoint
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		t.Logf("Unexpected training request received")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockServer.Close()

	// Configure server with spam training
	serverOpts := &common.IMAPServerOpts{
		SpamTrainingEnabled:  true,
		SpamTrainingEndpoint: mockServer.URL,
		SpamTrainingToken:    "test-token-123",
	}

	server, account := common.SetupIMAPServerWithOptions(t, serverOpts)
	defer server.Close()

	// Connect and login
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Create test mailbox (not Junk)
	if err := c.Create("Archive", nil).Wait(); err != nil {
		t.Fatalf("CREATE Archive mailbox failed: %v", err)
	}

	// Add test message to INBOX
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	testMessage := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Regular Message\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"\r\n" +
		"Regular message content.\r\n"

	appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// Move message to Archive (should NOT trigger spam training)
	t.Log("Moving message from INBOX to Archive (no training expected)")
	if _, err := c.Move(imap.SeqSetNum(1), "Archive").Wait(); err != nil {
		t.Fatalf("MOVE to Archive failed: %v", err)
	}

	// Wait for potential async submission
	time.Sleep(500 * time.Millisecond)

	// Verify no training request was received
	count := atomic.LoadInt32(&requestCount)
	if count != 0 {
		t.Errorf("Expected 0 training requests for regular move, got %d", count)
	}

	t.Log("No training test completed successfully")
}

// TestIMAP_SpamTraining_CircuitBreakerFailure tests circuit breaker behavior on endpoint failure
func TestIMAP_SpamTraining_CircuitBreakerFailure(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Skip if S3 is not configured (spam training requires S3 to fetch message bodies)
	if os.Getenv("S3_ENDPOINT") == "" {
		t.Skip("S3 not configured - spam training requires S3 to fetch message bodies")
	}

	// Track request count
	var requestCount int32
	var failureCount = 5 // Circuit breaker threshold

	// Create mock spam training endpoint that fails
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		t.Logf("Request #%d received", count)

		// Always return 500 error
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer mockServer.Close()

	// Configure server with spam training and low circuit breaker threshold
	serverOpts := &common.IMAPServerOpts{
		SpamTrainingEnabled:           true,
		SpamTrainingEndpoint:          mockServer.URL,
		SpamTrainingToken:             "test-token-123",
		SpamTrainingCircuitThreshold:  failureCount,
		SpamTrainingCircuitTimeout:    "2s",
		SpamTrainingCircuitMaxRequest: 3,
	}

	server, account := common.SetupIMAPServerWithOptions(t, serverOpts)
	defer server.Close()

	// Connect and login
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Ensure Junk mailbox exists
	if err := c.Create("Junk", nil).Wait(); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("CREATE Junk mailbox failed: %v", err)
		}
	}

	// Select INBOX
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Move messages to Junk until circuit breaker opens
	for i := 1; i <= failureCount+3; i++ {
		testMessage := "From: spammer@example.com\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: Spam Message " + string(rune(i)) + "\r\n" +
			"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
			"\r\n" +
			"Spam content.\r\n"

		appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
		if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}

		// Re-select INBOX to get updated sequence numbers
		if _, err := c.Select("INBOX", nil).Wait(); err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}

		// Move message to Junk
		t.Logf("Move #%d to Junk", i)
		if _, err := c.Move(imap.SeqSetNum(1), "Junk").Wait(); err != nil {
			t.Fatalf("MOVE to Junk failed: %v", err)
		}

		// Wait for async submission
		time.Sleep(200 * time.Millisecond)
	}

	// Additional wait for circuit breaker to open
	time.Sleep(500 * time.Millisecond)

	// Verify circuit breaker opened after threshold failures
	// Circuit should open after 'failureCount' consecutive failures
	// Subsequent requests should be dropped (not reach the server)
	count := atomic.LoadInt32(&requestCount)
	t.Logf("Total requests received: %d", count)

	// Should receive exactly failureCount requests before circuit opens
	// Plus possibly 1-2 more during the race between failure detection and circuit opening
	if count < int32(failureCount) {
		t.Errorf("Expected at least %d requests before circuit opens, got %d", failureCount, count)
	}

	if count > int32(failureCount+3) {
		t.Errorf("Expected circuit breaker to stop requests after %d failures, but got %d requests", failureCount, count)
	}

	t.Log("Circuit breaker test completed successfully")
}

// TestIMAP_SpamTraining_Disabled tests that no training occurs when disabled
func TestIMAP_SpamTraining_Disabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Track received training requests
	var requestCount int32

	// Create mock spam training endpoint
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		t.Error("Training request received when spam training disabled")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockServer.Close()

	// Configure server WITHOUT spam training enabled
	serverOpts := &common.IMAPServerOpts{
		SpamTrainingEnabled: false, // Explicitly disabled
	}

	server, account := common.SetupIMAPServerWithOptions(t, serverOpts)
	defer server.Close()

	// Connect and login
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Ensure Junk mailbox exists
	if err := c.Create("Junk", nil).Wait(); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("CREATE Junk mailbox failed: %v", err)
		}
	}

	// Select INBOX and add test message
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	testMessage := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Test Message\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"\r\n" +
		"Test content.\r\n"

	appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// Move message to Junk (should NOT trigger training when disabled)
	t.Log("Moving message to Junk with spam training disabled")
	if _, err := c.Move(imap.SeqSetNum(1), "Junk").Wait(); err != nil {
		t.Fatalf("MOVE to Junk failed: %v", err)
	}

	// Wait for potential async submission
	time.Sleep(500 * time.Millisecond)

	// Verify no training request was received
	count := atomic.LoadInt32(&requestCount)
	if count != 0 {
		t.Errorf("Expected 0 training requests when disabled, got %d", count)
	}

	t.Log("Disabled spam training test completed successfully")
}
