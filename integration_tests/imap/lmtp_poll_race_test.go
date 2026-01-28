//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// deliverViaLMTP is a helper that delivers a message via LMTP protocol
func deliverViaLMTP(t *testing.T, lmtpAddr, from, to, subject, body string) error {
	t.Helper()

	conn, err := net.DialTimeout("tcp", lmtpAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read greeting: %w", err)
	}
	if !strings.HasPrefix(line, "220") {
		return fmt.Errorf("unexpected greeting: %s", line)
	}

	// LHLO
	if _, err := conn.Write([]byte("LHLO test\r\n")); err != nil {
		return err
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// MAIL FROM
	if _, err := conn.Write([]byte(fmt.Sprintf("MAIL FROM:<%s>\r\n", from))); err != nil {
		return err
	}
	if _, err := reader.ReadString('\n'); err != nil {
		return err
	}

	// RCPT TO
	if _, err := conn.Write([]byte(fmt.Sprintf("RCPT TO:<%s>\r\n", to))); err != nil {
		return err
	}
	if _, err := reader.ReadString('\n'); err != nil {
		return err
	}

	// DATA
	if _, err := conn.Write([]byte("DATA\r\n")); err != nil {
		return err
	}
	if _, err := reader.ReadString('\n'); err != nil {
		return err
	}

	// Message
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\n\r\n%s\r\n.\r\n",
		from, to, subject, time.Now().Format(time.RFC1123Z), body)
	if _, err := conn.Write([]byte(message)); err != nil {
		return err
	}
	if _, err := reader.ReadString('\n'); err != nil {
		return err
	}

	// QUIT
	conn.Write([]byte("QUIT\r\n"))
	return nil
}

// TestIMAP_LMTPPollRaceCondition tests that messages delivered via LMTP
// are properly visible to IMAP clients via Poll, even under race conditions.
// This reproduces the bug where Poll could return seq_num=0 for newly inserted
// messages if the query ran between INSERT and the sequence trigger completing.
//
// NOTE: The race window is very small (microseconds) and happens within a single
// transaction, so this test may not always reproduce the bug even without the fix.
// However, in production with high concurrency and READ COMMITTED isolation, the
// race is more likely. The test serves as a regression test to ensure the fix
// (filtering ms.seqnum IS NOT NULL) stays in place.
func TestIMAP_LMTPPollRaceCondition(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup both IMAP and LMTP servers
	imapServer, imapAccount := common.SetupIMAPServer(t)
	defer imapServer.Close()

	lmtpServer, _ := common.SetupLMTPServer(t)
	defer lmtpServer.Close()

	// Use the same account email for both
	accountEmail := imapAccount.Email

	// Connect IMAP client and SELECT INBOX
	client, err := imapclient.DialInsecure(imapServer.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP: %v", err)
	}
	defer client.Logout()

	if err := client.Login(accountEmail, imapAccount.Password).Wait(); err != nil {
		t.Fatalf("IMAP login failed: %v", err)
	}

	selectData, err := client.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	initialCount := selectData.NumMessages
	t.Logf("Initial message count: %d", initialCount)

	// Deliver multiple messages rapidly via LMTP to increase chance of catching race
	numMessages := 5
	for i := 1; i <= numMessages; i++ {
		from := fmt.Sprintf("sender%d@example.com", i)
		subject := fmt.Sprintf("LMTP Test Message %d", i)
		body := fmt.Sprintf("This is test message %d delivered via LMTP.", i)

		if err := deliverViaLMTP(t, lmtpServer.Address, from, accountEmail, subject, body); err != nil {
			t.Fatalf("Failed to deliver message %d: %v", i, err)
		}

		t.Logf("Delivered message %d/%d via LMTP", i, numMessages)

		// Immediately poll IMAP to try to catch the race condition
		// where message_sequences might not be populated yet
		if err := client.Noop().Wait(); err != nil {
			t.Fatalf("NOOP failed after message %d: %v", i, err)
		}
	}

	// Wait a bit for all deliveries to settle
	time.Sleep(200 * time.Millisecond)

	// Final poll to ensure all messages are visible
	if err := client.Noop().Wait(); err != nil {
		t.Fatalf("Final NOOP failed: %v", err)
	}

	// Verify all messages are now visible
	finalSelectData, err := client.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Final SELECT failed: %v", err)
	}

	expectedCount := initialCount + uint32(numMessages)
	if finalSelectData.NumMessages != expectedCount {
		t.Errorf("Expected %d messages, got %d", expectedCount, finalSelectData.NumMessages)
	}

	// Fetch all messages to verify they have valid sequence numbers and UIDs
	// This is the critical test - before the fix, some messages might have
	// seq_num=0 in Poll response, causing them to appear empty
	if expectedCount == 0 {
		t.Log("No messages to fetch")
		return
	}

	seqSet := imap.SeqSet{}
	seqSet.AddRange(1, expectedCount)

	fetchResults, err := client.Fetch(seqSet, &imap.FetchOptions{
		UID:      true,
		Envelope: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}

	if len(fetchResults) != int(expectedCount) {
		t.Errorf("Expected %d fetch results, got %d", expectedCount, len(fetchResults))
	}

	// Verify each message has valid seq and UID
	seenSeqs := make(map[uint32]bool)
	seenUIDs := make(map[imap.UID]bool)
	emptyCount := 0

	for _, result := range fetchResults {
		// Check for invalid sequence number (0 or duplicate)
		if result.SeqNum == 0 {
			t.Errorf("Message has invalid sequence number 0 (UID: %d)", result.UID)
		}
		if seenSeqs[result.SeqNum] {
			t.Errorf("Duplicate sequence number %d", result.SeqNum)
		}
		seenSeqs[result.SeqNum] = true

		// Check for invalid UID (0 or duplicate)
		if result.UID == 0 {
			t.Errorf("Message has invalid UID 0 (seq: %d)", result.SeqNum)
		}
		if seenUIDs[result.UID] {
			t.Errorf("Duplicate UID %d", result.UID)
		}
		seenUIDs[result.UID] = true

		// Verify envelope is present (message not "empty")
		if result.Envelope == nil {
			t.Errorf("Message seq=%d UID=%d has nil Envelope (appears empty)", result.SeqNum, result.UID)
			emptyCount++
		} else {
			// Check that it's one of our test messages
			if strings.HasPrefix(result.Envelope.Subject, "LMTP Test Message") {
				t.Logf("✓ Found test message: %s (seq=%d, UID=%d)", result.Envelope.Subject, result.SeqNum, result.UID)
			}
		}
	}

	if emptyCount > 0 {
		t.Errorf("Found %d empty messages (race condition bug!)", emptyCount)
	}

	t.Logf("✓ All %d messages have valid sequence numbers and UIDs", expectedCount)
	t.Logf("✓ No empty messages detected (race condition handled correctly)")
}
