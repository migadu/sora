//go:build integration

package imap_test

import (
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_MalformedMessage tests that FETCH operations handle corrupted messages gracefully
// rather than failing completely. This prevents one corrupted message from blocking access
// to an entire mailbox.
func TestIMAP_MalformedMessage(t *testing.T) {
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

	t.Run("FETCH with malformed MIME header", func(t *testing.T) {
		// SELECT INBOX first so client tracks messages properly
		if _, err := c.Select("INBOX", nil).Wait(); err != nil {
			t.Fatalf("SELECT INBOX failed: %v", err)
		}

		// Append a valid message first
		validMsg := "From: sender@example.com\r\n" +
			"To: recipient@example.com\r\n" +
			"Subject: Valid Message\r\n" +
			"Content-Type: text/plain\r\n" +
			"\r\n" +
			"This is a valid message.\r\n"

		appendCmd := c.Append("INBOX", int64(len(validMsg)), &imap.AppendOptions{
			Flags: []imap.Flag{imap.FlagSeen},
		})
		if _, err := appendCmd.Write([]byte(validMsg)); err != nil {
			t.Fatalf("Failed to write valid message: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND valid message failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND wait failed: %v", err)
		}

		// Append a message with malformed MIME headers
		// This simulates the kind of corruption seen in production logs
		malformedMsg := "From: sender@example.com\r\n" +
			"To: recipient@example.com\r\n" +
			"Subject?\r\n" + // Invalid - missing colon after header name
			"Content-Type: text/plain\r\n" +
			"\r\n" +
			"This message has a malformed header.\r\n"

		appendCmd2 := c.Append("INBOX", int64(len(malformedMsg)), &imap.AppendOptions{
			Flags: []imap.Flag{imap.FlagSeen},
		})
		if _, err := appendCmd2.Write([]byte(malformedMsg)); err != nil {
			t.Fatalf("Failed to write malformed message: %v", err)
		}
		if err := appendCmd2.Close(); err != nil {
			t.Fatalf("APPEND malformed message failed: %v", err)
		}
		if _, err := appendCmd2.Wait(); err != nil {
			t.Fatalf("APPEND wait failed: %v", err)
		}

		// Append another valid message
		validMsg2 := "From: sender2@example.com\r\n" +
			"To: recipient@example.com\r\n" +
			"Subject: Second Valid Message\r\n" +
			"Content-Type: text/plain\r\n" +
			"\r\n" +
			"This is another valid message.\r\n"

		appendCmd3 := c.Append("INBOX", int64(len(validMsg2)), &imap.AppendOptions{
			Flags: []imap.Flag{imap.FlagSeen},
		})
		if _, err := appendCmd3.Write([]byte(validMsg2)); err != nil {
			t.Fatalf("Failed to write second valid message: %v", err)
		}
		if err := appendCmd3.Close(); err != nil {
			t.Fatalf("APPEND second valid message failed: %v", err)
		}
		if _, err := appendCmd3.Wait(); err != nil {
			t.Fatalf("APPEND wait failed: %v", err)
		}

		// FETCH all messages - use a UID range (1:3) not individual UIDs
		uidSet := imap.UIDSet{imap.UIDRange{Start: 1, Stop: 3}}
		fetchCmd := c.Fetch(uidSet, &imap.FetchOptions{
			Flags:       true,
			UID:         true,
			BodySection: []*imap.FetchItemBodySection{{Specifier: imap.PartSpecifierNone}},
		})

		msgs, err := fetchCmd.Collect()
		if err != nil {
			t.Fatalf("FETCH failed: %v", err)
		}

		// Verify we received all 3 messages
		if len(msgs) != 3 {
			t.Errorf("Expected to receive 3 messages, got %d", len(msgs))
		}

		// Check that all messages have body content (even if it's an error message for malformed)
		for i, msg := range msgs {
			t.Logf("Received message %d with UID %d", msg.SeqNum, msg.UID)
			if len(msg.BodySection) == 0 {
				t.Errorf("Message %d: Expected body section, got none", i+1)
			}
			for _, content := range msg.BodySection {
				if len(content.Bytes) == 0 {
					t.Errorf("Message %d: Expected non-empty body section", i+1)
				}
				t.Logf("Message %d body section: %d bytes", i+1, len(content.Bytes))
			}
		}

		t.Log("Successfully handled FETCH with malformed message present")
	})

	t.Run("FETCH multiple corrupted messages", func(t *testing.T) {
		// Create a new mailbox for this test
		if err := c.Create("CorruptTest", nil).Wait(); err != nil {
			t.Fatalf("CREATE failed: %v", err)
		}

		// Append multiple malformed messages
		for i := 0; i < 5; i++ {
			malformedMsg := "From: sender@example.com\r\n" +
				"To: recipient@example.com\r\n" +
				"Subject" + string(rune('?'+i)) + "\r\n" + // Different malformations
				"Content-Type: text/plain\r\n" +
				"\r\n" +
				"Corrupted message body.\r\n"

			appendCmd := c.Append("CorruptTest", int64(len(malformedMsg)), nil)
			if _, err := appendCmd.Write([]byte(malformedMsg)); err != nil {
				t.Fatalf("Failed to write malformed message %d: %v", i, err)
			}
			if err := appendCmd.Close(); err != nil {
				t.Fatalf("APPEND malformed message %d failed: %v", i, err)
			}
			if _, err := appendCmd.Wait(); err != nil {
				t.Fatalf("APPEND wait failed: %v", err)
			}
		}

		// Select the test mailbox
		selectData, err := c.Select("CorruptTest", nil).Wait()
		if err != nil {
			t.Fatalf("SELECT failed: %v", err)
		}

		if selectData.NumMessages != 5 {
			t.Fatalf("Expected 5 messages, got %d", selectData.NumMessages)
		}

		// FETCH all using UID FETCH - use a UID range (1:5) not individual UIDs
		uidSet := imap.UIDSet{imap.UIDRange{Start: 1, Stop: 5}}
		fetchCmd := c.Fetch(uidSet, &imap.FetchOptions{
			BodySection: []*imap.FetchItemBodySection{{Specifier: imap.PartSpecifierNone}},
		})

		msgs, err := fetchCmd.Collect()
		if err != nil {
			t.Fatalf("FETCH failed: %v", err)
		}

		if len(msgs) != 5 {
			t.Errorf("Expected to receive 5 messages, got %d", len(msgs))
		}

		t.Log("Successfully handled FETCH with multiple corrupted messages")
	})

	t.Run("APPEND message with NULL bytes in body", func(t *testing.T) {
		// Create a new mailbox for this test
		if err := c.Create("NullByteTest", nil).Wait(); err != nil {
			t.Fatalf("CREATE failed: %v", err)
		}

		// Select the mailbox
		if _, err := c.Select("NullByteTest", nil).Wait(); err != nil {
			t.Fatalf("SELECT failed: %v", err)
		}

		// Append a message with NULL bytes in the body
		// This simulates binary data or corrupted messages seen in production
		msgWithNullBytes := "From: sender@example.com\r\n" +
			"To: recipient@example.com\r\n" +
			"Subject: Message with NULL bytes\r\n" +
			"Content-Type: text/plain\r\n" +
			"\r\n" +
			"This message has NULL bytes:\x00\x00 embedded in the body.\r\n" +
			"PostgreSQL should not reject this.\x00\r\n"

		appendCmd := c.Append("NullByteTest", int64(len(msgWithNullBytes)), nil)
		if _, err := appendCmd.Write([]byte(msgWithNullBytes)); err != nil {
			t.Fatalf("Failed to write message with NULL bytes: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND message with NULL bytes failed: %v", err)
		}
		appendData, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND wait failed: %v", err)
		}

		if appendData.UID == 0 {
			t.Fatal("APPEND should return non-zero UID")
		}

		t.Logf("Successfully appended message with NULL bytes, UID=%d", appendData.UID)

		// FETCH the message to verify it was stored
		uidSet := imap.UIDSet{imap.UIDRange{Start: appendData.UID, Stop: appendData.UID}}
		fetchCmd := c.Fetch(uidSet, &imap.FetchOptions{
			UID:         true,
			BodySection: []*imap.FetchItemBodySection{{Specifier: imap.PartSpecifierNone}},
		})

		msgs, err := fetchCmd.Collect()
		if err != nil {
			t.Fatalf("FETCH failed: %v", err)
		}

		if len(msgs) != 1 {
			t.Fatalf("Expected 1 message, got %d", len(msgs))
		}

		if len(msgs[0].BodySection) == 0 {
			t.Fatal("Expected body section, got none")
		}

		// Verify the body was stored and retrieved
		for _, content := range msgs[0].BodySection {
			if len(content.Bytes) == 0 {
				t.Fatal("Expected non-empty body section")
			}
			t.Logf("Retrieved message body: %d bytes", len(content.Bytes))

			// NULL bytes should have been removed by SanitizeUTF8
			// Note: We can't directly verify NULL bytes were removed from the database
			// since the original message bytes are stored in S3, but the text search
			// content in PostgreSQL should have NULL bytes removed
		}

		t.Log("Successfully stored and retrieved message with NULL bytes")
	})

	t.Run("APPEND message with NULL bytes in headers", func(t *testing.T) {
		// Select the test mailbox
		if _, err := c.Select("NullByteTest", nil).Wait(); err != nil {
			t.Fatalf("SELECT failed: %v", err)
		}

		// Append a message with NULL bytes in headers
		// This is more problematic as headers are stored in PostgreSQL text columns
		msgWithNullInHeaders := "From: sender@example.com\x00\r\n" +
			"To: recipient@example.com\r\n" +
			"Subject: Test\x00Subject\r\n" +
			"Content-Type: text/plain\r\n" +
			"\r\n" +
			"Body content.\r\n"

		appendCmd := c.Append("NullByteTest", int64(len(msgWithNullInHeaders)), nil)
		if _, err := appendCmd.Write([]byte(msgWithNullInHeaders)); err != nil {
			t.Fatalf("Failed to write message: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
		appendData, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND wait failed: %v", err)
		}

		t.Logf("Successfully appended message with NULL bytes in headers, UID=%d", appendData.UID)

		// FETCH the message to verify it was stored despite NULL bytes in headers
		// This is the critical test - the APPEND should have succeeded
		uidSet := imap.UIDSet{imap.UIDRange{Start: appendData.UID, Stop: appendData.UID}}
		fetchCmd := c.Fetch(uidSet, &imap.FetchOptions{
			UID:         true,
			BodySection: []*imap.FetchItemBodySection{{Specifier: imap.PartSpecifierNone}},
		})

		msgs, err := fetchCmd.Collect()
		if err != nil {
			t.Fatalf("FETCH failed: %v", err)
		}

		if len(msgs) != 1 {
			t.Fatalf("Expected 1 message, got %d", len(msgs))
		}

		if len(msgs[0].BodySection) == 0 {
			t.Fatal("Expected body section, got none")
		}

		t.Log("Successfully stored and retrieved message with NULL bytes in headers")
	})
}
