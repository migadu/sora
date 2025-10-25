//go:build integration

package imap_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_FetchBodySections tests that all BODY section types are served correctly.
// This is a regression test for the bug where BODY[TEXT] was returning 0 bytes
// for messages with encoded text parts.
func TestIMAP_FetchBodySections(t *testing.T) {
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

	// Select INBOX
	_, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Test Case 1: Simple single-part message with quoted-printable encoding
	t.Run("SinglePartQuotedPrintable", func(t *testing.T) {
		msg := "From: sender@example.com\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: Test QP Message\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"Content-Transfer-Encoding: quoted-printable\r\n" +
			"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
			"\r\n" +
			"Hello=20World=21\r\n" +
			"This is a test message with quoted-printable encoding.\r\n"

		uid := appendMessage(t, c, msg)

		// Fetch BODY[HEADER]
		header := fetchBodySection(t, c, uid, &imap.FetchItemBodySection{
			Specifier: imap.PartSpecifierHeader,
		})
		if !strings.Contains(string(header), "Subject: Test QP Message") {
			t.Errorf("BODY[HEADER] missing expected subject")
		}
		if !strings.HasSuffix(string(header), "\r\n\r\n") {
			t.Errorf("BODY[HEADER] should end with CRLF CRLF, got: %q", string(header[len(header)-4:]))
		}

		// Fetch BODY[TEXT] - should return the RAW encoded body
		text := fetchBodySection(t, c, uid, &imap.FetchItemBodySection{
			Specifier: imap.PartSpecifierText,
		})
		if len(text) == 0 {
			t.Fatalf("BODY[TEXT] returned 0 bytes - this is the bug we're testing!")
		}
		if !bytes.Contains(text, []byte("Hello=20World=21")) {
			t.Errorf("BODY[TEXT] should contain encoded text 'Hello=20World=21', got: %q", string(text))
		}
		// The decoded version would be "Hello World!" but we want the encoded version
		if bytes.Contains(text, []byte("Hello World!")) {
			t.Errorf("BODY[TEXT] should NOT contain decoded text 'Hello World!' - it should be encoded")
		}

		// Fetch BODY[] - should return the full message
		full := fetchBodySection(t, c, uid, &imap.FetchItemBodySection{
			Specifier: imap.PartSpecifierNone,
		})
		if len(full) == 0 {
			t.Fatalf("BODY[] returned 0 bytes")
		}
		if !bytes.Contains(full, []byte("Subject: Test QP Message")) {
			t.Errorf("BODY[] should contain headers")
		}
		if !bytes.Contains(full, []byte("Hello=20World=21")) {
			t.Errorf("BODY[] should contain body")
		}
	})

	// Test Case 2: Multipart message with base64 encoded text/plain
	t.Run("MultipartWithBase64", func(t *testing.T) {
		msg := "From: sender@example.com\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: Test Multipart Message\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: multipart/alternative; boundary=\"boundary123\"\r\n" +
			"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
			"\r\n" +
			"--boundary123\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"Content-Transfer-Encoding: base64\r\n" +
			"\r\n" +
			"SGVsbG8gV29ybGQh\r\n" +
			"--boundary123\r\n" +
			"Content-Type: text/html; charset=utf-8\r\n" +
			"\r\n" +
			"<html><body>Hello World!</body></html>\r\n" +
			"--boundary123--\r\n"

		uid := appendMessage(t, c, msg)

		// Fetch BODY[TEXT] - for multipart, this is everything after the main headers
		text := fetchBodySection(t, c, uid, &imap.FetchItemBodySection{
			Specifier: imap.PartSpecifierText,
		})
		if len(text) == 0 {
			t.Fatalf("BODY[TEXT] returned 0 bytes for multipart message")
		}
		// Should contain the MIME structure with boundaries
		if !bytes.Contains(text, []byte("--boundary123")) {
			t.Errorf("BODY[TEXT] should contain boundary markers for multipart, got: %q", string(text))
		}
		// Should contain the base64 encoded content
		if !bytes.Contains(text, []byte("SGVsbG8gV29ybGQh")) {
			t.Errorf("BODY[TEXT] should contain base64 encoded 'SGVsbG8gV29ybGQh', got: %q", string(text))
		}
		// Should NOT be decoded to "Hello World!"
		if bytes.Contains(text, []byte("Hello World!")) && !bytes.Contains(text, []byte("<html>")) {
			// The HTML part has "Hello World!" which is OK, but the plain text part should be encoded
			plainTextSection := text
			if idx := bytes.Index(text, []byte("--boundary123")); idx >= 0 {
				if idx2 := bytes.Index(text[idx+13:], []byte("--boundary123")); idx2 >= 0 {
					plainTextSection = text[idx : idx+13+idx2]
				}
			}
			if bytes.Contains(plainTextSection, []byte("Hello World!")) && !bytes.Contains(plainTextSection, []byte("SGVsbG8gV29ybGQh")) {
				t.Errorf("BODY[TEXT] plain text part should NOT be decoded")
			}
		}

		// Fetch BODY[1] - first part body only (text/plain with base64)
		part1 := fetchBodySection(t, c, uid, &imap.FetchItemBodySection{
			Specifier: imap.PartSpecifierNone,
			Part:      []int{1},
		})
		if len(part1) == 0 {
			t.Fatalf("BODY[1] returned 0 bytes")
		}
		// For BODY[1] without specifier, only the body is returned (no part headers)
		// Should NOT include part headers
		if bytes.Contains(part1, []byte("Content-Type:")) {
			t.Errorf("BODY[1] should NOT contain headers (that's BODY[1.HEADER] or BODY[1.MIME])")
		}
		// Should contain base64 encoded content
		if !bytes.Contains(part1, []byte("SGVsbG8gV29ybGQh")) {
			t.Errorf("BODY[1] should contain base64 content, got: %q", string(part1))
		}

		// Fetch BODY[1.TEXT] - just the body of the first part (still encoded)
		part1Text := fetchBodySection(t, c, uid, &imap.FetchItemBodySection{
			Specifier: imap.PartSpecifierText,
			Part:      []int{1},
		})
		if len(part1Text) == 0 {
			t.Fatalf("BODY[1.TEXT] returned 0 bytes")
		}
		// Should NOT include headers
		if bytes.Contains(part1Text, []byte("Content-Type:")) {
			t.Errorf("BODY[1.TEXT] should NOT contain headers")
		}
		// Should still be base64 encoded
		if !bytes.Contains(part1Text, []byte("SGVsbG8gV29ybGQh")) {
			t.Errorf("BODY[1.TEXT] should contain base64 content")
		}

		// Fetch BODY[2] - second part (text/html)
		part2 := fetchBodySection(t, c, uid, &imap.FetchItemBodySection{
			Specifier: imap.PartSpecifierNone,
			Part:      []int{2},
		})
		if len(part2) == 0 {
			t.Fatalf("BODY[2] returned 0 bytes")
		}
		if !bytes.Contains(part2, []byte("<html>")) {
			t.Errorf("BODY[2] should contain HTML content")
		}
	})

	// Test Case 3: BODY[HEADER.FIELDS (...)]
	t.Run("HeaderFields", func(t *testing.T) {
		msg := "From: sender@example.com\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: Test Header Fields\r\n" +
			"X-Custom: CustomValue\r\n" +
			"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
			"\r\n" +
			"Body content\r\n"

		uid := appendMessage(t, c, msg)

		// Fetch specific header fields
		headerFields := fetchBodySection(t, c, uid, &imap.FetchItemBodySection{
			Specifier:    imap.PartSpecifierHeader,
			HeaderFields: []string{"Subject", "From"},
		})
		if len(headerFields) == 0 {
			t.Fatalf("BODY[HEADER.FIELDS (Subject From)] returned 0 bytes")
		}
		if !bytes.Contains(headerFields, []byte("Subject: Test Header Fields")) {
			t.Errorf("Should contain Subject header")
		}
		if !bytes.Contains(headerFields, []byte("From: sender@example.com")) {
			t.Errorf("Should contain From header")
		}
		// Should NOT contain other headers
		if bytes.Contains(headerFields, []byte("X-Custom:")) {
			t.Errorf("Should NOT contain X-Custom header")
		}
		if bytes.Contains(headerFields, []byte("To:")) {
			t.Errorf("Should NOT contain To header")
		}
	})

	// Test Case 4: BODY.PEEK to ensure no \Seen flag is set
	t.Run("PeekNoSeenFlag", func(t *testing.T) {
		msg := "From: sender@example.com\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: Test Peek\r\n" +
			"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
			"\r\n" +
			"Body\r\n"

		uid := appendMessage(t, c, msg)

		// Verify message doesn't have \Seen flag initially
		flags := fetchFlags(t, c, uid)
		if containsFlag(flags, imap.FlagSeen) {
			t.Fatalf("Message should not have \\Seen flag initially")
		}

		// Fetch with PEEK
		_ = fetchBodySection(t, c, uid, &imap.FetchItemBodySection{
			Specifier: imap.PartSpecifierText,
			Peek:      true,
		})

		// Verify \Seen flag is still not set
		flags = fetchFlags(t, c, uid)
		if containsFlag(flags, imap.FlagSeen) {
			t.Errorf("BODY.PEEK should not set \\Seen flag")
		}

		// Fetch without PEEK
		_ = fetchBodySection(t, c, uid, &imap.FetchItemBodySection{
			Specifier: imap.PartSpecifierText,
			Peek:      false,
		})

		// Verify \Seen flag is now set
		flags = fetchFlags(t, c, uid)
		if !containsFlag(flags, imap.FlagSeen) {
			t.Errorf("BODY[TEXT] without PEEK should set \\Seen flag")
		}
	})
}

// appendMessage appends a message and returns its UID
func appendMessage(t *testing.T, c *imapclient.Client, msg string) imap.UID {
	t.Helper()
	appendCmd := c.Append("INBOX", int64(len(msg)), &imap.AppendOptions{
		Time: time.Now(),
	})
	_, err := appendCmd.Write([]byte(msg))
	if err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}
	return appendData.UID
}

// fetchBodySection fetches a specific body section and returns its content
func fetchBodySection(t *testing.T, c *imapclient.Client, uid imap.UID, section *imap.FetchItemBodySection) []byte {
	t.Helper()
	fetchCmd := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{section},
	})
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}

	msg := msgs[0]
	// Use the convenience method to find the body section
	data := msg.FindBodySection(section)
	if data == nil {
		t.Fatalf("Body section not found in response")
	}
	return data
}

// fetchFlags fetches the flags for a message
func fetchFlags(t *testing.T, c *imapclient.Client, uid imap.UID) []imap.Flag {
	t.Helper()
	fetchCmd := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{
		UID:   true,
		Flags: true,
	})
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH flags failed: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}
	return msgs[0].Flags
}
