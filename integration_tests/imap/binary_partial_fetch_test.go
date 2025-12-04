//go:build integration

package imap_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_BinaryPartialFetch tests BINARY with partial range fetches
// This mirrors imaptest fetch-binary-mime-base64 which tests:
// - binary.peek[5]<0.7> - Fetch bytes 0-7
// - binary.peek[5]<10.10> - Fetch bytes 10-20
func TestIMAP_BinaryPartialFetch(t *testing.T) {
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

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Create a multipart message similar to imaptest's test
	// Part 1: Plain text
	// Part 2-4: Various text parts
	// Part 5: Base64-encoded binary content (the part imaptest fetches)

	// The base64-encoded content will decode to a known string
	// imaptest uses: "abcdefghijklmnop" (16 bytes)
	binaryData := []byte("abcdefghijklmnop")
	encodedData := base64.StdEncoding.EncodeToString(binaryData)

	rawMessage := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Binary Partial Fetch Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"boundary123\"\r\n" +
		"\r\n" +
		"--boundary123\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Part 1\r\n" +
		"--boundary123\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Part 2\r\n" +
		"--boundary123\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Part 3\r\n" +
		"--boundary123\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Part 4\r\n" +
		"--boundary123\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		encodedData + "\r\n" +
		"--boundary123--\r\n"

	appendCmd := c.Append("INBOX", int64(len(rawMessage)), nil)
	if _, err := appendCmd.Write([]byte(rawMessage)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	t.Log("=== Test 1: BINARY[5]<0.7> - Fetch first 7 bytes ===")
	// Test partial fetch: first 7 bytes (bytes 0-6)
	// Expected: "abcdefg"
	fetchCmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{
			{
				Part: []int{5},
				Partial: &imap.SectionPartial{
					Offset: 0,
					Size:   7,
				},
			},
		},
	})

	var binaryContent []byte
	var foundBinary bool

	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if binaryItem, ok := item.(imapclient.FetchItemDataBinarySection); ok {
				foundBinary = true
				if binaryItem.Section.Partial != nil {
					t.Logf("BINARY section: part=%v, offset=%d, size=%d",
						binaryItem.Section.Part, binaryItem.Section.Partial.Offset, binaryItem.Section.Partial.Size)
				} else {
					t.Logf("BINARY section: part=%v (no partial)", binaryItem.Section.Part)
				}

				buf := new(bytes.Buffer)
				io.Copy(buf, binaryItem.Literal)
				binaryContent = buf.Bytes()
				t.Logf("BINARY content: %q (length: %d)", string(binaryContent), len(binaryContent))
			}
		}
	}
	fetchCmd.Close()

	if !foundBinary {
		t.Error("BINARY section not found in response")
	}

	// Verify we got exactly 7 bytes
	if len(binaryContent) != 7 {
		t.Errorf("Expected 7 bytes, got %d", len(binaryContent))
	}

	// Verify content is correct
	expectedContent := "abcdefg"
	if string(binaryContent) != expectedContent {
		t.Errorf("Expected content %q, got %q", expectedContent, string(binaryContent))
	}

	t.Log("=== Test 2: BINARY[5]<10.6> - Fetch 6 bytes starting at offset 10 ===")
	// Test partial fetch: 6 bytes starting at offset 10
	// Expected: "klmnop" (bytes 10-15)
	fetchCmd = c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{
			{
				Part: []int{5},
				Partial: &imap.SectionPartial{
					Offset: 10,
					Size:   6,
				},
			},
		},
	})

	binaryContent = nil
	foundBinary = false

	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if binaryItem, ok := item.(imapclient.FetchItemDataBinarySection); ok {
				foundBinary = true
				if binaryItem.Section.Partial != nil {
					t.Logf("BINARY section: part=%v, offset=%d, size=%d",
						binaryItem.Section.Part, binaryItem.Section.Partial.Offset, binaryItem.Section.Partial.Size)
				} else {
					t.Logf("BINARY section: part=%v (no partial)", binaryItem.Section.Part)
				}

				buf := new(bytes.Buffer)
				io.Copy(buf, binaryItem.Literal)
				binaryContent = buf.Bytes()
				t.Logf("BINARY content: %q (length: %d)", string(binaryContent), len(binaryContent))
			}
		}
	}
	fetchCmd.Close()

	if !foundBinary {
		t.Error("BINARY section not found in response")
	}

	// Verify we got exactly 6 bytes
	if len(binaryContent) != 6 {
		t.Errorf("Expected 6 bytes, got %d", len(binaryContent))
	}

	// Verify content is correct
	expectedContent = "klmnop"
	if string(binaryContent) != expectedContent {
		t.Errorf("Expected content %q, got %q", expectedContent, string(binaryContent))
	}

	t.Log("=== Test 3: BINARY[5]<0.20> - Fetch beyond end (request more than available) ===")
	// Test partial fetch: request 20 bytes but only 16 exist
	// Should return all 16 bytes
	fetchCmd = c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{
			{
				Part: []int{5},
				Partial: &imap.SectionPartial{
					Offset: 0,
					Size:   20,
				},
			},
		},
	})

	binaryContent = nil
	foundBinary = false

	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if binaryItem, ok := item.(imapclient.FetchItemDataBinarySection); ok {
				foundBinary = true

				buf := new(bytes.Buffer)
				io.Copy(buf, binaryItem.Literal)
				binaryContent = buf.Bytes()
				t.Logf("BINARY content: %q (length: %d)", string(binaryContent), len(binaryContent))
			}
		}
	}
	fetchCmd.Close()

	if !foundBinary {
		t.Error("BINARY section not found in response")
	}

	// Should return all 16 bytes (the full content)
	if len(binaryContent) != 16 {
		t.Errorf("Expected 16 bytes (all available), got %d", len(binaryContent))
	}

	expectedContent = "abcdefghijklmnop"
	if string(binaryContent) != expectedContent {
		t.Errorf("Expected full content %q, got %q", expectedContent, string(binaryContent))
	}

	t.Log("✅ All BINARY partial fetch tests passed")
}

// TestIMAP_BinaryPartialFetchQuotedPrintable tests BINARY partial fetch with quoted-printable
func TestIMAP_BinaryPartialFetchQuotedPrintable(t *testing.T) {
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

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Create message with quoted-printable content
	// QP: "hello  \r\nbar=\r\n\r\nfoo\t=\r\nbar\r\n..."
	// Decoded: Should preserve certain whitespace, strip others
	qpContent := "hello  \r\n" +
		"bar=\r\n" + // soft break
		"\r\n" +
		"foo\t=\r\n" + // soft break with tab
		"bar\r\n" +
		"test\r\n"

	rawMessage := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Binary QP Partial Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"boundary123\"\r\n" +
		"\r\n" +
		"--boundary123\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" +
		qpContent +
		"--boundary123--\r\n"

	appendCmd := c.Append("INBOX", int64(len(rawMessage)), nil)
	if _, err := appendCmd.Write([]byte(rawMessage)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	t.Log("=== Test: BINARY[1]<0.10> - Partial fetch of QP-encoded part ===")

	// First, fetch the full decoded content to see what we're working with
	fetchFullCmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{
			{Part: []int{1}},
		},
	})

	var fullContent []byte
	for {
		msg := fetchFullCmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if binaryItem, ok := item.(imapclient.FetchItemDataBinarySection); ok {
				buf := new(bytes.Buffer)
				io.Copy(buf, binaryItem.Literal)
				fullContent = buf.Bytes()
				t.Logf("Full decoded content: %q (length: %d)", string(fullContent), len(fullContent))
			}
		}
	}
	fetchFullCmd.Close()

	// Now fetch partial: first 10 bytes
	fetchCmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{
			{
				Part: []int{1},
				Partial: &imap.SectionPartial{
					Offset: 0,
					Size:   10,
				},
			},
		},
	})

	var binaryContent []byte
	var foundBinary bool

	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if binaryItem, ok := item.(imapclient.FetchItemDataBinarySection); ok {
				foundBinary = true

				buf := new(bytes.Buffer)
				io.Copy(buf, binaryItem.Literal)
				binaryContent = buf.Bytes()
				t.Logf("Partial content (0-10): %q (length: %d)", string(binaryContent), len(binaryContent))
			}
		}
	}
	fetchCmd.Close()

	if !foundBinary {
		t.Error("BINARY section not found in response")
	}

	// Verify we got exactly 10 bytes
	if len(binaryContent) != 10 {
		t.Errorf("Expected 10 bytes, got %d", len(binaryContent))
	}

	// Verify it matches the first 10 bytes of the full decoded content
	if len(fullContent) >= 10 {
		expectedPartial := string(fullContent[:10])
		if string(binaryContent) != expectedPartial {
			t.Errorf("Partial fetch mismatch. Expected %q, got %q",
				expectedPartial, string(binaryContent))
		}
	}

	t.Log("✅ BINARY QP partial fetch test passed")
}

// TestIMAP_BinaryPartialFetchResponseFormat tests that BINARY partial responses
// include the correct offset marker in the response
func TestIMAP_BinaryPartialFetchResponseFormat(t *testing.T) {
	t.Skip("This test requires raw protocol inspection to verify response format")

	// This test would need to check that:
	// - Response includes BINARY[5]<0> not just BINARY[5]
	// - Response uses literal format {7}\nabcdefg not quoted "abcdefg"
	//
	// The go-imap client library may parse this differently, so we'd need
	// to inspect the raw IMAP protocol responses to verify correctness.
	//
	// The imaptest failures suggest the server is sending:
	//   BINARY[5] "abcdefg"
	// But should send:
	//   BINARY[5]<0> {7}\nabcdefg
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
