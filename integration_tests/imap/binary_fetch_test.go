//go:build integration

package imap_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_BinaryFetch tests BINARY FETCH returns literals, not quoted strings
func TestIMAP_BinaryFetch(t *testing.T) {
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

	// Test message with base64-encoded MIME part
	// This is similar to the imaptest fetch-binary-mime-base64 test
	rawMessage := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Binary Fetch Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"boundary123\"\r\n" +
		"\r\n" +
		"--boundary123\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Part 1 text\r\n" +
		"--boundary123\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		base64.StdEncoding.EncodeToString([]byte("abcdefg")) + "\r\n" + // "YWJjZGVmZw==" encodes to "abcdefg"
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

	// Verify message was added
	mbox, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	if mbox.NumMessages != 1 {
		t.Fatalf("Expected 1 message, got %d", mbox.NumMessages)
	}

	// Fetch BINARY[2] - should return decoded content of part 2 (the base64 part)
	// According to RFC 3516, BINARY should return the decoded MIME part
	fetchCmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{
			{Part: []int{2}}, // Part 2 is the base64-encoded part
		},
	})

	var foundBinary bool
	var binaryContent []byte

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

			switch item := item.(type) {
			case imapclient.FetchItemDataBinarySection:
				foundBinary = true
				t.Logf("BINARY section: %v", item.Section)

				// Read the content
				buf := new(bytes.Buffer)
				if _, err := io.Copy(buf, item.Literal); err != nil {
					t.Fatalf("Failed to read BINARY content: %v", err)
				}
				binaryContent = buf.Bytes()
				t.Logf("BINARY content: %q", string(binaryContent))
			}
		}
	}

	if err := fetchCmd.Close(); err != nil {
		t.Fatalf("FETCH close failed: %v", err)
	}

	if !foundBinary {
		t.Fatal("BINARY section not found in FETCH response")
	}

	// Verify the binary content is the DECODED base64 content
	expectedContent := "abcdefg"
	if string(binaryContent) != expectedContent {
		t.Errorf("Expected BINARY content %q, got %q", expectedContent, string(binaryContent))
	}

	// The key test: verify the content length is the decoded length
	if len(binaryContent) != len(expectedContent) {
		t.Errorf("Expected BINARY content length %d, got %d", len(expectedContent), len(binaryContent))
	}

	t.Log("BINARY FETCH test completed successfully")
}

// TestIMAP_BinarySizeFetch tests BINARY.SIZE returns decoded size, not 0
func TestIMAP_BinarySizeFetch(t *testing.T) {
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

	// Test message with quoted-printable encoded content in a multipart structure
	// Based on imaptest fetch-binary-mime-qp test
	// The decoded content should be 65 bytes
	// In quoted-printable: '=' at end of line = soft line break (continuation)
	qpContent := "hello  \r\n" +
		"bar=\r\n" + // "bar=" means continue on next line (soft break)
		"\r\n" +
		"foo\t=\r\n" + // "foo\t=" continues
		"bar\r\n" +
		"foo\t \t= \r\n" + // Note: space after '=' is encoded
		"=62\r\n" + // =62 is 'b'
		"foo = \t\r\n" + // Space before '=' is literal
		"bar\r\n" +
		"foo =\r\n" + // "foo =" continues
		"=62\r\n" + // =62 is 'b'
		"foo  \r\n" +
		"bar=\r\n" + // "bar=" continues
		"\r\n" +
		"foo_bar\r\n"

	rawMessage := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Binary Size Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=boundary123\r\n" +
		"\r\n" +
		"This is a multi-part message.\r\n" +
		"\r\n" +
		"--boundary123\r\n" +
		"Content-Type: text/plain; charset=us-ascii\r\n" +
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

	// First, fetch BODY[] to see the full message
	fetchFullBodyCmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{
			{Part: []int{}},
		},
	})

	var fullBodyContent []byte
	for {
		msg := fetchFullBodyCmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if bodyItem, ok := item.(imapclient.FetchItemDataBodySection); ok {
				buf := new(bytes.Buffer)
				io.Copy(buf, bodyItem.Literal)
				fullBodyContent = buf.Bytes()
				t.Logf("BODY[] full message length: %d", len(fullBodyContent))
				t.Logf("BODY[] first 200 chars:\n%s", string(fullBodyContent[:min(200, len(fullBodyContent))]))
			}
		}
	}
	fetchFullBodyCmd.Close()

	// Now fetch BODY[1] to see if normal body fetch works
	fetchBodyCmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{
			{Part: []int{1}},
		},
	})

	var bodyContent []byte
	for {
		msg := fetchBodyCmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if bodyItem, ok := item.(imapclient.FetchItemDataBodySection); ok {
				buf := new(bytes.Buffer)
				io.Copy(buf, bodyItem.Literal)
				bodyContent = buf.Bytes()
				t.Logf("BODY[1] content length: %d, preview: %q", len(bodyContent), string(bodyContent[:min(50, len(bodyContent))]))
			}
		}
	}
	fetchBodyCmd.Close()

	// Now fetch BINARY[1] to see if binary fetch works
	fetchBinaryCmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{
			{Part: []int{1}},
		},
	})

	var binaryContent []byte
	for {
		msg := fetchBinaryCmd.Next()
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
				binaryContent = buf.Bytes()
				t.Logf("BINARY[1] content length: %d, preview: %q", len(binaryContent), string(binaryContent[:min(20, len(binaryContent))]))
			}
		}
	}
	fetchBinaryCmd.Close()

	// Now fetch BINARY.SIZE[1] - should return decoded size of part 1
	fetchCmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BinarySectionSize: []*imap.FetchItemBinarySectionSize{
			{Part: []int{1}}, // Part 1 is the quoted-printable part
		},
	})

	var foundBinarySize bool
	var binarySize uint32

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

			switch item := item.(type) {
			case imapclient.FetchItemDataBinarySectionSize:
				foundBinarySize = true
				binarySize = item.Size
				t.Logf("BINARY.SIZE: %d", binarySize)
			}
		}
	}

	if err := fetchCmd.Close(); err != nil {
		t.Fatalf("FETCH close failed: %v", err)
	}

	if !foundBinarySize {
		t.Fatal("BINARY.SIZE not found in FETCH response")
	}

	// The decoded content should be 63 bytes
	// (Standard QP decoding strips trailing whitespace at EOL, but preserves whitespace before soft breaks)
	expectedSize := uint32(63)
	if binarySize != expectedSize {
		t.Errorf("Expected BINARY.SIZE %d, got %d", expectedSize, binarySize)
	}

	// Ensure it's not returning 0 (which was the bug reported in imaptest)
	if binarySize == 0 {
		t.Error("BINARY.SIZE returned 0 (bug detected)")
	}

	t.Log("BINARY.SIZE FETCH test completed successfully")
}

// TestIMAP_BinaryVsBodyFetch compares BINARY and BODY fetch results
func TestIMAP_BinaryVsBodyFetch(t *testing.T) {
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

	// Test message with base64 content
	base64Content := base64.StdEncoding.EncodeToString([]byte("test content 123"))

	rawMessage := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Compare Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		base64Content + "\r\n"

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

	// Fetch BODY[] (should return encoded content with headers)
	fetchBodyCmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{
			{Part: []int{}},
		},
	})

	var bodyContent []byte
	for {
		msg := fetchBodyCmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if bodyItem, ok := item.(imapclient.FetchItemDataBodySection); ok {
				buf := new(bytes.Buffer)
				io.Copy(buf, bodyItem.Literal)
				bodyContent = buf.Bytes()
			}
		}
	}
	fetchBodyCmd.Close()

	// Fetch BINARY[] (should return decoded content without headers)
	fetchBinaryCmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{
			{Part: []int{}},
		},
	})

	var binaryContent []byte
	for {
		msg := fetchBinaryCmd.Next()
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
				binaryContent = buf.Bytes()
			}
		}
	}
	fetchBinaryCmd.Close()

	t.Logf("BODY[] length: %d", len(bodyContent))
	t.Logf("BINARY[] length: %d", len(binaryContent))

	// BODY should contain base64 encoded data
	if !bytes.Contains(bodyContent, []byte(base64Content)) {
		t.Error("BODY[] should contain base64 encoded content")
	}

	// BINARY should contain decoded data
	expectedDecoded := "test content 123"
	if !strings.Contains(string(binaryContent), expectedDecoded) {
		t.Errorf("BINARY[] should contain decoded content %q, got %q", expectedDecoded, string(binaryContent))
	}

	// BINARY should be shorter than BODY (since it's decoded and no headers)
	if len(binaryContent) >= len(bodyContent) {
		t.Error("BINARY[] should be shorter than BODY[] (decoded content without headers)")
	}

	t.Log("BINARY vs BODY comparison test completed successfully")
}

// TestIMAP_BinaryQP_EdgeCases tests specific QP edge cases using BINARY FETCH
func TestIMAP_BinaryQP_EdgeCases(t *testing.T) {
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

	// Test case constructed to verify specific lenient QP behaviors:
	// 1. =62 -> b (Valid hex preserved)
	// 2. =\r\n -> "" (Valid soft break preserved)
	// 3. =  \r\n -> "" (Malformed soft break with spaces -> treated as soft break)
	// 4. foo  =\r\n -> foo  (Spaces before soft break preserved)
	// 5. equation = 5 -> equation =3D 5 (Malformed literal -> encoded)
	// 6. foo  \r\n -> foo (Trailing whitespace at EOL -> stripped by standard decoder)

	qpContent :=
		"=62\r\n" + // "b"
			"soft=\r\nbreak\r\n" + // "softbreak"
			"malformed=  \r\nsoft\r\n" + // "malformedsoft"
			"spaces  =\r\nkept\r\n" + // "spaces  kept"
			"equation = 5\r\n" + // "equation = 5"
			"trailing  \r\n" // "trailing"

	rawMessage := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: QP Edge Cases\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" +
		qpContent

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

	// Fetch BINARY content
	fetchCmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{
			{Part: []int{}},
		},
	})

	var binaryContent []byte
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
				buf := new(bytes.Buffer)
				io.Copy(buf, binaryItem.Literal)
				binaryContent = buf.Bytes()
			}
		}
	}
	fetchCmd.Close()

	decoded := string(binaryContent)
	t.Logf("Decoded content:\n%q", decoded)

	// Check each case
	if !strings.Contains(decoded, "b\r\n") {
		t.Error("Case 1: =62 failed")
	}
	if !strings.Contains(decoded, "softbreak\r\n") {
		t.Error("Case 2: valid soft break failed")
	}
	if !strings.Contains(decoded, "malformedsoft\r\n") {
		t.Error("Case 3: malformed soft break failed")
	}
	if !strings.Contains(decoded, "spaces  kept\r\n") {
		t.Error("Case 4: spaces before soft break failed")
	}
	if !strings.Contains(decoded, "equation = 5\r\n") {
		t.Error("Case 5: malformed literal failed")
	}
	// Check trailing whitespace stripping (strict EOL behavior)
	if strings.Contains(decoded, "trailing  ") {
		t.Error("Case 6: trailing whitespace should be stripped but was preserved")
	}
	if !strings.Contains(decoded, "trailing\r\n") {
		t.Error("Case 6: trailing content malformed")
	}
}
