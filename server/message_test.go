package server

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseMessage_ValidMessage(t *testing.T) {
	validMsg := `From: sender@example.com
To: recipient@example.com
Subject: Test Message
Content-Type: text/plain

This is a test message.
`
	msg, err := ParseMessage(strings.NewReader(validMsg))
	if err != nil {
		t.Fatalf("ParseMessage failed for valid message: %v", err)
	}
	if msg == nil {
		t.Fatal("ParseMessage returned nil entity for valid message")
	}

	// Check basic headers are accessible
	from := msg.Header.Get("From")
	if from != "sender@example.com" {
		t.Errorf("Expected From: sender@example.com, got: %s", from)
	}
}

func TestParseMessage_MalformedMIMEHeader(t *testing.T) {
	// Create a message with a malformed MIME header (missing colon after header name)
	// This mimics the kind of corruption seen in production logs
	malformedMsg := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject?\r\n" + // Invalid - missing colon
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"This message has a malformed header.\r\n"

	msg, err := ParseMessage(strings.NewReader(malformedMsg))

	// Should NOT return an error (graceful fallback)
	if err != nil {
		t.Fatalf("ParseMessage should handle malformed MIME gracefully, got error: %v", err)
	}

	if msg == nil {
		t.Fatal("ParseMessage should return a fallback entity, got nil")
	}

	// Check that fallback entity has error marker
	parseError := msg.Header.Get("X-Sora-Parse-Error")
	if parseError == "" {
		t.Error("Expected X-Sora-Parse-Error header in fallback entity")
	}
	if !strings.Contains(parseError, "malformed MIME header") {
		t.Errorf("Expected parse error to mention 'malformed MIME header', got: %s", parseError)
	}
}

func TestParseMessage_CompletelyInvalidMIME(t *testing.T) {
	// Test with a message that has truly broken MIME structure
	brokenMsg := `From: sender@example.com
Subject?=` + "\r\n" + `
To: recipient@example.com

Body content
`
	msg, err := ParseMessage(strings.NewReader(brokenMsg))

	// Should handle gracefully
	if err != nil {
		t.Fatalf("ParseMessage should handle broken MIME gracefully, got error: %v", err)
	}

	if msg == nil {
		t.Fatal("ParseMessage should return a fallback entity, got nil")
	}

	// Verify it's a fallback entity
	parseError := msg.Header.Get("X-Sora-Parse-Error")
	if parseError == "" {
		t.Error("Expected X-Sora-Parse-Error header in fallback entity")
	}
}

func TestParseMessage_UnknownCharset(t *testing.T) {
	// Test that unknown charset errors are still handled gracefully (existing behavior)
	msgWithWeirdCharset := `From: sender@example.com
To: recipient@example.com
Subject: Test
Content-Type: text/plain; charset=unknown-charset-xyz

Body
`
	msg, err := ParseMessage(strings.NewReader(msgWithWeirdCharset))

	// Unknown charset should not cause an error
	if err != nil {
		t.Fatalf("ParseMessage should handle unknown charset, got error: %v", err)
	}

	if msg == nil {
		t.Fatal("ParseMessage returned nil entity")
	}
}

func TestCreateFallbackEntity(t *testing.T) {
	originalErr := bytes.ErrTooLarge

	entity := createFallbackEntity(originalErr)

	if entity == nil {
		t.Fatal("createFallbackEntity returned nil")
	}

	// Check fallback entity structure
	parseError := entity.Header.Get("X-Sora-Parse-Error")
	if parseError == "" {
		t.Error("Expected X-Sora-Parse-Error header in fallback entity")
	}

	contentType := entity.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("Expected Content-Type: text/plain, got: %s", contentType)
	}
}
