package lmtp

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/server/sieveengine"
)

// TestVacationMessageConstruction tests that vacation messages are properly constructed
func TestVacationMessageConstruction(t *testing.T) {
	tests := []struct {
		name           string
		vacationResult sieveengine.Result
		expectedFrom   string
		expectedSubj   string
		expectedBody   string
	}{
		{
			name: "Basic vacation message",
			vacationResult: sieveengine.Result{
				Action:       sieveengine.ActionVacation,
				VacationFrom: "user@example.com",
				VacationSubj: "Out of Office",
				VacationMsg:  "I'm away. Will respond when I return.",
			},
			expectedFrom: "user@example.com",
			expectedSubj: "Out of Office",
			expectedBody: "I'm away. Will respond when I return.",
		},
		{
			name: "Vacation with multiline body",
			vacationResult: sieveengine.Result{
				Action:       sieveengine.ActionVacation,
				VacationFrom: "user@example.com",
				VacationSubj: "Auto Reply",
				VacationMsg:  "Thank you for your email.\n\nI am currently out of the office.\nI will respond when I return.",
			},
			expectedFrom: "user@example.com",
			expectedSubj: "Auto Reply",
			expectedBody: "Thank you for your email.\n\nI am currently out of the office.\nI will respond when I return.",
		},
		{
			name: "Vacation with special characters",
			vacationResult: sieveengine.Result{
				Action:       sieveengine.ActionVacation,
				VacationFrom: "user@example.com",
				VacationSubj: "Out of Office: Réponse automatique",
				VacationMsg:  "Bonjour,\n\nJe suis absent(e). Réponse différée.\n\nMerci!",
			},
			expectedFrom: "user@example.com",
			expectedSubj: "Out of Office: Réponse automatique",
			expectedBody: "Bonjour,\n\nJe suis absent(e). Réponse différée.\n\nMerci!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Construct vacation message like handleVacationResponse does
			var vacationMessage bytes.Buffer
			var h message.Header
			h.Set("From", tt.vacationResult.VacationFrom)
			h.Set("To", "sender@example.com")
			h.Set("Subject", tt.vacationResult.VacationSubj)
			messageID := "<test.vacation@example.com>"
			h.Set("Message-ID", messageID)
			h.Set("Auto-Submitted", "auto-replied")
			h.Set("X-Auto-Response-Suppress", "All")
			h.Set("Date", time.Now().Format(time.RFC1123Z))
			h.Set("Content-Type", "text/plain; charset=utf-8")

			w, err := message.CreateWriter(&vacationMessage, h)
			if err != nil {
				t.Fatalf("Failed to create message writer: %v", err)
			}

			_, err = w.Write([]byte(tt.vacationResult.VacationMsg))
			if err != nil {
				w.Close()
				t.Fatalf("Failed to write vacation message body: %v", err)
			}

			w.Close()

			// Parse the constructed message
			entity, err := message.Read(bytes.NewReader(vacationMessage.Bytes()))
			if err != nil {
				t.Fatalf("Failed to parse message: %v", err)
			}

			// Verify headers
			mailHeader := mail.Header{Header: entity.Header}

			from, err := mailHeader.AddressList("From")
			if err != nil {
				t.Fatalf("Failed to get From header: %v", err)
			}
			if len(from) != 1 || from[0].Address != tt.expectedFrom {
				t.Errorf("Expected From: %s, got: %v", tt.expectedFrom, from)
			}

			subject, err := mailHeader.Subject()
			if err != nil {
				t.Fatalf("Failed to get Subject: %v", err)
			}
			if subject != tt.expectedSubj {
				t.Errorf("Expected Subject: %q, got: %q", tt.expectedSubj, subject)
			}

			// Verify auto-response headers
			autoSubmitted := entity.Header.Get("Auto-Submitted")
			if autoSubmitted != "auto-replied" {
				t.Errorf("Expected Auto-Submitted: auto-replied, got: %s", autoSubmitted)
			}

			xAutoSuppress := entity.Header.Get("X-Auto-Response-Suppress")
			if xAutoSuppress != "All" {
				t.Errorf("Expected X-Auto-Response-Suppress: All, got: %s", xAutoSuppress)
			}

			// Verify Content-Type
			contentType := entity.Header.Get("Content-Type")
			if !strings.Contains(contentType, "text/plain") {
				t.Errorf("Expected Content-Type to contain text/plain, got: %s", contentType)
			}
			if !strings.Contains(contentType, "utf-8") {
				t.Errorf("Expected Content-Type to contain utf-8, got: %s", contentType)
			}

			// Verify body
			var body bytes.Buffer
			_, err = body.ReadFrom(entity.Body)
			if err != nil {
				t.Fatalf("Failed to read body: %v", err)
			}

			if body.String() != tt.expectedBody {
				t.Errorf("Body mismatch:\nExpected: %q\nGot: %q", tt.expectedBody, body.String())
			}
		})
	}
}

// TestVacationMessageWithInReplyTo tests that In-Reply-To and References headers are set correctly
func TestVacationMessageWithInReplyTo(t *testing.T) {
	originalMessageID := "<original@example.com>"

	var vacationMessage bytes.Buffer
	var h message.Header
	h.Set("From", "user@example.com")
	h.Set("To", "sender@example.com")
	h.Set("Subject", "Out of Office")
	h.Set("Message-ID", "<vacation@example.com>")
	h.Set("In-Reply-To", originalMessageID)
	h.Set("References", originalMessageID)
	h.Set("Auto-Submitted", "auto-replied")
	h.Set("X-Auto-Response-Suppress", "All")
	h.Set("Date", time.Now().Format(time.RFC1123Z))
	h.Set("Content-Type", "text/plain; charset=utf-8")

	w, err := message.CreateWriter(&vacationMessage, h)
	if err != nil {
		t.Fatalf("Failed to create message writer: %v", err)
	}

	_, err = w.Write([]byte("I'm away"))
	if err != nil {
		w.Close()
		t.Fatalf("Failed to write body: %v", err)
	}

	w.Close()

	// Parse and verify
	entity, err := message.Read(bytes.NewReader(vacationMessage.Bytes()))
	if err != nil {
		t.Fatalf("Failed to parse message: %v", err)
	}

	inReplyTo := entity.Header.Get("In-Reply-To")
	if inReplyTo != originalMessageID {
		t.Errorf("Expected In-Reply-To: %s, got: %s", originalMessageID, inReplyTo)
	}

	references := entity.Header.Get("References")
	if references != originalMessageID {
		t.Errorf("Expected References: %s, got: %s", originalMessageID, references)
	}
}

// TestVacationMessageIsNotMultipart tests that vacation messages are simple text, not multipart
func TestVacationMessageIsNotMultipart(t *testing.T) {
	var vacationMessage bytes.Buffer
	var h message.Header
	h.Set("From", "user@example.com")
	h.Set("To", "sender@example.com")
	h.Set("Subject", "Out of Office")
	h.Set("Message-ID", "<vacation@example.com>")
	h.Set("Auto-Submitted", "auto-replied")
	h.Set("Date", time.Now().Format(time.RFC1123Z))
	h.Set("Content-Type", "text/plain; charset=utf-8")

	w, err := message.CreateWriter(&vacationMessage, h)
	if err != nil {
		t.Fatalf("Failed to create message writer: %v", err)
	}

	_, err = w.Write([]byte("Simple text message"))
	if err != nil {
		w.Close()
		t.Fatalf("Failed to write body: %v", err)
	}

	w.Close()

	// Verify the message is NOT multipart
	msgStr := vacationMessage.String()
	if strings.Contains(msgStr, "multipart") {
		t.Errorf("Message should not be multipart, but Content-Type contains 'multipart'")
	}

	// Verify we can parse it as a simple message
	entity, err := message.Read(bytes.NewReader(vacationMessage.Bytes()))
	if err != nil {
		t.Fatalf("Failed to parse as simple message: %v", err)
	}

	contentType := entity.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("Expected text/plain content type, got: %s", contentType)
	}

	// Verify it's not multipart
	if entity.MultipartReader() != nil {
		t.Error("Message should not be multipart")
	}
}

// TestVacationMessageEncoding tests that UTF-8 content is properly encoded
func TestVacationMessageEncoding(t *testing.T) {
	testBody := "Hello 世界 🌍\nBonjour à tous!\nGuten Tag Köln"

	var vacationMessage bytes.Buffer
	var h message.Header
	h.Set("From", "user@example.com")
	h.Set("To", "sender@example.com")
	h.Set("Subject", "Out of Office")
	h.Set("Message-ID", "<vacation@example.com>")
	h.Set("Date", time.Now().Format(time.RFC1123Z))
	h.Set("Content-Type", "text/plain; charset=utf-8")

	w, err := message.CreateWriter(&vacationMessage, h)
	if err != nil {
		t.Fatalf("Failed to create message writer: %v", err)
	}

	_, err = w.Write([]byte(testBody))
	if err != nil {
		w.Close()
		t.Fatalf("Failed to write body: %v", err)
	}

	w.Close()

	// Parse and verify UTF-8 content is preserved
	entity, err := message.Read(bytes.NewReader(vacationMessage.Bytes()))
	if err != nil {
		t.Fatalf("Failed to parse message: %v", err)
	}

	var body bytes.Buffer
	_, err = body.ReadFrom(entity.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	if body.String() != testBody {
		t.Errorf("UTF-8 content not preserved:\nExpected: %q\nGot: %q", testBody, body.String())
	}
}
