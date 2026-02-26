package lmtp

import (
	"strings"
	"testing"

	"github.com/emersion/go-message"
	"github.com/migadu/sora/server"
)

func makeMessage(headers map[string]string) *message.Entity {
	var sb strings.Builder
	for k, v := range headers {
		sb.WriteString(k + ": " + v + "\r\n")
	}
	sb.WriteString("\r\nBody text\r\n")
	entity, _ := message.Read(strings.NewReader(sb.String()))
	return entity
}

func TestShouldSuppressVacation(t *testing.T) {
	normalSender, _ := server.NewAddress("sender@example.com")

	tests := []struct {
		name     string
		sender   *server.Address
		headers  map[string]string
		suppress bool // true = vacation should be suppressed
	}{
		{
			name:     "normal message - no suppression",
			sender:   &normalSender,
			headers:  map[string]string{"From": "sender@example.com", "Subject": "Hello"},
			suppress: false,
		},
		{
			name:     "nil sender",
			sender:   nil,
			headers:  map[string]string{"From": "sender@example.com"},
			suppress: true,
		},
		{
			name:     "empty sender (MAIL FROM:<>)",
			sender:   &server.Address{},
			headers:  map[string]string{"From": "MAILER-DAEMON@example.com"},
			suppress: true,
		},
		{
			name:     "Auto-Submitted: auto-replied",
			sender:   &normalSender,
			headers:  map[string]string{"From": "sender@example.com", "Auto-Submitted": "auto-replied"},
			suppress: true,
		},
		{
			name:     "Auto-Submitted: auto-generated",
			sender:   &normalSender,
			headers:  map[string]string{"From": "sender@example.com", "Auto-Submitted": "auto-generated"},
			suppress: true,
		},
		{
			name:     "Auto-Submitted: no (allowed)",
			sender:   &normalSender,
			headers:  map[string]string{"From": "sender@example.com", "Auto-Submitted": "no"},
			suppress: false,
		},
		{
			name:     "Precedence: bulk",
			sender:   &normalSender,
			headers:  map[string]string{"From": "list@example.com", "Precedence": "bulk"},
			suppress: true,
		},
		{
			name:     "Precedence: junk",
			sender:   &normalSender,
			headers:  map[string]string{"From": "list@example.com", "Precedence": "junk"},
			suppress: true,
		},
		{
			name:     "Precedence: list",
			sender:   &normalSender,
			headers:  map[string]string{"From": "list@example.com", "Precedence": "list"},
			suppress: true,
		},
		{
			name:     "Precedence: normal (allowed)",
			sender:   &normalSender,
			headers:  map[string]string{"From": "sender@example.com", "Precedence": "normal"},
			suppress: false,
		},
		{
			name:     "List-Id present",
			sender:   &normalSender,
			headers:  map[string]string{"From": "list@example.com", "List-Id": "<list.example.com>"},
			suppress: true,
		},
		{
			name:     "case insensitive Auto-Submitted",
			sender:   &normalSender,
			headers:  map[string]string{"From": "sender@example.com", "Auto-Submitted": "Auto-Replied"},
			suppress: true,
		},
		{
			name:     "case insensitive Precedence",
			sender:   &normalSender,
			headers:  map[string]string{"From": "list@example.com", "Precedence": "Bulk"},
			suppress: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := makeMessage(tt.headers)
			reason := shouldSuppressVacation(tt.sender, msg)

			if tt.suppress && reason == "" {
				t.Errorf("expected suppression but got none")
			}
			if !tt.suppress && reason != "" {
				t.Errorf("expected no suppression but got: %s", reason)
			}
			if reason != "" {
				t.Logf("suppressed: %s", reason)
			}
		})
	}
}
