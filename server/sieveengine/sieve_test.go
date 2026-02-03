package sieveengine

import (
	"context"
	"testing"
	"time"
)

func TestRedirectWithExplicitKeep(t *testing.T) {
	script := `
if header :contains "Subject" "Security code" {
	keep;
	stop;
}

if header :contains "Subject" "Verify your candidate account" {
	keep;
	stop;
}

redirect "another@email.com";
keep;
stop;
`

	// Use standard enabled extensions like LMTP does
	enabledExtensions := []string{"envelope", "fileinto", "redirect", "encoded-character", "imap4flags", "variables", "relational", "vacation", "copy", "regex"}
	executor, err := NewSieveExecutorWithExtensions(script, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	tests := []struct {
		name             string
		subject          string
		expectedAction   Action
		expectedCopy     bool
		expectedRedirect string
	}{
		{
			name:             "Security code match - should keep only",
			subject:          "Your Security code is 12345",
			expectedAction:   ActionKeep,
			expectedCopy:     false,
			expectedRedirect: "",
		},
		{
			name:             "Verify match - should keep only",
			subject:          "Verify your candidate account",
			expectedAction:   ActionKeep,
			expectedCopy:     false,
			expectedRedirect: "",
		},
		{
			name:             "No match - should redirect with keep",
			subject:          "Regular email",
			expectedAction:   ActionRedirect,
			expectedCopy:     true,
			expectedRedirect: "another@email.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := Context{
				EnvelopeFrom: "sender@example.com",
				EnvelopeTo:   "recipient@example.com",
				Header: map[string][]string{
					"Subject": {tt.subject},
					"From":    {"sender@example.com"},
					"To":      {"recipient@example.com"},
				},
				Body: "Test message body",
			}

			result, err := executor.Evaluate(context.Background(), ctx)
			if err != nil {
				t.Fatalf("Failed to evaluate script: %v", err)
			}

			if result.Action != tt.expectedAction {
				t.Errorf("Expected action %s, got %s", tt.expectedAction, result.Action)
			}

			if result.Copy != tt.expectedCopy {
				t.Errorf("Expected Copy=%v, got %v", tt.expectedCopy, result.Copy)
			}

			if result.RedirectTo != tt.expectedRedirect {
				t.Errorf("Expected RedirectTo=%s, got %s", tt.expectedRedirect, result.RedirectTo)
			}
		})
	}
}

func TestRedirectWithoutExplicitKeep(t *testing.T) {
	script := `
redirect "another@email.com";
`

	enabledExtensions := []string{"envelope", "fileinto", "redirect", "encoded-character", "imap4flags", "variables", "relational", "vacation", "copy", "regex"}
	executor, err := NewSieveExecutorWithExtensions(script, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	ctx := Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header: map[string][]string{
			"Subject": {"Test"},
			"From":    {"sender@example.com"},
			"To":      {"recipient@example.com"},
		},
		Body: "Test message body",
	}

	result, err := executor.Evaluate(context.Background(), ctx)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	// Without explicit keep, redirect should not keep a copy (RFC 5228 behavior)
	if result.Action != ActionRedirect {
		t.Errorf("Expected action %s, got %s", ActionRedirect, result.Action)
	}

	if result.Copy {
		t.Errorf("Expected Copy=false (no explicit keep), got true")
	}

	if result.RedirectTo != "another@email.com" {
		t.Errorf("Expected RedirectTo=another@email.com, got %s", result.RedirectTo)
	}
}

func TestRedirectWithCopyModifier(t *testing.T) {
	script := `
require ["copy"];
redirect :copy "another@email.com";
`

	enabledExtensions := []string{"envelope", "fileinto", "redirect", "encoded-character", "imap4flags", "variables", "relational", "vacation", "copy", "regex"}
	executor, err := NewSieveExecutorWithExtensions(script, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	ctx := Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header: map[string][]string{
			"Subject": {"Test"},
			"From":    {"sender@example.com"},
			"To":      {"recipient@example.com"},
		},
		Body: "Test message body",
	}

	result, err := executor.Evaluate(context.Background(), ctx)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	// With :copy modifier, should keep a copy
	if result.Action != ActionRedirect {
		t.Errorf("Expected action %s, got %s", ActionRedirect, result.Action)
	}

	if !result.Copy {
		t.Errorf("Expected Copy=true (with :copy modifier), got false")
	}

	if result.RedirectTo != "another@email.com" {
		t.Errorf("Expected RedirectTo=another@email.com, got %s", result.RedirectTo)
	}
}

func TestFileIntoWithExplicitKeep(t *testing.T) {
	script := `
require ["fileinto"];
fileinto "Spam";
keep;
`

	enabledExtensions := []string{"envelope", "fileinto", "redirect", "encoded-character", "imap4flags", "variables", "relational", "vacation", "copy", "regex"}
	executor, err := NewSieveExecutorWithExtensions(script, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	ctx := Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header: map[string][]string{
			"Subject": {"Test"},
			"From":    {"sender@example.com"},
			"To":      {"recipient@example.com"},
		},
		Body: "Test message body",
	}

	result, err := executor.Evaluate(context.Background(), ctx)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	// With explicit keep after fileinto, should save to both Spam and INBOX
	if result.Action != ActionFileInto {
		t.Errorf("Expected action %s, got %s", ActionFileInto, result.Action)
	}

	if !result.Copy {
		t.Errorf("Expected Copy=true (explicit keep after fileinto), got false")
	}

	if result.Mailbox != "Spam" {
		t.Errorf("Expected Mailbox=Spam, got %s", result.Mailbox)
	}
}

func TestFileIntoWithoutExplicitKeep(t *testing.T) {
	script := `
require ["fileinto"];
fileinto "Spam";
`

	enabledExtensions := []string{"envelope", "fileinto", "redirect", "encoded-character", "imap4flags", "variables", "relational", "vacation", "copy", "regex"}
	executor, err := NewSieveExecutorWithExtensions(script, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	ctx := Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header: map[string][]string{
			"Subject": {"Test"},
			"From":    {"sender@example.com"},
			"To":      {"recipient@example.com"},
		},
		Body: "Test message body",
	}

	result, err := executor.Evaluate(context.Background(), ctx)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	// Without explicit keep, fileinto should not copy to INBOX (RFC 5228 behavior)
	if result.Action != ActionFileInto {
		t.Errorf("Expected action %s, got %s", ActionFileInto, result.Action)
	}

	if result.Copy {
		t.Errorf("Expected Copy=false (no explicit keep), got true")
	}

	if result.Mailbox != "Spam" {
		t.Errorf("Expected Mailbox=Spam, got %s", result.Mailbox)
	}
}

// mockVacationOracle is a test implementation of VacationOracle
type mockVacationOracle struct {
	responses map[string]time.Time // key: "accountID:originalSender:handle"
}

func newMockVacationOracle() *mockVacationOracle {
	return &mockVacationOracle{
		responses: make(map[string]time.Time),
	}
}

func (m *mockVacationOracle) IsVacationResponseAllowed(ctx context.Context, accountID int64, originalSender string, handle string, duration time.Duration) (bool, error) {
	key := m.makeKey(accountID, originalSender, handle)
	lastSent, exists := m.responses[key]
	if !exists {
		return true, nil
	}
	return time.Since(lastSent) >= duration, nil
}

func (m *mockVacationOracle) RecordVacationResponseSent(ctx context.Context, accountID int64, originalSender string, handle string) error {
	key := m.makeKey(accountID, originalSender, handle)
	m.responses[key] = time.Now()
	return nil
}

func (m *mockVacationOracle) makeKey(accountID int64, originalSender string, handle string) string {
	return string(rune(accountID)) + ":" + originalSender + ":" + handle
}

func TestVacationIsImplicitKeep(t *testing.T) {
	// This is the bug scenario: vacation should NOT discard the message
	script := `
require "vacation";
if not header :contains "precedence" ["list", "bulk", "junk"] {
  vacation :days 7 :subject "Out of Office"
"Thank you for your email. I am currently out of the office and will get back to you shortly.";
}
`

	oracle := newMockVacationOracle()
	enabledExtensions := []string{"envelope", "fileinto", "redirect", "encoded-character", "imap4flags", "variables", "relational", "vacation", "copy", "regex"}
	executor, err := NewSieveExecutorWithOracleAndExtensions(script, 6007, oracle, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	ctx := Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header: map[string][]string{
			"Subject": {"Test message"},
			"From":    {"sender@example.com"},
			"To":      {"recipient@example.com"},
		},
		Body: "Test message body",
	}

	result, err := executor.Evaluate(context.Background(), ctx)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	// The bug was that this returned ActionDiscard
	// Correct behavior: vacation is an implicit keep (RFC 5230)
	if result.Action != ActionVacation {
		t.Errorf("Expected action %s, got %s - vacation should be implicit keep, not discard", ActionVacation, result.Action)
	}

	if result.VacationSubj != "Out of Office" {
		t.Errorf("Expected vacation subject 'Out of Office', got %s", result.VacationSubj)
	}

	expectedMsg := "Thank you for your email. I am currently out of the office and will get back to you shortly."
	if result.VacationMsg != expectedMsg {
		t.Errorf("Expected vacation message %q, got %q", expectedMsg, result.VacationMsg)
	}
}

func TestVacationWithExplicitKeep(t *testing.T) {
	script := `
require "vacation";
vacation :days 1 :subject "Away" "I'm away";
keep;
`

	oracle := newMockVacationOracle()
	enabledExtensions := []string{"vacation"}
	executor, err := NewSieveExecutorWithOracleAndExtensions(script, 1, oracle, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	ctx := Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header: map[string][]string{
			"Subject": {"Test"},
			"From":    {"sender@example.com"},
		},
		Body: "Test body",
	}

	result, err := executor.Evaluate(context.Background(), ctx)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	// Vacation should be the action
	if result.Action != ActionVacation {
		t.Errorf("Expected action %s, got %s", ActionVacation, result.Action)
	}
}

func TestVacationWithDiscard(t *testing.T) {
	// When vacation is followed by explicit discard, discard should win
	// The vacation command preserves ImplicitKeep=true, but discard sets it to false
	script := `
require "vacation";
vacation :days 1 :subject "Away" "I'm away";
discard;
`

	oracle := newMockVacationOracle()
	enabledExtensions := []string{"vacation"}
	executor, err := NewSieveExecutorWithOracleAndExtensions(script, 1, oracle, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	ctx := Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header: map[string][]string{
			"Subject": {"Test"},
			"From":    {"sender@example.com"},
		},
		Body: "Test body",
	}

	result, err := executor.Evaluate(context.Background(), ctx)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	// Explicit discard should override vacation's implicit keep
	if result.Action != ActionDiscard {
		t.Errorf("Expected action %s, got %s - explicit discard should override vacation", ActionDiscard, result.Action)
	}
}

func TestVacationWithFileinto(t *testing.T) {
	script := `
require ["vacation", "fileinto"];
vacation :days 1 :subject "Away" "I'm away";
fileinto "Archive";
`

	oracle := newMockVacationOracle()
	enabledExtensions := []string{"vacation", "fileinto"}
	executor, err := NewSieveExecutorWithOracleAndExtensions(script, 1, oracle, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	ctx := Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header: map[string][]string{
			"Subject": {"Test"},
			"From":    {"sender@example.com"},
		},
		Body: "Test body",
	}

	result, err := executor.Evaluate(context.Background(), ctx)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	// Fileinto should take precedence as the primary action
	if result.Action != ActionFileInto {
		t.Errorf("Expected action %s, got %s", ActionFileInto, result.Action)
	}

	if result.Mailbox != "Archive" {
		t.Errorf("Expected mailbox Archive, got %s", result.Mailbox)
	}

	// Note: In a real implementation, we might want to track that vacation
	// was also triggered, but current implementation only returns one action
}

func TestVacationRateLimiting(t *testing.T) {
	script := `
require "vacation";
vacation :days 7 :subject "Away" "I'm away";
`

	oracle := newMockVacationOracle()
	enabledExtensions := []string{"vacation"}
	executor, err := NewSieveExecutorWithOracleAndExtensions(script, 1, oracle, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	ctx := Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header: map[string][]string{
			"Subject": {"Test"},
			"From":    {"sender@example.com"},
		},
		Body: "Test body",
	}

	// First evaluation - should trigger vacation
	result1, err := executor.Evaluate(context.Background(), ctx)
	if err != nil {
		t.Fatalf("Failed to evaluate script (first): %v", err)
	}

	if result1.Action != ActionVacation {
		t.Errorf("First evaluation: Expected action %s, got %s", ActionVacation, result1.Action)
	}

	// Second evaluation immediately after - should NOT trigger vacation (rate limited)
	// Need to create new executor instance to simulate new message evaluation
	executor2, err := NewSieveExecutorWithOracleAndExtensions(script, 1, oracle, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor (second): %v", err)
	}

	result2, err := executor2.Evaluate(context.Background(), ctx)
	if err != nil {
		t.Fatalf("Failed to evaluate script (second): %v", err)
	}

	// Should fall back to implicit keep (vacation blocked by rate limit)
	if result2.Action != ActionKeep {
		t.Errorf("Second evaluation: Expected action %s (vacation rate limited), got %s", ActionKeep, result2.Action)
	}
}

func TestVacationPrecedenceHeader(t *testing.T) {
	// Common pattern: don't send vacation for bulk/list mail
	script := `
require "vacation";
if not header :contains "precedence" ["list", "bulk", "junk"] {
  vacation :days 7 :subject "Away" "I'm away";
}
`

	oracle := newMockVacationOracle()
	enabledExtensions := []string{"vacation"}
	executor, err := NewSieveExecutorWithOracleAndExtensions(script, 1, oracle, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	tests := []struct {
		name           string
		precedence     string
		expectedAction Action
	}{
		{
			name:           "Regular email - should send vacation",
			precedence:     "",
			expectedAction: ActionVacation,
		},
		{
			name:           "List email - should not send vacation",
			precedence:     "list",
			expectedAction: ActionKeep,
		},
		{
			name:           "Bulk email - should not send vacation",
			precedence:     "bulk",
			expectedAction: ActionKeep,
		},
		{
			name:           "Junk email - should not send vacation",
			precedence:     "junk",
			expectedAction: ActionKeep,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := map[string][]string{
				"Subject": {"Test"},
				"From":    {"sender@example.com"},
			}
			if tt.precedence != "" {
				headers["Precedence"] = []string{tt.precedence}
			}

			ctx := Context{
				EnvelopeFrom: "sender@example.com",
				EnvelopeTo:   "recipient@example.com",
				Header:       headers,
				Body:         "Test body",
			}

			result, err := executor.Evaluate(context.Background(), ctx)
			if err != nil {
				t.Fatalf("Failed to evaluate script: %v", err)
			}

			if result.Action != tt.expectedAction {
				t.Errorf("Expected action %s, got %s", tt.expectedAction, result.Action)
			}
		})
	}
}
