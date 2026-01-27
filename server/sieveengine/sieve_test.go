package sieveengine

import (
	"context"
	"testing"
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
