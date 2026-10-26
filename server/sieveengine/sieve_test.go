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
				Message: bodyOnly("Test message body"),
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
		Message: bodyOnly("Test message body"),
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
		Message: bodyOnly("Test message body"),
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
		Message: bodyOnly("Test message body"),
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
		Message: bodyOnly("Test message body"),
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

func (m *mockVacationOracle) CountRedirectsSince(ctx context.Context, accountID int64, window time.Duration) (int, error) {
	return 0, nil
}

func (m *mockVacationOracle) RecordRedirect(ctx context.Context, accountID int64) error {
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
	executor, err := NewSieveExecutorWithOracleAndExtensions(script, 6007, oracle, oracle, 10, time.Hour, 0, enabledExtensions)
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
		Message: bodyOnly("Test message body"),
	}

	result, err := executor.Evaluate(context.Background(), ctx)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	// The bug was that this returned ActionDiscard
	// Correct behavior: vacation does not cancel the implicit keep (RFC 5230 §4.7)
	if result.Action != ActionKeep {
		t.Errorf("Expected action %s, got %s - vacation should be implicit keep, not discard", ActionKeep, result.Action)
	}

	if result.Vacation == nil {
		t.Fatalf("Expected a vacation reply")
	}
	if result.Vacation.Subject != "Out of Office" {
		t.Errorf("Expected vacation subject 'Out of Office', got %s", result.Vacation.Subject)
	}

	expectedMsg := "Thank you for your email. I am currently out of the office and will get back to you shortly."
	if result.Vacation.Body != expectedMsg {
		t.Errorf("Expected vacation message %q, got %q", expectedMsg, result.Vacation.Body)
	}
}

// TestVacationAlongsideEveryAction is issue #113: the reply used to be one more
// Action, taken only when the script did nothing else with the message, so a message
// it filed, redirected or discarded got none. RFC 5230 §4.7: vacation "does not affect
// Sieve's implicit keep action", and "Implementations MUST NOT consider vacation used
// with discard, keep, fileinto, or redirect an error."
func TestVacationAlongsideEveryAction(t *testing.T) {
	tests := []struct {
		name    string
		command string // what the script does after the vacation
		want    Result // only Action, Mailbox, RedirectTo and Copy are compared
	}{
		{name: "implicit keep", want: Result{Action: ActionKeep}},
		{name: "keep", command: `keep;`, want: Result{Action: ActionKeep}},
		{name: "fileinto", command: `fileinto "Archive";`, want: Result{Action: ActionFileInto, Mailbox: "Archive"}},
		{name: "fileinto :copy", command: `fileinto :copy "Archive";`, want: Result{Action: ActionFileInto, Mailbox: "Archive", Copy: true}},
		{name: "redirect", command: `redirect "elsewhere@example.net";`, want: Result{Action: ActionRedirect, RedirectTo: "elsewhere@example.net"}},
		{name: "discard", command: `discard;`, want: Result{Action: ActionDiscard}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := "require [\"vacation\", \"fileinto\", \"copy\"];\n" +
				"vacation :days 1 :subject \"Away\" \"I'm away\";\n" + tt.command + "\n"
			oracle := newMockVacationOracle()
			executor, err := NewSieveExecutorWithOracleAndExtensions(script, 1, oracle, oracle, 10, time.Hour, 0, []string{"vacation", "fileinto", "copy"})
			if err != nil {
				t.Fatalf("Failed to create executor: %v", err)
			}

			result, err := executor.Evaluate(context.Background(), Context{
				EnvelopeFrom: "sender@example.com",
				EnvelopeTo:   "recipient@example.com",
				Header: map[string][]string{
					"Subject": {"Test"},
					"From":    {"sender@example.com"},
				},
				Message: bodyOnly("Test body"),
			})
			if err != nil {
				t.Fatalf("Failed to evaluate script: %v", err)
			}

			if result.Action != tt.want.Action || result.Mailbox != tt.want.Mailbox ||
				result.RedirectTo != tt.want.RedirectTo || result.Copy != tt.want.Copy {
				t.Errorf("got action %s mailbox %q redirect %q copy %v, want %s %q %q %v",
					result.Action, result.Mailbox, result.RedirectTo, result.Copy,
					tt.want.Action, tt.want.Mailbox, tt.want.RedirectTo, tt.want.Copy)
			}
			if result.Vacation == nil {
				t.Fatalf("the vacation reply was dropped next to %s", result.Action)
			}
			if result.Vacation.Subject != "Away" || result.Vacation.Body != "I'm away" {
				t.Errorf("reply subject %q body %q, want \"Away\" \"I'm away\"", result.Vacation.Subject, result.Vacation.Body)
			}
			if result.Vacation.RecordSent == nil {
				t.Errorf("expected a recorder to commit the :days window with")
			}
		})
	}
}

func TestVacationRateLimiting(t *testing.T) {
	script := `
require "vacation";
vacation :days 7 :subject "Away" "I'm away";
`

	oracle := newMockVacationOracle()
	enabledExtensions := []string{"vacation"}
	executor, err := NewSieveExecutorWithOracleAndExtensions(script, 1, oracle, oracle, 10, time.Hour, 0, enabledExtensions)
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
		Message: bodyOnly("Test body"),
	}

	// First evaluation - should trigger vacation
	result1, err := executor.Evaluate(context.Background(), ctx)
	if err != nil {
		t.Fatalf("Failed to evaluate script (first): %v", err)
	}

	if result1.Vacation == nil {
		t.Fatalf("First evaluation: expected a vacation reply")
	}

	// The window is consumed by the delivery path once the reply is handed off.
	if result1.Vacation.RecordSent == nil {
		t.Fatalf("First evaluation: expected a recorder for the sent reply")
	}
	if err := result1.Vacation.RecordSent(context.Background()); err != nil {
		t.Fatalf("Failed to record vacation response: %v", err)
	}

	// Second evaluation immediately after - should NOT trigger vacation (rate limited)
	// Need to create new executor instance to simulate new message evaluation
	executor2, err := NewSieveExecutorWithOracleAndExtensions(script, 1, oracle, oracle, 10, time.Hour, 0, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor (second): %v", err)
	}

	result2, err := executor2.Evaluate(context.Background(), ctx)
	if err != nil {
		t.Fatalf("Failed to evaluate script (second): %v", err)
	}

	// The implicit keep, with no reply (vacation blocked by rate limit)
	if result2.Action != ActionKeep {
		t.Errorf("Second evaluation: Expected action %s, got %s", ActionKeep, result2.Action)
	}
	if result2.Vacation != nil {
		t.Errorf("Second evaluation: expected no vacation reply inside the :days window")
	}
}

// TestVacationWindowNotConsumedByEvaluation guards the split between deciding to reply
// and committing the :days window: the delivery path still applies the RFC 5230 §4.5
// suppression rules after evaluation and may drop the reply, so an evaluation on its
// own must leave the window open for the next message from that sender.
func TestVacationWindowNotConsumedByEvaluation(t *testing.T) {
	script := `
require "vacation";
vacation :days 7 :subject "Away" "I'm away";
`

	oracle := newMockVacationOracle()
	enabledExtensions := []string{"vacation"}
	ctx := Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header:       map[string][]string{"From": {"sender@example.com"}},
		Message:      bodyOnly("Test body"),
	}

	for i := 1; i <= 2; i++ {
		executor, err := NewSieveExecutorWithOracleAndExtensions(script, 1, oracle, oracle, 10, time.Hour, 0, enabledExtensions)
		if err != nil {
			t.Fatalf("Evaluation %d: failed to create executor: %v", i, err)
		}
		result, err := executor.Evaluate(context.Background(), ctx)
		if err != nil {
			t.Fatalf("Evaluation %d: failed to evaluate script: %v", i, err)
		}
		if result.Vacation == nil {
			t.Fatalf("Evaluation %d: expected a vacation reply", i)
		}
		if result.Vacation.RecordSent == nil {
			t.Fatalf("Evaluation %d: expected a recorder to commit the window with", i)
		}
	}
	if len(oracle.responses) != 0 {
		t.Errorf("evaluation must not consume the per-sender window, oracle recorded %d response(s)", len(oracle.responses))
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
	executor, err := NewSieveExecutorWithOracleAndExtensions(script, 1, oracle, oracle, 10, time.Hour, 0, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	tests := []struct {
		name       string
		precedence string
		wantReply  bool
	}{
		{
			name:       "Regular email - should send vacation",
			precedence: "",
			wantReply:  true,
		},
		{
			name:       "List email - should not send vacation",
			precedence: "list",
		},
		{
			name:       "Bulk email - should not send vacation",
			precedence: "bulk",
		},
		{
			name:       "Junk email - should not send vacation",
			precedence: "junk",
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
				Message:      bodyOnly("Test body"),
			}

			result, err := executor.Evaluate(context.Background(), ctx)
			if err != nil {
				t.Fatalf("Failed to evaluate script: %v", err)
			}

			if result.Action != ActionKeep {
				t.Errorf("Expected action %s, got %s", ActionKeep, result.Action)
			}
			if got := result.Vacation != nil; got != tt.wantReply {
				t.Errorf("vacation reply = %v, want %v", got, tt.wantReply)
			}
		})
	}
}

func TestHeaderCaseInsensitivity(t *testing.T) {
	// RFC 5228 §2.6.2.1: Header field names are case-insensitive
	// This test verifies that header matching works regardless of case
	// in both the script and the header map
	script := `
require "vacation";
if header :contains "From" "@gmail.com" {
  vacation :days 1 :subject "Gmail blocked" "Please use your domain email";
}
`

	tests := []struct {
		name      string
		headerKey string // "From", "from", "FROM", etc.
	}{
		{
			name:      "Capital From (standard)",
			headerKey: "From",
		},
		{
			name:      "Lowercase from (LMTP normalized)",
			headerKey: "from",
		},
		{
			name:      "Uppercase FROM",
			headerKey: "FROM",
		},
		{
			name:      "Mixed case FrOm",
			headerKey: "FrOm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh oracle and executor for each test to avoid rate limiting
			oracle := newMockVacationOracle()
			enabledExtensions := []string{"vacation"}
			executor, err := NewSieveExecutorWithOracleAndExtensions(script, 1, oracle, oracle, 10, time.Hour, 0, enabledExtensions)
			if err != nil {
				t.Fatalf("Failed to create executor: %v", err)
			}

			headers := map[string][]string{
				tt.headerKey: {"sender@gmail.com"},
				"Subject":    {"Test"},
			}

			ctx := Context{
				EnvelopeFrom: "sender@gmail.com",
				EnvelopeTo:   "recipient@example.com",
				Header:       headers,
				Message:      bodyOnly("Test body"),
			}

			result, err := executor.Evaluate(context.Background(), ctx)
			if err != nil {
				t.Fatalf("Failed to evaluate script: %v", err)
			}

			if result.Vacation == nil {
				t.Fatalf("Expected a vacation reply")
			}
			if result.Vacation.Subject != "Gmail blocked" {
				t.Errorf("Expected vacation subject 'Gmail blocked', got '%s'", result.Vacation.Subject)
			}
		})
	}
}

func TestBodyExtension(t *testing.T) {
	script := `
require ["body", "fileinto"];
if body :contains "URGENT" {
	fileinto "Urgent";
} else {
	keep;
}
`

	enabledExtensions := []string{"body", "fileinto"}
	executor, err := NewSieveExecutorWithExtensions(script, enabledExtensions)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	tests := []struct {
		name           string
		body           string
		expectedAction Action
		expectedBox    string
	}{
		{
			name:           "Contains URGENT",
			body:           "This is an URGENT message!",
			expectedAction: ActionFileInto,
			expectedBox:    "Urgent",
		},
		{
			name:           "Contains urgent (case-insensitive)",
			body:           "This is an urgent message!",
			expectedAction: ActionFileInto,
			expectedBox:    "Urgent",
		},
		{
			name:           "Does not contain URGENT",
			body:           "Just a regular message.",
			expectedAction: ActionKeep,
			expectedBox:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := Context{
				EnvelopeFrom: "sender@example.com",
				EnvelopeTo:   "recipient@example.com",
				Header: map[string][]string{
					"Subject":      {"Test message"},
					"From":         {"sender@example.com"},
					"Content-Type": {"text/plain"},
				},
				Message: bodyOnly(tt.body),
			}

			result, err := executor.Evaluate(context.Background(), ctx)
			if err != nil {
				t.Fatalf("Failed to evaluate script: %v", err)
			}

			if result.Action != tt.expectedAction {
				t.Errorf("Expected action %s, got %s", tt.expectedAction, result.Action)
			}
			if result.Action == ActionFileInto && result.Mailbox != tt.expectedBox {
				t.Errorf("Expected mailbox %s, got %s", tt.expectedBox, result.Mailbox)
			}
		})
	}
}

func TestEvaluateCancelledContext(t *testing.T) {
	script := `
keep;
`

	executor, err := NewSieveExecutor(script)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	ctx := Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header: map[string][]string{
			"Subject": {"Test"},
		},
		Message: bodyOnly("Test body"),
	}

	// Create an already cancelled context
	evalCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = executor.Evaluate(evalCtx, ctx)
	if err == nil {
		t.Error("Expected error when evaluating with cancelled context, got nil")
	}
}

// bodyOnly builds Context.Message for tests that supply their headers through
// Context.Header: an empty header block, then body.
func bodyOnly(body string) []byte {
	return []byte("\r\n" + body)
}
