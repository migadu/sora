package sieveengine

import (
	"context"
	"testing"
)

// A message with a null envelope sender (a bounce, DSN or MDN) must still go through
// the user's filters when their script also holds a vacation. go-sieve before v1.4.3
// failed the whole script on it ("vacation: failed to get sender from envelope"), and
// delivery kept the message in INBOX, past every filter (#114).
func TestVacationNullSenderRunsTheFilters(t *testing.T) {
	script := `
require ["vacation", "fileinto"];
vacation :days 1 :subject "Away" "I am away until Monday.";
if header :contains "subject" "invoice" { fileinto "Invoices"; }
`
	compiled, err := CompileScript(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	for _, tc := range []struct {
		name    string
		subject string
		want    Action
		mailbox string
	}{
		{"filtered", "invoice 42", ActionFileInto, "Invoices"},
		{"kept", "hello", ActionKeep, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := compiled.NewExecutor(1, nil, nil, 0, 0, 0).Evaluate(context.Background(), Context{
				EnvelopeFrom: "",
				EnvelopeTo:   "user@example.com",
				Header:       map[string][]string{"Subject": {tc.subject}, "To": {"user@example.com"}},
				Message:      bodyOnly("Delivery failed."),
			})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if result.Action != tc.want || result.Mailbox != tc.mailbox {
				t.Errorf("action = %s (mailbox %q), want %s (mailbox %q)", result.Action, result.Mailbox, tc.want, tc.mailbox)
			}
		})
	}
}
