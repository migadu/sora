package sieveengine

import (
	"context"
	"errors"
	"testing"
)

// TestMailboxExistsAsksTheMailstore is issue #323: the mailboxexists test (RFC 5490
// §3.1) is answered by Context.MailboxExists, and is true only if every name is.
func TestMailboxExistsAsksTheMailstore(t *testing.T) {
	script := "require [\"fileinto\", \"mailbox\"];\n" +
		"if mailboxexists [\"Exists\", \"${name}\"] { fileinto \"Yes\"; } else { fileinto \"No\"; }\n"
	exts := []string{"fileinto", "mailbox", "variables"}
	known := map[string]bool{"Exists": true, "Other": true}

	for _, tc := range []struct {
		name   string
		check  func(context.Context, string) (bool, error)
		second string
		want   string
	}{
		{name: "all exist", check: lookup(known), second: "Other", want: "Yes"},
		{name: "one missing", check: lookup(known), second: "Missing", want: "No"},
		{name: "no mailstore", second: "Missing", want: "Yes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executor, err := NewSieveExecutorWithExtensions(
				"require \"variables\";\nset \"name\" \""+tc.second+"\";\n"+script, exts)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			result, err := executor.Evaluate(context.Background(), Context{
				EnvelopeFrom:  "sender@example.com",
				EnvelopeTo:    "user@example.com",
				Header:        map[string][]string{"From": {"sender@example.com"}},
				Message:       bodyOnly("body"),
				MailboxExists: tc.check,
			})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if len(result.Mailboxes) != 1 || result.Mailboxes[0] != tc.want {
				t.Errorf("filed into %q, want [%s]", result.Mailboxes, tc.want)
			}
		})
	}

	t.Run("a mailstore error fails the script", func(t *testing.T) {
		executor, err := NewSieveExecutorWithExtensions(script, exts)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		_, err = executor.Evaluate(context.Background(), Context{
			EnvelopeFrom: "sender@example.com",
			EnvelopeTo:   "user@example.com",
			Header:       map[string][]string{"From": {"sender@example.com"}},
			Message:      bodyOnly("body"),
			MailboxExists: func(context.Context, string) (bool, error) {
				return false, errors.New("database down")
			},
		})
		if err == nil {
			t.Errorf("a failed lookup must be an evaluation error (the message is kept), not a false test")
		}
	})
}

func lookup(known map[string]bool) func(context.Context, string) (bool, error) {
	return func(_ context.Context, name string) (bool, error) { return known[name], nil }
}
