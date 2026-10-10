package sieveengine

import (
	"context"
	"testing"
)

// An address test must see through a bare angle-addr: To: <user@example.com>
// is a valid mailbox (RFC 5322 §3.4, the display name is optional) and is how
// bulk mail addresses the recipient. go-sieve before v1.4.2 compared it as the
// literal "<user@example.com>", so a user's "spam to my address -> Trash" rule
// never fired and the message stayed in Junk. A non-ASCII local part, which
// LMTP accepts under SMTPUTF8, must match the same way.
func TestAddressTestMatchesBareAngleAddr(t *testing.T) {
	script := `
require ["fileinto"];
if address :is ["to", "cc"] ["user@example.com", "josé@example.com"] {
	fileinto "Trash";
	stop;
}
`
	compiled, err := CompileScript(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	for _, tc := range []struct {
		name   string
		header map[string][]string
		want   Action
	}{
		{"bare angle-addr", map[string][]string{"To": {"<user@example.com>"}}, ActionFileInto},
		{"bare angle-addr in Cc", map[string][]string{"To": {"other@example.com"}, "Cc": {"<user@example.com>"}}, ActionFileInto},
		{"bare angle-addr, non-ASCII local part", map[string][]string{"To": {"<josé@example.com>"}}, ActionFileInto},
		{"display name", map[string][]string{"To": {"User <user@example.com>"}}, ActionFileInto},
		{"another recipient", map[string][]string{"To": {"<other@example.com>"}}, ActionKeep},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := compiled.NewExecutor(1, nil, nil, 0, 0, 0).Evaluate(context.Background(), Context{
				EnvelopeFrom: "sender@example.com",
				EnvelopeTo:   "user@example.com",
				Header:       tc.header,
				Message:      bodyOnly("Test message body"),
			})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if result.Action != tc.want {
				t.Errorf("action = %s (mailbox %q), want %s", result.Action, result.Mailbox, tc.want)
			}
		})
	}
}
