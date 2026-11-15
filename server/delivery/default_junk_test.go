package delivery

import (
	"context"
	"testing"

	"github.com/migadu/sora/server/sieveengine"
)

// TestDefaultJunkIndex runs the real default script: its spam filing is the one
// ResolveDefaultJunk points at the \Junk mailbox (issue #987), and its +detail
// filing, even to a +junk address, keeps going by name. A change to default.sieve
// that moved the spam filing off this shape would leave spam filed by name again.
func TestDefaultJunkIndex(t *testing.T) {
	compiled, err := sieveengine.CompileScript(DefaultSieveScript, sieveengine.EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile the default script: %v", err)
	}
	cases := []struct {
		name   string
		rcpt   string
		header map[string][]string
		want   int
	}{
		{name: "spam", rcpt: "user@example.com", header: map[string][]string{"X-Spam": {"Yes"}}, want: 0},
		{name: "spam to a +detail address", rcpt: "user+receipts@example.com", header: map[string][]string{"X-Spam": {"Yes"}}, want: 0},
		{name: "+junk detail", rcpt: "user+Junk@example.com", want: -1},
		{name: "plain", rcpt: "user@example.com", want: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := map[string][]string{"From": {"sender@example.com"}, "To": {tc.rcpt}, "Subject": {"A message"}}
			for k, v := range tc.header {
				header[k] = v
			}
			result, err := compiled.NewExecutor(1, nil, nil, 0, 0, 0).Evaluate(context.Background(), sieveengine.Context{
				EnvelopeFrom: "sender@example.com",
				EnvelopeTo:   tc.rcpt,
				Header:       header,
				Message:      []byte("From: sender@example.com\r\nTo: " + tc.rcpt + "\r\nSubject: A message\r\n\r\nHello.\r\n"),
			})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if got := defaultJunkIndex(result); got != tc.want {
				t.Errorf("defaultJunkIndex = %d, want %d (mailboxes %v, create %v)", got, tc.want, result.Mailboxes, result.CreateMailboxes)
			}
		})
	}
}
