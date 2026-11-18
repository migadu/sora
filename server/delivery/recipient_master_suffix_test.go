package delivery

import (
	"context"
	"strings"
	"testing"
)

// A delivery recipient is an envelope address, not a login name: the master-token
// suffix (user@domain@SUFFIX) has no meaning in it (#1961, as LMTP RCPT in #1938). Read
// with the suffix rule, user@example.com@SUFFIX was delivered to user@example.com, and
// the unquoted form of `"a@b.example"@example.com` to a@b.example. Both are refused as
// an invalid address, before any lookup: the context has no database.
func TestLookupRecipientRefusesMasterSuffix(t *testing.T) {
	d := &DeliveryContext{}
	for _, rcpt := range []string{"user@example.com@SUFFIX", "a@b.example@example.com"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("LookupRecipient(%q) went on to the database lookup (panic: %v), want an invalid address", rcpt, r)
				}
			}()
			info, err := d.LookupRecipient(context.Background(), rcpt)
			if err == nil {
				t.Errorf("LookupRecipient(%q) = account %d, want an error", rcpt, info.AccountID)
				return
			}
			// The Admin API reports this text as the request's fault (400, not transient).
			if !strings.Contains(err.Error(), "invalid recipient address") {
				t.Errorf("LookupRecipient(%q): %v, want an invalid recipient address", rcpt, err)
			}
		}()
	}
}
