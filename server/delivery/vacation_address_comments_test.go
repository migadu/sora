package delivery

import (
	"context"
	"strings"
	"testing"

	"github.com/migadu/sora/server/sieveengine"
)

// TestVacationPersonalMessageAddressWithComments: RFC 5322 §3.4.1 lets comments and
// folding white space surround the "@" of an addr-spec, so
// "<jane (comment)@ (comment) example.com>" in To names jane@example.com, and the message
// is personal (RFC 5230 §4.5). net/mail rejects that header, and the vacation reply was
// suppressed as if the owner were not addressed at all (#2037).
func TestVacationPersonalMessageAddressWithComments(t *testing.T) {
	const owner = "jane@example.com"
	owns := func(_ context.Context, _ int64, addr string) (bool, error) {
		return strings.EqualFold(addr, owner), nil
	}
	for _, field := range []string{"To", "Cc", "Resent-To"} {
		t.Run(field, func(t *testing.T) {
			rq := &captureRelayQueue{}
			h := &StandardVacationHandler{Hostname: "mail.example.com", RelayQueue: rq, IsAnyOwnedAddress: ownsAny(owns)}
			headers := map[string]string{"From": "bob@example.org", "Subject": "Hello"}
			if field != "To" {
				headers["To"] = "list@example.net"
			}
			headers[field] = "<jane (comment)@ (comment) example.com>"
			reply := sieveengine.VacationReply{Body: "I am away."}
			if err := h.HandleVacationResponse(context.Background(), 1, reply, vacAddr(t, "bob@example.org"), vacAddr(t, owner), makeMessage(headers)); err != nil {
				t.Fatalf("HandleVacationResponse: %v", err)
			}
			if len(rq.calls) != 1 {
				t.Errorf("%s: %s names the owner: expected 1 reply, got %d", field, headers[field], len(rq.calls))
			}
		})
	}
}
