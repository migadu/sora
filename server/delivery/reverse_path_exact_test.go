package delivery

import (
	"context"
	"strings"
	"testing"

	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
)

// The vacation reply and the MAIL FROM of a relayed redirect go to the sender exactly as
// it sent the message (#2101). LMTP and the Admin API both hand this package a sender
// parsed by server.NewReversePath: go-smtp unquotes a quoted local part, the Admin API
// passes it as written. Either way the reply goes to `"John Doe"@example.com`, once
// quoted and with its case, not to `"john doe"@example.com` (another mailbox, RFC 5321
// §2.4) or to `"\"john doe\""@example.com`.
func TestQuotedSenderGetsReplyAndRedirectAtExactAddress(t *testing.T) {
	const owner = "jane@example.com"
	const want = `"John Doe"@example.com`
	for _, in := range []string{
		`"John Doe"@example.com`, // Admin API "from"
		`John Doe@example.com`,   // LMTP, as go-smtp hands MAIL FROM over
	} {
		t.Run(in, func(t *testing.T) {
			sender, err := server.NewReversePath(in)
			if err != nil {
				t.Fatalf("NewReversePath(%q): %v", in, err)
			}
			ownerAddr := vacAddr(t, owner)

			rq := &captureRelayQueue{}
			h := &StandardVacationHandler{
				Hostname:   "mail.example.com",
				RelayQueue: rq,
				IsOwnedAddress: func(_ context.Context, _ int64, addr string) (bool, error) {
					return strings.EqualFold(addr, owner), nil
				},
			}
			orig := makeMessage(map[string]string{"From": want, "To": owner, "Message-ID": "<orig@example.com>"})
			if err := h.HandleVacationResponse(context.Background(), 1, sieveengine.VacationReply{Body: "I am away."}, &sender, ownerAddr, orig); err != nil {
				t.Fatalf("HandleVacationResponse: %v", err)
			}
			if len(rq.calls) != 1 || rq.calls[0].to != want {
				t.Fatalf("vacation replies to %q, want one to %s", relayed(rq, func(c capturedRelay) string { return c.to }), want)
			}
			if !strings.Contains(string(rq.calls[0].body), "\r\nTo: "+want+"\r\n") {
				t.Errorf("vacation reply To: is not %s:\n%s", want, rq.calls[0].body)
			}

			rq = &captureRelayQueue{}
			commit, abort, allHeld := RedirectHold{
				Queue:        rq,
				Log:          &captureRedirectLog{},
				AccountID:    1,
				From:         &sender,
				Owner:        ownerAddr,
				MessageBytes: []byte("Subject: x\r\n\r\nbody\r\n"),
			}.Hold(context.Background(), sieveengine.Result{Action: sieveengine.ActionRedirect, RedirectTo: []string{"fwd@example.net"}})
			defer abort()
			if !allHeld || !commit() {
				t.Fatalf("redirect not handed over")
			}
			if len(rq.calls) != 1 || rq.calls[0].from != want {
				t.Fatalf("redirects relayed with MAIL FROM %q, want one with %s", relayed(rq, func(c capturedRelay) string { return c.from }), want)
			}
		})
	}
}

func relayed(q *captureRelayQueue, field func(capturedRelay) string) []string {
	var out []string
	for _, c := range q.calls {
		out = append(out, field(c))
	}
	return out
}
