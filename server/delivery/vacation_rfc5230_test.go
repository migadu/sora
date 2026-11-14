package delivery

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-message"
	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/server/sieveengine"
)

// TestVacationReplyHasNullEnvelopeSender is issue #326 (2). RFC 5230 §5.1: "The SMTP
// MAIL FROM address of the message envelope SHOULD be set to <>." It used to be the
// user's address, so bounces of the auto-reply went back to the user.
func TestVacationReplyHasNullEnvelopeSender(t *testing.T) {
	const owner = "jane@example.com"
	owns := func(_ context.Context, _ int64, addr string) (bool, error) {
		return strings.EqualFold(addr, owner), nil
	}
	original := makeMessage(map[string]string{"From": "bob@example.org", "To": owner, "Subject": "Hello"})
	reply := sieveengine.VacationReply{From: owner, Body: "I am away."}

	t.Run("relay queue", func(t *testing.T) {
		rq := &captureRelayQueue{}
		h := &StandardVacationHandler{Hostname: "mail.example.com", RelayQueue: rq, IsOwnedAddress: owns}
		if err := h.HandleVacationResponse(context.Background(), 1, reply, vacAddr(t, "bob@example.org"), vacAddr(t, owner), original); err != nil {
			t.Fatalf("HandleVacationResponse: %v", err)
		}
		if len(rq.calls) != 1 {
			t.Fatalf("expected 1 enqueue, got %d", len(rq.calls))
		}
		if rq.calls[0].from != "" {
			t.Errorf("envelope sender = %q, want the null reverse-path", rq.calls[0].from)
		}
	})

	t.Run("SMTP relay", func(t *testing.T) {
		backend := &vacationSMTPBackend{messages: make(chan vacationSMTPMessage, 1)}
		smtpServer := smtp.NewServer(backend)
		smtpServer.Domain = "relay.example.com"
		smtpServer.ReadTimeout = 5 * time.Second
		smtpServer.WriteTimeout = 5 * time.Second
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { smtpServer.Close() })
		go smtpServer.Serve(listener)

		h := &StandardVacationHandler{
			Hostname:       "mail.example.com",
			RelayHandler:   &SMTPRelayHandler{SMTPHost: listener.Addr().String()},
			IsOwnedAddress: owns,
		}
		if err := h.HandleVacationResponse(context.Background(), 1, reply, vacAddr(t, "bob@example.org"), vacAddr(t, owner), original); err != nil {
			t.Fatalf("relay rejected the vacation reply: %v", err)
		}
		select {
		case received := <-backend.messages:
			if received.from != "" || received.to != "bob@example.org" {
				t.Errorf("reply envelope = <%s> -> <%s>, want <> -> <bob@example.org>", received.from, received.to)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("relay did not receive the vacation reply")
		}
	})
}

// TestVacationPersonalMessageHeaders is issue #326 (1) for the header fields. RFC 5230
// §4.5: "Vacation" MUST NOT respond to a message unless the recipient user's email
// address is in a "To", "Cc", "Bcc", "Resent-To", "Resent-Cc", or "Resent-Bcc" line
// of the original message. Only To and Cc used to be looked at.
func TestVacationPersonalMessageHeaders(t *testing.T) {
	const owner = "jane@example.com"
	owns := func(_ context.Context, _ int64, addr string) (bool, error) {
		return strings.EqualFold(addr, owner), nil
	}
	for _, field := range []string{"To", "Cc", "Bcc", "Resent-To", "Resent-Cc", "Resent-Bcc"} {
		t.Run(field, func(t *testing.T) {
			rq := &captureRelayQueue{}
			h := &StandardVacationHandler{Hostname: "mail.example.com", RelayQueue: rq, IsOwnedAddress: owns}
			headers := map[string]string{"From": "bob@example.org", "Subject": "Hello"}
			if field != "To" {
				headers["To"] = "list@example.net"
			}
			headers[field] = owner
			reply := sieveengine.VacationReply{Body: "I am away."}
			if err := h.HandleVacationResponse(context.Background(), 1, reply, vacAddr(t, "bob@example.org"), vacAddr(t, owner), makeMessage(headers)); err != nil {
				t.Fatalf("HandleVacationResponse: %v", err)
			}
			if len(rq.calls) != 1 {
				t.Errorf("the owner in %s makes the message personal: expected 1 reply, got %d", field, len(rq.calls))
			}
		})
	}
}

// TestVacationScriptAddressesArePersonal is issue #326 (1): an address the script
// lists in :addresses belongs to the recipient for the personal message check (RFC
// 5230 §4.5, item 3), compared without regard to case.
func TestVacationScriptAddressesArePersonal(t *testing.T) {
	const owner = "jane@example.com"
	owns := func(_ context.Context, _ int64, addr string) (bool, error) {
		return strings.EqualFold(addr, owner), nil
	}
	original := makeMessage(map[string]string{"From": "bob@example.org", "To": "jane@example.net", "Subject": "Hello"})
	for _, tc := range []struct {
		name      string
		addresses []string
		replies   int
	}{
		{name: "listed", addresses: []string{"Jane@Example.net"}, replies: 1},
		{name: "not listed", addresses: []string{"someone@example.net"}, replies: 0},
		{name: "none", replies: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rq := &captureRelayQueue{}
			h := &StandardVacationHandler{Hostname: "mail.example.com", RelayQueue: rq, IsOwnedAddress: owns}
			reply := sieveengine.VacationReply{Body: "I am away.", Addresses: tc.addresses}
			if err := h.HandleVacationResponse(context.Background(), 1, reply, vacAddr(t, "bob@example.org"), vacAddr(t, owner), original); err != nil {
				t.Fatalf("HandleVacationResponse: %v", err)
			}
			if len(rq.calls) != tc.replies {
				t.Errorf("replies = %d, want %d", len(rq.calls), tc.replies)
			}
		})
	}
}

// TestVacationPersonalMessageEveryFieldOccurrence: a message resent more than once
// carries one block of Resent-* fields per resending, the most recent first (RFC 5322
// §3.6.6), and RFC 5230 §4.5 asks whether the recipient is in "a" Resent-To line, not
// the first one. Only the first occurrence of each field used to be read.
func TestVacationPersonalMessageEveryFieldOccurrence(t *testing.T) {
	const owner = "jane@example.com"
	owns := func(_ context.Context, _ int64, addr string) (bool, error) {
		return strings.EqualFold(addr, owner), nil
	}
	raw := strings.Join([]string{
		"Resent-From: carol@example.org",
		"Resent-To: list@example.net",
		"Resent-From: alice@example.org",
		"Resent-To: " + owner,
		"From: bob@example.org",
		"To: alice@example.org",
		"Subject: Hello",
		"",
		"body",
	}, "\r\n")
	original, err := message.Read(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse original: %v", err)
	}
	rq := &captureRelayQueue{}
	h := &StandardVacationHandler{Hostname: "mail.example.com", RelayQueue: rq, IsOwnedAddress: owns}
	reply := sieveengine.VacationReply{Body: "I am away."}
	if err := h.HandleVacationResponse(context.Background(), 1, reply, vacAddr(t, "bob@example.org"), vacAddr(t, owner), original); err != nil {
		t.Fatalf("HandleVacationResponse: %v", err)
	}
	if len(rq.calls) != 1 {
		t.Errorf("the owner in the second Resent-To makes the message personal: expected 1 reply, got %d", len(rq.calls))
	}
}
