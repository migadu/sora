package delivery

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
)

// captureRelayQueue records what HandleVacationResponse enqueues so the produced
// message and envelope can be inspected.
type captureRelayQueue struct{ calls []capturedRelay }

type capturedRelay struct {
	from, to, msgType string
	body              []byte
}

func (q *captureRelayQueue) Enqueue(from, to, msgType string, body []byte) error {
	q.calls = append(q.calls, capturedRelay{from, to, msgType, body})
	return nil
}

func vacAddr(t *testing.T, s string) *server.Address {
	t.Helper()
	a, err := server.NewAddress(s)
	if err != nil {
		t.Fatalf("NewAddress(%q): %v", s, err)
	}
	return &a
}

// TestHandleVacationResponse exercises the consolidated vacation handler end-to-end
// (the path now shared by LMTP and the Admin API): ownership-constrained ":from",
// single-part body, RFC 2047 subject, RFC 5230 §4.5 suppression, and the notify hook.
func TestHandleVacationResponse(t *testing.T) {
	const owner = "jane@example.com"
	sender := vacAddr(t, "bob@external.com") // person who emailed; receives the reply
	toAddress := vacAddr(t, owner)           // the vacationing account (default From)
	ownsJane := func(_ context.Context, _ int64, addr string) (bool, error) {
		return strings.EqualFold(addr, owner), nil
	}

	t.Run("owned :from honored; single-part; encoded subject; envelope sender", func(t *testing.T) {
		rq := &captureRelayQueue{}
		notified := false
		h := &StandardVacationHandler{
			Hostname:       "mail.example.com",
			RelayQueue:     rq,
			IsOwnedAddress: ownsJane,
			RelayNotify:    func() { notified = true },
		}
		result := sieveengine.Result{
			VacationFrom: owner,
			VacationSubj: "Réponse: Out of Office",
			VacationMsg:  "I am away.",
		}
		orig := makeMessage(map[string]string{"From": "bob@external.com", "To": owner, "Message-ID": "<orig@external.com>"})

		if err := h.HandleVacationResponse(context.Background(), 1, result, sender, toAddress, orig); err != nil {
			t.Fatalf("HandleVacationResponse: %v", err)
		}
		if len(rq.calls) != 1 {
			t.Fatalf("expected 1 enqueue, got %d", len(rq.calls))
		}
		call := rq.calls[0]
		if call.from != owner {
			t.Errorf("envelope sender = %q, want %q (owned)", call.from, owner)
		}
		if call.to != "bob@external.com" {
			t.Errorf("envelope recipient = %q, want bob@external.com", call.to)
		}
		if !notified {
			t.Errorf("RelayNotify should have been called after enqueue")
		}

		ent, err := message.Read(bytes.NewReader(call.body))
		if err != nil {
			t.Fatalf("parse message: %v", err)
		}
		if got := ent.Header.Get("From"); got != owner {
			t.Errorf("From header = %q, want %q", got, owner)
		}
		if ent.MultipartReader() != nil {
			t.Errorf("vacation message must not be multipart")
		}
		if got := ent.Header.Get("Auto-Submitted"); got != "auto-replied" {
			t.Errorf("Auto-Submitted = %q, want auto-replied", got)
		}
		// In-Reply-To / References must carry angle brackets (RFC 5322 §3.6.4) so the
		// reply threads to the original.
		if got := ent.Header.Get("In-Reply-To"); got != "<orig@external.com>" {
			t.Errorf("In-Reply-To = %q, want <orig@external.com>", got)
		}
		if got := ent.Header.Get("References"); got != "<orig@external.com>" {
			t.Errorf("References = %q, want <orig@external.com>", got)
		}
		if raw := ent.Header.Get("Subject"); !strings.Contains(raw, "=?") {
			t.Errorf("non-ASCII Subject should be RFC 2047-encoded on the wire, got %q", raw)
		}
		decoded := mail.Header{Header: ent.Header}
		if subj, _ := decoded.Subject(); subj != "Réponse: Out of Office" {
			t.Errorf("decoded Subject = %q, want %q", subj, "Réponse: Out of Office")
		}
	})

	t.Run("unowned :from falls back to default From (no spoofing)", func(t *testing.T) {
		rq := &captureRelayQueue{}
		h := &StandardVacationHandler{Hostname: "m", RelayQueue: rq, IsOwnedAddress: ownsJane}
		result := sieveengine.Result{VacationFrom: "ceo@victim.com", VacationMsg: "away"}
		orig := makeMessage(map[string]string{"From": "bob@external.com", "To": owner})

		if err := h.HandleVacationResponse(context.Background(), 1, result, sender, toAddress, orig); err != nil {
			t.Fatalf("HandleVacationResponse: %v", err)
		}
		if len(rq.calls) != 1 {
			t.Fatalf("expected 1 enqueue, got %d", len(rq.calls))
		}
		if rq.calls[0].from != owner {
			t.Errorf("unowned :from should fall back to %q, got %q", owner, rq.calls[0].from)
		}
	})

	t.Run("RFC 5230 §4.5: account in Cc only -> reply", func(t *testing.T) {
		rq := &captureRelayQueue{}
		h := &StandardVacationHandler{Hostname: "m", RelayQueue: rq, IsOwnedAddress: ownsJane}
		result := sieveengine.Result{VacationMsg: "away"}
		// Owner not in To, but present in Cc — still a personal message.
		orig := makeMessage(map[string]string{"From": "bob@external.com", "To": "team@example.com", "Cc": owner})

		if err := h.HandleVacationResponse(context.Background(), 1, result, sender, toAddress, orig); err != nil {
			t.Fatalf("HandleVacationResponse: %v", err)
		}
		if len(rq.calls) != 1 {
			t.Fatalf("expected 1 enqueue (Cc counts), got %d", len(rq.calls))
		}
	})

	t.Run("RFC 5230 §4.5: plus-addressed recipient counts -> reply", func(t *testing.T) {
		rq := &captureRelayQueue{}
		h := &StandardVacationHandler{Hostname: "m", RelayQueue: rq, IsOwnedAddress: ownsJane}
		result := sieveengine.Result{VacationMsg: "away"}
		// ownsJane only owns the base address; the To carries a +detail recipient, which
		// must still be recognized as personal mail after base-address normalization.
		orig := makeMessage(map[string]string{"From": "bob@external.com", "To": "jane+newsletter@example.com"})

		if err := h.HandleVacationResponse(context.Background(), 1, result, sender, toAddress, orig); err != nil {
			t.Fatalf("HandleVacationResponse: %v", err)
		}
		if len(rq.calls) != 1 {
			t.Fatalf("expected 1 enqueue (plus-addressing counts), got %d", len(rq.calls))
		}
	})

	t.Run("RFC 5230 §4.5: account not in To/Cc -> no reply (backscatter)", func(t *testing.T) {
		rq := &captureRelayQueue{}
		h := &StandardVacationHandler{Hostname: "m", RelayQueue: rq, IsOwnedAddress: ownsJane}
		result := sieveengine.Result{VacationMsg: "away"}
		// Delivered to the account (Bcc / alias expansion), but the account's address
		// appears in neither To nor Cc — auto-replying here is backscatter.
		orig := makeMessage(map[string]string{"From": "bob@external.com", "To": "list@example.com"})

		if err := h.HandleVacationResponse(context.Background(), 1, result, sender, toAddress, orig); err != nil {
			t.Fatalf("HandleVacationResponse: %v", err)
		}
		if len(rq.calls) != 0 {
			t.Errorf("expected suppression for non-personal mail (0 enqueues), got %d", len(rq.calls))
		}
	})

	t.Run("RFC 5230 suppression: Auto-Submitted original -> no reply", func(t *testing.T) {
		rq := &captureRelayQueue{}
		h := &StandardVacationHandler{Hostname: "m", RelayQueue: rq, IsOwnedAddress: ownsJane}
		result := sieveengine.Result{VacationMsg: "away"}
		orig := makeMessage(map[string]string{"From": "bob@external.com", "Auto-Submitted": "auto-replied"})

		if err := h.HandleVacationResponse(context.Background(), 1, result, sender, toAddress, orig); err != nil {
			t.Fatalf("HandleVacationResponse: %v", err)
		}
		if len(rq.calls) != 0 {
			t.Errorf("expected suppression (0 enqueues), got %d", len(rq.calls))
		}
	})
}
