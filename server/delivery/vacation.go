package delivery

import (
	"bytes"
	"context"
	"fmt"
	"mime"
	"strings"
	"time"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
)

// VacationHandler interface defines the contract for handling vacation responses.
type VacationHandler interface {
	HandleVacationResponse(ctx context.Context, AccountID int64, result sieveengine.Result, fromAddr *server.Address, toAddress *server.Address, originalMessage *message.Entity) error
}

// StandardVacationHandler implements the standard vacation response handling.
type StandardVacationHandler struct {
	Hostname     string
	RelayHandler RelayHandler
	RelayQueue   RelayQueue // Optional: disk-based queue for relay retry
	Logger       Logger
	// IsOwnedAddress reports whether `address` is a credential of `accountID`. It is
	// used to constrain a user-supplied SIEVE vacation ":from" to an address the
	// account owns (RFC 5230 §4.4). When nil, any non-empty ":from" is ignored.
	IsOwnedAddress func(ctx context.Context, accountID int64, address string) (bool, error)
	// RelayNotify, when set, is called after a vacation response is successfully
	// enqueued, so a relay worker can process it immediately instead of on its next
	// poll. Optional.
	RelayNotify func()
}

// shouldSuppressVacation implements RFC 5230 §4.5 mandatory suppression rules for
// vacation auto-replies, returning a non-empty reason if a reply must NOT be sent:
//   - null/empty sender (MAIL FROM:<>): bounce/DSN messages never get replies
//   - Auto-Submitted (not "no"): messages from other auto-responders → loop risk
//   - Precedence bulk/junk/list: mailing lists / mass mailings
//   - List-Id present (RFC 2919): additional mailing-list safety net
func shouldSuppressVacation(sender *server.Address, originalMessage *message.Entity) string {
	if sender == nil || sender.FullAddress() == "" {
		return "null or empty sender (bounce message)"
	}
	if autoSubmitted := originalMessage.Header.Get("Auto-Submitted"); autoSubmitted != "" {
		if strings.ToLower(strings.TrimSpace(autoSubmitted)) != "no" {
			return fmt.Sprintf("Auto-Submitted: %s", autoSubmitted)
		}
	}
	if precedence := originalMessage.Header.Get("Precedence"); precedence != "" {
		p := strings.ToLower(strings.TrimSpace(precedence))
		if p == "bulk" || p == "junk" || p == "list" {
			return fmt.Sprintf("Precedence: %s", precedence)
		}
	}
	if listID := originalMessage.Header.Get("List-Id"); listID != "" {
		return fmt.Sprintf("List-Id: %s", listID)
	}
	return ""
}

// log emits a message via the optional Logger.
func (h *StandardVacationHandler) log(format string, args ...any) {
	if h.Logger != nil {
		h.Logger.Log(format, args...)
	}
}

// resolveVacationFrom returns a validated, account-owned ":from" address to use, or
// "" to signal the caller should fall back to the default. A user-supplied ":from"
// must parse as an address and be a credential of the account; otherwise it is
// ignored to prevent the auto-reply from spoofing an arbitrary sender/return-path.
func (h *StandardVacationHandler) resolveVacationFrom(ctx context.Context, accountID int64, candidate string) string {
	if candidate == "" {
		return ""
	}
	addr, err := server.NewAddress(candidate)
	if err != nil {
		h.log("[VACATION] ignoring malformed :from %q: %v", candidate, err)
		return ""
	}
	if h.IsOwnedAddress == nil {
		h.log("[VACATION] ignoring :from %q: ownership check unavailable", candidate)
		return ""
	}
	owned, err := h.IsOwnedAddress(ctx, accountID, addr.FullAddress())
	if err != nil {
		h.log("[VACATION] ignoring :from %q: ownership check failed: %v", candidate, err)
		return ""
	}
	if !owned {
		h.log("[VACATION] ignoring :from %q not owned by account %d", candidate, accountID)
		return ""
	}
	return addr.FullAddress()
}

// HandleVacationResponse handles vacation auto-response.
func (h *StandardVacationHandler) HandleVacationResponse(ctx context.Context, AccountID int64, result sieveengine.Result, fromAddr *server.Address, toAddress *server.Address, originalMessage *message.Entity) error {
	if h.RelayHandler == nil && h.RelayQueue == nil {
		h.log("[VACATION] external relay not configured, cannot send vacation response")
		return nil
	}

	// RFC 5230 §4.5: never auto-reply to bounces, other auto-responders, or list mail.
	if reason := shouldSuppressVacation(fromAddr, originalMessage); reason != "" {
		h.log("[VACATION] suppressed: %s", reason)
		return nil
	}

	// Create vacation response message. A user-supplied ":from" is honored only if it
	// is an address the account owns; otherwise fall back to the delivered-to address.
	vacationFrom := toAddress.FullAddress()
	if owned := h.resolveVacationFrom(ctx, AccountID, result.VacationFrom); owned != "" {
		vacationFrom = owned
	}

	vacationSubject := "Auto: Out of Office"
	if result.VacationSubj != "" {
		vacationSubject = result.VacationSubj
	}

	// Build vacation message
	var vacationMessage bytes.Buffer
	var msgHeader message.Header
	msgHeader.Set("From", vacationFrom)
	msgHeader.Set("To", fromAddr.FullAddress())
	// RFC 2047-encode the subject so a non-ASCII value is a valid 7-bit header.
	msgHeader.Set("Subject", mime.QEncoding.Encode("utf-8", vacationSubject))
	msgHeader.Set("Message-ID", fmt.Sprintf("<%d.vacation@%s>", time.Now().UnixNano(), h.Hostname))
	msgHeader.Set("Auto-Submitted", "auto-replied")
	msgHeader.Set("X-Auto-Response-Suppress", "All")
	msgHeader.Set("Date", time.Now().Format(time.RFC1123Z))
	// Single-part text/plain (not multipart) — the appropriate shape for an auto-reply.
	msgHeader.Set("Content-Type", "text/plain; charset=utf-8")

	originalHeader := mail.Header{Header: originalMessage.Header}
	if originalMessageID, _ := originalHeader.MessageID(); originalMessageID != "" {
		// MessageID() returns the bare id; In-Reply-To/References msg-ids require angle
		// brackets (RFC 5322 §3.6.4) for clients to thread the reply to the original.
		msgHeader.Set("In-Reply-To", "<"+originalMessageID+">")
		msgHeader.Set("References", "<"+originalMessageID+">")
	}

	w, err := message.CreateWriter(&vacationMessage, msgHeader)
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(result.VacationMsg)); err != nil {
		w.Close()
		return err
	}
	w.Close()

	// Send via external relay or queue
	if h.RelayQueue != nil {
		// Queue for background delivery with retry
		if err := h.RelayQueue.Enqueue(vacationFrom, fromAddr.FullAddress(), "vacation", vacationMessage.Bytes()); err != nil {
			h.log("[VACATION] Failed to enqueue vacation response: %v", err)
			return err
		}
		if h.RelayNotify != nil {
			h.RelayNotify()
		}
		return nil
	} else if h.RelayHandler != nil {
		return h.RelayHandler.SendToExternalRelay(vacationFrom, fromAddr.FullAddress(), vacationMessage.Bytes())
	}

	return nil
}
