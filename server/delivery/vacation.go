package delivery

import (
	"bytes"
	"context"
	"fmt"
	"mime"
	"time"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/helpers"
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
// vacation auto-replies, returning a non-empty reason if a reply must NOT be sent.
// It delegates to the shared helpers.ShouldSuppressAuto.
func shouldSuppressVacation(sender *server.Address, originalMessage *message.Entity) string {
	envFrom := ""
	if sender != nil {
		envFrom = sender.FullAddress()
	}

	headerGet := func(k string) []string {
		if val := originalMessage.Header.Get(k); val != "" {
			return []string{val}
		}
		return nil
	}

	return helpers.ShouldSuppressAuto(envFrom, headerGet)
}

// recipientIsAddressed reports whether at least one of the account's addresses appears in
// the message's To or Cc header (RFC 5230 §4.5 "personal message" rule). It prevents
// auto-replying to mail the user received only via Bcc, or via an alias/list not present
// in To/Cc — classic backscatter. Ownership (not a literal match) is used so aliases and
// plus-addressed recipients still count. Returns an error only if the ownership lookup fails.
func (h *StandardVacationHandler) recipientIsAddressed(ctx context.Context, accountID int64, originalMessage *message.Entity) (bool, error) {
	hdr := mail.Header{Header: originalMessage.Header}
	var recipients []*mail.Address
	for _, field := range []string{"To", "Cc"} {
		if list, err := hdr.AddressList(field); err == nil {
			recipients = append(recipients, list...)
		}
	}
	for _, a := range recipients {
		// Check the address as written and its base form (without +detail). Credentials
		// are stored without plus-addressing detail, and a plus-addressed or aliased
		// recipient is still a personal recipient — so jane+tag@ must not be suppressed.
		candidates := []string{a.Address}
		if parsed, err := server.NewAddress(a.Address); err == nil {
			if base := parsed.BaseAddress(); base != a.Address {
				candidates = append(candidates, base)
			}
		}
		for _, c := range candidates {
			owned, err := h.IsOwnedAddress(ctx, accountID, c)
			if err != nil {
				return false, err
			}
			if owned {
				return true, nil
			}
		}
	}
	return false, nil
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

	// RFC 5230 §4.5: only auto-reply to "personal" mail — at least one of the account's
	// addresses must appear in To/Cc. Avoids backscatter to Bcc'd or list/alias mail the
	// user wasn't directly addressed on. On lookup error, fail open and proceed (the
	// null-sender/Auto-Submitted/per-sender-period protections still apply).
	if h.IsOwnedAddress != nil {
		addressed, err := h.recipientIsAddressed(ctx, AccountID, originalMessage)
		if err != nil {
			h.log("[VACATION] To/Cc ownership check failed, proceeding: %v", err)
		} else if !addressed {
			h.log("[VACATION] suppressed: account address not in To/Cc (not a personal message)")
			return nil
		}
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
