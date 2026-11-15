package delivery

import (
	"bytes"
	"context"
	"fmt"
	"mime"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
)

// VacationHandler interface defines the contract for handling vacation responses.
type VacationHandler interface {
	HandleVacationResponse(ctx context.Context, AccountID int64, reply sieveengine.VacationReply, fromAddr *server.Address, toAddress *server.Address, originalMessage *message.Entity) error
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
	// IsAnyOwnedAddress reports whether any of `addresses` is a credential of
	// `accountID`, in one lookup. It decides the RFC 5230 §4.5 personal message check,
	// which asks about every recipient of the original message. When nil, that check
	// is skipped.
	IsAnyOwnedAddress func(ctx context.Context, accountID int64, addresses []string) (bool, error)
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

// personalMessageFields are the header fields RFC 5230 §4.5 looks for the recipient in:
// "Vacation" MUST NOT respond to a message unless the recipient user's email address is
// in a "To", "Cc", "Bcc", "Resent-To", "Resent-Cc", or "Resent-Bcc" line of the original
// message.
var personalMessageFields = []string{"To", "Cc", "Bcc", "Resent-To", "Resent-Cc", "Resent-Bcc"}

// recipientIsAddressed reports whether one of the recipient's addresses appears in the
// message's personalMessageFields (RFC 5230 §4.5 "personal message" rule). It prevents
// auto-replying to mail the user received only via a stripped Bcc, or via an alias/list
// not named there — classic backscatter. The recipient's addresses are those the account
// owns (ownership, not a literal match, so aliases and plus-addressed recipients count)
// and the script's :addresses. Returns an error only if the ownership lookup fails.
func (h *StandardVacationHandler) recipientIsAddressed(ctx context.Context, accountID int64, scriptAddresses []string, originalMessage *message.Entity) (bool, error) {
	var recipients []*mail.Address
	for _, field := range personalMessageFields {
		// Every occurrence: a message resent more than once has one set of Resent-*
		// fields per resending (RFC 5322 §3.6.6), and §4.5 asks for "a" matching line.
		for _, value := range originalMessage.Header.Values(field) {
			if list, err := mail.ParseAddressList(value); err == nil {
				recipients = append(recipients, list...)
			}
		}
	}
	// The :addresses are a string comparison; try them all before any recipient
	// costs an ownership query.
	for _, a := range recipients {
		for _, own := range scriptAddresses {
			if strings.EqualFold(strings.TrimSpace(own), a.Address) {
				return true, nil
			}
		}
	}
	// Check every address as written and in its base form (without +detail), in one
	// lookup. Credentials are stored without plus-addressing detail, and a
	// plus-addressed or aliased recipient is still a personal recipient — so jane+tag@
	// must not be suppressed.
	candidates := make([]string, 0, 2*len(recipients))
	for _, a := range recipients {
		candidates = append(candidates, a.Address)
		if parsed, err := server.NewAddress(a.Address); err == nil {
			candidates = append(candidates, parsed.BaseAddress())
		}
	}
	if len(candidates) == 0 {
		return false, nil
	}
	slices.Sort(candidates)
	return h.IsAnyOwnedAddress(ctx, accountID, slices.Compact(candidates))
}

// maxVacationSubjectCodePoints caps the reply's Subject. Without :subject it carries the
// sender's original subject, which can be as long as the original's header block; RFC
// 3834 §3.1.5 asks for "contents of the Subject field (or a portion thereof)". Pigeonhole
// keeps the same 256 code points (SIEVE_MAX_SUBJECT_HEADER_CODEPOINTS).
const maxVacationSubjectCodePoints = 256

// truncateCodePoints returns s cut to at most n code points, never inside one.
func truncateCodePoints(s string, n int) string {
	for i := range s {
		if n == 0 {
			return s[:i]
		}
		n--
	}
	return s
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

// replyReferences returns the msg-ids of a reply's References field per RFC 5322
// §3.6.4: the parent's References (if any), or its In-Reply-To when that holds a
// single msg-id and there is no References, followed by the parent's Message-ID (if
// any). Only the ids that parse are carried over, so a malformed tail in the parent
// cannot put a malformed id on the wire; the header writer folds a long list.
func replyReferences(parent mail.Header) []string {
	refs, _ := parent.MsgIDList("References")
	if len(refs) == 0 {
		if inReplyTo, _ := parent.MsgIDList("In-Reply-To"); len(inReplyTo) == 1 {
			refs = inReplyTo
		}
	}
	if id, _ := parent.MessageID(); id != "" {
		refs = append(refs, id)
	}
	return refs
}

// HandleVacationResponse handles vacation auto-response.
func (h *StandardVacationHandler) HandleVacationResponse(ctx context.Context, AccountID int64, reply sieveengine.VacationReply, fromAddr *server.Address, toAddress *server.Address, originalMessage *message.Entity) error {
	if h.RelayHandler == nil && h.RelayQueue == nil {
		h.log("[VACATION] external relay not configured, cannot send vacation response")
		return nil
	}

	// RFC 5230 §4.5: never auto-reply to bounces, other auto-responders, or list mail.
	if reason := shouldSuppressVacation(fromAddr, originalMessage); reason != "" {
		h.log("[VACATION] suppressed: %s", reason)
		return nil
	}

	// RFC 5230 §4.5: only auto-reply to "personal" mail — one of the recipient's
	// addresses must appear in To/Cc/Bcc/Resent-*. Avoids backscatter to Bcc'd or
	// list/alias mail the user wasn't directly addressed on. On lookup error, fail open
	// and proceed (the null-sender/Auto-Submitted/per-sender-period protections still apply).
	if h.IsAnyOwnedAddress != nil {
		addressed, err := h.recipientIsAddressed(ctx, AccountID, reply.Addresses, originalMessage)
		if err != nil {
			h.log("[VACATION] recipient ownership check failed, proceeding: %v", err)
		} else if !addressed {
			h.log("[VACATION] suppressed: no recipient address in To/Cc/Bcc/Resent-* (not a personal message)")
			return nil
		}
	}

	// Create vacation response message. A user-supplied ":from" is honored only if it
	// is an address the account owns; otherwise fall back to the delivered-to address.
	vacationFrom := toAddress.FullAddress()
	if owned := h.resolveVacationFrom(ctx, AccountID, reply.From); owned != "" {
		vacationFrom = owned
	}

	// The interpreter supplies the :subject or the RFC 5230 §5.3 default ("Auto: " and
	// the original subject); the fixed subject is for a reply built without one.
	vacationSubject := "Automated reply"
	if reply.Subject != "" {
		vacationSubject = truncateCodePoints(reply.Subject, maxVacationSubjectCodePoints)
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
	// RFC 3834 §3.1.8: discourage pre-RFC 3834 responders from answering the reply;
	// "bulk" is what Pigeonhole sends on every vacation reply.
	msgHeader.Set("Precedence", "bulk")
	msgHeader.Set("X-Auto-Response-Suppress", "All")
	// Attribute the script to its owning account even when :from selects an alias.
	msgHeader.Set(helpers.RedirectedByHeader, toAddress.FullAddress())
	msgHeader.Set("Date", time.Now().Format(time.RFC1123Z))

	// MessageID() and MsgIDList() return bare ids; In-Reply-To/References msg-ids
	// require angle brackets (RFC 5322 §3.6.4) for clients to thread the reply.
	originalHeader := mail.Header{Header: originalMessage.Header}
	if originalMessageID, _ := originalHeader.MessageID(); originalMessageID != "" {
		msgHeader.Set("In-Reply-To", "<"+originalMessageID+">")
	}
	if refs := replyReferences(originalHeader); len(refs) > 0 {
		msgHeader.Set("References", "<"+strings.Join(refs, "> <")+">")
	}

	if reply.IsMime {
		if err := writeVacationMIME(&vacationMessage, msgHeader, reply.Body); err != nil {
			h.log("[VACATION] not sending: %v", err)
			return err
		}
	} else {
		msgHeader.Set("Content-Type", "text/plain; charset=utf-8")
		w, err := message.CreateWriter(&vacationMessage, msgHeader)
		if err != nil {
			return err
		}
		if _, err := w.Write([]byte(reply.Body)); err != nil {
			w.Close()
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
	}

	// Atomically consume the RFC 5230 :days window now, after suppression checks
	// and message construction but before relay handoff. Multiple evaluations can
	// have passed the earlier allowance check; only this claim's winner may reply.
	// A failed or ambiguous claim blocks the reply. An enqueue failure still leaves
	// the period consumed, preventing duplicates if its outcome was uncertain.
	if reply.ClaimResponse != nil {
		claimed, err := reply.ClaimResponse(ctx)
		if err != nil {
			h.log("[VACATION] not sending: %v", err)
			return err
		}
		if !claimed {
			h.log("[VACATION] suppressed: another delivery consumed the response period")
			return nil
		}
	}

	// Send via external relay or queue, from the null reverse-path. RFC 5230 §5.1: "The
	// SMTP MAIL FROM address of the message envelope SHOULD be set to <>"; a bounce of
	// the reply then goes nowhere, instead of to the user (RFC 3834 §3.3).
	//
	// A failure from here on is lost for the rest of the :days window, and the session
	// trace (h.log) is debug-level on both LMTP and the Admin API, so it is also
	// reported at Warn where an operator sees it.
	const nullReversePath = ""
	if h.RelayQueue != nil {
		// Queue for background delivery with retry
		if err := h.RelayQueue.Enqueue(nullReversePath, fromAddr.FullAddress(), "vacation", vacationMessage.Bytes()); err != nil {
			h.log("[VACATION] Failed to enqueue vacation response: %v", err)
			logger.Warn("Sieve vacation reply could not be queued; the response period is consumed",
				"account_id", AccountID, "sender", fromAddr.FullAddress(), "error", err)
			return err
		}
		if h.RelayNotify != nil {
			h.RelayNotify()
		}
		return nil
	} else if h.RelayHandler != nil {
		if err := h.RelayHandler.SendToExternalRelay(nullReversePath, fromAddr.FullAddress(), vacationMessage.Bytes()); err != nil {
			h.log("[VACATION] Failed to relay vacation response: %v", err)
			logger.Warn("Sieve vacation reply could not be relayed; the response period is consumed",
				"account_id", AccountID, "sender", fromAddr.FullAddress(), "error", err)
			return err
		}
		return nil
	}

	return nil
}
