package delivery

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/sieveengine"
)

// SieveOutcome is the result of evaluating a recipient's Sieve script for one delivery.
type SieveOutcome struct {
	// MailboxName is where the delivered copy goes. Discarded means nothing is stored.
	MailboxName string
	Discarded   bool
	// Flags set by the script via imap4flags (RFC 5232), applied to every stored copy.
	Flags []imap.Flag
	// MessageBytes/MessageEntity carry the message after any header edits (RFC 5293
	// editheader); they are always set. The caller MUST hash and store THESE bytes:
	// content_hash is the S3 object key, so it has to describe the body actually written.
	MessageBytes  []byte
	MessageEntity *message.Entity
	// CopyMailbox is the `fileinto :copy` target. The caller saves it AFTER staging the
	// body locally: SaveMessageToMailbox writes a pending_uploads row, and the uploader
	// treats a pending upload whose local file is missing as permanent content loss.
	CopyMailbox string
}

// SieveExecutor interface defines the contract for Sieve script execution.
type SieveExecutor interface {
	ExecuteSieve(ctx context.Context, recipient RecipientInfo, messageEntity *message.Entity, plaintextBody *string, fullMessageBytes []byte) (*SieveOutcome, error)
}

// VacationOracle implements the sieveengine.VacationOracle interface using the database.
type VacationOracle struct {
	RDB *resilient.ResilientDatabase
}

// IsVacationResponseAllowed checks if a vacation response is allowed for the given original sender and handle.
func (o *VacationOracle) IsVacationResponseAllowed(ctx context.Context, AccountID int64, originalSender string, handle string, duration time.Duration) (bool, error) {
	hasRecent, err := o.RDB.HasRecentVacationResponseWithRetry(ctx, AccountID, originalSender, duration)
	if err != nil {
		return false, fmt.Errorf("checking db for recent vacation response: %w", err)
	}
	return !hasRecent, nil
}

// RecordVacationResponseSent records that a vacation response has been sent.
func (o *VacationOracle) RecordVacationResponseSent(ctx context.Context, AccountID int64, originalSender string, handle string) error {
	return o.RDB.RecordVacationResponseWithRetry(ctx, AccountID, originalSender)
}

// CountRedirectsSince returns the number of redirects performed by the given account within the specified duration window.
func (o *VacationOracle) CountRedirectsSince(ctx context.Context, accountID int64, window time.Duration) (int, error) {
	return o.RDB.CountRedirectsSinceWithRetry(ctx, accountID, window)
}

// RecordRedirect records that a redirect action was performed.
func (o *VacationOracle) RecordRedirect(ctx context.Context, accountID int64) error {
	return o.RDB.RecordRedirectWithRetry(ctx, accountID)
}

// RelayQueue interface defines operations for queuing relay messages
type RelayQueue interface {
	Enqueue(from, to, messageType string, messageBytes []byte) error
}

// StandardSieveExecutor implements the standard Sieve execution flow.
type StandardSieveExecutor struct {
	DeliveryCtx        *DeliveryContext
	VacationOracle     *VacationOracle
	VacationHandler    VacationHandler
	RelayHandler       RelayHandler
	RelayQueue         RelayQueue // Optional: disk-based queue for relay retry
	RedirectRateLimit  int
	RedirectRateWindow time.Duration
	MaxRedirectHops    int
	// SieveExtensions is the configured [sieve] enabled_extensions set. Empty means
	// the default set, matching how server/lmtp resolves it. Both ingress paths must
	// compile with the same set or one user script behaves differently per path.
	SieveExtensions []string
}

// sieveExtensions resolves the extension set to compile with, falling back to the
// default set exactly as server/lmtp does when nothing is configured.
func (s *StandardSieveExecutor) sieveExtensions() []string {
	if len(s.SieveExtensions) == 0 {
		return sieveengine.DefaultSieveExtensions
	}
	return s.SieveExtensions
}

// ExecuteSieve executes Sieve scripts and returns the outcome for this delivery. It
// performs the script's non-storage side effects (redirect, vacation) itself; storing
// the message — including any `fileinto :copy` target — is left to the caller, which
// must do it from SieveOutcome.MessageBytes.
func (s *StandardSieveExecutor) ExecuteSieve(ctx context.Context, recipient RecipientInfo, messageEntity *message.Entity, plaintextBody *string, fullMessageBytes []byte) (*SieveOutcome, error) {
	// Default to INBOX with the message unmodified
	outcome := &SieveOutcome{
		MailboxName:   consts.MailboxInbox,
		MessageBytes:  fullMessageBytes,
		MessageEntity: messageEntity,
	}

	// Create Sieve context
	envelopeFrom := ""
	if recipient.FromAddress != nil {
		envelopeFrom = recipient.FromAddress.FullAddress()
	}

	sieveCtx := sieveengine.Context{
		EnvelopeFrom: envelopeFrom,
		EnvelopeTo:   recipient.ToAddress.FullAddress(),
		Header:       messageEntity.Header.Map(),
		Body:         *plaintextBody,
	}

	// Get user's active script
	activeScript, err := s.DeliveryCtx.RDB.GetActiveScriptWithRetry(ctx, recipient.AccountID)
	if err != nil && err != consts.ErrDBNotFound {
		// Non-critical error, continue with INBOX delivery
		return outcome, nil
	}

	var result sieveengine.Result
	if activeScript != nil {
		// Execute user script
		// go-sieve rejects every `require` when no extension list is supplied, so an
		// unset list would silently degrade fileinto/vacation scripts to a plain INBOX
		// keep. Compile with the same configured set the LMTP path uses, so one script
		// cannot behave differently depending on which ingress delivered the message.
		compiled, err := sieveengine.SharedScriptCache().GetOrCompile(activeScript.Script, s.sieveExtensions())
		if err != nil {
			metrics.SieveExecutions.WithLabelValues(s.DeliveryCtx.MetricsLabel, "failure").Inc()
			return outcome, nil
		}
		executor := compiled.NewExecutor(recipient.AccountID, s.VacationOracle, s.VacationOracle, s.RedirectRateLimit, s.RedirectRateWindow, s.MaxRedirectHops)

		result, err = executor.Evaluate(ctx, sieveCtx)
		if err != nil {
			metrics.SieveExecutions.WithLabelValues(s.DeliveryCtx.MetricsLabel, "failure").Inc()
			return outcome, nil
		}

		metrics.SieveExecutions.WithLabelValues(s.DeliveryCtx.MetricsLabel, "success").Inc()
	} else {
		// No script, keep in INBOX
		result = sieveengine.Result{Action: sieveengine.ActionKeep}
	}

	// Apply header edits if any (RFC 5293 - editheader extension), before the caller
	// hashes and stores the body, exactly as the LMTP path does: content_hash must
	// describe the edited bytes, and every copy of this delivery - the redirected one and
	// the :copy below included - is made from them.
	if len(result.HeaderEdits) > 0 {
		edited, editErr := sieveengine.ApplyHeaderEdits(outcome.MessageBytes, result.HeaderEdits)
		if editErr != nil {
			s.DeliveryCtx.Logger.Log("Failed to apply Sieve header edits, delivering unmodified: %v", editErr)
		} else if reparsed, parseErr := message.Read(bytes.NewReader(edited)); parseErr != nil {
			// Bytes and entity must stay consistent: the entity is what the stored
			// metadata (subject, message id, body structure) is derived from.
			s.DeliveryCtx.Logger.Log("Failed to re-parse message after Sieve header edits, delivering unmodified: %v", parseErr)
		} else {
			outcome.MessageBytes = edited
			outcome.MessageEntity = reparsed
		}
	}

	// Flags set by the Sieve script via imap4flags (RFC 5232). Applied to every
	// locally stored copy of the message.
	outcome.Flags = helpers.SanitizeFlags(helpers.StringsToFlags(result.Flags))

	// Process result
	switch result.Action {
	case sieveengine.ActionDiscard:
		outcome.MailboxName = ""
		outcome.Discarded = true
		return outcome, nil

	case sieveengine.ActionFileInto:
		outcome.MailboxName = result.Mailbox
		if result.Copy {
			// Save to the specified mailbox as well. Deferred to the caller, which does it
			// once the body has been staged locally (see SieveOutcome.CopyMailbox).
			outcome.CopyMailbox = result.Mailbox
			// Also save to INBOX
			outcome.MailboxName = consts.MailboxInbox
		}

	case sieveengine.ActionRedirect:
		// Handle redirect via external relay
		if recipient.FromAddress != nil {
			// Stamp the outgoing copy with an incremented hop count (loop backstop).
			relayBytes := helpers.PrependHeaderLine(outcome.MessageBytes, helpers.RedirectLoopHeader, strconv.Itoa(helpers.RedirectHopCount(helpers.HeaderGetter(outcome.MessageEntity.Header.Map()))+1))
			// Try immediate delivery first if queue is not configured
			if s.RelayQueue == nil && s.RelayHandler != nil {
				err := s.RelayHandler.SendToExternalRelay(recipient.FromAddress.FullAddress(), result.RedirectTo, relayBytes)
				if err == nil && !result.Copy {
					// Successfully redirected without copy
					outcome.MailboxName = ""
					outcome.Discarded = true
					return outcome, nil
				}
			} else if s.RelayQueue != nil {
				// Queue for background delivery with retry
				err := s.RelayQueue.Enqueue(recipient.FromAddress.FullAddress(), result.RedirectTo, "redirect", relayBytes)
				if err != nil {
					// Failed to enqueue, log error but don't fail delivery
					s.DeliveryCtx.Logger.Log("Failed to enqueue redirect message: %v", err)
				} else if !result.Copy {
					// Successfully queued for redirect without copy
					outcome.MailboxName = ""
					outcome.Discarded = true
					return outcome, nil
				}
			}
		}
		// Fallback or copy: deliver to INBOX
		outcome.MailboxName = consts.MailboxInbox

	case sieveengine.ActionVacation:
		// Handle vacation response
		if s.VacationHandler != nil && recipient.FromAddress != nil {
			_ = s.VacationHandler.HandleVacationResponse(ctx, recipient.AccountID, result, recipient.FromAddress, recipient.Address, outcome.MessageEntity)
		}
		outcome.MailboxName = consts.MailboxInbox

	default:
		outcome.MailboxName = consts.MailboxInbox
	}

	return outcome, nil
}
