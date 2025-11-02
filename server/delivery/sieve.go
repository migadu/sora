package delivery

import (
	"context"
	"fmt"
	"time"

	"github.com/emersion/go-message"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/sieveengine"
)

// SieveExecutor interface defines the contract for Sieve script execution.
type SieveExecutor interface {
	ExecuteSieve(ctx context.Context, recipient RecipientInfo, messageEntity *message.Entity, plaintextBody *string, fullMessageBytes []byte) (mailboxName string, discarded bool, err error)
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

// RelayQueue interface defines operations for queuing relay messages
type RelayQueue interface {
	Enqueue(from, to, messageType string, messageBytes []byte) error
}

// StandardSieveExecutor implements the standard Sieve execution flow.
type StandardSieveExecutor struct {
	DeliveryCtx     *DeliveryContext
	VacationOracle  *VacationOracle
	VacationHandler VacationHandler
	RelayHandler    RelayHandler
	RelayQueue      RelayQueue // Optional: disk-based queue for relay retry
}

// ExecuteSieve executes Sieve scripts and returns target mailbox.
// Returns: mailboxName, discarded, error
func (s *StandardSieveExecutor) ExecuteSieve(ctx context.Context, recipient RecipientInfo, messageEntity *message.Entity, plaintextBody *string, fullMessageBytes []byte) (string, bool, error) {
	// Default to INBOX
	mailboxName := consts.MailboxInbox

	// Create Sieve context
	envelopeFrom := ""
	if recipient.FromAddress != nil {
		envelopeFrom = recipient.FromAddress.FullAddress()
	}

	sieveCtx := sieveengine.Context{
		EnvelopeFrom: envelopeFrom,
		EnvelopeTo:   recipient.Address.FullAddress(),
		Header:       messageEntity.Header.Map(),
		Body:         *plaintextBody,
	}

	// Get user's active script
	activeScript, err := s.DeliveryCtx.RDB.GetActiveScriptWithRetry(ctx, recipient.AccountID)
	if err != nil && err != consts.ErrDBNotFound {
		// Non-critical error, continue with INBOX delivery
		return mailboxName, false, nil
	}

	var result sieveengine.Result
	if activeScript != nil {
		// Execute user script
		executor, err := sieveengine.NewSieveExecutorWithOracle(activeScript.Script, recipient.AccountID, s.VacationOracle)
		if err != nil {
			metrics.SieveExecutions.WithLabelValues(s.DeliveryCtx.MetricsLabel, "failure").Inc()
			return mailboxName, false, nil
		}

		result, err = executor.Evaluate(ctx, sieveCtx)
		if err != nil {
			metrics.SieveExecutions.WithLabelValues(s.DeliveryCtx.MetricsLabel, "failure").Inc()
			return mailboxName, false, nil
		}

		metrics.SieveExecutions.WithLabelValues(s.DeliveryCtx.MetricsLabel, "success").Inc()
	} else {
		// No script, keep in INBOX
		result = sieveengine.Result{Action: sieveengine.ActionKeep}
	}

	// Process result
	switch result.Action {
	case sieveengine.ActionDiscard:
		return "", true, nil

	case sieveengine.ActionFileInto:
		mailboxName = result.Mailbox
		if result.Copy {
			// Save to specified mailbox
			err := s.DeliveryCtx.SaveMessageToMailbox(ctx, recipient, result.Mailbox, fullMessageBytes, messageEntity, plaintextBody)
			if err != nil {
				return "", false, err
			}
			// Also save to INBOX
			mailboxName = consts.MailboxInbox
		}

	case sieveengine.ActionRedirect:
		// Handle redirect via external relay
		if recipient.FromAddress != nil {
			// Try immediate delivery first if queue is not configured
			if s.RelayQueue == nil && s.RelayHandler != nil {
				err := s.RelayHandler.SendToExternalRelay(recipient.FromAddress.FullAddress(), result.RedirectTo, fullMessageBytes)
				if err == nil && !result.Copy {
					// Successfully redirected without copy
					return "", true, nil
				}
			} else if s.RelayQueue != nil {
				// Queue for background delivery with retry
				err := s.RelayQueue.Enqueue(recipient.FromAddress.FullAddress(), result.RedirectTo, "redirect", fullMessageBytes)
				if err != nil {
					// Failed to enqueue, log error but don't fail delivery
					s.DeliveryCtx.Logger.Log("Failed to enqueue redirect message: %v", err)
				} else if !result.Copy {
					// Successfully queued for redirect without copy
					return "", true, nil
				}
			}
		}
		// Fallback or copy: deliver to INBOX
		mailboxName = consts.MailboxInbox

	case sieveengine.ActionVacation:
		// Handle vacation response
		if s.VacationHandler != nil && recipient.FromAddress != nil {
			_ = s.VacationHandler.HandleVacationResponse(ctx, recipient.AccountID, result, recipient.FromAddress, recipient.Address, messageEntity)
		}
		mailboxName = consts.MailboxInbox

	default:
		mailboxName = consts.MailboxInbox
	}

	return mailboxName, false, nil
}
