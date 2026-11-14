package delivery

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-message"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/sieveengine"
)

// DefaultSieveScript is the built-in script every delivery runs before the user's
// own: it files spam into Junk and a +detail recipient into the detail folder. Both
// delivery paths run it and merge its result with the user script's
// (MergeSieveResults), so one message is filed the same way whichever way it came.
//
//go:embed default.sieve
var DefaultSieveScript string

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
	// CreateMailbox is the fileinto :create target (RFC 5490 §3.2), MailboxName or
	// CopyMailbox: the caller creates it if no mailbox of that name exists.
	CreateMailbox string
}

// SieveExecutor interface defines the contract for Sieve script execution.
type SieveExecutor interface {
	ExecuteSieve(ctx context.Context, recipient RecipientInfo, messageEntity *message.Entity, fullMessageBytes []byte) (*SieveOutcome, error)
}

// VacationOracle implements the sieveengine.VacationOracle interface using the database.
type VacationOracle struct {
	RDB *resilient.ResilientDatabase
}

// IsVacationResponseAllowed checks if a vacation response is allowed for the given original sender and response identity.
func (o *VacationOracle) IsVacationResponseAllowed(ctx context.Context, AccountID int64, originalSender string, responseIdentity string, duration time.Duration) (bool, error) {
	hasRecent, err := o.RDB.HasRecentVacationResponseWithRetry(ctx, AccountID, originalSender, responseIdentity, duration)
	if err != nil {
		return false, fmt.Errorf("checking db for recent vacation response: %w", err)
	}
	return !hasRecent, nil
}

// ClaimVacationResponse makes the definitive suppression decision at handoff.
func (o *VacationOracle) ClaimVacationResponse(ctx context.Context, AccountID int64, originalSender, responseIdentity string, duration time.Duration) (bool, error) {
	return o.RDB.ClaimVacationResponseWithRetry(ctx, AccountID, originalSender, responseIdentity, duration)
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
	// SieveExtensions is the effective extension set, resolved once by the server
	// that builds the executor (sieveengine.EffectiveExtensions); empty means the
	// default set. Both ingress paths must compile with the same set or one user
	// script behaves differently per path.
	SieveExtensions []string
}

// sieveExtensions is the set to compile with; the resolution happened once,
// where the executor was built.
func (s *StandardSieveExecutor) sieveExtensions() []string {
	if len(s.SieveExtensions) == 0 {
		return sieveengine.DefaultSieveExtensions
	}
	return s.SieveExtensions
}

// evaluate runs one script for the recipient. A script that does not compile or
// fails at run time is a keep (RFC 5228 §2.10.6), which leaves the default script's
// result standing when merged.
func (s *StandardSieveExecutor) evaluate(ctx context.Context, recipient RecipientInfo, sieveCtx sieveengine.Context, script, source string) sieveengine.Result {
	keep := sieveengine.Result{Action: sieveengine.ActionKeep}
	// go-sieve rejects every `require` when no extension list is supplied, so an
	// unset list would silently degrade fileinto/vacation scripts to a plain INBOX
	// keep. Compile with the same configured set the LMTP path uses, so one script
	// cannot behave differently depending on which ingress delivered the message.
	compiled, err := sieveengine.SharedScriptCache().GetOrCompile(script, s.sieveExtensions())
	if err != nil {
		metrics.SieveExecutions.WithLabelValues(s.DeliveryCtx.MetricsLabel, "failure").Inc()
		s.DeliveryCtx.Logger.Log("Failed to compile the %s Sieve script: %v", source, err)
		return keep
	}
	executor := compiled.NewExecutor(recipient.AccountID, s.VacationOracle, s.VacationOracle, s.RedirectRateLimit, s.RedirectRateWindow, s.MaxRedirectHops)
	result, err := executor.Evaluate(ctx, sieveCtx)
	if err != nil {
		metrics.SieveExecutions.WithLabelValues(s.DeliveryCtx.MetricsLabel, "failure").Inc()
		s.DeliveryCtx.Logger.Log("The %s Sieve script failed: %v", source, err)
		return keep
	}
	metrics.SieveExecutions.WithLabelValues(s.DeliveryCtx.MetricsLabel, "success").Inc()
	return result
}

// ExecuteSieve executes Sieve scripts and returns the outcome for this delivery. It
// performs the script's non-storage side effects (redirect, vacation) itself; storing
// the message — including any `fileinto :copy` target — is left to the caller, which
// must do it from SieveOutcome.MessageBytes.
func (s *StandardSieveExecutor) ExecuteSieve(ctx context.Context, recipient RecipientInfo, messageEntity *message.Entity, fullMessageBytes []byte) (*SieveOutcome, error) {
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
		Message:      fullMessageBytes,
		MailboxExists: func(ctx context.Context, mailbox string) (bool, error) {
			return CanFileInto(ctx, s.DeliveryCtx.RDB, recipient.AccountID, mailbox)
		},
	}

	// The built-in default script runs first, as on LMTP, and the user's script then
	// takes the message over or keeps the default's filing (MergeSieveResults). A
	// script that fails to compile or run leaves the result before it standing.
	result := s.evaluate(ctx, recipient, sieveCtx, DefaultSieveScript, "default")
	activeScript, err := s.DeliveryCtx.RDB.GetActiveScriptWithRetry(ctx, recipient.AccountID)
	if err != nil && err != consts.ErrDBNotFound {
		s.DeliveryCtx.Logger.Log("Failed to get the active Sieve script, using the default script's result: %v", err)
	} else if activeScript != nil {
		userResult := s.evaluate(ctx, recipient, sieveCtx, activeScript.Script, "user")
		result, _ = MergeSieveResults(result, userResult)
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
	// locally stored copy of the message. Keywords that are not valid IMAP atoms
	// are dropped -- stored, they would wedge SELECT of the mailbox -- and named
	// in the log, as the LMTP path does, since the user's script line silently
	// did nothing.
	rawFlags := helpers.StringsToFlags(result.Flags)
	outcome.Flags = helpers.SanitizeFlags(rawFlags)
	if rejected := helpers.DroppedFlags(rawFlags, outcome.Flags); len(rejected) > 0 {
		s.DeliveryCtx.Logger.Log("Sieve set invalid IMAP keywords, dropped: %s (not a valid IMAP flag-keyword, RFC 9051 §9)",
			strings.Join(rejected, ","))
	}

	// The vacation reply goes out whatever happens to the message (RFC 5230 §4.7), and
	// after the header edits, which it has to see (RFC 5293 §7).
	if result.Vacation != nil && s.VacationHandler != nil && recipient.FromAddress != nil {
		_ = s.VacationHandler.HandleVacationResponse(ctx, recipient.AccountID, *result.Vacation, recipient.FromAddress, recipient.Address, outcome.MessageEntity)
	}

	// Process result
	switch result.Action {
	case sieveengine.ActionDiscard:
		if result.Rejected {
			action, reason := result.RejectLogFields()
			s.DeliveryCtx.Logger.Log("Sieve %s treated as discard, no bounce sent: %q", action, reason)
		}
		outcome.MailboxName = ""
		outcome.Discarded = true
		return outcome, nil

	case sieveengine.ActionFileInto:
		outcome.MailboxName = result.Mailbox
		if result.CreateMailbox {
			outcome.CreateMailbox = result.Mailbox
		}
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
			// Attribute this redirect to the script owner, replacing any earlier or
			// sender-supplied attribution. Aliases still use the account's primary address.
			relayBytes = helpers.SetHeaderLine(relayBytes, helpers.RedirectedByHeader, recipient.Address.FullAddress())
			from := recipient.FromAddress.FullAddress()
			relayed := s.RelayQueue != nil || s.RelayHandler != nil
			for _, redirectTo := range result.RedirectTo {
				// Try immediate delivery first if queue is not configured
				if s.RelayQueue == nil && s.RelayHandler != nil {
					if err := s.RelayHandler.SendToExternalRelay(from, redirectTo, relayBytes); err != nil {
						relayed = false
					}
				} else if s.RelayQueue != nil {
					// Queue for background delivery with retry
					if err := s.RelayQueue.Enqueue(from, redirectTo, "redirect", relayBytes); err != nil {
						// Failed to enqueue: keep the message in INBOX rather than fail the
						// delivery, but say so where an operator will see it — the user's
						// redirect silently did not happen.
						s.DeliveryCtx.Logger.Log("Failed to enqueue redirect message: %v", err)
						logger.Warn("Sieve redirect could not be queued; message kept in INBOX instead",
							"account_id", recipient.AccountID, "redirect_to", redirectTo, "error", err)
						relayed = false
					}
				}
			}
			if relayed && !result.Copy {
				// Every address relayed or queued, and no copy was asked for
				outcome.MailboxName = ""
				outcome.Discarded = true
				return outcome, nil
			}
		}
		// Fallback or copy: deliver to INBOX
		outcome.MailboxName = consts.MailboxInbox

	default:
		outcome.MailboxName = consts.MailboxInbox
	}

	return outcome, nil
}

// MergeSieveResults decides what the default script and the user script together
// ask of delivery. A user script that kept, implicitly or explicitly, leaves where
// the message goes to the default script, whatever it decided, and the two results
// are merged by keepDefaultAction; it reports keptDefault then. A user script that
// took an explicit fileinto, redirect or discard took the message over, and its
// result stands alone: the default script's flags, header edits and reply are all
// replaced, the reply with them, since the user script overruled that run entirely.
func MergeSieveResults(defaultResult, userResult sieveengine.Result) (merged sieveengine.Result, keptDefault bool) {
	if userResult.Action == sieveengine.ActionKeep {
		return keepDefaultAction(defaultResult, userResult), true
	}
	return userResult, false
}

// keepDefaultAction merges the result of a user script that ended in a keep into
// the default script's, whose action then stands, be it a filing or a keep of its
// own: the user script only left where the message goes to the default. Everything
// else it did still happens, after the default script's work as the two ran: its
// flags join the default's, its header edits follow the default's, and its vacation
// reply goes out (RFC 5230 §4.7), seeing those edits as RFC 5293 §7 requires. A user
// reply takes precedence; otherwise the default script's independent vacation reply
// still stands.
func keepDefaultAction(defaultResult, userResult sieveengine.Result) sieveengine.Result {
	merged := defaultResult
	merged.Flags = mergeFlags(defaultResult.Flags, userResult.Flags)
	merged.HeaderEdits = slices.Concat(defaultResult.HeaderEdits, userResult.HeaderEdits)
	if userResult.Vacation != nil {
		merged.Vacation = userResult.Vacation
	}
	return merged
}

// mergeFlags returns a's flags, then b's, without repeats. Flag names are
// case-insensitive (RFC 5232 §3), and the first spelling seen is kept.
func mergeFlags(a, b []string) []string {
	merged := make([]string, 0, len(a)+len(b))
	seen := make(map[string]bool, len(a)+len(b))
	for _, flag := range slices.Concat(a, b) {
		if key := strings.ToLower(flag); !seen[key] {
			seen[key] = true
			merged = append(merged, flag)
		}
	}
	return merged
}
