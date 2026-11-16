package delivery

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-message"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
)

// DefaultSieveScript is the built-in script every delivery runs before the user's
// own: it files spam into Junk (ResolveDefaultJunk) and a +detail recipient into the
// detail folder. Both delivery paths run it and merge its result with the user
// script's (MergeSieveResults), so one message is filed the same way whichever way
// it came.
//
//go:embed default.sieve
var DefaultSieveScript string

// defaultJunkIndex returns the position in the default script's result of its spam
// filing, the plain fileinto "Junk" of default.sieve, or -1 if it has none. The
// script's other filing, by +detail, is a fileinto :create of a lower-case name.
func defaultJunkIndex(result sieveengine.Result) int {
	i := slices.Index(result.Mailboxes, consts.MailboxJunk)
	if i < 0 || slices.Contains(result.CreateMailboxes, consts.MailboxJunk) {
		return -1
	}
	return i
}

// ResolveDefaultJunk points the default script's spam filing at the account's \Junk
// mailbox (RFC 6154 §2), the one LIST shows as the Junk folder. default.sieve files
// spam with fileinto "Junk", but the attribute, not the name, says which mailbox
// that is: it survives RENAME, and a plain folder may be named Junk. The filing is
// carried out as RFC 8579 §4 has fileinto :specialuse "\\Junk" "Junk" do: it "first
// checks whether a mailbox exists in the user's personal namespace [NAMESPACE] with
// the specified special-use attribute assigned to it", and only without one is the
// mailbox named Junk used. A user script's fileinto "Junk" still names a mailbox
// (RFC 5228 §4.1), so this is applied to the default script's result only, before
// it is merged with the user script's.
//
// A failed lookup fails the delivery, to be retried: RFC 8579 §4 does not let a
// failure that is not about the special-use mailbox's existence fall back to the
// named one, which would spread the account's spam over two folders.
func ResolveDefaultJunk(ctx context.Context, rdb *resilient.ResilientDatabase, accountID int64, result sieveengine.Result) (sieveengine.Result, error) {
	i := defaultJunkIndex(result)
	if i < 0 {
		return result, nil
	}
	name, err := rdb.GetPersonalMailboxNameBySpecialUseWithRetry(ctx, accountID, string(imap.MailboxAttrJunk))
	if errors.Is(err, consts.ErrMailboxNotFound) {
		return result, nil
	}
	if err != nil {
		return result, err // already "failed to look up the \Junk mailbox: ..."
	}
	result.Mailboxes = slices.Clone(result.Mailboxes)
	result.Mailboxes[i] = name
	if name != consts.MailboxJunk {
		if result.MailboxFlags != nil {
			result.MailboxFlags = maps.Clone(result.MailboxFlags)
			result.MailboxFlags[name] = result.MailboxFlags[consts.MailboxJunk]
			delete(result.MailboxFlags, consts.MailboxJunk)
		}
		if result.MailboxStoreOrder != nil {
			result.MailboxStoreOrder = maps.Clone(result.MailboxStoreOrder)
			result.MailboxStoreOrder[name] = result.MailboxStoreOrder[consts.MailboxJunk]
			delete(result.MailboxStoreOrder, consts.MailboxJunk)
		}
	}
	return result, nil
}

// SieveOutcome is the result of evaluating a recipient's Sieve script for one delivery.
type SieveOutcome struct {
	// MailboxName is where the delivered copy goes. Discarded means nothing is stored.
	MailboxName string
	Discarded   bool
	// Flags are those the script set on the MailboxName copy (imap4flags, RFC 5232):
	// each copy has the flags of the keep or fileinto that stores it.
	Flags []imap.Flag
	// MessageBytes/MessageEntity carry the message after any header edits (RFC 5293
	// editheader); they are always set. The caller MUST hash and store THESE bytes:
	// content_hash is the S3 object key, so it has to describe the body actually written.
	MessageBytes  []byte
	MessageEntity *message.Entity
	// Copies are the other mailboxes that get a copy: further fileinto targets, and
	// INBOX when the message is also kept. The caller saves them AFTER staging the
	// body locally: SaveMessageToMailbox writes a pending_uploads row, and the uploader
	// treats a pending upload whose local file is missing as permanent content loss.
	Copies []SieveCopy
	// Resolving can create mailboxes, so the caller invokes this only after the
	// storable-size check and body staging, with redirect abort already deferred.
	resolveDestinations func(context.Context) ([]SieveCopy, error)
	// CreateMailboxes are the fileinto :create targets (RFC 5490 §3.2): the caller
	// creates each missing mailbox before saving the copies.
	CreateMailboxes []string
	// Redirect hands the script's redirects to the relay worker. ExecuteSieve has
	// already written them to the relay queue (RelayQueue.Hold), so the caller calls it
	// once every requested copy is stored, and it reports false only for a redirect
	// that could not be handed over after all. RedirectOnly has no requested copy: call
	// Redirect first, keeping INBOX only if it fails. AbortRedirect drops every redirect
	// Redirect has not handed over; the caller calls it when the delivery returns, so
	// that a failed delivery leaves nothing for the relay and its retry relays once.
	Redirect      func() bool
	AbortRedirect func()
	RedirectOnly  bool
}

// SieveCopy is a further mailbox a delivery stores the message in, with the flags
// the script set on that copy (imap4flags, RFC 5232).
type SieveCopy struct {
	Mailbox string
	Flags   []imap.Flag
	target  *db.DBMailbox
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
	// Hold writes a message without handing it to the relay worker: commit hands it
	// over, abort removes it instead and does nothing after commit. A Sieve redirect is
	// held until the delivery that runs it can no longer fail, so that a delivery that
	// fails and is retried never relays it twice.
	Hold(from, to, messageType string, messageBytes []byte) (commit func() error, abort func(), err error)
}

// StandardSieveExecutor implements the standard Sieve execution flow.
type StandardSieveExecutor struct {
	DeliveryCtx        *DeliveryContext
	VacationOracle     *VacationOracle
	VacationHandler    VacationHandler
	RelayHandler       RelayHandler
	RelayQueue         RelayQueue // Optional: disk-based queue for relay retry
	RelayNotify        func()     // Optional: wakes the relay worker after a redirect is enqueued
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

// ExecuteSieve executes Sieve scripts and sends the vacation reply. The caller
// stores every requested copy from SieveOutcome.MessageBytes before invoking
// SieveOutcome.Redirect, and calls SieveOutcome.AbortRedirect when it returns. A
// redirect-only delivery uses INBOX only if handoff fails.
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
		Header:       sieveengine.HeaderMap(messageEntity.Header),
		Message:      fullMessageBytes,
		MailboxExists: func(ctx context.Context, mailbox string) (bool, error) {
			return CanFileInto(ctx, s.DeliveryCtx.RDB, s.DeliveryCtx.SharedMailboxes, recipient.AccountID, mailbox)
		},
	}

	// The built-in default script runs first, as on LMTP, and the user's script then
	// takes the message over or keeps the default's filing (MergeSieveResults). A
	// script that fails to compile or run leaves the result before it standing.
	result, err := ResolveDefaultJunk(ctx, s.DeliveryCtx.RDB, recipient.AccountID,
		s.evaluate(ctx, recipient, sieveCtx, DefaultSieveScript, "default"))
	if err != nil {
		return nil, err
	}
	activeScript, err := s.DeliveryCtx.RDB.GetActiveScriptWithRetry(ctx, recipient.AccountID)
	if err != nil && err != consts.ErrDBNotFound {
		s.DeliveryCtx.Logger.Log("Failed to get the active Sieve script, using the default script's result: %v", err)
	} else if activeScript != nil {
		userResult := s.evaluate(ctx, recipient, sieveCtx, activeScript.Script, "user")
		result, _ = MergeSieveResults(result, userResult)
	}

	// Apply header edits if any (RFC 5293 - editheader extension), before the caller
	// hashes and stores the body, exactly as the LMTP path does: content_hash must
	// describe the edited bytes, and every copy of this delivery - the redirected ones and
	// every stored one - is made from them.
	if len(result.HeaderEdits) > 0 {
		edited, editErr := sieveengine.ApplyHeaderEdits(outcome.MessageBytes, result.HeaderEdits)
		if editErr != nil {
			s.DeliveryCtx.Logger.Log("Failed to apply Sieve header edits, delivering unmodified: %v", editErr)
		} else if reparsed, parseErr := server.ParseMessage(bytes.NewReader(edited)); parseErr != nil {
			// Bytes and entity must stay consistent: the entity is what the stored
			// metadata (subject, message id, body structure) is derived from.
			s.DeliveryCtx.Logger.Log("Failed to re-parse message after Sieve header edits, delivering unmodified: %v", parseErr)
		} else {
			outcome.MessageBytes = edited
			outcome.MessageEntity = reparsed
		}
	}

	// The vacation reply goes out whatever happens to the message (RFC 5230 §4.7), and
	// after the header edits, which it has to see (RFC 5293 §7).
	if result.Vacation != nil && s.VacationHandler != nil && recipient.FromAddress != nil {
		_ = s.VacationHandler.HandleVacationResponse(ctx, recipient.AccountID, *result.Vacation, recipient.FromAddress, recipient.Address, outcome.MessageEntity)
	}

	// Write every redirect to the relay queue now, but hand none to the relay worker
	// before the caller has stored what this delivery stores: a target the queue cannot
	// take keeps the message in INBOX when nothing else stores it, and a delivery that
	// fails after a handoff would relay it again on every retry. The hop count is the
	// one the message arrived with, as the script saw it and RedirectAllowed checked it:
	// a count read after an editheader script deleted X-Sora-Loop would restart on
	// every pass and never reach max_redirect_hops.
	allHeld := true
	if len(result.RedirectTo) > 0 {
		arrivedHops := helpers.RedirectHopCount(helpers.HeaderGetter(sieveCtx.Header))
		outcome.Redirect, outcome.AbortRedirect, allHeld = s.holdRedirects(ctx, recipient, result, outcome.MessageBytes, arrivedHops)
	}

	if result.Action == sieveengine.ActionDiscard && result.Rejected {
		action, reason := result.RejectLogFields()
		s.DeliveryCtx.Logger.Log("Sieve %s treated as discard, no bounce sent: %q", action, reason)
	}

	// With every redirect held and no requested copy, the caller hands the redirects
	// over first, using INBOX only when that fails.
	destinations := result.Destinations(!allHeld)
	if len(destinations) == 0 {
		if outcome.Redirect != nil {
			outcome.RedirectOnly = true
			outcome.MailboxName = consts.MailboxInbox
			// Kept in INBOX only if the handoff fails, then with the keep's flags.
			outcome.Flags = s.sieveFlags(result.FlagsForKeep())
			return outcome, nil
		}
		outcome.MailboxName = ""
		outcome.Discarded = true
		return outcome, nil
	}
	outcome.MailboxName = destinations[0].Mailbox
	outcome.Flags = helpers.SanitizeFlags(helpers.StringsToFlags(destinations[0].Flags))
	for _, dest := range destinations {
		if dest.Create {
			outcome.CreateMailboxes = append(outcome.CreateMailboxes, dest.Mailbox)
		}
	}
	for _, dest := range destinations[1:] {
		outcome.Copies = append(outcome.Copies, SieveCopy{Mailbox: dest.Mailbox, Flags: helpers.SanitizeFlags(helpers.StringsToFlags(dest.Flags))})
	}
	outcome.resolveDestinations = func(ctx context.Context) ([]SieveCopy, error) {
		destinations, err := ResolveSieveDestinations(ctx, s.DeliveryCtx.RDB, s.DeliveryCtx.SharedMailboxes, recipient.AccountID, result, !allHeld, s.DeliveryCtx.Logger.Log)
		if err != nil {
			return nil, err
		}
		copies := make([]SieveCopy, len(destinations))
		for i, dest := range destinations {
			copies[i] = SieveCopy{Mailbox: dest.Target.Name, Flags: s.sieveFlags(dest.Flags), target: dest.Target}
		}
		return copies, nil
	}

	return outcome, nil
}

// sieveFlags converts one stored copy's Sieve flags to valid IMAP flags.
func (s *StandardSieveExecutor) sieveFlags(names []string) []imap.Flag {
	raw := helpers.StringsToFlags(names)
	flags := helpers.SanitizeFlags(raw)
	if rejected := helpers.DroppedFlags(raw, flags); len(rejected) > 0 {
		s.DeliveryCtx.Logger.Log("Sieve set invalid IMAP keywords, dropped: %s (not a valid IMAP flag-keyword, RFC 9051 §9)",
			strings.Join(rejected, ","))
	}
	return flags
}

// holdRedirects writes the message to the relay queue for every redirect without
// handing it to the relay worker, and reports whether every target was held. commit
// hands over every redirect still held, charges each one handed over against the rate
// limit, and reports whether all of them went; abort drops the ones still held. A
// direct relay handler cannot hold a message: its commit sends it. arrivedHops is
// the redirect hop count of the message before the script's header edits; every
// outgoing copy is stamped one above it.
func (s *StandardSieveExecutor) holdRedirects(ctx context.Context, recipient RecipientInfo, result sieveengine.Result, messageBytes []byte, arrivedHops int) (commit func() bool, abort func(), allHeld bool) {
	type heldRedirect struct {
		to     string
		commit func() error
		abort  func()
	}
	var held []heldRedirect
	allHeld = true
	if recipient.FromAddress != nil && (s.RelayQueue != nil || s.RelayHandler != nil) {
		// Stamp the outgoing copy with an incremented hop count (loop backstop).
		relayBytes := helpers.PrependHeaderLine(messageBytes, helpers.RedirectLoopHeader, strconv.Itoa(arrivedHops+1))
		// Attribute this redirect to the script owner, replacing any earlier or
		// sender-supplied attribution. Aliases still use the account's primary address.
		relayBytes = helpers.SetHeaderLine(relayBytes, helpers.RedirectedByHeader, recipient.Address.FullAddress())
		from := recipient.FromAddress.FullAddress()
		for _, redirectTo := range result.RedirectTo {
			if s.RelayQueue == nil {
				held = append(held, heldRedirect{
					to:     redirectTo,
					commit: func() error { return s.RelayHandler.SendToExternalRelay(from, redirectTo, relayBytes) },
					abort:  func() {},
				})
				continue
			}
			commit, abort, err := s.RelayQueue.Hold(from, redirectTo, "redirect", relayBytes)
			if err != nil {
				s.DeliveryCtx.Logger.Log("Failed to enqueue redirect message: %v", err)
				logger.Warn("Sieve redirect could not be queued",
					"account_id", recipient.AccountID, "redirect_to", redirectTo, "error", err)
				allHeld = false
				continue
			}
			held = append(held, heldRedirect{to: redirectTo, commit: commit, abort: abort})
		}
	} else {
		allHeld = false
	}

	commit = func() bool {
		ok := true
		for _, h := range held {
			if err := h.commit(); err != nil {
				s.DeliveryCtx.Logger.Log("Failed to hand redirect message to the relay: %v", err)
				logger.Warn("Sieve redirect could not be handed to the relay",
					"account_id", recipient.AccountID, "redirect_to", h.to, "error", err)
				ok = false
				continue
			}
			if s.RelayQueue != nil && s.RelayNotify != nil {
				s.RelayNotify()
			}
			if result.RecordRedirect != nil {
				if err := result.RecordRedirect(ctx); err != nil {
					logger.Warn("Sieve redirect could not be charged against the rate limit",
						"account_id", recipient.AccountID, "redirect_to", h.to, "error", err)
				}
			}
		}
		held = nil
		return ok
	}
	abort = func() {
		for _, h := range held {
			h.abort()
		}
		held = nil
	}
	return commit, abort, allHeld
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
// else it did still happens, after the default script's work as the two ran: the
// flags of its keep join those of every copy the default stores, its header edits
// follow the default's, and its vacation reply goes out (RFC 5230 §4.7), seeing
// those edits as RFC 5293 §7 requires. A user reply takes precedence; otherwise the
// default script's independent vacation reply still stands.
func keepDefaultAction(defaultResult, userResult sieveengine.Result) sieveengine.Result {
	merged := defaultResult
	userFlags := userResult.FlagsForKeep()
	merged.KeepFlags = mergeFlags(defaultResult.FlagsForKeep(), userFlags)
	merged.Flags = merged.KeepFlags
	if len(defaultResult.Mailboxes) > 0 {
		merged.MailboxFlags = make(map[string][]string, len(defaultResult.Mailboxes))
		for _, mailbox := range defaultResult.Mailboxes {
			merged.MailboxFlags[mailbox] = mergeFlags(defaultResult.FlagsForMailbox(mailbox), userFlags)
		}
	}
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
