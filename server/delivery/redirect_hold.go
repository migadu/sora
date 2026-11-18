package delivery

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
)

// RedirectRecords is the record of which redirect targets a delivery has handed to the
// relay (redirect_deliveries, #1912). *resilient.ResilientDatabase implements it.
type RedirectRecords interface {
	RedirectedTargetsWithRetry(ctx context.Context, accountID int64, deliveryHash string) ([]string, error)
	RecordRedirectDeliveryWithRetry(ctx context.Context, accountID int64, deliveryHash, redirectTo string) error
}

// RedirectLog receives the diagnostics of a RedirectHold. An LMTP session implements it.
type RedirectLog interface {
	DebugLog(msg string, keysAndValues ...any)
	InfoLog(msg string, keysAndValues ...any)
	WarnLog(msg string, keysAndValues ...any)
}

// RedirectHold is how one delivery hands its Sieve redirects to the relay. LMTP and
// Admin API delivery both use it, so the two cannot handle a redirect differently.
type RedirectHold struct {
	Records RedirectRecords
	Queue   RelayQueue   // holds each target until commit
	Handler RelayHandler // used when Queue is nil: it cannot hold, so commit sends
	Notify  func()       // optional: wakes the relay worker after a queued target is handed over
	Log     RedirectLog

	AccountID int64
	// DeliveryHash identifies the upstream submission (InsertMessageOptions.DeliveryHash).
	// Empty skips the check for, and the record of, an earlier attempt's redirects.
	DeliveryHash string
	From         *server.Address // the envelope sender; nil redirects nothing
	Owner        *server.Address // the script owner's primary address, also for aliases
	MessageBytes []byte          // the message as it is stored
	// ArrivedHops is the redirect hop count of the message before the script's header
	// edits; every outgoing copy is stamped one above it.
	ArrivedHops int
}

// Hold writes the message to the relay queue for every redirect of result without
// handing it to the relay worker, and reports whether every target was held. commit
// hands over every redirect still held, records and charges each one handed over
// against the rate limit, and reports whether all of them went; abort drops the ones
// still held.
//
// A target an earlier attempt of the same delivery already handed over (a retry whose
// acknowledgement was lost, maybe on another node) is skipped and counts as held, the
// way the stored copy of such a retry is absorbed. commit records each target after
// handing it over, so a crash, a failed lookup or a failed record errs toward relaying
// the message again rather than not at all.
func (h RedirectHold) Hold(ctx context.Context, result sieveengine.Result) (commit func() bool, abort func(), allHeld bool) {
	type heldRedirect struct {
		to     string
		queued bool // held in the relay queue, not sent directly by commit
		commit func() error
		abort  func()
	}
	var held []heldRedirect
	allHeld = true
	if len(result.RedirectTo) > 0 {
		if result.Copy {
			h.Log.DebugLog("sieve redirect :copy action", "redirect_to", result.RedirectTo)
		} else {
			h.Log.DebugLog("sieve redirect action", "redirect_to", result.RedirectTo)
		}
		switch {
		case h.Queue == nil && h.Handler == nil:
			h.Log.DebugLog("redirect requested but external relay not configured")
			allHeld = false
		case h.From == nil:
			h.Log.DebugLog("redirect requested but the delivery has no sender")
			allHeld = false
		default:
			// Stamp the outgoing copy with an incremented hop count (loop backstop).
			relayBytes := helpers.PrependHeaderLine(h.MessageBytes, helpers.RedirectLoopHeader, strconv.Itoa(h.ArrivedHops+1))
			// Replace earlier or sender-supplied attribution on the outgoing copy only.
			relayBytes = helpers.SetHeaderLine(relayBytes, helpers.RedirectedByHeader, h.Owner.FullAddress())
			from := h.From.FullAddress()
			var queued []string
			if h.DeliveryHash != "" {
				var err error
				if queued, err = h.Records.RedirectedTargetsWithRetry(ctx, h.AccountID, h.DeliveryHash); err != nil {
					h.Log.WarnLog("could not check for redirects queued by an earlier attempt, queuing all", "error", err)
				}
			}
			for _, redirectTo := range result.RedirectTo {
				if slices.Contains(queued, redirectTo) {
					h.Log.InfoLog("sieve redirect already queued by an earlier attempt of this delivery, skipping", "redirect_to", redirectTo)
					continue
				}
				if h.Queue == nil {
					held = append(held, heldRedirect{
						to:     redirectTo,
						commit: func() error { return h.Handler.SendToExternalRelay(from, redirectTo, relayBytes) },
						abort:  func() {},
					})
					continue
				}
				commit, abort, err := h.Queue.Hold(from, redirectTo, "redirect", relayBytes)
				if err != nil {
					// Delivery goes on: the message is kept in INBOX unless a fileinto
					// stores it (Result.Destinations). Say so where an operator will see
					// it: the user's redirect did not happen.
					h.Log.WarnLog("sieve redirect could not be queued", "redirect_to", redirectTo, "error", err)
					allHeld = false
					continue
				}
				held = append(held, heldRedirect{to: redirectTo, queued: true, commit: commit, abort: abort})
			}
		}
	}

	commit = func() bool {
		ok := true
		for _, r := range held {
			if err := r.commit(); err != nil {
				if r.queued {
					h.Log.WarnLog("sieve redirect could not be queued", "redirect_to", r.to, "error", err)
				} else {
					h.Log.WarnLog("sieve redirect could not be handed to the relay", "redirect_to", r.to, "error", err)
				}
				ok = false
				continue
			}
			if r.queued {
				h.Log.DebugLog("successfully queued message for relay delivery", "redirect_to", r.to)
				if h.Notify != nil {
					h.Notify()
				}
			} else {
				h.Log.DebugLog("sieve redirect handed to the relay", "redirect_to", r.to)
			}
			if h.DeliveryHash != "" {
				if err := h.Records.RecordRedirectDeliveryWithRetry(ctx, h.AccountID, h.DeliveryHash, r.to); err != nil {
					h.Log.WarnLog("failed to record a queued redirect, a retry of this delivery would queue it again", "redirect_to", r.to, "error", err)
				}
			}
			// Only a redirect handed over counts against the rate limit.
			if result.RecordRedirect != nil {
				if err := result.RecordRedirect(ctx); err != nil {
					h.Log.WarnLog("failed to charge redirect against the rate limit", "redirect_to", r.to, "error", err)
				}
			}
		}
		held = nil
		return ok
	}
	abort = func() {
		for _, r := range held {
			r.abort()
		}
		held = nil
	}
	return commit, abort, allHeld
}

// deliveryRedirectLog is the RedirectLog of an Admin API delivery: debug lines go to the
// delivery's logger, the rest to the server log with the account.
type deliveryRedirectLog struct {
	log       Logger
	accountID int64
}

func (l deliveryRedirectLog) DebugLog(msg string, keysAndValues ...any) {
	if l.log == nil {
		return
	}
	var b strings.Builder
	b.WriteString(msg)
	for i := 0; i+1 < len(keysAndValues); i += 2 {
		fmt.Fprintf(&b, " %v=%v", keysAndValues[i], keysAndValues[i+1])
	}
	l.log.Log("%s", b.String())
}

func (l deliveryRedirectLog) InfoLog(msg string, keysAndValues ...any) {
	logger.Info(msg, append([]any{"account_id", l.accountID}, keysAndValues...)...)
}

func (l deliveryRedirectLog) WarnLog(msg string, keysAndValues ...any) {
	logger.Warn(msg, append([]any{"account_id", l.accountID}, keysAndValues...)...)
}
