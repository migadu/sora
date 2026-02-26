package lmtp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/emersion/go-message"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// shouldSuppressVacation implements RFC 5230 §4.5 mandatory suppression rules
// for vacation auto-replies. It checks the incoming message to determine if a
// vacation response should NOT be sent.
//
// Vacation auto-reply loop prevention works at two levels:
//
// 1. Message-level suppression (this function):
//   - Null/empty sender (MAIL FROM:<>): bounce/DSN messages must never get replies
//   - Auto-Submitted header: messages from other auto-responders (auto-replied,
//     auto-generated, auto-notified) are suppressed to prevent reply loops
//   - Precedence header: bulk, junk, or list messages are suppressed to avoid
//     replying to mailing lists and mass mailings
//   - List-Id header: RFC 2919 mailing list identifier — additional safety net
//     for list messages that don't set Precedence
//
// 2. Rate-limiting via VacationOracle (database-level):
//   - The Sieve engine's VacationOracle tracks recent vacation responses per
//     (account, sender) pair in the database
//   - A vacation response is only sent once per sender within the configured
//     duration (typically 7 days), preventing repeated replies to the same person
//   - This is handled by the go-sieve library before it even triggers the
//     vacation action, so it's complementary to the suppression checks here
//
// The outgoing vacation response also sets these headers to prevent downstream loops:
//   - Auto-Submitted: auto-replied
//   - X-Auto-Response-Suppress: All
//
// Returns a non-empty reason string if vacation should be suppressed, empty string if allowed.
func shouldSuppressVacation(sender *server.Address, originalMessage *message.Entity) string {
	// 1. Do not reply to null/empty sender (bounce/DSN messages use MAIL FROM:<>)
	if sender == nil || sender.FullAddress() == "" {
		return "null or empty sender (bounce message)"
	}

	// 2. Do not reply if Auto-Submitted header is present and not "no"
	if autoSubmitted := originalMessage.Header.Get("Auto-Submitted"); autoSubmitted != "" {
		if strings.ToLower(strings.TrimSpace(autoSubmitted)) != "no" {
			return fmt.Sprintf("Auto-Submitted: %s", autoSubmitted)
		}
	}

	// 3. Do not reply to mailing list messages (Precedence: bulk, junk, or list)
	if precedence := originalMessage.Header.Get("Precedence"); precedence != "" {
		p := strings.ToLower(strings.TrimSpace(precedence))
		if p == "bulk" || p == "junk" || p == "list" {
			return fmt.Sprintf("Precedence: %s", precedence)
		}
	}

	// 4. Do not reply to messages from mailing list (List-Id header present)
	if listID := originalMessage.Header.Get("List-Id"); listID != "" {
		return fmt.Sprintf("List-Id: %s", listID)
	}

	return "" // No suppression needed
}

// dbVacationOracle implements the sieveengine.VacationOracle interface using the database.
type dbVacationOracle struct {
	rdb *resilient.ResilientDatabase
}

// IsVacationResponseAllowed checks if a vacation response is allowed for the given original sender and handle.
func (o *dbVacationOracle) IsVacationResponseAllowed(ctx context.Context, AccountID int64, originalSender string, handle string, duration time.Duration) (bool, error) {
	// Note: Current db.HasRecentVacationResponse does not take 'handle'.
	// This might require DB schema/method changes or adapting how 'handle' is stored/checked.
	// For this example, we'll ignore 'handle' for the DB check, assuming the DB stores per (AccountID, originalSender).
	hasRecent, err := o.rdb.HasRecentVacationResponseWithRetry(ctx, AccountID, originalSender, duration)
	if err != nil {
		return false, fmt.Errorf("checking db for recent vacation response: %w", err)
	}
	return !hasRecent, nil // Allowed if no recent response found
}

// RecordVacationResponseSent records that a vacation response has been sent.
func (o *dbVacationOracle) RecordVacationResponseSent(ctx context.Context, AccountID int64, originalSender string, handle string) error {
	// Note: Current db.RecordVacationResponse does not take 'handle'.
	// This might require DB schema/method changes or adapting how 'handle' is stored/recorded.
	// For this example, we'll ignore 'handle' for the DB recording.
	return o.rdb.RecordVacationResponseWithRetry(ctx, AccountID, originalSender)
}
