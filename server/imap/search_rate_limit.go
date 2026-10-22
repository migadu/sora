package imap

import (
	"context"

	"github.com/emersion/go-imap/v2"
)

// The search rate limit (server.SearchRateLimiter) is for the searches that are
// expensive, not for every command that happens to be a SEARCH. Clients such as
// webmail navigate with SEARCH, SORT and THREAD: a SEARCH by UID set to check
// that a MOVE emptied the source, a SORT of one page's UIDs, a SEARCH for unseen
// or flagged messages on every mailbox switch. Those run on indexed metadata,
// cost no more than the FETCH that follows them, and charging them throttled
// users clicking through their mail while their phone shared the same budget.
//
// What is charged:
//   - a criteria matching on message content: BODY, TEXT or any HEADER key
//     (FROM, TO, CC, BCC and SUBJECT among them), anywhere in the criteria,
//     NOT and OR included. These are the full-text and substring searches the
//     limit exists for;
//   - a SORT or THREAD over the whole mailbox, or more than confinedMaxMessages
//     of it, since it reads and orders every message it covers;
//   - a multi-mailbox ESEARCH, which runs one search per mailbox in scope.
//
// UID and sequence sets, flags and keywords, dates, sizes and MODSEQ are free.

// confinedMaxMessages is the most messages a UID or sequence set may name for a
// SORT or THREAD it confines to go uncharged: reading and ordering that many
// messages is a lookup, not a scan of the mailbox.
const confinedMaxMessages = 1000

// criteriaMatchesContent reports whether criteria, or any criteria nested in it,
// match on message content rather than on metadata.
func criteriaMatchesContent(criteria *imap.SearchCriteria) bool {
	if criteria == nil {
		return false
	}
	if len(criteria.Header) > 0 || len(criteria.Body) > 0 || len(criteria.Text) > 0 {
		return true
	}
	for i := range criteria.Not {
		if criteriaMatchesContent(&criteria.Not[i]) {
			return true
		}
	}
	for i := range criteria.Or {
		if criteriaMatchesContent(&criteria.Or[i][0]) || criteriaMatchesContent(&criteria.Or[i][1]) {
			return true
		}
	}
	return false
}

// criteriaConfined reports whether criteria hold the command to at most
// confinedMaxMessages messages by a UID or sequence set at the top level, where
// every message matched must be in it. A set with "*", or the saved result "$",
// confines nothing, whatever its size now.
func criteriaConfined(criteria *imap.SearchCriteria) bool {
	if criteria == nil {
		return false
	}
	for _, set := range criteria.UID {
		var n uint64
		for _, r := range set {
			n += rangeLen(uint32(r.Start), uint32(r.Stop))
		}
		if !set.Dynamic() && n <= confinedMaxMessages {
			return true
		}
	}
	for _, set := range criteria.SeqNum {
		var n uint64
		for _, r := range set {
			n += rangeLen(r.Start, r.Stop)
		}
		if !set.Dynamic() && n <= confinedMaxMessages {
			return true
		}
	}
	return false
}

// rangeLen is the number of messages a start:stop range names.
func rangeLen(start, stop uint32) uint64 {
	return uint64(max(start, stop)-min(start, stop)) + 1
}

// scanCharged reports whether a SORT or THREAD with criteria is charged to the
// search rate limit: when it matches on content, or is not confined to a few
// messages.
func scanCharged(criteria *imap.SearchCriteria) bool {
	return criteriaMatchesContent(criteria) || !criteriaConfined(criteria)
}

// chargeSearch takes one search from the account's search rate limit. A command
// refused for it gets NO [LIMIT] (RFC 5530 section 3, "The operation ran up
// against an implementation limit of some kind"), so that the client can tell
// throttling from failure and keep showing what it has.
func (s *IMAPSession) chargeSearch(ctx context.Context) error {
	if s.IMAPUser == nil {
		return nil
	}
	// The limiter logs with suppression and counts the refusal in its metrics.
	if err := s.server.searchRateLimiter.CanSearch(ctx, s.IMAPUser.AccountID()); err != nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeLimit,
			Text: err.Error(),
		}
	}
	return nil
}
