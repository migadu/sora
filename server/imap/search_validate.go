package imap

import (
	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/metrics"
)

// searchCriteriaValidator is the shared, stateless cost/complexity validator applied to
// every SEARCH, SORT, THREAD and MULTISEARCH request before the criteria is decoded or
// handed to the database layer.
//
// Critically, it enforces a nesting-depth and total-node cap: without it, a maliciously
// deep or wide criteria tree (e.g. thousands of nested or sibling ORs, which fit within
// the protocol's 50 KiB command limit) would recurse unbounded through the IMAP criteria
// decoder (decodeSearchCriteriaLocked) and the SQL builder (buildSearchCriteriaWithPrefix),
// generating a pathological multi-thousand-parameter WHERE clause and risking goroutine
// stack exhaustion — a fatal, unrecoverable crash of the whole process.
var searchCriteriaValidator = db.NewSearchCriteriaValidator()

// validateSearchCriteria runs the shared validator over an incoming criteria tree and
// returns a protocol-level BAD error (RFC 9051 §6.4.4) if it is too complex/deep to
// process safely. It returns nil when the criteria is acceptable.
//
// command is the IMAP command being handled (e.g. "SEARCH", "SORT", "THREAD",
// "MULTISEARCH"); it is used only for the rejection metric label so errors are tracked
// per command rather than all under "SEARCH".
//
// Call this at the top of every handler that accepts a client-supplied *imap.SearchCriteria,
// BEFORE the criteria is decoded or used to build a query.
func (s *IMAPSession) validateSearchCriteria(command string, criteria *imap.SearchCriteria) error {
	result := searchCriteriaValidator.ValidateSearchCriteria(criteria)
	if result.Valid {
		return nil
	}

	// Log the specific reason for debugging; keep the client-facing text generic so the
	// response is not an oracle for probing the validator's limits.
	if err := result.GetFirstError(); err != nil {
		s.DebugLog("rejecting search criteria", "command", command, "reason", err.Error())
	}
	metrics.ProtocolErrors.WithLabelValues("imap", command, "criteria_rejected", "client_error").Inc()

	return &imap.Error{
		Type: imap.StatusResponseTypeBad,
		Code: imap.ResponseCodeClientBug,
		Text: "Search criteria too complex",
	}
}
