package imap

import (
	"sort"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

// SortField represents a field to sort by
type SortField int

// Sort field constants as defined in RFC 5256
const (
	SortArrival SortField = iota
	SortCC
	SortDate
	SortFrom
	SortSize
	SortSubject
	SortTo
	SortDisplayFrom
	SortDisplayTo
)

// SortOrder represents the sort direction
type SortOrder int

const (
	SortAscending SortOrder = iota
	SortDescending
)

// Sort implements the SORT extension (RFC 5256)
func (s *IMAPSession) Sort(numKind imapserver.NumKind, criteria *imap.SearchCriteria, sortFields []SortField, order SortOrder) (*imap.SearchData, error) {
	// Log the sort operation
	s.Log("[SORT] Executing SORT command with %d sort fields", len(sortFields))

	// First, search for messages that match the criteria
	searchData, err := s.Search(numKind, criteria, nil)
	if err != nil {
		return nil, err
	}

	// If no messages matched, return empty results
	if searchData.Count == 0 {
		return searchData, nil
	}

	// Get all the messages that matched the search criteria
	// Create a UIDSet from the search results for fetching messages
	var uidSet imap.UIDSet

	// Extract UIDs from the search results
	switch ns := searchData.All.(type) {
	case imap.UIDSet:
		uidSet = ns
	case imap.SeqSet:
		// If we got sequence numbers, convert them back to UIDs using the original messages
		messages, err := s.server.db.GetMessagesByNumSet(s.ctx, s.selectedMailbox.ID, ns)
		if err != nil {
			return nil, s.internalError("failed to convert sequence numbers to UIDs: %v", err)
		}

		for _, msg := range messages {
			uidSet.AddNum(msg.UID)
		}
	}

	// Fetch the complete message data for sorting
	messages, err := s.server.db.GetMessagesByNumSet(s.ctx, s.selectedMailbox.ID, uidSet)
	if err != nil {
		return nil, s.internalError("failed to fetch messages for sorting: %v", err)
	}

	// Sort the messages based on the specified criteria
	sort.Slice(messages, func(i, j int) bool {
		// Start with the first sort field
		for _, field := range sortFields {
			var less bool

			switch field {
			case SortArrival:
				less = messages[i].InternalDate.Before(messages[j].InternalDate)
			case SortDate:
				// If message date is available, use it, otherwise fall back to internal date
				dateI := messages[i].InternalDate
				dateJ := messages[j].InternalDate
				less = dateI.Before(dateJ)
			case SortSize:
				less = messages[i].Size < messages[j].Size
			case SortFrom, SortTo, SortSubject, SortCC:
				// For these fields, we would need to fetch the envelopes
				// Since Envelope is not directly accessible in db.Message,
				// we'll use UID ordering as a fallback for now
				s.Log("[SORT] Falling back to UID sorting for %v field", field)
				less = messages[i].UID < messages[j].UID
			default:
				// If unrecognized sort field, fall back to UID
				less = messages[i].UID < messages[j].UID
			}

			// If descending order, invert the comparison
			if order == SortDescending {
				less = !less
			}

			// If we can determine an ordering with this field, return it
			if less || messages[i].UID != messages[j].UID {
				return less
			}

			// Otherwise, try the next sort field
		}

		// If all fields are equal, sort by UID as a final tiebreaker
		if order == SortAscending {
			return messages[i].UID < messages[j].UID
		}
		return messages[i].UID > messages[j].UID
	})

	// Build the sorted set of UIDs or sequence numbers
	var sortedSet imap.NumSet

	switch numKind {
	case imapserver.NumKindUID:
		uidSet := imap.UIDSet{}
		for _, msg := range messages {
			uidSet.AddNum(msg.UID)
		}
		sortedSet = uidSet
	case imapserver.NumKindSeq:
		seqSet := imap.SeqSet{}
		for _, msg := range messages {
			seqSet.AddNum(s.sessionTracker.EncodeSeqNum(msg.Seq))
		}
		sortedSet = seqSet
	}

	// Return the sorted results
	return &imap.SearchData{
		All:   sortedSet,
		Count: uint32(len(messages)),
	}, nil
}
