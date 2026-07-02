package imap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// GetMetadata implements the GETMETADATA command (RFC 5464).
// If mailbox is empty string "", retrieves server metadata.
func (s *IMAPSession) GetMetadata(mailbox string, entries []string, options *imap.GetMetadataOptions) (*imap.GetMetadataData, error) {
	s.DebugLog("GETMETADATA command", "mailbox", mailbox, "entries", entries)

	// RFC 5464 does not support wildcard mailbox names in GETMETADATA
	// SnappyMail webmail incorrectly sends "*" as the mailbox parameter
	// Reject wildcards with a clear error message
	if strings.ContainsAny(mailbox, "*%") {
		s.DebugLog("rejected wildcard mailbox", "mailbox", mailbox)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeClientBug,
			Text: "GETMETADATA does not support wildcard mailbox names. Use empty string \"\" for server metadata or a specific mailbox name.",
		}
	}

	// Canonicalise (case-fold) and validate entry names. RFC 5464 §3.1 makes
	// entry names case-insensitive, so we query using the canonical form.
	canonEntries := make([]string, len(entries))
	for i, entry := range entries {
		canonEntries[i] = canonicalMetadataEntry(entry)
		if err := validateMetadataEntry(canonEntries[i]); err != nil {
			return nil, err
		}
	}
	entries = canonEntries

	var mailboxID *int64
	var mailboxName string

	// If mailbox is specified, look it up
	if mailbox != "" {
		acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
		if !acquired {
			s.DebugLog("failed to acquire read lock")
			return nil, fmt.Errorf("failed to acquire session lock")
		}
		defer release()

		dbMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, s.AccountID(), mailbox)
		if err != nil {
			if errors.Is(err, consts.ErrMailboxNotFound) {
				return nil, &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeNonExistent,
					Text: fmt.Sprintf("mailbox does not exist: %s", mailbox),
				}
			}
			return nil, fmt.Errorf("failed to get mailbox: %w", err)
		}

		// Check ACL permissions - requires 'r' (read) right for mailbox metadata
		hasReadRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, dbMailbox.ID, s.AccountID(), 'r')
		if err != nil {
			return nil, fmt.Errorf("failed to check read permission: %w", err)
		}
		if !hasReadRight {
			s.DebugLog("user does not have read permission", "mailbox", mailbox)
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Text: "you do not have permission to get metadata for this mailbox",
			}
		}

		mailboxID = &dbMailbox.ID
		mailboxName = dbMailbox.Name
	}

	// Fetch metadata from database
	result, err := s.server.rdb.GetMetadataWithRetry(s.ctx, s.AccountID(), mailboxID, entries, options)
	if err != nil {
		s.DebugLog("failed to get metadata", "error", err)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: fmt.Sprintf("failed to get metadata: %v", err),
		}
	}

	result.Mailbox = mailboxName
	return result, nil
}

// SetMetadata implements the SETMETADATA command (RFC 5464).
// If mailbox is empty string "", sets server metadata.
// To remove an entry, set its value to nil.
func (s *IMAPSession) SetMetadata(mailbox string, entries map[string]*[]byte) error {
	// Canonicalise (case-fold) entry names first so the case-insensitivity rule
	// (RFC 5464 §3.1) is honoured for storage AND for the /private-vs-/shared
	// scope classification below — otherwise a /SHARED/... spelling would be
	// misclassified as private and skip the shared-scope 'w' ACL check.
	canonEntries := make(map[string]*[]byte, len(entries))
	for entryName, entryValue := range entries {
		canonName := canonicalMetadataEntry(entryName)
		if err := validateMetadataEntry(canonName); err != nil {
			return err
		}
		canonEntries[canonName] = entryValue
	}
	entries = canonEntries

	var mailboxID *int64

	// If mailbox is specified, look it up
	if mailbox != "" {
		acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
		if !acquired {
			s.DebugLog("failed to acquire read lock")
			return fmt.Errorf("failed to acquire session lock")
		}
		defer release()

		dbMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, s.AccountID(), mailbox)
		if err != nil {
			if errors.Is(err, consts.ErrMailboxNotFound) {
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeNonExistent,
					Text: fmt.Sprintf("mailbox does not exist: %s", mailbox),
				}
			}
			return fmt.Errorf("failed to get mailbox: %w", err)
		}

		// Check ACL permissions. Entries are already canonicalised (lower case),
		// so this scope classification is case-insensitive:
		//   - /shared entries require the 'w' (write) right
		//   - /private entries require only 'l' (lookup); they are per-user data
		needsWrite := false
		for entryName := range entries {
			if strings.HasPrefix(entryName, "/shared/") {
				needsWrite = true
				break
			}
		}

		if needsWrite {
			hasWriteRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, dbMailbox.ID, s.AccountID(), 'w')
			if err != nil {
				return fmt.Errorf("failed to check write permission: %w", err)
			}
			if !hasWriteRight {
				s.DebugLog("user does not have write permission", "mailbox", mailbox)
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Text: "you do not have permission to set shared metadata for this mailbox",
				}
			}
		} else {
			// For /private entries, just verify user has lookup permission (already verified by GetMailboxByName)
			hasLookupRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, dbMailbox.ID, s.AccountID(), 'l')
			if err != nil {
				return fmt.Errorf("failed to check lookup permission: %w", err)
			}
			if !hasLookupRight {
				s.DebugLog("user does not have lookup permission", "mailbox", mailbox)
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Text: "you do not have permission to set metadata for this mailbox",
				}
			}
		}

		mailboxID = &dbMailbox.ID
	}

	// Prepare metadata limits from server config
	limits := &db.MetadataLimits{
		MaxEntrySize:         s.server.metadataMaxEntrySize,
		MaxEntriesPerMailbox: s.server.metadataMaxEntriesPerMailbox,
		MaxEntriesPerServer:  s.server.metadataMaxEntriesPerServer,
		MaxTotalSize:         s.server.metadataMaxTotalSize,
	}

	// Set metadata in database with limit enforcement
	err := s.server.rdb.SetMetadataWithRetry(s.ctx, s.AccountID(), mailboxID, entries, limits)
	if err != nil {
		// Check if it's a metadata-specific error
		var metaErr *db.MetadataError
		if errors.As(err, &metaErr) {
			s.DebugLog("metadata limit exceeded", "error", metaErr)

			// Map MetadataError types to proper IMAP response codes
			var responseCode imap.ResponseCode
			switch metaErr.Type {
			case db.MetadataErrMaxSize:
				responseCode = imap.ResponseCodeTooBig
			case db.MetadataErrTooMany, db.MetadataErrQuotaExceeded:
				responseCode = imap.ResponseCodeTooMany
			case db.MetadataErrNoPrivate:
				responseCode = imap.ResponseCodeNoPrivate
			default:
				responseCode = imap.ResponseCodeLimit
			}

			// Return proper IMAP error with response code
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: responseCode,
				Text: metaErr.Message,
			}
		}

		s.DebugLog("failed to set metadata", "error", err)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: fmt.Sprintf("failed to set metadata: %v", err),
		}
	}

	s.useMasterDB.Store(true) // Pin session to master DB for read-your-writes consistency
	return nil
}

// canonicalMetadataEntry returns the canonical form of a metadata entry name.
// RFC 5464 §3.1 states entry names are case-insensitive, so we fold to lower
// case for storage, lookup, and /private-vs-/shared classification. Applying it
// at the protocol boundary keeps the case-insensitivity invariant in one place
// (and prevents a /SHARED/... spelling from evading the shared-scope ACL check).
func canonicalMetadataEntry(entry string) string {
	return strings.ToLower(entry)
}

// validateMetadataEntry validates a (canonicalised) metadata entry name per
// RFC 5464 §3.1 / §4.2.1: entry names live under the /private or /shared
// hierarchies and, being astrings, may contain any character EXCEPT "*", "%",
// non-ASCII octets, and control characters. Pass the canonical form.
func validateMetadataEntry(entry string) error {
	if entry == "" {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeClientBug,
			Text: "metadata entry name cannot be empty",
		}
	}

	if !strings.HasPrefix(entry, "/private/") && !strings.HasPrefix(entry, "/shared/") {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeClientBug,
			Text: "metadata entry must start with /private/ or /shared/",
		}
	}

	// RFC 5464 forbids "*", "%", non-ASCII, and control characters (incl. DEL);
	// everything else in the ASCII printable range is a valid entry-name octet.
	for i := 0; i < len(entry); i++ {
		ch := entry[i]
		if ch < 0x20 || ch >= 0x7f || ch == '*' || ch == '%' {
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeClientBug,
				Text: fmt.Sprintf("metadata entry contains invalid character: %q", string(ch)),
			}
		}
	}

	return nil
}
