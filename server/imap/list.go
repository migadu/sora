package imap

import (
	"context"
	"regexp"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

func (s *IMAPSession) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	ctx := context.Background()

	// Determine whether to list subscribed mailboxes
	subscribed := options != nil && options.SelectSubscribed

	// Fetch mailboxes from the database
	var mailboxes []db.Mailbox
	var err error
	if subscribed {
		mailboxes, err = s.server.db.GetSubscribedMailboxes(ctx, s.user.UserID())
	} else {
		mailboxes, err = s.server.db.GetMailboxes(ctx, s.user.UserID())
	}
	if err != nil {
		return s.internalError("failed to list mailboxes: %v", err)
	}

	for _, pattern := range patterns {
		// Resolve the pattern against the reference name
		resolvedPattern := resolveMailboxPattern(ref, pattern)

		for _, mbox := range mailboxes {
			if matchMailboxName(resolvedPattern, mbox.Name) {
				// Prepare attributes
				attributes := []imap.MailboxAttr{}

				// Check if the mailbox has children
				hasChildren, err := s.server.db.MailboxHasChildren(ctx, mbox.ID)
				if err != nil {
					return s.internalError("failed to check mailbox children: %v", err)
				}

				if hasChildren {
					attributes = append(attributes, imap.MailboxAttrHasChildren)
				} else {
					attributes = append(attributes, imap.MailboxAttrHasNoChildren)
				}

				// Add special attributes
				switch strings.ToUpper(mbox.Name) {
				case "SENT":
					attributes = append(attributes, imap.MailboxAttrSent)
				case "TRASH":
					attributes = append(attributes, imap.MailboxAttrTrash)
				case "DRAFTS":
					attributes = append(attributes, imap.MailboxAttrDrafts)
				case "ARCHIVE":
					attributes = append(attributes, imap.MailboxAttrArchive)
				case "JUNK":
					attributes = append(attributes, imap.MailboxAttrJunk)
				}

				fullMailboxPath := mbox.Name
				if mbox.ParentID != nil {
					fullMailboxPath = *mbox.ParentPath + string(consts.MailboxDelimiter) + mbox.Name
				}

				listData := &imap.ListData{
					Mailbox: fullMailboxPath,
					Delim:   consts.MailboxDelimiter,
					Attrs:   attributes,
				}

				if err := w.WriteList(listData); err != nil {
					return s.internalError("failed to write mailbox data: %v", err)
				}
			}
		}
	}

	return nil
}

func resolveMailboxPattern(ref, pattern string) string {
	// If pattern starts with hierarchy delimiter, ignore ref
	if len(pattern) > 0 && rune(pattern[0]) == consts.MailboxDelimiter {
		return pattern
	}
	// If ref is empty, return pattern
	if ref == "" {
		return pattern
	}
	// Combine ref and pattern with delimiter if needed
	combined := ref
	if len(ref) > 0 && rune(ref[len(ref)-1]) != consts.MailboxDelimiter {
		combined += string(consts.MailboxDelimiter)
	}
	combined += pattern
	return combined
}

func matchMailboxName(pattern, name string) bool {
	// Replace IMAP wildcards with Go wildcards
	pattern = strings.ReplaceAll(pattern, "%", "*")
	pattern = strings.ReplaceAll(pattern, "*", ".*")

	// Compile the pattern into a regular expression
	regexPattern := "^" + pattern + "$"
	matched, err := regexp.MatchString(regexPattern, name)
	if err != nil {
		return false
	}
	return matched
}
