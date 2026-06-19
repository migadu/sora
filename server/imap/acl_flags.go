package imap

import (
	"context"
	"sort"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
)

// userRightsForMailbox returns the current user's effective ACL rights string on
// the given mailbox. The mailbox owner implicitly holds every right, so personal
// mailboxes are answered without a database lookup.
func (s *IMAPSession) userRightsForMailbox(ctx context.Context, mailboxID, ownerAccountID int64) (string, error) {
	if ownerAccountID == s.AccountID() {
		return db.AllACLRights, nil
	}
	return s.server.rdb.GetUserMailboxRightsWithRetry(ctx, mailboxID, s.AccountID())
}

// flagRightHeld reports whether a user holding `rights` may set or clear `flag`,
// per RFC 4314 §4: \Seen requires the "s" right, \Deleted requires "t", and every
// other flag (including custom keywords) requires "w".
func flagRightHeld(flag imap.Flag, rights string) bool {
	switch flag {
	case imap.FlagSeen:
		return strings.ContainsRune(rights, 's')
	case imap.FlagDeleted:
		return strings.ContainsRune(rights, 't')
	default:
		return strings.ContainsRune(rights, 'w')
	}
}

// filterFlagsByRights returns the subset of flags the user may set given `rights`
// (RFC 4314 §4). Order is preserved.
func filterFlagsByRights(flags []imap.Flag, rights string) []imap.Flag {
	out := make([]imap.Flag, 0, len(flags))
	for _, f := range flags {
		if flagRightHeld(f, rights) {
			out = append(out, f)
		}
	}
	return out
}

// replaceTargetFlags computes the result of a STORE FLAGS (replace) that respects
// ACL rights (RFC 4314 §4): flags the user may not modify keep their current value,
// while flags the user may modify take the requested value. The owner (full rights)
// gets exactly `desired`.
func replaceTargetFlags(current, desired []imap.Flag, rights string) []imap.Flag {
	target := make([]imap.Flag, 0, len(current)+len(desired))
	seen := make(map[imap.Flag]struct{}, len(current)+len(desired))
	add := func(f imap.Flag) {
		if _, ok := seen[f]; !ok {
			seen[f] = struct{}{}
			target = append(target, f)
		}
	}
	// Preserve the current values of flags the user cannot modify.
	for _, f := range current {
		if !flagRightHeld(f, rights) {
			add(f)
		}
	}
	// Apply the requested values for flags the user can modify.
	for _, f := range desired {
		if flagRightHeld(f, rights) {
			add(f)
		}
	}
	return target
}

// flagSetKey returns an order-independent key identifying a set of flags, used to
// group messages that should receive the same STORE FLAGS batch.
func flagSetKey(flags []imap.Flag) string {
	parts := make([]string, len(flags))
	for i, f := range flags {
		parts[i] = string(f)
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}
