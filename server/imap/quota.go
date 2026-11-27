package imap

import (
	"context"
	"errors"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// IMAP QUOTA (RFC 9208), report-only. Each account has one quota root, the empty
// name "" (as in the RFC's examples), over all of its own mailboxes. Its one resource
// is STORAGE, accounts.storage_quota set through the Admin API; an unlimited account
// has the root without resources (§4.2.1 allows a root with no limits). Nothing
// refuses APPEND, COPY or MOVE over the limit: §3.1.2 lets limits be soft, and
// delivery is gated before Sora. SETQUOTA is refused by go-imap (NOPERM, and no
// QUOTASET advertised), since the Admin API owns the limit.

// quotaRoot is the name of an account's only quota root.
const quotaRoot = ""

// QuotaResourceTypes is the resource Sora reports, advertised as QUOTA=RES-STORAGE.
// RES-STORAGE needs STATUS DELETED-STORAGE (RFC 9208 §5.1), which Status serves.
// MESSAGE is left out: it would oblige STATUS DELETED without IMAP4rev2 (§5.2) and
// nothing limits it.
func (s *IMAPSession) QuotaResourceTypes() []imap.QuotaResourceType {
	return []imap.QuotaResourceType{imap.QuotaResourceStorage}
}

// GetQuota answers for the user's own root; any other name is no root of theirs.
func (s *IMAPSession) GetQuota(ctx context.Context, root string) (*imap.QuotaData, error) {
	if root != quotaRoot {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "No such quota root",
		}
	}
	ctx = s.pinnedContext(ctx)
	accountID, err := s.quotaAccountID(ctx)
	if err != nil {
		return nil, err
	}
	return s.accountQuota(ctx, accountID)
}

// GetQuotaRoot names the user's root for a mailbox of their own, existing or not
// (RFC 9208 §4.1.2: the root a mailbox would get when created). A mailbox someone
// else owns, which the user sees through sharing, gets no root: its messages count
// against its owner, whose quota is not the user's to read. So does a name in the
// shared namespace that does not exist yet. Either way the answer is the same as for
// a shared mailbox that does not exist, so it tells no one what exists.
func (s *IMAPSession) GetQuotaRoot(ctx context.Context, mboxName string) ([]imap.QuotaData, error) {
	ctx = s.pinnedContext(ctx)
	accountID, err := s.quotaAccountID(ctx)
	if err != nil {
		return nil, err
	}

	mailbox, err := s.server.rdb.GetMailboxByNameWithRetry(ctx, accountID, mboxName)
	switch {
	case errors.Is(err, consts.ErrMailboxNotFound):
		if s.server.config != nil && s.server.config.SharedMailboxes.InNamespace(mboxName) {
			return nil, nil
		}
	case err != nil:
		return nil, s.internalError("failed to fetch mailbox '%s' for GETQUOTAROOT: %v", mboxName, err)
	case mailbox.AccountID != accountID:
		return nil, nil
	}
	// The user owns the mailbox, so the read right STORAGE needs (RFC 9208 §6) is
	// theirs: has_mailbox_right() grants an owner every right.

	data, err := s.accountQuota(ctx, accountID)
	if err != nil {
		return nil, err
	}
	return []imap.QuotaData{*data}, nil
}

// quotaAccountID reads the session's account ID under the session's read lock.
func (s *IMAPSession) quotaAccountID(ctx context.Context) (int64, error) {
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		s.WarnLog("failed to acquire read lock")
		return 0, s.internalError("failed to acquire lock for quota")
	}
	defer release()
	return s.AccountID(), nil
}

// accountQuota is the QUOTA response for the session's account.
func (s *IMAPSession) accountQuota(ctx context.Context, accountID int64) (*imap.QuotaData, error) {
	quota, err := s.server.rdb.GetAccountQuotaWithRetry(ctx, accountID)
	if err != nil {
		return nil, s.internalError("failed to get quota: %v", err)
	}
	return quotaData(quota), nil
}

// quotaData renders an account's quota as its root's QUOTA response. STORAGE is in
// units of 1024 octets (RFC 9208 §5.1): the usage is rounded up, so a nonempty
// account never reads as empty, and the limit down, so the room it shows is never
// more than there is.
func quotaData(quota *db.AccountQuota) *imap.QuotaData {
	data := &imap.QuotaData{
		Root:      quotaRoot,
		Resources: map[imap.QuotaResourceType]imap.QuotaResourceData{},
	}
	if quota.StorageQuota != nil {
		used := max(quota.StorageUsed, 0) // the mailbox_stats cache can drift below zero
		data.Resources[imap.QuotaResourceStorage] = imap.QuotaResourceData{
			Usage: (used + 1023) / 1024,
			Limit: *quota.StorageQuota / 1024,
		}
	}
	return data
}

// setDeletedStatus fills the DELETED and DELETED-STORAGE items a STATUS (or a
// LIST-STATUS) asked for. DELETED-STORAGE is the sum of RFC822.SIZE of the \Deleted
// messages, which RFC 9208 §4.1.4 allows in place of the exact space an EXPUNGE would
// free; for Sora it is exact as far as the quota goes, since STORAGE sums the same sizes.
func setDeletedStatus(data *imap.StatusData, options *imap.StatusOptions, deleted db.DeletedMessages) {
	if options.NumDeleted {
		num := deleted.Count
		data.NumDeleted = &num
	}
	if options.DeletedStorage {
		size := deleted.Size
		data.DeletedStorage = &size
	}
}
