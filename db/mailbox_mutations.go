package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// CreatedMailbox is the immutable identity and initial state of this INSERT,
// not a later mailbox found under the same name. Visible follows the actor's
// addressable-name winner; an ancestor without lookup rights is not invented.
type CreatedMailbox struct {
	NotifyMailbox
	Visible bool
}

type mailboxCreationCapture struct {
	viewer int64
	state  CreatedMailbox
}

func (d *Database) CreateMailboxReturningState(ctx context.Context, tx pgx.Tx, ownerID, viewerID int64, name string, parentID *int64, specialUse string) (*CreatedMailbox, error) {
	capture := mailboxCreationCapture{viewer: viewerID}
	if err := d.createMailbox(ctx, tx, ownerID, name, parentID, specialUse, &capture); err != nil {
		return nil, err
	}
	return &capture.state, nil
}

// lockNotifyMailboxForMutation uses the same owned/direct-ACL/domain-anyone
// winner as the watch snapshot, constrained to one name. Lock the actual row
// before a name-based subscription write so DELETE/RENAME cannot swap its
// identity before commit. A missing/renamed/hidden row is conservative unknown.
// sharedAccess (Database.sharedAccess) gates the other owners' candidates.
func lockNotifyMailboxForMutation(ctx context.Context, tx pgx.Tx, actorID int64, name string, sharedAccess bool) (*NotifyMailbox, error) {
	var m NotifyMailbox
	var validity int64
	err := tx.QueryRow(ctx, `
		WITH candidates AS (
			SELECT id,0 AS priority FROM mailboxes
			WHERE account_id=$1 AND LOWER(name)=LOWER($2) AND deleted_at IS NULL
			UNION ALL
			SELECT m.id,1 FROM mailbox_acls a JOIN mailboxes m ON m.id=a.mailbox_id
			WHERE $3::boolean AND a.account_id=$1 AND position('l' IN a.rights)>0 AND m.is_shared=TRUE
			  AND m.deleted_at IS NULL AND LOWER(m.name)=LOWER($2)
			UNION ALL
			SELECT m.id,2 FROM mailbox_acls a JOIN mailboxes m ON m.id=a.mailbox_id
			WHERE $3::boolean AND a.identifier='anyone' AND position('l' IN a.rights)>0 AND m.is_shared=TRUE
			  AND m.deleted_at IS NULL AND LOWER(m.name)=LOWER($2)
			  AND m.owner_domain=(SELECT domain FROM credentials WHERE account_id=$1 AND primary_identity=TRUE)
		), winner AS (SELECT id FROM candidates ORDER BY priority,id LIMIT 1)
		SELECT m.id,m.name,LOWER(m.name),m.uid_validity,m.account_id,
		       EXISTS(SELECT 1 FROM subscriptions s WHERE s.account_id=$1 AND LOWER(s.mailbox_name)=LOWER(m.name))
		FROM mailboxes m JOIN winner w ON w.id=m.id
		WHERE m.deleted_at IS NULL AND LOWER(m.name)=LOWER($2)
		FOR NO KEY UPDATE OF m
	`, actorID, name, sharedAccess).Scan(&m.ID, &m.Name, &m.NameKey, &validity, &m.OwnerID, &m.Subscribed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock subscription mailbox identity: %w", err)
	}
	m.UIDValidity = uint32(validity)
	return &m, nil
}

// MailboxNameMutation describes only this transaction's name change, never a
// complete later snapshot entry (which could contain someone else's flags).
// When the caller is not the mailbox owner, db.RenameMailbox does not rewrite
// the caller's name-based subscriptions, so SubscribedSet is true. The NOTIFY
// caller resolves their destination-name subscription from its observed baseline,
// rather than absorbing a foreign change committed before the rename.
type MailboxNameMutation struct {
	ID                    int64
	BeforeName, BeforeKey string
	AfterName, AfterKey   string
	SubscribedSet         bool
}

type mailboxRenameCapture struct {
	viewer  int64
	changes []MailboxNameMutation
}

func (d *Database) RenameMailboxReturningNames(ctx context.Context, tx pgx.Tx, mailboxID, ownerID, viewerID int64, name string, parentID *int64) ([]MailboxNameMutation, error) {
	capture := mailboxRenameCapture{viewer: viewerID}
	if err := d.renameMailbox(ctx, tx, mailboxID, ownerID, name, parentID, &capture); err != nil {
		return nil, err
	}
	return capture.changes, nil
}

// SubscriptionMutation is emitted only when this write changed the name-based
// subscription. An idempotent request must not absorb a preceding foreign write.
type SubscriptionMutation struct {
	// NameKey is present even for a subscribed name with no visible mailbox.
	NameKey    string
	Mailbox    NotifyMailbox
	Subscribed bool
	Changed    bool
}

func (d *Database) UpdateSubscriptionReturningState(ctx context.Context, tx pgx.Tx, actorID int64, name string, subscribe bool) (SubscriptionMutation, error) {
	m, err := lockNotifyMailboxForMutation(ctx, tx, actorID, name, d.sharedAccess())
	if err != nil {
		return SubscriptionMutation{}, err
	}
	var changed bool
	if subscribe {
		changed, err = d.subscribe(ctx, tx, actorID, name)
	} else {
		changed, err = d.unsubscribe(ctx, tx, actorID, name)
	}
	if err != nil {
		return SubscriptionMutation{}, err
	}
	result := SubscriptionMutation{Subscribed: subscribe, Changed: changed}
	if m != nil {
		result.Mailbox = *m
		result.NameKey = m.NameKey
	} else if err := tx.QueryRow(ctx, "SELECT LOWER($1::text)", name).Scan(&result.NameKey); err != nil {
		return SubscriptionMutation{}, fmt.Errorf("read subscription name key: %w", err)
	}
	return result, nil
}
