package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
)

// Subscriptions (RFC 3501 §6.3.6 / RFC 9051 §6.3.7) are NAME-based and decoupled
// from mailbox existence: subscribing a name that has no mailbox is valid, and a
// subscription survives its mailbox's deletion (so LSUB / LIST (SUBSCRIBED) can
// report it with \NonExistent). The `subscriptions` table (migration 000046) is
// the authoritative store; the legacy `mailboxes.subscribed` column is unused by
// the subscription code path from here on.

// defaultMailboxNamesLower holds consts.DefaultMailboxes in lower case (they are
// ASCII), for Unsubscribe.
var defaultMailboxNamesLower = func() []string {
	names := make([]string, len(consts.DefaultMailboxes))
	for i, name := range consts.DefaultMailboxes {
		names[i] = strings.ToLower(name)
	}
	return names
}()

// Subscribe records a name-based subscription for the account. Idempotent and
// case-insensitive (matching mailbox-name case-insensitivity, migration 000041).
func (db *Database) Subscribe(ctx context.Context, tx pgx.Tx, accountID int64, mailboxName string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO subscriptions (account_id, mailbox_name)
		VALUES ($1, $2)
		ON CONFLICT (account_id, LOWER(mailbox_name)) DO NOTHING
	`, accountID, mailboxName)
	if err != nil {
		return fmt.Errorf("failed to subscribe %q: %w", mailboxName, err)
	}
	return nil
}

// Unsubscribe removes a name-based subscription. Idempotent and case-insensitive.
// A default mailbox's subscription is kept: default mailboxes stay permanently
// subscribed. Whether the name is a default mailbox's is asked of the row it
// matches (lower() under the "C" collation folds ASCII letters only). Also
// keep a legacy Unicode-spelled subscription when the database resolves it to
// a live, canonically named default mailbox of this account. An ordinary
// Unicode-named physical mailbox is not a default just because its lower()
// happens to match one: the stored physical name must be an ASCII default.
func (db *Database) Unsubscribe(ctx context.Context, tx pgx.Tx, accountID int64, mailboxName string) error {
	_, err := tx.Exec(ctx, `
		DELETE FROM subscriptions s
		WHERE s.account_id = $1 AND LOWER(s.mailbox_name) = LOWER($2)
		  AND LOWER(s.mailbox_name COLLATE "C") <> ALL ($3)
		  AND NOT EXISTS (
		      SELECT 1 FROM mailboxes m
		      WHERE m.account_id = s.account_id AND m.deleted_at IS NULL
		        AND LOWER(m.name) = LOWER(s.mailbox_name)
		        AND LOWER(m.name COLLATE "C") = ANY ($3)
		  )
	`, accountID, mailboxName, defaultMailboxNamesLower)
	if err != nil {
		return fmt.Errorf("failed to unsubscribe %q: %w", mailboxName, err)
	}
	return nil
}

// GetSubscribedMailboxNames returns every subscribed name for the account,
// including names that no longer have (or never had) a corresponding mailbox.
func (db *Database) GetSubscribedMailboxNames(ctx context.Context, accountID int64) ([]string, error) {
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT mailbox_name FROM subscriptions WHERE account_id = $1 ORDER BY mailbox_name
	`, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to list subscriptions: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("failed to scan subscription: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating subscriptions: %w", err)
	}
	return names, nil
}

// GetSubscribedMailboxNamesByKey returns every subscribed name for the account,
// keyed by LOWER(mailbox_name) as the database computes it, the key a
// subscription matches a mailbox by (DBMailbox.NameKey). Like
// GetSubscribedMailboxNames it includes names with no mailbox.
func (db *Database) GetSubscribedMailboxNamesByKey(ctx context.Context, accountID int64) (map[string]string, error) {
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT LOWER(mailbox_name), mailbox_name FROM subscriptions WHERE account_id = $1
	`, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to list subscriptions: %w", err)
	}
	defer rows.Close()

	names := make(map[string]string)
	for rows.Next() {
		var key, name string
		if err := rows.Scan(&key, &name); err != nil {
			return nil, fmt.Errorf("failed to scan subscription: %w", err)
		}
		names[key] = name
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating subscriptions: %w", err)
	}
	return names, nil
}

// RenameSubscriptions moves a subscription and all of its descendants from
// oldName to newName when a mailbox is renamed, so the subscription follows the
// rename (e.g. renaming "A" → "B" turns a subscription "A/x" into "B/x"). Any
// pre-existing subscription in the destination name-space is removed first so the
// per-account unique index cannot be violated. delimiter is the hierarchy
// separator (e.g. "/").
func (db *Database) RenameSubscriptions(ctx context.Context, tx pgx.Tx, accountID int64, oldName, newName, delimiter string) error {
	// LIKE pattern matching the descendants of oldName ("oldName/<anything>").
	descPattern := escapeLike(oldName+delimiter) + "%"

	// Drop any destination-namespace subscriptions that would collide with the
	// moved rows (the caller has already verified the destination MAILBOX does not
	// exist, but a subscription to the bare name can exist independently).
	if _, err := tx.Exec(ctx, `
		DELETE FROM subscriptions
		WHERE account_id = $1
		  AND (LOWER(mailbox_name) = LOWER($2)
		       OR LOWER(mailbox_name) LIKE LOWER($3) ESCAPE '\')
	`, accountID, newName, escapeLike(newName+delimiter)+"%"); err != nil {
		return fmt.Errorf("failed to clear destination subscriptions for rename: %w", err)
	}

	// Move the exact name and every descendant, preserving each descendant's
	// levels after the old name's (see mailboxNameLevels): a subscription matches
	// by LOWER(mailbox_name), so it can spell the old name with another length.
	if _, err := tx.Exec(ctx, `
		UPDATE subscriptions
		SET mailbox_name = array_to_string(ARRAY[$2::text] || (string_to_array(mailbox_name, $5))[$6::int + 1:], $5)
		WHERE account_id = $1
		  AND (LOWER(mailbox_name) = LOWER($4)
		       OR LOWER(mailbox_name) LIKE LOWER($3) ESCAPE '\')
	`, accountID, newName, descPattern, oldName, delimiter, mailboxNameLevels(oldName, delimiter)); err != nil {
		return fmt.Errorf("failed to move subscriptions for rename: %w", err)
	}
	return nil
}

// likeEscaper is built once: a strings.Replacer allocates its byte table on
// first use, and escapeLike runs once per entry name of a GETMETADATA request.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// escapeLike escapes the LIKE metacharacters in s so it can be used as a literal
// prefix in a `LIKE ... ESCAPE '\'` pattern.
func escapeLike(s string) string {
	return likeEscaper.Replace(s)
}
