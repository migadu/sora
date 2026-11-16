package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/migadu/sora/consts"
)

// destinationCompletedSQL applies to a messages row aliased as m. The shared
// s3_uploaded projection is compatibility state, never incremental eligibility:
// another process can be using the same cache for a different destination.
const destinationCompletedSQL = `EXISTS (
	SELECT 1 FROM import_completions c
	WHERE c.database_uuid = ? AND c.account_id = ?
	  AND c.hash = m.hash AND c.mailbox = m.mailbox
)`

// recoverOrphanedSQLiteState projects the completion history for this destination
// onto messages.s3_uploaded. A trusted completion survives a subsequent deletion
// in Sora. Legacy/exporter marks and marks from another destination are unverified:
// only a live copy in the account's own target mailbox can establish completion.
func (i *Importer) recoverOrphanedSQLiteState() error {
	if i.user == nil {
		return fmt.Errorf("import account has not been resolved")
	}
	if i.databaseUUID == "" {
		identity, err := i.rdb.GetDatabaseIdentityWithRetry(i.ctx)
		if err != nil {
			return fmt.Errorf("failed to identify destination database: %w", err)
		}
		if identity == "" {
			return fmt.Errorf("destination database identity is empty")
		}
		i.databaseUUID = identity
	}
	accountID := i.user.AccountID()
	rows, err := i.sqliteDB.QueryContext(i.ctx, `
		SELECT m.hash, m.mailbox, COALESCE(m.s3_uploaded, 0), EXISTS (
			SELECT 1 FROM import_completions c
			WHERE c.database_uuid = ? AND c.account_id = ?
			  AND c.hash = m.hash AND c.mailbox = m.mailbox
		)
		FROM messages m
		WHERE m.s3_uploaded = 1 OR EXISTS (
			SELECT 1 FROM import_completions c
			WHERE c.database_uuid = ? AND c.account_id = ?
			  AND c.hash = m.hash AND c.mailbox = m.mailbox
		)`, i.databaseUUID, accountID, i.databaseUUID, accountID)
	if err != nil {
		return fmt.Errorf("failed to read import completion history: %w", err)
	}
	var trusted []markedMessage
	unverified := make(map[string][]markedMessage)
	for rows.Next() {
		var m markedMessage
		var uploaded, completed bool
		if err := rows.Scan(&m.hash, &m.mailbox, &uploaded, &completed); err != nil {
			rows.Close()
			return fmt.Errorf("failed to read cached completion: %w", err)
		}
		if completed {
			if !uploaded {
				trusted = append(trusted, m)
			}
		} else {
			unverified[m.mailbox] = append(unverified[m.mailbox], m)
		}
	}
	readErr := rows.Err()
	closeErr := rows.Close() // Release the single SQLite connection before PostgreSQL.
	if readErr != nil {
		return fmt.Errorf("failed to read cached completions: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("failed to close cached completions: %w", closeErr)
	}

	var missing, verified []markedMessage
	// Completion proof must come from the primary, not a lagging read replica.
	readCtx := context.WithValue(i.ctx, consts.UseMasterDBKey, true)
	for mailbox, cached := range unverified {
		mailboxID, err := i.rdb.GetOwnedMailboxIDByNameWithRetry(readCtx, accountID, mailbox)
		if errors.Is(err, consts.ErrMailboxNotFound) {
			missing = append(missing, cached...)
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to verify cached mailbox %q: %w", mailbox, err)
		}
		for start := 0; start < len(cached); start += recoveryHashBatchSize {
			end := min(start+recoveryHashBatchSize, len(cached))
			chunk := cached[start:end]
			hashes := make([]string, len(chunk))
			for n, m := range chunk {
				hashes[n] = m.hash
			}
			var absent []string
			if err := i.rdb.QueryRowWithRetry(readCtx, `
				SELECT COALESCE(ARRAY_AGG(h), '{}')
				FROM UNNEST($3::text[]) AS h
				WHERE NOT EXISTS (
					SELECT 1 FROM messages
					WHERE account_id = $1 AND mailbox_id = $2
					  AND content_hash = h AND expunged_at IS NULL
				)`, accountID, mailboxID, hashes).Scan(&absent); err != nil {
				return fmt.Errorf("failed to verify cached messages in %q: %w", mailbox, err)
			}
			isAbsent := make(map[string]bool, len(absent))
			for _, hash := range absent {
				isAbsent[hash] = true
			}
			for _, m := range chunk {
				if isAbsent[m.hash] {
					missing = append(missing, m)
				} else {
					verified = append(verified, m)
				}
			}
		}
	}
	if len(trusted)+len(missing)+len(verified) == 0 {
		return nil
	}

	// Do not change a mark or create a trusted completion until every primary
	// check succeeded. All projection/ledger changes then commit atomically.
	tx, err := i.sqliteDB.BeginTx(i.ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin completion recovery: %w", err)
	}
	defer tx.Rollback()
	for _, m := range missing {
		if _, err := tx.ExecContext(i.ctx, `UPDATE messages
			SET s3_uploaded = 0, s3_uploaded_at = NULL, account_id = NULL
			WHERE hash = ? AND mailbox = ?`, m.hash, m.mailbox); err != nil {
			return fmt.Errorf("failed to re-arm cached message: %w", err)
		}
	}
	now := time.Now()
	for _, m := range append(trusted, verified...) {
		if _, err := tx.ExecContext(i.ctx, `UPDATE messages
			SET s3_uploaded = 1, s3_uploaded_at = COALESCE(s3_uploaded_at, ?), account_id = ?
			WHERE hash = ? AND mailbox = ?`, now, accountID, m.hash, m.mailbox); err != nil {
			return fmt.Errorf("failed to project cached completion: %w", err)
		}
	}
	for _, m := range verified {
		if _, err := tx.ExecContext(i.ctx, `INSERT OR IGNORE INTO import_completions
			(database_uuid, account_id, hash, mailbox, completed_at) VALUES (?, ?, ?, ?, ?)`,
			i.databaseUUID, accountID, m.hash, m.mailbox, now); err != nil {
			return fmt.Errorf("failed to record verified completion: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit completion recovery: %w", err)
	}
	return nil
}

// keepLegacyImportIdentity preserves a byte-proven SHA-256 identity that a prior
// import completed. Another destination's completion can preserve the identity,
// but cannot suppress this destination's import. Rekeying this shared cache row
// would lose the other destination's deletion history and default-run dedup key.
func (i *Importer) keepLegacyImportIdentity(m msgInfo, content []byte) (bool, error) {
	if m.hash != legacyImportHash(content) {
		return false, nil // A real byte change must always receive its current hash.
	}
	if m.imported {
		return true, nil // Current destination's completion was read with this row.
	}
	var known bool
	if err := i.sqliteDB.QueryRowContext(i.ctx, `SELECT EXISTS (
		SELECT 1 FROM import_completions WHERE hash = ? AND mailbox = ?
	)`, m.hash, m.mailbox).Scan(&known); err != nil {
		return false, fmt.Errorf("read completed legacy identity: %w", err)
	}
	return known, nil
}
