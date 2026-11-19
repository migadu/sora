package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/logger"
)

// MaxCrossAccountBodies bounds all distinct source bodies when any selected row
// is rekeyed to another account, including legacy rows already owned by the
// destination. Source/destination global body claims and FTS locks remain held
// through commit. Their budget excludes source-account and ordinary SQL locks,
// and concurrent commands still need shared lock-table capacity. Pure same-owner
// commands retain their existing policy. COPY cannot be split into partial commits.
const MaxCrossAccountBodies = 1000

// ErrCrossAccountBodyLimit refuses an oversized cross-account source budget.
// Account guards may be held for a fresh check, but no body lock, storage callback
// or message write has started.
var ErrCrossAccountBodyLimit = fmt.Errorf("a copy or move into another account's mailbox is limited to %d distinct source bodies", MaxCrossAccountBodies)

// CheckCrossAccountBodies checks a protocol preflight map containing every selected
// source UID when any row is rekeyed. The actual write transaction repeats the
// complete-source check under account-rekey guards. Repeated bodies count once.
func CheckCrossAccountBodies(sourceHashes map[imap.UID]string) error {
	if len(sourceHashes) <= MaxCrossAccountBodies {
		return nil
	}
	bodies := make(map[string]struct{}, MaxCrossAccountBodies+1)
	for _, hash := range sourceHashes {
		bodies[hash] = struct{}{}
		if len(bodies) > MaxCrossAccountBodies {
			return ErrCrossAccountBodyLimit
		}
	}
	return nil
}

// LockS3ObjectsSharedInTx takes the S3 object locks (GetS3ObjectLockID) of accountID's
// contentHashes in shared mode on tx, in id order, waiting for an exclusive holder (for at
// most the transaction's lock_timeout). They last until tx ends. Shared holders do not
// exclude one another; they keep out the exclusive holders used by typed durable
// body cleanup (the cleaner and purge skip a busy object). Restore, rekey admission and the uploader gate share
// immutable claims. Each lock consumes a lock-table entry until tx ends; callers
// budget their batches, including the complete-source COPY/MOVE check.
//
// The statement carries the ids as literals, so it goes over the simple protocol and
// leaves no portal or snapshot behind: a transaction that holds the locks across S3 round
// trips before its first write idles with neither a transaction id nor an xmin, and so
// holds back neither VACUUM nor CREATE INDEX CONCURRENTLY.
func LockS3ObjectsSharedInTx(ctx context.Context, tx pgx.Tx, accountID int64, contentHashes []string) error {
	if len(contentHashes) == 0 {
		return nil
	}
	ids := make([]int64, len(contentHashes))
	for i, hash := range contentHashes {
		ids[i] = GetS3ObjectLockID(accountID, hash)
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	literals := make([]string, len(ids))
	for i, id := range ids {
		literals[i] = strconv.FormatInt(id, 10)
	}
	// unnest preserves array order, so the locks are taken in it.
	sql := "SELECT pg_advisory_xact_lock_shared(id) FROM unnest(ARRAY[" + strings.Join(literals, ",") + "]::bigint[]) AS t(id)"
	if _, err := tx.Exec(ctx, sql); err != nil {
		return fmt.Errorf("failed to lock S3 objects: %w", err)
	}
	return CheckS3BodyClaims(ctx, tx, contentHashes)
}

// ErrMoveSourceChanged is returned by MoveMessages when a source row owned by another
// account than the destination no longer has the content hash the caller made its body
// available for under the destination owner's S3 path. Nothing is written; reading the
// source again and moving anew can succeed.
var ErrMoveSourceChanged = errors.New("a source message changed during the move")

// MoveMessages moves the messages with the given UIDs from srcMailboxID into
// destMailboxID, owned by destAccountID, within the caller's transaction, and returns a
// map of old UIDs to new UIDs.
//
// A moved row of another account is re-keyed to destAccountID's S3 path
// (destS3Domain/destS3Localpart), where the caller must first have made its body
// available (its object, or the staging file of the upload restagePendingUploads
// queues). sourceHashes holds, by source UID, the content hash each such row had when
// the caller did so, and the row is moved only if it still has it: sora-admin import
// rekey renames a body's hash (RekeyContentHash) under no lock the caller takes, and a
// row moved under the new hash would point at a key nothing wrote. A renamed source fails
// the move with ErrMoveSourceChanged before anything is written. The check is made once
// the source rows are locked, so their hashes cannot change again before tx ends.
//
// A re-keyed row is uploaded exactly when its body is in destObjects: the bodies whose
// object under that path the caller made exist while tx held their locks in shared mode
// (LockS3ObjectsSharedInTx), so the cleaner cannot have deleted it since and cannot until
// these rows commit. Any other re-keyed row is staged for an upload under the owner's
// path, from the staging file the caller linked there. Whether the source row is uploaded
// says nothing about the owner's key: an upload of the source that finished after the
// caller looked wrote only the source's key. sourceHashes and destObjects may be nil, as
// they are when every source row belongs to destAccountID.
func (db *Database) MoveMessages(ctx context.Context, tx pgx.Tx, ids *[]imap.UID, srcMailboxID, destMailboxID int64, destAccountID int64, destS3Domain string, destS3Localpart string, instanceID string, sourceHashes map[imap.UID]string, destObjects []string) (map[imap.UID]imap.UID, error) {
	// Map to store the original UID to new UID mapping
	messageUIDMap := make(map[imap.UID]imap.UID)
	if destObjects == nil {
		destObjects = []string{} // = ANY(NULL) would be NULL, not false
	}

	// Per RFC 6851, moving to the same mailbox is allowed and assigns new UIDs.
	// This is useful for "refreshing" messages with new UIDs.
	if srcMailboxID == destMailboxID {
		logger.Info("Database: moving messages within the same mailbox, will assign new UIDs", "mailbox_id", srcMailboxID)
	}

	if err := lockS3SourceClaims(ctx, tx, srcMailboxID, destMailboxID, destAccountID, ids, destObjects); err != nil {
		return nil, err
	}

	// Serialize unseen_count maintenance for both mailboxes by locking their
	// mailbox rows in ascending id order (see lockMailboxStats). This both
	// prevents the flag/expunge-vs-move trigger race from drifting the cache and
	// keeps a consistent lock ordering, so a concurrent MOVE between the same two
	// mailboxes cannot deadlock (A->B and B->A lock the same rows in the same order).
	if err := lockMailboxStatsPair(ctx, tx, srcMailboxID, destMailboxID); err != nil {
		return nil, fmt.Errorf("failed to lock mailbox stats for move on mailboxes %d and %d: %w", srcMailboxID, destMailboxID, err)
	}
	var srcWindow *ModSeqWindow
	if srcMailboxID != destMailboxID {
		srcWindow = modSeqWindowFor(ctx, srcMailboxID)
	}
	if err := srcWindow.begin(ctx, tx); err != nil {
		return nil, err
	}
	window := modSeqWindowFor(ctx, destMailboxID)
	if err := window.begin(ctx, tx); err != nil {
		return nil, err
	}

	// From here to the commit a rekey must not rename a source. The row locks below would
	// hold it off too, but a rekey waiting for them holds the FTS lock restageFTS needs.
	if err := lockRekeySources(ctx, tx, srcMailboxID, ids); err != nil {
		return nil, err
	}

	// Lock source message rows early (before INSERT triggers) to establish a
	// consistent lock ordering: mailbox_stats row locks → row locks on source rows.
	// Every unseen-mutating path (MOVE, EXPUNGE, STORE) acquires the mailbox_stats
	// row first and message rows second, so they cannot deadlock against each other.
	//
	// These row locks are also what protects the bodies of a move within one account,
	// which takes no S3 body lock (lockS3SourceClaims): the sources stay live until the
	// commit that expunges them and makes their replacements visible.
	rows, err := tx.Query(ctx, `
		SELECT id, uid, account_id, content_hash FROM messages
		WHERE mailbox_id = $1 AND uid = ANY($2) AND expunged_at IS NULL
		ORDER BY uid
		FOR UPDATE
	`, srcMailboxID, ids)
	if err != nil {
		logger.Error("Database: failed to query source messages", "err", err)
		return nil, fmt.Errorf("%w: %w", consts.ErrInternalError, err)
	}
	defer rows.Close()

	// Collect message IDs and source UIDs
	var messageIDs []int64
	var sourceUIDsForMap []imap.UID
	var rekeyed []bool // per message: re-keyed from another account to destAccountID
	for rows.Next() {
		var messageID, sourceAccountID int64
		var sourceUID imap.UID
		var contentHash string
		if err := rows.Scan(&messageID, &sourceUID, &sourceAccountID, &contentHash); err != nil {
			return nil, fmt.Errorf("failed to scan message ID and UID: %w", err)
		}
		// The row is locked now, so its hash is the one the INSERT below copies: a row
		// re-keyed to the owner must still have the hash the caller made its body
		// available for under the owner's key (sourceHashes).
		if srcMailboxID != destMailboxID && sourceAccountID != destAccountID && contentHash != sourceHashes[sourceUID] {
			return nil, fmt.Errorf("%w: UID %d", ErrMoveSourceChanged, sourceUID)
		}
		messageIDs = append(messageIDs, messageID)
		sourceUIDsForMap = append(sourceUIDsForMap, sourceUID)
		// A move within one mailbox keeps every row's account and S3 key (see below), so it
		// re-keys nothing, even a row of another account than the mailbox owner.
		rekeyed = append(rekeyed, sourceAccountID != destAccountID && srcMailboxID != destMailboxID)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through source messages: %w", err)
	}

	if len(messageIDs) == 0 {
		logger.Warn("Database: no messages found to move", "mailbox_id", srcMailboxID)
		return messageUIDMap, nil
	}

	// Atomically increment highest_uid for the number of messages being moved.
	var newHighestUID int64
	numToMove := int64(len(messageIDs))
	err = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + $1 WHERE id = $2 RETURNING highest_uid`, numToMove, destMailboxID).Scan(&newHighestUID)
	if err != nil {
		logger.Error("Database: failed to update highest UID", "err", err)
		return nil, fmt.Errorf("%w: %w", consts.ErrDBUpdateFailed, err)
	}

	// Calculate the new UIDs for the moved messages, and split them by whether the
	// move is re-keyed to the destination owner (see restagePendingUploads).
	var newUIDs, keptUIDs, rekeyedUIDs []int64
	startUID := newHighestUID - numToMove + 1
	for i, sourceUID := range sourceUIDsForMap {
		newUID := startUID + int64(i)
		newUIDs = append(newUIDs, newUID)
		if rekeyed[i] {
			rekeyedUIDs = append(rekeyedUIDs, newUID)
		} else {
			keptUIDs = append(keptUIDs, newUID)
		}
		messageUIDMap[sourceUID] = imap.UID(newUID)
	}

	// Fetch destination mailbox name within the same transaction
	var destMailboxName string
	if err := tx.QueryRow(ctx, "SELECT name FROM mailboxes WHERE id = $1", destMailboxID).Scan(&destMailboxName); err != nil {
		return nil, fmt.Errorf("failed to get destination mailbox name: %w", err)
	}

	// Batch insert the moved messages.
	//
	// For same-mailbox moves, we must mark old messages as expunged BEFORE inserting
	// new ones to avoid having two active copies of the same message.
	//
	// Both paths carry the source's flags. A source without a message_state row (left
	// by an older build) has none, and the moved message gets a
	// row with none.
	if srcMailboxID == destMailboxID {
		// Step 1: Mark old messages as expunged to remove them from the unique index
		_, err = tx.Exec(ctx, `
			UPDATE messages
			SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
			WHERE mailbox_id = $1 AND id = ANY($2) AND expunged_at IS NULL
		`, srcMailboxID, messageIDs)
		if err != nil {
			logger.Error("Database: failed to mark messages as expunged for same-mailbox move", "err", err)
			return nil, fmt.Errorf("failed to mark messages as expunged: %w", err)
		}

		// Step 2: Insert new copies with new UIDs
		// The expunged messages are now excluded from the unique index, so this succeeds
		_, err = tx.Exec(ctx, `
			WITH src_data AS (
				SELECT
					m.account_id, m.content_hash, m.uploaded, m.message_id, m.in_reply_to, m."references",
					m.subject, m.sent_date, m.sent_utc_offset, m.sent_date_unknown, m.internal_date, m.size,
					m.body_structure, m.recipients_json, m.s3_domain, m.s3_localpart,
					m.subject_sort, m.from_name_sort, m.from_email_sort, m.to_name_sort, m.to_email_sort, m.cc_email_sort, m.extra_addresses, m.header_presence, m.message_id_raw,
					m.id AS original_id,
					d.new_uid
				FROM messages m
				JOIN unnest($3::bigint[], $4::bigint[]) AS d(message_id, new_uid) ON m.id = d.message_id
			),
			inserted AS (
				INSERT INTO messages (
					account_id, content_hash, uploaded, message_id, in_reply_to, "references",
					subject, sent_date, sent_utc_offset, sent_date_unknown, internal_date, size,
					body_structure, recipients_json, s3_domain, s3_localpart,
					subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort, extra_addresses, header_presence, message_id_raw,
					mailbox_id, mailbox_path, created_modseq, uid
				)
				SELECT
					account_id, content_hash, uploaded, message_id, in_reply_to, "references",
					subject, sent_date, sent_utc_offset, sent_date_unknown, internal_date, size,
					body_structure, recipients_json, s3_domain, s3_localpart,
					subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort, extra_addresses, header_presence, message_id_raw,
					$1 AS mailbox_id,
					$2 AS mailbox_path,
					nextval('messages_modseq') AS created_modseq,
					new_uid
				FROM src_data
				RETURNING id, uid
			)
			INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
			SELECT i.id, $1, COALESCE(ms.flags, 0), COALESCE(ms.custom_flags, '[]'::jsonb), NOW(), nextval('messages_modseq')
			FROM inserted i
			JOIN src_data s ON s.new_uid = i.uid
			LEFT JOIN message_state ms ON ms.message_id = s.original_id
		`, srcMailboxID, destMailboxName, messageIDs, newUIDs)
		if err != nil {
			logger.Error("Database: failed to insert new messages for same-mailbox move", "err", err)
			return nil, fmt.Errorf("failed to move messages: %w", err)
		}
		logger.Info("Database: moved message(s) with new UIDs in same-mailbox move (old messages marked as expunged)", "count", len(messageIDs))
	} else {
		// Different mailbox: keyword identity is case-insensitive (RFC 9051 §2.3.2),
		// so fold each moved message's keywords onto the DESTINATION mailbox's
		// canonical case before inserting. Without this, a message carrying
		// "WAREHOUSING" moved into a mailbox whose canonical case is "warehousing"
		// would leave that mailbox reporting two cases of the same keyword across
		// its messages — the per-message inconsistency that trips strict clients.
		customFlagsCanon, err := db.canonicalizeMovedCustomFlags(ctx, tx, destMailboxID, messageIDs)
		if err != nil {
			return nil, err
		}

		// Different mailbox: normal insert from existing rows
		_, err = tx.Exec(ctx, `
			WITH src_data AS (
				SELECT
					m.content_hash, m.uploaded, m.message_id, m.in_reply_to, m."references",
					m.subject, m.sent_date, m.sent_utc_offset, m.sent_date_unknown, m.internal_date, m.size,
					m.body_structure, m.recipients_json,
					m.subject_sort, m.from_name_sort, m.from_email_sort, m.to_name_sort, m.to_email_sort, m.cc_email_sort, m.extra_addresses, m.header_presence, m.message_id_raw,
					m.id AS original_id,
					m.account_id AS src_account_id, m.s3_domain AS src_s3_domain, m.s3_localpart AS src_s3_localpart,
					d.new_uid,
					d.custom_flags_canon
				FROM messages m
				JOIN unnest($3::bigint[], $4::bigint[], $5::jsonb[]) AS d(message_id, new_uid, custom_flags_canon) ON m.id = d.message_id
			),
			inserted AS (
				INSERT INTO messages (
					account_id, content_hash, uploaded, message_id, in_reply_to, "references",
					subject, sent_date, sent_utc_offset, sent_date_unknown, internal_date, size,
					body_structure, recipients_json, s3_domain, s3_localpart,
					subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort, extra_addresses, header_presence, message_id_raw,
					mailbox_id, mailbox_path, created_modseq, uid
				)
				SELECT
					$6 AS account_id, content_hash,
					CASE WHEN src_account_id = $6 THEN uploaded ELSE content_hash = ANY($9::text[]) END AS uploaded,
					message_id, in_reply_to, "references",
					subject, sent_date, sent_utc_offset, sent_date_unknown, internal_date, size,
					body_structure, recipients_json,
					-- Same-account moves keep the source row's S3 key (the object lives there);
					-- only a move into another account's mailbox is re-keyed to the owner,
					-- whose copy of the object the caller has made in this transaction
					-- (destObjects, above).
					CASE WHEN src_account_id = $6 THEN src_s3_domain ELSE $7 END AS s3_domain,
					CASE WHEN src_account_id = $6 THEN src_s3_localpart ELSE $8 END AS s3_localpart,
					subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort, extra_addresses, header_presence, message_id_raw,
					$1 AS mailbox_id,
					$2 AS mailbox_path,
					nextval('messages_modseq') AS created_modseq,
					new_uid
				FROM src_data
				RETURNING id, uid
			)
			INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
			SELECT i.id, $1, COALESCE(ms.flags, 0), s.custom_flags_canon, NOW(), nextval('messages_modseq')
			FROM inserted i
			JOIN src_data s ON s.new_uid = i.uid
			LEFT JOIN message_state ms ON ms.message_id = s.original_id
		`, destMailboxID, destMailboxName, messageIDs, newUIDs, customFlagsCanon, destAccountID, destS3Domain, destS3Localpart, destObjects)
		if err != nil {
			logger.Error("Database: failed to batch insert messages into destination mailbox", "err", err)
			return nil, fmt.Errorf("failed to move messages: %w", err)
		}
	}

	// Re-stage uploads for any moved rows whose body is not yet in S3, so the
	// background uploader writes the body under the destination owner's S3 path
	// and marks the new row uploaded. Without this, a cross-account move of a
	// not-yet-uploaded message would never reach the owner's path and would
	// become unreadable once local staging is cleaned up.
	if err := db.restagePendingUploads(ctx, tx, destMailboxID, keptUIDs, rekeyedUIDs, instanceID); err != nil {
		return nil, err
	}
	if err := db.restageFTS(ctx, tx, destMailboxID, rekeyedUIDs); err != nil {
		return nil, err
	}

	// Mark the original messages as expunged in the source mailbox
	// (unless we already did this above for same-mailbox moves)
	// AND expunged_at IS NULL ensures we only touch rows we actually locked via
	// FOR UPDATE above, avoiding unnecessary lock contention on already-expunged rows.
	if srcMailboxID != destMailboxID {
		_, err = tx.Exec(ctx, `
			UPDATE messages
			SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
			WHERE mailbox_id = $1 AND id = ANY($2) AND expunged_at IS NULL
		`, srcMailboxID, messageIDs)

		if err != nil {
			logger.Error("Database: failed to mark original messages as expunged", "err", err)
			return nil, fmt.Errorf("failed to mark original messages as expunged: %w", err)
		}
	}

	if err := srcWindow.end(ctx, tx); err != nil {
		return nil, err
	}
	if err := window.end(ctx, tx); err != nil {
		return nil, err
	}
	return messageUIDMap, nil
}

// canonicalizeMovedCustomFlags returns, for each id in messageIDs (in order), the
// JSON-encoded custom_flags array folded onto destMailboxID's canonical keyword
// case (RFC 9051 §2.3.2). The result is parallel to messageIDs and is passed as a
// jsonb[] into the cross-mailbox move INSERT, so a moved message adopts the
// destination's existing case for any keyword it already uses; keywords new to the
// destination keep their case and become canonical there (first-seen wins, shared
// across the whole moved set). Every entry is a valid JSON array ("[]" when empty).
func (db *Database) canonicalizeMovedCustomFlags(ctx context.Context, tx pgx.Tx, destMailboxID int64, messageIDs []int64) ([]string, error) {
	destCanonical, err := db.mailboxKeywordCanonicalMap(ctx, tx, destMailboxID)
	if err != nil {
		return nil, fmt.Errorf("failed to read destination canonical keywords for move: %w", err)
	}

	srcCustomFlags := make(map[int64][]byte, len(messageIDs))
	rows, err := tx.Query(ctx, `SELECT message_id, custom_flags FROM message_state WHERE message_id = ANY($1)`, messageIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to read source custom_flags for move: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var mid int64
		var cf []byte
		if err := rows.Scan(&mid, &cf); err != nil {
			return nil, fmt.Errorf("failed to scan source custom_flags for move: %w", err)
		}
		srcCustomFlags[mid] = cf
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating source custom_flags for move: %w", err)
	}

	out := make([]string, len(messageIDs))
	for i, mid := range messageIDs {
		var kws []string
		if raw := srcCustomFlags[mid]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &kws); err != nil {
				return nil, fmt.Errorf("failed to unmarshal source custom_flags for move (message %d): %w", mid, err)
			}
		}
		folded := foldKeywordsWithMap(destCanonical, kws)
		if len(folded) == 0 {
			out[i] = "[]"
			continue
		}
		encoded, err := json.Marshal(folded)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal canonical custom_flags for move (message %d): %w", mid, err)
		}
		out[i] = string(encoded)
	}
	return out, nil
}
