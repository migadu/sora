package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

// truncateHash safely truncates a hash string for logging purposes
// sortColumnsFor derives the denormalized header columns stored on messages for SORT and
// header SEARCH: the RFC 5256 subject sort key, the lowercased first From/To/Cc name and
// address, and extra_addresses, which holds every other lowercased From/To/Cc name and
// address so that SEARCH FROM/TO/CC can match any of them (RFC 9051 §6.4.4 defines those
// keys on the envelope's address lists; layout in extraAddressesSectionSep). Every value is
// bounded in bytes (helpers.MaxSubjectBytes, helpers.MaxSortColumnBytes, and
// helpers.MaxAddressColumnsBytes shared by the five sort columns and extra_addresses)
// because idx_messages_mailbox_headers_v2 carries these columns and a btree tuple over the
// limit makes the INSERT fail. The bound is on the stored column only; the message itself
// is intact.
func sortColumnsFor(subject string, recipients []helpers.Recipient) (subjectSort, fromNameSort, fromEmailSort, toNameSort, toEmailSort, ccEmailSort, extraAddresses string) {
	// SanitizeSubjectForSort calls SanitizeUTF8 internally.
	subjectSort = helpers.TruncateUTF8Safe(helpers.SanitizeSubjectForSort(subject), helpers.MaxSubjectBytes)
	bound := func(v string) string { return helpers.TruncateUTF8Safe(strings.ToLower(v), helpers.MaxSortColumnBytes) }
	// What the sort columns do not hold, per header: every address after the first, and the
	// first Cc's name (there is no cc_name_sort).
	var sections [3][]string // From, To, Cc
	extra := func(section int, values ...string) {
		for _, v := range values {
			if v != "" {
				sections[section] = append(sections[section], extraAddressesValue.Replace(strings.ToLower(v)))
			}
		}
	}
	var fromFound, toFound, ccFound bool
	for _, r := range recipients {
		if r.GroupEnd {
			continue
		}
		// A group start is an address whose addr-mailbox is the group name and whose
		// addr-host is NIL (RFC 3501 §7.4.2), so a header that starts with a group has it
		// as its first address, and RFC 5256 §3 FROM/TO/CC and RFC 5957 §3
		// DISPLAYFROM/DISPLAYTO (it has no addr-name) all sort it by that name, whole even
		// when it holds an '@'. The columns hold only header text, since SEARCH reads them:
		// the group's email column stays empty, which no address leaves it, and the name
		// goes where the header's first name goes, the name column for From and To and
		// the head of the Cc section of extra_addresses for Cc. SORT reads it back from
		// there (groupAwareAddrMailboxExpr). A later group start has no name or address
		// of its own, so extra() leaves it out.
		name, email := bound(r.Name), bound(r.EmailAddress)
		if r.Group != "" {
			name, email = bound(r.Group), ""
		}
		switch r.AddressType {
		case "from":
			if fromFound {
				extra(0, r.Name, r.EmailAddress)
			} else {
				fromNameSort, fromEmailSort, fromFound = name, email, true
			}
		case "to":
			if toFound {
				extra(1, r.Name, r.EmailAddress)
			} else {
				toNameSort, toEmailSort, toFound = name, email, true
			}
		case "cc":
			if ccFound {
				extra(2, r.Name, r.EmailAddress)
			} else {
				ccEmailSort, ccFound = email, true
				extra(2, r.Name, r.Group)
			}
		}
	}
	joined := make([]string, len(sections))
	for i, values := range sections {
		joined[i] = strings.Join(values, extraAddressesValueSep)
	}
	budget := helpers.MaxAddressColumnsBytes - len(fromNameSort) - len(fromEmailSort) - len(toNameSort) - len(toEmailSort) - len(ccEmailSort)
	extraAddresses = helpers.TruncateUTF8Safe(
		strings.TrimRight(strings.Join(joined, extraAddressesSectionSep), extraAddressesSectionSep), max(budget, 0))
	return
}

// Layout of messages.extra_addresses: three sections, From, To and Cc in that order,
// separated by a newline, and inside a section the names and addresses in header order,
// separated by a tab. A tab or newline inside a name is stored as a space, so a value can
// never leak into another section (the search splits on the newline, see
// addressHeaderCond). Trailing empty sections are left out, and a message with nothing to
// add stores the empty string. NULL means the row was written before the column existed, or
// by a binary that does not write it; the search reads it as empty, so such rows are matched
// on their first addresses only until scripts/backfill_extra_addresses.sql fills them.
const (
	extraAddressesSectionSep = "\n"
	extraAddressesValueSep   = "\t"
)

var extraAddressesValue = strings.NewReplacer("\t", " ", "\n", " ")

// ErrCopySourceChanged is returned by CopyMessages when a source row owned by another
// account than the destination no longer has the content hash the caller made its body
// available for under the destination owner's S3 path. Nothing is written; reading the
// source again and copying anew can succeed.
var ErrCopySourceChanged = errors.New("a source message changed during the copy")

func truncateHash(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

// CopyMessages copies multiple messages from a source mailbox to a destination mailbox within a given transaction.
// It returns a map of old UIDs to new UIDs.
// CopyMessages copies the given source UIDs into destMailboxID within the caller's
// transaction. It returns the source→destination UID map AND the BIGSERIAL primary keys
// of the newly inserted rows. Those ids are the copy's proof of commit: they exist if and
// only if this transaction committed, and PostgreSQL never reissues a serial value, so a
// caller that loses the COMMIT acknowledgement (ErrCommitOutcomeUnknown) can read them back
// to learn — exactly, and immune to concurrency — whether the copy actually landed. See
// server/imap/copy.go for that resolution.
//
// A copy of a row owned by another account than destAccountID is re-keyed to
// destAccountID's S3 path, where the caller must first have made the body available (its
// object, or the staging file of the upload restagePendingUploads queues). sourceHashes
// holds, by source UID, the content hash each such row had when the caller did so, and
// the row is copied only if it still has it: sora-admin import rekey can rename a body's
// hash before this copy takes its source-account lock, and a copy under the new hash would
// point at a key nothing wrote. A renamed source fails the copy with ErrCopySourceChanged
// before anything commits. The check is made by the INSERT, the statement that copies the
// rows' hashes; once inserted, a copy keeps its hash whatever happens to the source.
// destObjects names the destination bodies made to exist in S3 while tx holds their
// shared object locks. Only those re-keyed rows are uploaded; all other re-keyed rows
// are staged for upload, even if their source's upload finished in the meantime.
func (db *Database) CopyMessages(ctx context.Context, tx pgx.Tx, uids *[]imap.UID, srcMailboxID, destMailboxID int64, destAccountID int64, destS3Domain string, destS3Localpart string, instanceID string, sourceHashes map[imap.UID]string, destObjects []string) (map[imap.UID]imap.UID, []int64, error) {
	messageUIDMap := make(map[imap.UID]imap.UID)
	if destObjects == nil {
		destObjects = []string{} // = ANY(NULL) would be NULL, not false.
	}
	if srcMailboxID == destMailboxID {
		return nil, nil, fmt.Errorf("source and destination mailboxes cannot be the same")
	}

	if err := lockS3SourceClaims(ctx, tx, srcMailboxID, destMailboxID, destAccountID, uids, destObjects); err != nil {
		return nil, nil, err
	}

	// The caller is responsible for beginning and committing/rolling back the transaction.

	// Get the source message IDs and UIDs
	rows, err := tx.Query(ctx, `SELECT id, uid, account_id FROM messages WHERE mailbox_id = $1 AND uid = ANY($2) AND expunged_at IS NULL ORDER BY uid`, srcMailboxID, uids)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", consts.ErrInternalError, err)
	}
	defer rows.Close()

	var messageIDs []int64
	var sourceUIDsForMap []imap.UID
	var expectedHashes []string // per message: sourceHashes, checked for re-keyed rows only
	var rekeyed []bool          // per message: owned by another account than destAccountID
	for rows.Next() {
		var messageID, sourceAccountID int64
		var sourceUID imap.UID
		if err := rows.Scan(&messageID, &sourceUID, &sourceAccountID); err != nil {
			return nil, nil, fmt.Errorf("failed to scan message ID and UID: %w", err)
		}
		messageIDs = append(messageIDs, messageID)
		sourceUIDsForMap = append(sourceUIDsForMap, sourceUID)
		expectedHashes = append(expectedHashes, sourceHashes[sourceUID])
		rekeyed = append(rekeyed, sourceAccountID != destAccountID)
	}
	if err = rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("error iterating through source messages: %w", err)
	}

	if len(messageIDs) == 0 {
		return messageUIDMap, nil, nil // No messages to copy
	}

	// Atomically increment highest_uid for the number of messages being copied.
	var newHighestUID int64
	numToCopy := int64(len(messageIDs))
	err = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + $1 WHERE id = $2 RETURNING highest_uid`, numToCopy, destMailboxID).Scan(&newHighestUID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", consts.ErrDBUpdateFailed, err)
	}
	// The highest_uid UPDATE holds the destination's row lock from here on.
	window := modSeqWindowFor(ctx, destMailboxID)
	if err := window.begin(ctx, tx); err != nil {
		return nil, nil, err
	}

	// Calculate the new UIDs for the copied messages, and split them by whether the
	// copy is re-keyed to the destination owner (see restagePendingUploads).
	var newUIDs, keptUIDs, rekeyedUIDs []int64
	startUID := newHighestUID - numToCopy + 1
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
		return nil, nil, fmt.Errorf("failed to get destination mailbox name: %w", err)
	}

	// Keyword identity is case-insensitive (RFC 9051 §2.3.2): fold each copied
	// message's keywords onto the destination mailbox's canonical case so the
	// destination never ends up reporting two cases of the same keyword.
	customFlagsCanon, err := db.canonicalizeMovedCustomFlags(ctx, tx, destMailboxID, messageIDs)
	if err != nil {
		return nil, nil, err
	}

	// From here to the commit a rekey must not rename a source: the INSERT reads its hash.
	if err := lockRekeySources(ctx, tx, srcMailboxID, uids); err != nil {
		return nil, nil, err
	}

	// Batch insert the copied messages and their state in one round trip. The
	// message_state INSERT is a data-modifying CTE, which PostgreSQL executes to
	// completion exactly once regardless of whether the primary query reads its
	// output, so the top-level SELECT can return the new message ids while the state
	// rows are still written. Those ids are the copy's commit proof (see the doc
	// comment above).
	// RFC 3501 §2.3.2: \Recent is a session flag and must NOT be stored
	// persistently.  Preserve only the source message's existing flags.
	// A source without a message_state row (left by an older build) has none, and its copy gets a row with none.
	insRows, err := tx.Query(ctx, `
		WITH src_data AS (
			SELECT
				m.content_hash,
				CASE WHEN m.account_id = $6 THEN m.uploaded ELSE m.content_hash = ANY($10::text[]) END AS uploaded,
				m.message_id, m.in_reply_to, m."references",
				m.subject, m.sent_date, m.sent_utc_offset, m.sent_date_unknown, m.internal_date, m.size,
				m.body_structure, m.recipients_json,
				m.subject_sort, m.from_name_sort, m.from_email_sort, m.to_name_sort, m.to_email_sort, m.cc_email_sort, m.extra_addresses, m.header_presence, m.message_id_raw,
				m.id AS original_id,
				m.account_id AS src_account_id, m.s3_domain AS src_s3_domain, m.s3_localpart AS src_s3_localpart,
				d.new_uid,
				d.custom_flags_canon
			FROM messages m
			JOIN unnest($3::bigint[], $4::bigint[], $5::jsonb[], $9::text[]) AS d(message_id, new_uid, custom_flags_canon, expected_hash) ON m.id = d.message_id
			-- A row re-keyed to another account is copied only with the hash whose body the
			-- caller made available under the owner's key (sourceHashes); a row left out
			-- here fails the copy below.
			WHERE m.account_id = $6 OR m.content_hash = d.expected_hash
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
				$6 AS account_id, content_hash, uploaded, message_id, in_reply_to, "references",
				subject, sent_date, sent_utc_offset, sent_date_unknown, internal_date, size,
				body_structure, recipients_json,
				-- The S3 key is per row: the body lives under whatever the account's primary
				-- address was when the source row was written, and readers build their GET
				-- key from the row. A same-account copy keeps that key; only a copy into
				-- another account's mailbox is re-keyed to the owner (the caller has copied
				-- the object under the owner's key first, see server/imap/copy.go).
				CASE WHEN src_account_id = $6 THEN src_s3_domain ELSE $7 END AS s3_domain,
				CASE WHEN src_account_id = $6 THEN src_s3_localpart ELSE $8 END AS s3_localpart,
				subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort, extra_addresses, header_presence, message_id_raw,
				$1 AS mailbox_id,
				$2 AS mailbox_path,
				nextval('messages_modseq'),
				new_uid
			FROM src_data
			RETURNING id, uid
		),
		state_inserted AS (
			INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
			SELECT i.id, $1, COALESCE(ms.flags, 0), s.custom_flags_canon, NOW(), nextval('messages_modseq')
			FROM inserted i
			JOIN src_data s ON s.new_uid = i.uid
			LEFT JOIN message_state ms ON ms.message_id = s.original_id
			RETURNING message_id
		)
		SELECT id FROM inserted ORDER BY uid
	`, destMailboxID, destMailboxName, messageIDs, newUIDs, customFlagsCanon, destAccountID, destS3Domain, destS3Localpart, expectedHashes, destObjects)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to batch copy messages: %w", err)
	}
	var newMessageIDs []int64
	for insRows.Next() {
		var id int64
		if err := insRows.Scan(&id); err != nil {
			insRows.Close()
			return nil, nil, fmt.Errorf("failed to scan new message id: %w", err)
		}
		newMessageIDs = append(newMessageIDs, id)
	}
	insRows.Close()
	if err := insRows.Err(); err != nil {
		return nil, nil, fmt.Errorf("error iterating new message ids: %w", err)
	}
	if len(newMessageIDs) != len(messageIDs) {
		return nil, nil, fmt.Errorf("%w: copied %d of %d messages", ErrCopySourceChanged, len(newMessageIDs), len(messageIDs))
	}

	// Re-stage uploads for any copied rows whose body is not yet in S3, so the
	// background uploader writes the body under the destination owner's S3 path
	// (s3_domain/s3_localpart) and marks the new row uploaded. Without this, a
	// cross-account copy of a not-yet-uploaded message would never reach the
	// owner's path and would become unreadable once local staging is cleaned up.
	if err := db.restagePendingUploads(ctx, tx, destMailboxID, keptUIDs, rekeyedUIDs, instanceID); err != nil {
		return nil, nil, err
	}
	if err := db.restageFTS(ctx, tx, destMailboxID, rekeyedUIDs); err != nil {
		return nil, nil, err
	}

	if err := window.end(ctx, tx); err != nil {
		return nil, nil, err
	}
	return messageUIDMap, newMessageIDs, nil
}

// restagePendingUploads ensures every just-inserted, not-yet-uploaded message in
// mailboxID has a pending_upload under its own account so the uploader writes the body
// under that account's S3 path. instanceID must be the upload instance id of the node
// holding the local file (config.InstanceID, the key its uploader leases under), not its
// mail hostname, so its own worker, not a peer or nobody, picks the task up.
//
// rekeyedUIDs are the copies of another account's rows, re-keyed to the mailbox owner. One
// that is not uploaded is one whose body the caller has just staged on this node under
// FilePath(content_hash, owner) (see CopyMessages), so the owner's row is re-armed for
// this node as a fresh delivery re-arms it (InsertMessage): an existing row may be one no
// uploader leases any more, its attempts used up or its instance gone, and left as it is
// the copy is never uploaded and CleanupFailedUploads deletes it. DISTINCT ON because two
// copies of one body propose the same row, which ON CONFLICT DO UPDATE refuses.
//
// keptUIDs are the copies of the owner's own rows. They stage nothing here: the body is
// wherever the source was delivered, possibly another node, so an existing row is left
// alone (DO NOTHING) rather than taken over by this one.
func (db *Database) restagePendingUploads(ctx context.Context, tx pgx.Tx, mailboxID int64, keptUIDs, rekeyedUIDs []int64, instanceID string) error {
	if len(rekeyedUIDs) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO pending_uploads (instance_id, content_hash, size, created_at, account_id)
			SELECT DISTINCT ON (m.content_hash, m.account_id) $1, m.content_hash, m.size, NOW(), m.account_id
			FROM messages m
			WHERE m.mailbox_id = $2 AND m.uid = ANY($3) AND m.uploaded = FALSE AND m.expunged_at IS NULL
			ON CONFLICT (content_hash, account_id) DO UPDATE
			SET attempts = 0, instance_id = EXCLUDED.instance_id, last_attempt = NULL`,
			instanceID, mailboxID, rekeyedUIDs); err != nil {
			return fmt.Errorf("failed to re-stage pending uploads: %w", err)
		}
	}
	if len(keptUIDs) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO pending_uploads (instance_id, content_hash, size, created_at, account_id)
			SELECT $1, m.content_hash, m.size, NOW(), m.account_id
			FROM messages m
			WHERE m.mailbox_id = $2 AND m.uid = ANY($3) AND m.uploaded = FALSE AND m.expunged_at IS NULL
			ON CONFLICT (content_hash, account_id) DO NOTHING`,
			instanceID, mailboxID, keptUIDs); err != nil {
			return fmt.Errorf("failed to re-stage pending uploads: %w", err)
		}
	}
	return nil
}

// restageFTS ensures every just-inserted message in (mailboxID, rekeyedUIDs) has a
// per-account FTS row under its own account, so it is searchable by body for its new owner.
//
// This is the search-side analogue of restagePendingUploads. messages_fts_v2 is keyed by
// (content_hash, account_id), so a cross-account COPY or MOVE lands a message under an
// account that has no row for that body: without this it would be silently unsearchable in
// the destination, exactly as it would be unreadable without the pending_upload re-stage.
//
// Callers pass only the copies re-keyed from another account. A copy of a row that already
// belonged to the destination account (every row of a same-account COPY or MOVE, and a
// message that account added to another owner's shared mailbox while messages.account_id
// was still the adder's) needs nothing: that account's row for the body is anchored by the
// source row itself, which stays in messages (MOVE only expunges it, and the orphan sweep
// counts expunged rows), so the sweep cannot delete the row and there is nothing to insert.
// A rekey, which renames the source row's hash, waits for the copy (lockRekeySources) and so
// sees the copied rows too. Leaving those copies out matters: the shared lock below is one
// entry per distinct body in PostgreSQL's server-wide lock table, held until commit, a bulk
// same-account MOVE is the common case, and the re-keyed bodies are what one command is
// limited to (MaxCrossAccountBodies).
//
// Do not replace the lock with a "row already exists" pre-check. A row that exists can be an
// orphan the sweep is about to delete, and the sweep cannot see the uncommitted message that
// now needs it; TestRestageFTSHoldsOffTheOrphanSweep reproduces that loss.
//
// The new rows carry no text: the body was staged (or already indexed) when the source
// message was delivered, so the FTS worker fills these by copying the finished vector from
// a sibling rather than tokenising anything again. The EXISTS guard keeps us from creating
// rows for a body that was never indexed at all -- empty, past fts_retention, or pruned --
// which would otherwise be queued forever and then poisoned.
func (db *Database) restageFTS(ctx context.Context, tx pgx.Tx, mailboxID int64, rekeyedUIDs []int64) error {
	if len(rekeyedUIDs) == 0 {
		return nil
	}
	// Acquire shared advisory locks on all distinct content_hashes for these messages
	// so any concurrent orphan sweep for these hashes either skips them (if restage
	// arrived first) or restage waits for the sweep to commit (if sweep arrived first)
	// so the v2 insert's statement snapshot sees the deletion and inserts fresh.
	if _, err := tx.Exec(ctx, `
		SELECT pg_advisory_xact_lock_shared($1, hashtext(m.content_hash))
		FROM (
			SELECT DISTINCT m.content_hash
			FROM messages m
			WHERE m.mailbox_id = $2 AND m.uid = ANY($3) AND m.expunged_at IS NULL
		) m`,
		consts.SoraFTSOrphanSweepLockClassID, mailboxID, rekeyedUIDs); err != nil {
		return fmt.Errorf("failed to acquire shared advisory lock for fts restage: %w", err)
	}

	_, err := tx.Exec(ctx, `
		INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, sent_date)
		SELECT DISTINCT m.content_hash, m.account_id, NULL, m.sent_date
		FROM messages m
		WHERE m.mailbox_id = $1 AND m.uid = ANY($2) AND m.expunged_at IS NULL
		  AND EXISTS (SELECT 1 FROM messages_fts_v2 s WHERE s.content_hash = m.content_hash)
		ON CONFLICT (content_hash, account_id) DO NOTHING`,
		mailboxID, rekeyedUIDs)
	if err != nil {
		return fmt.Errorf("failed to re-stage fts rows: %w", err)
	}
	return nil
}

type InsertMessageOptions struct {
	AccountID   int64
	MailboxID   int64
	MailboxName string
	S3Domain    string
	S3Localpart string
	ContentHash string
	// DeliveryHash identifies the upstream submission: the hash of the message bytes
	// as received, before any local trace stamping. Empty on non-MTA paths (IMAP
	// APPEND, importer, User API), which disables the retry-duplicate check below.
	DeliveryHash string
	MessageID    string
	// CustomFlags are handled by splitting options.Flags in InsertMessage
	Flags               []imap.Flag
	InternalDate        time.Time
	Size                int64
	Subject             string
	PlaintextBody       string
	SentDate            time.Time // The parsed Date: header; zero when none parses (see storedSentDate)
	SentDateUnknownZone bool      // The parser explicitly reported no known source zone
	InReplyTo           []string
	References          []string
	BodyStructure       *imap.BodyStructure
	Recipients          []helpers.Recipient
	// HeaderPresence is known only for newly ingested final headers. nil preserves
	// legacy search behavior; COPY/MOVE/restore carry it without reading old bodies.
	HeaderPresence *int16
	// MessageIDRaw holds the unfolded Message-ID field text when messages.message_id
	// cannot represent it losslessly (#529). nil for absent or canonical single IDs.
	MessageIDRaw         *string
	PreservedUID         *uint32       // Optional: preserved UID from import
	PreservedUIDValidity *uint32       // Optional: preserved UIDVALIDITY from import
	FTSRetention         time.Duration // Optional: skip creating messages_fts_v2 entirely for messages older than this
}

// shouldStageFTS reports whether a messages_fts_v2 row is worth creating. A zero
// retention means FTS data is kept indefinitely, so everything is staged. A
// message already past the retention window is skipped: the row would only add
// immediate work for the cleanup worker.
func shouldStageFTS(retention time.Duration, sentDate, now time.Time) bool {
	if retention == 0 || sentDate.IsZero() {
		return true
	}
	return !sentDate.Before(now.Add(-retention))
}

// FTS staging SQL.
//
//	ftsStageV2SQL  the per-account messages_fts_v2 row that the composite GIN indexes. This
//	               is what lets a body search be scoped to one account instead of scanning
//	               the whole corpus.
//
// The v2 statement decides IN SQL whether to carry the body text, so it costs one round trip
// rather than two. It runs inside the transaction that already holds the mailbox row lock,
// where every extra round trip serializes deliveries to that mailbox. If a sibling row for
// this hash already carries a computed vector, the worker copies that vector and staging the
// text again is pure waste: a newsletter delivered to 10k accounts would otherwise stage
// 10k copies of the same 64 KB body.
const (
	// Every parameter is cast explicitly. In "INSERT ... SELECT $1, $2" PostgreSQL cannot
	// infer a parameter's type from the target column, so $1 would be deduced as text in
	// the select list and as varchar from its comparison inside the EXISTS -- "inconsistent
	// types deduced for parameter $1", which fails the statement at prepare time.
	ftsStageV2SQL = `
		INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, sent_date)
		SELECT $1::varchar(64), $2::bigint,
		       CASE WHEN EXISTS (
		           SELECT 1 FROM messages_fts_v2 s
		           WHERE s.content_hash = $1::varchar(64) AND s.text_body_tsv IS NOT NULL
		       ) THEN NULL ELSE $3::text END,
		       $4::timestamptz
		ON CONFLICT (content_hash, account_id) DO NOTHING`
)

// stageFTS writes the FTS staging row for a freshly inserted message into messages_fts_v2.
//
// Best-effort by design: if this fails the message is still delivered and uploaded, it is
// merely unsearchable by body, so the write sits in its own savepoint and cannot fail
// the caller.
func stageFTS(ctx context.Context, tx pgx.Tx, contentHash string, accountID int64, textBody any, sentDate time.Time) {
	savepoint := "fts_v2"
	if _, err := tx.Exec(ctx, "SAVEPOINT "+savepoint); err != nil {
		logger.Warn("Database: failed to create savepoint for fts insert", "savepoint", savepoint, "err", err)
		return
	}

	// Acquire shared advisory lock on the content_hash as its own statement BEFORE
	// the v2 insert. Any concurrent orphan sweep on this hash either skips it (if
	// delivery holds the lock first) or delivery waits for the sweep to commit (if
	// sweep holds it first), ensuring the v2 insert statement's snapshot is taken
	// AFTER the sweep's deletion and inserts the row fresh.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock_shared($1, hashtext($2))",
		consts.SoraFTSOrphanSweepLockClassID, contentHash); err != nil {
		tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+savepoint)
		logger.Warn("Database: failed to acquire shared advisory lock for fts insert",
			"content_hash", truncateHash(contentHash), "account_id", accountID, "err", err)
		return
	}
	if _, err := tx.Exec(ctx, ftsStageV2SQL, contentHash, accountID, textBody, sentDate); err != nil {
		tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+savepoint)
		logger.Warn("Database: failed to insert message fts payload (non-fatal, message will be unsearchable)",
			"content_hash", truncateHash(contentHash), "account_id", accountID, "err", err)
		return
	}
	tx.Exec(ctx, "RELEASE SAVEPOINT "+savepoint)
}

// maxSentUTCOffset bounds the Date: header zone offsets kept in messages.sent_utc_offset, in
// seconds. Real zones lie between -12:00 and +14:00; the RFC 5322 §3.3 grammar admits any
// four digits. The SENT* search keys rely on the bound: they look the offset up only for
// messages sent within this distance of the searched date (sentDayCond).
const maxSentUTCOffset = 24 * 60 * 60

// sentUTCOffset returns the messages.sent_utc_offset value for sentDate: the UTC offset, in
// seconds, of the zone it is expressed in. Ingress passes the parsed Date: header in its own
// zone, so sent_date plus this offset is the header's wall-clock time, whose day the SENT*
// keys compare (RFC 9051 §6.4.4: "disregarding time and timezone"). nil (NULL, searched by
// the UTC day) for an offset beyond maxSentUTCOffset, and for a date whose zone is unknown
// (unknownZone, RFC 5322 §3.3 "-0000"): its UTC day is the day it names, and
// sentDateInHeaderZone gives it back in UTC, so its ENVELOPE date keeps the zone "-0000".
func sentUTCOffset(sentDate time.Time, unknownZone bool) *int32 {
	if unknownZone {
		return nil
	}
	_, offset := sentDate.Zone()
	if offset < -maxSentUTCOffset || offset > maxSentUTCOffset {
		return nil
	}
	o := int32(offset)
	return &o
}

// sentDateInHeaderZone is the inverse of sentUTCOffset: messages.sent_date in the zone of
// the Date: header it was parsed from, given that row's sent_utc_offset. The ENVELOPE date
// is formatted from it and must name the header's own day, time of day and zone (RFC 9051
// §7.5.2: the envelope "is computed by the server by parsing the [RFC5322] header into the
// component parts"). A row without an offset (a zone that is unknown, one beyond
// maxSentUTCOffset, or a row written before migration 000060) is given in UTC rather than
// in the time.Local pgx decodes a timestamptz into, so the ENVELOPE never depends on the
// server's TZ. Readers separately record an unknown source zone for a present
// Date header when offset is NULL; time.Location does not carry that status.
func sentDateInHeaderZone(sentDate time.Time, offset *int32) time.Time {
	if offset == nil {
		return sentDate.UTC()
	}
	return sentDate.In(time.FixedZone("", int(*offset)))
}

// storedSentDate returns the messages.sent_date and sent_date_unknown values for a message,
// whose InternalDate the caller has already defaulted. A message without a Date: header that
// parses has no sent date, and SORT and THREAD use its INTERNALDATE instead (RFC 5256 §2.2:
// "If the sent date cannot be determined (a Date: header is missing or cannot be parsed), the
// INTERNALDATE for that message is used as the sent date"). sent_date_unknown records that
// sent_date is that substitute, so the ENVELOPE reports the date as NIL (RFC 9051 §7.5.2,
// BuildEnvelope); it is NULL, not false, for every other message.
func storedSentDate(options *InsertMessageOptions) (sentDate time.Time, unknown *bool) {
	if options.SentDate.IsZero() {
		t := true
		return options.InternalDate, &t
	}
	return options.SentDate, nil
}

func (d *Database) InsertMessage(ctx context.Context, tx pgx.Tx, options *InsertMessageOptions, upload PendingUpload) (messageID int64, uid int64, err error) {
	start := time.Now()
	defer func() {
		status := "success"
		if err != nil {
			// Check for duplicate key violation
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				status = "duplicate"
			} else {
				status = "error"
			}
		}
		metrics.DBQueryDuration.WithLabelValues("message_insert", "write").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("message_insert", status, "write").Inc()
	}()

	// Sanitize user-controlled text fields that go into PostgreSQL text columns.
	// S3Domain, S3Localpart, and ContentHash are system-generated and don't need sanitization.
	saneMessageID := helpers.SanitizeUTF8(options.MessageID)
	saneMailboxName := helpers.SanitizeUTF8(options.MailboxName)

	if saneMessageID == "" {
		logger.Info("Database: messageID is empty after sanitization, generating a synthetic one without modifying the message")
		// A message without a Message-ID gets a fresh synthetic one per insert: on this
		// live path (IMAP APPEND) two identical appends are two messages, as clients
		// expect. Delivery retries are absorbed by delivery_hash, and the importer uses
		// a content-derived id (InsertMessageFromImporter) so re-runs do not duplicate.
		saneMessageID = fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), saneMailboxName)
	}

	bodyStructureData, err := helpers.SerializeBodyStructureGob(options.BodyStructure)
	if err != nil {
		logger.Error("Database: failed to serialize BodyStructure", "err", err)
		return 0, 0, consts.ErrSerializationFailed
	}

	bodyClaimable := true
	if claimErr := LockS3ObjectsSharedInTx(ctx, tx, options.AccountID, []string{options.ContentHash}); claimErr != nil {
		if errors.Is(claimErr, ErrS3BodyQuarantined) {
			bodyClaimable = false
		} else {
			return 0, 0, claimErr
		}
	}

	if options.InternalDate.IsZero() {
		options.InternalDate = time.Now()
	}
	sentDate, sentDateUnknown := storedSentDate(options)

	var highestUID int64
	var uidToUse int64

	// Check UIDVALIDITY before deciding whether to use preserved UID
	if options.PreservedUID != nil && options.PreservedUIDValidity != nil {
		// Check if any messages already exist in this mailbox
		var hasMessages bool
		err = tx.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM messages
				WHERE mailbox_id = $1
				AND expunged_at IS NULL
				LIMIT 1
			)`, options.MailboxID).Scan(&hasMessages)
		if err != nil {
			logger.Error("Database: failed to check for existing messages", "err", err)
			return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBQueryFailed, err)
		}

		// Get current UIDVALIDITY
		var currentUIDValidity uint32
		err = tx.QueryRow(ctx, `SELECT uid_validity FROM mailboxes WHERE id = $1`, options.MailboxID).Scan(&currentUIDValidity)
		if err != nil {
			logger.Error("Database: failed to query current UIDVALIDITY", "err", err)
			return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBQueryFailed, err)
		}

		if hasMessages {
			// Mailbox already has messages - check if UIDVALIDITY matches
			if currentUIDValidity != *options.PreservedUIDValidity {
				// UIDVALIDITY changed - ignore preserved UID and deliver normally
				// Only log once per mailbox to avoid log spam
				if _, logged := d.uidValidityMismatchLoggedMap.LoadOrStore(options.MailboxID, true); !logged {
					logger.Warn("Database: UIDVALIDITY mismatch, ignoring preserved UID and delivering normally",
						"mailbox_id", options.MailboxID, "current", currentUIDValidity, "requested", *options.PreservedUIDValidity)
				}

				// Clear preserved values to use normal auto-increment
				options.PreservedUID = nil
				options.PreservedUIDValidity = nil
			}
			// If UIDVALIDITY matches, continue with UID preservation
		} else {
			// First preserved message - set UIDVALIDITY (overriding auto-generated value)
			if currentUIDValidity != *options.PreservedUIDValidity {
				_, err = tx.Exec(ctx, `
					UPDATE mailboxes
					SET uid_validity = $2
					WHERE id = $1`,
					options.MailboxID, *options.PreservedUIDValidity)
				if err != nil {
					logger.Error("Database: failed to update UIDVALIDITY", "err", err)
					return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBUpdateFailed, err)
				}
				logger.Info("Database: set UIDVALIDITY for first preserved message",
					"mailbox_id", options.MailboxID, "from", currentUIDValidity, "to", *options.PreservedUIDValidity)
			}
		}
	}

	// Now assign UID (either preserved or auto-increment based on above logic)
	if options.PreservedUID != nil {
		uidToUse = int64(*options.PreservedUID)

		// Update highest_uid if preserved UID is higher (handles out-of-order)
		err = tx.QueryRow(ctx, `
			UPDATE mailboxes
			SET highest_uid = GREATEST(highest_uid, $2)
			WHERE id = $1
			RETURNING highest_uid`,
			options.MailboxID, uidToUse).Scan(&highestUID)
		if err != nil {
			logger.Error("Database: failed to update highest UID with preserved UID", "err", err)
			return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBUpdateFailed, err)
		}
	} else {
		// Atomically increment and get the new highest UID for the mailbox
		err = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + 1 WHERE id = $1 RETURNING highest_uid`, options.MailboxID).Scan(&highestUID)
		if err != nil {
			logger.Error("Database: failed to update highest UID", "err", err)
			return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBUpdateFailed, err)
		}
		uidToUse = highestUID
	}

	// The highest_uid UPDATE holds the mailbox row lock from here on.
	window := modSeqWindowFor(ctx, options.MailboxID)
	if err := window.begin(ctx, tx); err != nil {
		return 0, 0, err
	}

	// Check for existing EXACT duplicate message
	var existingUID int64
	var existingContentHash string
	err = tx.QueryRow(ctx, `
		SELECT uid, content_hash FROM messages
		WHERE mailbox_id = $1
		AND message_id = $2
		AND content_hash = $3
		AND expunged_at IS NULL
		LIMIT 1`,
		options.MailboxID, saneMessageID, options.ContentHash).Scan(&existingUID, &existingContentHash)

	if err == nil {
		// True duplicate (same Message-ID + same content_hash) - skip insert
		logger.Info("Database: duplicate message detected, skipping insert", "message_id", saneMessageID, "content_hash", options.ContentHash, "mailbox_id", options.MailboxID, "existing_uid", existingUID)
		return 0, existingUID, consts.ErrMessageExists
	} else if err != pgx.ErrNoRows {
		// Unexpected error
		logger.Error("Database: failed to check for duplicate message", "err", err)
		return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBQueryFailed, err)
	}
	// err == pgx.ErrNoRows means no exact duplicate found, continue with insert

	// An MTA redelivery of the same queue entry. The check above cannot see one: the
	// delivering session stamps its own per-attempt trace header before content_hash is
	// computed, and a message with no Message-ID gets a fresh synthetic one per attempt.
	if options.DeliveryHash != "" {
		err = tx.QueryRow(ctx, `
			SELECT uid FROM messages
			WHERE mailbox_id = $1
			AND delivery_hash = $2
			AND expunged_at IS NULL
			LIMIT 1`,
			options.MailboxID, options.DeliveryHash).Scan(&existingUID)

		if err == nil {
			logger.Info("Database: duplicate delivery detected, skipping insert", "message_id", saneMessageID, "delivery_hash", options.DeliveryHash, "mailbox_id", options.MailboxID, "existing_uid", existingUID)
			return 0, existingUID, consts.ErrMessageExists
		} else if err != pgx.ErrNoRows {
			logger.Error("Database: failed to check for duplicate delivery", "err", err)
			return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBQueryFailed, err)
		}
	}

	// Sanitize recipients defensively before JSON marshaling.
	// json.Marshal encodes NULL bytes as \u0000, which PostgreSQL JSONB rejects (SQLSTATE 22P05).
	saneRecipients := make([]helpers.Recipient, len(options.Recipients))
	for i, r := range options.Recipients {
		saneRecipients[i] = helpers.Recipient{
			Name:         helpers.SanitizeUTF8(r.Name),
			EmailAddress: helpers.SanitizeUTF8(r.EmailAddress),
			AddressType:  r.AddressType,
			Group:        helpers.SanitizeUTF8(r.Group),
			GroupEnd:     r.GroupEnd,
		}
	}

	recipientsJSON, err := json.Marshal(saneRecipients)
	if err != nil {
		logger.Error("Database: failed to marshal recipients", "err", err)
		return 0, 0, consts.ErrSerializationFailed
	}

	// Prepare denormalized sort fields for faster sorting (bounded; see sortColumnsFor).
	subjectSort, fromNameSort, fromEmailSort, toNameSort, toEmailSort, ccEmailSort, extraAddresses := sortColumnsFor(options.Subject, saneRecipients)

	inReplyToStr := strings.Join(options.InReplyTo, " ")

	systemFlagsToSet, customKeywordsToSet := SplitFlags(options.Flags)
	bitwiseFlags := FlagsToBitwise(systemFlagsToSet)
	// Fold keywords onto the case already used in this mailbox (RFC 9051 §2.3.2)
	// so an APPEND/import carrying a different-case variant of an existing keyword
	// does not introduce a second case.
	customKeywordsToSet, err = d.canonicalizeKeywords(ctx, tx, options.MailboxID, customKeywordsToSet)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to canonicalize custom keywords for InsertMessage: %w", err)
	}
	// Degrade gracefully rather than failing the APPEND if it carries more
	// keywords than a single message may hold (see MaxCustomKeywordsPerMessage).
	customKeywordsToSet = capCustomKeywords(customKeywordsToSet)

	var customKeywordsJSON []byte
	if len(customKeywordsToSet) == 0 {
		customKeywordsJSON = []byte("[]")
	} else {
		customKeywordsJSON, err = json.Marshal(customKeywordsToSet)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to marshal custom keywords for InsertMessage: %w", err)
		}
	}

	var messageRowId int64

	// Sanitize inputs
	saneSubject := helpers.TruncateUTF8Safe(helpers.SanitizeUTF8(options.Subject), helpers.MaxSubjectBytes)
	saneInReplyToStr := helpers.TruncateUTF8Safe(helpers.SanitizeUTF8(inReplyToStr), 2000)

	saneReferencesStr := helpers.TrimReferences(options.References, helpers.MaxReferencesBytes)

	sanePlaintextBody := helpers.SanitizeUTF8(options.PlaintextBody)

	var deliveryHash *string
	if options.DeliveryHash != "" {
		deliveryHash = &options.DeliveryHash
	}

	err = tx.QueryRow(ctx, `
		WITH inserted AS (
			INSERT INTO messages
				(account_id, mailbox_id, mailbox_path, uid, message_id, content_hash, delivery_hash, s3_domain, s3_localpart, internal_date, size, subject, sent_date, sent_utc_offset, sent_date_unknown, in_reply_to, "references", body_structure, recipients_json, created_modseq, subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort, extra_addresses, header_presence, message_id_raw)
			VALUES
				(@account_id, @mailbox_id, @mailbox_path, @uid, @message_id, @content_hash, @delivery_hash, @s3_domain, @s3_localpart, @internal_date, @size, @subject, @sent_date, @sent_utc_offset, @date_unknown, @in_reply_to, @references, @body_structure, @recipients_json, nextval('messages_modseq'), @subject_sort, @from_name_sort, @from_email_sort, @to_name_sort, @to_email_sort, @cc_email_sort, @extra_addresses, @header_presence, @message_id_raw)
			RETURNING id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
		SELECT id, @mailbox_id, @flags, @custom_flags, NOW(), nextval('messages_modseq') FROM inserted
		RETURNING message_id
	`, pgx.NamedArgs{
		"account_id":      options.AccountID,
		"mailbox_id":      options.MailboxID,
		"mailbox_path":    saneMailboxName,
		"s3_domain":       options.S3Domain,
		"s3_localpart":    options.S3Localpart,
		"uid":             uidToUse,
		"message_id":      saneMessageID,
		"content_hash":    options.ContentHash,
		"delivery_hash":   deliveryHash,
		"flags":           bitwiseFlags,
		"custom_flags":    customKeywordsJSON,
		"internal_date":   options.InternalDate,
		"size":            options.Size,
		"subject":         saneSubject,
		"sent_date":       sentDate,
		"sent_utc_offset": sentUTCOffset(sentDate, options.SentDateUnknownZone && !options.SentDate.IsZero()),
		"date_unknown":    sentDateUnknown,
		"in_reply_to":     saneInReplyToStr,
		"references":      saneReferencesStr,
		"body_structure":  bodyStructureData,
		"recipients_json": recipientsJSON,
		"subject_sort":    subjectSort,
		"from_name_sort":  fromNameSort,
		"from_email_sort": fromEmailSort,
		"to_name_sort":    toNameSort,
		"to_email_sort":   toEmailSort,
		"cc_email_sort":   ccEmailSort,
		"extra_addresses": extraAddresses,
		"header_presence": options.HeaderPresence,
		"message_id_raw":  helpers.SanitizeMessageIDRaw(options.MessageIDRaw),
	}).Scan(&messageRowId)

	if err != nil {
		// Check for a unique constraint violation
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" && pgErr.ConstraintName == "idx_messages_mailbox_id_uid" {
			// A preserved UID the mailbox already uses: this message was NOT stored.
			// Distinct from the "already there" unique violations below, which a caller
			// may legitimately count as a duplicate and skip.
			logger.Error("Database: uid conflict, returning error to caller", "message_id", saneMessageID, "mailbox_id", options.MailboxID)
			return 0, 0, consts.ErrUIDConflict
		}
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" &&
			(pgErr.ConstraintName == "messages_message_id_mailbox_id_key" ||
				pgErr.ConstraintName == "messages_message_id_mailbox_id_active_idx") {
			// Unique constraint violation on message_id - message already exists in this mailbox.
			// The transaction is now in an aborted state and must be rolled back.
			// We cannot query for the existing message within this transaction.
			logger.Error("Database: unique constraint violation, returning error to caller", "message_id", saneMessageID, "mailbox_id", options.MailboxID)
			return 0, 0, consts.ErrDBUniqueViolation
		}
		// Log the actual error details for debugging
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			logger.Error("Database: failed to insert message into database",
				"err", err,
				"pg_code", pgErr.Code,
				"pg_message", pgErr.Message,
				"pg_detail", pgErr.Detail,
				"pg_constraint", pgErr.ConstraintName)
		} else {
			logger.Error("Database: failed to insert message into database", "err", err)
		}
		return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBInsertFailed, err)
	}

	// Check if content is already uploaded for this account UNDER THIS ROW'S KEY (content
	// deduplication). If so, mark this message as uploaded immediately without creating
	// a pending_upload.
	//
	// The key matters: readers build their GET key from the row's own s3_domain/
	// s3_localpart, and one account's rows can carry different keys (the primary address
	// at the time each was written, or the address an import ran under). An uploaded row
	// under another key proves nothing about this key — deduping against it would mark
	// this row uploaded with no object behind it (404 NoSuchKey on fetch, served as an
	// empty body).
	//
	// IMPORTANT: Only consider non-expunged messages. Expunged messages may be pending
	// S3 cleanup — if we dedup against them, the new message gets marked uploaded=TRUE
	// without any S3 upload, and the cleaner then deletes the S3 object, leaving the
	// new message referencing a non-existent object (404 NoSuchKey on fetch).
	var alreadyUploaded bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM messages
			WHERE $5::bool AND content_hash = $1
			  AND account_id = $2
			  AND s3_domain = $3
			  AND s3_localpart = $4
			  AND uploaded = TRUE
			  AND expunged_at IS NULL
			LIMIT 1
		)
	`, options.ContentHash, upload.AccountID, options.S3Domain, options.S3Localpart, bodyClaimable).Scan(&alreadyUploaded)
	if err != nil {
		logger.Error("Database: failed to check if content already uploaded", "content_hash", upload.ContentHash, "err", err)
		return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBQueryFailed, err)
	}

	if alreadyUploaded {
		// Content already exists in S3 for this account - mark this message as uploaded immediately
		_, err = tx.Exec(ctx, `
			UPDATE messages
			SET uploaded = TRUE
			WHERE id = $1
		`, messageRowId)
		if err != nil {
			logger.Error("Database: failed to mark message as uploaded (dedup)", "content_hash", upload.ContentHash, "err", err)
			return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBUpdateFailed, err)
		}
		logger.Info("Database: message marked as uploaded via content deduplication",
			"content_hash", truncateHash(options.ContentHash), "account_id", upload.AccountID)
	} else {
		// Content not yet uploaded - create pending_upload.
		//
		// An existing row is re-armed rather than left alone: this delivery has just
		// written a fresh spool file on this instance, so the body is here again even if
		// an earlier copy's file went missing and the uploader used up the row's
		// attempts (one per lease, see processSingleUpload). Without the reset, AcquireAndLeasePendingUploads
		// — which requires attempts < maxAttempts and instance_id = its own — would never
		// lease the row again, and CleanupFailedUploads would eventually delete this
		// message. Clearing last_attempt makes it leasable on the next worker tick; the
		// owning instance's heartbeat carries the liveness signal the cleaner reaps by.
		_, err = tx.Exec(ctx, `
			INSERT INTO pending_uploads (instance_id, content_hash, size, created_at, account_id)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (content_hash, account_id) DO UPDATE
			SET attempts = 0, instance_id = EXCLUDED.instance_id, last_attempt = NULL`,
			upload.InstanceID,
			upload.ContentHash,
			upload.Size,
			time.Now(),
			upload.AccountID,
		)
		if err != nil {
			logger.Error("Database: failed to insert into pending_uploads", "content_hash", upload.ContentHash, "err", err)
			return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBInsertFailed, err) // Transaction will rollback
		}
		logger.Info("Database: pending_upload created",
			"content_hash", truncateHash(options.ContentHash), "account_id", upload.AccountID)
	}

	// ---- FTS STAGING QUEUE (best-effort, non-fatal) ----
	// Insert into messages_fts_v2 AFTER the critical message row and pending_upload
	// are secured. This safely enqueues the raw payloads for the background daemon
	// to asynchronously perform the expensive to_tsvector() conversion. If this fails, the message is still
	// delivered and uploaded to S3 — it just won't be FTS-searchable.
	if shouldStageFTS(options.FTSRetention, sentDate, time.Now()) {
		// Decide what to store in messages_fts_v2.
		// Very large bodies (>64KB) are truncated to their first 64KB, which is all that
		// gets indexed; the full content is always available in S3.
		// text_body is staged in messages_fts_v2, then processed by fts_worker.
		const maxStoredBodySize = 64 * 1024 // 64 KB
		var textBodyArg any = sanePlaintextBody

		if len(sanePlaintextBody) > maxStoredBodySize {
			truncLen := maxStoredBodySize
			for truncLen > 0 && !utf8.RuneStart(sanePlaintextBody[truncLen]) {
				truncLen--
			}
			textBodyArg = sanePlaintextBody[:truncLen]
			logger.Info("Database: truncating text_body for FTS indexing to 64KB for very large message",
				"content_hash", truncateHash(options.ContentHash), "original_size_bytes", len(sanePlaintextBody))
			metrics.LargeBodyStorageSkipped.Inc()
		}

		textBodyStr, _ := textBodyArg.(string)
		if textBodyStr != "" {
			stageFTS(ctx, tx, options.ContentHash, options.AccountID, textBodyArg, sentDate)
		}
	}

	if err := window.end(ctx, tx); err != nil {
		return 0, 0, err
	}
	return messageRowId, uidToUse, nil
}

func (d *Database) InsertMessageFromImporter(ctx context.Context, tx pgx.Tx, options *InsertMessageOptions) (messageID int64, uid int64, err error) {
	// Sanitize user-controlled text fields that go into PostgreSQL text columns.
	// S3Domain, S3Localpart, and ContentHash are system-generated and don't need sanitization.
	saneMessageID := helpers.SanitizeUTF8(options.MessageID)
	saneMailboxName := helpers.SanitizeUTF8(options.MailboxName)

	if saneMessageID == "" {
		logger.Info("Database: messageID is empty after sanitization, generating a synthetic one without modifying the message")
		// A message without a Message-ID gets a synthetic one derived from its content
		// hash, so the SAME bytes always get the SAME id: the (message_id, content_hash)
		// duplicate check then still recognizes a re-import or a retried delivery. A
		// fresh id per attempt made every such message a new one on every run.
		saneMessageID = syntheticMessageID(options.ContentHash, saneMailboxName)
	}

	bodyStructureData, err := helpers.SerializeBodyStructureGob(options.BodyStructure)
	if err != nil {
		logger.Error("Database: failed to serialize BodyStructure", "err", err)
		return 0, 0, consts.ErrSerializationFailed
	}

	if err := LockS3ObjectsSharedInTx(ctx, tx, options.AccountID, []string{options.ContentHash}); err != nil {
		return 0, 0, err
	}

	if options.InternalDate.IsZero() {
		options.InternalDate = time.Now()
	}
	sentDate, sentDateUnknown := storedSentDate(options)

	var highestUID int64
	var uidToUse int64

	// Check UIDVALIDITY before deciding whether to use preserved UID
	if options.PreservedUID != nil && options.PreservedUIDValidity != nil {
		// Check if any messages already exist in this mailbox
		var hasMessages bool
		err = tx.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM messages
				WHERE mailbox_id = $1
				AND expunged_at IS NULL
				LIMIT 1
			)`, options.MailboxID).Scan(&hasMessages)
		if err != nil {
			logger.Error("Database: failed to check for existing messages", "err", err)
			return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBQueryFailed, err)
		}

		// Get current UIDVALIDITY
		var currentUIDValidity uint32
		err = tx.QueryRow(ctx, `SELECT uid_validity FROM mailboxes WHERE id = $1`, options.MailboxID).Scan(&currentUIDValidity)
		if err != nil {
			logger.Error("Database: failed to query current UIDVALIDITY", "err", err)
			return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBQueryFailed, err)
		}

		if hasMessages {
			// Mailbox already has messages - check if UIDVALIDITY matches
			if currentUIDValidity != *options.PreservedUIDValidity {
				// UIDVALIDITY changed - ignore preserved UID and deliver normally
				// Only log once per mailbox to avoid log spam
				if _, logged := d.uidValidityMismatchLoggedMap.LoadOrStore(options.MailboxID, true); !logged {
					logger.Warn("Database: UIDVALIDITY mismatch, ignoring preserved UID and delivering normally",
						"mailbox_id", options.MailboxID, "current", currentUIDValidity, "requested", *options.PreservedUIDValidity)
				}

				// Clear preserved values to use normal auto-increment
				options.PreservedUID = nil
				options.PreservedUIDValidity = nil
			}
			// If UIDVALIDITY matches, continue with UID preservation
		} else {
			// First preserved message - set UIDVALIDITY (overriding auto-generated value)
			if currentUIDValidity != *options.PreservedUIDValidity {
				_, err = tx.Exec(ctx, `
					UPDATE mailboxes
					SET uid_validity = $2
					WHERE id = $1`,
					options.MailboxID, *options.PreservedUIDValidity)
				if err != nil {
					logger.Error("Database: failed to update UIDVALIDITY", "err", err)
					return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBUpdateFailed, err)
				}
				logger.Info("Database: set UIDVALIDITY for first preserved message",
					"mailbox_id", options.MailboxID, "from", currentUIDValidity, "to", *options.PreservedUIDValidity)
			}
		}
	}

	// Now assign UID (either preserved or auto-increment based on above logic)
	if options.PreservedUID != nil {
		uidToUse = int64(*options.PreservedUID)

		// Update highest_uid if preserved UID is higher (handles out-of-order)
		err = tx.QueryRow(ctx, `
			UPDATE mailboxes
			SET highest_uid = GREATEST(highest_uid, $2)
			WHERE id = $1
			RETURNING highest_uid`,
			options.MailboxID, uidToUse).Scan(&highestUID)
		if err != nil {
			logger.Error("Database: failed to update highest UID with preserved UID", "err", err)
			return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBUpdateFailed, err)
		}
	} else {
		// Atomically increment and get the new highest UID for the mailbox
		// The UPDATE statement implicitly locks the row, making a prior SELECT FOR UPDATE redundant
		err = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + 1 WHERE id = $1 RETURNING highest_uid`, options.MailboxID).Scan(&highestUID)
		if err != nil {
			logger.Error("Database: failed to update highest UID", "err", err)
			return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBUpdateFailed, err)
		}
		uidToUse = highestUID
	}

	// Deduplication: Check if an EXACT duplicate exists (use sanitized message ID to match what's stored)
	var existingUID int64
	var existingContentHash string
	err = tx.QueryRow(ctx, `
		SELECT uid, content_hash FROM messages
		WHERE mailbox_id = $1
		AND message_id = $2
		AND content_hash = $3
		AND expunged_at IS NULL
		LIMIT 1`,
		options.MailboxID, saneMessageID, options.ContentHash).Scan(&existingUID, &existingContentHash)
	if err == nil {
		// True duplicate (same Message-ID + same content) - skip insert
		logger.Info("Database: duplicate message detected, skipping insert", "message_id", saneMessageID, "content_hash", options.ContentHash, "mailbox_id", options.MailboxID, "existing_uid", existingUID)
		// Return unique violation error so importer can count it as skipped
		return 0, existingUID, consts.ErrDBUniqueViolation
	} else if err != pgx.ErrNoRows {
		// Unexpected error
		logger.Error("Database: failed to check for duplicate message", "err", err)
		return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBQueryFailed, err)
	}
	// err == pgx.ErrNoRows means no exact duplicate found, continue with insert

	// Sanitize recipients defensively before JSON marshaling.
	// json.Marshal encodes NULL bytes as \u0000, which PostgreSQL JSONB rejects (SQLSTATE 22P05).
	saneRecipients := make([]helpers.Recipient, len(options.Recipients))
	for i, r := range options.Recipients {
		saneRecipients[i] = helpers.Recipient{
			Name:         helpers.SanitizeUTF8(r.Name),
			EmailAddress: helpers.SanitizeUTF8(r.EmailAddress),
			AddressType:  r.AddressType,
			Group:        helpers.SanitizeUTF8(r.Group),
			GroupEnd:     r.GroupEnd,
		}
	}

	recipientsJSON, err := json.Marshal(saneRecipients)
	if err != nil {
		logger.Error("Database: failed to marshal recipients", "err", err)
		return 0, 0, consts.ErrSerializationFailed
	}

	// Prepare denormalized sort fields for faster sorting (bounded; see sortColumnsFor).
	subjectSort, fromNameSort, fromEmailSort, toNameSort, toEmailSort, ccEmailSort, extraAddresses := sortColumnsFor(options.Subject, saneRecipients)

	inReplyToStr := strings.Join(options.InReplyTo, " ")

	systemFlagsToSet, customKeywordsToSet := SplitFlags(options.Flags)
	bitwiseFlags := FlagsToBitwise(systemFlagsToSet)
	// Fold keywords onto the case already used in this mailbox (RFC 9051 §2.3.2)
	// so an APPEND/import carrying a different-case variant of an existing keyword
	// does not introduce a second case.
	customKeywordsToSet, err = d.canonicalizeKeywords(ctx, tx, options.MailboxID, customKeywordsToSet)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to canonicalize custom keywords for InsertMessage: %w", err)
	}
	// Degrade gracefully rather than failing the APPEND if it carries more
	// keywords than a single message may hold (see MaxCustomKeywordsPerMessage).
	customKeywordsToSet = capCustomKeywords(customKeywordsToSet)

	var customKeywordsJSON []byte
	if len(customKeywordsToSet) == 0 {
		customKeywordsJSON = []byte("[]")
	} else {
		customKeywordsJSON, err = json.Marshal(customKeywordsToSet)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to marshal custom keywords for InsertMessage: %w", err)
		}
	}

	var messageRowId int64

	// Sanitize inputs
	saneSubject := helpers.TruncateUTF8Safe(helpers.SanitizeUTF8(options.Subject), helpers.MaxSubjectBytes)
	saneInReplyToStr := helpers.TruncateUTF8Safe(helpers.SanitizeUTF8(inReplyToStr), 2000)

	saneReferencesStr := helpers.TrimReferences(options.References, helpers.MaxReferencesBytes)

	sanePlaintextBody := helpers.SanitizeUTF8(options.PlaintextBody)

	err = tx.QueryRow(ctx, `
		WITH inserted AS (
			INSERT INTO messages
				(account_id, mailbox_id, mailbox_path, uid, message_id, content_hash, s3_domain, s3_localpart, internal_date, size, subject, sent_date, sent_utc_offset, sent_date_unknown, in_reply_to, "references", body_structure, recipients_json, uploaded, created_modseq, subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort, extra_addresses, header_presence, message_id_raw)
			VALUES
				(@account_id, @mailbox_id, @mailbox_path, @uid, @message_id, @content_hash, @s3_domain, @s3_localpart, @internal_date, @size, @subject, @sent_date, @sent_utc_offset, @date_unknown, @in_reply_to, @references, @body_structure, @recipients_json, true, nextval('messages_modseq'), @subject_sort, @from_name_sort, @from_email_sort, @to_name_sort, @to_email_sort, @cc_email_sort, @extra_addresses, @header_presence, @message_id_raw)
			RETURNING id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
		SELECT id, @mailbox_id, @flags, @custom_flags, NOW(), nextval('messages_modseq') FROM inserted
		RETURNING message_id
	`, pgx.NamedArgs{
		"account_id":      options.AccountID,
		"mailbox_id":      options.MailboxID,
		"mailbox_path":    saneMailboxName,
		"s3_domain":       options.S3Domain,
		"s3_localpart":    options.S3Localpart,
		"uid":             uidToUse,
		"message_id":      saneMessageID,
		"content_hash":    options.ContentHash,
		"flags":           bitwiseFlags,
		"custom_flags":    customKeywordsJSON,
		"internal_date":   options.InternalDate,
		"size":            options.Size,
		"subject":         saneSubject,
		"sent_date":       sentDate,
		"sent_utc_offset": sentUTCOffset(sentDate, options.SentDateUnknownZone && !options.SentDate.IsZero()),
		"date_unknown":    sentDateUnknown,
		"in_reply_to":     saneInReplyToStr,
		"references":      saneReferencesStr,
		"body_structure":  bodyStructureData,
		"recipients_json": recipientsJSON,
		"subject_sort":    subjectSort,
		"from_name_sort":  fromNameSort,
		"from_email_sort": fromEmailSort,
		"to_name_sort":    toNameSort,
		"to_email_sort":   toEmailSort,
		"cc_email_sort":   ccEmailSort,
		"extra_addresses": extraAddresses,
		"header_presence": options.HeaderPresence,
		"message_id_raw":  helpers.SanitizeMessageIDRaw(options.MessageIDRaw),
	}).Scan(&messageRowId)

	if err != nil {
		// Check for a unique constraint violation
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" && pgErr.ConstraintName == "idx_messages_mailbox_id_uid" {
			// A preserved UID the mailbox already uses: this message was NOT stored.
			// Distinct from the "already there" unique violations below, which a caller
			// may legitimately count as a duplicate and skip.
			logger.Error("Database: uid conflict, returning error to caller", "message_id", saneMessageID, "mailbox_id", options.MailboxID)
			return 0, 0, consts.ErrUIDConflict
		}
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" &&
			(pgErr.ConstraintName == "messages_message_id_mailbox_id_key" ||
				pgErr.ConstraintName == "messages_message_id_mailbox_id_active_idx") {
			// Unique constraint violation on message_id - message already exists in this mailbox.
			// The transaction is now in an aborted state and must be rolled back.
			// We cannot query for the existing message within this transaction.
			logger.Error("Database: unique constraint violation, returning error to caller", "message_id", saneMessageID, "mailbox_id", options.MailboxID)
			return 0, 0, consts.ErrDBUniqueViolation
		}
		// Log the actual error details for debugging
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			logger.Error("Database: failed to insert message into database",
				"err", err,
				"pg_code", pgErr.Code,
				"pg_message", pgErr.Message,
				"pg_detail", pgErr.Detail,
				"pg_constraint", pgErr.ConstraintName)
		} else {
			logger.Error("Database: failed to insert message into database", "err", err)
		}
		return 0, 0, fmt.Errorf("%w: %w", consts.ErrDBInsertFailed, err)
	}

	if shouldStageFTS(options.FTSRetention, sentDate, time.Now()) {
		// Decide what to store in messages_fts_v2.
		// Very large bodies (>64KB) are truncated to their first 64KB, which is all that
		// gets indexed; the full content is always available in S3.
		const maxStoredBodySize = 64 * 1024 // 64 KB
		var textBodyArg any = sanePlaintextBody

		if len(sanePlaintextBody) > maxStoredBodySize {
			truncLen := maxStoredBodySize
			for truncLen > 0 && !utf8.RuneStart(sanePlaintextBody[truncLen]) {
				truncLen--
			}
			textBodyArg = sanePlaintextBody[:truncLen]
			logger.Info("Database: truncating text_body for FTS indexing to 64KB for very large message",
				"content_hash", truncateHash(options.ContentHash), "original_size_bytes", len(sanePlaintextBody))
			metrics.LargeBodyStorageSkipped.Inc()
		}

		// Only insert when there is actual content. A missing messages_fts_v2 row is
		// expected for old/large messages and is handled gracefully downstream (unsearchable).
		textBodyStr, _ := textBodyArg.(string)
		if textBodyStr != "" {
			stageFTS(ctx, tx, options.ContentHash, options.AccountID, textBodyArg, sentDate)
		}
	}

	return messageRowId, uidToUse, nil
}

// InsertMessagesBatch performs a high-performance bulk insert of messages.
//
// Requirements:
// - All messages MUST belong to the same MailboxID and AccountID
// - Recommended batch size: 100-1000 messages (larger batches have diminishing returns)
// - Duplicates are automatically filtered before insert
//
// Returns:
// - messageIDs: Row IDs of successfully inserted messages
// - uids: Assigned UIDs (same length as messageIDs)
// - contentHashes: Content hashes of successfully inserted messages (same length as messageIDs)
// - error: Non-nil if batch fails (all-or-nothing semantics)
func (d *Database) InsertMessagesBatch(
	ctx context.Context,
	tx pgx.Tx,
	options []*InsertMessageOptions,
	uploads []PendingUpload,
) ([]int64, []int64, []string, error) {
	if len(options) == 0 {
		return nil, nil, nil, nil
	}

	mailboxID := options[0].MailboxID
	accountID := options[0].AccountID
	isImporter := len(uploads) == 0 // Importers don't pass pending uploads

	// 1. Validate that all options belong to the same mailbox and account
	for _, opt := range options {
		if opt.MailboxID != mailboxID {
			return nil, nil, nil, fmt.Errorf("InsertMessagesBatch: mixed MailboxIDs in batch (expected %d, got %d)", mailboxID, opt.MailboxID)
		}
		if opt.AccountID != accountID {
			return nil, nil, nil, fmt.Errorf("InsertMessagesBatch: mixed AccountIDs in batch (expected %d, got %d)", accountID, opt.AccountID)
		}
	}

	// Keyword identity is case-insensitive (RFC 9051 §2.3.2). This batch is
	// single-mailbox, so read the mailbox's canonical keyword map once and fold
	// every message's keywords onto it (first-seen case wins, shared across the
	// whole batch). The per-write canonicalizer can't be used here: the cache is
	// not updated until the batch commits, so it would see no intra-batch keywords.
	batchCanonical, err := d.mailboxKeywordCanonicalMap(ctx, tx, mailboxID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("InsertMessagesBatch: failed to read canonical keywords for mailbox %d: %w", mailboxID, err)
	}

	// 2. Pre-sanitize and process options
	type processedMessage struct {
		Opt                *InsertMessageOptions
		Upload             *PendingUpload
		SaneMessageID      string
		SaneMailboxName    string
		SaneSubject        string
		SanePlaintextBody  string
		SaneInReplyToStr   string
		SaneReferencesStr  string
		BodyStructureData  []byte
		RecipientsJSON     []byte
		CustomKeywordsJSON []byte
		BitwiseFlags       int32
		SubjectSort        string
		FromNameSort       string
		FromEmailSort      string
		ToNameSort         string
		ToEmailSort        string
		CcEmailSort        string
		ExtraAddresses     string
		SentDate           time.Time
		SentDateUnknown    *bool
		AssignedUID        int64
	}

	processed := make([]*processedMessage, 0, len(options))
	messageIDs := make([]string, 0, len(options))
	contentHashes := make([]string, 0, len(options))

	for i, opt := range options {
		saneMessageID := helpers.SanitizeUTF8(opt.MessageID)
		saneMailboxName := helpers.SanitizeUTF8(opt.MailboxName)
		if saneMessageID == "" {
			// Deterministic (see InsertMessage): identical bytes get the identical id.
			saneMessageID = syntheticMessageID(opt.ContentHash, saneMailboxName)
		}

		// A message that cannot be prepared fails the batch rather than being dropped:
		// the caller only learns of it through the error (it then retries the batch one
		// message at a time, where the failure is reported per message). Silently
		// skipping it here made the caller count it as a duplicate.
		bodyStructureData, err := helpers.SerializeBodyStructureGob(opt.BodyStructure)
		if err != nil {
			logger.Error("Database: failed to serialize BodyStructure in batch", "content_hash", truncateHash(opt.ContentHash), "err", err)
			return nil, nil, nil, fmt.Errorf("failed to serialize body structure for message %s: %w", truncateHash(opt.ContentHash), err)
		}

		if opt.InternalDate.IsZero() {
			opt.InternalDate = time.Now()
		}
		sentDate, sentDateUnknown := storedSentDate(opt)

		saneRecipients := make([]helpers.Recipient, len(opt.Recipients))
		for j, r := range opt.Recipients {
			saneRecipients[j] = helpers.Recipient{
				Name:         helpers.SanitizeUTF8(r.Name),
				EmailAddress: helpers.SanitizeUTF8(r.EmailAddress),
				AddressType:  r.AddressType,
				Group:        helpers.SanitizeUTF8(r.Group),
				GroupEnd:     r.GroupEnd,
			}
		}

		recipientsJSON, err := json.Marshal(saneRecipients)
		if err != nil {
			logger.Error("Database: failed to marshal recipients in batch", "content_hash", truncateHash(opt.ContentHash), "err", err)
			return nil, nil, nil, fmt.Errorf("failed to marshal recipients for message %s: %w", truncateHash(opt.ContentHash), err)
		}

		subjectSort, fromNameSort, fromEmailSort, toNameSort, toEmailSort, ccEmailSort, extraAddresses := sortColumnsFor(opt.Subject, saneRecipients)

		inReplyToStr := strings.Join(opt.InReplyTo, " ")
		systemFlagsToSet, customKeywordsToSet := SplitFlags(opt.Flags)
		// Fold onto the batch's shared canonical map (RFC 9051 §2.3.2).
		customKeywordsToSet = foldKeywordsWithMap(batchCanonical, customKeywordsToSet)
		// Degrade gracefully rather than failing the import if a message carries
		// more keywords than it may hold (see MaxCustomKeywordsPerMessage).
		customKeywordsToSet = capCustomKeywords(customKeywordsToSet)
		bitwiseFlags := FlagsToBitwise(systemFlagsToSet)

		var customKeywordsJSON []byte
		if len(customKeywordsToSet) == 0 {
			customKeywordsJSON = []byte("[]")
		} else {
			customKeywordsJSON, err = json.Marshal(customKeywordsToSet)
			if err != nil {
				logger.Error("Database: failed to marshal custom keywords in batch", "content_hash", truncateHash(opt.ContentHash), "err", err)
				return nil, nil, nil, fmt.Errorf("failed to marshal custom keywords for message %s: %w", truncateHash(opt.ContentHash), err)
			}
		}

		var uploadPtr *PendingUpload
		if !isImporter && i < len(uploads) {
			uploadPtr = &uploads[i]
		}

		processed = append(processed, &processedMessage{
			Opt:                opt,
			Upload:             uploadPtr,
			SaneMessageID:      saneMessageID,
			SaneMailboxName:    saneMailboxName,
			SaneSubject:        helpers.TruncateUTF8Safe(helpers.SanitizeUTF8(opt.Subject), helpers.MaxSubjectBytes),
			SanePlaintextBody:  helpers.SanitizeUTF8(opt.PlaintextBody),
			SaneInReplyToStr:   helpers.TruncateUTF8Safe(helpers.SanitizeUTF8(inReplyToStr), 2000),
			SaneReferencesStr:  helpers.TrimReferences(opt.References, helpers.MaxReferencesBytes),
			BodyStructureData:  bodyStructureData,
			RecipientsJSON:     recipientsJSON,
			CustomKeywordsJSON: customKeywordsJSON,
			BitwiseFlags:       int32(bitwiseFlags),
			SubjectSort:        subjectSort,
			FromNameSort:       fromNameSort,
			FromEmailSort:      fromEmailSort,
			ToNameSort:         toNameSort,
			ToEmailSort:        toEmailSort,
			CcEmailSort:        ccEmailSort,
			ExtraAddresses:     extraAddresses,
			SentDate:           sentDate,
			SentDateUnknown:    sentDateUnknown,
		})
		messageIDs = append(messageIDs, saneMessageID)
		contentHashes = append(contentHashes, opt.ContentHash)
	}

	if len(processed) == 0 {
		return nil, nil, nil, nil
	}

	bodyClaimable := true
	if claimErr := LockS3ObjectsSharedInTx(ctx, tx, accountID, contentHashes); claimErr != nil {
		if !isImporter && errors.Is(claimErr, ErrS3BodyQuarantined) {
			bodyClaimable = false
		} else {
			return nil, nil, nil, claimErr
		}
	}

	// 3. Deduplication (Find exact duplicates in one query)
	rows, err := tx.Query(ctx, `
		SELECT message_id, content_hash FROM messages 
		WHERE mailbox_id = $1 
		AND (message_id, content_hash) IN (SELECT * FROM UNNEST($2::text[], $3::text[]))
		AND expunged_at IS NULL
	`, mailboxID, messageIDs, contentHashes)

	if err != nil && err != pgx.ErrNoRows {
		return nil, nil, nil, fmt.Errorf("InsertMessagesBatch: failed to check duplicates: %w", err)
	}

	duplicateSet := make(map[string]bool)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var msgID, hash string
			if err := rows.Scan(&msgID, &hash); err == nil {
				duplicateSet[msgID+"||"+hash] = true
			}
		}
	}

	// Filter out duplicates
	uniqueProcessed := make([]*processedMessage, 0, len(processed))
	for _, p := range processed {
		key := p.SaneMessageID + "||" + p.Opt.ContentHash
		if duplicateSet[key] {
			logger.Info("Database: duplicate message detected in batch, skipping", "message_id", p.SaneMessageID, "content_hash", p.Opt.ContentHash)
			continue
		}
		uniqueProcessed = append(uniqueProcessed, p)
	}

	if len(uniqueProcessed) == 0 {
		return nil, nil, nil, nil
	}

	// 4. Content Deduplication (Find already uploaded S3 hashes)
	uploadedHashesSet := make(map[string]bool)
	if !isImporter && bodyClaimable {
		uHashes := make([]string, 0, len(uniqueProcessed))
		for _, p := range uniqueProcessed {
			uHashes = append(uHashes, p.Opt.ContentHash)
		}
		// Keyed by the full S3 key, not the bare hash: a row is "already uploaded" only
		// if an uploaded row exists under the SAME s3_domain/s3_localpart (see the
		// single-message dedup in InsertMessage for why).
		uRows, err := tx.Query(ctx, `
			SELECT DISTINCT content_hash, s3_domain, s3_localpart FROM messages
			WHERE account_id = $1 AND uploaded = TRUE AND content_hash = ANY($2) AND expunged_at IS NULL
		`, accountID, uHashes)
		if err == nil {
			defer uRows.Close()
			for uRows.Next() {
				var hash, domain, localpart string
				if err := uRows.Scan(&hash, &domain, &localpart); err == nil {
					uploadedHashesSet[helpers.NewS3Key(domain, localpart, hash)] = true
				}
			}
		}
	}

	// 5. Bulk UID Allocation
	// Handle preserved UIDVALIDITY first
	if isImporter && uniqueProcessed[0].Opt.PreservedUID != nil && uniqueProcessed[0].Opt.PreservedUIDValidity != nil {
		var hasMessages bool
		_ = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL LIMIT 1)`, mailboxID).Scan(&hasMessages)
		var currentUIDValidity uint32
		_ = tx.QueryRow(ctx, `SELECT uid_validity FROM mailboxes WHERE id = $1`, mailboxID).Scan(&currentUIDValidity)

		preservedValidity := *uniqueProcessed[0].Opt.PreservedUIDValidity
		if hasMessages && currentUIDValidity != preservedValidity {
			// UIDVALIDITY mismatch, fallback to normal append for all
			if _, logged := d.uidValidityMismatchLoggedMap.LoadOrStore(mailboxID, true); !logged {
				logger.Warn("Database: UIDVALIDITY mismatch in batch, ignoring preserved UIDs", "mailbox_id", mailboxID)
			}
			for _, p := range uniqueProcessed {
				p.Opt.PreservedUID = nil
			}
		} else if !hasMessages && currentUIDValidity != preservedValidity {
			_, _ = tx.Exec(ctx, `UPDATE mailboxes SET uid_validity = $2 WHERE id = $1`, mailboxID, preservedValidity)
			logger.Info("Database: set UIDVALIDITY for first preserved message in batch", "mailbox_id", mailboxID)
		}
	}

	// Allocate UIDs
	var autoIncrementCount int
	var highestUID int64
	var maxPreservedUID int64

	for _, p := range uniqueProcessed {
		if p.Opt.PreservedUID != nil {
			u := int64(*p.Opt.PreservedUID)
			p.AssignedUID = u
			if u > maxPreservedUID {
				maxPreservedUID = u
			}
		} else {
			autoIncrementCount++
		}
	}

	if maxPreservedUID > 0 {
		_ = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = GREATEST(highest_uid, $2) WHERE id = $1 RETURNING highest_uid`, mailboxID, maxPreservedUID).Scan(&highestUID)
	}

	if autoIncrementCount > 0 {
		_ = tx.QueryRow(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + $2 WHERE id = $1 RETURNING highest_uid`, mailboxID, autoIncrementCount).Scan(&highestUID)
		// Distribute newly allocated UIDs (from lowest to highest)
		currentAutoUID := highestUID - int64(autoIncrementCount) + 1
		for _, p := range uniqueProcessed {
			if p.Opt.PreservedUID == nil {
				p.AssignedUID = currentAutoUID
				currentAutoUID++
			}
		}
	}

	// 6. Execute Inserts via pgx.Batch
	batch := &pgx.Batch{}

	// The queue loop below and the result loop that follows it must reach identical
	// staging decisions, so both evaluate the retention window against this instant.
	ftsNow := time.Now()
	var ftsHashesToLock []string
	ftsHashesSeen := make(map[string]struct{})

	for _, p := range uniqueProcessed {
		uploaded := isImporter || uploadedHashesSet[helpers.NewS3Key(p.Opt.S3Domain, p.Opt.S3Localpart, p.Opt.ContentHash)]

		batch.Queue(`
			WITH inserted AS (
				INSERT INTO messages
					(account_id, mailbox_id, mailbox_path, uid, message_id, content_hash, s3_domain, s3_localpart, internal_date, size, subject, sent_date, sent_utc_offset, sent_date_unknown, in_reply_to, "references", body_structure, recipients_json, uploaded, created_modseq, subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort, extra_addresses, header_presence, message_id_raw)
				VALUES
					($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $27, $28, $13, $14, $15, $16, $17, nextval('messages_modseq'), $18, $19, $20, $21, $22, $23, $26, $29, $30)
				RETURNING id
			)
			INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
			SELECT id, $2, $24, $25, NOW(), nextval('messages_modseq') FROM inserted
			RETURNING message_id
		`,
			p.Opt.AccountID, mailboxID, p.SaneMailboxName, p.AssignedUID, p.SaneMessageID, p.Opt.ContentHash,
			p.Opt.S3Domain, p.Opt.S3Localpart, p.Opt.InternalDate, p.Opt.Size, p.SaneSubject, p.SentDate,
			p.SaneInReplyToStr, p.SaneReferencesStr, p.BodyStructureData, p.RecipientsJSON, uploaded, p.SubjectSort,
			p.FromNameSort, p.FromEmailSort, p.ToNameSort, p.ToEmailSort, p.CcEmailSort,
			p.BitwiseFlags, p.CustomKeywordsJSON, p.ExtraAddresses, sentUTCOffset(p.SentDate, p.Opt.SentDateUnknownZone && !p.Opt.SentDate.IsZero()), p.SentDateUnknown, p.Opt.HeaderPresence, helpers.SanitizeMessageIDRaw(p.Opt.MessageIDRaw),
		)

		if !uploaded && p.Upload != nil {
			batch.Queue(`
				INSERT INTO pending_uploads (instance_id, content_hash, size, created_at, account_id)
				VALUES ($1, $2, $3, NOW(), $4)
				ON CONFLICT (content_hash, account_id) DO NOTHING
			`, p.Upload.InstanceID, p.Upload.ContentHash, p.Upload.Size, p.Upload.AccountID)
		}

		if shouldStageFTS(p.Opt.FTSRetention, p.SentDate, ftsNow) {
			const maxStoredBodySize = 64 * 1024 // 64 KB
			var textBodyArg any = p.SanePlaintextBody

			if len(p.SanePlaintextBody) > maxStoredBodySize {
				truncLen := maxStoredBodySize
				for truncLen > 0 && !utf8.RuneStart(p.SanePlaintextBody[truncLen]) {
					truncLen--
				}
				textBodyArg = p.SanePlaintextBody[:truncLen]
				metrics.LargeBodyStorageSkipped.Inc()
			}

			textBodyStr, _ := textBodyArg.(string)
			if textBodyStr != "" {
				if _, seen := ftsHashesSeen[p.Opt.ContentHash]; !seen {
					ftsHashesSeen[p.Opt.ContentHash] = struct{}{}
					ftsHashesToLock = append(ftsHashesToLock, p.Opt.ContentHash)
				}
				batch.Queue(ftsStageV2SQL, p.Opt.ContentHash, p.Opt.AccountID, textBodyArg, p.SentDate)
			}
		}
	}

	if len(ftsHashesToLock) > 0 {
		if _, err := tx.Exec(ctx, `
			SELECT pg_advisory_xact_lock_shared($1, hashtext(h))
			FROM unnest($2::text[]) h`,
			consts.SoraFTSOrphanSweepLockClassID, ftsHashesToLock); err != nil {
			return nil, nil, nil, fmt.Errorf("InsertMessagesBatch: failed to acquire shared advisory lock for fts: %w", err)
		}
	}

	br := tx.SendBatch(ctx, batch)
	defer br.Close()

	var insertedRowIDs []int64
	var insertedUIDs []int64
	var insertedHashes []string

	// pgx.Batch guarantees results are returned in the same order as queued
	for _, p := range uniqueProcessed {
		var rowID int64
		err := br.QueryRow().Scan(&rowID)
		if err != nil {
			// If unique constraint violation occurs during batch execution, we fail the batch
			if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
				return nil, nil, nil, consts.ErrDBUniqueViolation
			}
			return nil, nil, nil, fmt.Errorf("InsertMessagesBatch: failed execution: %w", err)
		}
		insertedRowIDs = append(insertedRowIDs, rowID)
		insertedUIDs = append(insertedUIDs, p.AssignedUID)
		insertedHashes = append(insertedHashes, p.Opt.ContentHash)

		uploaded := isImporter || uploadedHashesSet[helpers.NewS3Key(p.Opt.S3Domain, p.Opt.S3Localpart, p.Opt.ContentHash)]
		if !uploaded && p.Upload != nil {
			_, err = br.Exec() // pending_uploads
			if err != nil {
				return nil, nil, nil, fmt.Errorf("InsertMessagesBatch: failed pending_upload: %w", err)
			}
		}

		if shouldStageFTS(p.Opt.FTSRetention, p.SentDate, ftsNow) {
			textBodyStr, _ := p.SanePlaintextBody, false
			if len(p.SanePlaintextBody) > 64*1024 {
				textBodyStr = "..." // Mocked just to check if we queued it
			}
			if textBodyStr != "" {
				_, err = br.Exec() // messages_fts_v2
				if err != nil {
					return nil, nil, nil, fmt.Errorf("InsertMessagesBatch: failed messages_fts_v2: %w", err)
				}
			}
		}
	}

	return insertedRowIDs, insertedUIDs, insertedHashes, nil
}

// InsertMessageFromImporterBatch is a wrapper for InsertMessagesBatch tailored for sora-admin import
func (d *Database) InsertMessagesFromImporterBatch(ctx context.Context, tx pgx.Tx, options []*InsertMessageOptions) ([]int64, []int64, []string, error) {
	return d.InsertMessagesBatch(ctx, tx, options, nil)
}

// syntheticMessageID is the Message-ID stored for a message that has none. It is a
// pure function of the content hash so that the same bytes always get the same id:
// duplicate detection on (message_id, content_hash) then keeps working for re-imports
// and retried deliveries, which a per-attempt id (a timestamp) silently defeated —
// every run inserted such messages again. The mailbox name only serves as a readable
// domain part.
func syntheticMessageID(contentHash, mailboxName string) string {
	if contentHash == "" {
		contentHash = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("<%s@%s.synthetic.invalid>", contentHash, mailboxName)
}

// headerMessageID is the Message-ID header a stored message_id stands for, or "" when
// the message had no usable one. The ingress parser (mail.Header.MessageID) returns a
// msg-id without its angle brackets, and its id-left cannot begin with '<'; only the
// synthetic IDs stored for duplicate detection (InsertMessage, syntheticMessageID) keep
// theirs. Every reader that reports message_id as the message's header goes through
// this; messageIDFieldExpr is the same rule in SQL.
func headerMessageID(stored string) string {
	if strings.HasPrefix(stored, "<") {
		return ""
	}
	return stored
}
