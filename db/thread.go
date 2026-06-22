package db

import (
	"context"
	"fmt"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

// ThreadMessageResult represents the lightweight metadata needed to run
// the ORDEREDSUBJECT and REFERENCES threading algorithms in memory.
type ThreadMessageResult struct {
	UID         imap.UID
	MessageID   string
	InReplyTo   string
	References  string
	SubjectSort string
	SentDate    time.Time
	Seq         uint32
}

// ThreadMaxMessages defines the hard cap for how many messages we will thread at once to prevent OOM/CPU spikes.
const ThreadMaxMessages = 5000

// GetMessagesForThreading executes a query to retrieve threading metadata for all matching messages.
// It leverages idx_messages_mailbox_dates_uid for high performance index-only scans.
func (db *Database) GetMessagesForThreading(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, includeSubject bool) ([]ThreadMessageResult, error) {
	// Fold custom keywords in the criteria onto the mailbox's canonical case so
	// THREAD ... KEYWORD <name> matches case-insensitively (RFC 9051 §2.3.2),
	// mirroring the SEARCH executors.
	if err := db.canonicalizeSearchCriteriaKeywords(ctx, nil, mailboxID, criteria); err != nil {
		return nil, err
	}
	paramCounter := 0
	whereClause, whereArgs, err := db.buildSearchCriteria(criteria, "m", &paramCounter)
	if err != nil {
		return nil, fmt.Errorf("failed to build search criteria for threading: %w", err)
	}

	whereArgs["mailbox_id"] = mailboxID

	subjectSelect1 := `'' AS subject_sort`
	subjectSelect2 := `l.subject_sort`
	if includeSubject {
		subjectSelect1 = `m.subject_sort`
	}

	finalQueryString := fmt.Sprintf(`
		WITH seq AS (
			SELECT uid, ROW_NUMBER() OVER(ORDER BY uid ASC) as seqnum
			FROM messages 
			WHERE mailbox_id = @mailbox_id AND expunged_at IS NULL
		),
		latest_msgs AS (
			SELECT m.uid, m.message_id, m.in_reply_to, m."references", %s, m.sent_date
			FROM messages m
			LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
			LEFT JOIN messages_fts mc ON m.content_hash = mc.content_hash
			WHERE m.mailbox_id = @mailbox_id
			  AND m.expunged_at IS NULL
			  AND %s
			ORDER BY m.uid DESC
			LIMIT %d
		)
		SELECT l.uid, l.message_id, l.in_reply_to, l."references", %s, l.sent_date, seq.seqnum
		FROM latest_msgs l
		JOIN seq ON l.uid = seq.uid
		ORDER BY l.uid ASC
	`, subjectSelect1, whereClause, ThreadMaxMessages, subjectSelect2)

	start := time.Now()
	rows, err := db.ReadPool.Query(ctx, finalQueryString, whereArgs)

	metrics.DBQueryDuration.WithLabelValues("search_thread", "read").Observe(time.Since(start).Seconds())
	if err != nil {
		metrics.DBQueriesTotal.WithLabelValues("search_thread", "error", "read").Inc()
		logger.Error("Database: failed executing thread search query", "query", finalQueryString, "args", whereArgs, "err", err, "duration", time.Since(start))
		return nil, fmt.Errorf("failed to execute thread search query: %w", err)
	}
	defer rows.Close()

	var messages []ThreadMessageResult
	for rows.Next() {
		var msg ThreadMessageResult
		// Handle potential NULLs using pgx's implicit pointer handling if necessary.
		// However, in_reply_to and message_id are usually empty strings rather than NULL in our schema,
		// but we'll use pointers just in case to be perfectly safe.
		var msgID, inReplyTo, references, subjectSort *string
		var sentDate *time.Time

		if err := rows.Scan(&msg.UID, &msgID, &inReplyTo, &references, &subjectSort, &sentDate, &msg.Seq); err != nil {
			return nil, fmt.Errorf("failed to scan thread message: %w", err)
		}

		if msgID != nil {
			msg.MessageID = *msgID
		}
		if inReplyTo != nil {
			msg.InReplyTo = *inReplyTo
		}
		if references != nil {
			msg.References = *references
		}
		if subjectSort != nil {
			msg.SubjectSort = *subjectSort
		}
		if sentDate != nil {
			msg.SentDate = *sentDate
		}

		messages = append(messages, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error scanning thread rows: %w", err)
	}
	metrics.DBQueriesTotal.WithLabelValues("search_thread", "success", "read").Inc()

	return messages, nil
}
