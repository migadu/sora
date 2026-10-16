package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

// ThreadMessageResult represents the lightweight metadata needed to run
// the ORDEREDSUBJECT and REFERENCES threading algorithms in memory.
type ThreadMessageResult struct {
	UID          imap.UID
	MessageID    string
	InReplyTo    string
	References   string
	SubjectSort  string
	SentDate     time.Time
	InternalDate time.Time // arrival; THREAD=REFS orders threads by it
	Seq          uint32
}

// ThreadMaxMessages is the most messages one THREAD command threads. A search
// matching more is refused with ErrThreadTooManyMessages rather than threaded in
// part: a client such as Roundcube shows the THREAD result as the message list, so
// a partial result would present the rest of the folder as gone.
//
// Threading is in memory and cheap (about 18 ms and 27 MB for 50,000 messages);
// the cap bounds the rows one command pulls from the database. It is a variable
// only so tests can lower it.
var ThreadMaxMessages = 50000

// ErrThreadTooManyMessages is returned when a THREAD search matches more than
// ThreadMaxMessages messages.
var ErrThreadTooManyMessages = errors.New("THREAD search matches too many messages")

// GetMessagesForThreading returns the threading metadata of the messages in a
// mailbox that match criteria, in UID order. withSeqNums fills in each message's
// sequence number, which only THREAD (not UID THREAD) needs and which costs a
// ROW_NUMBER() over the whole mailbox; otherwise Seq is 0.
func (db *Database) GetMessagesForThreading(ctx context.Context, mailboxID, accountID int64, criteria *imap.SearchCriteria, includeSubject, withSeqNums bool) ([]ThreadMessageResult, error) {
	// Fold custom keywords in the criteria onto the mailbox's canonical case so
	// THREAD ... KEYWORD <name> matches case-insensitively (RFC 9051 §2.3.2),
	// mirroring the SEARCH executors.
	if err := db.canonicalizeSearchCriteriaKeywords(ctx, nil, mailboxID, criteria); err != nil {
		return nil, err
	}
	// A sequence-set search key compiles to a seqnum column the query does not
	// have; name the same messages by UID instead, as SEARCH does.
	if err := db.mapSeqNumCriteriaToUID(ctx, mailboxID, criteria); err != nil {
		return nil, err
	}
	paramCounter := 0
	whereClause, whereArgs, err := db.buildSearchCriteria(criteria, "m", &paramCounter)
	if err != nil {
		return nil, fmt.Errorf("failed to build search criteria for threading: %w", err)
	}
	whereArgs["mailbox_id"] = mailboxID
	whereArgs["accountID"] = accountID

	subjectSelect := `'' AS subject_sort`
	if includeSubject {
		subjectSelect = `m.subject_sort`
	}

	// The FTS table is joined only for a BODY or TEXT key: one probe per message
	// otherwise buys nothing. When joined, it is account-scoped (see ftsScopedJoin).
	ftsJoin := ""
	if criteriaContainsFTS(criteria) {
		ftsJoin = ftsScopedJoin
	}

	seqCTE, seqJoin, seqSelect := "", "", "0"
	if withSeqNums {
		seqCTE = `WITH seq AS (
			SELECT uid, ROW_NUMBER() OVER (ORDER BY uid) AS seqnum
			FROM messages
			WHERE mailbox_id = @mailbox_id AND expunged_at IS NULL
		)`
		seqJoin = "JOIN seq ON seq.uid = m.uid"
		seqSelect = "seq.seqnum"
	}

	// One row past the cap tells a search that is too large from one that is not.
	finalQueryString := fmt.Sprintf(`
		%s
		SELECT m.uid, m.message_id, m.in_reply_to, m."references", %s, m.sent_date, m.internal_date, %s
		FROM messages m
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		%s
		%s
		WHERE m.mailbox_id = @mailbox_id
		  AND m.expunged_at IS NULL
		  AND %s
		ORDER BY m.uid
		LIMIT %d
	`, seqCTE, subjectSelect, seqSelect, ftsJoin, seqJoin, whereClause, ThreadMaxMessages+1)

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

		if err := rows.Scan(&msg.UID, &msgID, &inReplyTo, &references, &subjectSort, &sentDate, &msg.InternalDate, &msg.Seq); err != nil {
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
		if len(messages) > ThreadMaxMessages {
			metrics.DBQueriesTotal.WithLabelValues("search_thread", "too_many", "read").Inc()
			return nil, ErrThreadTooManyMessages
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error scanning thread rows: %w", err)
	}
	metrics.DBQueriesTotal.WithLabelValues("search_thread", "success", "read").Inc()

	return messages, nil
}
