package db

import (
	"context"
	"fmt"
	"log"
	"maps"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/pkg/metrics"
)

const (
	// MaxSearchResults limits search queries to prevent memory exhaustion on large mailboxes
	// This is a safety limit - IMAP clients should use reasonable search criteria
	MaxSearchResults = 1000

	// MaxComplexSortResults limits expensive sorting operations (JSONB sorts, etc.)
	// Lower limit due to per-row JSONB processing overhead
	MaxComplexSortResults = 500
)

// buildSearchCriteria builds the SQL WHERE clause for the search criteria
func (db *Database) buildSearchCriteria(criteria *imap.SearchCriteria, paramPrefix string, paramCounter *int) (string, pgx.NamedArgs, error) {
	return db.buildSearchCriteriaWithPrefix(criteria, paramPrefix, paramCounter, "m")
}

// buildSearchCriteriaWithPrefix builds the SQL WHERE clause with configurable table prefix
func (db *Database) buildSearchCriteriaWithPrefix(criteria *imap.SearchCriteria, paramPrefix string, paramCounter *int, tablePrefix string) (string, pgx.NamedArgs, error) {
	var conditions []string
	args := pgx.NamedArgs{}

	nextParam := func() string {
		*paramCounter++
		return fmt.Sprintf("%s%d", paramPrefix, *paramCounter)
	}

	// For SeqNum - use seqnum column directly in CTE context
	seqColumn := "seqnum"
	if tablePrefix == "m" {
		seqColumn = "ms.seqnum" // When joining with message_sequences
	}
	for _, seqSet := range criteria.SeqNum {
		seqCond, seqArgs, err := buildNumSetCondition(seqSet, seqColumn, paramPrefix, paramCounter)
		if err != nil {
			return "", nil, fmt.Errorf("failed to build SeqNum condition: %w", err)
		}
		maps.Copy(args, seqArgs)
		conditions = append(conditions, seqCond)
	}

	// For UID
	uidColumn := fmt.Sprintf("%s.uid", tablePrefix)
	if tablePrefix == "" {
		uidColumn = "uid"
	}
	for _, uidSet := range criteria.UID {
		uidCond, uidArgs, err := buildNumSetCondition(uidSet, uidColumn, paramPrefix, paramCounter)
		if err != nil {
			return "", nil, fmt.Errorf("failed to build UID condition: %w", err)
		}
		maps.Copy(args, uidArgs)
		conditions = append(conditions, uidCond)
	}

	// Date filters
	datePrefix := tablePrefix
	if tablePrefix == "" {
		datePrefix = ""
	} else {
		datePrefix = tablePrefix + "."
	}

	if !criteria.Since.IsZero() {
		param := nextParam()
		args[param] = criteria.Since
		conditions = append(conditions, fmt.Sprintf("%sinternal_date >= @%s", datePrefix, param))
	}
	if !criteria.Before.IsZero() {
		param := nextParam()
		args[param] = criteria.Before
		conditions = append(conditions, fmt.Sprintf("%sinternal_date <= @%s", datePrefix, param))
	}
	if !criteria.SentSince.IsZero() {
		param := nextParam()
		args[param] = criteria.SentSince
		conditions = append(conditions, fmt.Sprintf("%ssent_date >= @%s", datePrefix, param))
	}
	if !criteria.SentBefore.IsZero() {
		param := nextParam()
		args[param] = criteria.SentBefore
		conditions = append(conditions, fmt.Sprintf("%ssent_date <= @%s", datePrefix, param))
	}

	// Message size
	if criteria.Larger > 0 {
		param := nextParam()
		args[param] = criteria.Larger
		conditions = append(conditions, fmt.Sprintf("%ssize > @%s", datePrefix, param))
	}
	if criteria.Smaller > 0 {
		param := nextParam()
		args[param] = criteria.Smaller
		conditions = append(conditions, fmt.Sprintf("%ssize < @%s", datePrefix, param))
	}

	// Body full-text search
	for _, bodyCriteria := range criteria.Body {
		param := nextParam()
		args[param] = bodyCriteria
		// Handle case where FTS data may be cleaned up (text_body_tsv is NULL)
		// This ensures search still works but returns no results for cleaned messages
		conditions = append(conditions, fmt.Sprintf("text_body_tsv IS NOT NULL AND text_body_tsv @@ plainto_tsquery('simple', @%s)", param))
	}
	// Text search - searches both headers and body
	for _, textCriteria := range criteria.Text {
		param := nextParam()
		args[param] = textCriteria
		// Search in both headers and body text using full-text search
		// Note: headers_tsv column may not exist in current schema, so search only body for now
		conditions = append(conditions, fmt.Sprintf(
			"(text_body_tsv IS NOT NULL AND text_body_tsv @@ plainto_tsquery('simple', @%s))",
			param))
	}

	// Flags
	for _, flag := range criteria.Flag {
		param := nextParam()
		args[param] = FlagToBitwise(flag)
		conditions = append(conditions, fmt.Sprintf("(%sflags & @%s) != 0", datePrefix, param))
	}
	for _, flag := range criteria.NotFlag {
		param := nextParam()
		args[param] = FlagToBitwise(flag)
		conditions = append(conditions, fmt.Sprintf("(%sflags & @%s) = 0", datePrefix, param))
	}

	// Header conditions
	for _, header := range criteria.Header {
		lowerValue := strings.ToLower(header.Value)
		lowerKey := strings.ToLower(header.Key)
		switch lowerKey {
		case "subject":
			param := nextParam()
			args[param] = "%" + lowerValue + "%"
			conditions = append(conditions, fmt.Sprintf("LOWER(%ssubject) LIKE @%s", datePrefix, param))
		case "message-id":
			param := nextParam()
			// if the message ID is wrapped in <messageId>, we need to remove the brackets
			if strings.HasPrefix(lowerValue, "<") && strings.HasSuffix(lowerValue, ">") {
				lowerValue = lowerValue[1 : len(lowerValue)-1]
			}
			args[param] = lowerValue
			conditions = append(conditions, fmt.Sprintf("LOWER(%smessage_id) = @%s", datePrefix, param))
		case "in-reply-to":
			param := nextParam()
			args[param] = lowerValue
			conditions = append(conditions, fmt.Sprintf("LOWER(%sin_reply_to) = @%s", datePrefix, param))
		case "from", "to", "cc", "bcc", "reply-to":
			recipientJSONParam := nextParam()
			recipientValue := fmt.Sprintf(`[{"type": "%s", "email": "%s"}]`, lowerKey, lowerValue)
			args[recipientJSONParam] = recipientValue
			conditions = append(conditions, fmt.Sprintf(`%srecipients_json @> @%s::jsonb`, datePrefix, recipientJSONParam))
		default:
			return "", nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Text: "SEARCH criteria generic HEADER is not supported",
			}
		}
	}

	// Recursive NOT
	for _, notCriteria := range criteria.Not {
		subCond, subArgs, err := db.buildSearchCriteriaWithPrefix(&notCriteria, paramPrefix, paramCounter, tablePrefix)
		if err != nil {
			return "", nil, err
		}
		maps.Copy(args, subArgs)
		conditions = append(conditions, fmt.Sprintf("NOT (%s)", subCond))
	}

	// Recursive OR
	for _, orPair := range criteria.Or {
		leftCond, leftArgs, err := db.buildSearchCriteriaWithPrefix(&orPair[0], paramPrefix, paramCounter, tablePrefix)
		if err != nil {
			return "", nil, err
		}
		rightCond, rightArgs, err := db.buildSearchCriteriaWithPrefix(&orPair[1], paramPrefix, paramCounter, tablePrefix)
		if err != nil {
			return "", nil, err
		}

		maps.Copy(args, leftArgs)
		maps.Copy(args, rightArgs)

		conditions = append(conditions, fmt.Sprintf("(%s OR %s)", leftCond, rightCond))
	}

	finalCondition := "1=1"
	if len(conditions) > 0 {
		finalCondition = strings.Join(conditions, " AND ")
	}

	return finalCondition, args, nil
}

// buildSortOrderClause builds an SQL ORDER BY clause from IMAP sort criteria
func (db *Database) buildSortOrderClause(sortCriteria []imap.SortCriterion) string {
	return db.buildSortOrderClauseWithPrefix(sortCriteria, "m")
}

// buildSortOrderClauseWithPrefix builds an SQL ORDER BY clause from IMAP sort criteria with configurable table prefix
func (db *Database) buildSortOrderClauseWithPrefix(sortCriteria []imap.SortCriterion, tablePrefix string) string {
	// Determine column prefix (empty for CTE queries, "m." for regular queries)
	var colPrefix string
	if tablePrefix == "" {
		colPrefix = ""
	} else {
		colPrefix = tablePrefix + "."
	}

	if len(sortCriteria) == 0 {
		return fmt.Sprintf("ORDER BY %suid", colPrefix)
	}

	var orderClauses []string

	for _, criterion := range sortCriteria {
		var direction string
		if criterion.Reverse {
			direction = "DESC"
		} else {
			direction = "ASC"
		}

		var orderField string
		switch criterion.Key {
		case imap.SortKeyArrival:
			orderField = fmt.Sprintf("%sinternal_date", colPrefix)
		case imap.SortKeyDate:
			orderField = fmt.Sprintf("%ssent_date", colPrefix)
		case imap.SortKeySubject:
			// Use the pre-normalized sort column for performance.
			orderField = fmt.Sprintf("%ssubject_sort", colPrefix)
		case imap.SortKeySize:
			orderField = fmt.Sprintf("%ssize", colPrefix)
		case imap.SortKeyDisplay:
			// Use pre-normalized columns. Fallback from name to email.
			orderField = fmt.Sprintf("COALESCE(%sfrom_name_sort, %sfrom_email_sort)", colPrefix, colPrefix)
		case imap.SortKeyFrom:
			// Use the pre-normalized sort column.
			orderField = fmt.Sprintf("%sfrom_email_sort", colPrefix)
		case imap.SortKeyTo:
			// Use the pre-normalized sort column.
			orderField = fmt.Sprintf("%sto_email_sort", colPrefix)
		case imap.SortKeyCc:
			// Use the pre-normalized sort column.
			orderField = fmt.Sprintf("%scc_email_sort", colPrefix)
		default:
			// If the sort key is not supported, default to uid
			orderField = fmt.Sprintf("%suid", colPrefix)
		}

		orderClauses = append(orderClauses, fmt.Sprintf("%s %s", orderField, direction))
	}
	// Always include uid as the final sort criterion to ensure consistent ordering
	orderClauses = append(orderClauses, fmt.Sprintf("%suid ASC", colPrefix))

	return "ORDER BY " + strings.Join(orderClauses, ", ")
}

func buildNumSetCondition(numSet imap.NumSet, columnName string, paramPrefix string, paramCounter *int) (string, pgx.NamedArgs, error) {
	args := pgx.NamedArgs{}
	var conditions []string

	nextParam := func() string {
		*paramCounter++
		return fmt.Sprintf("%s%d", paramPrefix, *paramCounter)
	}

	switch s := numSet.(type) {
	case imap.SeqSet:
		for _, r := range s {
			if r.Start == r.Stop {
				param := nextParam()
				args[param] = r.Start
				conditions = append(conditions, fmt.Sprintf("%s = @%s", columnName, param))
			} else {
				startParam := nextParam()
				stopParam := nextParam()
				args[startParam] = r.Start
				args[stopParam] = r.Stop
				conditions = append(conditions, fmt.Sprintf("%s BETWEEN @%s AND @%s", columnName, startParam, stopParam))
			}
		}
	case imap.UIDSet:
		for _, r := range s {
			if r.Start == r.Stop {
				param := nextParam()
				args[param] = r.Start
				conditions = append(conditions, fmt.Sprintf("%s = @%s", columnName, param))
			} else {
				startParam := nextParam()
				stopParam := nextParam()
				args[startParam] = r.Start

				// Handle * wildcard: Stop=0 means "highest UID in mailbox"
				stopValue := r.Stop
				if r.Stop == 0 {
					// For UID ranges, * should be the highest possible UID (MaxUint32)
					// This ensures the range includes all UIDs from Start to the actual highest UID
					stopValue = 4294967295 // MaxUint32
				}
				args[stopParam] = stopValue

				conditions = append(conditions, fmt.Sprintf("%s BETWEEN @%s AND @%s", columnName, startParam, stopParam))
			}
		}
	default:
		return "", nil, fmt.Errorf("unsupported NumSet type: %T", numSet)
	}

	finalCondition := strings.Join(conditions, " OR ")
	if len(conditions) > 1 {
		finalCondition = "(" + finalCondition + ")"
	}

	return finalCondition, args, nil
}

// needsComplexQuery determines if the search criteria requires the complex CTE query
// with ROW_NUMBER() and message_contents JOIN, or if we can use the optimized simple query
func (db *Database) needsComplexQuery(criteria *imap.SearchCriteria, orderByClause string) bool {
	// Need complex query for full-text search
	if len(criteria.Body) > 0 || len(criteria.Text) > 0 {
		return true
	}

	// Need complex query for sequence number searches (requires seqnum calculation)
	for _, seqSet := range criteria.SeqNum {
		if len(seqSet) > 0 {
			return true
		}
	}

	// Check if ORDER BY clause requires complex operations
	if strings.Contains(strings.ToLower(orderByClause), "seqnum") ||
		strings.Contains(strings.ToLower(orderByClause), "jsonb_array_elements") ||
		strings.Contains(strings.ToLower(orderByClause), "coalesce(") {
		return true
	}

	return false
}

// getMessagesQueryExecutor is a helper function to execute the message retrieval query,
// handling both default and custom sorting with optimized query selection.
func (db *Database) getMessagesQueryExecutor(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, orderByClause string) ([]Message, error) {
	paramCounter := 0

	var finalQueryString string
	var metricsLabel string
	var resultLimit int
	var whereCondition string
	var whereArgs pgx.NamedArgs
	var err error

	// Determine appropriate result limit based on query complexity
	isComplexQuery := db.needsComplexQuery(criteria, orderByClause)
	if isComplexQuery {
		// Complex queries (CTE, JSONB sorting) get lower limits due to processing overhead
		if strings.Contains(strings.ToLower(orderByClause), "coalesce(") ||
			strings.Contains(strings.ToLower(orderByClause), "jsonb_array_elements") {
			resultLimit = MaxComplexSortResults // 1k for expensive JSONB sorting
		} else {
			resultLimit = MaxSearchResults // 5k for other complex queries (FTS, sequence)
		}
	} else {
		resultLimit = MaxSearchResults // 5k for simple queries - reasonable for IMAP clients
	}

	// Use optimized query path when possible
	if !isComplexQuery {
		// Fast path: Simple query with table aliases
		whereCondition, whereArgs, err = db.buildSearchCriteriaWithPrefix(criteria, "p", &paramCounter, "m")
		if err != nil {
			return nil, err
		}
		whereArgs["mailboxID"] = mailboxID

		// For simple queries, ensure ORDER BY uses "m." prefix
		if orderByClause == "" {
			orderByClause = "ORDER BY m.uid"
		}

		// Fast path: Simple query without joining message_contents.
		// We still need to generate seqnum for non-UID searches.
		const simpleQuery = `			
			SELECT 
				m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, m.flags, m.custom_flags,
				m.internal_date, m.size, m.body_structure, m.created_modseq, m.updated_modseq, m.expunged_modseq, ms.seqnum,
				m.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
			FROM messages m
			JOIN message_sequences ms ON m.mailbox_id = ms.mailbox_id AND m.uid = ms.uid
		`
		// The WHERE clause needs to be applied to the joined result.
		// The join condition on message_sequences implicitly filters for non-expunged messages.
		finalQueryString = fmt.Sprintf("%s WHERE m.mailbox_id = @mailboxID AND %s %s LIMIT %d", simpleQuery, whereCondition, orderByClause, resultLimit)
		metricsLabel = "search_messages_simple"
	} else {
		// Complex path: Use CTE with empty table prefix (CTE columns are accessed directly)
		whereCondition, whereArgs, err = db.buildSearchCriteriaWithPrefix(criteria, "p", &paramCounter, "")
		if err != nil {
			return nil, err
		}
		whereArgs["mailboxID"] = mailboxID

		// For CTE queries, ensure ORDER BY uses no prefix
		if orderByClause == "" {
			orderByClause = "ORDER BY uid"
		}

		// Complex path: Use CTE when sequence numbers or FTS are needed
		const complexQuery = `
		WITH message_seqs AS (
			SELECT
				m.id, m.uid,
				ms.seqnum,
				m.account_id, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, m.flags, m.custom_flags,
				m.internal_date, m.size, m.body_structure, m.created_modseq, m.updated_modseq, m.expunged_modseq,
				m.flags_changed_at, m.subject, m.sent_date, m.message_id,
				m.in_reply_to, m.recipients_json, mc.text_body_tsv,
				m.subject_sort, m.from_name_sort, m.from_email_sort, m.to_email_sort, m.cc_email_sort
			FROM messages m
			JOIN message_sequences ms ON m.mailbox_id = ms.mailbox_id AND m.uid = ms.uid
			LEFT JOIN message_contents mc ON m.content_hash = mc.content_hash
			WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL
		)
		SELECT 
			id, account_id, uid, mailbox_id, content_hash, s3_domain, s3_localpart, uploaded, flags, custom_flags,
			internal_date, size, body_structure, created_modseq, updated_modseq, expunged_modseq, seqnum,
			flags_changed_at, subject, sent_date, message_id, in_reply_to, recipients_json
		FROM message_seqs`
		finalQueryString = fmt.Sprintf("%s WHERE %s %s LIMIT %d", complexQuery, whereCondition, orderByClause, resultLimit)
		metricsLabel = "search_messages_complex"
	}

	start := time.Now()
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, finalQueryString, whereArgs)

	// Record metrics
	status := "success"
	if err != nil {
		status = "error"
	}
	metrics.DBQueryDuration.WithLabelValues(metricsLabel, "read").Observe(time.Since(start).Seconds())
	metrics.DBQueriesTotal.WithLabelValues(metricsLabel, status, "read").Inc()

	if err != nil {
		log.Printf("[DB] ERROR: failed executing query: %s\nArgs: %#v\nError: %v", finalQueryString, whereArgs, err)
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	messages, err := scanMessages(rows)
	if err != nil {
		return nil, fmt.Errorf("getMessagesQueryExecutor: failed to scan messages: %w", err)
	}

	// Log warning if we hit the result limit (may indicate client needs to refine search)
	if len(messages) >= resultLimit {
		log.Printf("[DB] WARNING: Search query hit result limit (%d) for mailbox %d. "+
			"Client may need to use more specific search criteria. Complex: %v",
			resultLimit, mailboxID, isComplexQuery)
	}

	return messages, nil
}

func (db *Database) GetMessagesWithCriteria(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria) ([]Message, error) {
	messages, err := db.getMessagesQueryExecutor(ctx, mailboxID, criteria, "ORDER BY uid") // Default sort
	if err != nil {
		return nil, fmt.Errorf("GetMessagesWithCriteria: %w", err)
	}
	return messages, nil
}

// GetMessagesSorted retrieves messages that match the search criteria, sorted according to the provided sort criteria
func (db *Database) GetMessagesSorted(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, sortCriteria []imap.SortCriterion) ([]Message, error) {
	// Build ORDER BY clause first to determine if it requires complex query
	// We'll use a temporary prefix to check complexity, then rebuild with correct prefix
	tempOrderBy := db.buildSortOrderClauseWithPrefix(sortCriteria, "m")
	isComplexQuery := db.needsComplexQuery(criteria, tempOrderBy)

	var orderBy string
	if isComplexQuery {
		// Complex queries use CTE, so no table prefix needed
		orderBy = db.buildSortOrderClauseWithPrefix(sortCriteria, "")
	} else {
		// Simple queries use table aliases, so use "m" prefix
		orderBy = tempOrderBy
	}

	messages, err := db.getMessagesQueryExecutor(ctx, mailboxID, criteria, orderBy)
	if err != nil {
		// The error from getMessagesQueryExecutor will be wrapped here
		return nil, fmt.Errorf("GetMessagesSorted: %w", err)
	}
	return messages, nil
}
