package db

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

const (
	// MaxSearchResults is the default limit for SEARCH/SORT operations returning message metadata
	// This includes full Message structs (subjects, recipients, body_structure, etc) but NOT message bodies
	// Estimated ~2KB per message: 100k messages = ~200MB of memory for results
	// IMAP FETCH is NOT limited by this - it uses GetMessagesByNumSet() which has no limit
	MaxSearchResults = 100000

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

	// For SeqNum - use seqnum column with appropriate prefix
	seqColumn := "seqnum"
	if tablePrefix != "" {
		seqColumn = tablePrefix + ".seqnum"
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
	// Note: text_body_tsv is in messages_fts table, which is only available in complex query path
	for _, bodyCriteria := range criteria.Body {
		param := nextParam()
		args[param] = bodyCriteria
		// Handle case where FTS data may be cleaned up (text_body_tsv is NULL)
		// This ensures search still works but returns no results for cleaned messages
		// Note: This column is in messages_fts table, only joined in complex query
		conditions = append(conditions, fmt.Sprintf("text_body_tsv IS NOT NULL AND text_body_tsv @@ plainto_tsquery('simple', @%s)", param))
	}
	// Text search - searches both headers and body (RFC 3501: TEXT matches header or body)
	// Note: text_body_tsv and headers_tsv are in messages_fts table, only available in complex query path
	for _, textCriteria := range criteria.Text {
		param := nextParam()
		args[param] = textCriteria
		// Search in both headers and body text using full-text search
		// Either TSV matching is sufficient; NULL-safe so pruned columns are skipped gracefully
		// Note: These columns are in messages_fts table, only joined in complex query
		conditions = append(conditions, fmt.Sprintf(
			"((text_body_tsv IS NOT NULL AND text_body_tsv @@ plainto_tsquery('simple', @%s)) OR (headers_tsv IS NOT NULL AND headers_tsv @@ plainto_tsquery('simple', @%s)))",
			param, param))
	}

	// State prefix for fields moved to message_state
	statePrefix := ""
	if tablePrefix == "m" {
		statePrefix = "ms."
	} else if tablePrefix != "" {
		statePrefix = tablePrefix + "."
	}

	// Flags
	for _, flag := range criteria.Flag {
		param := nextParam()
		args[param] = FlagToBitwise(flag)
		conditions = append(conditions, fmt.Sprintf("(%sflags & @%s) != 0", statePrefix, param))
	}
	for _, flag := range criteria.NotFlag {
		param := nextParam()
		args[param] = FlagToBitwise(flag)
		conditions = append(conditions, fmt.Sprintf("(%sflags & @%s) = 0", statePrefix, param))
	}

	// MODSEQ filtering (CONDSTORE extension - RFC 7162)
	// Search for messages with MODSEQ >= specified value
	if criteria.ModSeq != nil {
		param := nextParam()
		args[param] = criteria.ModSeq.ModSeq
		// MODSEQ is the maximum of created_modseq, updated_modseq, and expunged_modseq
		// GREATEST returns the largest non-NULL value
		conditions = append(conditions, fmt.Sprintf(
			"GREATEST(%screated_modseq, COALESCE(%supdated_modseq, 0), COALESCE(%sexpunged_modseq, 0)) >= @%s",
			datePrefix, statePrefix, datePrefix, param))
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
		case "from":
			param := nextParam()
			// Support partial matching on both email address and display name
			// This allows searching for "peter" to find "peter@whatever.com" or "Peter Smith"
			// Note: *_sort columns are already lowercase
			args[param] = "%" + lowerValue + "%"
			conditions = append(conditions, fmt.Sprintf(
				"(%sfrom_email_sort LIKE @%s OR %sfrom_name_sort LIKE @%s)",
				datePrefix, param, datePrefix, param))
		case "to":
			param := nextParam()
			// Support partial matching on both email address and display name
			// Note: *_sort columns are already lowercase
			args[param] = "%" + lowerValue + "%"
			conditions = append(conditions, fmt.Sprintf(
				"(%sto_email_sort LIKE @%s OR %sto_name_sort LIKE @%s)",
				datePrefix, param, datePrefix, param))
		case "cc":
			param := nextParam()
			// Support partial email matching using indexed cc_email_sort column
			// Note: CC doesn't have a name_sort column, only email
			args[param] = "%" + lowerValue + "%"
			conditions = append(conditions, fmt.Sprintf("%scc_email_sort LIKE @%s", datePrefix, param))
		case "bcc", "reply-to":
			// BCC and Reply-To don't have dedicated sort columns, fall back to JSONB search
			recipientJSONParam := nextParam()
			// Use json.Marshal to safely build JSONB value (handles special characters in search values)
			recipientEntry := []map[string]string{{"type": lowerKey, "email": lowerValue}}
			recipientJSON, _ := json.Marshal(recipientEntry)
			args[recipientJSONParam] = string(recipientJSON)
			conditions = append(conditions, fmt.Sprintf(`%srecipients_json @> @%s::jsonb`, datePrefix, recipientJSONParam))
		default:
			// Generic HEADER search for arbitrary headers (e.g., HEADER List-ID "value")
			// Use FTS search on headers_tsv column
			// Note: needsComplexQuery() will detect this and use complex query path
			param := nextParam()
			args[param] = lowerValue
			conditions = append(conditions, fmt.Sprintf(
				"headers_tsv IS NOT NULL AND headers_tsv @@ plainto_tsquery('simple', @%s)",
				param))
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
		case imap.SortKeyDisplayFrom:
			// DISPLAYFROM: Use display name if available, fallback to email (RFC 5256)
			orderField = fmt.Sprintf("COALESCE(%sfrom_name_sort, %sfrom_email_sort)", colPrefix, colPrefix)
		case imap.SortKeyFrom:
			// FROM: Use email address only
			orderField = fmt.Sprintf("%sfrom_email_sort", colPrefix)
		case imap.SortKeyDisplayTo:
			// DISPLAYTO: Use display name if available, fallback to email (RFC 5256)
			orderField = fmt.Sprintf("COALESCE(%sto_name_sort, %sto_email_sort)", colPrefix, colPrefix)
		case imap.SortKeyTo:
			// TO: Use email address only
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
	// Always include uid as the final sort criterion to ensure consistent ordering.
	// We align the UID direction with the primary sort direction to allow PostgreSQL
	// to use btree index scanning backwards instead of falling back to in-memory sorts.
	uidDirection := "ASC"
	if len(sortCriteria) > 0 && sortCriteria[0].Reverse {
		uidDirection = "DESC"
	}
	orderClauses = append(orderClauses, fmt.Sprintf("%suid %s", colPrefix, uidDirection))

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

	// If no conditions were generated (empty set), return a condition that matches nothing
	if len(conditions) == 0 {
		return "1=0", args, nil
	}

	finalCondition := strings.Join(conditions, " OR ")
	if len(conditions) > 1 {
		finalCondition = "(" + finalCondition + ")"
	}

	return finalCondition, args, nil
}

// needsComplexQuery determines if the search criteria requires the complex CTE query
// with ROW_NUMBER() and messages_fts JOIN, or if we can use the optimized simple query
func (db *Database) needsComplexQuery(criteria *imap.SearchCriteria, orderByClause string) bool {
	// Need complex query for full-text search
	if len(criteria.Body) > 0 || len(criteria.Text) > 0 {
		return true
	}

	// Need complex query for generic header searches (requires headers_tsv from messages_fts)
	for _, headerField := range criteria.Header {
		lowerKey := strings.ToLower(headerField.Key)
		// Check if this is a generic header (not one with a dedicated column)
		switch lowerKey {
		case "from", "to", "cc", "bcc", "subject", "message-id", "in-reply-to", "reply-to":
			// These have dedicated columns, no need for complex query
			continue
		default:
			// Generic header requires headers_tsv search
			return true
		}
	}

	// Need complex query for sequence number searches (requires seqnum calculation)
	for _, seqSet := range criteria.SeqNum {
		if len(seqSet) > 0 {
			return true
		}
	}

	// Check nested criteria for Body/Text (in OR and NOT clauses)
	for _, notCriteria := range criteria.Not {
		if db.needsComplexQuery(&notCriteria, orderByClause) {
			return true
		}
	}
	for _, orPair := range criteria.Or {
		if db.needsComplexQuery(&orPair[0], orderByClause) || db.needsComplexQuery(&orPair[1], orderByClause) {
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
func (db *Database) getMessagesQueryExecutor(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, orderByClause string, limit int) ([]Message, error) {
	paramCounter := 0

	var finalQueryString string
	var metricsLabel string
	var resultLimit int
	var whereCondition string
	var whereArgs pgx.NamedArgs
	var err error

	// Determine appropriate result limit based on query complexity
	isComplexQuery := db.needsComplexQuery(criteria, orderByClause)
	if limit > 0 {
		// Caller specified an explicit limit - use it
		resultLimit = limit
	} else if isComplexQuery {
		// Complex queries (CTE, JSONB sorting) get lower limits due to processing overhead
		if strings.Contains(strings.ToLower(orderByClause), "coalesce(") ||
			strings.Contains(strings.ToLower(orderByClause), "jsonb_array_elements") {
			resultLimit = MaxComplexSortResults // 500 for expensive JSONB sorting
		} else {
			resultLimit = MaxSearchResults // 100k for other complex queries (FTS, sequence)
		}
	} else {
		resultLimit = MaxSearchResults // 100k for simple queries - reasonable for IMAP clients
	}

	needsSeqNumSearch := false
	var checkSeqNum func(*imap.SearchCriteria) bool
	checkSeqNum = func(c *imap.SearchCriteria) bool {
		if c == nil {
			return false
		}
		if len(c.SeqNum) > 0 {
			return true
		}
		for _, n := range c.Not {
			if checkSeqNum(&n) {
				return true
			}
		}
		for _, pair := range c.Or {
			if checkSeqNum(&pair[0]) || checkSeqNum(&pair[1]) {
				return true
			}
		}
		return false
	}
	needsSeqNumSearch = checkSeqNum(criteria)
	// If ordering uses sequence numbers dynamically, we can't push it down
	if strings.Contains(strings.ToLower(orderByClause), "seqnum") {
		needsSeqNumSearch = true
	}

	if needsSeqNumSearch && !strings.Contains(strings.ToLower(orderByClause), "seqnum") {
		// If we only need seqnum for WHERE filtering, we can map the SeqSets to UIDSets
		// and completely bypass the catastrophic ROW_NUMBER() materialization!
		var mapSeqToUID func(*imap.SearchCriteria) error
		mapSeqToUID = func(c *imap.SearchCriteria) error {
			if c == nil {
				return nil
			}
			if len(c.SeqNum) > 0 {
				for _, seqSet := range c.SeqNum {
					var mappedUIDSet imap.UIDSet
					for _, seqRange := range seqSet {
						startUID, err := db.getUIDBySeqNum(ctx, mailboxID, seqRange.Start)
						if err != nil {
							continue // Out of bounds or invalid
						}

						uidRange := imap.UIDRange{Start: startUID}
						if seqRange.Stop == 0 {
							uidRange.Stop = 0
						} else {
							stopUID, err := db.getUIDBySeqNum(ctx, mailboxID, seqRange.Stop)
							if err != nil {
								uidRange.Stop = 0 // Cap to highest
							} else {
								uidRange.Start = min(startUID, stopUID)
								uidRange.Stop = max(startUID, stopUID)
							}
						}
						mappedUIDSet = append(mappedUIDSet, uidRange)
					}
					if len(mappedUIDSet) > 0 {
						c.UID = append(c.UID, mappedUIDSet)
					} else if len(seqSet) > 0 {
						c.UID = append(c.UID, []imap.UIDRange{{Start: 0, Stop: 0}})
					}
				}
				// Clear the SeqNum criteria since we moved them to UID
				c.SeqNum = nil
			}
			for i := range c.Not {
				if err := mapSeqToUID(&c.Not[i]); err != nil {
					return err
				}
			}
			for i := range c.Or {
				if err := mapSeqToUID(&c.Or[i][0]); err != nil {
					return err
				}
				if err := mapSeqToUID(&c.Or[i][1]); err != nil {
					return err
				}
			}
			return nil
		}

		if err := mapSeqToUID(criteria); err == nil {
			needsSeqNumSearch = false
		}
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
			orderByClause = "ORDER BY m.uid DESC"
		}

		// Fast path: Simple query without joining messages_fts.
		// We use a scalar subquery to dynamically generate sequence numbers safely only for the matched rows.
		// This incredibly speeds up queries with LIMIT (like searches or sorts returning latest 50 messages)
		// because Postgres filters and sorts the base table directly without materializing the whole mailbox.
		simpleQueryTemplate := `
		WITH filtered_messages AS (
			SELECT
				m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, ms.flags, ms.custom_flags,
				m.internal_date, m.size, m.created_modseq, ms.updated_modseq, m.expunged_modseq,
				ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json,
				m.subject_sort, m.from_name_sort, m.from_email_sort, m.to_name_sort, m.to_email_sort, m.cc_email_sort
			FROM messages m
			LEFT JOIN message_state ms ON ms.message_id = m.id
			WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL AND (%s)
			%s
			LIMIT %d
		),
		bounds AS MATERIALIZED (
			SELECT COALESCE(MIN(uid), 0) as min_uid, COALESCE(MAX(uid), 0) as max_uid FROM filtered_messages
		),
		base_count AS MATERIALIZED (
			SELECT COUNT(*) as base
			FROM messages m
			WHERE m.mailbox_id = @mailboxID
			  AND m.uid < (SELECT min_uid FROM bounds)
			  AND m.expunged_at IS NULL
		),
		range_counts AS MATERIALIZED (
			SELECT m.uid, ROW_NUMBER() OVER(ORDER BY m.uid ASC) as offset
			FROM messages m
			WHERE m.mailbox_id = @mailboxID
			  AND m.uid BETWEEN (SELECT min_uid FROM bounds) AND (SELECT max_uid FROM bounds)
			  AND m.expunged_at IS NULL
		)
		SELECT
			f.id, f.account_id, f.uid, f.mailbox_id, f.content_hash, f.s3_domain, f.s3_localpart, f.uploaded, f.flags, f.custom_flags,
			f.internal_date, f.size, f.created_modseq, f.updated_modseq, f.expunged_modseq,
			(bc.base + rc.offset) as seqnum,
			f.flags_changed_at, f.subject, f.sent_date, f.message_id, f.in_reply_to, f.recipients_json
		FROM filtered_messages f
		CROSS JOIN base_count bc
		JOIN range_counts rc ON f.uid = rc.uid
		%s`

		// Note: The ordering clause uses "m." prefix initially, but we need it to use "f." for the outer query
		outerOrderByClause := strings.ReplaceAll(orderByClause, "m.", "f.")
		finalQueryString = fmt.Sprintf(simpleQueryTemplate, whereCondition, orderByClause, resultLimit, outerOrderByClause)
		metricsLabel = "search_messages_simple"

	} else if !needsSeqNumSearch {
		// Modern Complex path: We need FTS or JSONB generic headers, BUT we do NOT need SeqNum filtering.
		// Thus, we can push down complex where clauses (FTS joins) into the CTE too!
		whereCondition, whereArgs, err = db.buildSearchCriteriaWithPrefix(criteria, "p", &paramCounter, "m")
		if err != nil {
			return nil, err
		}
		whereArgs["mailboxID"] = mailboxID

		if orderByClause == "" {
			orderByClause = "ORDER BY m.uid DESC"
		}

		complexQueryTemplate := `
		WITH filtered_messages AS (
			SELECT
				m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, ms.flags, ms.custom_flags,
				m.internal_date, m.size, m.created_modseq, ms.updated_modseq, m.expunged_modseq,
				ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json,
				m.subject_sort, m.from_name_sort, m.from_email_sort, m.to_name_sort, m.to_email_sort, m.cc_email_sort
			FROM messages m
			LEFT JOIN messages_fts mc ON m.content_hash = mc.content_hash
			LEFT JOIN message_state ms ON ms.message_id = m.id
			WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL AND (%s)
			%s
			LIMIT %d
		),
		bounds AS MATERIALIZED (
			SELECT COALESCE(MIN(uid), 0) as min_uid, COALESCE(MAX(uid), 0) as max_uid FROM filtered_messages
		),
		base_count AS MATERIALIZED (
			SELECT COUNT(*) as base
			FROM messages m
			WHERE m.mailbox_id = @mailboxID
			  AND m.uid < (SELECT min_uid FROM bounds)
			  AND m.expunged_at IS NULL
		),
		range_counts AS MATERIALIZED (
			SELECT m.uid, ROW_NUMBER() OVER(ORDER BY m.uid ASC) as offset
			FROM messages m
			WHERE m.mailbox_id = @mailboxID
			  AND m.uid BETWEEN (SELECT min_uid FROM bounds) AND (SELECT max_uid FROM bounds)
			  AND m.expunged_at IS NULL
		)
		SELECT
			f.id, f.account_id, f.uid, f.mailbox_id, f.content_hash, f.s3_domain, f.s3_localpart, f.uploaded, f.flags, f.custom_flags,
			f.internal_date, f.size, f.created_modseq, f.updated_modseq, f.expunged_modseq,
			(bc.base + rc.offset) as seqnum,
			f.flags_changed_at, f.subject, f.sent_date, f.message_id, f.in_reply_to, f.recipients_json
		FROM filtered_messages f
		CROSS JOIN base_count bc
		JOIN range_counts rc ON f.uid = rc.uid
		%s`

		outerOrderByClause := strings.ReplaceAll(orderByClause, "m.", "f.")
		finalQueryString = fmt.Sprintf(complexQueryTemplate, whereCondition, orderByClause, resultLimit, outerOrderByClause)
		metricsLabel = "search_messages_complex_fast"

	} else {
		// Legacy Complex path: Use CTE with empty table prefix because SeqNum filtering REQUIRES evaluating Sequence IDs BEFORE where
		whereCondition, whereArgs, err = db.buildSearchCriteriaWithPrefix(criteria, "p", &paramCounter, "")
		if err != nil {
			return nil, err
		}
		whereArgs["mailboxID"] = mailboxID

		if orderByClause == "" {
			orderByClause = "ORDER BY uid DESC"
		}

		// Complex path: Use CTE when sequence numbers are needed in WHERE
		const complexQuery = `
		WITH message_seqs AS (
			SELECT
				m.id, m.uid,
				ROW_NUMBER() OVER(ORDER BY uid) as seqnum,
				m.account_id, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, ms.flags, ms.custom_flags,
				m.internal_date, m.size, m.created_modseq, ms.updated_modseq, m.expunged_modseq,
				ms.flags_changed_at, m.subject, m.sent_date, m.message_id,
				m.in_reply_to, m.recipients_json, mc.text_body_tsv, mc.headers_tsv,
				m.subject_sort, m.from_name_sort, m.from_email_sort, m.to_name_sort, m.to_email_sort, m.cc_email_sort
			FROM messages m
			LEFT JOIN messages_fts mc ON m.content_hash = mc.content_hash
			LEFT JOIN message_state ms ON ms.message_id = m.id
			WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL
		)
		SELECT 
			id, account_id, uid, mailbox_id, content_hash, s3_domain, s3_localpart, uploaded, flags, custom_flags,
			internal_date, size, created_modseq, updated_modseq, expunged_modseq, seqnum,
			flags_changed_at, subject, sent_date, message_id, in_reply_to, recipients_json
		FROM message_seqs`
		finalQueryString = fmt.Sprintf("%s WHERE %s %s LIMIT %d", complexQuery, whereCondition, orderByClause, resultLimit)
		metricsLabel = "search_messages_complex_legacy"
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
		logger.Error("Database: failed executing query", "query", finalQueryString, "args", whereArgs, "err", err)
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	messages, err := scanMessages(rows, false)
	if err != nil {
		return nil, fmt.Errorf("getMessagesQueryExecutor: failed to scan messages: %w", err)
	}

	// Log warning if we hit the default result limit (may indicate client needs to refine search)
	// Don't warn if caller explicitly requested this limit (limit > 0)
	if limit == 0 && len(messages) >= resultLimit {
		logger.Warn("Database: search query hit result limit", "limit", resultLimit, "mailbox_id", mailboxID, "complex", isComplexQuery, "message", "Client may need to use more specific search criteria")
	}

	return messages, nil
}

func (db *Database) GetMessagesWithCriteria(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, limit int) ([]Message, error) {
	messages, err := db.getMessagesQueryExecutor(ctx, mailboxID, criteria, "", limit) // Empty string triggers default sort
	if err != nil {
		return nil, fmt.Errorf("GetMessagesWithCriteria: %w", err)
	}
	return messages, nil
}

// GetMessagesSorted retrieves messages that match the search criteria, sorted according to the provided sort criteria
func (db *Database) GetMessagesSorted(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, sortCriteria []imap.SortCriterion, limit int) ([]Message, error) {
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

	messages, err := db.getMessagesQueryExecutor(ctx, mailboxID, criteria, orderBy, limit)
	if err != nil {
		// The error from getMessagesQueryExecutor will be wrapped here
		return nil, fmt.Errorf("GetMessagesSorted: %w", err)
	}
	return messages, nil
}
