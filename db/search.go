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
	// SEARCH ALL is also exempted from this limit to avoid breaking clients like imapsync
	MaxSearchResults = 100000

	// MaxComplexSortResults limits expensive sorting operations (JSONB sorts, etc.)
	// Lower limit due to per-row JSONB processing overhead
	MaxComplexSortResults = 500
)

// buildSearchCriteria builds the SQL WHERE clause for the search criteria
func (db *Database) buildSearchCriteria(criteria *imap.SearchCriteria, paramPrefix string, paramCounter *int) (string, pgx.NamedArgs, error) {
	return db.buildSearchCriteriaWithPrefix(criteria, paramPrefix, paramCounter, "m")
}

// isCriteriaSearchAll checks if the search criteria is effectively a "SEARCH ALL" command,
// i.e., it has no filtering conditions and will match all messages in the mailbox.
func isCriteriaSearchAll(criteria *imap.SearchCriteria) bool {
	if criteria == nil {
		return true
	}

	// Check if all fields are empty/default
	return len(criteria.SeqNum) == 0 &&
		len(criteria.UID) == 0 &&
		criteria.Since.IsZero() &&
		criteria.Before.IsZero() &&
		criteria.SentSince.IsZero() &&
		criteria.SentBefore.IsZero() &&
		len(criteria.Header) == 0 &&
		len(criteria.Body) == 0 &&
		len(criteria.Text) == 0 &&
		len(criteria.Flag) == 0 &&
		len(criteria.NotFlag) == 0 &&
		criteria.Larger == 0 &&
		criteria.Smaller == 0 &&
		len(criteria.Not) == 0 &&
		len(criteria.Or) == 0 &&
		criteria.ModSeq == nil
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
	// We search:
	//   1. text_body_tsv (FTS index on message body in messages_fts table)
	//   2. Dedicated columns: subject, from/to/cc sort columns (indexed in messages table)
	//
	// Note: headers_tsv was removed in migration 000030 because all searchable headers
	// (From/To/Cc/Subject) have dedicated indexed columns. The headers_tsv index was
	// 7.5 GB (vs text_body_tsv at 1.2 GB) and caused 12+ second UPDATE queries.
	for _, textCriteria := range criteria.Text {
		param := nextParam()
		args[param] = textCriteria
		likeParam := nextParam()
		lowerText := strings.ToLower(textCriteria)
		args[likeParam] = "%" + lowerText + "%"

		// Search across: body FTS, subject column, and recipient sort columns
		// Note: text_body_tsv is in messages_fts table (complex query only)
		// Note: *_sort columns are already lowercase, so no need for LOWER()
		conditions = append(conditions, fmt.Sprintf(
			"((text_body_tsv IS NOT NULL AND text_body_tsv @@ plainto_tsquery('simple', @%s)) "+
				"OR LOWER(%ssubject) LIKE @%s "+
				"OR %sfrom_email_sort LIKE @%s "+
				"OR %sfrom_name_sort LIKE @%s "+
				"OR %sto_email_sort LIKE @%s "+
				"OR %sto_name_sort LIKE @%s "+
				"OR %scc_email_sort LIKE @%s)",
			param, datePrefix, likeParam,
			datePrefix, likeParam, datePrefix, likeParam,
			datePrefix, likeParam, datePrefix, likeParam,
			datePrefix, likeParam))
	}

	// State prefix for fields moved to message_state
	statePrefix := ""
	if tablePrefix == "m" {
		statePrefix = "ms."
	} else if tablePrefix != "" {
		statePrefix = tablePrefix + "."
	}

	// Flags - inline the flag bitmasks to allow Postgres to use partial indexes natively
	// (e.g. idx_message_state_first_unseen) instead of parameterized variables that defeat the query planner
	for _, flag := range criteria.Flag {
		bitwise := FlagToBitwise(flag)
		if bitwise != 0 {
			conditions = append(conditions, fmt.Sprintf("(%sflags & %d) != 0", statePrefix, bitwise))
		} else {
			param := nextParam()
			args[param] = string(flag)
			conditions = append(conditions, fmt.Sprintf("%scustom_flags @> jsonb_build_array(@%s::text)", statePrefix, param))
		}
	}
	for _, flag := range criteria.NotFlag {
		bitwise := FlagToBitwise(flag)
		if bitwise != 0 {
			conditions = append(conditions, fmt.Sprintf("(%sflags & %d) = 0", statePrefix, bitwise))
		} else {
			param := nextParam()
			args[param] = string(flag)
			conditions = append(conditions, fmt.Sprintf("NOT (%scustom_flags @> jsonb_build_array(@%s::text))", statePrefix, param))
		}
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
		case "references":
			// The References header holds a space-separated chain of Message-IDs.
			// Threading clients search it for a containing Message-ID, so match
			// as a substring against the dedicated column added in migration 000036.
			param := nextParam()
			args[param] = "%" + lowerValue + "%"
			conditions = append(conditions, fmt.Sprintf(`LOWER(%s"references") LIKE @%s`, datePrefix, param))
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
			// HEADER search on a header without a dedicated, indexed column
			// (e.g. List-ID, X-*). Sora stores no raw-header representation to
			// query, so these match nothing. All commonly-searched headers
			// (From/To/Cc/Subject/Message-ID/In-Reply-To/References) are handled
			// above via dedicated columns. Return FALSE to match nothing.
			conditions = append(conditions, "FALSE")
			logger.Debug("HEADER search on non-indexed header returns no results",
				"header", lowerKey, "value", lowerValue)
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

	// Note: Generic header searches no longer need complex query after headers_tsv removal.
	// They will return FALSE (no matches) per the buildSearchCriteria logic above.
	// All commonly-searched headers have dedicated columns (from/to/cc/subject/etc.)

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

	// Check if ORDER BY clause requires sequence number complex operations
	// We do NOT check for 'coalesce' or 'json' operations since the Simple Query syntax natively supports them
	if strings.Contains(strings.ToLower(orderByClause), "seqnum") {
		return true
	}

	return false
}

// needsIndexScanBiasBuster checks if the target query contains unstructured text filters
// (such as LIKE '%...%' or FTS) that benefit from Postgres's bitmap heap scanning over
// falling back to a naive backward streaming index scan.
func (db *Database) needsIndexScanBiasBuster(criteria *imap.SearchCriteria) bool {
	if criteria == nil {
		return false
	}
	if len(criteria.Text) > 0 || len(criteria.Body) > 0 || len(criteria.Header) > 0 {
		return true
	}
	for _, notCriteria := range criteria.Not {
		if db.needsIndexScanBiasBuster(&notCriteria) {
			return true
		}
	}
	for _, orPair := range criteria.Or {
		if db.needsIndexScanBiasBuster(&orPair[0]) || db.needsIndexScanBiasBuster(&orPair[1]) {
			return true
		}
	}
	return false
}

// hasNestedFTS reports whether any OR/NOT subtree of the criteria contains a
// full-text (Body/Text) condition. The TEXT UNION rewrite can only split an FTS
// term that appears as a single top-level AND factor; an FTS term buried inside
// OR/NOT cannot be lifted into a UNION branch without changing semantics, so its
// presence disqualifies the rewrite.
func hasNestedFTS(c *imap.SearchCriteria) bool {
	if c == nil {
		return false
	}
	for i := range c.Not {
		if criteriaContainsFTS(&c.Not[i]) {
			return true
		}
	}
	for i := range c.Or {
		if criteriaContainsFTS(&c.Or[i][0]) || criteriaContainsFTS(&c.Or[i][1]) {
			return true
		}
	}
	return false
}

// criteriaContainsFTS reports whether the criteria contains a Body/Text condition
// anywhere (top level or nested).
func criteriaContainsFTS(c *imap.SearchCriteria) bool {
	if c == nil {
		return false
	}
	if len(c.Body) > 0 || len(c.Text) > 0 {
		return true
	}
	return hasNestedFTS(c)
}

// canUseTextUnion reports whether a search is eligible for the TEXT UNION rewrite.
//
// IMAP TEXT search expands to an OR that mixes messages_fts.text_body_tsv (reachable
// only through the content_hash join) with LIKE filters on messages.* columns. A
// single OR spanning two tables cannot be driven by any one index, so on a large
// mailbox the planner degrades to a full mailbox scan with a per-row probe into
// messages_fts (measured at 24s vs 13.6s for the UNION form). The rewrite splits the
// term into an indexable header branch (trigram indexes on messages) UNION an
// indexable body branch (FTS GIN on messages_fts).
//
// Eligibility is intentionally conservative — exactly one top-level TEXT term, no
// BODY term, and no FTS nested in OR/NOT — so the decomposition is a simple two-branch
// UNION with no disjunction cross-product. Everything else falls back to the existing
// complex-fast path unchanged. This is a strict subset of the complex-fast conditions
// (needsSeqNumSearch must be false, ORDER BY must not need seqnum).
func (db *Database) canUseTextUnion(criteria *imap.SearchCriteria, needsSeqNumSearch bool, orderByClause string) bool {
	if criteria == nil || needsSeqNumSearch {
		return false
	}
	if len(criteria.Text) != 1 || len(criteria.Body) != 0 {
		return false
	}
	if hasNestedFTS(criteria) {
		return false
	}
	if strings.Contains(strings.ToLower(orderByClause), "seqnum") {
		return false
	}
	return true
}

// buildTextSearchBranches generates the two SQL predicates for a single IMAP TEXT
// term, split for the UNION rewrite. The body predicate matches messages_fts.
// text_body_tsv (unqualified so it resolves to the joined messages_fts row, exactly
// as in buildSearchCriteriaWithPrefix); the header predicate matches the indexed
// messages.* sort columns. Together they are semantically identical to the combined
// OR produced for criteria.Text, just separated so each side can use its own index.
func buildTextSearchBranches(text string, args pgx.NamedArgs, paramPrefix string, paramCounter *int) (headerCond, bodyCond string) {
	next := func() string {
		*paramCounter++
		return fmt.Sprintf("%s%d", paramPrefix, *paramCounter)
	}
	tsParam := next()
	args[tsParam] = text
	likeParam := next()
	args[likeParam] = "%" + strings.ToLower(text) + "%"

	bodyCond = fmt.Sprintf("text_body_tsv IS NOT NULL AND text_body_tsv @@ plainto_tsquery('simple', @%s)", tsParam)
	headerCond = fmt.Sprintf(
		"(LOWER(m.subject) LIKE @%[1]s "+
			"OR m.from_email_sort LIKE @%[1]s "+
			"OR m.from_name_sort LIKE @%[1]s "+
			"OR m.to_email_sort LIKE @%[1]s "+
			"OR m.to_name_sort LIKE @%[1]s "+
			"OR m.cc_email_sort LIKE @%[1]s)",
		likeParam)
	return headerCond, bodyCond
}

// Sort columns carried through the UNION CTE (in addition to each branch's data
// projection) so the outer ORDER BY, which references the CTE alias f, can sort by
// them. They are not returned to the caller. The lightweight projection omits the
// non-name columns from its data set, so it must carry them here too; the full
// projection already includes internal_date/sent_date/size and only needs the *_sort
// columns. Each must appear EXACTLY ONCE across (branchSelect + sortColumns) or the CTE
// gets a duplicate column.
const (
	textUnionSortColumnsFull  = "m.subject_sort, m.from_name_sort, m.from_email_sort, m.to_name_sort, m.to_email_sort, m.cc_email_sort"
	textUnionSortColumnsLight = "m.internal_date, m.sent_date, m.size, " + textUnionSortColumnsFull
)

// buildTextUnionQuery builds the validated TEXT UNION query for an eligible search
// (see canUseTextUnion). branchSelect is the per-branch data projection from messages m
// / message_state ms; sortColumns are the additional messages.* columns the outer ORDER
// BY needs (see textUnionSortColumns*); outerSelect is the final projection over the
// deduped CTE alias f (and is where "0 as seqnum" lives). All non-Text criteria are
// built once and replicated into both branches so combined searches (TEXT +
// flags/dates/etc.) stay correct.
func (db *Database) buildTextUnionQuery(criteria *imap.SearchCriteria, mailboxID int64, branchSelect, sortColumns, outerSelect, orderByClause string, resultLimit int, paramCounter *int) (string, pgx.NamedArgs, error) {
	// Base (non-Text) conditions, replicated into both branches. A shallow copy with
	// Text cleared is sufficient: buildSearchCriteriaWithPrefix only reads the criteria.
	base := *criteria
	base.Text = nil
	baseCond, args, err := db.buildSearchCriteriaWithPrefix(&base, paramPrefix, paramCounter, "m")
	if err != nil {
		return "", nil, err
	}

	headerCond, bodyCond := buildTextSearchBranches(criteria.Text[0], args, paramPrefix, paramCounter)

	if orderByClause == "" {
		orderByClause = "ORDER BY m.uid DESC"
	}
	// The outer query sorts the (small) deduped CTE, so the bias-buster is applied for
	// parity with the validated query; it is harmless on a CTE with no index to scan.
	outerOrder := orderByClause
	if db.needsIndexScanBiasBuster(criteria) {
		outerOrder = strings.ReplaceAll(outerOrder, "ORDER BY m.uid", "ORDER BY m.uid + 0")
		if outerOrder == orderByClause {
			outerOrder = strings.ReplaceAll(outerOrder, "ORDER BY uid", "ORDER BY uid + 0")
		}
	}
	outerOrder = strings.ReplaceAll(outerOrder, "m.", "f.")

	args["mailboxID"] = mailboxID

	limitClause := ""
	if resultLimit > 0 {
		limitClause = fmt.Sprintf("LIMIT %d", resultLimit)
	}

	query := fmt.Sprintf(`
		WITH matched AS (
			SELECT %[1]s, %[2]s
			FROM messages m
			LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
			WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL AND (%[3]s) AND (%[4]s)
			UNION
			SELECT %[1]s, %[2]s
			FROM messages m
			LEFT JOIN messages_fts mc ON m.content_hash = mc.content_hash
			LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
			WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL AND (%[3]s) AND (%[5]s)
		)
		SELECT %[6]s
		FROM matched f
		%[7]s
		%[8]s`,
		branchSelect, sortColumns, baseCond, headerCond, bodyCond, outerSelect, outerOrder, limitClause)

	return query, args, nil
}

// paramPrefix is the named-argument prefix used across the search query builders.
const paramPrefix = "p"

// resolveResultLimit selects the row cap for a search query. It must be called
// AFTER any seqnum→UID rewrite so that isComplexQuery reflects the final query
// shape: a search that was only "complex" because of sequence-number criteria is
// downgraded to a simple query and therefore earns the higher simple-query limit.
func resolveResultLimit(explicitLimit int, isSearchAll, isComplexQuery bool, orderByClause string) int {
	if explicitLimit > 0 {
		// Caller specified an explicit limit - use it
		return explicitLimit
	}
	if isSearchAll {
		// SEARCH ALL should return all messages to avoid breaking clients like imapsync.
		// This is safe because SEARCH only returns UIDs/sequence numbers (4 bytes each);
		// even 1 million messages would only be ~4MB of UIDs.
		return 0 // No limit for SEARCH ALL
	}
	if isComplexQuery {
		// Complex queries (CTE, JSONB sorting) get lower limits due to processing overhead
		lower := strings.ToLower(orderByClause)
		if strings.Contains(lower, "coalesce(") || strings.Contains(lower, "jsonb_array_elements") {
			return MaxComplexSortResults // 500 for expensive JSONB sorting
		}
		return MaxSearchResults // 100k for other complex queries (FTS, sequence)
	}
	return MaxSearchResults // 100k for simple queries - reasonable for IMAP clients
}

// getMessagesQueryExecutor is a helper function to execute the message retrieval query,
// handling both default and custom sorting with optimized query selection.
func (db *Database) getMessagesQueryExecutor(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, orderByClause string, limit int) ([]Message, error) {
	if err := db.canonicalizeSearchCriteriaKeywords(ctx, nil, mailboxID, criteria); err != nil {
		return nil, err
	}
	paramCounter := 0

	var finalQueryString string
	var metricsLabel string
	var resultLimit int
	var whereCondition string
	var whereArgs pgx.NamedArgs
	var err error

	// Determine query complexity up front. This may be refined below: a
	// seqnum→UID rewrite can downgrade an otherwise-complex query to a simple
	// one, so the result limit is computed afterwards from the final value.
	isComplexQuery := db.needsComplexQuery(criteria, orderByClause)
	isSearchAll := isCriteriaSearchAll(criteria)

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
			isComplexQuery = db.needsComplexQuery(criteria, orderByClause)
		}
	}

	// Determine the result limit from the final query complexity (after any
	// seqnum→UID rewrite above may have downgraded a complex query to simple).
	resultLimit = resolveResultLimit(limit, isSearchAll, isComplexQuery, orderByClause)

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

		// Dynamic sequence optimization: Sequence numbers are computed natively downstream
		// via db.HydrateMessageSequences in Go, completely bypassing Postgres' O(N^2) constraints.
		simpleQueryTemplate := `
			WITH filtered_messages AS (
				SELECT
					m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, COALESCE(ms.flags, 0) as flags, COALESCE(ms.custom_flags, '[]'::jsonb) as custom_flags,
					m.internal_date, m.size, m.created_modseq, ms.updated_modseq, m.expunged_modseq,
					ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json,
					m.subject_sort, m.from_name_sort, m.from_email_sort, m.to_name_sort, m.to_email_sort, m.cc_email_sort
				FROM messages m
				LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
				WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL AND (%s)
				%s
				LIMIT %d
			)
			SELECT
				f.id, f.account_id, f.uid, f.mailbox_id, f.content_hash, f.s3_domain, f.s3_localpart, f.uploaded, f.flags, f.custom_flags,
				f.internal_date, f.size, f.created_modseq, f.updated_modseq, f.expunged_modseq,
				0 as seqnum,
				f.flags_changed_at, f.subject, f.sent_date, f.message_id, f.in_reply_to, f.recipients_json
			FROM filtered_messages f
			%s`

		// Neutralize the "Limit + Order By" backward index scan bias for non-FTS queries.
		// A memory sort of a single mailbox's rows takes <30ms, but streaming the mailbox
		// backward to find a massive needle-in-haystack (e.g. Header searches) times out at 5s.
		innerOrderByClause := orderByClause
		if db.needsIndexScanBiasBuster(criteria) {
			innerOrderByClause = strings.ReplaceAll(orderByClause, "ORDER BY m.uid", "ORDER BY m.uid + 0")
			if innerOrderByClause == orderByClause {
				innerOrderByClause = strings.ReplaceAll(orderByClause, "ORDER BY uid", "ORDER BY uid + 0")
			}
		}

		// Note: The ordering clause uses "m." prefix initially, but we need it to use "f." for the outer query
		outerOrderByClause := strings.ReplaceAll(orderByClause, "m.", "f.")
		if resultLimit > 0 {
			finalQueryString = fmt.Sprintf(simpleQueryTemplate, whereCondition, innerOrderByClause, resultLimit, outerOrderByClause)
		} else {
			// No limit for SEARCH ALL - build query without LIMIT clause
			// Note: This template needs special handling for the CTE structure
			noLimitTemplate := strings.Replace(simpleQueryTemplate, "LIMIT %d", "", 1)
			// The simple template uses 4 parameters (whereCondition, innerOrderByClause, resultLimit, outerOrderByClause)
			// After removing LIMIT, we need only 3 parameters
			finalQueryString = fmt.Sprintf(noLimitTemplate, whereCondition, innerOrderByClause, outerOrderByClause)
		}
		metricsLabel = "search_messages_simple"

	} else if db.canUseTextUnion(criteria, needsSeqNumSearch, orderByClause) {
		// TEXT UNION path: split the single mixed-table TEXT OR into an indexable
		// header branch (trigram indexes on messages) UNION an indexable body branch
		// (FTS GIN on messages_fts), avoiding the full-mailbox-scan + per-row probe the
		// combined OR forces on large mailboxes. See canUseTextUnion.
		const branchSelect = `m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, COALESCE(ms.flags, 0) as flags, COALESCE(ms.custom_flags, '[]'::jsonb) as custom_flags,
			m.internal_date, m.size, m.created_modseq, ms.updated_modseq, m.expunged_modseq,
			ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json`
		const outerSelect = `f.id, f.account_id, f.uid, f.mailbox_id, f.content_hash, f.s3_domain, f.s3_localpart, f.uploaded, f.flags, f.custom_flags,
			f.internal_date, f.size, f.created_modseq, f.updated_modseq, f.expunged_modseq,
			0 as seqnum,
			f.flags_changed_at, f.subject, f.sent_date, f.message_id, f.in_reply_to, f.recipients_json`
		finalQueryString, whereArgs, err = db.buildTextUnionQuery(criteria, mailboxID, branchSelect, textUnionSortColumnsFull, outerSelect, orderByClause, resultLimit, &paramCounter)
		if err != nil {
			return nil, err
		}
		metricsLabel = "search_messages_complex_text_union"

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

		// Dynamic sequence optimization: Sequence numbers are computed natively downstream
		// via db.HydrateMessageSequences in Go, completely bypassing Postgres' O(N^2) constraints.
		complexQueryTemplate := `
			WITH filtered_messages AS (
				SELECT
					m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, COALESCE(ms.flags, 0) as flags, COALESCE(ms.custom_flags, '[]'::jsonb) as custom_flags,
					m.internal_date, m.size, m.created_modseq, ms.updated_modseq, m.expunged_modseq,
					ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json,
					m.subject_sort, m.from_name_sort, m.from_email_sort, m.to_name_sort, m.to_email_sort, m.cc_email_sort
				FROM messages m
				LEFT JOIN messages_fts mc ON m.content_hash = mc.content_hash
				LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
				WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL AND (%s)
				%s
				LIMIT %d
			)
			SELECT
				f.id, f.account_id, f.uid, f.mailbox_id, f.content_hash, f.s3_domain, f.s3_localpart, f.uploaded, f.flags, f.custom_flags,
				f.internal_date, f.size, f.created_modseq, f.updated_modseq, f.expunged_modseq,
				0 as seqnum,
				f.flags_changed_at, f.subject, f.sent_date, f.message_id, f.in_reply_to, f.recipients_json
			FROM filtered_messages f
			%s`

		innerOrderByClause := orderByClause
		if db.needsIndexScanBiasBuster(criteria) {
			innerOrderByClause = strings.ReplaceAll(orderByClause, "ORDER BY m.uid", "ORDER BY m.uid + 0")
			if innerOrderByClause == orderByClause {
				innerOrderByClause = strings.ReplaceAll(orderByClause, "ORDER BY uid", "ORDER BY uid + 0")
			}
		}

		outerOrderByClause := strings.ReplaceAll(orderByClause, "m.", "f.")
		if resultLimit > 0 {
			finalQueryString = fmt.Sprintf(complexQueryTemplate, whereCondition, innerOrderByClause, resultLimit, outerOrderByClause)
		} else {
			// No limit for SEARCH ALL - remove the LIMIT clause from template
			noLimitTemplate := strings.Replace(complexQueryTemplate, "LIMIT %d", "", 1)
			finalQueryString = fmt.Sprintf(noLimitTemplate, whereCondition, innerOrderByClause, outerOrderByClause)
		}
		metricsLabel = "search_messages_complex_fast"

	} else {
		// Legacy Complex path: Use CTE with empty table prefix because SeqNum filtering REQUIRES evaluating Sequence IDs BEFORE where
		whereCondition, whereArgs, err = db.buildSearchCriteriaWithPrefix(criteria, "p", &paramCounter, "")
		if err != nil {
			return nil, err
		}
		whereArgs["mailboxID"] = mailboxID

		if orderByClause == "" {
			// The legacy CTE path's outer query joins message_seqs (seq.uid) and
			// messages (m.uid), so the default ORDER BY must qualify uid as m.uid to
			// avoid an ambiguous column reference (SQLSTATE 42702).
			orderByClause = "ORDER BY m.uid DESC"
		}

		const complexQuery = `
		WITH message_seqs AS (
			SELECT
				m.id, m.uid,
				ROW_NUMBER() OVER(ORDER BY uid) as seqnum
			FROM messages m
			WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL
		)
		SELECT 
			m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart, m.uploaded, COALESCE(ms.flags, 0) as flags, COALESCE(ms.custom_flags, '[]'::jsonb) as custom_flags,
			m.internal_date, m.size, m.created_modseq, ms.updated_modseq, m.expunged_modseq, seq.seqnum,
			ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
		FROM message_seqs seq
		INNER JOIN messages m ON m.id = seq.id
		LEFT JOIN messages_fts mc ON m.content_hash = mc.content_hash
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id`

		innerOrderByClause := orderByClause
		if db.needsIndexScanBiasBuster(criteria) {
			innerOrderByClause = strings.ReplaceAll(orderByClause, "ORDER BY m.uid", "ORDER BY m.uid + 0")
			if innerOrderByClause == orderByClause {
				innerOrderByClause = strings.ReplaceAll(orderByClause, "ORDER BY uid", "ORDER BY uid + 0")
			}
		}
		if resultLimit > 0 {
			finalQueryString = fmt.Sprintf("%s WHERE %s %s LIMIT %d", complexQuery, whereCondition, innerOrderByClause, resultLimit)
		} else {
			// No limit for SEARCH ALL
			finalQueryString = fmt.Sprintf("%s WHERE %s %s", complexQuery, whereCondition, innerOrderByClause)
		}
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
		logger.Error("Database: failed executing query", "query", finalQueryString, "args", whereArgs, "err", err, "duration", time.Since(start))
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	scanStart := time.Now()
	messages, err := scanMessages(rows, false)
	scanDuration := time.Since(scanStart)
	if err != nil {
		logger.Error("Database: failed scanning messages", "err", err, "scan_duration", scanDuration, "query_duration", time.Since(start), "mailbox_id", mailboxID, "query", finalQueryString, "args", whereArgs)
		return nil, fmt.Errorf("getMessagesQueryExecutor: failed to scan messages: %w", err)
	}
	if scanDuration > 5*time.Second {
		logger.Warn("Database: slow message scan detected", "scan_duration", scanDuration, "row_count", len(messages), "mailbox_id", mailboxID, "query_type", metricsLabel, "query", finalQueryString, "args", whereArgs)
	}

	// Dynamic sequence hydration (O(1) mapped iteration rather than PostgreSQL quadratic windowing)
	if len(messages) > 0 {
		if err := db.HydrateMessageSequences(ctx, mailboxID, messages); err != nil {
			return nil, fmt.Errorf("failed to hydrate sequences dynamically: %w", err)
		}
	}

	// Log warning if we hit the default result limit (may indicate client needs to refine search)
	// Don't warn if caller explicitly requested this limit (limit > 0) or if it's SEARCH ALL (resultLimit == 0)
	if limit == 0 && resultLimit > 0 && len(messages) >= resultLimit {
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
	// Every query path in getMessagesQueryExecutor aliases the messages table as
	// "m". The complex paths additionally LEFT JOIN messages_fts (which also has a
	// sent_date column) and the seqnum CTE joins message_seqs (which also has uid),
	// so an unqualified ORDER BY column would be ambiguous (SQLSTATE 42702). Always
	// qualify sort columns with "m.".
	orderBy := db.buildSortOrderClauseWithPrefix(sortCriteria, "m")

	messages, err := db.getMessagesQueryExecutor(ctx, mailboxID, criteria, orderBy, limit)
	if err != nil {
		// The error from getMessagesQueryExecutor will be wrapped here
		return nil, fmt.Errorf("GetMessagesSorted: %w", err)
	}
	return messages, nil
}

func (db *Database) getSearchMessagesQueryExecutor(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, orderByClause string, limit int) ([]SearchMessageResult, error) {
	if err := db.canonicalizeSearchCriteriaKeywords(ctx, nil, mailboxID, criteria); err != nil {
		return nil, err
	}
	paramCounter := 0

	var finalQueryString string
	var metricsLabel string
	var resultLimit int
	var whereCondition string
	var whereArgs pgx.NamedArgs
	var err error

	// Determine query complexity up front. This may be refined below: a
	// seqnum→UID rewrite can downgrade an otherwise-complex query to a simple
	// one, so the result limit is computed afterwards from the final value.
	isComplexQuery := db.needsComplexQuery(criteria, orderByClause)
	isSearchAll := isCriteriaSearchAll(criteria)

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
			isComplexQuery = db.needsComplexQuery(criteria, orderByClause)
		}
	}

	// Determine the result limit from the final query complexity (after any
	// seqnum→UID rewrite above may have downgraded a complex query to simple).
	resultLimit = resolveResultLimit(limit, isSearchAll, isComplexQuery, orderByClause)

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

		// Dynamic sequence optimization: Sequence numbers are computed natively downstream
		// via db.HydrateSearchMessageSequences in Go, completely bypassing Postgres' O(N^2) constraints.
		simpleQueryTemplate := `
				SELECT
					m.id, m.uid, m.mailbox_id, m.content_hash, m.created_modseq, ms.updated_modseq, m.expunged_modseq, 0 as seqnum
				FROM messages m
				LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
				WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL AND (%s)
				%s
				LIMIT %d`

		// Neutralize the "Limit + Order By" backward index scan bias for non-FTS queries.
		// A memory sort of a single mailbox's rows takes <30ms, but streaming the mailbox
		// backward to find a massive needle-in-haystack (e.g. Header searches) times out at 5s.
		innerOrderByClause := orderByClause
		if db.needsIndexScanBiasBuster(criteria) {
			innerOrderByClause = strings.ReplaceAll(orderByClause, "ORDER BY m.uid", "ORDER BY m.uid + 0")
			if innerOrderByClause == orderByClause {
				innerOrderByClause = strings.ReplaceAll(orderByClause, "ORDER BY uid", "ORDER BY uid + 0")
			}
		}

		if resultLimit > 0 {
			finalQueryString = fmt.Sprintf(simpleQueryTemplate, whereCondition, innerOrderByClause, resultLimit)
		} else {
			// No limit for SEARCH ALL - build query without LIMIT clause
			noLimitTemplate := `
				SELECT
					m.id, m.uid, m.mailbox_id, m.content_hash, m.created_modseq, ms.updated_modseq, m.expunged_modseq, 0 as seqnum
				FROM messages m
				LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
				WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL AND (%s)
				%s`
			finalQueryString = fmt.Sprintf(noLimitTemplate, whereCondition, innerOrderByClause)
		}
		metricsLabel = "search_messages_simple"

	} else if db.canUseTextUnion(criteria, needsSeqNumSearch, orderByClause) {
		// TEXT UNION path (lightweight columns): see canUseTextUnion and the matching
		// branch in getMessagesQueryExecutor.
		const branchSelect = `m.id, m.uid, m.mailbox_id, m.content_hash, m.created_modseq, ms.updated_modseq, m.expunged_modseq`
		const outerSelect = `f.id, f.uid, f.mailbox_id, f.content_hash, f.created_modseq, f.updated_modseq, f.expunged_modseq, 0 as seqnum`
		finalQueryString, whereArgs, err = db.buildTextUnionQuery(criteria, mailboxID, branchSelect, textUnionSortColumnsLight, outerSelect, orderByClause, resultLimit, &paramCounter)
		if err != nil {
			return nil, err
		}
		metricsLabel = "search_messages_complex_text_union"

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

		// Dynamic sequence optimization: Sequence numbers are computed natively downstream
		// via db.HydrateSearchMessageSequences in Go, completely bypassing Postgres' O(N^2) constraints.
		complexQueryTemplate := `
				SELECT
					m.id, m.uid, m.mailbox_id, m.content_hash, m.created_modseq, ms.updated_modseq, m.expunged_modseq, 0 as seqnum
				FROM messages m
				LEFT JOIN messages_fts mc ON m.content_hash = mc.content_hash
				LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
				WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL AND (%s)
				%s
				LIMIT %d`

		innerOrderByClause := orderByClause
		if db.needsIndexScanBiasBuster(criteria) {
			innerOrderByClause = strings.ReplaceAll(orderByClause, "ORDER BY m.uid", "ORDER BY m.uid + 0")
			if innerOrderByClause == orderByClause {
				innerOrderByClause = strings.ReplaceAll(orderByClause, "ORDER BY uid", "ORDER BY uid + 0")
			}
		}

		if resultLimit > 0 {
			finalQueryString = fmt.Sprintf(complexQueryTemplate, whereCondition, innerOrderByClause, resultLimit)
		} else {
			// No limit for SEARCH ALL - build query without LIMIT clause
			noLimitTemplate := `
				SELECT
					m.id, m.uid, m.mailbox_id, m.content_hash, m.created_modseq, ms.updated_modseq, m.expunged_modseq, 0 as seqnum
				FROM messages m
				LEFT JOIN messages_fts mc ON m.content_hash = mc.content_hash
				LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
				WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL AND (%s)
				%s`
			finalQueryString = fmt.Sprintf(noLimitTemplate, whereCondition, innerOrderByClause)
		}
		metricsLabel = "search_messages_complex_fast"

	} else {
		// Legacy Complex path: Use CTE with empty table prefix because SeqNum filtering REQUIRES evaluating Sequence IDs BEFORE where
		whereCondition, whereArgs, err = db.buildSearchCriteriaWithPrefix(criteria, "p", &paramCounter, "")
		if err != nil {
			return nil, err
		}
		whereArgs["mailboxID"] = mailboxID

		if orderByClause == "" {
			// The legacy CTE path's outer query joins message_seqs (seq.uid) and
			// messages (m.uid), so the default ORDER BY must qualify uid as m.uid to
			// avoid an ambiguous column reference (SQLSTATE 42702).
			orderByClause = "ORDER BY m.uid DESC"
		}

		const complexQuery = `
		WITH message_seqs AS (
			SELECT
				m.id, m.uid,
				ROW_NUMBER() OVER(ORDER BY uid) as seqnum
			FROM messages m
			WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL
		)
		SELECT 
			m.id, m.uid, m.mailbox_id, m.content_hash, m.created_modseq, ms.updated_modseq, m.expunged_modseq, seq.seqnum
		FROM message_seqs seq
		INNER JOIN messages m ON m.id = seq.id
		LEFT JOIN messages_fts mc ON m.content_hash = mc.content_hash
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id`

		innerOrderByClause := orderByClause
		if db.needsIndexScanBiasBuster(criteria) {
			innerOrderByClause = strings.ReplaceAll(orderByClause, "ORDER BY m.uid", "ORDER BY m.uid + 0")
			if innerOrderByClause == orderByClause {
				innerOrderByClause = strings.ReplaceAll(orderByClause, "ORDER BY uid", "ORDER BY uid + 0")
			}
		}
		if resultLimit > 0 {
			finalQueryString = fmt.Sprintf("%s WHERE %s %s LIMIT %d", complexQuery, whereCondition, innerOrderByClause, resultLimit)
		} else {
			// No limit for SEARCH ALL
			finalQueryString = fmt.Sprintf("%s WHERE %s %s", complexQuery, whereCondition, innerOrderByClause)
		}
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
		logger.Error("Database: failed executing query", "query", finalQueryString, "args", whereArgs, "err", err, "duration", time.Since(start))
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	scanStart := time.Now()
	messages, err := scanSearchMessages(rows)
	scanDuration := time.Since(scanStart)
	if err != nil {
		logger.Error("Database: failed scanning messages", "err", err, "scan_duration", scanDuration, "query_duration", time.Since(start), "mailbox_id", mailboxID, "query", finalQueryString, "args", whereArgs)
		return nil, fmt.Errorf("getMessagesQueryExecutor: failed to scan messages: %w", err)
	}
	if scanDuration > 5*time.Second {
		logger.Warn("Database: slow message scan detected", "scan_duration", scanDuration, "row_count", len(messages), "mailbox_id", mailboxID, "query_type", metricsLabel, "query", finalQueryString, "args", whereArgs)
	}

	// Dynamic sequence hydration (O(1) mapped iteration rather than PostgreSQL quadratic windowing)
	if len(messages) > 0 {
		if err := db.HydrateSearchMessageSequences(ctx, mailboxID, messages); err != nil {
			return nil, fmt.Errorf("failed to hydrate sequences dynamically: %w", err)
		}
	}

	// Log warning if we hit the default result limit (may indicate client needs to refine search)
	// Don't warn if caller explicitly requested this limit (limit > 0) or if it's SEARCH ALL (resultLimit == 0)
	if limit == 0 && resultLimit > 0 && len(messages) >= resultLimit {
		logger.Warn("Database: search query hit result limit", "limit", resultLimit, "mailbox_id", mailboxID, "complex", isComplexQuery, "message", "Client may need to use more specific search criteria")
	}

	return messages, nil
}

// SearchMessagesWithCriteria retrieves only lightweight message metadata needed for IMAP SEARCH requests.
func (db *Database) SearchMessagesWithCriteria(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, limit int) ([]SearchMessageResult, error) {
	messages, err := db.getSearchMessagesQueryExecutor(ctx, mailboxID, criteria, "", limit) // Empty string triggers default sort
	if err != nil {
		return nil, fmt.Errorf("SearchMessagesWithCriteria: %w", err)
	}
	return messages, nil
}

// SearchMessagesSorted retrieves lightweight message metadata that matches the search criteria, sorted.
func (db *Database) SearchMessagesSorted(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, sortCriteria []imap.SortCriterion, limit int) ([]SearchMessageResult, error) {
	// Every query path in getSearchMessagesQueryExecutor aliases the messages table
	// as "m". The complex paths additionally LEFT JOIN messages_fts (which also has
	// a sent_date column) and the seqnum CTE joins message_seqs (which also has
	// uid), so an unqualified ORDER BY column would be ambiguous (SQLSTATE 42702).
	// Always qualify sort columns with "m.".
	orderBy := db.buildSortOrderClauseWithPrefix(sortCriteria, "m")

	messages, err := db.getSearchMessagesQueryExecutor(ctx, mailboxID, criteria, orderBy, limit)
	if err != nil {
		return nil, fmt.Errorf("SearchMessagesSorted: %w", err)
	}
	return messages, nil
}

// canonicalizeSearchCriteriaKeywords folds keywords in criteria.Flag and criteria.NotFlag
// (including nested Not and Or search criteria) onto the canonical case established for the mailbox.
func (db *Database) canonicalizeSearchCriteriaKeywords(ctx context.Context, tx pgx.Tx, mailboxID int64, criteria *imap.SearchCriteria) error {
	if criteria == nil {
		return nil
	}

	// Read canonical map once if there are any custom flags in this criteria tree.
	var checkCustomFlags func(*imap.SearchCriteria) bool
	checkCustomFlags = func(c *imap.SearchCriteria) bool {
		if c == nil {
			return false
		}
		for _, f := range c.Flag {
			if FlagToBitwise(f) == 0 {
				return true
			}
		}
		for _, f := range c.NotFlag {
			if FlagToBitwise(f) == 0 {
				return true
			}
		}
		for i := range c.Not {
			if checkCustomFlags(&c.Not[i]) {
				return true
			}
		}
		for i := range c.Or {
			if checkCustomFlags(&c.Or[i][0]) || checkCustomFlags(&c.Or[i][1]) {
				return true
			}
		}
		return false
	}

	if !checkCustomFlags(criteria) {
		return nil
	}

	canonical, err := db.mailboxKeywordCanonicalMap(ctx, tx, mailboxID)
	if err != nil {
		return err
	}

	var rewrite func(*imap.SearchCriteria)
	rewrite = func(c *imap.SearchCriteria) {
		if c == nil {
			return
		}
		for i, f := range c.Flag {
			if FlagToBitwise(f) == 0 {
				key := foldKeyword(string(f))
				if canon, ok := canonical[key]; ok {
					c.Flag[i] = imap.Flag(canon)
				}
			}
		}
		for i, f := range c.NotFlag {
			if FlagToBitwise(f) == 0 {
				key := foldKeyword(string(f))
				if canon, ok := canonical[key]; ok {
					c.NotFlag[i] = imap.Flag(canon)
				}
			}
		}
		for i := range c.Not {
			rewrite(&c.Not[i])
		}
		for i := range c.Or {
			rewrite(&c.Or[i][0])
			rewrite(&c.Or[i][1])
		}
	}

	rewrite(criteria)
	return nil
}
