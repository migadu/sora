package db

import (
	"context"
	"fmt"
	"log"
	"maps"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
)

// buildSearchCriteria builds the SQL WHERE clause for the search criteria
func (db *Database) buildSearchCriteria(criteria *imap.SearchCriteria, paramPrefix string, paramCounter *int) (string, pgx.NamedArgs, error) {
	var conditions []string
	args := pgx.NamedArgs{}

	nextParam := func() string {
		*paramCounter++
		return fmt.Sprintf("%s%d", paramPrefix, *paramCounter)
	}

	// For SeqNum
	for _, seqSet := range criteria.SeqNum {
		seqCond, seqArgs := buildNumSetCondition(seqSet, "seqnum", paramPrefix, paramCounter)
		maps.Copy(args, seqArgs)
		conditions = append(conditions, seqCond)
	}

	// For UID
	for _, uidSet := range criteria.UID {
		uidCond, uidArgs := buildNumSetCondition(uidSet, "uid", paramPrefix, paramCounter)
		maps.Copy(args, uidArgs)
		conditions = append(conditions, uidCond)
	}

	// Date filters
	if !criteria.Since.IsZero() {
		param := nextParam()
		args[param] = criteria.Since
		conditions = append(conditions, fmt.Sprintf("internal_date >= @%s", param))
	}
	if !criteria.Before.IsZero() {
		param := nextParam()
		args[param] = criteria.Before
		conditions = append(conditions, fmt.Sprintf("internal_date <= @%s", param))
	}
	if !criteria.SentSince.IsZero() {
		param := nextParam()
		args[param] = criteria.SentSince
		conditions = append(conditions, fmt.Sprintf("sent_date >= @%s", param))
	}
	if !criteria.SentBefore.IsZero() {
		param := nextParam()
		args[param] = criteria.SentBefore
		conditions = append(conditions, fmt.Sprintf("sent_date <= @%s", param))
	}

	// Message size
	if criteria.Larger > 0 {
		param := nextParam()
		args[param] = criteria.Larger
		conditions = append(conditions, fmt.Sprintf("size > @%s", param))
	}
	if criteria.Smaller > 0 {
		param := nextParam()
		args[param] = criteria.Smaller
		conditions = append(conditions, fmt.Sprintf("size < @%s", param))
	}

	// Body full-text search
	for _, bodyCriteria := range criteria.Body {
		param := nextParam()
		args[param] = bodyCriteria
		conditions = append(conditions, fmt.Sprintf("text_body_tsv @@ plainto_tsquery('simple', @%s)", param))
	}
	if len(criteria.Text) > 0 {
		return "", nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "SEARCH criteria TEXT is not supported",
		}
	}

	// Flags
	for _, flag := range criteria.Flag {
		param := nextParam()
		args[param] = FlagToBitwise(flag)
		conditions = append(conditions, fmt.Sprintf("(flags & @%s) != 0", param))
	}
	for _, flag := range criteria.NotFlag {
		param := nextParam()
		args[param] = FlagToBitwise(flag)
		conditions = append(conditions, fmt.Sprintf("(flags & @%s) = 0", param))
	}

	// Header conditions
	for _, header := range criteria.Header {
		lowerValue := strings.ToLower(header.Value)
		lowerKey := strings.ToLower(header.Key)
		switch lowerKey {
		case "subject":
			param := nextParam()
			args[param] = "%" + lowerValue + "%"
			conditions = append(conditions, fmt.Sprintf("LOWER(subject) LIKE @%s", param))
		case "message-id":
			param := nextParam()
			// if the message ID is wrapped in <messageId>, we need to remove the brackets
			if strings.HasPrefix(lowerValue, "<") && strings.HasSuffix(lowerValue, ">") {
				lowerValue = lowerValue[1 : len(lowerValue)-1]
			}
			args[param] = lowerValue
			conditions = append(conditions, fmt.Sprintf("LOWER(message_id) = @%s", param))
		case "in-reply-to":
			param := nextParam()
			args[param] = lowerValue
			conditions = append(conditions, fmt.Sprintf("LOWER(in_reply_to) = @%s", param))
		case "from", "to", "cc", "bcc", "reply-to":
			recipientJSONParam := nextParam()
			recipientValue := fmt.Sprintf(`[{"type": "%s", "email": "%s"}]`, lowerKey, lowerValue)
			args[recipientJSONParam] = recipientValue
			conditions = append(conditions, fmt.Sprintf(`recipients_json @> @%s::jsonb`, recipientJSONParam))
		default:
			return "", nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Text: "SEARCH criteria generic HEADER is not supported",
			}
		}
	}

	// Recursive NOT
	for _, notCriteria := range criteria.Not {
		subCond, subArgs, err := db.buildSearchCriteria(&notCriteria, paramPrefix, paramCounter)
		if err != nil {
			return "", nil, err
		}
		for k, v := range subArgs {
			args[k] = v
		}
		conditions = append(conditions, fmt.Sprintf("NOT (%s)", subCond))
	}

	// Recursive OR
	for _, orPair := range criteria.Or {
		leftCond, leftArgs, err := db.buildSearchCriteria(&orPair[0], paramPrefix, paramCounter)
		if err != nil {
			return "", nil, err
		}
		rightCond, rightArgs, err := db.buildSearchCriteria(&orPair[1], paramPrefix, paramCounter)
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

func buildNumSetCondition(numSet imap.NumSet, columnName string, paramPrefix string, paramCounter *int) (string, pgx.NamedArgs) {
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
				args[stopParam] = r.Stop
				conditions = append(conditions, fmt.Sprintf("%s BETWEEN @%s AND @%s", columnName, startParam, stopParam))
			}
		}
	default:
		panic("unsupported NumSet type")
	}

	finalCondition := strings.Join(conditions, " OR ")
	if len(conditions) > 1 {
		finalCondition = "(" + finalCondition + ")"
	}

	return finalCondition, args
}

func (db *Database) GetMessagesWithCriteria(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria) ([]Message, error) {
	baseQuery := `
	WITH message_seqs AS (
		SELECT
			uid,
			ROW_NUMBER() OVER (ORDER BY uid) AS seqnum, -- id is needed for ordering/seqnum
			account_id, mailbox_id, m.content_hash, uploaded, flags, custom_flags,
			internal_date, size, body_structure,
			created_modseq, updated_modseq, expunged_modseq,
			subject,
			sent_date,
			message_id,
			in_reply_to,
			recipients_json,
			mc.text_body_tsv -- Select from message_contents
		FROM messages m
		LEFT JOIN message_contents mc ON m.content_hash = mc.content_hash
		WHERE m.mailbox_id = @mailboxID AND m.expunged_at IS NULL
	)
	SELECT 
		account_id, uid, mailbox_id, content_hash, uploaded, flags, custom_flags,
		internal_date, size, body_structure,
		created_modseq, updated_modseq, expunged_modseq, seqnum
	FROM message_seqs`

	paramCounter := 0
	whereCondition, whereArgs, err := db.buildSearchCriteria(criteria, "p", &paramCounter)
	if err != nil {
		return nil, err
	}
	whereArgs["mailboxID"] = mailboxID

	finalQueryString := baseQuery + fmt.Sprintf(" WHERE %s ORDER BY uid", whereCondition)

	rows, err := db.Pool.Query(ctx, finalQueryString, whereArgs)
	if err != nil {
		// It's helpful to log the query and arguments when an error occurs for easier debugging.
		log.Printf("Error executing query: %s\nArgs: %#v\nError: %v", finalQueryString, whereArgs, err)
		return nil, err
	}
	defer rows.Close()

	messages, err := scanMessages(rows)
	if err != nil {
		return nil, fmt.Errorf("GetMessagesWithCriteria: failed to scan messages: %w", err)
	}
	return messages, nil
}
