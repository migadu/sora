package db

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// TestSearchNegatedFlagsMatchMessageWithoutState covers #1899: a message with no
// message_state row (left by older builds) has no flags and no keywords, so every
// negated flag criterion (UNSEEN, NOT SEEN, UNKEYWORD, NOT KEYWORD, ...) must match it
// and every positive one must not. A bare (ms.flags & N) = 0 over the LEFT JOIN is NULL
// for such a row and silently dropped it. SORT and THREAD build their WHERE clause with
// the same builder, so they are checked too.
func TestSearchNegatedFlagsMatchMessageWithoutState(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	now := time.Now()

	const keyword = "$Label1"
	insert := func(uid uint32, flags []imap.Flag) int64 {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		subject := fmt.Sprintf("Stateless %d", uid)
		msg := "From: a@example.com\r\nTo: b@example.com\r\nSubject: " + subject + "\r\n\r\nBody\r\n"
		id, _, err := db.InsertMessageFromImporter(ctx, tx, &InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailboxID,
			MailboxName:   "INBOX",
			Flags:         flags,
			PreservedUID:  &uid,
			InternalDate:  now,
			SentDate:      now,
			Subject:       subject,
			MessageID:     fmt.Sprintf("<stateless-%d@example.com>", uid),
			Size:          int64(len(msg)),
			PlaintextBody: msg,
		})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return id
	}

	// UID 1 has no message_state row; UID 2 carries every flag and the keyword, so
	// it must be left out of every negated search and match every positive one.
	stateless := insert(1, nil)
	insert(2, []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft, keyword})
	_, err := db.GetWritePool().Exec(ctx, `DELETE FROM message_state WHERE message_id = $1`, stateless)
	require.NoError(t, err)

	not := func(c imap.SearchCriteria) imap.SearchCriteria {
		return imap.SearchCriteria{Not: []imap.SearchCriteria{c}}
	}
	or := func(a, b imap.SearchCriteria) imap.SearchCriteria {
		return imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{a, b}}}
	}
	flag := func(f imap.Flag) imap.SearchCriteria { return imap.SearchCriteria{Flag: []imap.Flag{f}} }
	notFlag := func(f imap.Flag) imap.SearchCriteria { return imap.SearchCriteria{NotFlag: []imap.Flag{f}} }

	cases := []struct {
		name     string
		criteria imap.SearchCriteria
		want     []imap.UID
	}{
		{"UNSEEN", notFlag(imap.FlagSeen), []imap.UID{1}},
		{"UNANSWERED", notFlag(imap.FlagAnswered), []imap.UID{1}},
		{"UNFLAGGED", notFlag(imap.FlagFlagged), []imap.UID{1}},
		{"UNDELETED", notFlag(imap.FlagDeleted), []imap.UID{1}},
		{"UNDRAFT", notFlag(imap.FlagDraft), []imap.UID{1}},
		{"UNKEYWORD", notFlag(keyword), []imap.UID{1}},
		{"NOT SEEN", not(flag(imap.FlagSeen)), []imap.UID{1}},
		{"NOT KEYWORD", not(flag(keyword)), []imap.UID{1}},
		{"NOT (OR SEEN KEYWORD)", not(or(flag(imap.FlagSeen), flag(keyword))), []imap.UID{1}},
		{"NOT NOT UNSEEN", not(not(notFlag(imap.FlagSeen))), []imap.UID{1}},
		{"SEEN", flag(imap.FlagSeen), []imap.UID{2}},
		{"KEYWORD", flag(keyword), []imap.UID{2}},
		{"NOT UNSEEN", not(notFlag(imap.FlagSeen)), []imap.UID{2}},
		{"NOT UNKEYWORD", not(notFlag(keyword)), []imap.UID{2}},
	}

	uids := func(t *testing.T, got []SearchMessageResult) []imap.UID {
		t.Helper()
		out := make([]imap.UID, 0, len(got))
		for _, m := range got {
			out = append(out, m.UID)
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			criteria := tc.criteria
			got, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, &criteria, 0, 0)
			require.NoError(t, err)
			require.Equal(t, tc.want, uids(t, got), "SEARCH %s", tc.name)

			criteria = tc.criteria
			sorted, err := db.SearchMessagesSorted(ctx, mailboxID, accountID, &criteria,
				[]imap.SortCriterion{{Key: imap.SortKeyArrival}}, 0, 0)
			require.NoError(t, err)
			require.Equal(t, tc.want, uids(t, sorted), "SORT %s", tc.name)

			criteria = tc.criteria
			threaded, err := db.GetMessagesForThreading(ctx, mailboxID, accountID, &criteria, true, false, 0)
			require.NoError(t, err)
			threadUIDs := make([]imap.UID, 0, len(threaded))
			for _, m := range threaded {
				threadUIDs = append(threadUIDs, m.UID)
			}
			sort.Slice(threadUIDs, func(i, j int) bool { return threadUIDs[i] < threadUIDs[j] })
			require.Equal(t, tc.want, threadUIDs, "THREAD %s", tc.name)
		})
	}
}
