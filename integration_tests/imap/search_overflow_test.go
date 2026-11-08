//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// A default database row cap must never turn an incomplete search into OK.
// Exercise the real cap and wire handlers: exactly the cap succeeds, one more
// match is refused, and an explicit caller limit still means a bounded page.
func TestIMAP_SearchOverflowIsLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()
	c := dialRawIMAP(t, srv.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	c.do("CREATE Overflow")
	c.appendMsg("Overflow", "From: sender@example.com\r\nSubject: match\r\n\r\nbody\r\n")
	ctx := context.Background()
	database := srv.ResilientDB.GetDatabase()
	var mailboxID, accountID int64
	require.NoError(t, database.GetWritePool().QueryRow(ctx, `
		SELECT m.id, m.account_id FROM mailboxes m JOIN credentials c ON c.account_id = m.account_id
		WHERE m.name = 'Overflow' AND c.address = $1`, account.Email).Scan(&mailboxID, &accountID))
	_, err := database.GetWritePool().Exec(ctx, `
		INSERT INTO messages
		(account_id, mailbox_id, mailbox_path, uid, message_id, in_reply_to, content_hash, s3_domain, s3_localpart,
		 internal_date, size, subject, sent_date, body_structure, recipients_json, created_modseq,
		 subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort)
		SELECT m.account_id, m.mailbox_id, m.mailbox_path, n, '<overflow-'||n||'@example.com>', '',
		 m.content_hash, m.s3_domain, m.s3_localpart, m.internal_date, m.size, m.subject, m.sent_date,
		 m.body_structure, m.recipients_json, nextval('messages_modseq'), m.subject_sort, m.from_name_sort,
		 m.from_email_sort, m.to_name_sort, m.to_email_sort, m.cc_email_sort
		FROM messages m CROSS JOIN generate_series(2, $2::integer) n
		WHERE m.mailbox_id = $1 AND m.uid = 1`, mailboxID, db.MaxSearchResults+1)
	require.NoError(t, err)
	_, err = database.GetWritePool().Exec(ctx, "UPDATE mailboxes SET highest_uid = $2 WHERE id = $1", mailboxID, db.MaxSearchResults+1)
	require.NoError(t, err)
	// Direct bulk seeding must publish realistic planner statistics as well as
	// mailbox state; this test is about completeness, not a stale-statistics plan.
	_, err = database.GetWritePool().Exec(ctx, "ANALYZE messages")
	require.NoError(t, err)
	c.do("SELECT Overflow")

	// ALL remains exempt, and an exact-cap filtered search is complete.
	all, _ := c.do("UID SEARCH RETURN (COUNT MIN MAX) ALL")
	require.Contains(t, strings.Join(all, " "), fmt.Sprintf("MIN 1 MAX %d COUNT %d", db.MaxSearchResults+1, db.MaxSearchResults+1))
	exact, _ := c.do(fmt.Sprintf("UID SEARCH RETURN (COUNT MIN MAX) UID 2:%d", db.MaxSearchResults+1))
	require.Contains(t, strings.Join(exact, " "), fmt.Sprintf("MIN 2 MAX %d COUNT %d", db.MaxSearchResults+1, db.MaxSearchResults))

	for _, command := range []string{
		"UID SEARCH SUBJECT match",
		"UID SEARCH RETURN (COUNT MIN MAX) SUBJECT match",
		"UID SORT (SUBJECT) UTF-8 SUBJECT match",
		"UID SORT RETURN (COUNT MIN MAX) (SUBJECT) UTF-8 SUBJECT match",
		"ESEARCH IN (SELECTED) RETURN (COUNT MIN MAX) SUBJECT match",
	} {
		t.Run(command, func(t *testing.T) {
			untagged, tagged := c.read(c.send(command), command)
			require.Contains(t, tagged, " NO [LIMIT] ", "must refuse overflow rather than acknowledge partial results")
			for _, line := range untagged {
				require.False(t, strings.HasPrefix(line, "* SEARCH") || strings.HasPrefix(line, "* SORT") || strings.HasPrefix(line, "* ESEARCH"), "partial result leaked: %s", line)
			}
		})
	}

	for _, command := range []string{
		"UID SEARCH RETURN (SAVE) SUBJECT match",
		"ESEARCH IN (SELECTED) RETURN (SAVE) SUBJECT match",
	} {
		t.Run(command, func(t *testing.T) {
			c.do("UID SEARCH RETURN (SAVE) UID 1")
			require.Len(t, c.fetchDollarUIDs(), 1)
			require.Contains(t, c.status(command), "NO [LIMIT] ")
			require.Empty(t, c.fetchDollarUIDs(), "failed SAVE must empty the old saved result")
		})
	}

	page, err := database.SearchMessagesWithCriteria(ctx, mailboxID, accountID, &imap.SearchCriteria{}, 2, db.MaxSearchResults+1)
	require.NoError(t, err, "an explicit caller limit is a page, not a complete search")
	require.Len(t, page, 2)
}
