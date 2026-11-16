//go:build integration

package imap

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// crossAccountBodyCap is the most distinct messages one COPY or MOVE may carry into a
// mailbox of another account.
const crossAccountBodyCap = db.MaxCrossAccountBodies

// A COPY or MOVE into another account's mailbox holds two lock-table entries per distinct
// message until it commits, so one over the cap is refused with NO [LIMIT] (RFC 5530) and
// copies or moves nothing; a COPY may not be split, RFC 9051 §6.4.7: "partial copy MUST
// NOT be done".
func TestIMAP_CrossAccountCopyMoveOverTheBodyCapAnswersLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, contributor, fake := common.SetupIMAPServerWithRealS3(t)
	defer server.Close()
	ctx := context.Background()
	rdb := server.ResilientDB

	_, ownerID, shared := createOwnerWithSharedMailbox(t, server, contributor.Email, "lrswi")
	contributorID, err := rdb.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
	require.NoError(t, err)

	cc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer cc.Logout()
	require.NoError(t, cc.Login(contributor.Email, contributor.Password).Wait())

	// One appended message and crossAccountBodyCap copies of its row, each with a body of
	// its own, all of them marked uploaded under the contributor's key.
	const messages = crossAccountBodyCap + 1
	appendTo(t, cc, "INBOX", "Body cap", "cross-account body cap marker")
	server.WaitForUploads(t)
	var inboxID, sourceID int64
	require.NoError(t, rdb.QueryRowWithRetry(ctx, `
		SELECT m.mailbox_id, m.id FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
		WHERE mb.account_id = $1 AND mb.name = 'INBOX' AND m.expunged_at IS NULL`,
		contributorID).Scan(&inboxID, &sourceID))
	_, err = rdb.ExecWithRetry(ctx, `
		WITH inserted AS (
			INSERT INTO messages (account_id, uid, s3_domain, s3_localpart, content_hash, uploaded,
			                      recipients_json, message_id, in_reply_to, "references", subject,
			                      sent_date, sent_utc_offset, sent_date_unknown, internal_date, size,
			                      body_structure, subject_sort, from_name_sort, from_email_sort,
			                      to_name_sort, to_email_sort, cc_email_sort, extra_addresses,
			                      mailbox_id, mailbox_path, created_modseq)
			SELECT m.account_id, m.uid + g, m.s3_domain, m.s3_localpart, $2 || g, TRUE,
			       m.recipients_json, '<' || $2 || g || '@example.com>', m.in_reply_to, m."references", m.subject,
			       m.sent_date, m.sent_utc_offset, m.sent_date_unknown, m.internal_date, m.size,
			       m.body_structure, m.subject_sort, m.from_name_sort, m.from_email_sort,
			       m.to_name_sort, m.to_email_sort, m.cc_email_sort, m.extra_addresses,
			       m.mailbox_id, m.mailbox_path, nextval('messages_modseq')
			FROM messages m, generate_series(1, $3::int) AS g
			WHERE m.id = $1
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
		SELECT id, mailbox_id, 0, '[]'::jsonb, now(), nextval('messages_modseq') FROM inserted`,
		sourceID, fmt.Sprintf("xacct-cap-%d-", common.GetTimestamp()), messages-1)
	require.NoError(t, err)
	_, err = rdb.ExecWithRetry(ctx, `UPDATE mailboxes SET highest_uid = highest_uid + $2 WHERE id = $1`, inboxID, messages-1)
	require.NoError(t, err)

	_, err = cc.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	all := imap.UIDSet{imap.UIDRange{Start: 1, Stop: 0}}

	count := func(accountID int64, mailbox string) int {
		var n int
		require.NoError(t, rdb.QueryRowWithRetry(ctx, `
			SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
			WHERE mb.account_id = $1 AND mb.name = $2 AND m.expunged_at IS NULL`,
			accountID, mailbox).Scan(&n))
		return n
	}
	requireLimit := func(command string, err error) {
		t.Helper()
		var imapErr *imap.Error
		if !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeNo || imapErr.Code != imap.ResponseCodeLimit {
			t.Errorf("UID %s of %d distinct messages into another user's mailbox: got %v, want NO [LIMIT]", command, messages, err)
		}
		if n := count(ownerID, shared); n != 0 {
			t.Errorf("UID %s over the cap left %d messages in the shared mailbox, want 0", command, n)
		}
		if n := count(contributorID, "INBOX"); n != messages {
			t.Errorf("UID %s over the cap left %d messages in INBOX, want %d", command, n, messages)
		}
	}

	objects := fake.ObjectCount()
	_, err = cc.Copy(all, shared).Wait()
	requireLimit("COPY", err)
	_, err = cc.Move(all, shared).Wait()
	requireLimit("MOVE", err)
	if n := fake.ObjectCount(); n != objects {
		t.Errorf("refused commands changed the S3 object count from %d to %d", objects, n)
	}

	// Legacy destination-owned rows still need source body admission. One row is
	// rekeyed, but all1001 distinct source bodies must count before any S3 copy.
	_, err = rdb.ExecWithRetry(ctx, `UPDATE messages SET account_id=$2 WHERE mailbox_id=$1 AND uid>1`, inboxID, ownerID)
	require.NoError(t, err)
	_, err = cc.Copy(all, shared).Wait()
	requireLimit("COPY mixed ownership", err)
	_, err = cc.Move(all, shared).Wait()
	requireLimit("MOVE mixed ownership", err)
	require.Equal(t, objects, fake.ObjectCount(), "mixed-ownership refusal must precede storage changes")
}
