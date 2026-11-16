package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A known plain-UTC date stores zero, while an explicitly unknown zone stores
// NULL. COPY and MOVE must preserve that distinction and keep an absent Date
// header separate from a present header with an unknown zone.
func TestEnvelopeDateZoneSurvivesCopyMove(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	database, accountID, inboxID := setupSearchTestDatabase(t)
	defer database.Close()
	ctx := context.Background()
	archiveID := createTestMailbox(t, database, accountID, "Archive")
	movedID := createTestMailbox(t, database, accountID, "Moved")
	instant := time.Date(2025, 1, 1, 4, 0, 0, 0, time.UTC)
	cases := []struct {
		name                         string
		date                         time.Time
		unknown, legacy, wantUnknown bool
		uid                          imap.UID
	}{
		{name: "known UTC", date: instant},
		{name: "unknown UTC", date: instant, unknown: true, wantUnknown: true},
		{name: "absent header", unknown: true}, // stale caller flag must not mark the INTERNALDATE fallback unknown
		{name: "legacy NULL", date: instant, legacy: true, wantUnknown: true},
		{name: "sanitized offset", date: instant.In(time.FixedZone("", 25*3600)), wantUnknown: true},
	}
	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	var body imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 64}
	var sourceUIDs []imap.UID
	for i := range cases {
		tc := &cases[i]
		hash := fmt.Sprintf("env-zone-copy-%d-%d", time.Now().UnixNano(), i)
		_, uid, err := database.InsertMessage(ctx, tx, &InsertMessageOptions{
			AccountID: accountID, MailboxID: inboxID, MailboxName: "INBOX",
			S3Domain: "example.com", S3Localpart: "envzone", ContentHash: hash, MessageID: hash + "@example.com",
			InternalDate: instant, SentDate: tc.date, SentDateUnknownZone: tc.unknown,
			Size: 64, Subject: tc.name, BodyStructure: &body,
		}, PendingUpload{InstanceID: "envzone", ContentHash: hash, Size: 64, AccountID: accountID})
		require.NoError(t, err)
		tc.uid = imap.UID(uid)
		sourceUIDs = append(sourceUIDs, tc.uid)
		if tc.legacy {
			_, err = tx.Exec(ctx, `UPDATE messages SET sent_utc_offset=NULL WHERE mailbox_id=$1 AND uid=$2`, inboxID, uid)
			require.NoError(t, err)
		}
	}
	require.NoError(t, tx.Commit(ctx))

	tx, err = database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	copied, _, err := database.CopyMessages(ctx, tx, &sourceUIDs, inboxID, archiveID, accountID, "example.com", "envzone", "test", nil, nil)
	require.NoError(t, err)
	moved, err := database.MoveMessages(ctx, tx, &sourceUIDs, inboxID, movedID, accountID, "example.com", "envzone", "test", nil, nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	for _, path := range []struct {
		name    string
		mailbox int64
		uids    map[imap.UID]imap.UID
	}{{"COPY", archiveID, copied}, {"MOVE", movedID, moved}} {
		t.Run(path.name, func(t *testing.T) {
			for _, tc := range cases {
				uid := path.uids[tc.uid]
				require.NotZero(t, uid, tc.name)
				var offset *int32
				require.NoError(t, database.GetReadPool().QueryRow(ctx, `SELECT sent_utc_offset FROM messages WHERE mailbox_id=$1 AND uid=$2`, path.mailbox, uid).Scan(&offset))
				if tc.wantUnknown {
					assert.Nil(t, offset, tc.name)
				} else if assert.NotNil(t, offset, tc.name) {
					assert.Zero(t, *offset, tc.name)
				}
				messages, err := database.GetMessagesByNumSet(ctx, path.mailbox, imap.UIDSetNum(uid))
				require.NoError(t, err)
				require.Len(t, messages, 1)
				assert.Equal(t, tc.wantUnknown, messages[0].SentDateUnknownZone, tc.name)
				assert.Equal(t, tc.date.IsZero(), messages[0].NoDateHeader, tc.name)
				envelope, err := database.GetMessageEnvelope(ctx, uid, path.mailbox)
				require.NoError(t, err)
				assert.Equal(t, tc.wantUnknown, envelope.DateUnknownZone, tc.name)
				assert.Equal(t, tc.date.IsZero(), envelope.Date.IsZero(), tc.name)
			}
		})
	}
}
