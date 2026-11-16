package db

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// Creation and a later STORE can both precede one poll. IsNew describes the UID's
// birth; FlagsAreInitial separately proves whether suppressing its flags is safe.
func TestPollMailboxInitialStateVersions(t *testing.T) {
	d, account, _ := setupSearchTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100}
	for _, writer := range []string{"append", "import", "append batch", "import batch"} {
		t.Run(writer, func(t *testing.T) {
			name := fmt.Sprintf("Initial-%d", time.Now().UnixNano())
			box := createTestMailbox(t, d, account, name)
			o := &InsertMessageOptions{AccountID: account, MailboxID: box, MailboxName: name,
				ContentHash: fmt.Sprintf("initial-%d", time.Now().UnixNano()), MessageID: fmt.Sprintf("initial-%d@example.org", time.Now().UnixNano()),
				InternalDate: time.Now(), SentDate: time.Now(), Size: 100, BodyStructure: &bs,
				S3Domain: "example.com", S3Localpart: "initial", Flags: []imap.Flag{imap.FlagSeen}}
			tx, err := d.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)
			var uid int64
			switch writer {
			case "append":
				_, uid, err = d.InsertMessage(ctx, tx, o, PendingUpload{InstanceID: "test", ContentHash: o.ContentHash, Size: o.Size, AccountID: account})
			case "import":
				_, uid, err = d.InsertMessageFromImporter(ctx, tx, o)
			case "append batch":
				_, us, _, e := d.InsertMessagesBatch(ctx, tx, []*InsertMessageOptions{o}, nil)
				err = e
				if e == nil {
					uid = us[0]
				}
			case "import batch":
				_, us, _, e := d.InsertMessagesFromImporterBatch(ctx, tx, []*InsertMessageOptions{o})
				err = e
				if e == nil {
					uid = us[0]
				}
			}
			require.NoError(t, err)
			require.NoError(t, tx.Commit(ctx))
			var initial, updated uint64
			require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT initial_modseq, updated_modseq FROM message_state ms JOIN messages m ON m.id=ms.message_id WHERE m.mailbox_id=$1 AND m.uid=$2`, box, uid).Scan(&initial, &updated))
			require.Equal(t, updated, initial)
			p, err := d.PollMailbox(ctx, box, 0)
			require.NoError(t, err)
			require.Len(t, p.Updates, 1)
			require.True(t, p.Updates[0].IsNew)
			require.True(t, p.Updates[0].FlagsAreInitial)
			// Later flags must not disappear just because this UID is also new.
			tx, err = d.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			_, _, err = d.AddMessageFlags(ctx, tx, imap.UID(uid), box, []imap.Flag{imap.FlagFlagged, "LaterKeyword"})
			require.NoError(t, err)
			require.NoError(t, tx.Commit(ctx))
			p, err = d.PollMailbox(ctx, box, 0)
			require.NoError(t, err)
			require.Len(t, p.Updates, 1)
			u := p.Updates[0]
			require.True(t, u.IsNew)
			require.False(t, u.FlagsAreInitial)
			require.True(t, ContainsFlag(u.BitwiseFlags, FlagFlagged))
			require.Contains(t, u.CustomFlags, "LaterKeyword")
			require.Greater(t, u.EffectiveModSeq, initial)
			// Even an UPDATE naming the birth version cannot rewrite it.
			_, err = d.GetWritePool().Exec(ctx, `UPDATE message_state SET initial_modseq=updated_modseq WHERE mailbox_id=$1`, box)
			require.NoError(t, err)
			var kept uint64
			require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT initial_modseq FROM message_state WHERE mailbox_id=$1`, box).Scan(&kept))
			require.Equal(t, initial, kept)
		})
	}
}

func TestPollMailboxUnknownInitialStateIsConservative(t *testing.T) {
	d, account, box := setupSearchTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	tx, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUIDForPoll(t, d, ctx, tx, account, box, "INBOX", 1, nil)
	require.NoError(t, tx.Commit(ctx))
	var id int64
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT id FROM messages WHERE mailbox_id=$1 AND uid=1`, box).Scan(&id))
	_, err = d.GetWritePool().Exec(ctx, `DELETE FROM message_state WHERE message_id=$1`, id)
	require.NoError(t, err)
	p, err := d.PollMailbox(ctx, box, 0)
	require.NoError(t, err)
	require.Len(t, p.Updates, 1)
	require.True(t, p.Updates[0].IsNew)
	require.False(t, p.Updates[0].FlagsAreInitial, "missing sidecar is not proof of an initial state")
	// A NULL version remains unknown even after a later STORE supplies a version.
	_, err = d.GetWritePool().Exec(ctx, `INSERT INTO message_state(message_id,mailbox_id,flags,updated_modseq) VALUES($1,$2,0,NULL)`, id, box)
	require.NoError(t, err)
	tx, err = d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, _, err = d.AddMessageFlags(ctx, tx, 1, box, []imap.Flag{imap.FlagFlagged})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	var initial sql.NullInt64
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT initial_modseq FROM message_state WHERE message_id=$1`, id).Scan(&initial))
	require.False(t, initial.Valid)
	p, err = d.PollMailbox(ctx, box, 0)
	require.NoError(t, err)
	require.Len(t, p.Updates, 1)
	require.True(t, p.Updates[0].IsNew)
	require.False(t, p.Updates[0].FlagsAreInitial)
	require.True(t, ContainsFlag(p.Updates[0].BitwiseFlags, FlagFlagged))
}

func TestCopyMoveRestoreInstallFreshInitialState(t *testing.T) {
	d, account, box := setupSearchTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	tx, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUIDForPoll(t, d, ctx, tx, account, box, "INBOX", 1, nil)
	require.NoError(t, tx.Commit(ctx))
	tx, err = d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, _, err = d.AddMessageFlags(ctx, tx, 1, box, []imap.Flag{imap.FlagFlagged})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	var sourceInitial uint64
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT initial_modseq FROM message_state WHERE mailbox_id=$1`, box).Scan(&sourceInitial))
	assertInitial := func(boxID int64) uint64 {
		t.Helper()
		p, err := d.PollMailbox(ctx, boxID, 0)
		require.NoError(t, err)
		require.Len(t, p.Updates, 1)
		require.True(t, p.Updates[0].IsNew)
		require.True(t, p.Updates[0].FlagsAreInitial)
		require.True(t, ContainsFlag(p.Updates[0].BitwiseFlags, FlagFlagged))
		require.Greater(t, p.Updates[0].EffectiveModSeq, sourceInitial)
		return p.Updates[0].EffectiveModSeq
	}
	dest := createTestMailbox(t, d, account, "InitialCopy")
	tx, err = d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	set := []imap.UID{1}
	_, _, err = d.CopyMessages(ctx, tx, &set, box, dest, account, "example.com", "initial", "test", nil, nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	copied := assertInitial(dest)
	moved := createTestMailbox(t, d, account, "InitialMove")
	tx, err = d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = d.MoveMessages(ctx, tx, &set, dest, moved, account, "example.com", "initial", "test", nil, nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	require.Greater(t, assertInitial(moved), copied)
	var id int64
	var email string
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT id FROM messages WHERE mailbox_id=$1 AND expunged_at IS NULL`, moved).Scan(&id))
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT address FROM credentials WHERE account_id=$1 LIMIT 1`, account).Scan(&email))
	tx, err = d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `UPDATE messages SET expunged_at=now(),expunged_modseq=nextval('messages_modseq') WHERE id=$1`, id)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	tx, err = d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	n, err := d.RestoreMessages(ctx, tx, RestoreMessagesParams{Email: email, MessageIDs: []int64{id}})
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	require.NoError(t, tx.Commit(ctx))
	assertInitial(moved)
	var unchanged uint64
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT initial_modseq FROM message_state WHERE message_id=$1`, id).Scan(&unchanged))
	require.Greater(t, unchanged, copied, "the old tombstone retains its own immutable state version")
}
