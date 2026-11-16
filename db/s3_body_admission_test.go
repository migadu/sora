package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

func TestS3BodyQuarantineStagesDeliveryButRefusesUploadedAdmissions(t *testing.T) {
	d, _, account, inbox := setupCleanerTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	hash := fmt.Sprintf("admit-%d", time.Now().UnixNano())
	insertKeyedMessage(t, d, account, inbox, 1, hash, "admit", true, time.Time{})
	_, err := d.GetWritePool().Exec(ctx, `UPDATE mailboxes SET highest_uid=1 WHERE id=$1`, inbox)
	require.NoError(t, err)
	tx, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, d.CreateMailbox(ctx, tx, account, "Archive", nil))
	require.NoError(t, tx.Commit(ctx))
	archive, err := d.GetMailboxByName(ctx, account, "Archive")
	require.NoError(t, err)
	_, err = d.GetWritePool().Exec(ctx, `INSERT INTO s3_body_delete_intents(content_hash,operation_id,object_keys,retire_snapshot) VALUES($1,$2,ARRAY[$3],'[]')`, hash, uuid.NewString(), "example.com/admit/"+hash)
	require.NoError(t, err)
	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
	options := func(name string) *InsertMessageOptions {
		return &InsertMessageOptions{AccountID: account, MailboxID: inbox, MailboxName: "INBOX", ContentHash: hash, S3Domain: "example.com", S3Localpart: "admit", MessageID: "<" + name + hash + "@example.org>", BodyStructure: &bs, Size: 100}
	}
	upload := PendingUpload{AccountID: account, ContentHash: hash, InstanceID: "admit", Size: 100}
	tx, err = d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	id, _, err := d.InsertMessage(ctx, tx, options("delivery"), upload)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	var uploaded bool
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT uploaded FROM messages WHERE id=$1`, id).Scan(&uploaded))
	require.False(t, uploaded, "quarantine must disable live-sibling content dedup while permitting staging")
	tx, err = d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	ids, _, _, err := d.InsertMessagesBatch(ctx, tx, []*InsertMessageOptions{options("delivery-batch")}, []PendingUpload{upload})
	require.NoError(t, err)
	require.Len(t, ids, 1)
	require.NoError(t, tx.Commit(ctx))
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT uploaded FROM messages WHERE id=$1`, ids[0]).Scan(&uploaded))
	require.False(t, uploaded)
	for _, mode := range []string{"single-import", "batch-import", "same-account-copy", "same-account-move"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := d.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)
			uids := []imap.UID{1}
			switch mode {
			case "single-import":
				_, _, err = d.InsertMessageFromImporter(ctx, tx, options(mode))
			case "batch-import":
				_, _, _, err = d.InsertMessagesBatch(ctx, tx, []*InsertMessageOptions{options(mode)}, nil)
			case "same-account-copy":
				_, _, err = d.CopyMessages(ctx, tx, &uids, inbox, archive.ID, account, "example.com", "admit", "admit", nil, nil)
			case "same-account-move":
				_, err = d.MoveMessages(ctx, tx, &uids, inbox, archive.ID, account, "example.com", "admit", "admit", nil, nil)
			}
			require.ErrorIs(t, err, ErrS3BodyQuarantined)
		})
	}
	var copies int
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT count(*) FROM messages WHERE mailbox_id=$1`, archive.ID).Scan(&copies))
	require.Zero(t, copies)
}
