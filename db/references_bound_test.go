package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// TestInsertPathsKeepLastReferences: every insert path bounds messages."references" by
// dropping whole message IDs from the middle, so the first ID (the thread's root) and the
// last ones (the parent's among them, RFC 5256 §2.2 "the last reference") survive and no
// ID is stored cut short. The bound kept the first 2000 bytes, which in a long thread
// lost the parent and cut the last kept ID in the middle (#610).
func TestInsertPathsKeepLastReferences(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, inboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	// 40 message IDs of 62 bytes join to 2519 bytes. The first plus the last 30 are
	// 62 + 30*63 = 1952 bytes; one more ID would be 2015, over the 2000-byte bound.
	var refs []string
	for n := 1; n <= 40; n++ {
		refs = append(refs, fmt.Sprintf("CAB%02d%s@mail.example.com", n, strings.Repeat("x", 40)))
	}
	want := strings.Join(append([]string{refs[0]}, refs[10:]...), " ")

	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100}
	base := time.Now().UnixNano()
	options := func(path string) *InsertMessageOptions {
		hash := fmt.Sprintf("longrefs-%s-%d", path, base)
		return &InsertMessageOptions{
			AccountID: accountID, MailboxID: inboxID, MailboxName: "INBOX",
			S3Domain: "example.com", S3Localpart: "longrefs", ContentHash: hash,
			MessageID: "<" + hash + "@example.com>", InternalDate: time.Now(), SentDate: time.Now(),
			Size: 100, Subject: "Re: long thread", BodyStructure: &bs,
			InReplyTo: refs[len(refs)-1:], References: refs,
		}
	}
	upload := func(o *InsertMessageOptions) PendingUpload {
		return PendingUpload{InstanceID: "test", ContentHash: o.ContentHash, Size: o.Size, AccountID: accountID}
	}

	for _, tc := range []struct {
		path   string
		insert func(tx pgx.Tx, o *InsertMessageOptions) (int64, error)
	}{
		{"InsertMessage", func(tx pgx.Tx, o *InsertMessageOptions) (int64, error) {
			id, _, err := db.InsertMessage(ctx, tx, o, upload(o))
			return id, err
		}},
		{"InsertMessageFromImporter", func(tx pgx.Tx, o *InsertMessageOptions) (int64, error) {
			id, _, err := db.InsertMessageFromImporter(ctx, tx, o)
			return id, err
		}},
		{"InsertMessagesBatch", func(tx pgx.Tx, o *InsertMessageOptions) (int64, error) {
			ids, _, _, err := db.InsertMessagesBatch(ctx, tx, []*InsertMessageOptions{o}, []PendingUpload{upload(o)})
			if err != nil {
				return 0, err
			}
			return ids[0], nil
		}},
		{"InsertMessagesFromImporterBatch", func(tx pgx.Tx, o *InsertMessageOptions) (int64, error) {
			ids, _, _, err := db.InsertMessagesFromImporterBatch(ctx, tx, []*InsertMessageOptions{o})
			if err != nil {
				return 0, err
			}
			return ids[0], nil
		}},
	} {
		t.Run(tc.path, func(t *testing.T) {
			tx, err := db.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)

			id, err := tc.insert(tx, options(tc.path))
			require.NoError(t, err)
			var stored string
			require.NoError(t, tx.QueryRow(ctx, `SELECT "references" FROM messages WHERE id = $1`, id).Scan(&stored))
			require.Equal(t, want, stored, "the first and the last message IDs, whole")
		})
	}
}
