package db

import (
	"context"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

func (db *Database) ExpungeMessageUIDs(ctx context.Context, tx pgx.Tx, mailboxID int64, uids ...imap.UID) (int64, error) {
	start := time.Now()
	var err error
	defer func() {
		status := "success"
		if err != nil {
			status = "error"
		}
		metrics.DBQueryDuration.WithLabelValues("message_expunge", "write").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("message_expunge", status, "write").Inc()
	}()

	if len(uids) == 0 {
		logger.Info("Database: no UIDs to expunge", "mailbox_id", mailboxID)
		return 0, nil
	}

	logger.Info("Database: expunging messages", "count", len(uids), "mailbox_id", mailboxID, "uids", uids)

	var currentModSeq int64
	var rowsAffected int64
	err = tx.QueryRow(ctx, `
		WITH updated AS (
			UPDATE messages
			SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
			WHERE mailbox_id = $1 AND uid = ANY($2) AND expunged_at IS NULL
			RETURNING expunged_modseq
		)
		SELECT COUNT(*), COALESCE(MAX(expunged_modseq), 0)
		FROM updated
	`, mailboxID, uids).Scan(&rowsAffected, &currentModSeq)

	if err != nil {
		logger.Error("Database: error executing expunge update", "err", err)
		return 0, err
	}

	logger.Info("Database: successfully expunged messages", "count", rowsAffected, "mailbox_id", mailboxID, "modseq", currentModSeq)
	return currentModSeq, nil
}
