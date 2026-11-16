//go:build integration

package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/require"
)

func TestReconcileBodyDeletionVerifiesProtectedBytes(t *testing.T) {
	f := newRekeyFixture(t)
	account, domain, local := f.account("intent-protected")
	body := f.body("protected")
	hash := helpers.HashContent(body)
	key := helpers.NewS3Key(domain, local, hash)
	f.insert(account, "INBOX", domain, local, hash, body, fmt.Sprintf("<protected-%d@example.org>", time.Now().UnixNano()))
	id := uuid.NewString()
	f.exec(`INSERT INTO s3_body_delete_intents(content_hash,operation_id,object_keys,retire_snapshot) VALUES($1,$2,ARRAY[$3],'[]')`, hash, id, key)
	require.Error(t, reconcileBodyDeletion(f.ctx, f.rdb, f.store, hash, id, false))
	require.ErrorContains(t, reconcileBodyDeletion(f.ctx, f.rdb, f.store, hash, id, true), "protected body")
	f.put(key, []byte("corrupt"))
	require.ErrorContains(t, reconcileBodyDeletion(f.ctx, f.rdb, f.store, hash, id, true), "does not match")
	var n int
	require.NoError(t, f.rdb.QueryRowWithRetry(f.ctx, `SELECT count(*) FROM s3_body_delete_intents WHERE content_hash=$1`, hash).Scan(&n))
	require.Equal(t, 1, n)
	f.put(key, body)
	require.NoError(t, reconcileBodyDeletion(f.ctx, f.rdb, f.store, hash, id, true))
	require.NoError(t, f.rdb.QueryRowWithRetry(f.ctx, `SELECT count(*) FROM s3_body_delete_intents WHERE content_hash=$1`, hash).Scan(&n))
	require.Zero(t, n)
	stored, exists := f.stored(key)
	require.True(t, exists)
	require.Equal(t, body, stored)
}

func TestReconcileBodyDeletionRejectsMismatchedIntentKey(t *testing.T) {
	f := newRekeyFixture(t)
	hash := helpers.HashContent(f.body("invalid-key"))
	id := uuid.NewString()
	key := "example.org/other/" + helpers.HashContent([]byte("other"))
	f.exec(`INSERT INTO s3_body_delete_intents(content_hash,operation_id,object_keys,retire_snapshot) VALUES($1,$2,ARRAY[$3],'[]')`, hash, id, key)
	require.ErrorContains(t, reconcileBodyDeletion(context.Background(), f.rdb, f.store, hash, id, true), "invalid body key")
	// The selected exact intent remains; no unrelated key is operated on.
	intents, err := f.rdb.ListS3BodyDeleteIntents(f.ctx)
	require.NoError(t, err)
	found := false
	for _, i := range intents {
		if i.ContentHash == hash {
			found = true
			require.Equal(t, id, i.OperationID)
			require.Equal(t, []string{key}, i.ObjectKeys)
		}
	}
	require.True(t, found)
}
