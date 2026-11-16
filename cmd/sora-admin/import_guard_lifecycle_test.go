package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/require"
)

type postCommitGuardLossDB struct {
	*mockResilientDatabase
	loss error
}

func (m *postCommitGuardLossDB) ExecuteWithSharedS3ObjectLocks(ctx context.Context, _ int64, _ []string, fn func(context.Context) error) error {
	if err := fn(ctx); err != nil {
		return err
	}
	return m.loss
}

func TestImportMaildirPropagatesPostCommitGuardLoss(t *testing.T) {
	maildir := newCleanupDBMaildir(t, 1)
	loss := errors.New("original body holder was lost after callback")
	i, err := NewImporter(context.Background(), maildir, "user@example.com", 1, nil, &countingStorage{}, ImporterOptions{})
	require.NoError(t, err)
	defer i.Close()
	i.rdb = &postCommitGuardLossDB{mockResilientDatabase: newMockResilientDatabase(), loss: loss}
	err = i.Run()
	require.ErrorIs(t, err, loss, "a known holder failure was merely logged and the command reported success")
}

func TestImportMaildirPutUsesGuardedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ignored atomic.Bool
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		cancel()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(400 * time.Millisecond):
			ignored.Store(true)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	st, err := storage.New(strings.TrimPrefix(server.URL, "http://"), "test", "secret", "bucket", false, false, 2*time.Second)
	require.NoError(t, err)
	i := &Importer{s3: st, jobs: 1}
	got := i.uploadBatchToS3(ctx, []uploadedMsg{{msg: msgInfo{hash: "hash", path: "message"}, content: []byte("body"), metadata: &messageMetadata{domain: "example.com", localpart: "user"}}})
	require.False(t, ignored.Load(), "Maildir PUT ignored guarded context cancellation")
	require.Empty(t, got)
	require.EqualValues(t, 1, requests.Load(), "canceled upload was retried")
}
