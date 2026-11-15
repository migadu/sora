package main

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/require"
)

const s3ImportTestEmail = "user@example.com"

// s3ImportTestBucket is an S3 endpoint holding one account's message bodies. It answers
// ListObjectsV2 a page of pageSize keys at a time, and GetObject, and counts both.
// onList, when set, runs before the n-th listing request (from 1) is answered.
type s3ImportTestBucket struct {
	objects  map[string][]byte
	pageSize int

	mu     sync.Mutex
	onList func(n int)
	lists  int
	gets   int
}

func newS3ImportTestBucket(t *testing.T, messages, pageSize int) (*s3ImportTestBucket, *storage.S3Storage) {
	t.Helper()
	b := &s3ImportTestBucket{objects: make(map[string][]byte), pageSize: pageSize}
	for n := 1; n <= messages; n++ {
		body := []byte(fmt.Sprintf("From: sender@example.org\r\nTo: %s\r\nSubject: message %d\r\n"+
			"Date: Mon, 02 Nov 2026 10:%02d:00 +0000\r\nMessage-ID: <m%d@example.org>\r\n\r\nBody %d.\r\n",
			s3ImportTestEmail, n, n, n, n))
		b.objects[helpers.NewS3Key("example.com", "user", helpers.HashContent(body))] = body
	}
	server := httptest.NewServer(b)
	t.Cleanup(server.Close)
	s3storage, err := storage.New(strings.TrimPrefix(server.URL, "http://"), "test-access-key", "test-secret-key",
		"test-bucket", false, false, 10*time.Second)
	require.NoError(t, err)
	return b, s3storage
}

type s3ListResult struct {
	XMLName               xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name                  string
	Prefix                string
	KeyCount              int
	MaxKeys               int
	IsTruncated           bool
	NextContinuationToken string `xml:",omitempty"`
	Contents              []s3ListedObject
}

type s3ListedObject struct {
	Key          string
	LastModified string
	ETag         string
	Size         int
}

func (b *s3ImportTestBucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path-style requests: /<bucket> lists, /<bucket>/<key> reads an object.
	_, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if key == "" {
		b.list(w, r)
		return
	}
	b.mu.Lock()
	b.gets++
	b.mu.Unlock()
	body, ok := b.objects[key]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

func (b *s3ImportTestBucket) list(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	b.lists++
	n, hook := b.lists, b.onList
	b.mu.Unlock()
	if hook != nil {
		hook(n)
	}

	prefix := r.URL.Query().Get("prefix")
	var keys []string
	for key := range b.objects {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	start, _ := strconv.Atoi(r.URL.Query().Get("continuation-token"))
	end := min(start+b.pageSize, len(keys))
	result := s3ListResult{Name: "test-bucket", Prefix: prefix, KeyCount: end - start, MaxKeys: 1000,
		IsTruncated: end < len(keys)}
	if result.IsTruncated {
		result.NextContinuationToken = strconv.Itoa(end)
	}
	for _, key := range keys[start:end] {
		result.Contents = append(result.Contents, s3ListedObject{Key: key,
			LastModified: "2026-11-02T10:00:00.000Z", ETag: `"etag"`, Size: len(b.objects[key])})
	}
	w.Header().Set("Content-Type", "application/xml")
	_ = xml.NewEncoder(w).Encode(result)
}

// s3ImportTestDB stands in for PostgreSQL: one account with an INBOX, and the import's
// writes recorded. exists answers the "already imported?" check; onInsert runs after
// a message is stored. Like the resilient database's, every call fails once its
// context is done.
type s3ImportTestDB struct {
	exists   func(ctx context.Context, count *int) error
	onInsert func()

	mu        sync.Mutex
	inserted  []string // content hashes of the messages stored
	completed []string // content hashes marked uploaded
}

func (m *s3ImportTestDB) GetAccountIDByAddressWithRetry(ctx context.Context, address string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return 42, nil
}

func (m *s3ImportTestDB) CreateDefaultMailboxesWithRetry(ctx context.Context, accountID int64) error {
	return ctx.Err()
}

func (m *s3ImportTestDB) QueryRowWithRetry(ctx context.Context, sql string, args ...any) pgx.Row {
	return rowFunc(func(dest ...any) error { return m.exists(ctx, dest[0].(*int)) })
}

func (m *s3ImportTestDB) GetMailboxByNameWithRetry(ctx context.Context, accountID int64, name string) (*db.DBMailbox, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &db.DBMailbox{ID: 7, AccountID: accountID, Name: name}, nil
}

func (m *s3ImportTestDB) InsertMessageWithRetry(ctx context.Context, options *db.InsertMessageOptions, upload db.PendingUpload) (int64, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	m.inserted = append(m.inserted, options.ContentHash)
	if m.onInsert != nil {
		m.onInsert()
	}
	return int64(len(m.inserted)), int64(len(m.inserted)), nil
}

func (m *s3ImportTestDB) CompleteS3UploadWithRetry(ctx context.Context, hash string, accountID int64, writtenKeys []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	m.completed = append(m.completed, hash)
	return nil
}

func notImportedYet(_ context.Context, count *int) error { *count = 0; return nil }

// runS3Import runs si until it returns, and fails the test if that takes longer than
// a run of a handful of objects can.
func runS3Import(t *testing.T, si *S3Importer) (string, error) {
	t.Helper()
	type result struct {
		out string
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := runCapturingStdout(t, si.Run)
		done <- result{out, err}
	}()
	select {
	case r := <-done:
		return r.out, r.err
	case <-time.After(10 * time.Second):
		t.Fatal("Run() did not return within 10s")
		return "", nil
	}
}

// TestS3ImportScanStopsOnInterrupt: Ctrl-C (SIGINT/SIGTERM cancel the command's
// context) while `import s3` lists the bucket ends the scan: no page after the
// interrupt is requested, and the scan fails with the interrupt.
func TestS3ImportScanStopsOnInterrupt(t *testing.T) {
	bucket, s3storage := newS3ImportTestBucket(t, 6, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bucket.onList = func(n int) {
		if n == 2 {
			cancel()
		}
	}
	si, err := NewS3Importer(ctx, nil, s3storage, S3ImporterOptions{Email: s3ImportTestEmail, Workers: 1, BatchSize: 1000, CleanupDB: true})
	require.NoError(t, err)
	defer si.Close()

	err = si.scanS3Objects()
	if !errors.Is(err, context.Canceled) {
		t.Errorf("scanS3Objects() = %v, want an error wrapping %v", err, context.Canceled)
	}
	bucket.mu.Lock()
	lists := bucket.lists
	bucket.mu.Unlock()
	if lists > 2 {
		t.Errorf("the scan requested %d pages, want at most 2 (the interrupt landed in the second)", lists)
	}
}

// TestS3ImportDryRunStopsOnInterruptAndLookupErrors: `import s3 --dry-run` reports, per
// object, whether the import would store it. An interrupt or a failed "already
// imported?" check leaves the rest of the objects unchecked, so the dry run must stop
// with that error (a non-zero exit) instead of listing them as "IMPORT ... new message"
// under a complete-looking summary.
func TestS3ImportDryRunStopsOnInterruptAndLookupErrors(t *testing.T) {
	const objects = 5
	errUnavailable := errors.New("simulated database unavailable")

	run := func(t *testing.T, exists func(ctx context.Context, cancel context.CancelFunc, count *int) error) (string, error) {
		t.Helper()
		_, s3storage := newS3ImportTestBucket(t, objects, 1000)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		si, err := NewS3Importer(ctx, nil, s3storage, S3ImporterOptions{Email: s3ImportTestEmail, DryRun: true,
			Workers: 1, BatchSize: 1000, CleanupDB: true})
		require.NoError(t, err)
		si.rdb = &s3ImportTestDB{exists: func(ctx context.Context, count *int) error { return exists(ctx, cancel, count) }}
		return runS3Import(t, si)
	}
	wantStopped := func(t *testing.T, out string, err, want error, maxReported int) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("Run() = %v, want an error wrapping %v", err, want)
		}
		if n := strings.Count(out, "Action: IMPORT"); n > maxReported {
			t.Errorf("the dry run reported %d objects as IMPORT, want at most %d (the ones it checked)", n, maxReported)
		}
		if strings.Contains(out, "Overall Summary") {
			t.Errorf("the dry run printed a summary for objects it did not check:\n%s", out)
		}
	}

	t.Run("interrupt between objects", func(t *testing.T) {
		out, err := run(t, func(_ context.Context, cancel context.CancelFunc, count *int) error {
			cancel()
			*count = 0
			return nil
		})
		wantStopped(t, out, err, context.Canceled, 1)
	})
	t.Run("interrupt during the existence check", func(t *testing.T) {
		out, err := run(t, func(ctx context.Context, cancel context.CancelFunc, _ *int) error {
			cancel()
			return ctx.Err()
		})
		wantStopped(t, out, err, context.Canceled, 0)
	})
	t.Run("database error on the existence check", func(t *testing.T) {
		out, err := run(t, func(context.Context, context.CancelFunc, *int) error { return errUnavailable })
		wantStopped(t, out, err, errUnavailable, 0)
	})
	t.Run("objects not imported yet", func(t *testing.T) {
		out, err := run(t, func(ctx context.Context, _ context.CancelFunc, count *int) error { return notImportedYet(ctx, count) })
		require.NoError(t, err)
		require.Equal(t, objects, strings.Count(out, "Action: IMPORT"))
		require.Contains(t, out, fmt.Sprintf("Would import: %d messages", objects))
	})
	t.Run("objects already imported", func(t *testing.T) {
		out, err := run(t, func(_ context.Context, _ context.CancelFunc, count *int) error { *count = 1; return nil })
		require.NoError(t, err)
		require.Contains(t, out, fmt.Sprintf("Would skip: %d messages", objects))
		require.Contains(t, out, "Would import: 0 messages")
	})
}

// TestS3ImportStopsOnInterrupt: Ctrl-C during `import s3` stops the import: no object
// is started after the interrupt, the configured --import-delay is not waited out, and
// the run fails with the interrupt (a non-zero exit). A message already stored when
// the interrupt lands is still marked uploaded: its body is the S3 object it was read
// from, and left unmarked it would wait in pending_uploads for an upload that never
// comes from this host.
func TestS3ImportStopsOnInterrupt(t *testing.T) {
	const objects, workers = 10, 3
	bucket, s3storage := newS3ImportTestBucket(t, objects, 1000)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	si, err := NewS3Importer(ctx, nil, s3storage, S3ImporterOptions{Email: s3ImportTestEmail, Workers: workers,
		BatchSize: 1000, CleanupDB: true, InstanceID: "test-instance", ImportDelay: time.Hour})
	require.NoError(t, err)
	// The interrupt lands as the first message is stored.
	mock := &s3ImportTestDB{exists: notImportedYet, onInsert: cancel}
	si.rdb = mock

	_, err = runS3Import(t, si)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run() = %v, want an error wrapping %v", err, context.Canceled)
	}

	mock.mu.Lock()
	inserted, completed := append([]string(nil), mock.inserted...), append([]string(nil), mock.completed...)
	mock.mu.Unlock()
	if len(inserted) == 0 || len(inserted) > workers {
		t.Errorf("stored %d messages, want 1 to %d (the ones in flight when the interrupt landed)", len(inserted), workers)
	}
	sort.Strings(inserted)
	sort.Strings(completed)
	require.Equal(t, inserted, completed, "a message stored before the interrupt was not marked uploaded")
	bucket.mu.Lock()
	gets := bucket.gets
	bucket.mu.Unlock()
	if gets > workers {
		t.Errorf("read %d objects from S3, want at most %d (one per worker in flight)", gets, workers)
	}
}

// TestS3ImportDoesNotImportWhenTheExistenceCheckFails: the import asks the database
// whether each object's message is already stored. A failed check is not a "no": the
// object fails, and is neither read from S3 nor stored, as it would be a duplicate when
// the message is there.
func TestS3ImportDoesNotImportWhenTheExistenceCheckFails(t *testing.T) {
	const objects = 3
	bucket, s3storage := newS3ImportTestBucket(t, objects, 1000)
	si, err := NewS3Importer(context.Background(), nil, s3storage, S3ImporterOptions{Email: s3ImportTestEmail,
		Workers: 1, BatchSize: 1000, CleanupDB: true, InstanceID: "test-instance"})
	require.NoError(t, err)
	mock := &s3ImportTestDB{exists: func(context.Context, *int) error { return errors.New("simulated database unavailable") }}
	si.rdb = mock

	_, err = runS3Import(t, si)
	require.NoError(t, err)

	require.Empty(t, mock.inserted, "objects whose existence check failed were imported")
	require.Zero(t, bucket.gets, "objects whose existence check failed were read from S3")
	require.EqualValues(t, objects, si.failedMessages)
}

// TestS3ImportInterruptIsNotAFailure: an object the interrupt stops before it is stored
// is left for the next run, like the objects still queued and like the messages
// `import maildir` leaves at an interrupt (#945): it is neither counted as failed nor
// recorded in the work database as processed, with the interrupt as its error.
func TestS3ImportInterruptIsNotAFailure(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	si, err := NewS3Importer(ctx, nil, nil, S3ImporterOptions{Email: s3ImportTestEmail, Workers: 1, CleanupDB: true})
	require.NoError(t, err)
	defer si.Close()
	// The interrupt lands while the first object's "already imported?" check runs.
	si.rdb = &s3ImportTestDB{exists: func(ctx context.Context, _ *int) error { cancel(); return ctx.Err() }}
	insertS3Objects(t, si, "example.com", "user", 3)

	err = si.importFromS3()
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, atomic.LoadInt64(&si.failedMessages), "an object the interrupt stopped was counted as failed")
	var marked int
	require.NoError(t, si.db.QueryRow(`SELECT COUNT(*) FROM s3_objects WHERE processed`).Scan(&marked))
	require.Zero(t, marked, "an object the interrupt stopped was recorded as processed")
}
