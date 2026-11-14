//go:build integration

package main

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const verifyTestBucket = "verify-test"

// memS3 is an in-memory, path-style S3 endpoint with the calls `verify s3` makes:
// ListObjectsV2, HEAD, GET, PUT and DELETE of single objects.
type memS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newMemS3(t *testing.T) (*memS3, string) {
	t.Helper()
	isolateVerifyAWSEnvironment(t)
	m := &memS3{objects: make(map[string][]byte)}
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return m, strings.TrimPrefix(srv.URL, "http://")
}

func (m *memS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	path := strings.TrimPrefix(r.URL.Path, "/"+verifyTestBucket)
	key := strings.TrimPrefix(path, "/")
	if key == "" {
		if r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2" {
			m.list(w, r.URL.Query().Get("prefix"))
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	switch r.Method {
	case http.MethodHead, http.MethodGet:
		data, ok := m.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	case http.MethodPut:
		data, _ := io.ReadAll(r.Body)
		m.objects[key] = data
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		delete(m.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *memS3) list(w http.ResponseWriter, prefix string) {
	type content struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int    `xml:"Size"`
		StorageClass string `xml:"StorageClass"`
	}
	type listResult struct {
		XMLName     xml.Name  `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
		Name        string    `xml:"Name"`
		Prefix      string    `xml:"Prefix"`
		KeyCount    int       `xml:"KeyCount"`
		MaxKeys     int       `xml:"MaxKeys"`
		IsTruncated bool      `xml:"IsTruncated"`
		Contents    []content `xml:"Contents"`
	}
	res := listResult{Name: verifyTestBucket, Prefix: prefix, MaxKeys: 1000}
	for key, data := range m.objects {
		if strings.HasPrefix(key, prefix) {
			res.Contents = append(res.Contents, content{
				Key: key, LastModified: "2026-01-01T00:00:00.000Z", ETag: `"etag"`, Size: len(data), StorageClass: "STANDARD",
			})
		}
	}
	sort.Slice(res.Contents, func(i, j int) bool { return res.Contents[i].Key < res.Contents[j].Key })
	res.KeyCount = len(res.Contents)
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(res)
}

func (m *memS3) put(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = []byte("body of " + key)
}

func (m *memS3) has(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.objects[key]
	return ok
}

// isolateVerifyAWSEnvironment keeps the developer's or CI's AWS settings out of the S3
// client the test builds.
func isolateVerifyAWSEnvironment(t *testing.T) {
	t.Helper()
	none := t.TempDir() + "/none"
	t.Setenv("AWS_CONFIG_FILE", none)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", none)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	for _, name := range []string{"AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3"} {
		t.Setenv(name, "")
	}
}

func verifyTestConfig(t *testing.T, endpoint string) AdminConfig {
	return AdminConfig{
		Database: *adminTestDBConfig(t),
		S3: config.S3Config{
			Endpoint:   endpoint,
			DisableTLS: true,
			AccessKey:  "test-access-key",
			SecretKey:  "test-secret-key",
			Bucket:     verifyTestBucket,
			Timeout:    "5s",
		},
	}
}

// TestVerifyS3FixOrphanedKeepsReferencedObjects: `verify s3 --fix-orphaned` may only
// delete an object that nothing references. A message expunged but still inside the
// cleanup grace period can be restored with its body, a row of another account can
// carry a key under this address (keys use the address at write time), and a pending
// upload is about to need the body: each keeps its object. Only an object no row and
// no upload points at goes.
func TestVerifyS3FixOrphanedKeepsReferencedObjects(t *testing.T) {
	f := newRekeyFixture(t)
	mem, endpoint := newMemS3(t)

	accountID, domain, localpart := f.account("verify")
	otherID, _, _ := f.account("verify-other")
	key := func(hash string) string { return helpers.NewS3Key(domain, localpart, hash) }

	liveHash := helpers.HashContent(f.body("live"))
	f.insert(accountID, "INBOX", domain, localpart, liveHash, f.body("live"), "<live-"+f.nonce+"@example.org>")
	mem.put(key(liveHash))

	expungedHash := helpers.HashContent(f.body("expunged"))
	expungedID := f.insert(accountID, "INBOX", domain, localpart, expungedHash, f.body("expunged"), "<expunged-"+f.nonce+"@example.org>")
	f.exec("UPDATE messages SET expunged_at = now() WHERE id = $1", expungedID)
	mem.put(key(expungedHash))

	// A row of another account whose key lies under this address.
	otherHash := helpers.HashContent(f.body("other-account"))
	f.insert(otherID, "INBOX", domain, localpart, otherHash, f.body("other-account"), "<other-"+f.nonce+"@example.org>")
	mem.put(key(otherHash))

	// A pending upload of a body whose rows are not there (yet).
	pendingHash := helpers.HashContent(f.body("pending"))
	f.exec("INSERT INTO pending_uploads (instance_id, content_hash, size, account_id) VALUES ('verify-test', $1, 10, $2)",
		pendingHash, accountID)
	mem.put(key(pendingHash))

	orphanHash := helpers.HashContent(f.body("orphan"))
	mem.put(key(orphanHash))

	err := verifyS3Storage(f.ctx, verifyTestConfig(t, endpoint), localpart+"@"+domain,
		true, true, false, false, 1000, false)
	require.NoError(t, err)

	assert.True(t, mem.has(key(liveHash)), "the body of a live message was deleted")
	assert.True(t, mem.has(key(expungedHash)), "the body of an expunged, still restorable message was deleted")
	assert.True(t, mem.has(key(otherHash)), "a body another account's message points at was deleted")
	assert.True(t, mem.has(key(pendingHash)), "a body with a pending upload was deleted")
	assert.False(t, mem.has(key(orphanHash)), "an object nothing references was kept")
}

// TestVerifyS3NotUploadedRowsAreNotMissing: a row whose body is still waiting for the
// uploader (uploaded = false) has no object yet; that is not a missing object.
func TestVerifyS3NotUploadedRowsAreNotMissing(t *testing.T) {
	f := newRekeyFixture(t)
	mem, endpoint := newMemS3(t)

	accountID, domain, localpart := f.account("verify-pending")
	pendingHash := helpers.HashContent(f.body("pending"))
	pendingID := f.insert(accountID, "INBOX", domain, localpart, pendingHash, f.body("pending"), "<pending-"+f.nonce+"@example.org>")
	f.exec("UPDATE messages SET uploaded = FALSE WHERE id = $1", pendingID)
	f.exec("INSERT INTO pending_uploads (instance_id, content_hash, size, account_id) VALUES ('verify-test', $1, 10, $2)",
		pendingHash, accountID)

	uploadedHash := helpers.HashContent(f.body("uploaded"))
	f.insert(accountID, "INBOX", domain, localpart, uploadedHash, f.body("uploaded"), "<uploaded-"+f.nonce+"@example.org>")
	mem.put(helpers.NewS3Key(domain, localpart, uploadedHash))

	cfg := verifyTestConfig(t, endpoint)
	s3Storage, err := storage.New(cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, false, false, 5*time.Second)
	require.NoError(t, err)

	result := &verificationResult{}
	require.NoError(t, checkDBToS3(context.Background(), f.rdb, s3Storage, accountID, result, 1000, false))

	assert.Empty(t, result.MissingFromS3, "a row whose upload is pending was reported missing from S3")
}

// TestVerifyS3NotUploadedRowWithoutPendingUploadIsMissing: a row marked not uploaded
// with no pending upload (the upload was given up, or --fix-missing marked the row) is
// waiting for nothing: no uploader will write its body, and the cleaner reaps the row
// once it is older than the grace period. Its object is missing from S3, as on main; it
// is not an upload in progress, and a second run after --fix-missing must not call the
// account consistent.
func TestVerifyS3NotUploadedRowWithoutPendingUploadIsMissing(t *testing.T) {
	f := newRekeyFixture(t)
	_, endpoint := newMemS3(t)

	accountID, domain, localpart := f.account("verify-stranded")
	strandedHash := helpers.HashContent(f.body("stranded"))
	strandedID := f.insert(accountID, "INBOX", domain, localpart, strandedHash, f.body("stranded"), "<stranded-"+f.nonce+"@example.org>")
	f.exec("UPDATE messages SET uploaded = FALSE WHERE id = $1", strandedID)

	cfg := verifyTestConfig(t, endpoint)
	s3Storage, err := storage.New(cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, false, false, 5*time.Second)
	require.NoError(t, err)

	result := &verificationResult{}
	require.NoError(t, checkDBToS3(context.Background(), f.rdb, s3Storage, accountID, result, 1000, false))

	assert.Equal(t, []string{helpers.NewS3Key(domain, localpart, strandedHash)}, result.MissingFromS3,
		"a row with no body in S3 and no pending upload was not reported missing")
	assert.Zero(t, result.NotUploaded, "a row with no pending upload was counted as an upload in progress")
}

// TestVerifyHashPendingUploadIsNotStuck: `verify hash` on a body whose upload is still
// pending found no object and live rows marked not uploaded, and called that a stuck
// upload whose messages are safe to delete. The body waits in the receiving node's
// spool; deleting those rows loses the message. A row whose pending upload is gone is
// still reported as the failure it is.
func TestVerifyHashPendingUploadIsNotStuck(t *testing.T) {
	f := newRekeyFixture(t)
	_, endpoint := newMemS3(t)
	cfg := verifyTestConfig(t, endpoint)

	accountID, domain, localpart := f.account("verify-hash-pending")
	pendingHash := helpers.HashContent(f.body("pending"))
	pendingID := f.insert(accountID, "INBOX", domain, localpart, pendingHash, f.body("pending"), "<pending-"+f.nonce+"@example.org>")
	f.exec("UPDATE messages SET uploaded = FALSE WHERE id = $1", pendingID)
	f.exec("INSERT INTO pending_uploads (instance_id, content_hash, size, account_id) VALUES ('verify-test', $1, 10, $2)",
		pendingHash, accountID)

	out := captureStdout(t, func() error {
		return verifyContentHash(f.ctx, cfg, pendingHash, localpart+"@"+domain, false, false, "", "")
	})
	assert.NotContains(t, out, "Safe to delete", "a pending upload was called safe to delete:\n%s", out)
	assert.Contains(t, out, "Upload pending", "a pending upload was not reported as pending:\n%s", out)

	// Without the pending upload nothing will write the body: that stays a failure.
	f.exec("DELETE FROM pending_uploads WHERE content_hash = $1 AND account_id = $2", pendingHash, accountID)
	out = captureStdout(t, func() error {
		return verifyContentHash(f.ctx, cfg, pendingHash, localpart+"@"+domain, false, false, "", "")
	})
	assert.Contains(t, out, "[FAIL] Problem detected: Content missing from S3", "a stranded row was not reported:\n%s", out)
}

// TestVerifyS3FixOrphanedRechecksBeforeDelete: an object reported orphaned can be
// claimed before --fix-orphaned reaches it (a delivery of the same body re-uploads it).
// The delete re-checks under the body's object lock and keeps it.
func TestVerifyS3FixOrphanedRechecksBeforeDelete(t *testing.T) {
	f := newRekeyFixture(t)
	mem, endpoint := newMemS3(t)

	accountID, domain, localpart := f.account("verify-recheck")
	claimedHash := helpers.HashContent(f.body("claimed"))
	claimedKey := helpers.NewS3Key(domain, localpart, claimedHash)
	mem.put(claimedKey)
	orphanKey := helpers.NewS3Key(domain, localpart, helpers.HashContent(f.body("orphan")))
	mem.put(orphanKey)

	result := &verificationResult{OrphanedInS3: []string{claimedKey, orphanKey}}
	// Claimed after the check, before the delete.
	f.insert(accountID, "INBOX", domain, localpart, claimedHash, f.body("claimed"), "<claimed-"+f.nonce+"@example.org>")

	cfg := verifyTestConfig(t, endpoint)
	s3Storage, err := storage.New(cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, false, false, 5*time.Second)
	require.NoError(t, err)
	require.NoError(t, applyFixes(f.ctx, f.rdb, s3Storage, accountID, result, true, false))

	assert.True(t, mem.has(claimedKey), "an object claimed after the check was deleted")
	assert.False(t, mem.has(orphanKey), "an object nothing references was kept")
	assert.Equal(t, 1, result.FixedOrphaned)
}
