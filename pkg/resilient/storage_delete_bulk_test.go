package resilient

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/storage"
)

// deleteObjectsRecorder answers S3 DeleteObjects requests and records how many keys
// each request carried.
type deleteObjectsRecorder struct {
	mu       sync.Mutex
	requests [][]string
}

func (r *deleteObjectsRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	var keys []string
	for _, part := range strings.Split(string(body), "<Key>")[1:] {
		keys = append(keys, part[:strings.Index(part, "</Key>")])
	}

	r.mu.Lock()
	r.requests = append(r.requests, keys)
	r.mu.Unlock()

	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></DeleteResult>`))
}

// TestDeleteBulkWithRetry_SplitsOversizedBatches pins the safety property that makes
// batched deletion usable by the cleaner: every key must actually be sent. S3 caps
// DeleteObjects at 1000 keys and the storage layer drops the overflow with only a log
// line, which would look like success to a caller that then deletes the database rows
// of objects still sitting in the bucket.
func TestDeleteBulkWithRetry_SplitsOversizedBatches(t *testing.T) {
	recorder := &deleteObjectsRecorder{}
	server := httptest.NewServer(recorder)
	defer server.Close()

	s3storage, err := storage.New(strings.TrimPrefix(server.URL, "http://"),
		"test-access-key", "test-secret-key", "test-bucket", false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create test storage: %v", err)
	}

	keys := make([]string, 0, 1500)
	for i := 0; i < 1500; i++ {
		keys = append(keys, fmt.Sprintf("example.com/user/hash%04d", i))
	}

	failures := NewResilientS3Storage(s3storage).DeleteBulkWithRetry(t.Context(), keys)
	if len(failures) != 0 {
		t.Fatalf("expected no failures, got %d: %v", len(failures), failures)
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	var sent []string
	for _, request := range recorder.requests {
		if len(request) > 1000 {
			t.Errorf("request carried %d keys, over S3's 1000-key DeleteObjects limit", len(request))
		}
		sent = append(sent, request...)
	}
	if len(sent) != len(keys) {
		t.Fatalf("sent %d keys to S3, want all %d — the rest would be reported as deleted while still in the bucket", len(sent), len(keys))
	}
	for i, key := range keys {
		if sent[i] != key {
			t.Fatalf("key %d sent as %q, want %q", i, sent[i], key)
		}
	}
}
