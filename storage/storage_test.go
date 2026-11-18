package storage

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestS3Object_Structure tests the S3Object struct
func TestS3Object_Structure(t *testing.T) {
	now := time.Now()
	obj := S3Object{
		Key:          "example.com/user1/abc123",
		Size:         1024,
		LastModified: now,
		ETag:         "d41d8cd98f00b204e9800998ecf8427e",
	}

	assert.Equal(t, "example.com/user1/abc123", obj.Key)
	assert.Equal(t, int64(1024), obj.Size)
	assert.Equal(t, now, obj.LastModified)
	assert.Equal(t, "d41d8cd98f00b204e9800998ecf8427e", obj.ETag)
}

// listingS3 answers ListObjectsV2 the way S3 does for the parameters ListObjects sends:
// keys in lexical order, prefix, delimiter (keys below a further delimiter are common
// prefixes, not objects) and pages of pageSize entries chained by continuation tokens.
type listingS3 struct {
	mu       sync.Mutex
	keys     []string
	pageSize int
	failPage int // when > 0, the request for this page (1-based) and later ones answer NoSuchBucket
	requests []url.Values
}

func newListingS3(t *testing.T, keys ...string) (*listingS3, *S3Storage) {
	t.Helper()
	isolateAWSEnvironment(t)
	l := &listingS3{keys: slices.Sorted(slices.Values(keys)), pageSize: 1000}
	srv := httptest.NewServer(l)
	t.Cleanup(srv.Close)
	s, err := New(srv.URL, "AKIDEXAMPLE", "secret", "mail", false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l, s
}

func (l *listingS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if r.Method != http.MethodGet || q.Get("list-type") != "2" || strings.Trim(r.URL.Path, "/") != "mail" {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	l.mu.Lock()
	l.requests = append(l.requests, q)
	page := len(l.requests)
	fail := l.failPage > 0 && page >= l.failPage
	keys, pageSize := l.keys, l.pageSize
	l.mu.Unlock()

	if fail {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`)
		return
	}

	prefix, delimiter := q.Get("prefix"), q.Get("delimiter")
	start := 0
	if token := q.Get("continuation-token"); token != "" {
		start, _ = strconv.Atoi(token)
	}

	var b strings.Builder
	var commonPrefixes []string
	entries, next := 0, -1
	for i := start; i < len(keys); i++ {
		key := keys[i]
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if entries == pageSize {
			next = i
			break
		}
		if delimiter != "" {
			if j := strings.Index(key[len(prefix):], delimiter); j >= 0 {
				cp := key[:len(prefix)+j+len(delimiter)]
				if !slices.Contains(commonPrefixes, cp) {
					commonPrefixes = append(commonPrefixes, cp)
					entries++
				}
				continue
			}
		}
		b.WriteString("<Contents><Key>")
		_ = xml.EscapeText(&b, []byte(key))
		fmt.Fprintf(&b, `</Key><Size>%d</Size><ETag>"etag-%d"</ETag><LastModified>2026-01-02T03:04:05.000Z</LastModified></Contents>`, len(key), i)
		entries++
	}
	for _, cp := range commonPrefixes {
		b.WriteString("<CommonPrefixes><Prefix>")
		_ = xml.EscapeText(&b, []byte(cp))
		b.WriteString("</Prefix></CommonPrefixes>")
	}

	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>mail</Name><KeyCount>%d</KeyCount>`, entries)
	if next >= 0 {
		fmt.Fprintf(w, "<IsTruncated>true</IsTruncated><NextContinuationToken>%d</NextContinuationToken>", next)
	} else {
		_, _ = io.WriteString(w, "<IsTruncated>false</IsTruncated>")
	}
	_, _ = io.WriteString(w, b.String()+"</ListBucketResult>")
}

func (l *listingS3) recordedRequests() []url.Values {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.requests)
}

// listAll lists prefix and drains both channels the way the callers do, failing the
// test instead of hanging it if the lister never closes them.
func listAll(t *testing.T, s *S3Storage, prefix string, recursive bool) ([]S3Object, error) {
	t.Helper()
	objectCh, errCh := s.ListObjects(context.Background(), prefix, recursive)
	var objects []S3Object
	timeout := time.After(10 * time.Second)
	for {
		select {
		case obj, ok := <-objectCh:
			if !ok {
				// The lister closes errCh before objectCh, keeping an error it sent.
				return objects, <-errCh
			}
			objects = append(objects, obj)
		case <-timeout:
			t.Fatalf("ListObjects did not close its channels within 10s (%d objects so far)", len(objects))
		}
	}
}

func objectKeys(objects []S3Object) []string {
	keys := make([]string, len(objects))
	for i, o := range objects {
		keys[i] = o.Key
	}
	return keys
}

var listingFixture = []string{
	"example.com/user1/aaa",
	"example.com/user1/bbb",
	"example.com/user1/sub/ccc",
	"example.com/user2/ddd",
	"example.org/user1/eee",
}

// TestListObjects_Prefix: the prefix reaches S3 and only that prefix's objects come
// back, with their size, ETag (unquoted) and modification time; an empty prefix lists
// everything and an unknown one nothing.
func TestListObjects_Prefix(t *testing.T) {
	l, s := newListingS3(t, listingFixture...)

	objects, err := listAll(t, s, "example.com/user1/", true)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	assert.Equal(t, []string{"example.com/user1/aaa", "example.com/user1/bbb", "example.com/user1/sub/ccc"}, objectKeys(objects))
	assert.Equal(t, "example.com/user1/", l.recordedRequests()[0].Get("prefix"))
	if assert.NotEmpty(t, objects) {
		assert.Equal(t, int64(len("example.com/user1/aaa")), objects[0].Size)
		assert.Equal(t, "etag-0", objects[0].ETag)
		assert.Equal(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), objects[0].LastModified)
	}

	objects, err = listAll(t, s, "", true)
	if err != nil {
		t.Fatalf("ListObjects with empty prefix: %v", err)
	}
	assert.Equal(t, listingFixture, objectKeys(objects))

	objects, err = listAll(t, s, "example.net/", true)
	if err != nil {
		t.Fatalf("ListObjects with unknown prefix: %v", err)
	}
	assert.Empty(t, objects)
}

// TestListObjects_Recursive: recursive lists every nested object; non-recursive asks
// S3 for a "/" delimiter, so a "directory" below the prefix is not listed as objects.
func TestListObjects_Recursive(t *testing.T) {
	l, s := newListingS3(t, listingFixture...)

	objects, err := listAll(t, s, "example.com/user1/", true)
	if err != nil {
		t.Fatalf("recursive ListObjects: %v", err)
	}
	assert.Equal(t, []string{"example.com/user1/aaa", "example.com/user1/bbb", "example.com/user1/sub/ccc"}, objectKeys(objects))
	assert.False(t, l.recordedRequests()[0].Has("delimiter"), "recursive listing sent a delimiter")

	objects, err = listAll(t, s, "example.com/user1/", false)
	if err != nil {
		t.Fatalf("non-recursive ListObjects: %v", err)
	}
	assert.Equal(t, []string{"example.com/user1/aaa", "example.com/user1/bbb"}, objectKeys(objects))
	assert.Equal(t, "/", l.recordedRequests()[1].Get("delimiter"))
}

// TestListObjects_EmptyBucket: nothing to list closes both channels with no error.
func TestListObjects_EmptyBucket(t *testing.T) {
	_, s := newListingS3(t)

	objects, err := listAll(t, s, "", true)
	if err != nil {
		t.Fatalf("ListObjects on an empty bucket: %v", err)
	}
	assert.Empty(t, objects)
}

// TestListObjects_LargeResults: S3 answers at most 1000 keys per request; ListObjects
// follows the continuation tokens until the listing is complete, in key order.
func TestListObjects_LargeResults(t *testing.T) {
	keys := make([]string, 2500)
	for i := range keys {
		keys[i] = fmt.Sprintf("example.com/user1/%064d", i)
	}
	l, s := newListingS3(t, keys...)

	objects, err := listAll(t, s, "example.com/user1/", true)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	assert.Equal(t, keys, objectKeys(objects))

	requests := l.recordedRequests()
	if assert.Len(t, requests, 3, "expected one request per 1000-key page") {
		assert.Empty(t, requests[0].Get("continuation-token"))
		assert.Equal(t, "1000", requests[1].Get("continuation-token"))
		assert.Equal(t, "2000", requests[2].Get("continuation-token"))
	}
}

// TestListObjects_ErrorHandling: a failed request is reported on the error channel and
// both channels close; objects from pages that did arrive are still delivered.
func TestListObjects_ErrorHandling(t *testing.T) {
	t.Run("FirstPage", func(t *testing.T) {
		l, s := newListingS3(t, listingFixture...)
		l.failPage = 1

		objects, err := listAll(t, s, "", true)
		if err == nil {
			t.Fatal("ListObjects against a missing bucket reported no error")
		}
		assert.Contains(t, err.Error(), "NoSuchBucket")
		assert.Empty(t, objects)
	})

	t.Run("LaterPage", func(t *testing.T) {
		l, s := newListingS3(t, listingFixture...)
		l.pageSize = 2
		l.failPage = 2

		objects, err := listAll(t, s, "", true)
		if err == nil {
			t.Fatal("a failed second page reported no error")
		}
		assert.Equal(t, listingFixture[:2], objectKeys(objects))
	})
}

// TestListObjects_ContextCancellation: once the caller's context is cancelled the lister
// stops and closes its channels, even if the caller no longer reads objects (the callers
// in cmd/sora-admin verify.go and tls.go return on ctx.Done() without draining).
func TestListObjects_ContextCancellation(t *testing.T) {
	// TODO(#1992): see report. The lister sends on the unbuffered objects channel without
	// watching ctx, so once the caller stops reading its goroutine blocks forever.
	t.Skip("ListObjects ignores cancellation while sending an object; see report on #1992")

	_, s := newListingS3(t, listingFixture...)

	ctx, cancel := context.WithCancel(context.Background())
	objectCh, errCh := s.ListObjects(ctx, "", true)
	<-objectCh // the page has arrived; the lister is now sending the rest of it
	cancel()

	select {
	case <-errCh: // closed (or carrying ctx.Err()) once the lister has returned
	case <-time.After(5 * time.Second):
		t.Fatal("ListObjects kept running after its context was cancelled and the caller stopped reading")
	}
}
