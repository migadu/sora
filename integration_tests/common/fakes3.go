//go:build integration

package common

import (
	"crypto/md5"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/storage"
)

// FakeS3 is a minimal, in-memory, path-style S3-compatible server that supports
// exactly the operations Sora's storage.S3Storage performs: PutObject, GetObject,
// HeadObject (Exists), CopyObject (server-side copy), and DeleteObject. It is
// bucket-agnostic — any bucket name in the request path is accepted and stripped,
// and objects are keyed by the remainder of the path.
//
// This is NOT a complete S3 implementation; it exists so integration tests can
// exercise the real upload → S3 → fetch and cross-account server-side-copy paths
// end to end without an external S3/minio dependency.
type FakeS3 struct {
	server      *httptest.Server
	mu          sync.Mutex
	objects     map[string][]byte
	hangGets    bool                // when set, GET holds the connection open until the client gives up
	failDeletes bool                // when set, every delete is refused with AccessDenied
	onDelete    func(keys []string) // called before a delete is applied, outside the lock
}

// HangGets makes every GET block until the requesting client disconnects, simulating a
// provider that accepts connections but never answers. Existence checks and writes
// keep working. Pass false to restore normal service.
func (f *FakeS3) HangGets(hang bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hangGets = hang
}

// FailDeletes makes every DeleteObject and every key of a DeleteObjects request fail
// with AccessDenied, like a provider rejecting the credentials. Pass false to restore.
func (f *FakeS3) FailDeletes(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failDeletes = fail
}

// OnDelete registers fn to run with the requested keys before each delete request is
// applied, so a test can make something happen in the middle of a deletion. nil clears it.
func (f *FakeS3) OnDelete(fn func(keys []string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onDelete = fn
}

// Keys returns the stored keys that start with prefix.
func (f *FakeS3) Keys(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys
}

// NewFakeS3 starts an in-memory S3 server and returns it. Call Close (or rely on
// the cleanup wired by SetupIMAPServerWithRealS3) to shut it down.
func NewFakeS3() *FakeS3 {
	f := &FakeS3{objects: make(map[string][]byte)}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

// Endpoint returns the host:port (no scheme) suitable for storage.New.
func (f *FakeS3) Endpoint() string {
	return strings.TrimPrefix(f.server.URL, "http://")
}

func (f *FakeS3) Close() { f.server.Close() }

// ObjectCount returns the number of stored objects (test diagnostics).
func (f *FakeS3) ObjectCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.objects)
}

// objectKeyFromPath extracts the object key from a path-style URL:
// "/{bucket}/{key...}" -> "{key...}".
func objectKeyFromPath(p string) string {
	p = strings.TrimPrefix(p, "/")
	i := strings.IndexByte(p, '/')
	if i < 0 {
		return "" // bucket-level request, no object key
	}
	return p[i+1:]
}

func (f *FakeS3) handle(w http.ResponseWriter, r *http.Request) {
	key := objectKeyFromPath(r.URL.Path)

	switch r.Method {
	case http.MethodPut:
		// A PUT carrying x-amz-copy-source is a server-side CopyObject; otherwise
		// it is a normal PutObject.
		if src := r.Header.Get("x-amz-copy-source"); src != "" {
			f.copyObject(w, src, key)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeS3Error(w, http.StatusInternalServerError, "InternalError", key)
			return
		}
		f.mu.Lock()
		f.objects[key] = body
		f.mu.Unlock()
		w.Header().Set("ETag", etag(body))
		w.WriteHeader(http.StatusOK)

	case http.MethodHead:
		f.mu.Lock()
		data, ok := f.objects[key]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("ETag", etag(data))
		w.WriteHeader(http.StatusOK)

	case http.MethodGet:
		f.mu.Lock()
		data, ok := f.objects[key]
		hang := f.hangGets
		f.mu.Unlock()
		if hang {
			<-r.Context().Done()
			return
		}
		if !ok {
			writeS3Error(w, http.StatusNotFound, "NoSuchKey", key)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("ETag", etag(data))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)

	case http.MethodPost:
		// POST /{bucket}?delete is DeleteObjects, the bulk delete.
		if _, ok := r.URL.Query()["delete"]; !ok || key != "" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		f.deleteObjects(w, r)

	case http.MethodDelete:
		f.mu.Lock()
		hook, fail := f.onDelete, f.failDeletes
		f.mu.Unlock()
		if hook != nil {
			hook([]string{key})
		}
		if fail {
			writeS3Error(w, http.StatusForbidden, "AccessDenied", key)
			return
		}
		f.mu.Lock()
		delete(f.objects, key)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *FakeS3) copyObject(w http.ResponseWriter, copySource, destKey string) {
	// copySource is "{bucket}/{key}", possibly URL-encoded and possibly with a
	// leading '/'. Decode first so an encoded '/' (%2F) collapses back, then strip
	// the bucket segment.
	src := strings.TrimPrefix(copySource, "/")
	if decoded, err := url.PathUnescape(src); err == nil {
		src = decoded
	}
	if i := strings.IndexByte(src, '/'); i >= 0 {
		src = src[i+1:] // strip bucket
	}

	f.mu.Lock()
	data, ok := f.objects[src]
	if ok {
		cp := make([]byte, len(data))
		copy(cp, data)
		f.objects[destKey] = cp
	}
	f.mu.Unlock()

	if !ok {
		writeS3Error(w, http.StatusNotFound, "NoSuchKey", src)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_ = xml.NewEncoder(w).Encode(copyObjectResult{
		ETag:         etag(data),
		LastModified: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	})
}

type copyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

// deleteObjects serves DeleteObjects. Deleting a key that does not exist succeeds, as on
// S3; with FailDeletes every key is reported back as an error.
func (f *FakeS3) deleteObjects(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Objects []struct {
			Key string `xml:"Key"`
		} `xml:"Object"`
	}
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		writeS3Error(w, http.StatusBadRequest, "MalformedXML", "")
		return
	}
	keys := make([]string, len(req.Objects))
	for i, o := range req.Objects {
		keys[i] = o.Key
	}

	f.mu.Lock()
	hook := f.onDelete
	f.mu.Unlock()
	if hook != nil {
		hook(keys)
	}

	var result strings.Builder
	result.WriteString(`<?xml version="1.0" encoding="UTF-8"?><DeleteResult>`)
	f.mu.Lock()
	for _, k := range keys {
		if f.failDeletes {
			fmt.Fprintf(&result, `<Error><Key>%s</Key><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`, k)
			continue
		}
		delete(f.objects, k)
	}
	f.mu.Unlock()
	result.WriteString(`</DeleteResult>`)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, result.String())
}

func etag(b []byte) string { return fmt.Sprintf("%q", fmt.Sprintf("%x", md5.Sum(b))) }

func writeS3Error(w http.ResponseWriter, status int, code, key string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message><Key>%s</Key></Error>`, code, code, key)
}

// NewFakeS3Storage starts a FakeS3 and returns a storage.S3Storage wired to it.
// The FakeS3 is closed via t.Cleanup.
func NewFakeS3Storage(t *testing.T) (*FakeS3, *storage.S3Storage) {
	t.Helper()
	fake := NewFakeS3()
	t.Cleanup(fake.Close)

	s3storage, err := storage.New(
		fake.Endpoint(),
		"test-access-key",
		"test-secret-key",
		"test-bucket",
		false, // useSSL
		false, // debug
		10*time.Second,
	)
	if err != nil {
		t.Fatalf("Failed to create S3 storage against fake S3: %v", err)
	}
	return fake, s3storage
}
