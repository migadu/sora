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
	server  *httptest.Server
	mu      sync.Mutex
	objects map[string][]byte
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
		f.mu.Unlock()
		if !ok {
			writeS3Error(w, http.StatusNotFound, "NoSuchKey", key)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("ETag", etag(data))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)

	case http.MethodDelete:
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
