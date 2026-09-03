package resilient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A GET used to run on a background context: a caller's deadline or disconnect could
// not end an attempt in flight, so against a provider that accepts connections and
// never answers, one body fetch cost the full operation timeout per attempt — minutes
// for one FETCH, while the IMAP client had long reported the server as not responding.
func TestGetWithRetry_HonorsCallerDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // hold the connection until the client gives up
	}))
	defer server.Close()

	s3storage, err := storage.New(strings.TrimPrefix(server.URL, "http://"),
		"test-access-key", "test-secret-key", "test-bucket", false, false, 5*time.Second)
	require.NoError(t, err)
	rs := NewResilientS3Storage(s3storage)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	reader, err := rs.GetWithRetry(ctx, "some/key")
	elapsed := time.Since(start)

	require.Error(t, err)
	if reader != nil {
		reader.Close()
	}
	assert.Less(t, elapsed, 2*time.Second, "the caller's deadline must end the attempt in flight, not the 5s operation timeout")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}
