package tlsmanager

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// recordingS3 answers every request with 200 and keeps the Authorization headers
// it was sent.
type recordingS3 struct {
	mu   sync.Mutex
	auth []string
}

func newRecordingS3(t *testing.T) (*recordingS3, string) {
	t.Helper()
	rec := &recordingS3{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.auth = append(rec.auth, r.Header.Get("Authorization"))
		rec.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return rec, srv.URL
}

func (r *recordingS3) lastAuthorization() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.auth) == 0 {
		return "<no request>"
	}
	return r.auth[len(r.auth)-1]
}

// isolateAWSEnvironment keeps the developer's or CI's AWS settings out of a test.
func isolateAWSEnvironment(t *testing.T) {
	t.Helper()
	none := filepath.Join(t.TempDir(), "none")
	t.Setenv("AWS_CONFIG_FILE", none)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", none)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	for _, name := range []string{
		"AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION",
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
	} {
		t.Setenv(name, "")
	}
}

// TestS3CacheSignsForTheConfiguredRegion: AWS refuses a SigV4 request signed for
// another region than the bucket's, so a certificate bucket outside us-east-1 needs
// the region to be configurable.
func TestS3CacheSignsForTheConfiguredRegion(t *testing.T) {
	isolateAWSEnvironment(t)

	cases := []struct {
		name, region, want string
	}{
		{name: "configured", region: `region = "eu-central-1"`, want: "/eu-central-1/s3/aws4_request"},
		{name: "default", want: "/us-east-1/s3/aws4_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, endpoint := newRecordingS3(t)
			cfg := decodeS3Config(t, fmt.Sprintf("bucket = \"certs\"\nendpoint = %q\naccess_key = \"AKIDEXAMPLE\"\nsecret_key = \"secret\"\n%s\n",
				endpoint, tc.region))

			if _, err := NewS3Cache(cfg); err != nil {
				t.Fatalf("NewS3Cache: %v", err)
			}
			if auth := rec.lastAuthorization(); !strings.Contains(auth, tc.want) {
				t.Errorf("Authorization = %q, want a credential scope ending in %q", auth, tc.want)
			}
		})
	}
}

// TestS3CacheUsesTheDefaultCredentialChain: without access_key and secret_key the
// cache is documented to take credentials from the AWS default chain (environment,
// shared files, instance role). Unsigned requests are refused by a private bucket.
func TestS3CacheUsesTheDefaultCredentialChain(t *testing.T) {
	isolateAWSEnvironment(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDFROMENVIRONMENT")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret-from-environment")

	rec, endpoint := newRecordingS3(t)
	if _, err := NewS3Cache(config.TLSLetsEncryptS3Config{Bucket: "certs", Endpoint: endpoint}); err != nil {
		t.Fatalf("NewS3Cache: %v", err)
	}
	if auth := rec.lastAuthorization(); !strings.Contains(auth, "Credential=AKIDFROMENVIRONMENT/") {
		t.Errorf("Authorization = %q, want a signature with the key from the environment", auth)
	}
}

// syncBuffer is a bytes.Buffer safe for concurrent writers.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestS3CacheDebugLogsRequests: debug = true is documented as request/response
// tracing, so the requests must reach the log.
func TestS3CacheDebugLogsRequests(t *testing.T) {
	isolateAWSEnvironment(t)
	logs := &syncBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { logger.Swap(prev) })

	_, endpoint := newRecordingS3(t)
	if _, err := NewS3Cache(config.TLSLetsEncryptS3Config{
		Bucket: "certs", Endpoint: endpoint, AccessKey: "AKIDEXAMPLE", SecretKey: "secret", Debug: true,
	}); err != nil {
		t.Fatalf("NewS3Cache: %v", err)
	}
	if !strings.Contains(logs.String(), "HEAD /certs") {
		t.Errorf("debug = true logged no S3 request; log:\n%s", logs.String())
	}
}
