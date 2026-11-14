package storage

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
)

// recordingS3 answers HEAD and PUT with 200 and GET with a fixed body, and keeps the
// Authorization headers it was sent.
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
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("message body"))
			return
		}
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

// headObject sends one request through the client and fails the test if it does not
// reach the stub.
func headObject(t *testing.T, s *S3Storage) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := s.ExistsContext(ctx, "example.com/user/hash"); err != nil {
		t.Fatalf("ExistsContext: %v", err)
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

func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	logs := &syncBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { logger.Swap(prev) })
	return logs
}

// TestNewDebugLogsRequests: [s3] debug = true is documented as request/response
// tracing. The SDK discards the trace unless the client is given a logger.
func TestNewDebugLogsRequests(t *testing.T) {
	isolateAWSEnvironment(t)
	logs := captureLog(t)

	_, endpoint := newRecordingS3(t)
	s, err := New(endpoint, "AKIDEXAMPLE", "secret", "mail", false, true, 5*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	headObject(t, s)

	if !strings.Contains(logs.String(), "HEAD /mail/example.com/user/hash") {
		t.Errorf("debug = true logged no S3 request; log:\n%s", logs.String())
	}
}

// TestNewDebugLogOmitsSignatureAndSessionToken: the request trace goes to the server
// log, so it must not carry what lets a reader of that log replay the request (S3
// accepts the same signed request again while its X-Amz-Date is recent) or sign with
// the deployment's role: the SigV4 signature and the session token. The credential
// scope stays, since it shows the signing region.
func TestNewDebugLogOmitsSignatureAndSessionToken(t *testing.T) {
	isolateAWSEnvironment(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDFROMENVIRONMENT")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret-from-environment")
	t.Setenv("AWS_SESSION_TOKEN", "session-token-from-environment")
	logs := captureLog(t)

	rec, endpoint := newRecordingS3(t)
	s, err := New(endpoint, "", "", "mail", false, true, 5*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	headObject(t, s)

	auth := rec.lastAuthorization()
	_, signature, ok := strings.Cut(auth, "Signature=")
	if !ok || signature == "" {
		t.Fatalf("Authorization = %q, want a SigV4 signature", auth)
	}
	out := logs.String()
	if !strings.Contains(out, "HEAD /mail/example.com/user/hash") {
		t.Fatalf("debug = true logged no S3 request; log:\n%s", out)
	}
	if strings.Contains(out, signature) {
		t.Errorf("debug log carries the request signature %q:\n%s", signature, out)
	}
	if strings.Contains(out, "session-token-from-environment") {
		t.Errorf("debug log carries the session token:\n%s", out)
	}
	if !strings.Contains(out, "Credential=AKIDFROMENVIRONMENT/") || !strings.Contains(out, "/us-east-1/s3/aws4_request") {
		t.Errorf("debug log lost the credential scope; log:\n%s", out)
	}
}

// TestNewWithoutDebugWritesNothingToStderr: the server logs through the logger
// package, and with debug = false the S3 client logs nothing at all - not even the
// SDK's "Response has no supported checksum" warning, which a store that sends no
// checksum header (as the stub, and many S3-compatible stores) causes on every GET.
func TestNewWithoutDebugWritesNothingToStderr(t *testing.T) {
	isolateAWSEnvironment(t)
	logs := captureLog(t)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	stderr := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = stderr })
	captured := make(chan []byte)
	go func() {
		out, _ := io.ReadAll(r)
		captured <- out
	}()

	_, endpoint := newRecordingS3(t)
	s, err := New(endpoint, "AKIDEXAMPLE", "secret", "mail", false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body, err := s.GetContext(ctx, "example.com/user/hash")
	if err != nil {
		t.Fatalf("GetContext: %v", err)
	}
	_, _ = io.ReadAll(body)
	body.Close()

	os.Stderr = stderr
	w.Close()
	if out := <-captured; len(out) != 0 {
		t.Errorf("debug = false wrote to stderr, outside the server log:\n%s", out)
	}
	if strings.Contains(logs.String(), "AWS SDK") {
		t.Errorf("debug = false logged SDK output:\n%s", logs.String())
	}
}

// TestNewSignsForTheConfiguredRegion: AWS refuses a SigV4 request signed for another
// region than the bucket's, so a bucket outside us-east-1 needs [s3] region.
func TestNewSignsForTheConfiguredRegion(t *testing.T) {
	isolateAWSEnvironment(t)

	cases := []struct {
		name string
		env  string
		opts []Option
		want string
	}{
		{name: "configured", opts: []Option{WithRegion("eu-central-1")}, want: "/eu-central-1/s3/aws4_request"},
		{name: "configured over environment", env: "eu-west-2", opts: []Option{WithRegion("eu-central-1")}, want: "/eu-central-1/s3/aws4_request"},
		{name: "environment", env: "eu-west-2", want: "/eu-west-2/s3/aws4_request"},
		{name: "default", want: "/us-east-1/s3/aws4_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AWS_REGION", tc.env)
			rec, endpoint := newRecordingS3(t)
			s, err := New(endpoint, "AKIDEXAMPLE", "secret", "mail", false, false, 5*time.Second, tc.opts...)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			headObject(t, s)
			if auth := rec.lastAuthorization(); !strings.Contains(auth, tc.want) {
				t.Errorf("Authorization = %q, want a credential scope ending in %q", auth, tc.want)
			}
		})
	}
}

// TestNewUsesTheDefaultCredentialChain: without access_key and secret_key the client
// takes credentials from the AWS default chain (environment, shared files, web
// identity, container or instance role) instead of empty static keys, which fail
// every request before it is sent.
func TestNewUsesTheDefaultCredentialChain(t *testing.T) {
	isolateAWSEnvironment(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDFROMENVIRONMENT")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret-from-environment")

	rec, endpoint := newRecordingS3(t)
	s, err := New(endpoint, "", "", "mail", false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	headObject(t, s)
	if auth := rec.lastAuthorization(); !strings.Contains(auth, "Credential=AKIDFROMENVIRONMENT/") {
		t.Errorf("Authorization = %q, want a signature with the key from the environment", auth)
	}
}

// TestNewRefusesMissingCredentials: a client that can sign nothing must fail at
// startup, as the server did when it required both keys, rather than on every
// message read and write.
func TestNewRefusesMissingCredentials(t *testing.T) {
	isolateAWSEnvironment(t)
	_, endpoint := newRecordingS3(t)

	cases := []struct{ name, accessKey, secretKey string }{
		{name: "no keys and an empty default chain"},
		{name: "access key only", accessKey: "AKIDEXAMPLE"},
		{name: "secret key only", secretKey: "secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(endpoint, tc.accessKey, tc.secretKey, "mail", false, false, 5*time.Second); err == nil {
				t.Error("New succeeded without usable credentials")
			}
		})
	}
}
