package spamtraining

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const testMessage = "From: sender@example.org\r\nTo: user@example.com\r\nSubject: Buy now\r\n\r\nCheap.\r\n"

// recordingEndpoint is a training service that counts and keeps what it is sent.
type recordingEndpoint struct {
	mu       sync.Mutex
	requests []TrainingRequest
	bodies   [][]byte // the request bodies as sent
}

func (e *recordingEndpoint) received() []TrainingRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]TrainingRequest(nil), e.requests...)
}

func (e *recordingEndpoint) receivedBodies() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([][]byte(nil), e.bodies...)
}

func (e *recordingEndpoint) waitFor(t *testing.T, n int) []TrainingRequest {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := e.received()
		if len(got) >= n || time.Now().After(deadline) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// newTestClient starts a client against a recording endpoint. cfg's Enabled and
// Endpoint are filled in.
func newTestClient(t *testing.T, cfg config.SpamTrainingConfig) (*Client, *recordingEndpoint) {
	t.Helper()
	e := &recordingEndpoint{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading training request: %v", err)
		}
		var req TrainingRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("training request does not decode: %v", err)
		}
		e.mu.Lock()
		e.requests = append(e.requests, req)
		e.bodies = append(e.bodies, body)
		e.mu.Unlock()
	}))
	t.Cleanup(srv.Close)

	cfg.Enabled = true
	cfg.Endpoint = srv.URL
	c, err := NewClient(&cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(c.Close)
	return c, e
}

func openString(s string) func(context.Context) (io.ReadCloser, error) {
	return func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(s)), nil
	}
}

// A MOVE of many messages hands the client one job per message. However many there
// are, no more than `workers` bodies may be fetched at once.
func TestEnqueueFetchesAtMostWorkersBodiesAtOnce(t *testing.T) {
	const workers, jobs = 2, 10
	c, endpoint := newTestClient(t, config.SpamTrainingConfig{Workers: workers, QueueSize: jobs})

	release := make(chan struct{})
	var inFlight, peak atomic.Int32
	open := func(context.Context) (io.ReadCloser, error) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		<-release
		return io.NopCloser(strings.NewReader(testMessage)), nil
	}

	for i := 0; i < jobs; i++ {
		if err := c.Enqueue(Job{Type: TrainingTypeSpam, User: "user@example.com", Size: int64(len(testMessage)), Open: open}); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}
	time.Sleep(200 * time.Millisecond) // every job that can start has started
	if got := peak.Load(); got != workers {
		t.Errorf("%d bodies fetched at once, want %d (the worker count)", got, workers)
	}
	close(release)

	if got := endpoint.waitFor(t, jobs); len(got) != jobs {
		t.Fatalf("endpoint received %d submissions, want %d", len(got), jobs)
	}
	if got := peak.Load(); got > workers {
		t.Errorf("%d bodies fetched at once, want at most %d", got, workers)
	}
}

// With every worker busy and the queue full, a job is dropped at once (and counted),
// rather than queued without bound or blocking the IMAP command.
func TestEnqueueDropsWhenQueueIsFull(t *testing.T) {
	c, endpoint := newTestClient(t, config.SpamTrainingConfig{Workers: 1, QueueSize: 2})
	dropped := metrics.SpamTrainingMessagesTotal.WithLabelValues("dropped")
	droppedBefore := testutil.ToFloat64(dropped)

	started := make(chan struct{})
	release := make(chan struct{})
	blocking := func(context.Context) (io.ReadCloser, error) {
		close(started)
		<-release
		return io.NopCloser(strings.NewReader(testMessage)), nil
	}
	job := Job{Type: TrainingTypeSpam, User: "user@example.com", Size: int64(len(testMessage)), Open: openString(testMessage)}

	busy := job
	busy.Open = blocking
	if err := c.Enqueue(busy); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	<-started // the only worker is busy

	for i := 0; i < 2; i++ {
		if err := c.Enqueue(job); err != nil {
			t.Fatalf("Enqueue into a queue with room: %v", err)
		}
	}
	if err := c.Enqueue(job); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("Enqueue into a full queue = %v, want ErrQueueFull", err)
	}
	if got := testutil.ToFloat64(dropped) - droppedBefore; got != 1 {
		t.Errorf("dropped counter rose by %v, want 1", got)
	}

	close(release)
	if got := endpoint.waitFor(t, 3); len(got) != 3 {
		t.Fatalf("endpoint received %d submissions, want 3 (the busy job and the two queued)", len(got))
	}
}

// A message whose stored size is over max_message_size is refused before its body is
// fetched.
func TestEnqueueRefusesOversizedMessageWithoutFetchingIt(t *testing.T) {
	c, endpoint := newTestClient(t, config.SpamTrainingConfig{MaxMessageSize: "1kb"})

	var opened atomic.Bool
	open := func(context.Context) (io.ReadCloser, error) {
		opened.Store(true)
		return io.NopCloser(strings.NewReader(testMessage)), nil
	}
	err := c.Enqueue(Job{Type: TrainingTypeSpam, User: "user@example.com", Size: 1025, Open: open})
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("Enqueue of a 1025-byte message with max_message_size 1kb = %v, want ErrMessageTooLarge", err)
	}

	if err := c.Enqueue(Job{Type: TrainingTypeSpam, User: "user@example.com", Size: 1024, Open: openString(testMessage)}); err != nil {
		t.Fatalf("Enqueue of a message at the limit: %v", err)
	}
	if got := endpoint.waitFor(t, 1); len(got) != 1 {
		t.Fatalf("endpoint received %d submissions, want 1", len(got))
	}
	if opened.Load() {
		t.Error("the oversized message's body was fetched")
	}
}

// countingReader serves n bytes and records how many were read and when it was closed.
type countingReader struct {
	remaining int64
	read      atomic.Int64
	closed    chan struct{}
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := min(int64(len(p)), r.remaining)
	for i := range p[:n] {
		p[i] = 'x'
	}
	r.remaining -= n
	r.read.Add(n)
	return int(n), nil
}

func (r *countingReader) Close() error {
	close(r.closed)
	return nil
}

// The stored size can be wrong. The body is read through a limit, so a worker never
// holds more than max_message_size + 1 bytes of it, and an oversized body is not sent.
func TestWorkerReadsAtMostMaxMessageSize(t *testing.T) {
	c, endpoint := newTestClient(t, config.SpamTrainingConfig{MaxMessageSize: "1kb"})

	body := &countingReader{remaining: 1 << 20, closed: make(chan struct{})}
	err := c.Enqueue(Job{
		Type: TrainingTypeSpam, User: "user@example.com",
		Size: 100, // the row understates the body
		Open: func(context.Context) (io.ReadCloser, error) { return body, nil },
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	select {
	case <-body.closed:
	case <-time.After(10 * time.Second):
		t.Fatal("the worker never closed the body")
	}
	c.Close() // waits for the worker to finish the job

	if got := body.read.Load(); got > 1025 {
		t.Errorf("worker read %d bytes of the body, want at most 1025", got)
	}
	if got := endpoint.received(); len(got) != 0 {
		t.Errorf("an oversized body was submitted %d times", len(got))
	}
}

// Workers send the message as it was fetched, with the job's metadata.
func TestWorkerSubmitsTheFetchedMessage(t *testing.T) {
	c, endpoint := newTestClient(t, config.SpamTrainingConfig{})
	err := c.Enqueue(Job{
		Type: TrainingTypeHam, User: "user@example.com", SourceMailbox: "Junk", DestMailbox: "INBOX",
		Size: int64(len(testMessage)), Open: openString(testMessage),
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	got := endpoint.waitFor(t, 1)
	if len(got) != 1 {
		t.Fatalf("endpoint received %d submissions, want 1", len(got))
	}
	req := got[0]
	if req.Type != TrainingTypeHam || req.User != "user@example.com" || req.SourceMailbox != "Junk" ||
		req.DestMailbox != "INBOX" || req.Message != testMessage || req.Timestamp.IsZero() {
		t.Errorf("unexpected submission: %+v", req)
	}
}

// TestSubmittedMessageKeepsItsBytes: a JSON string is Unicode, and json.Marshal
// replaces every byte that is not valid UTF-8 with U+FFFD. 8-bit text in any other
// charset, in a body, a part kept from a multipart or a raw header value, must
// still reach the endpoint byte for byte: in message_base64, with message as it
// was for receivers that do not read message_base64. A UTF-8 message is exact in
// message and its request has no message_base64.
func TestSubmittedMessageKeepsItsBytes(t *testing.T) {
	multipart := "Subject: x\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain; charset=windows-1251\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" +
		"\xcf\xf0\xe8\xe2\xe5\xf2\r\n" +
		"--b\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nAAAA\r\n" +
		"--b--\r\n"
	strippedMultipart, err := StripAttachments([]byte(multipart))
	if err != nil {
		t.Fatalf("StripAttachments: %v", err)
	}

	tests := []struct {
		name    string
		message string // as fetched
		want    string // as it must reach the endpoint
		lossy   bool   // not valid UTF-8
	}{{
		name:    "8-bit iso-8859-1 single part",
		message: "Subject: test\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\nSch\xf6n\r\n",
		lossy:   true,
	}, {
		name:    "raw 8-bit header value",
		message: "Subject: Sch\xf6n\r\nFrom: sender@example.org\r\n\r\nbody\r\n",
		lossy:   true,
	}, {
		name:    "8-bit windows-1251 part kept from a multipart",
		message: multipart,
		want:    string(strippedMultipart),
		lossy:   true,
	}, {
		name:    "UTF-8",
		message: "Subject: Schön\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nSchön <&>\r\n",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.want
			if want == "" {
				want = tc.message
			}
			c, endpoint := newTestClient(t, config.SpamTrainingConfig{})
			err := c.Enqueue(Job{Type: TrainingTypeSpam, User: "user@example.com",
				Size: int64(len(tc.message)), Open: openString(tc.message)})
			if err != nil {
				t.Fatalf("Enqueue: %v", err)
			}
			if got := endpoint.waitFor(t, 1); len(got) != 1 {
				t.Fatalf("endpoint received %d submissions, want 1", len(got))
			}

			// Decoded as a receiver outside this package would.
			var wire struct {
				Message       string  `json:"message"`
				MessageBase64 *string `json:"message_base64"`
			}
			if err := json.Unmarshal(endpoint.receivedBodies()[0], &wire); err != nil {
				t.Fatalf("decoding the request: %v", err)
			}

			if !tc.lossy {
				if wire.MessageBase64 != nil {
					t.Errorf("a UTF-8 message was also sent in message_base64")
				}
				if wire.Message != want {
					t.Errorf("message = %q, want %q", wire.Message, want)
				}
				return
			}

			// message is what it always was: the text with each invalid byte replaced.
			var asBefore string
			b, _ := json.Marshal(want)
			_ = json.Unmarshal(b, &asBefore)
			if wire.Message != asBefore {
				t.Errorf("message = %q, want %q (unchanged for receivers that do not read message_base64)", wire.Message, asBefore)
			}
			if wire.MessageBase64 == nil {
				t.Fatalf("no message_base64: the endpoint received only %q, the message was %q", wire.Message, want)
			}
			got, err := base64.StdEncoding.DecodeString(*wire.MessageBase64)
			if err != nil {
				t.Fatalf("message_base64 is not standard base64: %v", err)
			}
			if string(got) != want {
				t.Errorf("message_base64 decodes to %q, want %q", got, want)
			}
		})
	}
}

func TestCloseStopsWorkersAndRefusesJobs(t *testing.T) {
	c, endpoint := newTestClient(t, config.SpamTrainingConfig{Workers: 3})
	c.Close()
	c.Close() // idempotent

	err := c.Enqueue(Job{Type: TrainingTypeSpam, User: "user@example.com", Size: int64(len(testMessage)), Open: openString(testMessage)})
	if err == nil {
		t.Fatal("Enqueue after Close succeeded")
	}
	time.Sleep(50 * time.Millisecond)
	if got := endpoint.received(); len(got) != 0 {
		t.Errorf("a job enqueued after Close was submitted")
	}
}

func TestNewClientRejectsInvalidMaxMessageSize(t *testing.T) {
	for _, size := range []string{"0", "lots"} {
		cfg := config.SpamTrainingConfig{Enabled: true, Endpoint: "http://127.0.0.1:1/train", MaxMessageSize: size}
		if c, err := NewClient(&cfg); err == nil {
			c.Close()
			t.Errorf("NewClient accepted max_message_size %q", size)
		}
	}
}

// While the training endpoint is down the circuit breaker is open and refuses every
// submission. A worker must not download a body it cannot send.
func TestOpenCircuitBreakerSkipsTheFetch(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	cfg := config.SpamTrainingConfig{
		Enabled: true, Endpoint: srv.URL, Workers: 1,
		CircuitBreaker: config.SpamTrainingCircuitBreakerConfig{Threshold: 1, Timeout: "1h"},
	}
	c, err := NewClient(&cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(c.Close)

	failed := metrics.SpamTrainingMessagesTotal.WithLabelValues("failed")
	failedBefore := testutil.ToFloat64(failed)
	waitForFailed := func(n float64) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for testutil.ToFloat64(failed)-failedBefore < n {
			if time.Now().After(deadline) {
				t.Fatalf("%v jobs failed, want %v", testutil.ToFloat64(failed)-failedBefore, n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	var opens atomic.Int32
	job := Job{
		Type: TrainingTypeSpam, User: "user@example.com", Size: int64(len(testMessage)),
		Open: func(context.Context) (io.ReadCloser, error) {
			opens.Add(1)
			return io.NopCloser(strings.NewReader(testMessage)), nil
		},
	}

	// The first submission fails and opens the breaker.
	if err := c.Enqueue(job); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	waitForFailed(1)
	if state := c.GetCircuitBreakerState(); state != circuitbreaker.StateOpen {
		t.Fatalf("circuit breaker is %v after a failed submission with threshold 1, want open", state)
	}

	const more = 5
	for i := 0; i < more; i++ {
		if err := c.Enqueue(job); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}
	waitForFailed(1 + more)

	if got := opens.Load(); got != 1 {
		t.Errorf("%d bodies fetched, want 1: with the breaker open the other %d cannot be sent", got, more)
	}
	if got := posts.Load(); got != 1 {
		t.Errorf("endpoint received %d submissions, want 1", got)
	}
}

// TestSubmitTrainingDoesNotFollowRedirects: a 3xx answer to the training POST is not
// an accepted submission. Followed, a 301/302/303 turns the POST into a body-less GET
// whose 2xx counted as accepted, and a 307/308 replayed the message and the bearer
// token to the Location. The 3xx itself must be reported as a failure naming the
// Location.
func TestSubmitTrainingDoesNotFollowRedirects(t *testing.T) {
	for _, status := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var landingHits, landingPosts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/train" {
					http.Redirect(w, r, "/landing", status)
					return
				}
				landingHits.Add(1)
				if r.Method == http.MethodPost {
					landingPosts.Add(1)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			c, err := NewClient(&config.SpamTrainingConfig{
				Enabled:   true,
				Endpoint:  srv.URL + "/train",
				AuthToken: "training-token",
			})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			t.Cleanup(c.Close)

			err = c.SubmitTraining(context.Background(), &TrainingRequest{
				Type:      TrainingTypeSpam,
				Message:   "Subject: x\r\n\r\nbody",
				User:      "user@example.com",
				Timestamp: time.Now(),
			})
			if err == nil {
				t.Fatalf("SubmitTraining = nil after a %d, want an error (a redirect is not an accepted submission); Location was requested %d time(s), %d as POST",
					status, landingHits.Load(), landingPosts.Load())
			}
			if !strings.Contains(err.Error(), "/landing") {
				t.Errorf("error %q does not name the Location", err)
			}
			if n := landingHits.Load(); n != 0 {
				t.Errorf("Location was requested %d time(s), want 0 (redirects must not be followed)", n)
			}
		})
	}
}

// bodyTransport answers every request with status and body, without a network.
type bodyTransport struct {
	status int
	header http.Header
	body   io.ReadCloser
}

func (t *bodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		req.Body.Close()
	}
	return &http.Response{
		Status:        http.StatusText(t.status),
		StatusCode:    t.status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        t.header,
		Body:          t.body,
		ContentLength: -1,
		Request:       req,
	}, nil
}

// TestSubmitTrainingBoundsResponseBody: of the endpoint's answer only the status is
// needed, and for a refusal a short excerpt of the body for the error. However large
// a body an accepted, redirected or refused submission is answered with, only a
// bounded part of it is read, and the body is closed.
func TestSubmitTrainingBoundsResponseBody(t *testing.T) {
	const bodySize = 8 << 20
	const maxRead = 4 << 10
	for _, tc := range []struct {
		status  int
		wantErr bool
	}{
		{http.StatusOK, false},
		{http.StatusFound, true},
		{http.StatusBadRequest, true},
		{http.StatusInternalServerError, true},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			c, err := NewClient(&config.SpamTrainingConfig{Enabled: true, Endpoint: "http://training.example.com/train"})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			t.Cleanup(c.Close)

			body := &countingReader{remaining: bodySize, closed: make(chan struct{})}
			header := http.Header{}
			if tc.status >= 300 && tc.status < 400 {
				header.Set("Location", "http://training.example.com/landing")
			}
			c.httpClient.Transport = &bodyTransport{status: tc.status, header: header, body: body}

			err = c.SubmitTraining(context.Background(), &TrainingRequest{Type: TrainingTypeSpam, Message: "body", User: "user@example.com"})
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("SubmitTraining = %v for a %d answer, want error: %v", err, tc.status, tc.wantErr)
			}
			if got := body.read.Load(); got > maxRead {
				t.Errorf("read %d bytes of a %d-byte response body, want at most %d", got, bodySize, maxRead)
			}
			select {
			case <-body.closed:
			default:
				t.Error("response body was not closed")
			}
			if err == nil {
				return
			}
			if n := len(err.Error()); n > maxRead {
				t.Errorf("error message is %d bytes long, want at most %d", n, maxRead)
			}
			if tc.status >= 400 && !strings.Contains(err.Error(), "xxxx") {
				t.Errorf("error %q does not quote the start of the response body", err)
			}
		})
	}
}

// TestSubmitTrainingReusesConnection: a short answer is read to its end, so the
// transport keeps the connection for the next submission rather than opening a new
// one each time, whether the submission was accepted or refused.
func TestSubmitTrainingReusesConnection(t *testing.T) {
	var conns, requests atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if requests.Add(1) == 2 {
			http.Error(w, "try again later", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)

	c, err := NewClient(&config.SpamTrainingConfig{Enabled: true, Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(c.Close)

	for i, wantErr := range []bool{false, true, false} {
		err := c.SubmitTraining(context.Background(), &TrainingRequest{Type: TrainingTypeSpam, Message: "body", User: "user@example.com"})
		if gotErr := err != nil; gotErr != wantErr {
			t.Fatalf("submission %d = %v, want error: %v", i+1, err, wantErr)
		}
	}
	if got := conns.Load(); got != 1 {
		t.Errorf("3 submissions opened %d connections, want 1", got)
	}
}
