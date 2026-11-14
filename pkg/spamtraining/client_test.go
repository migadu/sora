package spamtraining

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
}

func (e *recordingEndpoint) received() []TrainingRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]TrainingRequest(nil), e.requests...)
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
		var req TrainingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("training request does not decode: %v", err)
		}
		e.mu.Lock()
		e.requests = append(e.requests, req)
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
