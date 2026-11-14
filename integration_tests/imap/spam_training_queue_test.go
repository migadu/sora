//go:build integration

package imap_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/spamtraining"
	imapserver "github.com/migadu/sora/server/imap"
)

// trainingEndpoint is a spam training service that records what it is sent.
type trainingEndpoint struct {
	mu       sync.Mutex
	requests []spamtraining.TrainingRequest
}

func newTrainingEndpoint(t *testing.T) (*trainingEndpoint, string) {
	t.Helper()
	e := &trainingEndpoint{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req spamtraining.TrainingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("training request does not decode: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		e.mu.Lock()
		e.requests = append(e.requests, req)
		e.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return e, srv.URL
}

func (e *trainingEndpoint) received() []spamtraining.TrainingRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]spamtraining.TrainingRequest(nil), e.requests...)
}

// waitForTraining waits until the endpoint has received want requests.
func (e *trainingEndpoint) waitForTraining(t *testing.T, want int, timeout time.Duration) []spamtraining.TrainingRequest {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got := e.received()
		if len(got) >= want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// setupSpamTrainingServer starts an IMAP server whose bodies live in a fake S3 and
// whose spam training goes to a recording endpoint, and logs a client in with a Junk
// mailbox created and INBOX selected.
func setupSpamTrainingServer(t *testing.T, cfg config.SpamTrainingConfig) (*imapclient.Client, *common.FakeS3, *trainingEndpoint, common.TestAccount) {
	t.Helper()
	common.SkipIfDatabaseUnavailable(t)

	endpoint, url := newTrainingEndpoint(t)
	cfg.Enabled = true
	cfg.Endpoint = url
	client, err := spamtraining.NewClient(&cfg)
	if err != nil {
		t.Fatalf("spamtraining.NewClient: %v", err)
	}
	t.Cleanup(client.Close)

	server, account, fakeS3 := common.SetupIMAPServerWithRealS3Options(t, func(o *imapserver.IMAPServerOptions) {
		o.SpamTraining = client
	})
	t.Cleanup(server.Close)

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Logout() })
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := c.Create("Junk", nil).Wait(); err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("CREATE Junk: %v", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX: %v", err)
	}
	return c, fakeS3, endpoint, account
}

func appendToInbox(t *testing.T, c *imapclient.Client, msg string) {
	t.Helper()
	cmd := c.Append("INBOX", int64(len(msg)), nil)
	if _, err := cmd.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write: %v", err)
	}
	if err := cmd.Close(); err != nil {
		t.Fatalf("APPEND close: %v", err)
	}
	if _, err := cmd.Wait(); err != nil {
		t.Fatalf("APPEND: %v", err)
	}
}

func trainingMessage(to, subject, body string) string {
	return "From: sender@example.org\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"\r\n" +
		body + "\r\n"
}

func moveAllToJunk(t *testing.T, c *imapclient.Client) {
	t.Helper()
	var all imap.SeqSet
	all.AddRange(1, 0) // 1:*
	if _, err := c.Move(all, "Junk").Wait(); err != nil {
		t.Fatalf("MOVE 1:* Junk: %v", err)
	}
}

// One MOVE of many messages into Junk used to start a goroutine, and an S3 download,
// per message, all at once. The downloads must go through the fixed worker pool.
func TestIMAP_SpamTraining_MoveDoesNotDownloadEveryMessageAtOnce(t *testing.T) {
	const moved = 20
	const workers = 4 // the default [spam_training] workers

	c, fakeS3, endpoint, account := setupSpamTrainingServer(t, config.SpamTrainingConfig{})
	for i := 0; i < moved; i++ {
		appendToInbox(t, c, trainingMessage(account.Email, fmt.Sprintf("Spam %d", i), "Buy now."))
	}

	// Hold every training download until released, and record how many run at once.
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAll)
	var inFlight, peak atomic.Int32
	fakeS3.OnGet(func(string) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	})
	getsBefore := fakeS3.GetCount()

	moveAllToJunk(t, c)

	// Give every message the chance to start its download.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && peak.Load() < moved {
		time.Sleep(20 * time.Millisecond)
	}
	concurrent := peak.Load()
	releaseAll()

	got := endpoint.waitForTraining(t, moved, 20*time.Second)

	if concurrent > workers {
		t.Errorf("%d training downloads ran at once for a MOVE of %d messages, want at most %d (the worker count)", concurrent, moved, workers)
	}
	if concurrent == 0 {
		t.Errorf("no training download started")
	}
	if len(got) != moved {
		t.Fatalf("training endpoint received %d submissions, want %d", len(got), moved)
	}
	if gets := fakeS3.GetCount() - getsBefore; gets != moved {
		t.Errorf("%d S3 downloads for %d moved messages, want one each", gets, moved)
	}
	for _, req := range got {
		if req.Type != spamtraining.TrainingTypeSpam || req.User != account.Email ||
			req.SourceMailbox != "INBOX" || req.DestMailbox != "Junk" || !strings.Contains(req.Message, "Subject: Spam ") {
			t.Errorf("unexpected training submission: type=%q user=%q source=%q dest=%q message=%q",
				req.Type, req.User, req.SourceMailbox, req.DestMailbox, req.Message)
		}
	}
}

// A message larger than max_message_size must be skipped before its body is fetched.
func TestIMAP_SpamTraining_SkipsOversizedMessageWithoutDownloading(t *testing.T) {
	c, fakeS3, endpoint, account := setupSpamTrainingServer(t, config.SpamTrainingConfig{MaxMessageSize: "2kb"})

	appendToInbox(t, c, trainingMessage(account.Email, "Small spam", "Buy now."))
	appendToInbox(t, c, trainingMessage(account.Email, "Large spam", strings.Repeat("Buy now. ", 1000)))
	getsBefore := fakeS3.GetCount()

	moveAllToJunk(t, c)

	endpoint.waitForTraining(t, 1, 10*time.Second)
	time.Sleep(500 * time.Millisecond) // let a second submission, if any, arrive
	got := endpoint.received()

	if gets := fakeS3.GetCount() - getsBefore; gets != 1 {
		t.Errorf("%d S3 downloads, want 1: the message over max_message_size must not be fetched", gets)
	}
	if len(got) != 1 {
		t.Fatalf("training endpoint received %d submissions, want 1", len(got))
	}
	if !strings.Contains(got[0].Message, "Subject: Small spam") {
		t.Errorf("submitted the wrong message: %q", got[0].Message)
	}
}

// A message moved into Junk before its upload completes must still be trained. Its
// body is only in this node's staging directory, where FETCH finds it; S3 does not
// have it yet, so a training read from S3 alone gets a 404 and the message is lost.
func TestIMAP_SpamTraining_TrainsMessageMovedBeforeUpload(t *testing.T) {
	c, fakeS3, endpoint, account := setupSpamTrainingServer(t, config.SpamTrainingConfig{})
	fakeS3.FailPuts(true) // the upload stalls and the body stays staged on this node

	appendToInbox(t, c, trainingMessage(account.Email, "Spam before upload", "Buy now."))
	if n := fakeS3.ObjectCount(); n != 0 {
		t.Fatalf("%d objects in S3 after APPEND, want 0: the upload must still be pending", n)
	}
	getsBefore := fakeS3.GetCount()

	moveAllToJunk(t, c)

	got := endpoint.waitForTraining(t, 1, 10*time.Second)
	if len(got) != 1 {
		t.Fatalf("training endpoint received %d submissions, want 1: the staged body was not trained", len(got))
	}
	if req := got[0]; req.Type != spamtraining.TrainingTypeSpam || req.User != account.Email ||
		req.SourceMailbox != "INBOX" || req.DestMailbox != "Junk" || !strings.Contains(req.Message, "Subject: Spam before upload") {
		t.Errorf("unexpected training submission: type=%q user=%q source=%q dest=%q message=%q",
			req.Type, req.User, req.SourceMailbox, req.DestMailbox, req.Message)
	}
	if gets := fakeS3.GetCount() - getsBefore; gets != 0 {
		t.Errorf("%d S3 downloads, want 0: a body staged on this node is read from disk", gets)
	}
}
