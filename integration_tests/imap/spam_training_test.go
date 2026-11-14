//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/spamtraining"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// These tests run on setupSpamTrainingServer: an APPENDed message is uploaded to the
// fake S3 before the APPEND completes and no local copy is kept, so a training
// worker downloads every moved body from S3.

// checkTraining reports a submission that is not the whole message with this subject
// and body, moved by user from source to dest and trained as typ.
func checkTraining(t *testing.T, req spamtraining.TrainingRequest, typ spamtraining.TrainingType, user, source, dest, subject, body string) {
	t.Helper()
	if req.Type != typ || req.User != user || req.SourceMailbox != source || req.DestMailbox != dest {
		t.Errorf("training submission type=%q user=%q source=%q dest=%q, want type=%q user=%q source=%q dest=%q",
			req.Type, req.User, req.SourceMailbox, req.DestMailbox, typ, user, source, dest)
	}
	if !strings.Contains(req.Message, "Subject: "+subject+"\r\n") || !strings.Contains(req.Message, "\r\n\r\n"+body) {
		t.Errorf("training submission does not hold the message with subject %q and body %q: %q", subject, body, req.Message)
	}
}

// Moving a message into Junk submits it as spam.
func TestIMAP_SpamTraining_MoveToJunk(t *testing.T) {
	c, fakeS3, endpoint, account := setupSpamTrainingServer(t, config.SpamTrainingConfig{AuthToken: "test-token-123"})
	appendToMailbox(t, c, "INBOX", trainingMessage(account.Email, "Spam Test Message", "This is a spam test message."))
	getsBefore := fakeS3.GetCount()

	if _, err := c.Move(imap.SeqSetNum(1), "Junk").Wait(); err != nil {
		t.Fatalf("MOVE to Junk: %v", err)
	}

	got := endpoint.waitForTraining(t, 1, 10*time.Second)
	if len(got) != 1 {
		t.Fatalf("training endpoint received %d submissions, want 1", len(got))
	}
	checkTraining(t, got[0], spamtraining.TrainingTypeSpam, account.Email, "INBOX", "Junk", "Spam Test Message", "This is a spam test message.")
	if auth := endpoint.authorizations()[0]; auth != "Bearer test-token-123" {
		t.Errorf("training request Authorization %q, want %q", auth, "Bearer test-token-123")
	}
	if gets := fakeS3.GetCount() - getsBefore; gets != 1 {
		t.Errorf("%d S3 downloads, want 1: the moved body is only in S3", gets)
	}
}

// Moving a message out of Junk submits it as ham.
func TestIMAP_SpamTraining_MoveFromJunk(t *testing.T) {
	c, fakeS3, endpoint, account := setupSpamTrainingServer(t, config.SpamTrainingConfig{})
	appendToMailbox(t, c, "Junk", trainingMessage(account.Email, "Ham Test Message", "This is a legitimate message."))
	if _, err := c.Select("Junk", nil).Wait(); err != nil {
		t.Fatalf("SELECT Junk: %v", err)
	}
	getsBefore := fakeS3.GetCount()

	if _, err := c.Move(imap.SeqSetNum(1), "INBOX").Wait(); err != nil {
		t.Fatalf("MOVE from Junk: %v", err)
	}

	got := endpoint.waitForTraining(t, 1, 10*time.Second)
	if len(got) != 1 {
		t.Fatalf("training endpoint received %d submissions, want 1", len(got))
	}
	checkTraining(t, got[0], spamtraining.TrainingTypeHam, account.Email, "Junk", "INBOX", "Ham Test Message", "This is a legitimate message.")
	if gets := fakeS3.GetCount() - getsBefore; gets != 1 {
		t.Errorf("%d S3 downloads, want 1: the moved body is only in S3", gets)
	}
}

// A MOVE that neither enters nor leaves Junk is not trained on.
func TestIMAP_SpamTraining_NoTrainingForRegularMoves(t *testing.T) {
	// One worker runs the jobs in the order the MOVEs queued them, so when the
	// second MOVE's submission arrives, one queued by the first would have too.
	c, fakeS3, endpoint, account := setupSpamTrainingServer(t, config.SpamTrainingConfig{Workers: 1})
	if err := c.Create("Archive", nil).Wait(); err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("CREATE Archive: %v", err)
	}
	appendToMailbox(t, c, "INBOX", trainingMessage(account.Email, "Regular Message", "Regular message content."))
	appendToMailbox(t, c, "INBOX", trainingMessage(account.Email, "Spam Message", "Buy now."))
	getsBefore := fakeS3.GetCount()

	if _, err := c.Move(imap.SeqSetNum(1), "Archive").Wait(); err != nil {
		t.Fatalf("MOVE to Archive: %v", err)
	}
	if _, err := c.Move(imap.SeqSetNum(1), "Junk").Wait(); err != nil {
		t.Fatalf("MOVE to Junk: %v", err)
	}

	got := endpoint.waitForTraining(t, 1, 10*time.Second)
	if len(got) != 1 {
		t.Fatalf("training endpoint received %d submissions, want 1 (the message moved to Junk)", len(got))
	}
	checkTraining(t, got[0], spamtraining.TrainingTypeSpam, account.Email, "INBOX", "Junk", "Spam Message", "Buy now.")
	if gets := fakeS3.GetCount() - getsBefore; gets != 1 {
		t.Errorf("%d S3 downloads, want 1: the message moved to Archive must not be fetched", gets)
	}
}

// After threshold consecutive failed submissions the circuit breaker opens, and the
// messages moved next are neither submitted nor downloaded.
func TestIMAP_SpamTraining_CircuitBreakerFailure(t *testing.T) {
	const threshold = 5
	const afterOpen = 3
	// One worker: a job's failure is counted by the breaker before the next job starts.
	// The breaker's timeout outlasts the test, so it does not half-open.
	c, fakeS3, endpoint, account := setupSpamTrainingServer(t, config.SpamTrainingConfig{
		Workers:        1,
		CircuitBreaker: config.SpamTrainingCircuitBreakerConfig{Threshold: threshold, Timeout: "1m"},
	})
	endpoint.failing.Store(true)
	for i := 1; i <= threshold+afterOpen; i++ {
		appendToMailbox(t, c, "INBOX", trainingMessage(account.Email, fmt.Sprintf("Spam %d", i), "Buy now."))
	}
	failed := metrics.SpamTrainingMessagesTotal.WithLabelValues("failed")
	failedBefore := testutil.ToFloat64(failed)
	getsBefore := fakeS3.GetCount()

	moveAllToJunk(t, c)

	// Every job ends as failed: refused by the endpoint, then by the open breaker.
	jobs := float64(threshold + afterOpen)
	deadline := time.Now().Add(10 * time.Second)
	for testutil.ToFloat64(failed)-failedBefore < jobs && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if done := testutil.ToFloat64(failed) - failedBefore; done != jobs {
		t.Fatalf("%v training jobs failed, want %v", done, jobs)
	}
	if n := len(endpoint.received()); n != threshold {
		t.Errorf("training endpoint received %d submissions, want %d: the breaker must open after %d consecutive failures", n, threshold, threshold)
	}
	if gets := fakeS3.GetCount() - getsBefore; gets != threshold {
		t.Errorf("%d S3 downloads, want %d: no body is fetched while the breaker is open", gets, threshold)
	}
}

// Without a spam training client, a MOVE into Junk fetches nothing.
func TestIMAP_SpamTraining_Disabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account, fakeS3 := common.SetupIMAPServerWithRealS3(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := c.Create("Junk", nil).Wait(); err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("CREATE Junk: %v", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX: %v", err)
	}
	appendToMailbox(t, c, "INBOX", trainingMessage(account.Email, "Test Message", "Test content."))
	getsBefore := fakeS3.GetCount()

	if _, err := c.Move(imap.SeqSetNum(1), "Junk").Wait(); err != nil {
		t.Fatalf("MOVE to Junk: %v", err)
	}

	// The MOVE queues training before it completes, so there is nothing to wait for.
	if gets := fakeS3.GetCount() - getsBefore; gets != 0 {
		t.Errorf("%d S3 downloads after a MOVE to Junk with spam training disabled, want 0", gets)
	}
}
