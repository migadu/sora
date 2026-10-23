//go:build integration

package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
)

// gatedUploaderS3 is the stack's S3 with every PUT held until the test releases it.
type gatedUploaderS3 struct {
	*resilient.ResilientS3Storage
	started     chan struct{} // closed when the first PUT begins
	release     chan struct{} // PUTs wait for this to close
	startedOnce sync.Once
}

func (g *gatedUploaderS3) PutWithRetry(ctx context.Context, key string, r io.Reader, size int64) error {
	g.startedOnce.Do(func() { close(g.started) })
	<-g.release
	return g.ResilientS3Storage.PutWithRetry(ctx, key, r, size)
}

// uploadInFlight is a delivered body whose upload is held mid-PUT.
type uploadInFlight struct {
	key      string
	release  func()
	finished chan struct{}
	drainErr error
}

// startUploadInFlight delivers one body to the account's INBOX and starts a real upload
// worker on it, returning once the PUT has begun and is being held.
func (s *purgeStack) startUploadInFlight(t *testing.T, accountID int64, email string) *uploadInFlight {
	t.Helper()
	ctx := context.Background()
	gated := &gatedUploaderS3{
		ResilientS3Storage: resilient.NewResilientS3Storage(s.st),
		started:            make(chan struct{}),
		release:            make(chan struct{}),
	}
	// The worker's own instance id: it leases only this test's row, never one another
	// test left in the shared database.
	instanceID := "purge-flight-" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")
	worker, err := uploader.NewWithS3Interface(t.TempDir(), 10, 1, 5, 30*time.Second, 0, instanceID, s.rdb, gated, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte("Subject: in flight\r\n\r\nbody in flight " + email)
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	if _, err := worker.StoreLocally(hash, accountID, body); err != nil {
		t.Fatal(err)
	}
	mailbox, err := s.rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	local, domain, _ := strings.Cut(email, "@")
	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
	if _, _, err := s.rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
		AccountID: accountID, MailboxID: mailbox.ID, MailboxName: "INBOX",
		S3Domain: domain, S3Localpart: local, ContentHash: hash,
		MessageID: "<in-flight@example.com>", InternalDate: time.Now(),
		Size: int64(len(body)), PlaintextBody: "body in flight", BodyStructure: &bs,
	}, db.PendingUpload{InstanceID: instanceID, ContentHash: hash, Size: int64(len(body)), AccountID: accountID}); err != nil {
		t.Fatal(err)
	}

	u := &uploadInFlight{
		key:      domain + "/" + local + "/" + hash,
		release:  sync.OnceFunc(func() { close(gated.release) }),
		finished: make(chan struct{}),
	}
	go func() {
		defer close(u.finished)
		u.drainErr = worker.DrainSync(ctx)
	}()
	// Whatever happens in the test, let the upload finish before the stack closes the
	// database.
	t.Cleanup(func() {
		u.release()
		select {
		case <-u.finished:
		case <-time.After(30 * time.Second):
		}
	})
	select {
	case <-gated.started:
	case <-time.After(30 * time.Second):
		t.Fatal("the upload never reached S3")
	}
	return u
}

// finish lets the held PUT land and waits for the upload to finalize.
func (u *uploadInFlight) finish(t *testing.T) {
	t.Helper()
	u.release()
	select {
	case <-u.finished:
		if u.drainErr != nil {
			t.Fatalf("drain: %v", u.drainErr)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the upload did not finish")
	}
}

// An upload holds no lock across its transfer, so a purge that runs while a body is in
// flight deletes the account's rows and keys without waiting for it, and the write lands
// afterwards. The uploader learns at the finalize that the pending row it leased is gone
// and removes what it wrote: nothing of the account may be left, in the database or in S3.
func TestPurgeWorker_UploadInFlightLeavesNothingBehind(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "worker-flight", "worker-pass-8")
	s.addMessage(t, accountID, email, "settled", true)
	upload := s.startUploadInFlight(t, accountID, email)

	// The purge runs to the end while the body is in flight: nothing holds its lock.
	s.requestPurge(t, email)
	s.runWorker(t)
	if n := s.count(t, "accounts", accountID); n != 0 {
		t.Fatal("the purge waited on the upload in flight instead of finishing")
	}

	upload.finish(t)
	s.requireGone(t, accountID, email)
}

// The background cleaner hard-deletes an account soft-deleted past its grace period in
// steps: messages expunged, then mailboxes and pending uploads removed, and only later the
// S3 phase, which lists uploaded rows only. If an upload is mid-PUT when the pending row
// goes, its rows are still there at the finalize — expunged, never marked uploaded,
// with no pending row — and CleanupFailedUploads will reap them without touching S3. Such
// rows must not count as references: the uploader removes the object itself, or nothing
// ever will.
func TestHardDelete_UploadInFlightRemovesWhatItWrote(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "hard-flight", "worker-pass-9")
	upload := s.startUploadInFlight(t, accountID, email)

	// Soft-delete, then run the background cleaner's hard delete of the account.
	s.request(t, "DELETE", "/admin/accounts/"+email, nil, http.StatusOK)
	if err := s.rdb.HardDeleteAccountWithRetry(context.Background(), accountID); err != nil {
		t.Fatalf("hard delete: %v", err)
	}
	if n := s.count(t, "pending_uploads", accountID); n != 0 {
		t.Fatalf("the hard delete left %d pending uploads", n)
	}

	upload.finish(t)
	if keys := s.s3.Keys(upload.key); len(keys) != 0 {
		t.Errorf("the body of an abandoned upload was left in S3 with only reapable rows pointing at it: %v", keys)
	}
}
