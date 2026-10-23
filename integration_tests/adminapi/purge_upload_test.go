//go:build integration

package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
)

// An upload holds no lock across its transfer. What keeps account deletion away from a
// body in flight is its pending row, leased to the upload from the write gate to the
// finalize: deletion leaves a leased row alone, the S3 phase refuses a body that has a
// pending row, so the account's rows, and the account itself, outlive the upload. These
// tests hold a real upload mid-PUT and run the real deletion, restore and purge paths
// against it.

// gatedUploaderS3 is the stack's S3 with every PUT held until the test releases it, and
// the PUTs of keys matching fail refused once released.
type gatedUploaderS3 struct {
	*resilient.ResilientS3Storage
	started     chan struct{} // closed when the first PUT begins
	release     chan struct{} // PUTs wait for this to close
	startedOnce sync.Once
	fail        func(key string) bool

	mu   sync.Mutex
	puts []string // every key a PUT was started for
}

// putKeys is every key a PUT was started for, in order.
func (g *gatedUploaderS3) putKeys() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.puts...)
}

func (g *gatedUploaderS3) PutWithRetry(ctx context.Context, key string, r io.Reader, size int64) error {
	g.mu.Lock()
	g.puts = append(g.puts, key)
	g.mu.Unlock()
	g.startedOnce.Do(func() { close(g.started) })
	<-g.release
	if g.fail != nil && g.fail(key) {
		return errors.New("503 SlowDown (test)")
	}
	return g.ResilientS3Storage.PutWithRetry(ctx, key, r, size)
}

// uploadInFlight is a delivered body whose upload is held mid-PUT.
type uploadInFlight struct {
	hash      string
	keys      []string // the primary address's key first
	messageID int64    // the row under the primary address
	release   func()
	finished  chan struct{}
	drainErr  error
}

// startUploadInFlight delivers one body to the account's INBOX, also under each alias
// localpart given (rows of one account can carry several keys), and starts a real upload
// worker on it, returning once the first PUT has begun and is being held. PUTs of keys
// for which fail answers true are refused once released.
func (s *purgeStack) startUploadInFlight(t *testing.T, accountID int64, email string, aliases []string, fail func(key string) bool) *uploadInFlight {
	t.Helper()
	ctx := context.Background()
	gated := &gatedUploaderS3{
		ResilientS3Storage: resilient.NewResilientS3Storage(s.st),
		started:            make(chan struct{}),
		release:            make(chan struct{}),
		fail:               fail,
	}
	// The worker's own instance id: it leases only this test's rows, never one another
	// test left in the shared database.
	instanceID := fmt.Sprintf("purge-flight-%d", time.Now().UnixNano())
	worker, err := uploader.NewWithS3Interface(t.TempDir(), 10, 1, 5, 30*time.Second, 0, instanceID, s.rdb, gated, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte("Subject: in flight\r\n\r\nbody in flight")
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
	u := &uploadInFlight{hash: hash, finished: make(chan struct{})}
	for i, localpart := range append([]string{local}, aliases...) {
		var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
		id, _, err := s.rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID: accountID, MailboxID: mailbox.ID, MailboxName: "INBOX",
			S3Domain: domain, S3Localpart: localpart, ContentHash: hash,
			MessageID: fmt.Sprintf("<in-flight-%d@example.com>", i), InternalDate: time.Now(),
			Size: int64(len(body)), PlaintextBody: "body in flight", BodyStructure: &bs,
		}, db.PendingUpload{InstanceID: instanceID, ContentHash: hash, Size: int64(len(body)), AccountID: accountID})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			u.messageID = id
		}
		u.keys = append(u.keys, domain+"/"+localpart+"/"+hash)
	}

	u.release = sync.OnceFunc(func() { close(gated.release) })
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

// finish lets the held PUTs land and waits for the upload to finalize or fail.
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

// uploadedRows counts the account's rows of the body that are marked uploaded.
func (s *purgeStack) uploadedRows(t *testing.T, accountID int64, hash string) int {
	t.Helper()
	var n int
	if err := s.rdb.QueryRowWithRetry(context.Background(),
		`SELECT count(*) FROM messages WHERE account_id = $1 AND content_hash = $2 AND uploaded`, accountID, hash).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A purge waits for an upload in flight, as it did when the upload held the object's lock,
// and so gives up the address only once nothing of the account can land in S3 any more:
// a new account taking the address, and receiving the same body under the same key, keeps
// it.
func TestPurgeWorker_WaitsForAnUploadInFlight(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "worker-flight", "worker-pass-8")
	s.addMessage(t, accountID, email, "settled", true)
	upload := s.startUploadInFlight(t, accountID, email, nil, nil)

	s.requestPurge(t, email)
	s.runWorker(t)
	s.requireRetryable(t, accountID, email)
	if n := s.count(t, "pending_uploads", accountID); n != 1 {
		t.Fatalf("the purge dropped the pending row of an upload in flight (%d left)", n)
	}

	upload.finish(t)
	if len(s.s3.Keys(upload.keys[0])) != 1 {
		t.Fatal("the upload did not land")
	}
	s.requestPurge(t, email) // clears the backoff the failed pass recorded
	s.runWorker(t)
	s.requireGone(t, accountID, email)

	// The address is free; a new account takes it and receives the same body.
	s.request(t, "POST", "/admin/accounts", map[string]string{"email": email, "password": "worker-pass-8b"}, http.StatusCreated)
	newID, err := s.rdb.GetAccountIDByEmailWithRetry(context.Background(), email)
	if err != nil || newID == accountID {
		t.Fatalf("the address was not reprovisioned as a new account: id=%d err=%v", newID, err)
	}
	if err := s.rdb.CreateDefaultMailboxesWithRetry(context.Background(), newID); err != nil {
		t.Fatal(err)
	}
	again := s.startUploadInFlight(t, newID, email, nil, nil)
	if again.keys[0] != upload.keys[0] {
		t.Fatalf("the test needs the same key under the reused address: %s vs %s", again.keys[0], upload.keys[0])
	}
	again.finish(t)
	if len(s.s3.Keys(again.keys[0])) != 1 || s.uploadedRows(t, newID, again.hash) != 1 {
		t.Fatal("the new account's body is not in place")
	}
}

// The background cleaner's hard delete of a soft-deleted account must leave an upload in
// flight its pending row: the upload finalizes, marking the rows uploaded, and the cleaner
// later lists those rows and deletes the body like any other.
func TestHardDelete_LeavesAnUploadInFlightAlone(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "hard-flight", "worker-pass-9")
	upload := s.startUploadInFlight(t, accountID, email, nil, nil)

	s.request(t, "DELETE", "/admin/accounts/"+email, nil, http.StatusOK)
	if err := s.rdb.HardDeleteAccountWithRetry(context.Background(), accountID); err != nil {
		t.Fatalf("hard delete: %v", err)
	}
	if n := s.count(t, "pending_uploads", accountID); n != 1 {
		t.Fatalf("the hard delete dropped the pending row of an upload in flight (%d left)", n)
	}

	upload.finish(t)
	if n := s.uploadedRows(t, accountID, upload.hash); n != 1 {
		t.Errorf("the upload's rows were not finalized (%d uploaded), so no cleaner pass would list the body", n)
	}
	if n := s.count(t, "pending_uploads", accountID); n != 0 {
		t.Errorf("%d pending rows left after the upload finalized", n)
	}
}

// An account hard-deleted and then restored, with one of its messages, while that
// message's upload is in flight: the upload must finalize the restored message, whose
// body it just wrote, rather than leave it unreadable or delete it.
func TestRestore_KeepsTheUploadInFlight(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "restore-flight", "worker-pass-10")
	upload := s.startUploadInFlight(t, accountID, email, nil, nil)

	s.request(t, "DELETE", "/admin/accounts/"+email, nil, http.StatusOK)
	if err := s.rdb.HardDeleteAccountWithRetry(context.Background(), accountID); err != nil {
		t.Fatalf("hard delete: %v", err)
	}
	s.request(t, "POST", "/admin/accounts/"+email+"/restore", nil, http.StatusOK)
	s.request(t, "POST", "/admin/accounts/"+email+"/messages/restore", map[string]any{"message_ids": []int64{upload.messageID}}, http.StatusOK)

	upload.finish(t)
	var live, uploaded bool
	if err := s.rdb.QueryRowWithRetry(context.Background(),
		`SELECT expunged_at IS NULL, uploaded FROM messages WHERE id = $1`, upload.messageID).Scan(&live, &uploaded); err != nil {
		t.Fatal(err)
	}
	if !live || !uploaded {
		t.Fatalf("the restored message is not readable: live=%v uploaded=%v", live, uploaded)
	}
	if len(s.s3.Keys(upload.keys[0])) != 1 {
		t.Fatal("the restored message's body is not in S3")
	}
}

// One key of a body lands and another is refused, while a purge is waiting on the upload.
// The failed upload gives its lease back, its pending row and rows remain, and the purge's
// next run lists every key the rows carry and deletes the one that landed.
func TestPurgeWorker_RemovesWhatAPartlyFailedUploadWrote(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "partial-flight", "worker-pass-11")
	alias := fmt.Sprintf("alias-%d", time.Now().UnixNano())
	var puts atomic.Int32 // the keys come in no particular order: the second is refused
	upload := s.startUploadInFlight(t, accountID, email, []string{alias}, func(key string) bool {
		return puts.Add(1) > 1
	})

	s.requestPurge(t, email)
	s.runWorker(t)
	s.requireRetryable(t, accountID, email)

	upload.finish(t)
	landed := 0
	for _, key := range upload.keys {
		landed += len(s.s3.Keys(key))
	}
	if landed != 1 {
		t.Fatalf("%d keys landed, want exactly one", landed)
	}
	s.requestPurge(t, email)
	s.runWorker(t)
	s.requireGone(t, accountID, email)
	for _, key := range upload.keys {
		if len(s.s3.Keys(key)) != 0 {
			t.Errorf("%s was left in S3", key)
		}
	}
}

// Two nodes can hold the same pending row: node A's batch leases it while the task waits
// for a free upload slot, and a second delivery of the body on node B re-arms the row for
// B, whose worker leases it and starts writing. When A's task gets its slot, B's lease must
// turn it away — A must neither write the body nor finalize and drop the row under B — and
// a purge must keep waiting for B, so that B's write cannot land after the purge and stay
// in S3 with nothing pointing at it.
func TestTwoNodesNeverUploadTheSameRowAtOnce(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "two-nodes", "worker-pass-12")
	ctx := context.Background()
	mailbox, err := s.rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	local, domain, _ := strings.Cut(email, "@")
	suffix := time.Now().UnixNano()

	newNode := func(name string) (*uploader.UploadWorker, *gatedUploaderS3, string) {
		gated := &gatedUploaderS3{
			ResilientS3Storage: resilient.NewResilientS3Storage(s.st),
			started:            make(chan struct{}),
			release:            make(chan struct{}),
		}
		instanceID := fmt.Sprintf("%s-%d", name, suffix)
		// concurrency 1: a node's second task waits for its first to finish.
		w, err := uploader.NewWithS3Interface(t.TempDir(), 10, 1, 5, 30*time.Second, 0, instanceID, s.rdb, gated, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return w, gated, instanceID
	}
	deliver := func(w *uploader.UploadWorker, instanceID, tag string, body []byte) string {
		sum := sha256.Sum256(body)
		hash := hex.EncodeToString(sum[:])
		if _, err := w.StoreLocally(hash, accountID, body); err != nil {
			t.Fatal(err)
		}
		var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
		if _, _, err := s.rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID: accountID, MailboxID: mailbox.ID, MailboxName: "INBOX",
			S3Domain: domain, S3Localpart: local, ContentHash: hash,
			MessageID: fmt.Sprintf("<%s-%d@example.com>", tag, suffix), InternalDate: time.Now(),
			Size: int64(len(body)), PlaintextBody: tag, BodyStructure: &bs,
		}, db.PendingUpload{InstanceID: instanceID, ContentHash: hash, Size: int64(len(body)), AccountID: accountID}); err != nil {
			t.Fatal(err)
		}
		return domain + "/" + local + "/" + hash
	}
	// drain runs one node's queue; wait returns its error once it has finished.
	drain := func(w *uploader.UploadWorker, gated *gatedUploaderS3) (wait func() error) {
		finished := make(chan struct{})
		var drainErr error
		go func() {
			defer close(finished)
			drainErr = w.DrainSync(ctx)
		}()
		t.Cleanup(func() {
			select {
			case <-gated.release:
			default:
				close(gated.release)
			}
			select {
			case <-finished:
			case <-time.After(30 * time.Second):
			}
		})
		return func() error {
			select {
			case <-finished:
				return drainErr
			case <-time.After(30 * time.Second):
				return errors.New("the node's uploads did not finish")
			}
		}
	}
	waitFor := func(ch <-chan struct{}, what string) {
		select {
		case <-ch:
		case <-time.After(30 * time.Second):
			t.Fatal(what)
		}
	}

	// Node A queues two bodies; the second, shared one waits behind the first's PUT.
	nodeA, s3A, instanceA := newNode("node-a")
	firstKey := deliver(nodeA, instanceA, "first", []byte("Subject: first\r\n\r\nfirst body"))
	shared := []byte("Subject: shared\r\n\r\nshared body")
	sharedKey := deliver(nodeA, instanceA, "shared-a", shared)
	doneA := drain(nodeA, s3A)
	waitFor(s3A.started, "node A never started its first upload")

	// The shared body arrives again on node B, which re-arms the row and starts writing.
	nodeB, s3B, instanceB := newNode("node-b")
	deliver(nodeB, instanceB, "shared-b", shared)
	doneB := drain(nodeB, s3B)
	waitFor(s3B.started, "node B never started its upload")

	// A's first upload lands; its task for the shared row now reaches the gate.
	close(s3A.release)
	if err := doneA(); err != nil {
		t.Fatalf("node A: %v", err)
	}
	if got := s3A.putKeys(); len(got) != 1 || got[0] != firstKey {
		t.Fatalf("node A wrote %v; it must not write the body node B holds the lease on", got)
	}
	if n := s.count(t, "pending_uploads", accountID); n != 1 {
		t.Fatalf("%d pending rows left; node A must not finalize the row node B is writing under", n)
	}

	// A purge while B is mid-PUT waits for it.
	s.requestPurge(t, email)
	s.runWorker(t)
	s.requireRetryable(t, accountID, email)

	close(s3B.release)
	if err := doneB(); err != nil {
		t.Fatalf("node B: %v", err)
	}
	if len(s.s3.Keys(sharedKey)) != 1 {
		t.Fatal("node B's write did not land")
	}
	s.requestPurge(t, email)
	s.runWorker(t)
	s.requireGone(t, accountID, email)
}
