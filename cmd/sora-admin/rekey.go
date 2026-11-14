package main

// rekey.go - `sora-admin import rekey`: move the bodies that older maildir imports stored
// under their SHA-256 digest to the BLAKE3 key that every other path uses.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
)

// storedBodyKind is what a stored body's bytes say about the hash in its key.
type storedBodyKind int

const (
	// storedBodyBLAKE3: the key is the body's BLAKE3 digest, as on every path.
	storedBodyBLAKE3 storedBodyKind = iota
	// storedBodyLegacySHA256: the key is the body's SHA-256 digest. Older versions of
	// `import maildir` stored bodies that way; the body is intact, only the key differs.
	storedBodyLegacySHA256
	// storedBodyMismatch: the body hashes to neither, so the object is corrupt.
	storedBodyMismatch
)

// classifyStoredBody compares keyHash, the hash an object is stored under, with the digests
// of its body. It also returns the body's BLAKE3 digest: the hash the body belongs under.
func classifyStoredBody(content []byte, keyHash string) (storedBodyKind, string) {
	blake3 := helpers.HashContent(content)
	if blake3 == keyHash {
		return storedBodyBLAKE3, blake3
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) == keyHash {
		return storedBodyLegacySHA256, blake3
	}
	return storedBodyMismatch, blake3
}

// readStoredBody downloads (and, with client-side encryption, decrypts) a whole object.
func readStoredBody(store interface {
	Get(key string) (io.ReadCloser, error)
}, key string) ([]byte, error) {
	reader, err := store.Get(key)
	if err != nil {
		return nil, fmt.Errorf("download/decrypt failed: %w", err)
	}
	defer reader.Close()
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	return content, nil
}

// rekeyOldObjectDelay is how long the old object of a re-keyed body is kept before it is
// deleted. A transaction that read a message row before the re-key committed can still write
// a row with the old hash afterwards: COPY inserts its rows with INSERT ... SELECT, which takes
// content_hash from its snapshot without waiting for row locks. Server write transactions are
// bounded by the database write_timeout (10 to 15 seconds by default), so after this delay
// every row that will ever carry the old hash has committed, and the reference check that
// precedes the delete sees it. A variable so tests can shorten it.
var rekeyOldObjectDelay = 30 * time.Second

type rekeyOptions struct {
	DryRun     bool
	BatchSize  int
	Jobs       int
	StartAfter db.ContentObject // resume after this object; the zero value starts at the beginning
	Progress   io.Writer        // per-batch progress lines; nil for none
}

// rekeyReport is what a run found and did. Lists hold S3 keys, with the error where there
// was one.
type rekeyReport struct {
	Checked      int   // bodies downloaded and classified
	Current      int   // already under their BLAKE3 key
	Legacy       int   // under their SHA-256 key (in a dry run, the ones that would be re-keyed)
	Rekeyed      int   // legacy bodies whose rows were moved to the BLAKE3 key
	RowsUpdated  int64 // message rows moved
	Written      int   // BLAKE3 objects written
	Reused       int   // BLAKE3 objects that already held the body
	OldDeleted   int   // old SHA-256 objects deleted
	OldKept      []string
	OldLeft      []string
	Unrecognised []string
	Unreadable   []string
	Pending      []string
	Failed       []string
	// Cursor is the last object of the last batch that was processed in full: where
	// --start-after resumes an interrupted run.
	Cursor db.ContentObject
}

type rekeyedObject struct {
	old       db.ContentObject
	committed time.Time
}

type rekeyRun struct {
	rdb       *resilient.ResilientDatabase
	store     objectStorage
	accountID int64
	opts      rekeyOptions

	mu     sync.Mutex
	report *rekeyReport
	// written holds the BLAKE3 objects this run wrote or verified. The listing walks keys
	// in order, so a body re-keyed early comes round again under its new key; it was just
	// verified and needs no second download.
	written map[db.ContentObject]bool
	// oldObjects are the SHA-256 objects whose rows moved, waiting for rekeyOldObjectDelay.
	oldObjects []rekeyedObject
}

// rekeyAccount re-keys every body of accountID that is stored under its SHA-256 digest. It
// walks the account's objects in key order, in batches of opts.BatchSize, and for each one:
//
//  1. downloads it and classifies the body (classifyStoredBody); only a body whose bytes
//     hash to the key with SHA-256 is touched, and a dry run stops here;
//  2. under the S3 object lock of the new key (the lock the cleaner takes before it deletes
//     an object), makes sure the BLAKE3 object holds the body, writing it unless an intact
//     copy is already there, and moves the account's rows to it (db.RekeyContentHash);
//  3. after rekeyOldObjectDelay, under the old key's lock, deletes the old object if nothing
//     references it any more.
//
// Every step is idempotent, so a failed or interrupted run is repaired by running again.
// The report is returned even with an error.
func rekeyAccount(ctx context.Context, rdb *resilient.ResilientDatabase, store objectStorage, accountID int64, opts rekeyOptions) (*rekeyReport, error) {
	if opts.BatchSize <= 0 {
		opts.BatchSize = 100
	}
	if opts.Jobs <= 0 {
		opts.Jobs = 1
	}
	// A job holds one write-pool connection for its S3 object lock and needs a second one
	// for the re-key transaction it runs under that lock. Jobs whose locks held every
	// connection would each wait for a second one until the write timeout failed them.
	if poolSize := int(rdb.GetOperationalDatabase().GetWritePool().Stat().MaxConns()); opts.Jobs > max(1, poolSize/2) {
		opts.Jobs = max(1, poolSize/2)
		if opts.Progress != nil {
			fmt.Fprintf(opts.Progress, "  Running %d jobs: each needs 2 of the %d connections of the database write pool\n", opts.Jobs, poolSize)
		}
	}
	r := &rekeyRun{
		rdb:       rdb,
		store:     store,
		accountID: accountID,
		opts:      opts,
		report:    &rekeyReport{Cursor: opts.StartAfter},
		written:   make(map[db.ContentObject]bool),
	}
	// Whatever is still queued when the run ends was not deleted.
	defer r.abandonOldObjects()

	for ctx.Err() == nil {
		batch, err := rdb.ListRekeyCandidatesWithRetry(ctx, accountID, r.report.Cursor, opts.BatchSize)
		if err != nil {
			return r.report, fmt.Errorf("failed to list the account's objects: %w", err)
		}
		if len(batch) == 0 {
			break
		}
		r.processBatch(ctx, batch)
		if ctx.Err() != nil {
			break // the batch may be incomplete: the cursor stays before it
		}
		r.report.Cursor = batch[len(batch)-1]
		r.deleteOldObjects(ctx, false)
		if opts.Progress != nil {
			fmt.Fprintf(opts.Progress, "  %d checked, %d under SHA-256, %d re-keyed (at %s)\n",
				r.report.Checked, r.report.Legacy, r.report.Rekeyed, r.report.Cursor.Key())
		}
	}
	if ctx.Err() == nil {
		r.deleteOldObjects(ctx, true)
	}
	return r.report, ctx.Err()
}

func (r *rekeyRun) processBatch(ctx context.Context, batch []db.ContentObject) {
	work := make(chan db.ContentObject)
	var wg sync.WaitGroup
	for i := 0; i < r.opts.Jobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for obj := range work {
				r.processObject(ctx, obj)
			}
		}()
	}
dispatch:
	for _, obj := range batch {
		r.mu.Lock()
		done := r.written[obj]
		r.mu.Unlock()
		if done {
			continue
		}
		select {
		case work <- obj:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(work)
	wg.Wait()
}

func (r *rekeyRun) processObject(ctx context.Context, obj db.ContentObject) {
	content, err := readStoredBody(r.store, obj.Key())
	if err != nil {
		r.mu.Lock()
		r.report.Unreadable = append(r.report.Unreadable, fmt.Sprintf("%s: %v", obj.Key(), err))
		r.mu.Unlock()
		return
	}
	kind, blake3 := classifyStoredBody(content, obj.ContentHash)

	r.mu.Lock()
	r.report.Checked++
	switch kind {
	case storedBodyBLAKE3:
		r.report.Current++
	case storedBodyLegacySHA256:
		r.report.Legacy++
	default:
		r.report.Unrecognised = append(r.report.Unrecognised, fmt.Sprintf("%s: content hashes to %s", obj.Key(), blake3))
	}
	r.mu.Unlock()
	if kind != storedBodyLegacySHA256 || r.opts.DryRun {
		return
	}

	newObj := db.ContentObject{S3Domain: obj.S3Domain, S3Localpart: obj.S3Localpart, ContentHash: blake3}
	rows, wrote, err := r.moveBody(ctx, obj, newObj, content)
	committed := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()
	if wrote {
		r.report.Written++
	}
	switch {
	case errors.Is(err, db.ErrRekeyUploadPending):
		r.report.Pending = append(r.report.Pending, obj.Key())
	case err != nil:
		// The commit may or may not have happened (a lost lock, an unknown commit outcome),
		// so the old object stays: a later run finds the rows on whichever key they are.
		r.report.Failed = append(r.report.Failed, fmt.Sprintf("%s: %v", obj.Key(), err))
	default:
		if !wrote {
			r.report.Reused++
		}
		r.report.Rekeyed++
		r.report.RowsUpdated += rows
		r.written[newObj] = true
		r.oldObjects = append(r.oldObjects, rekeyedObject{old: obj, committed: committed})
	}
}

// moveBody makes newObj hold content and moves the account's rows from obj to it. It reports
// how many rows moved and whether it wrote newObj.
func (r *rekeyRun) moveBody(ctx context.Context, obj, newObj db.ContentObject, content []byte) (rows int64, wrote bool, err error) {
	// db.RekeyContentHash refuses a body with a pending upload; asking first keeps such a
	// body from leaving behind a BLAKE3 object that no row points at.
	pending, err := r.rdb.PendingUploadExistsWithRetry(ctx, obj.ContentHash, r.accountID)
	if err != nil {
		return 0, false, err
	}
	if pending {
		return 0, false, db.ErrRekeyUploadPending
	}

	err = r.rdb.ExecuteWithS3ObjectLock(ctx, newObj.ContentHash, r.accountID, func(ctx context.Context) error {
		// An object already under the new key is reused only if it holds the body: the old
		// object, the one copy known to be good, is deleted afterwards.
		if existing, err := readStoredBody(r.store, newObj.Key()); err != nil || helpers.HashContent(existing) != newObj.ContentHash {
			if err := r.store.Put(newObj.Key(), bytes.NewReader(content), int64(len(content))); err != nil {
				return fmt.Errorf("failed to write %s: %w", newObj.Key(), err)
			}
			wrote = true
		}
		var err error
		rows, err = r.rdb.RekeyContentHashWithRetry(ctx, r.accountID, obj, newObj.ContentHash)
		return err
	})
	return rows, wrote, err
}

// deleteOldObjects deletes the queued old objects whose delay has passed. With wait it waits
// for the rest and deletes them too.
func (r *rekeyRun) deleteOldObjects(ctx context.Context, wait bool) {
	var waiting []rekeyedObject
	for _, o := range r.oldObjects {
		due := o.committed.Add(rekeyOldObjectDelay)
		if d := time.Until(due); d > 0 {
			if !wait {
				waiting = append(waiting, o)
				continue
			}
			select {
			case <-time.After(d):
			case <-ctx.Done():
			}
		}
		if ctx.Err() != nil {
			waiting = append(waiting, o)
			continue
		}
		r.deleteOldObject(ctx, o.old)
	}
	r.oldObjects = waiting
}

// deleteOldObject deletes old if nothing references it, holding its S3 object lock across
// the check and the delete as the cleaner does, so a restore or cross-account COPY that
// claims the body in between is either seen or waits.
func (r *rekeyRun) deleteOldObject(ctx context.Context, old db.ContentObject) {
	var referenced bool
	err := r.rdb.ExecuteWithS3ObjectLock(ctx, old.ContentHash, r.accountID, func(ctx context.Context) error {
		var err error
		if referenced, err = r.rdb.IsContentObjectReferencedWithRetry(ctx, old); err != nil || referenced {
			return err
		}
		return r.store.Delete(old.Key())
	})
	switch {
	case err != nil:
		r.report.OldLeft = append(r.report.OldLeft, fmt.Sprintf("%s: %v", old.Key(), err))
	case referenced:
		r.report.OldKept = append(r.report.OldKept, old.Key())
	default:
		r.report.OldDeleted++
	}
}

// abandonOldObjects reports the old objects still queued when the run ended.
func (r *rekeyRun) abandonOldObjects() {
	for _, o := range r.oldObjects {
		r.report.OldLeft = append(r.report.OldLeft, o.old.Key()+": run ended before it was deleted")
	}
	r.oldObjects = nil
}

// parseRekeyCursor parses a --start-after value: an S3 key domain/localpart/hash. A
// localpart may itself contain '/', a domain and a hash cannot.
func parseRekeyCursor(key string) (db.ContentObject, error) {
	first := strings.Index(key, "/")
	last := strings.LastIndex(key, "/")
	if first <= 0 || last == first || last == len(key)-1 {
		return db.ContentObject{}, fmt.Errorf("%q is not an S3 key of the form domain/localpart/hash", key)
	}
	return db.ContentObject{S3Domain: key[:first], S3Localpart: key[first+1 : last], ContentHash: key[last+1:]}, nil
}

func handleImportRekey(ctx context.Context) {
	fs := flag.NewFlagSet("import rekey", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account to repair (required)")
	dryRun := fs.Bool("dry-run", false, "Download and classify the bodies and report, without changing anything")
	batchSize := fs.Int("batch-size", 100, "Number of stored bodies listed and processed per batch")
	jobs := fs.Int("jobs", 4, "Number of bodies downloaded and re-keyed in parallel")
	startAfter := fs.String("start-after", "", "Resume after this S3 key (domain/localpart/hash), as printed by an interrupted run")

	fs.Usage = func() {
		fmt.Printf(`Re-key message bodies that an older import stored under their SHA-256 digest

Older versions of 'sora-admin import maildir' stored each message body under
the SHA-256 digest of its bytes, where every other path uses the BLAKE3 digest.
For that mail 'verify s3 --deep' reports intact objects as corrupt, a delivered
copy of the same message never deduplicates with it, and importing the maildir
again without --incremental adds every message a second time.

This command downloads every uploaded body the account's messages point at
(bodies of MTA deliveries excepted: those were always BLAKE3) and hashes it.
A body stored under its SHA-256 digest is written under its BLAKE3 key (an
intact object already there is reused), the account's message and full-text
search rows are moved to the BLAKE3 hash, and the old object is deleted once
nothing references it, at least 30 seconds later. Bodies already under their
BLAKE3 key, and objects whose bytes match neither digest, are left alone.

Every step is idempotent: a failed or interrupted run can be repeated, or
resumed with --start-after. Do not run it while an import into the account is
running, and import with a sora-admin that hashes with BLAKE3 afterwards.

Usage:
  sora-admin import rekey --email <email> [options]

Options:
  --email string        Email address of the account to repair (required)
  --dry-run             Download and classify the bodies and report, change nothing
  --batch-size int      Stored bodies listed and processed per batch (default: 100)
  --jobs int            Bodies downloaded and re-keyed in parallel (default: 4)
  --start-after string  Resume after this S3 key (domain/localpart/hash), as
                        printed by an interrupted run
  --config string       Path to TOML configuration file (required)

Examples:
  sora-admin import rekey --email user@example.com --dry-run --config config.toml
  sora-admin import rekey --email user@example.com --config config.toml
`)
	}

	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}
	if *batchSize <= 0 || *jobs <= 0 {
		fmt.Printf("Error: --batch-size and --jobs must be positive\n")
		os.Exit(1)
	}
	var cursor db.ContentObject
	if *startAfter != "" {
		var err error
		if cursor, err = parseRekeyCursor(*startAfter); err != nil {
			fmt.Printf("Error: --start-after: %v\n", err)
			os.Exit(1)
		}
	}

	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}
	defer rdb.Close()

	s3Timeout, err := globalConfig.S3.GetTimeout()
	if err != nil {
		logger.Fatalf("Invalid S3 timeout configuration: %v", err)
	}
	s3, err := storage.New(globalConfig.S3.Endpoint, globalConfig.S3.AccessKey, globalConfig.S3.SecretKey, globalConfig.S3.Bucket, !globalConfig.S3.DisableTLS, globalConfig.S3.GetDebug(), s3Timeout)
	if err != nil {
		logger.Fatalf("Failed to initialize S3 storage: %v", err)
	}
	if globalConfig.S3.Encrypt {
		if err := s3.EnableEncryption(globalConfig.S3.EncryptionKey); err != nil {
			logger.Fatalf("Failed to enable S3 encryption: %v", err)
		}
	}

	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		logger.Fatalf("Failed to find account %s: %v", *email, err)
	}

	if *dryRun {
		fmt.Printf("Checking stored bodies of %s (dry run, nothing is changed)...\n", *email)
	} else {
		fmt.Printf("Re-keying stored bodies of %s...\n", *email)
	}
	start := time.Now()
	report, runErr := rekeyAccount(ctx, rdb, s3, accountID, rekeyOptions{
		DryRun:     *dryRun,
		BatchSize:  *batchSize,
		Jobs:       *jobs,
		StartAfter: cursor,
		Progress:   os.Stdout,
	})
	printRekeyReport(report, *email, *dryRun, time.Since(start))
	if runErr != nil {
		if (report.Cursor != db.ContentObject{}) {
			fmt.Printf("\nResume with: --start-after %s\n", report.Cursor.Key())
		}
		logger.Fatalf("Re-key stopped: %v", runErr)
	}
	if len(report.Failed) > 0 || len(report.OldLeft) > 0 {
		os.Exit(1)
	}
}

func printRekeyReport(r *rekeyReport, email string, dryRun bool, elapsed time.Duration) {
	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Bodies checked:                %d\n", r.Checked)
	fmt.Printf("  Already under BLAKE3:          %d\n", r.Current)
	if dryRun {
		fmt.Printf("  Under SHA-256, would re-key:   %d\n", r.Legacy)
	} else {
		fmt.Printf("  Under SHA-256:                 %d\n", r.Legacy)
		fmt.Printf("  Re-keyed:                      %d (%d message rows)\n", r.Rekeyed, r.RowsUpdated)
		fmt.Printf("  BLAKE3 objects written:        %d\n", r.Written)
		fmt.Printf("  BLAKE3 objects reused:         %d\n", r.Reused)
		fmt.Printf("  Old objects deleted:           %d\n", r.OldDeleted)
	}
	fmt.Printf("  Duration:                      %s\n", elapsed.Round(time.Millisecond))

	printRekeyList("Matching neither digest (corrupt, left alone; see 'verify hash')", r.Unrecognised)
	printRekeyList("Unreadable (missing or a read error; see 'verify s3')", r.Unreadable)
	printRekeyList("Skipped, an upload of the body is pending (run again later)", r.Pending)
	printRekeyList("Failed (run again)", r.Failed)
	printRekeyList("Old objects kept, still referenced (run again; rows of another account need that account's run)", r.OldKept)
	if len(r.OldLeft) > 0 {
		printRekeyList("Old objects not deleted", r.OldLeft)
		fmt.Printf("  Their rows moved, so nothing should reference them any more. Before deleting one,\n")
		fmt.Printf("  check it with: sora-admin verify hash --email %s --hash <hash>\n", email)
	}
}

func printRekeyList(title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Printf("\n%s: %d\n", title, len(items))
	for i, item := range items {
		if i == 100 {
			fmt.Printf("  ... and %d more\n", len(items)-100)
			break
		}
		fmt.Printf("  - %s\n", item)
	}
}
