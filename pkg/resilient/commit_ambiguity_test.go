//go:build integration

package resilient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
)

// lostAckError is a net.Error timeout, matching how a COMMIT severed in flight
// surfaces to pgx: a read deadline expiring on a connection the server has
// already acted upon.
type lostAckError struct{}

func (lostAckError) Error() string   { return "synthetic: commit acknowledgement lost" }
func (lostAckError) Timeout() bool   { return true }
func (lostAckError) Temporary() bool { return true }

// commitFaultConn forwards everything to the real connection until it carries a
// COMMIT while armed. It then reads the server's reply — proving the COMMIT was
// applied — discards it, and fails every later read with lostAckError. The
// failure has to be sticky: pgconn's MultiResultReader.NextResult peeks with the
// error discarded, so a one-shot failure is swallowed and the read retried.
type commitFaultConn struct {
	net.Conn
	armed *atomic.Bool
	fired *atomic.Bool
	dead  atomic.Bool
}

func (c *commitFaultConn) Write(b []byte) (int, error) {
	if c.dead.Load() {
		return 0, lostAckError{}
	}
	n, err := c.Conn.Write(b)
	if err == nil && isCommitQuery(b) && c.armed.CompareAndSwap(true, false) {
		var scratch [512]byte
		if _, rerr := c.Conn.Read(scratch[:]); rerr != nil {
			return n, rerr
		}
		c.dead.Store(true)
		c.fired.Store(true)
	}
	return n, err
}

func (c *commitFaultConn) Read(b []byte) (int, error) {
	if c.dead.Load() {
		return 0, lostAckError{}
	}
	return c.Conn.Read(b)
}

// isCommitQuery reports whether b is the simple-protocol Query message carrying
// the transaction commit that pgx emits from Tx.Commit.
func isCommitQuery(b []byte) bool {
	return len(b) > 5 && b[0] == 'Q' && string(b[5:len(b)-1]) == "commit"
}

func testDatabaseConfig() *config.DatabaseConfig {
	dbName := os.Getenv("SORA_TEST_DB_NAME")
	if dbName == "" {
		dbName = "sora_test_db"
	}
	return &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts: []string{"localhost"},
			Port:  "5432",
			User:  "postgres",
			Name:  dbName,
		},
	}
}

func newTestPool(t *testing.T, cfg *config.DatabaseConfig, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *pgxpool.Pool {
	t.Helper()
	endpoint := cfg.Write
	poolCfg, err := pgxpool.ParseConfig(fmt.Sprintf("postgres://%s@%s:%s/%s?sslmode=disable",
		endpoint.User, endpoint.Hosts[0], endpoint.Port, endpoint.Name))
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	if dial != nil {
		poolCfg.ConnConfig.DialFunc = dial
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Skipf("PostgreSQL not available: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// newFaultyPool returns a pool whose connections drop the acknowledgement of the
// first COMMIT written while armed is set.
func newFaultyPool(t *testing.T, cfg *config.DatabaseConfig, armed, fired *atomic.Bool) *pgxpool.Pool {
	t.Helper()
	return newTestPool(t, cfg, func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := new(net.Dialer).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &commitFaultConn{Conn: conn, armed: armed, fired: fired}, nil
	})
}

// newTestResilientDatabase wires a ResilientDatabase around a single, caller-supplied
// pool so a fault-injecting dialer can be installed underneath the retry wrapper.
func newTestResilientDatabase(cfg *config.DatabaseConfig, pool *pgxpool.Pool) *ResilientDatabase {
	dbPool := &DatabasePool{database: &db.Database{WritePool: pool, ReadPool: pool}, host: "localhost"}
	dbPool.isHealthy.Store(true)
	manager := &RuntimeFailoverManager{
		writePools:      []*DatabasePool{dbPool},
		readPools:       []*DatabasePool{dbPool},
		config:          cfg,
		healthCheckStop: make(chan struct{}),
	}
	return &ResilientDatabase{
		failoverManager: manager,
		queryBreaker:    circuitbreaker.NewCircuitBreaker(circuitbreaker.DefaultSettings("test_query")),
		writeBreaker:    circuitbreaker.NewCircuitBreaker(circuitbreaker.DefaultSettings("test_write")),
		config:          cfg,
	}
}

type copyFixture struct {
	accountID int64
	srcID     int64
	destID    int64
}

func newCopyFixture(t *testing.T, pool *pgxpool.Pool, messages int) copyFixture {
	t.Helper()
	ctx := context.Background()

	var f copyFixture
	if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&f.accountID); err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		pool.Exec(cleanupCtx, `DELETE FROM pending_uploads WHERE account_id = $1`, f.accountID)
		pool.Exec(cleanupCtx, `DELETE FROM messages WHERE account_id = $1`, f.accountID)
		pool.Exec(cleanupCtx, `DELETE FROM mailboxes WHERE account_id = $1`, f.accountID)
		pool.Exec(cleanupCtx, `DELETE FROM accounts WHERE id = $1`, f.accountID)
	})

	uidValidity := time.Now().Unix()
	for i, name := range []string{"SRC", "DEST"} {
		var id int64
		err := pool.QueryRow(ctx, `
			INSERT INTO mailboxes (account_id, name, uid_validity, path, highest_uid)
			VALUES ($1, $2, $3, $4, 0) RETURNING id`,
			f.accountID, name, uidValidity, fmt.Sprintf("%016x", i+1)).Scan(&id)
		if err != nil {
			t.Fatalf("create mailbox %s: %v", name, err)
		}
		if i == 0 {
			f.srcID = id
		} else {
			f.destID = id
		}
	}

	for i := 1; i <= messages; i++ {
		var messageID int64
		err := pool.QueryRow(ctx, `
			INSERT INTO messages (
				account_id, uid, s3_domain, s3_localpart, content_hash, uploaded,
				recipients_json, message_id, subject, sent_date, internal_date, size,
				body_structure, mailbox_id, mailbox_path, created_modseq)
			VALUES ($1, $2, 'example.com', 'user', $3, TRUE,
				'[]'::jsonb, $4, 'subject', NOW(), NOW(), 100,
				'\x00'::bytea, $5, 'SRC', nextval('messages_modseq'))
			RETURNING id`,
			f.accountID, i, fmt.Sprintf("hash-%d-%d", f.accountID, i),
			fmt.Sprintf("<msg-%d-%d@example.com>", f.accountID, i), f.srcID).Scan(&messageID)
		if err != nil {
			t.Fatalf("insert message %d: %v", i, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
			VALUES ($1, $2, 0, '[]'::jsonb, NOW(), nextval('messages_modseq'))`,
			messageID, f.srcID); err != nil {
			t.Fatalf("insert message_state %d: %v", i, err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE mailboxes SET highest_uid = $1 WHERE id = $2`, messages, f.srcID); err != nil {
		t.Fatalf("bump source highest_uid: %v", err)
	}
	return f
}

func countLiveMessages(t *testing.T, pool *pgxpool.Pool, mailboxID int64) int {
	t.Helper()
	var n int
	err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL`, mailboxID).Scan(&n)
	if err != nil {
		t.Fatalf("count messages: %v", err)
	}
	return n
}

// TestCopyMessagesNotDuplicatedWhenCommitAckLost covers the ambiguous-commit case:
// the COMMIT reaches PostgreSQL and is applied, but its acknowledgement never gets
// back to the client. Re-running the transaction allocates a second UID range and
// inserts a second full copy of every message, so the wrapper must not retry.
func TestCopyMessagesNotDuplicatedWhenCommitAckLost(t *testing.T) {
	const messageCount = 3

	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	fixture := newCopyFixture(t, plain, messageCount)

	var armed, fired atomic.Bool
	rdb := newTestResilientDatabase(cfg, newFaultyPool(t, cfg, &armed, &fired))

	uids := []imap.UID{1, 2, 3}
	armed.Store(true)
	_, _, err := rdb.CopyMessagesWithRetry(context.Background(), &uids,
		fixture.srcID, fixture.destID, fixture.accountID, "example.com", "user", "test-instance")
	t.Logf("CopyMessagesWithRetry returned: %v", err)

	if !fired.Load() {
		t.Fatal("fault was never injected: the COMMIT acknowledgement was not dropped, so this test proves nothing")
	}
	if n := countLiveMessages(t, plain, fixture.destID); n != messageCount {
		t.Errorf("destination mailbox has %d messages, want %d (the committed copy, not a second set)", n, messageCount)
	}
}

// TestAmbiguousCopyCommitResolvesToCommitted is the positive half of the COPY ambiguity
// resolution: when the COMMIT applies but its acknowledgement is lost, the wrapper returns
// ErrCommitOutcomeUnknown together with the new rows' BIGSERIAL ids, and reading those ids
// back on a healthy connection confirms the copy committed. This is what lets the IMAP COPY
// handler answer OK truthfully instead of the loss-unsafe alternatives (a spurious NO that
// duplicates on retry, or a spurious OK on a copy that never landed).
func TestAmbiguousCopyCommitResolvesToCommitted(t *testing.T) {
	const messageCount = 3

	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	fixture := newCopyFixture(t, plain, messageCount)

	var armed, fired atomic.Bool
	faulty := newTestResilientDatabase(cfg, newFaultyPool(t, cfg, &armed, &fired))

	uids := []imap.UID{1, 2, 3}
	armed.Store(true)
	uidMap, newIDs, err := faulty.CopyMessagesWithRetry(context.Background(), &uids,
		fixture.srcID, fixture.destID, fixture.accountID, "example.com", "user", "test-instance")

	if !fired.Load() {
		t.Fatal("fault was never injected: the COMMIT acknowledgement was not dropped, so this test proves nothing")
	}
	if !errors.Is(err, ErrCommitOutcomeUnknown) {
		t.Fatalf("expected ErrCommitOutcomeUnknown, got %v", err)
	}

	// The captured values must survive the discarded transaction result.
	if len(newIDs) != messageCount {
		t.Fatalf("got %d captured message ids, want %d — the side-effect capture did not survive the ambiguous commit", len(newIDs), messageCount)
	}
	if len(uidMap) != messageCount {
		t.Errorf("captured uidMap has %d entries, want %d", len(uidMap), messageCount)
	}

	// The read-back — on a HEALTHY database — must confirm the copy committed. This is the
	// exact decision the COPY handler makes before answering OK.
	healthy := newTestResilientDatabase(cfg, plain)
	committed, rbErr := healthy.CopiedMessagesCommittedWithRetry(context.Background(), newIDs)
	if rbErr != nil {
		t.Fatalf("read-back failed: %v", rbErr)
	}
	if !committed {
		t.Error("read-back reported the copy as NOT committed, but the COMMIT was applied before the ack was dropped — the handler would wrongly answer NO and a client retry would duplicate")
	}
}

// TestCopiedMessagesCommittedReadBackIsExact pins the read-back primitive itself: it reports
// committed only when EVERY id is present. A false "committed" is the loss case (the handler
// would answer OK on a copy that rolled back, and a copy-delete client would then expunge
// the source), so the partial and absent cases must both report not-committed.
func TestCopiedMessagesCommittedReadBackIsExact(t *testing.T) {
	const messageCount = 3

	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	fixture := newCopyFixture(t, plain, messageCount)
	rdb := newTestResilientDatabase(cfg, plain)
	ctx := context.Background()

	// Commit a real copy on a healthy connection and collect its ids.
	uids := []imap.UID{1, 2, 3}
	_, newIDs, err := rdb.CopyMessagesWithRetry(ctx, &uids,
		fixture.srcID, fixture.destID, fixture.accountID, "example.com", "user", "test-instance")
	if err != nil {
		t.Fatalf("copy failed: %v", err)
	}
	if len(newIDs) != messageCount {
		t.Fatalf("got %d new ids, want %d", len(newIDs), messageCount)
	}

	cases := []struct {
		name string
		ids  []int64
		want bool
	}{
		{"all present → committed", newIDs, true},
		{"none present → not committed", []int64{-1, -2, -3}, false},
		{"partial present → not committed", append([]int64{newIDs[0], newIDs[1]}, -1), false},
		{"empty → not committed", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := rdb.CopiedMessagesCommittedWithRetry(ctx, tc.ids)
			if err != nil {
				t.Fatalf("read-back error: %v", err)
			}
			if got != tc.want {
				t.Errorf("committed = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCommitFailureDoesNotReExecuteClosure states the wrapper contract behind that
// guarantee: a failed Commit ends the retry loop, so the transaction body runs once
// and the caller gets an error it can recognise as ambiguous rather than a success.
func TestCommitFailureDoesNotReExecuteClosure(t *testing.T) {
	cfg := testDatabaseConfig()

	var armed, fired atomic.Bool
	rdb := newTestResilientDatabase(cfg, newFaultyPool(t, cfg, &armed, &fired))

	attempts := 0
	armed.Store(true)
	_, err := rdb.executeWriteInTxWithRetry(context.Background(), writeRetryConfig, timeoutWrite,
		func(ctx context.Context, tx pgx.Tx) (any, error) {
			attempts++
			_, execErr := tx.Exec(ctx, `SELECT 1`)
			return nil, execErr
		})

	if !fired.Load() {
		t.Fatal("fault was never injected")
	}
	if attempts != 1 {
		t.Errorf("transaction body ran %d times, want 1", attempts)
	}
	if !errors.Is(err, ErrCommitOutcomeUnknown) {
		t.Errorf("got error %v, want one wrapping ErrCommitOutcomeUnknown", err)
	}
}

// TestCommitAckLostIsClassifiedRetryable pins the precondition the duplication
// depends on: a lost commit acknowledgement survives pgx/pgconn wrapping as an
// error isRetryableError accepts, so the wrapper really would re-run the closure.
func TestCommitAckLostIsClassifiedRetryable(t *testing.T) {
	cfg := testDatabaseConfig()

	var armed, fired atomic.Bool
	rdb := newTestResilientDatabase(cfg, newFaultyPool(t, cfg, &armed, &fired))

	ctx := context.Background()
	tx, err := rdb.BeginTxWithRetry(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT 1`); err != nil {
		t.Fatalf("exec: %v", err)
	}

	armed.Store(true)
	commitErr := tx.Commit(ctx)
	if !fired.Load() {
		t.Fatal("fault was never injected")
	}
	if commitErr == nil {
		t.Fatal("expected commit to report the lost acknowledgement as an error")
	}
	var lost lostAckError
	if !errors.As(commitErr, &lost) {
		t.Errorf("commit error %v (%T) no longer unwraps to the injected net.Error", commitErr, commitErr)
	}
	if !rdb.isRetryableError(commitErr) {
		t.Errorf("commit error %v is not classified retryable; the duplication test would prove nothing", commitErr)
	}
}
