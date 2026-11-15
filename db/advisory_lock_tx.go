package db

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/logger"
)

// advisoryLockKeepalive is how long a held AdvisoryLockTx may sit without a statement
// before its keepalive runs one. The server kills a session whose transaction has been
// idle for idle_in_transaction_session_timeout (10 minutes on Sora's reference
// deployment), and work guarded by these locks — an S3 transfer under retry, a cleanup
// cycle, a schema migration — can legitimately outlast that. Ticks that find a recent
// statement skip, so the gap between statements can reach twice this value; the server
// setting must stay well above that. A variable so tests can shorten it.
var advisoryLockKeepalive = 30 * time.Second

// advisoryLockStatementTimeout bounds the keepalive ping and the final ROLLBACK, both of
// which run on detached contexts: a lock must be released even when the work it guarded
// was abandoned with its context. A variable so tests can shorten it.
var advisoryLockStatementTimeout = 5 * time.Second

// AdvisoryLockTx holds transaction-scoped advisory locks in a dedicated, otherwise idle
// transaction on one pooled connection.
//
// Sora's write pool may sit behind a transaction-pooling proxy (PgBouncer in transaction
// mode). Such a proxy binds a client to one PostgreSQL backend only for the duration of
// a transaction; between transactions, consecutive statements from the same client may
// run on different backends. A SESSION-level advisory lock is therefore taken on
// whichever backend ran that statement, the matching unlock runs on another backend
// where it is a no-op ("you don't own a lock of type ExclusiveLock"), and the lock stays
// on the first backend until the proxy retires it — pgbouncer's server_lifetime, an hour
// by default. Every stranded lock is an entry in PostgreSQL's fixed-size shared lock
// table (max_locks_per_transaction × max_connections); once it is full, every session
// in the cluster fails with "out of shared memory" (SQLSTATE 53200). That is how the
// 2026-09-06 outage happened: the cleaner's per-object S3 locks and the uploader's
// per-upload locks stranded tens of thousands of entries within an hour.
//
// Holding the lock inside an open transaction is the one pooler-agnostic way to pin a
// backend: a proxy cannot move a transaction, pg_advisory_xact_lock is released when the
// transaction ends however it ends (COMMIT, ROLLBACK, a killed session, a dropped
// connection), and nothing can be left behind.
//
// The transaction is READ COMMITTED and READ ONLY, so it never gets a transaction id,
// and every operation on it ends with a bare "SELECT 1", so it holds no snapshot while
// it idles: that statement drops the unnamed portal an extended-protocol statement
// leaves behind (whose snapshot would otherwise live until the next Bind) and takes a
// fresh transaction snapshot, which invalidates the catalog snapshot the function lookup
// in pg_advisory_xact_lock registers (which would otherwise live until the next
// statement). Either would keep backend_xmin set for the whole S3 round trip, holding
// back VACUUM and — worse — making CREATE INDEX CONCURRENTLY wait for the transaction to
// end, which deadlocks a migration that runs one while the leader lock is held. With
// them cleared the backend sits idle in transaction with backend_xid and backend_xmin
// both NULL, holding back nothing; TestAdvisoryLockTxIdlesWithoutSnapshot pins that.
// (Under REPEATABLE READ the first snapshot would last until ROLLBACK, hence the
// explicit isolation level.)
//
// The locks can still be lost while the guarded work runs — the backend dies, a
// failover, a proxy retiring the connection, a failed keepalive. Guard hands the work a
// context that is cancelled the moment that is noticed, and Err reports it afterwards,
// so an S3 delete stops instead of landing after a fresh upload of the same body.
//
// They also stop meaning anything when Sora stops writing through the server that holds
// them, even while this transaction lives on and its keepalive succeeds: the runtime
// selector moved writes to another host, or the write pool was reconnected because its
// server turned read-only. An upload through the new writer passes its write gate there,
// where these locks exclude nothing. The failover therefore fences them: RetireWriter
// before it writes through another host, FenceAdvisoryLocks once it has dropped the
// connections of a host whose server turned read-only. A fence is a loss like any other.
// A failover that another node notices first is outside this process's view;
// docs/DATABASE.md ("Advisory locks across a failover") states what the failover tooling
// must do about it.
//
// What the transaction does hold is one pooled connection — one backend behind a pooler
// — for as long as the locks are held. That is the honest cost of mutual exclusion
// across an S3 round trip; callers bound it with their contexts, and operators size
// pooler pools for it (see docs/DATABASE.md, "PgBouncer and other connection poolers"). A caller that only
// needs to order itself after a holder, not exclude others for a while, should not pay
// it: the uploader takes the lock in a single autocommit statement instead
// (PassS3WriteGate).
//
// pgx connections are not safe for concurrent use, so every statement on the
// transaction, including the keepalive, is serialized by mu. Any statement error aborts
// a PostgreSQL transaction, so after the first error the locks are gone and every later
// call reports that error; the caller must Release.
type AdvisoryLockTx struct {
	mu            sync.Mutex
	conn          *pgxpool.Conn
	tx            pgx.Tx
	lastStatement time.Time // when the transaction last ran a statement (resets the server's idle timer)

	// lostMu guards lost and guards. It is never held across a statement, so a fence
	// cancels the guarded work at once, even while a statement holds mu (a Lock waiting
	// for its holder, a batch re-check).
	lostMu sync.Mutex
	lost   error // first loss: an error on the transaction, a fence, or Release
	guards []context.CancelCauseFunc

	fence *advisoryLockFence // the register of the database this transaction runs on

	pingMu     sync.Mutex
	pingCancel context.CancelFunc // cancels a keepalive ping in flight, so Release never waits on a dead socket

	stopKeepalive chan struct{}
	keepaliveDone chan struct{}
	releaseOnce   sync.Once
}

var errAdvisoryLockTxReleased = errors.New("advisory lock transaction already released")

// ErrAdvisoryLocksFenced is the loss an AdvisoryLockTx reports when its locks were
// revoked because Sora stopped writing through the server that holds them.
var ErrAdvisoryLocksFenced = errors.New("advisory locks fenced, the write host changed")

// advisoryLockFence is a database's register of open lock transactions, through which a
// failover revokes their locks (Database.FenceAdvisoryLocks, Database.RetireWriter).
type advisoryLockFence struct {
	mu      sync.Mutex
	gen     uint64 // bumped by every fence
	cause   error  // the latest fence's loss
	retired error  // while set, no lock transaction may open (RetireWriter)
	open    map[*AdvisoryLockTx]struct{}
}

// admit returns the generation a lock transaction starts opening under, or the refusal
// while the database is retired.
func (f *advisoryLockFence) admit() (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.retired != nil {
		return 0, f.retired
	}
	return f.gen, nil
}

// register records l, which started opening under generation gen, as open. It refuses l
// when a fence came in between: l's connection may be one of those the fence revoked.
func (f *advisoryLockFence) register(l *AdvisoryLockTx, gen uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.retired != nil {
		return f.retired
	}
	if f.gen != gen {
		return f.cause
	}
	if f.open == nil {
		f.open = make(map[*AdvisoryLockTx]struct{})
	}
	f.open[l] = struct{}{}
	return nil
}

func (f *advisoryLockFence) unregister(l *AdvisoryLockTx) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.open, l)
}

// revoke fences every open lock transaction, and every one still opening, with a loss
// wrapping cause; with retire, it also refuses new ones until reinstate.
func (f *advisoryLockFence) revoke(cause error, retire bool) {
	lost := fmt.Errorf("%w: %w", ErrAdvisoryLocksFenced, cause)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gen++
	f.cause = lost
	if retire {
		f.retired = lost
	}
	if len(f.open) > 0 {
		logger.Warn("Database: fencing advisory locks, Sora no longer writes through the server holding them", "count", len(f.open), "cause", cause)
	}
	for l := range f.open {
		l.fail(lost)
	}
}

func (f *advisoryLockFence) reinstate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retired = nil
}

// FenceAdvisoryLocks revokes the locks of every lock transaction open on d's write pool,
// and of every one being opened right now: their guarded work is cancelled, and they
// report a loss wrapping ErrAdvisoryLocksFenced and cause. A failover calls it when the
// connections opened so far may lead to another server than the one Sora writes to from
// now on. Call it after resetting the pool, never before, or a lock transaction could
// pick up an old connection in between and stay unfenced. Lock transactions opened
// afterwards are not affected.
func (d *Database) FenceAdvisoryLocks(cause error) {
	d.advisoryLocks.revoke(cause, false)
}

// RetireWriter fences d's advisory locks (FenceAdvisoryLocks) when Sora stops writing
// through d, and refuses to open lock transactions on d until ReinstateWriter: a caller
// that picked d just before the switch must not take locks there, where they exclude
// nothing on the new write host.
func (d *Database) RetireWriter(cause error) {
	d.advisoryLocks.revoke(cause, true)
}

// ReinstateWriter lets lock transactions open on d again, once Sora writes through d.
func (d *Database) ReinstateWriter() {
	d.advisoryLocks.reinstate()
}

// BeginAdvisoryLockTx opens the transaction that will hold advisory locks. ctx bounds
// only acquiring the connection and starting the transaction; the locks themselves live
// until Release, which the caller must always reach (defer it).
func (d *Database) BeginAdvisoryLockTx(ctx context.Context) (*AdvisoryLockTx, error) {
	// Before the connection is taken: a fence that came after this point is seen by
	// register below, whichever connection the pool hands out.
	gen, err := d.advisoryLocks.admit()
	if err != nil {
		return nil, fmt.Errorf("failed to begin advisory lock transaction: %w", err)
	}
	conn, err := d.GetWritePool().Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire connection for advisory locks: %w", err)
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly})
	if err != nil {
		conn.Release()
		return nil, fmt.Errorf("failed to begin advisory lock transaction: %w", err)
	}
	l := &AdvisoryLockTx{
		conn:          conn,
		tx:            tx,
		lastStatement: time.Now(),
		fence:         &d.advisoryLocks,
		stopKeepalive: make(chan struct{}),
		keepaliveDone: make(chan struct{}),
	}
	go l.keepalive()
	if err := d.advisoryLocks.register(l, gen); err != nil {
		l.Release()
		return nil, fmt.Errorf("failed to begin advisory lock transaction: %w", err)
	}
	return l, nil
}

// Lock takes the advisory lock id, waiting for a current holder. Cancel ctx to stop
// waiting; the transaction is then aborted and must be released.
func (l *AdvisoryLockTx) Lock(ctx context.Context, id int64) error {
	return l.run(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock("+strconv.FormatInt(id, 10)+")")
		return err
	})
}

// TryLock takes the advisory lock id if it is free and reports whether it did.
func (l *AdvisoryLockTx) TryLock(ctx context.Context, id int64) (bool, error) {
	var acquired bool
	err := l.run(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock("+strconv.FormatInt(id, 10)+")").Scan(&acquired)
	})
	return acquired, err
}

// TryLockAll tries every id in one statement and returns, in the same order, whether
// each was taken. An id that appears twice is taken twice by this same transaction, so
// a duplicate never reads as held by someone else.
func (l *AdvisoryLockTx) TryLockAll(ctx context.Context, ids []int64) ([]bool, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	literals := make([]string, len(ids))
	for i, id := range ids {
		literals[i] = strconv.FormatInt(id, 10)
	}
	sql := "SELECT pg_try_advisory_xact_lock(id) FROM unnest(ARRAY[" + strings.Join(literals, ",") + "]::bigint[]) AS t(id)"

	var acquired []bool
	err := l.run(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql)
		if err != nil {
			return err
		}
		acquired, err = pgx.CollectRows(rows, pgx.RowTo[bool])
		if err != nil {
			return err
		}
		if len(acquired) != len(ids) {
			return fmt.Errorf("got %d lock results for %d ids", len(acquired), len(ids))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return acquired, nil
}

// Ping proves the locks are still held: it runs a statement on the transaction, which
// fails if the session was killed or the connection dropped, taking the locks with it.
func (l *AdvisoryLockTx) Ping(ctx context.Context) error {
	return l.run(ctx, func(context.Context, pgx.Tx) error { return nil })
}

// Err reports whether the locks have been lost: nil while they are held, otherwise the
// error that took them (or errAdvisoryLockTxReleased after Release). Work that must not
// complete unprotected checks it after the guarded step.
func (l *AdvisoryLockTx) Err() error {
	l.lostMu.Lock()
	defer l.lostMu.Unlock()
	return l.lost
}

// Guard returns a child of parent that is cancelled, with the loss as its cause, as
// soon as the locks are lost or released. Work guarded by the locks runs under it so
// it stops rather than finishing unprotected. Call the returned function when the work
// is done.
func (l *AdvisoryLockTx) Guard(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	l.lostMu.Lock()
	if l.lost != nil {
		cancel(l.lost)
	} else {
		l.guards = append(l.guards, cancel)
	}
	l.lostMu.Unlock()
	return ctx, func() { cancel(nil) }
}

// run executes fn on the transaction under mu, then the bare SELECT 1 that leaves the
// backend idle without a snapshot (see the type comment). Ping is that trailing
// statement alone. The first failure marks the locks lost. A fence that came while the
// statements ran is reported too: what they locked or read no longer counts.
func (l *AdvisoryLockTx) run(ctx context.Context, fn func(ctx context.Context, tx pgx.Tx) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.Err(); err != nil {
		return err
	}
	if err := fn(ctx, l.tx); err != nil {
		l.fail(err)
		return err
	}
	if _, err := l.tx.Exec(ctx, "SELECT 1"); err != nil {
		l.fail(err)
		return err
	}
	l.lastStatement = time.Now()
	return l.Err()
}

// fail records the loss of the locks and cancels every Guard; only the first loss
// counts. It takes lostMu alone, so a fence calls it without waiting for a statement.
func (l *AdvisoryLockTx) fail(err error) {
	l.lostMu.Lock()
	defer l.lostMu.Unlock()
	if l.lost != nil {
		return
	}
	l.lost = err
	for _, cancel := range l.guards {
		cancel(err)
	}
	l.guards = nil
}

func (l *AdvisoryLockTx) keepalive() {
	defer close(l.keepaliveDone)
	ticker := time.NewTicker(advisoryLockKeepalive)
	defer ticker.Stop()
	for {
		select {
		case <-l.stopKeepalive:
			return
		case <-ticker.C:
			if !l.keepaliveTick() {
				return
			}
		}
	}
}

// keepaliveTick pings the transaction if nothing has run on it for a keepalive interval
// and reports whether the keepalive should go on. The ping's timeout starts only once
// the transaction is ours: a deadline armed while another statement held mu — a Lock
// waiting for its holder, a batch re-check — could expire in the queue, and a ping
// started with a dead context is cancelled at once, which aborts the transaction and
// drops every lock it holds.
func (l *AdvisoryLockTx) keepaliveTick() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.Err() != nil {
		return false
	}
	if time.Since(l.lastStatement) < advisoryLockKeepalive {
		return true // a statement just reset the server's idle timer
	}

	ctx, cancel := context.WithTimeout(context.Background(), advisoryLockStatementTimeout)
	defer cancel()
	l.pingMu.Lock()
	l.pingCancel = cancel
	l.pingMu.Unlock()
	defer func() {
		l.pingMu.Lock()
		l.pingCancel = nil
		l.pingMu.Unlock()
	}()

	if _, err := l.tx.Exec(ctx, "SELECT 1"); err != nil {
		// The transaction is gone and so are the locks; nothing left to keep alive.
		l.fail(err)
		return false
	}
	l.lastStatement = time.Now()
	return true
}

// Release ends the transaction, releasing every lock it holds, and returns the
// connection to the pool. It is idempotent, never blocks on the caller's context, and is
// safe after the transaction has already died. A keepalive ping in flight is cancelled
// rather than waited for, so a dead socket costs at most one statement timeout. A
// connection whose ROLLBACK fails is still inside a transaction as far as pgxpool can
// tell, so the pool destroys it rather than handing its locks to the next user.
func (l *AdvisoryLockTx) Release() {
	l.releaseOnce.Do(func() {
		close(l.stopKeepalive)
		l.pingMu.Lock()
		if l.pingCancel != nil {
			l.pingCancel()
		}
		l.pingMu.Unlock()
		<-l.keepaliveDone

		l.mu.Lock()
		defer l.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), advisoryLockStatementTimeout)
		defer cancel()
		// Quiet when the transaction is already known dead; a fenced one is not.
		if err := l.tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) && (l.Err() == nil || errors.Is(l.Err(), ErrAdvisoryLocksFenced)) {
			logger.Warn("Database: advisory lock transaction could not be rolled back, discarding its connection", "err", err)
		}
		l.conn.Release()
		l.fail(errAdvisoryLockTxReleased)
		l.fence.unregister(l)
	})
}
