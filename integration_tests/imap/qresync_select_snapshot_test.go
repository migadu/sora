//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	serverimap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selectSummaryGate pauses a SELECT of one mailbox just after it has read the mailbox
// summary, the statement EXISTS, UIDNEXT and HIGHESTMODSEQ come from, so that a write
// from another session commits before the rest of the SELECT reads the mailbox.
type selectSummaryGate struct {
	mailboxID        int64
	armed, paused    atomic.Bool
	reached, release chan struct{}
	once             sync.Once
}

type selectSummaryGateKey struct{}

func (g *selectSummaryGate) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if g.armed.Load() && strings.Contains(q.SQL, "mb.highest_uid + 1") && strings.Contains(q.SQL, "LEFT JOIN mailbox_stats") &&
		len(q.Args) == 1 && q.Args[0] == g.mailboxID {
		return context.WithValue(ctx, selectSummaryGateKey{}, true)
	}
	return ctx
}

func (g *selectSummaryGate) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryEndData) {
	if ctx.Value(selectSummaryGateKey{}) != true || q.Err != nil || !g.paused.CompareAndSwap(false, true) {
		return
	}
	close(g.reached)
	select {
	case <-g.release:
	case <-ctx.Done():
	}
}

func (g *selectSummaryGate) resume() { g.once.Do(func() { close(g.release) }) }

// startTracedIMAPServer starts an IMAP server on source's database whose pool runs
// tracer on every statement.
func startTracedIMAPServer(t *testing.T, source *resilient.ResilientDatabase, tracer pgx.QueryTracer) string {
	t.Helper()
	ctx := context.Background()
	cfg := source.GetDatabase().WritePool.Config().ConnConfig
	rdb, err := resilient.NewResilientDatabase(ctx, &config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{cfg.Host}, Port: fmt.Sprint(cfg.Port), User: cfg.User, Password: cfg.Password, Name: cfg.Database,
	}}, false, false)
	require.NoError(t, err)
	t.Cleanup(rdb.Close)
	database := rdb.GetDatabase()
	old := database.WritePool
	poolCfg := old.Config().Copy()
	poolCfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	require.NoError(t, err)
	database.WritePool, database.ReadPool = pool, pool
	old.Close()
	addr := common.GetRandomAddress(t)
	srv, err := serverimap.New(ctx, "qresync-select-snapshot", "localhost", addr, &storage.S3Storage{}, rdb, nil, nil,
		serverimap.IMAPServerOptions{InsecureAuth: true})
	require.NoError(t, err)
	go func() { _ = srv.Serve(addr) }()
	t.Cleanup(func() { srv.Close() })
	require.Eventually(t, func() bool {
		c, err := imapclient.DialInsecure(addr, nil)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond)
	return addr
}

var (
	qrsExistsRe      = regexp.MustCompile(`^\* (\d+) EXISTS$`)
	qrsFetchRe       = regexp.MustCompile(`^\* (\d+) FETCH \(`)
	qrsModSeqRe      = regexp.MustCompile(`MODSEQ \((\d+)\)`)
	qrsHighestRe     = regexp.MustCompile(`^\* OK \[HIGHESTMODSEQ (\d+)\]`)
	qrsUnseenRe      = regexp.MustCompile(`^\* OK \[UNSEEN (\d+)\]`)
	qrsUIDValidityRe = regexp.MustCompile(`^\* OK \[UIDVALIDITY (\d+)\]`)
	qrsVanishedRe    = regexp.MustCompile(`^\* VANISHED (\(EARLIER\) )?([0-9:,]+)$`)
)

// qrsUIDSet expands a UID set without "*" ("2,4:6") into its UIDs.
func qrsUIDSet(t *testing.T, set string) []imap.UID {
	t.Helper()
	var uids []imap.UID
	for _, r := range strings.Split(set, ",") {
		lo, hi, isRange := strings.Cut(r, ":")
		if !isRange {
			hi = lo
		}
		a, b := mustAtoi(t, lo), mustAtoi(t, hi)
		if a > b {
			a, b = b, a
		}
		for uid := a; uid <= b; uid++ {
			uids = append(uids, imap.UID(uid))
		}
	}
	return uids
}

func qrsNumber(t *testing.T, re *regexp.Regexp, lines []string) (uint64, bool) {
	t.Helper()
	for _, l := range lines {
		if m := re.FindStringSubmatch(l); m != nil {
			n, err := strconv.ParseUint(m[1], 10, 64)
			require.NoError(t, err)
			return n, true
		}
	}
	return 0, false
}

// mailboxUIDsAt returns the UIDs of the mailbox as it stood at modSeq: the messages
// created by then and not yet expunged by then, which is the mailbox a SELECT that
// reports HIGHESTMODSEQ modSeq must describe.
func mailboxUIDsAt(t *testing.T, rdb *resilient.ResilientDatabase, mailboxID int64, modSeq uint64) []imap.UID {
	t.Helper()
	rows, err := rdb.GetDatabase().GetWritePool().Query(context.Background(), `
		SELECT uid FROM messages
		WHERE mailbox_id = $1 AND created_modseq <= $2 AND (expunged_at IS NULL OR expunged_modseq > $2)
		ORDER BY uid`, mailboxID, int64(modSeq))
	require.NoError(t, err)
	defer rows.Close()
	var uids []imap.UID
	for rows.Next() {
		var uid int64
		require.NoError(t, rows.Scan(&uid))
		uids = append(uids, imap.UID(uid))
	}
	require.NoError(t, rows.Err())
	return uids
}

// TestIMAP_QResyncSelectDescribesOneState is the regression test for #1293: a QRESYNC
// SELECT took EXISTS and HIGHESTMODSEQ from the mailbox summary, then read the vanished
// UIDs, the changes and their sequence numbers (and [UNSEEN n]) in later statements, each
// in its own snapshot. A delivery committing after the summary was sent as a FETCH past
// the EXISTS, a flag change as a FETCH past the HIGHESTMODSEQ, and an expunge shifted the
// numbers of the FETCHes after it and, with known UIDs, was reported as VANISHED
// (EARLIER) while EXISTS still counted the message.
//
// The SELECT is paused just after the summary while another session writes. Its response
// must describe the mailbox as of the HIGHESTMODSEQ it sends (RFC 9051 §2.3.1.2: a client
// numbers new messages from EXISTS), and the next poll must bring the client to the
// mailbox as it is now.
func TestIMAP_QResyncSelectDescribesOneState(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	msg := func(n int) string {
		return fmt.Sprintf("From: sender@example.com\r\nTo: user@example.com\r\nSubject: snapshot %d\r\n\r\nbody %d\r\n", n, n)
	}

	cases := []struct {
		name      string
		knownUIDs string // the client's known-uids, or none
		// write commits from another session while the SELECT is paused.
		write func(w *rawIMAP)
	}{
		{name: "delivery after the summary", write: func(w *rawIMAP) { w.appendMsg("INBOX", msg(5)) }},
		{name: "flag change after the summary", write: func(w *rawIMAP) { w.do(`UID STORE 1 +FLAGS.SILENT (\Answered)`) }},
		{name: "expunge after the summary", write: func(w *rawIMAP) { w.do("EXPUNGE") }},
		{name: "expunge after the summary with known UIDs", knownUIDs: "1:3", write: func(w *rawIMAP) { w.do("EXPUNGE") }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()

			w := dialRawIMAP(t, server.Address)
			w.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			for i := 1; i <= 3; i++ {
				w.appendMsg("INBOX", msg(i))
			}
			w.do("SELECT INBOX")
			w.do(`UID STORE 1:2 +FLAGS.SILENT (\Seen)`)

			ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(ctx, owner.Email)
			require.NoError(t, err)
			mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, ownerID, "INBOX")
			require.NoError(t, err)

			// The client has UIDs 1-3 cached at modseq M. Since then UID 4 arrived, UID 3
			// was flagged and UID 2 marked \Deleted.
			var cached uint64
			require.NoError(t, server.ResilientDB.QueryRowWithRetry(ctx,
				`SELECT highest_modseq FROM mailbox_stats WHERE mailbox_id = $1`, mailbox.ID).Scan(&cached))
			w.appendMsg("INBOX", msg(4))
			w.do(`UID STORE 3 +FLAGS.SILENT (\Flagged)`)
			w.do(`UID STORE 2 +FLAGS.SILENT (\Deleted)`)

			gate := &selectSummaryGate{mailboxID: mailbox.ID, reached: make(chan struct{}), release: make(chan struct{})}
			defer gate.resume()
			addr := startTracedIMAPServer(t, server.ResilientDB, gate)

			c := dialRawIMAP(t, addr)
			c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			c.do("ENABLE QRESYNC")
			qresync := fmt.Sprintf("%d %d", mailbox.UIDValidity, cached)
			if tc.knownUIDs != "" {
				qresync += " " + tc.knownUIDs
			}

			gate.armed.Store(true)
			done := make(chan []string, 1)
			go func() {
				untagged, _ := c.do(fmt.Sprintf("SELECT INBOX (QRESYNC (%s))", qresync))
				done <- untagged
			}()
			select {
			case <-gate.reached:
			case <-time.After(5 * time.Second):
				t.Fatal("SELECT did not reach the summary gate")
			}
			tc.write(w)
			gate.resume()

			var lines []string
			select {
			case lines = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("SELECT did not finish")
			}
			t.Logf("SELECT response:\n%s", strings.Join(lines, "\n"))

			uidValidity, ok := qrsNumber(t, qrsUIDValidityRe, lines)
			require.True(t, ok && uint32(uidValidity) == mailbox.UIDValidity, "harness broken: UIDVALIDITY mismatch, QRESYNC was ignored")
			exists, ok := qrsNumber(t, qrsExistsRe, lines)
			require.True(t, ok, "no EXISTS in the SELECT response")
			highest, ok := qrsNumber(t, qrsHighestRe, lines)
			require.True(t, ok, "no HIGHESTMODSEQ in the SELECT response")

			// The mailbox the response must describe.
			view := mailboxUIDsAt(t, server.ResilientDB, mailbox.ID, highest)
			require.Equalf(t, len(view), int(exists), "* %d EXISTS, but the mailbox at HIGHESTMODSEQ %d holds %v", exists, highest, view)

			var fetched []imap.UID
			for _, l := range lines {
				if m := qrsVanishedRe.FindStringSubmatch(l); m != nil {
					assert.NotEmptyf(t, m[1], "a SELECT reports expunges as VANISHED (EARLIER): %s", l)
					for _, uid := range qrsUIDSet(t, m[2]) {
						assert.Falsef(t, slices.Contains(view, uid),
							"%s reports UID %d, which * %d EXISTS still counts in %v", l, uid, exists, view)
					}
					continue
				}
				m := qrsFetchRe.FindStringSubmatch(l)
				if m == nil {
					continue
				}
				seq := mustAtoi(t, m[1])
				um := uidRe.FindStringSubmatch(l)
				require.NotNilf(t, um, "QRESYNC FETCH without UID: %s", l)
				uid := imap.UID(mustAtoi(t, um[1]))
				fetched = append(fetched, uid)
				assert.Truef(t, seq >= 1 && seq <= len(view) && view[seq-1] == uid,
					"%s does not name that message in the mailbox %v announced by * %d EXISTS", l, view, exists)
				if mm := qrsModSeqRe.FindStringSubmatch(l); mm != nil {
					modSeq, err := strconv.ParseUint(mm[1], 10, 64)
					require.NoError(t, err)
					assert.LessOrEqualf(t, modSeq, highest, "%s reports a change past * OK [HIGHESTMODSEQ %d]", l, highest)
				}
			}
			// UIDs 2 and 3 changed after the client's mod-sequence and before HIGHESTMODSEQ,
			// and both are still in the mailbox at HIGHESTMODSEQ.
			for _, uid := range []imap.UID{2, 3} {
				assert.Containsf(t, fetched, uid, "the SELECT does not report the flag change of UID %d", uid)
			}

			// UIDs 1 and 2 are \Seen, so the first unseen message is UID 3.
			unseen, ok := qrsNumber(t, qrsUnseenRe, lines)
			require.True(t, ok, "no [UNSEEN n] in the SELECT response")
			assert.Truef(t, unseen >= 1 && int(unseen) <= len(view) && view[unseen-1] == 3,
				"[UNSEEN %d] does not name UID 3, the first unseen message of %v", unseen, view)
			if t.Failed() {
				return
			}

			// The next poll reports what happened after HIGHESTMODSEQ.
			client := slices.Clone(view)
			noop, _ := c.do("NOOP")
			t.Logf("NOOP response:\n%s", strings.Join(noop, "\n"))
			for _, l := range noop {
				if m := qrsVanishedRe.FindStringSubmatch(l); m != nil {
					require.Emptyf(t, m[1], "a poll reports expunges as VANISHED without EARLIER: %s", l)
					for _, uid := range qrsUIDSet(t, m[2]) {
						i := slices.Index(client, uid)
						require.GreaterOrEqualf(t, i, 0, "%s names a message the client does not have in %v", l, client)
						client = slices.Delete(client, i, i+1)
					}
				} else if m := qrsExistsRe.FindStringSubmatch(l); m != nil {
					n := mustAtoi(t, m[1])
					require.GreaterOrEqualf(t, n, len(client), "%s after the client was told of %v", l, client)
					for len(client) < n {
						client = append(client, 0)
					}
				} else if m := qrsFetchRe.FindStringSubmatch(l); m != nil {
					seq := mustAtoi(t, m[1])
					require.Truef(t, seq >= 1 && seq <= len(client), "%s is past the %d messages of %v", l, len(client), client)
					if um := uidRe.FindStringSubmatch(l); um != nil {
						uid := imap.UID(mustAtoi(t, um[1]))
						require.Truef(t, client[seq-1] == 0 || client[seq-1] == uid, "%s does not name that message in %v", l, client)
						client[seq-1] = uid
					}
				}
			}
			require.Equal(t, mailboxUIDsAt(t, server.ResilientDB, mailbox.ID, 1<<62), client,
				"after the next poll the client's view must be the mailbox")
		})
	}
}
