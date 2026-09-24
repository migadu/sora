//go:build integration

package imap_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// poisonKeyword is not a valid IMAP atom (RFC 9051 flag-keyword): every byte is
// non-ASCII. The Sieve `addflag` path stores keywords without any atom check, so
// a script can put this into message_state.custom_flags, from where the stats
// trigger unions it into mailbox_stats.custom_flags_cache — the per-mailbox
// keyword registry that SELECT advertises.
const poisonKeyword = "НЕОБРАБОТЕНО"

// TestIMAP_PoisonKeywordDoesNotWedgeSelect reproduces the production incident in
// which a Sieve `addflag "НЕОБРАБОТЕНО"` made INBOX permanently unopenable. The
// keyword reaches the mailbox keyword registry, SELECT puts it in * FLAGS (...),
// and the encoder rejects it mid-list: the untagged response is never terminated
// and never flushed, so the client waits for a tagged reply that never arrives.
//
// SELECT must complete. Advertising the keyword is optional; wedging is not.
func TestIMAP_PoisonKeywordDoesNotWedgeSelect(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	ctx := context.Background()

	// Append one message so INBOX has a message_state row to poison.
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	literal := "From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nbody\r\n"
	app := c.Append("INBOX", int64(len(literal)), nil)
	if _, err := app.Write([]byte(literal)); err != nil {
		t.Fatalf("APPEND write: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Fatalf("APPEND close: %v", err)
	}
	if _, err := app.Wait(); err != nil {
		t.Fatalf("APPEND: %v", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT before poisoning failed: %v", err)
	}
	c.Logout()

	// Poison exactly the way the Sieve path does: write the keyword onto the
	// message's custom_flags. The mailbox_stats trigger unions it into the
	// mailbox's custom_flags_cache from there.
	accountID, err := server.ResilientDB.GetDatabase().GetAccountIDByAddress(ctx, account.Email)
	if err != nil {
		t.Fatalf("resolving account id: %v", err)
	}

	pool := server.ResilientDB.GetDatabase().GetWritePool()
	tag, err := pool.Exec(ctx, `
		UPDATE message_state ms
		SET custom_flags = $1::jsonb, updated_modseq = ms.updated_modseq + 1
		FROM messages m
		JOIN mailboxes mb ON mb.id = m.mailbox_id
		WHERE ms.message_id = m.id
		  AND m.expunged_at IS NULL
		  AND mb.account_id = $2
		  AND lower(mb.name) = 'inbox'`,
		fmt.Sprintf(`[%q]`, poisonKeyword), accountID)
	if err != nil {
		t.Fatalf("poisoning message_state: %v", err)
	}
	if tag.RowsAffected() == 0 {
		t.Fatalf("poisoning affected no rows; test setup is wrong")
	}

	// Confirm the keyword really did reach the mailbox keyword registry, i.e.
	// that this test is exercising the reported failure and not something milder.
	var cache []byte
	if err := pool.QueryRow(ctx, `
		SELECT COALESCE(mstats.custom_flags_cache, '[]'::jsonb)::text::bytea
		FROM mailbox_stats mstats
		JOIN mailboxes mb ON mb.id = mstats.mailbox_id
		WHERE mb.account_id = $1 AND lower(mb.name) = 'inbox'`,
		accountID).Scan(&cache); err != nil {
		t.Fatalf("reading custom_flags_cache: %v", err)
	}
	if !strings.Contains(string(cache), poisonKeyword) {
		t.Fatalf("precondition failed: keyword never reached custom_flags_cache, got %s", cache)
	}
	t.Logf("mailbox keyword registry now holds: %s", cache)

	// Now SELECT INBOX over a raw connection so we can see the actual bytes and
	// bound the wait ourselves rather than hanging for the whole test timeout.
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)

	if _, err := br.ReadString('\n'); err != nil { // greeting
		t.Fatalf("greeting: %v", err)
	}
	fmt.Fprintf(conn, "a1 LOGIN %s %s\r\n", account.Email, account.Password)
	if err := readTaggedWithin(t, conn, br, "a1", 10*time.Second); err != nil {
		t.Fatalf("raw LOGIN: %v", err)
	}

	fmt.Fprintf(conn, "a2 SELECT INBOX\r\n")
	if err := readTaggedWithin(t, conn, br, "a2", 10*time.Second); err != nil {
		t.Fatalf("SELECT INBOX never produced a tagged response: %v\n"+
			"INBOX is wedged by the non-atom keyword %q in the mailbox keyword registry",
			err, poisonKeyword)
	}
}

// readTaggedWithin reads lines until one starts with tag+" ", bounding the wait
// with a read deadline on the connection. It reads synchronously on the caller's
// goroutine: a background reader would survive past its own call and steal the
// next command's response off the shared bufio.Reader.
func readTaggedWithin(t *testing.T, conn net.Conn, br *bufio.Reader, tag string, timeout time.Duration) error {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("setting read deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{})

	for {
		line, err := br.ReadString('\n')
		if line != "" {
			t.Logf("S: %q", strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			return fmt.Errorf("no tagged response for %q within %s: %w", tag, timeout, err)
		}
		if strings.HasPrefix(line, tag+" ") {
			return nil
		}
	}
}

// TestIMAP_PoisonKeywordDoesNotWedgeUnsolicitedFetch covers the other way a
// stored non-atom keyword reaches a client: the unsolicited FETCH another
// session's flag change produces. A system-only STORE (+FLAGS (\Seen)) updates
// the flags bitmask and leaves message_state.custom_flags untouched, so the
// poll that follows reports the message's full flag list -- poisoned keyword
// included -- to every session that has the mailbox selected. If that list is
// not filtered, the encoder abandons the untagged FETCH mid-list exactly as it
// did for SELECT, and the watching session never sees its next tagged reply.
func TestIMAP_PoisonKeywordDoesNotWedgeUnsolicitedFetch(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	ctx := context.Background()

	// Session B: appends the message and later changes its flags.
	b, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer b.Logout()
	if err := b.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login B: %v", err)
	}
	literal := "From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nbody\r\n"
	app := b.Append("INBOX", int64(len(literal)), nil)
	if _, err := app.Write([]byte(literal)); err != nil {
		t.Fatalf("APPEND write: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Fatalf("APPEND close: %v", err)
	}
	if _, err := app.Wait(); err != nil {
		t.Fatalf("APPEND: %v", err)
	}

	accountID, err := server.ResilientDB.GetDatabase().GetAccountIDByAddress(ctx, account.Email)
	if err != nil {
		t.Fatalf("resolving account id: %v", err)
	}
	pool := server.ResilientDB.GetDatabase().GetWritePool()
	if _, err := pool.Exec(ctx, `
		UPDATE message_state ms
		SET custom_flags = $1::jsonb, updated_modseq = nextval('messages_modseq')
		FROM messages m
		JOIN mailboxes mb ON mb.id = m.mailbox_id
		WHERE ms.message_id = m.id
		  AND m.expunged_at IS NULL
		  AND mb.account_id = $2
		  AND lower(mb.name) = 'inbox'`,
		fmt.Sprintf(`[%q]`, poisonKeyword), accountID); err != nil {
		t.Fatalf("poisoning message_state: %v", err)
	}

	// Session A: selects INBOX over a raw connection and watches.
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	fmt.Fprintf(conn, "a1 LOGIN %s %s\r\n", account.Email, account.Password)
	if err := readTaggedWithin(t, conn, br, "a1", 10*time.Second); err != nil {
		t.Fatalf("raw LOGIN: %v", err)
	}
	fmt.Fprintf(conn, "a2 SELECT INBOX\r\n")
	if err := readTaggedWithin(t, conn, br, "a2", 10*time.Second); err != nil {
		t.Fatalf("SELECT INBOX: %v", err)
	}

	// B sets a system flag only. This must leave the poisoned keyword in place,
	// or the test is not exercising the unfiltered path.
	if _, err := b.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT B: %v", err)
	}
	if _, err := b.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil).Collect(); err != nil {
		t.Fatalf("STORE +FLAGS (\\Seen) from B: %v", err)
	}
	var stillPoisoned bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM message_state ms
			JOIN mailboxes mb ON mb.id = ms.mailbox_id
			WHERE mb.account_id = $1 AND lower(mb.name) = 'inbox'
			  AND ms.custom_flags @> jsonb_build_array($2::text))`,
		accountID, poisonKeyword).Scan(&stillPoisoned); err != nil {
		t.Fatalf("checking custom_flags: %v", err)
	}
	if !stillPoisoned {
		t.Fatalf("precondition failed: the system-only STORE rewrote custom_flags, so the poll would not carry the keyword")
	}

	// A's next command triggers a poll, which reports B's change unsolicited.
	fmt.Fprintf(conn, "a3 NOOP\r\n")
	if err := readTaggedWithin(t, conn, br, "a3", 10*time.Second); err != nil {
		t.Fatalf("NOOP never completed after another session's flag change: %v\n"+
			"the unsolicited FETCH carried the non-atom keyword %q and wedged the session",
			err, poisonKeyword)
	}
}

// TestMigration049PurgesNonAtomKeywords runs migration 000049's SQL against a
// poisoned mailbox and a clean one. The poisoned mailbox holds a live and an
// expunged message: the expunged row must be cleaned too, or a later restore
// would carry the keyword back into the registry through the stats trigger.
// The clean mailbox proves the migration's registry-scoped lookup leaves
// unaffected mailboxes alone.
func TestMigration049PurgesNonAtomKeywords(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	ctx := context.Background()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := c.Create("Clean", nil).Wait(); err != nil {
		t.Fatalf("CREATE Clean: %v", err)
	}
	appendTo := func(mbox string) {
		t.Helper()
		literal := "From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nbody\r\n"
		app := c.Append(mbox, int64(len(literal)), nil)
		if _, err := app.Write([]byte(literal)); err != nil {
			t.Fatalf("APPEND write: %v", err)
		}
		if err := app.Close(); err != nil {
			t.Fatalf("APPEND close: %v", err)
		}
		if _, err := app.Wait(); err != nil {
			t.Fatalf("APPEND %s: %v", mbox, err)
		}
	}
	appendTo("INBOX")
	appendTo("INBOX")
	appendTo("Clean")

	// Expunge the second INBOX message so the poisoned mailbox has a soft-deleted row.
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT: %v", err)
	}
	if _, err := c.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Collect(); err != nil {
		t.Fatalf("STORE \\Deleted: %v", err)
	}
	if _, err := c.Expunge().Collect(); err != nil {
		t.Fatalf("EXPUNGE: %v", err)
	}

	accountID, err := server.ResilientDB.GetDatabase().GetAccountIDByAddress(ctx, account.Email)
	if err != nil {
		t.Fatalf("resolving account id: %v", err)
	}
	pool := server.ResilientDB.GetDatabase().GetWritePool()

	// Poison every INBOX row, live and expunged, alongside a valid keyword that
	// must survive. Give Clean a valid keyword only.
	if _, err := pool.Exec(ctx, `
		UPDATE message_state ms SET custom_flags = $1::jsonb
		FROM mailboxes mb
		WHERE mb.id = ms.mailbox_id AND mb.account_id = $2 AND lower(mb.name) = 'inbox'`,
		fmt.Sprintf(`[%q, "Work"]`, poisonKeyword), accountID); err != nil {
		t.Fatalf("poisoning INBOX: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE message_state ms SET custom_flags = '["Keep"]'::jsonb
		FROM mailboxes mb
		WHERE mb.id = ms.mailbox_id AND mb.account_id = $1 AND mb.name = 'Clean'`,
		accountID); err != nil {
		t.Fatalf("tagging Clean: %v", err)
	}

	var cleanStampBefore time.Time
	if err := pool.QueryRow(ctx, `
		SELECT mstats.updated_at FROM mailbox_stats mstats
		JOIN mailboxes mb ON mb.id = mstats.mailbox_id
		WHERE mb.account_id = $1 AND mb.name = 'Clean'`, accountID).Scan(&cleanStampBefore); err != nil {
		t.Fatalf("reading Clean stats: %v", err)
	}

	migration, err := os.ReadFile("../../db/migrations/000049_purge_non_atom_keywords.up.sql")
	if err != nil {
		t.Fatalf("reading migration: %v", err)
	}
	if _, err := pool.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("running migration 000049: %v", err)
	}

	type row struct {
		mailbox  string
		expunged bool
		flags    string
	}
	rows, err := pool.Query(ctx, `
		SELECT mb.name, m.expunged_at IS NOT NULL, ms.custom_flags::text
		FROM message_state ms
		JOIN messages m ON m.id = ms.message_id
		JOIN mailboxes mb ON mb.id = ms.mailbox_id
		WHERE mb.account_id = $1
		ORDER BY mb.name, m.uid`, accountID)
	if err != nil {
		t.Fatalf("reading message_state: %v", err)
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.mailbox, &r.expunged, &r.flags); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, r)
	}
	rows.Close()

	sawExpunged := false
	for _, r := range got {
		if strings.Contains(r.flags, poisonKeyword) {
			t.Errorf("%s message (expunged=%v) still carries the keyword: %s", r.mailbox, r.expunged, r.flags)
		}
		switch {
		case strings.EqualFold(r.mailbox, "INBOX"):
			if r.flags != `["Work"]` {
				t.Errorf("INBOX message (expunged=%v): custom_flags = %s, want [\"Work\"]", r.expunged, r.flags)
			}
			if r.expunged {
				sawExpunged = true
			}
		case r.mailbox == "Clean":
			if r.flags != `["Keep"]` {
				t.Errorf("Clean message was modified: custom_flags = %s", r.flags)
			}
		}
	}
	if !sawExpunged {
		t.Fatalf("precondition failed: no expunged INBOX row was checked")
	}

	var inboxCache string
	if err := pool.QueryRow(ctx, `
		SELECT mstats.custom_flags_cache::text FROM mailbox_stats mstats
		JOIN mailboxes mb ON mb.id = mstats.mailbox_id
		WHERE mb.account_id = $1 AND lower(mb.name) = 'inbox'`, accountID).Scan(&inboxCache); err != nil {
		t.Fatalf("reading INBOX registry: %v", err)
	}
	if strings.Contains(inboxCache, poisonKeyword) || !strings.Contains(inboxCache, "Work") {
		t.Errorf("INBOX registry = %s, want the keyword gone and \"Work\" kept", inboxCache)
	}

	var cleanStampAfter time.Time
	if err := pool.QueryRow(ctx, `
		SELECT mstats.updated_at FROM mailbox_stats mstats
		JOIN mailboxes mb ON mb.id = mstats.mailbox_id
		WHERE mb.account_id = $1 AND mb.name = 'Clean'`, accountID).Scan(&cleanStampAfter); err != nil {
		t.Fatalf("reading Clean stats: %v", err)
	}
	if !cleanStampAfter.Equal(cleanStampBefore) {
		t.Errorf("the migration rewrote the registry of a mailbox with no invalid keywords")
	}
}

// TestIMAP_PoisonKeywordDoesNotWedgeQresyncSelect covers the third way a stored
// keyword reaches a client: SELECT ... (QRESYNC (...)) reports every message
// changed since the client's modseq as a FETCH inside the SELECT response. That
// list is built in db.GetMessagesChangedSince, separately from FETCH and poll,
// so it needs the same filter.
func TestIMAP_PoisonKeywordDoesNotWedgeQresyncSelect(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	ctx := context.Background()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	literal := "From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nbody\r\n"
	app := c.Append("INBOX", int64(len(literal)), nil)
	if _, err := app.Write([]byte(literal)); err != nil {
		t.Fatalf("APPEND write: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Fatalf("APPEND close: %v", err)
	}
	if _, err := app.Wait(); err != nil {
		t.Fatalf("APPEND: %v", err)
	}
	sel, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT: %v", err)
	}
	uidValidity := sel.UIDValidity
	c.Logout()

	accountID, err := server.ResilientDB.GetDatabase().GetAccountIDByAddress(ctx, account.Email)
	if err != nil {
		t.Fatalf("resolving account id: %v", err)
	}
	// Bump updated_modseq so the message counts as changed since modseq 1.
	if _, err := server.ResilientDB.GetDatabase().GetWritePool().Exec(ctx, `
		UPDATE message_state ms
		SET custom_flags = $1::jsonb, updated_modseq = nextval('messages_modseq')
		FROM mailboxes mb
		WHERE mb.id = ms.mailbox_id AND mb.account_id = $2 AND lower(mb.name) = 'inbox'`,
		fmt.Sprintf(`[%q, "Work"]`, poisonKeyword), accountID); err != nil {
		t.Fatalf("poisoning message_state: %v", err)
	}

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	fmt.Fprintf(conn, "a1 LOGIN %s %s\r\n", account.Email, account.Password)
	if err := readTaggedWithin(t, conn, br, "a1", 10*time.Second); err != nil {
		t.Fatalf("raw LOGIN: %v", err)
	}
	fmt.Fprintf(conn, "a2 ENABLE QRESYNC\r\n")
	if err := readTaggedWithin(t, conn, br, "a2", 10*time.Second); err != nil {
		t.Fatalf("ENABLE QRESYNC: %v", err)
	}

	// Read the SELECT response by hand so we can check the modified-message
	// FETCH was actually emitted -- otherwise this is not exercising the path.
	fmt.Fprintf(conn, "a3 SELECT INBOX (QRESYNC (%d 1))\r\n", uidValidity)
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	sawModified := false
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			t.Logf("S: %q", strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			t.Fatalf("QRESYNC SELECT never completed: %v\n"+
				"the modified-message FETCH carried the non-atom keyword %q and aborted the response",
				err, poisonKeyword)
		}
		if strings.HasPrefix(line, "* 1 FETCH") {
			sawModified = true
			if strings.Contains(line, poisonKeyword) {
				t.Errorf("QRESYNC FETCH carried the invalid keyword: %q", line)
			}
			if !strings.Contains(line, "Work") {
				t.Errorf("QRESYNC FETCH dropped the valid keyword too: %q", line)
			}
		}
		if strings.HasPrefix(line, "a3 ") {
			if !strings.HasPrefix(line, "a3 OK") {
				t.Fatalf("QRESYNC SELECT failed: %q", line)
			}
			break
		}
	}
	if !sawModified {
		t.Fatalf("precondition failed: QRESYNC SELECT reported no modified message, so the filtered path was not exercised")
	}
}
