//go:build integration

package imap_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

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
