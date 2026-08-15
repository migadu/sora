//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_CrashRetryDeliversDuplicate is the DEDUP-1 proof.
//
// Scenario: an upstream MTA delivers a message over LMTP, the 250 is lost (server
// crash / connection reset after the DB commit), and the MTA retries the SAME message
// bytes in a fresh LMTP session. Sora is designed to absorb that retry: db/append.go
// returns consts.ErrMessageExists for an exact duplicate and server/lmtp/session.go
// treats ErrMessageExists as a successful delivery ("duplicate message accepted").
//
// The dedup predicate is (mailbox_id, message_id, content_hash). But session.go stamps a
// per-attempt Received: trace header containing idgen.New() and time.Now() onto the
// message BEFORE the content hash is computed, so the two attempts hash differently, the
// dedup lookup misses, and the mailbox ends up with TWO copies of the same mail.
//
// Asserts the user-visible outcome: after two deliveries of identical bytes, INBOX holds
// exactly one message.
func TestLMTP_CrashRetryDeliversDuplicate(t *testing.T) {
	account, lmtpAddr, tempDir := setupLMTPForDelivery(t)

	// Separate handle for verification queries (same test database).
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("resolve account id for %s: %v", account.Email, err)
	}

	// One fixed set of message bytes, reused verbatim for both attempts.
	msg := strings.Join([]string{
		"From: sender@example.com",
		"To: " + account.Email,
		"Subject: Crash Retry Dedup",
		"Message-ID: <dedup1-" + fmt.Sprintf("%d", time.Now().UnixNano()) + "@example.com>",
		"Date: Mon, 02 Jan 2006 15:04:05 -0700",
		"",
		"Byte-for-byte identical on both delivery attempts.",
	}, "\r\n")

	// Attempt 1: the delivery whose 250 the upstream MTA never sees.
	if resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, msg); !strings.HasPrefix(resp, "250") {
		t.Fatalf("first delivery must be accepted, got: %s", resp)
	}
	// Attempt 2: the upstream MTA's retry — new session, identical bytes.
	if resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, msg); !strings.HasPrefix(resp, "250") {
		t.Fatalf("retry must be accepted (LMTP treats duplicates as success), got: %s", resp)
	}

	time.Sleep(500 * time.Millisecond)

	rows, err := rdb.QueryWithRetry(ctx, `
		SELECT m.uid, m.message_id, m.content_hash
		FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.account_id = $1 AND UPPER(mb.name) = 'INBOX' AND m.expunged_at IS NULL
		ORDER BY m.uid`, accountID)
	if err != nil {
		t.Fatalf("query delivered messages: %v", err)
	}
	type row struct {
		uid             int64
		messageID, hash string
	}
	var stored []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.uid, &r.messageID, &r.hash); err != nil {
			rows.Close()
			t.Fatalf("scan delivered message: %v", err)
		}
		stored = append(stored, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate delivered messages: %v", err)
	}

	for _, r := range stored {
		t.Logf("stored message uid=%d message_id=%s content_hash=%s", r.uid, r.messageID, r.hash)
	}
	t.Logf("distinct content hashes on disk: %d", countStoredBodies(t, tempDir))

	if len(stored) != 1 {
		hashes := make([]string, 0, len(stored))
		for _, r := range stored {
			hashes = append(hashes, r.hash)
		}
		t.Fatalf("LMTP crash-retry of identical message bytes must be deduplicated: "+
			"want 1 message in INBOX, got %d (content hashes: %v).\n"+
			"The per-attempt Received: trace stamped in server/lmtp/session.go (idgen.New() + "+
			"time.Now(), session.go:441-458) changes the bytes before helpers.HashContent, so the "+
			"(mailbox_id, message_id, content_hash) dedup in db/append.go:326-346 never matches and "+
			"the retry is stored as a second copy.",
			len(stored), hashes)
	}
}

// countStoredBodies counts distinct message body files (named by their 64-hex content
// hash) written under the uploader temp dir.
func countStoredBodies(t *testing.T, tempDir string) int {
	t.Helper()
	n := 0
	_ = filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && len(filepath.Base(path)) == 64 {
			n++
		}
		return nil
	})
	return n
}
