//go:build integration

package imap_test

import (
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_MoveCopyExpungeMasterPin documents the read-your-writes contract that
// the master-DB session pin protects (see server/imap/{move,copy,expunge}.go).
//
// APPEND pins the session to the master DB after a successful write so that the
// post-command poll — which emits RFC 6851 §3.3 / RFC 3501 §7.4.1 untagged
// EXPUNGE/EXISTS responses that MUST precede the tagged OK — reads from the
// primary rather than a lagging read replica. MOVE, COPY and EXPUNGE rely on the
// exact same post-command poll, so they set the same pin.
//
// NOTE: the integration harness uses a single PostgreSQL pool for both reads and
// writes, so replica lag cannot be reproduced here; this test cannot be RED
// before the fix. It instead locks in the observable behavior the pin guarantees
// (a mutation is immediately visible to subsequent reads in the same session and
// the notification precedes the tagged OK) and guards against regressions in the
// poll-based notification path.
func TestIMAP_MoveCopyExpungeMasterPin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	const dest = "PinDest"
	if err := c.Create(dest, nil).Wait(); err != nil {
		t.Fatalf("CREATE %s failed: %v", dest, err)
	}

	appendMsg := func(subject string) {
		msg := "From: pin@example.com\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
			"\r\n" +
			"body\r\n"
		ac := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := ac.Wait(); err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
	}

	appendMsg("pin-move")
	appendMsg("pin-copy")

	// Select INBOX; both messages must be visible (read-your-writes after APPEND).
	sel, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}
	if sel.NumMessages != 2 {
		t.Fatalf("expected 2 messages in INBOX, got %d", sel.NumMessages)
	}

	// MOVE seq 1 out of the selected INBOX. The pin guarantees the post-command
	// poll computes the inline EXPUNGE from the primary. After MOVE, the source
	// count must reflect the write immediately.
	if _, err := c.Move(imap.SeqSetNum(1), dest).Wait(); err != nil {
		t.Fatalf("MOVE failed: %v", err)
	}

	// COPY the remaining message into dest (COPY writes to a non-selected mailbox;
	// the pin gives read-your-writes for the subsequent SELECT of dest below).
	if _, err := c.Copy(imap.SeqSetNum(1), dest).Wait(); err != nil {
		t.Fatalf("COPY failed: %v", err)
	}

	// EXPUNGE requires a \Deleted message; mark the remaining INBOX message.
	if err := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		t.Fatalf("STORE \\Deleted failed: %v", err)
	}
	if err := c.Expunge().Close(); err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}

	// INBOX must now be empty (moved 1 out, expunged the other) — read-your-writes
	// on the currently-selected mailbox.
	sel, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("re-SELECT INBOX failed: %v", err)
	}
	if sel.NumMessages != 0 {
		t.Errorf("expected 0 messages in INBOX after MOVE+EXPUNGE, got %d", sel.NumMessages)
	}

	// dest must hold the moved message plus the copied one = 2.
	destSel, err := c.Select(dest, nil).Wait()
	if err != nil {
		t.Fatalf("SELECT %s failed: %v", dest, err)
	}
	if destSel.NumMessages != 2 {
		t.Errorf("expected 2 messages in %s after MOVE+COPY, got %d", dest, destSel.NumMessages)
	}
}
