//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// TestDelete_TwoPhase_VisibleGoneImmediately verifies the user-facing contract of
// two-phase mailbox deletion: even though the heavy message expunge is deferred to the
// background cleaner, a DELETEd mailbox is invisible to the client IMMEDIATELY — gone
// from LIST and unselectable — and its name is free for an immediate re-CREATE. The
// invisibility is observed from a SEPARATE connection to rule out per-session caching.
func TestDelete_TwoPhase_VisibleGoneImmediately(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c.Close()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Create a folder with a message in it (so the deferred expunge has real work).
	if err := c.Create("Project", nil).Wait(); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	appendTestMsg(t, c, "Project", "hello")

	if err := c.Delete("Project").Wait(); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// From a FRESH connection: the folder must already be gone from LIST and SELECT.
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to connect (2nd): %v", err)
	}
	defer c2.Close()
	if err := c2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed (2nd): %v", err)
	}

	mboxes, err := c2.List("", "*", nil).Collect()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	for _, m := range mboxes {
		if m.Mailbox == "Project" {
			t.Fatalf("deleted mailbox 'Project' must not appear in LIST, but it did")
		}
	}

	if _, err := c2.Select("Project", &imap.SelectOptions{ReadOnly: true}).Wait(); err == nil {
		t.Fatalf("SELECT of a deleted mailbox must fail, but it succeeded")
	}

	// Name is free immediately: re-CREATE must succeed while the tombstone still exists.
	if err := c2.Create("Project", nil).Wait(); err != nil {
		t.Fatalf("re-CREATE of deleted mailbox name must succeed immediately: %v", err)
	}

	// The recreated folder is empty (the old message belongs to the tombstone, pending purge).
	selData, err := c2.Select("Project", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT of recreated mailbox failed: %v", err)
	}
	if selData.NumMessages != 0 {
		t.Fatalf("recreated mailbox should be empty, got %d messages", selData.NumMessages)
	}
}

// TestDelete_TwoPhase_BackgroundPurgeOrchestration exercises the real resilient sweep
// (PurgeSoftDeletedMailboxesWithRetry) end-to-end: after an IMAP DELETE soft-deletes a
// folder, the worker-path orchestration hard-deletes it in its own transaction and
// expunges its messages. This is the per-mailbox-transaction path (not a single batch tx)
// that prevents a poison pill on large backlogs.
func TestDelete_TwoPhase_BackgroundPurgeOrchestration(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	ctx := context.Background()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}

	if err := c.Create("Purgeable", nil).Wait(); err != nil {
		t.Fatalf("create: %v", err)
	}
	appendTestMsg(t, c, "Purgeable", "doomed")

	// Capture the mailbox id BEFORE delete (it becomes unresolvable by name after).
	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	mbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "Purgeable")
	if err != nil {
		t.Fatalf("get mailbox: %v", err)
	}
	mailboxID := mbox.ID

	if err := c.Delete("Purgeable").Wait(); err != nil {
		t.Fatalf("delete: %v", err)
	}

	pool := server.ResilientDB.GetDatabase().GetWritePool()

	// Drain via the real orchestration until our tombstone is gone. The shared test DB
	// accumulates tombstones from other tests (no cleaner runs), so loop like the worker.
	var rowCount = 1
	for i := 0; i < 200 && rowCount > 0; i++ {
		if _, err := server.ResilientDB.PurgeSoftDeletedMailboxesWithRetry(ctx, 0); err != nil {
			t.Fatalf("purge sweep returned error: %v", err)
		}
		if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM mailboxes WHERE id = $1", mailboxID).Scan(&rowCount); err != nil {
			t.Fatalf("count mailbox row: %v", err)
		}
	}
	if rowCount != 0 {
		t.Fatalf("tombstone mailbox row should be purged by the background sweep, still present")
	}

	// Its message is now expunged (entered the normal expunged-message cleanup path).
	var expunged int
	if err := pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE mailbox_path = 'Purgeable' AND account_id = $1 AND expunged_at IS NOT NULL", accountID).Scan(&expunged); err != nil {
		t.Fatalf("count expunged: %v", err)
	}
	if expunged != 1 {
		t.Fatalf("expected the purged folder's 1 message to be expunged with mailbox_path preserved, got %d", expunged)
	}
}

// TestDelete_TwoPhase_GetOrCreateSkipsTombstone guards against delivery/import data loss.
// GetOrCreateMailboxByNameWithRetry backs LMTP `fileinto :create` and the maildir importer.
// It must treat a soft-deleted mailbox as non-existent and create a FRESH live one — never
// reuse the tombstone, which the background sweep would expunge, silently dropping the
// just-delivered/imported message.
func TestDelete_TwoPhase_GetOrCreateSkipsTombstone(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	ctx := context.Background()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := c.Create("CustomBox", nil).Wait(); err != nil {
		t.Fatalf("create: %v", err)
	}

	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	orig, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "CustomBox")
	if err != nil {
		t.Fatalf("get original: %v", err)
	}

	if err := c.Delete("CustomBox").Wait(); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Simulate the LMTP/import resolve-or-create path against the just-deleted name.
	got, err := server.ResilientDB.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "CustomBox")
	if err != nil {
		t.Fatalf("GetOrCreate after soft-delete: %v", err)
	}
	if got.ID == orig.ID {
		t.Fatalf("GetOrCreate reused the soft-deleted tombstone (id=%d) — delivered mail would be purged", got.ID)
	}

	// The result is a live, resolvable mailbox.
	live, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "CustomBox")
	if err != nil {
		t.Fatalf("recreated mailbox should be resolvable: %v", err)
	}
	if live.ID != got.ID {
		t.Fatalf("GetOrCreate result (%d) and name lookup (%d) disagree", got.ID, live.ID)
	}
}

// TestDelete_TwoPhase_StatusInvisible verifies STATUS (a non-selecting lookup by name)
// also treats a soft-deleted mailbox as non-existent.
func TestDelete_TwoPhase_StatusInvisible(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}

	if err := c.Create("Folder", nil).Wait(); err != nil {
		t.Fatalf("create: %v", err)
	}
	// STATUS works while live.
	if _, err := c.Status("Folder", &imap.StatusOptions{NumMessages: true}).Wait(); err != nil {
		t.Fatalf("STATUS on live mailbox should succeed: %v", err)
	}

	if err := c.Delete("Folder").Wait(); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// STATUS on the deleted mailbox must fail (it is no longer resolvable by name).
	if _, err := c.Status("Folder", &imap.StatusOptions{NumMessages: true}).Wait(); err == nil {
		t.Fatalf("STATUS on a deleted mailbox must fail, but it succeeded")
	}
}

// TestDelete_TwoPhase_RenameIntoDeletedName verifies a live mailbox can be renamed onto
// a soft-deleted mailbox's name immediately — the tombstone does not block the name
// (collision check + partial unique index both ignore deleted_at IS NOT NULL rows).
func TestDelete_TwoPhase_RenameIntoDeletedName(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}

	if err := c.Create("Old", nil).Wait(); err != nil {
		t.Fatalf("create Old: %v", err)
	}
	if err := c.Create("Gone", nil).Wait(); err != nil {
		t.Fatalf("create Gone: %v", err)
	}
	appendTestMsg(t, c, "Old", "keepme")

	if err := c.Delete("Gone").Wait(); err != nil {
		t.Fatalf("delete Gone: %v", err)
	}

	// Rename Old -> Gone: must succeed despite the "Gone" tombstone.
	if err := c.Rename("Old", "Gone", nil).Wait(); err != nil {
		t.Fatalf("rename onto a soft-deleted name must succeed: %v", err)
	}

	// "Gone" now resolves to the renamed live mailbox, with its message.
	selData, err := c.Select("Gone", nil).Wait()
	if err != nil {
		t.Fatalf("select renamed Gone: %v", err)
	}
	if selData.NumMessages != 1 {
		t.Fatalf("renamed mailbox should carry its 1 message, got %d", selData.NumMessages)
	}
	// "Old" no longer exists.
	if _, err := c.Select("Old", nil).Wait(); err == nil {
		t.Fatalf("source name 'Old' should no longer exist after rename")
	}
}

// TestDelete_TwoPhase_SharedMailboxHiddenFromGrantee verifies the shared-mailbox path:
// a soft-deleted shared mailbox disappears from a grantee's LIST, which is served by
// db.GetMailboxes (its inline CTE filters deleted_at).
func TestDelete_TwoPhase_SharedMailboxHiddenFromGrantee(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	// Second user in the same domain (required for shared-mailbox access).
	domain := strings.Split(owner.Email, "@")[1]
	granteeEmail := fmt.Sprintf("grantee-%d@%s", common.GetTimestamp(), domain)
	granteePass := "granteePass1"
	if _, err := server.ResilientDB.CreateAccountWithRetry(context.Background(), db.CreateAccountRequest{
		Email: granteeEmail, Password: granteePass, HashType: "bcrypt", IsPrimary: true,
	}); err != nil {
		t.Fatalf("create grantee: %v", err)
	}

	// Owner creates a shared mailbox and grants the grantee lookup+read.
	co, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("owner connect: %v", err)
	}
	defer co.Close()
	if err := co.Login(owner.Email, owner.Password).Wait(); err != nil {
		t.Fatalf("owner login: %v", err)
	}
	shared := "Shared/Team"
	if err := co.Create(shared, nil).Wait(); err != nil {
		t.Fatalf("create shared: %v", err)
	}
	if err := co.SetACL(shared, imap.RightsIdentifier(granteeEmail), imap.RightModificationReplace, imap.RightSet("lr")).Wait(); err != nil {
		t.Fatalf("setacl: %v", err)
	}

	// Grantee sees it before deletion.
	cg, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("grantee connect: %v", err)
	}
	defer cg.Close()
	if err := cg.Login(granteeEmail, granteePass).Wait(); err != nil {
		t.Fatalf("grantee login: %v", err)
	}
	before, err := cg.List("", shared, nil).Collect()
	if err != nil {
		t.Fatalf("grantee list (before): %v", err)
	}
	if len(before) == 0 {
		t.Fatalf("grantee should see the shared mailbox before deletion")
	}

	// Owner deletes the shared mailbox.
	if err := co.Delete(shared).Wait(); err != nil {
		t.Fatalf("owner delete shared: %v", err)
	}

	// Grantee must no longer see it (db.GetMailboxes CTE filters deleted_at).
	after, err := cg.List("", shared, nil).Collect()
	if err != nil {
		t.Fatalf("grantee list (after): %v", err)
	}
	if len(after) != 0 {
		t.Fatalf("grantee must not see a soft-deleted shared mailbox, saw %d", len(after))
	}
	// And cannot SELECT it.
	if _, err := cg.Select(shared, &imap.SelectOptions{ReadOnly: true}).Wait(); err == nil {
		t.Fatalf("grantee SELECT of a deleted shared mailbox must fail")
	}
}
