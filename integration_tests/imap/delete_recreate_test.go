//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestDeleteRecreateDelete tests the sequence:
// 1. Create "TestFolder", add message, DELETE it
// 2. Create "TestFolder" again, add message, DELETE it again
// This should work cleanly since DELETE hard-removes the mailbox.
func TestDeleteRecreateDelete(t *testing.T) {
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

	// Round 1: Create, append, delete
	if err := c.Create("TestFolder", nil).Wait(); err != nil {
		t.Fatalf("Round 1: Failed to create TestFolder: %v", err)
	}
	t.Log("Round 1: Created TestFolder")

	appendTestMsg(t, c, "TestFolder", "Round 1 Message")
	t.Log("Round 1: Appended message")

	if err := c.Delete("TestFolder").Wait(); err != nil {
		t.Fatalf("Round 1: Failed to delete TestFolder: %v", err)
	}
	t.Log("Round 1: Deleted TestFolder")

	// Round 2: Recreate same name, append, delete again
	if err := c.Create("TestFolder", nil).Wait(); err != nil {
		t.Fatalf("Round 2: Failed to recreate TestFolder: %v", err)
	}
	t.Log("Round 2: Recreated TestFolder")

	appendTestMsg(t, c, "TestFolder", "Round 2 Message")
	t.Log("Round 2: Appended message")

	if err := c.Delete("TestFolder").Wait(); err != nil {
		t.Fatalf("Round 2: Failed to delete TestFolder again: %v", err)
	}
	t.Log("Round 2: Deleted TestFolder again")

	t.Log("✓ Delete-recreate-delete cycle works correctly")
}

// TestRenameToTrash_Twice tests the client pattern where:
// 1. Mailbox "Foo" is renamed to "Trash/Foo" (simulating "move to trash")
// 2. User creates "Foo" again
// 3. "Foo" is renamed to "Trash/Foo" again — should this fail?
func TestRenameToTrash_Twice(t *testing.T) {
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

	// Round 1: Create Foo, rename to Trash/Foo
	if err := c.Create("Foo", nil).Wait(); err != nil {
		t.Fatalf("Round 1: Failed to create Foo: %v", err)
	}
	appendTestMsg(t, c, "Foo", "Round 1")

	if err := c.Rename("Foo", "Trash/Foo", nil).Wait(); err != nil {
		t.Fatalf("Round 1: Failed to rename Foo to Trash/Foo: %v", err)
	}
	t.Log("Round 1: Renamed Foo → Trash/Foo")

	// Round 2: Create Foo again, try to rename to Trash/Foo
	if err := c.Create("Foo", nil).Wait(); err != nil {
		t.Fatalf("Round 2: Failed to recreate Foo: %v", err)
	}
	appendTestMsg(t, c, "Foo", "Round 2")

	err = c.Rename("Foo", "Trash/Foo", nil).Wait()
	if err != nil {
		// This is expected to fail — Trash/Foo already exists
		t.Logf("Round 2: Rename Foo → Trash/Foo failed (expected): %v", err)

		// Verify Foo still exists with its message
		selData, selErr := c.Select("Foo", nil).Wait()
		if selErr != nil {
			t.Errorf("Foo should still exist after failed rename: %v", selErr)
		} else {
			t.Logf("Foo still has %d messages (preserved after failed rename)", selData.NumMessages)
			if selData.NumMessages != 1 {
				t.Errorf("Expected 1 message in Foo, got %d", selData.NumMessages)
			}
		}
		t.Log("✓ Second rename correctly fails — Trash/Foo already exists, Foo preserved")
	} else {
		t.Log("⚠ Round 2: Rename succeeded — server allows overwriting Trash/Foo")
	}
}

// TestMoveToTrash_Twice tests the pattern where messages are moved to Trash:
// 1. Move messages from "Foo" to "Trash", then delete "Foo"
// 2. Recreate "Foo", add messages, move to Trash again, delete "Foo"
func TestMoveToTrash_Twice(t *testing.T) {
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

	// Round 1
	if err := c.Create("Foo", nil).Wait(); err != nil {
		t.Fatalf("Failed to create Foo: %v", err)
	}

	if _, err := c.Select("Foo", nil).Wait(); err != nil {
		t.Fatalf("Failed to select Foo: %v", err)
	}
	appendTestMsg(t, c, "Foo", "Round 1 msg")

	selData, _ := c.Select("Foo", nil).Wait()
	if selData.NumMessages > 0 {
		// Move all to Trash
		moveCmd := c.Move(imap.SeqSet{{Start: 1, Stop: 0}}, "Trash")
		_, err := moveCmd.Wait()
		if err != nil {
			t.Fatalf("Round 1: MOVE to Trash failed: %v", err)
		}
	}

	// Delete the now-empty Foo
	if err := c.Delete("Foo").Wait(); err != nil {
		t.Fatalf("Round 1: DELETE Foo failed: %v", err)
	}
	t.Log("Round 1: Moved msgs to Trash, deleted Foo ✓")

	// Round 2: Same flow
	if err := c.Create("Foo", nil).Wait(); err != nil {
		t.Fatalf("Round 2: Failed to recreate Foo: %v", err)
	}

	if _, err := c.Select("Foo", nil).Wait(); err != nil {
		t.Fatalf("Round 2: Failed to select Foo: %v", err)
	}
	appendTestMsg(t, c, "Foo", "Round 2 msg")

	selData, _ = c.Select("Foo", nil).Wait()
	if selData.NumMessages > 0 {
		moveCmd := c.Move(imap.SeqSet{{Start: 1, Stop: 0}}, "Trash")
		_, err := moveCmd.Wait()
		if err != nil {
			t.Fatalf("Round 2: MOVE to Trash failed: %v", err)
		}
	}

	if err := c.Delete("Foo").Wait(); err != nil {
		t.Fatalf("Round 2: DELETE Foo failed: %v", err)
	}
	t.Log("Round 2: Moved msgs to Trash, deleted Foo ✓")

	// Verify Trash has messages from both rounds
	selData, err = c.Select("Trash", nil).Wait()
	if err != nil {
		t.Fatalf("Failed to select Trash: %v", err)
	}
	t.Logf("Trash has %d messages (should have messages from both rounds)", selData.NumMessages)
	if selData.NumMessages < 2 {
		t.Errorf("Expected at least 2 messages in Trash, got %d", selData.NumMessages)
	}

	t.Log("✓ Move-to-Trash + delete + recreate cycle works correctly")
}
