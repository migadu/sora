//go:build integration

package imap_test

import (
	"reflect"
	"slices"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_CopyMoveKeepReferences checks that a copied or moved message keeps its
// References header for SEARCH HEADER References and THREAD in the destination mailbox.
func TestIMAP_CopyMoveKeepReferences(t *testing.T) {
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
	if err := c.Create("Replies", nil).Wait(); err != nil {
		t.Fatalf("CREATE Replies failed: %v", err)
	}

	// The replies name the question in References only and their subjects all differ,
	// so References is the only thing that can join them to it.
	start := time.Now().Add(-3 * time.Hour)
	for i, m := range []struct{ mailbox, body string }{
		{"Replies", "Message-ID: <q@example.com>\r\nSubject: Question\r\n\r\nAsking"},
		{"INBOX", "Message-ID: <a1@example.com>\r\nReferences: <q@example.com>\r\nSubject: Answer\r\n\r\nCopied"},
		{"INBOX", "Message-ID: <a2@example.com>\r\nReferences: <q@example.com>\r\nSubject: Second answer\r\n\r\nMoved"},
	} {
		appendCmd := c.Append(m.mailbox, int64(len(m.body)), &imap.AppendOptions{Time: start.Add(time.Duration(i) * time.Hour)})
		if _, err := appendCmd.Write([]byte(m.body)); err != nil {
			t.Fatalf("Append write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("Append close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("Append %d failed: %v", i+1, err)
		}
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	if _, err := c.Copy(imap.UIDSetNum(1), "Replies").Wait(); err != nil {
		t.Fatalf("UID COPY failed: %v", err)
	}
	if _, err := c.Move(imap.UIDSetNum(2), "Replies").Wait(); err != nil {
		t.Fatalf("UID MOVE failed: %v", err)
	}
	// Replies: UID 1 the question, UID 2 the copy, UID 3 the moved message.
	if _, err := c.Select("Replies", nil).Wait(); err != nil {
		t.Fatalf("Select Replies failed: %v", err)
	}

	search, err := c.UIDSearch(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "References", Value: "<q@example.com>"}},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("UID SEARCH HEADER References failed: %v", err)
	}
	if got, want := search.AllUIDs(), []imap.UID{2, 3}; !slices.Equal(got, want) {
		t.Errorf("UID SEARCH HEADER References <q@example.com>: got %v, want %v", got, want)
	}

	threads, err := c.UIDThread(&imapclient.ThreadOptions{
		Algorithm:      imap.ThreadReferences,
		SearchCriteria: &imap.SearchCriteria{},
	}).Wait()
	if err != nil {
		t.Fatalf("UID THREAD REFERENCES failed: %v", err)
	}
	// (1 (2)(3)): both answers are children of the question.
	want := []imap.ThreadData{{Chain: []uint32{1}, SubThreads: []imap.ThreadData{{Chain: []uint32{2}}, {Chain: []uint32{3}}}}}
	if !reflect.DeepEqual(threads, want) {
		t.Errorf("UID THREAD REFERENCES: got %+v, want %+v", threads, want)
	}
}
