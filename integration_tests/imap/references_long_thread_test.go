//go:build integration

package imap_test

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_LongReferencesKeepParent: a References field grows by one message ID per
// reply (RFC 5322 §3.6.4), and RFC 5256 §2.2 links a message to "the last reference".
// The stored list was cut to its first 2000 bytes, so in a 40-message thread the last
// IDs, the parent's among them, were lost: SEARCH HEADER References on them found
// nothing and THREAD put the reply beside its parent instead of under it (#610).
func TestIMAP_LongReferencesKeepParent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}

	// 64-byte message IDs, angle brackets included.
	id := func(n int) string {
		return fmt.Sprintf("<CAB%02d%s@mail.example.com>", n, strings.Repeat("x", 40))
	}
	// The References field of the reply to message n: IDs 1 to n, one per folded line.
	refs := func(n int) string {
		var ids []string
		for i := 1; i <= n; i++ {
			ids = append(ids, id(i))
		}
		return strings.Join(ids, "\r\n ")
	}
	appendMsg := func(msg string) imap.UID {
		t.Helper()
		ac := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND close: %v", err)
		}
		data, err := ac.Wait()
		if err != nil {
			t.Fatalf("APPEND: %v", err)
		}
		return data.UID
	}
	parent := appendMsg("From: a@example.com\r\nSubject: Re: long thread\r\n" +
		"Message-ID: " + id(40) + "\r\nIn-Reply-To: " + id(39) + "\r\n" +
		"References: " + refs(39) + "\r\n\r\nparent\r\n")
	reply := appendMsg("From: b@example.com\r\nSubject: Re: long thread\r\n" +
		"Message-ID: <reply@example.com>\r\nIn-Reply-To: " + id(40) + "\r\n" +
		"References: " + refs(40) + "\r\n\r\nreply\r\n")

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT: %v", err)
	}

	for _, tc := range []struct {
		name string
		ref  string
		want []imap.UID
	}{
		{"first ID", id(1), []imap.UID{parent, reply}},
		{"grandparent", id(39), []imap.UID{parent, reply}},
		{"parent", id(40), []imap.UID{reply}},
	} {
		criteria := &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "References", Value: tc.ref}}}
		data, err := c.UIDSearch(criteria, nil).Wait()
		if err != nil {
			t.Errorf("%s: UID SEARCH HEADER References failed: %v", tc.name, err)
			continue
		}
		got := data.AllUIDs()
		slices.Sort(got)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: UID SEARCH HEADER References = %v, want %v", tc.name, got, tc.want)
		}
	}

	want := []imap.ThreadData{{Chain: []uint32{uint32(parent), uint32(reply)}}}
	for _, alg := range []imap.ThreadAlgorithm{imap.ThreadReferences, imap.ThreadRefs} {
		res, err := c.UIDThread(&imapclient.ThreadOptions{Algorithm: alg, SearchCriteria: &imap.SearchCriteria{}}).Wait()
		if err != nil {
			t.Errorf("UID THREAD %s failed: %v", alg, err)
			continue
		}
		if !reflect.DeepEqual(res, want) {
			t.Errorf("UID THREAD %s = %+v, want the reply under its parent: %+v", alg, res, want)
		}
	}
}
