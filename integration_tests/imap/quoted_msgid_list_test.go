//go:build integration

package imap_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// Quoted local parts, UTF-8 atom text and no-fold domain literals remain one id in
// ENVELOPE, THREAD and SEARCH (#1875).
func TestIMAP_QuotedLocalPartMessageIDLists(t *testing.T) {
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

	ids := []string{
		`"foo bar"@example.com`,
		`"<inner>"@example.com`,
		"r3@example.com",
		"non\u00a0breaking@example.com",
		"em\u2003part@dom\u00a0ain.example",
		`literal@[<inner>]`,
		`"quoted local"@[<inner>]`,
		"r8@example.com",
	}
	start := time.Now().Add(-time.Duration(len(ids)) * time.Hour)
	var references []string
	for i, id := range ids {
		msg := fmt.Sprintf("From: a@example.com\r\nSubject: Chain message %d\r\nMessage-ID: <%s>\r\n", i+1, id)
		if i > 0 {
			msg += "In-Reply-To: <" + ids[i-1] + ">\r\nReferences: " + strings.Join(references, " ") + "\r\n"
		}
		msg += "\r\nBody\r\n"
		references = append(references, "<"+id+">")
		ac := c.Append("INBOX", int64(len(msg)), &imap.AppendOptions{Time: start.Add(time.Duration(i) * time.Hour)})
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND close: %v", err)
		}
		if _, err := ac.Wait(); err != nil {
			t.Fatalf("APPEND %d: %v", i+1, err)
		}
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT: %v", err)
	}

	t.Run("ENVELOPE", func(t *testing.T) {
		var seqs []uint32
		for i := 2; i <= len(ids); i++ {
			seqs = append(seqs, uint32(i))
		}
		msgs, err := c.Fetch(imap.SeqSetNum(seqs...), &imap.FetchOptions{Envelope: true}).Collect()
		if err != nil {
			t.Fatalf("FETCH: %v", err)
		}
		if len(msgs) != len(seqs) {
			t.Fatalf("FETCH returned %d messages, want %d", len(msgs), len(seqs))
		}
		seen := make(map[uint32]bool)
		for _, m := range msgs {
			if m.SeqNum < 2 || m.SeqNum > uint32(len(ids)) || seen[m.SeqNum] {
				t.Fatalf("unexpected or duplicate FETCH sequence number %d", m.SeqNum)
			}
			seen[m.SeqNum] = true
			if m.Envelope == nil {
				t.Fatalf("message %d has no ENVELOPE", m.SeqNum)
			}
			want := []string{ids[m.SeqNum-2]}
			if !slices.Equal(m.Envelope.InReplyTo, want) {
				t.Errorf("message %d ENVELOPE In-Reply-To = %q, want %q", m.SeqNum, m.Envelope.InReplyTo, want)
			}
			if m.Envelope.MessageID != ids[m.SeqNum-1] {
				t.Errorf("message %d ENVELOPE Message-ID = %q, want %q", m.SeqNum, m.Envelope.MessageID, ids[m.SeqNum-1])
			}
		}
	})

	for _, alg := range []imap.ThreadAlgorithm{imap.ThreadReferences, imap.ThreadRefs} {
		t.Run("THREAD "+string(alg), func(t *testing.T) {
			res, err := c.UIDThread(&imapclient.ThreadOptions{Algorithm: alg, SearchCriteria: &imap.SearchCriteria{}}).Wait()
			if err != nil {
				t.Fatalf("UID THREAD: %v", err)
			}
			if len(res) != 1 || !slices.Equal(res[0].Chain, []uint32{1, 2, 3, 4, 5, 6, 7, 8}) {
				t.Fatalf("UID THREAD %s = %+v, want one thread [1 2 3 4 5 6 7 8]", alg, res)
			}
		})
	}

	header := func(key, value string) *imap.SearchCriteria {
		return &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: key, Value: value}}}
	}
	for _, tc := range []struct {
		name     string
		criteria *imap.SearchCriteria
		want     []imap.UID
	}{
		{"In-Reply-To whole quoted id", header("In-Reply-To", `<"foo bar"@example.com>`), []imap.UID{2}},
		{"In-Reply-To quoted id with brackets", header("In-Reply-To", `<"<inner>"@example.com>`), []imap.UID{3}},
		{"References two quoted ids", header("References", `<"foo bar"@example.com> <"<inner>"@example.com>`), []imap.UID{3, 4, 5, 6, 7, 8}},
		{"References substring inside quotes", header("References", `"foo bar"@`), []imap.UID{2, 3, 4, 5, 6, 7, 8}},
		{"Message-ID whole quoted id", header("Message-ID", `<"foo bar"@example.com>`), []imap.UID{1}},
		{"In-Reply-To nonbreaking space atom", header("In-Reply-To", "<"+ids[3]+">"), []imap.UID{5}},
		{"In-Reply-To Unicode atom and domain", header("In-Reply-To", "<"+ids[4]+">"), []imap.UID{6}},
		{"In-Reply-To literal angles", header("In-Reply-To", "<"+ids[5]+">"), []imap.UID{7}},
		{"In-Reply-To quoted local and literal angles", header("In-Reply-To", "<"+ids[6]+">"), []imap.UID{8}},
		{"References Unicode atom and domain", header("References", "<"+ids[4]+">"), []imap.UID{6, 7, 8}},
		{"References literal angles", header("References", "<"+ids[5]+">"), []imap.UID{7, 8}},
		{"Message-ID literal angles", header("Message-ID", "<"+ids[5]+">"), []imap.UID{6}},
		{"Message-ID quoted local and literal angles", header("Message-ID", "<"+ids[6]+">"), []imap.UID{7}},
	} {
		data, err := c.UIDSearch(tc.criteria, nil).Wait()
		if err != nil {
			t.Errorf("%s: UID SEARCH: %v", tc.name, err)
			continue
		}
		got := data.AllUIDs()
		slices.Sort(got)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: UID SEARCH = %v, want %v", tc.name, got, tc.want)
		}
	}
}
