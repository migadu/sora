//go:build integration

package imap_test

import (
	"slices"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// A message id whose obsolete quoted local part holds white space or angle brackets
// (RFC 5322 §3.6.4 obs-id-left) is one id in ENVELOPE, THREAD and SEARCH (#1875).
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

	start := time.Now().Add(-4 * time.Hour)
	for i, msg := range []string{
		"From: a@example.com\r\nSubject: Question\r\nMessage-ID: <\"foo bar\"@example.com>\r\n\r\nAsking\r\n",
		"From: b@example.com\r\nSubject: Answer\r\nMessage-ID: <\"<inner>\"@example.com>\r\n" +
			"In-Reply-To: <\"foo bar\"@example.com>\r\nReferences: <\"foo bar\"@example.com>\r\n\r\nAnswering\r\n",
		"From: c@example.com\r\nSubject: Something else\r\nMessage-ID: <r3@example.com>\r\n" +
			"In-Reply-To: <\"<inner>\"@example.com>\r\nReferences: <\"foo bar\"@example.com> <\"<inner>\"@example.com>\r\n\r\nFollowing up\r\n",
	} {
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
		msgs, err := c.Fetch(imap.SeqSetNum(2, 3), &imap.FetchOptions{Envelope: true}).Collect()
		if err != nil {
			t.Fatalf("FETCH: %v", err)
		}
		want := map[uint32][]string{2: {`"foo bar"@example.com`}, 3: {`"<inner>"@example.com`}}
		for _, m := range msgs {
			if m.Envelope == nil || !slices.Equal(m.Envelope.InReplyTo, want[m.SeqNum]) {
				t.Errorf("message %d ENVELOPE In-Reply-To = %q, want %q", m.SeqNum, m.Envelope.InReplyTo, want[m.SeqNum])
			}
		}
	})

	for _, alg := range []imap.ThreadAlgorithm{imap.ThreadReferences, imap.ThreadRefs} {
		t.Run("THREAD "+string(alg), func(t *testing.T) {
			res, err := c.UIDThread(&imapclient.ThreadOptions{Algorithm: alg, SearchCriteria: &imap.SearchCriteria{}}).Wait()
			if err != nil {
				t.Fatalf("UID THREAD: %v", err)
			}
			if len(res) != 1 || !slices.Equal(res[0].Chain, []uint32{1, 2, 3}) {
				t.Fatalf("UID THREAD %s = %+v, want one thread [1 2 3]", alg, res)
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
		{"References two quoted ids", header("References", `<"foo bar"@example.com> <"<inner>"@example.com>`), []imap.UID{3}},
		{"References substring inside quotes", header("References", `"foo bar"@`), []imap.UID{2, 3}},
		{"Message-ID whole quoted id", header("Message-ID", `<"foo bar"@example.com>`), []imap.UID{1}},
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
