//go:build integration

package imap_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// appendStandalone appends n messages that thread on their own, each with its
// own subject, arriving one hour apart in UID order.
func appendStandalone(t *testing.T, c *imapclient.Client, n int) {
	t.Helper()
	base := time.Now().Add(-time.Duration(n) * time.Hour).Truncate(time.Second)
	for i := 0; i < n; i++ {
		date := base.Add(time.Duration(i) * time.Hour)
		body := fmt.Sprintf("Message-ID: <solo%d@example.com>\r\nSubject: Solo %d\r\nDate: %s\r\n\r\nbody\r\n", i, i, date.Format(time.RFC1123Z))
		appendCmd := c.Append("INBOX", int64(len(body)), &imap.AppendOptions{Time: date})
		if _, err := appendCmd.Write([]byte(body)); err != nil {
			t.Fatalf("Append write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("Append close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}
}

// roots returns the first message of each thread.
func roots(threads []imap.ThreadData) []uint32 {
	out := []uint32{}
	for _, td := range threads {
		out = append(out, td.Chain[0])
	}
	return out
}

func dialSelected(t *testing.T) (*imapclient.Client, func()) {
	t.Helper()
	server, account := common.SetupIMAPServer(t)
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		server.Close()
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	return c, func() { c.Logout(); server.Close() }
}

// TestIMAP_Thread_SequenceNumbers checks both numberings THREAD answers in and
// a sequence-set search key, after an expunge has made sequence numbers and
// UIDs differ: UIDs 2, 3 and 4 are sequence numbers 1, 2 and 3.
func TestIMAP_Thread_SequenceNumbers(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	c, done := dialSelected(t)
	defer done()

	appendStandalone(t, c, 4)
	if err := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagDeleted}, Silent: true}, nil).Close(); err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	if err := c.Expunge().Close(); err != nil {
		t.Fatalf("Expunge failed: %v", err)
	}

	thread := func(uid bool, criteria *imap.SearchCriteria) []uint32 {
		t.Helper()
		opts := &imapclient.ThreadOptions{Algorithm: imap.ThreadRefs, SearchCriteria: criteria}
		cmd := c.Thread(opts)
		if uid {
			cmd = c.UIDThread(opts)
		}
		res, err := cmd.Wait()
		if err != nil {
			t.Fatalf("THREAD (uid=%v, %+v) failed: %v", uid, criteria, err)
		}
		return roots(res)
	}

	seq23 := &imap.SearchCriteria{SeqNum: []imap.SeqSet{imap.SeqSet{imap.SeqRange{Start: 2, Stop: 3}}}}
	cases := []struct {
		name     string
		uid      bool
		criteria *imap.SearchCriteria
		want     []uint32
	}{
		{"THREAD ALL", false, &imap.SearchCriteria{}, []uint32{1, 2, 3}},
		{"UID THREAD ALL", true, &imap.SearchCriteria{}, []uint32{2, 3, 4}},
		{"THREAD 2:3", false, seq23, []uint32{2, 3}},
		{"UID THREAD 2:3", true, seq23, []uint32{3, 4}},
	}
	for _, tc := range cases {
		if got := thread(tc.uid, tc.criteria); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestIMAP_Thread_TooManyMessages checks that a THREAD matching more messages
// than db.ThreadMaxMessages is refused with NO [LIMIT] (RFC 5530 section 3)
// instead of threading only some of them: a client showing the result as its
// message list would otherwise present the rest as gone.
func TestIMAP_Thread_TooManyMessages(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	saved := db.ThreadMaxMessages
	db.ThreadMaxMessages = 3
	t.Cleanup(func() { db.ThreadMaxMessages = saved })

	c, done := dialSelected(t)
	defer done()

	appendStandalone(t, c, 4)

	_, err := c.UIDThread(&imapclient.ThreadOptions{Algorithm: imap.ThreadRefs, SearchCriteria: &imap.SearchCriteria{}}).Wait()
	var imapErr *imap.Error
	if !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeNo || imapErr.Code != imap.ResponseCodeLimit {
		t.Fatalf("UID THREAD over the limit = %v, want NO [LIMIT]", err)
	}

	// A search narrowed to the limit is threaded in full.
	res, err := c.UIDThread(&imapclient.ThreadOptions{
		Algorithm:      imap.ThreadRefs,
		SearchCriteria: &imap.SearchCriteria{UID: []imap.UIDSet{{imap.UIDRange{Start: 2, Stop: 4}}}},
	}).Wait()
	if err != nil {
		t.Fatalf("UID THREAD at the limit failed: %v", err)
	}
	if got, want := roots(res), []uint32{2, 3, 4}; !reflect.DeepEqual(got, want) {
		t.Errorf("UID THREAD UID 2:4 = %v, want %v", got, want)
	}
}
