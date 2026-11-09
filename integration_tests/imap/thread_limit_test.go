//go:build integration

package imap_test

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
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

func dialSelected(t *testing.T, opts *common.IMAPServerOpts) (*imapclient.Client, func()) {
	t.Helper()
	server, account := common.SetupIMAPServerWithOptions(t, opts)
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

	c, done := dialSelected(t, nil)
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
		var cmd *imapclient.ThreadCommand
		if uid {
			cmd = c.UIDThread(opts)
		} else {
			cmd = c.Thread(opts)
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
// than the configured cap is refused with NO [LIMIT] (RFC 5530 section 3)
// instead of threading only some of them: a client showing the result as its
// message list would otherwise present the rest as gone.
func TestIMAP_Thread_TooManyMessages(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	c, done := dialSelected(t, &common.IMAPServerOpts{ThreadMaxMessages: 3})
	defer done()

	appendStandalone(t, c, 4)

	check := func(t *testing.T, client *imapclient.Client, uid bool, algorithm imap.ThreadAlgorithm, criteria *imap.SearchCriteria, want []uint32) {
		t.Helper()
		opts := &imapclient.ThreadOptions{Algorithm: algorithm, SearchCriteria: criteria}
		var cmd *imapclient.ThreadCommand
		if uid {
			cmd = client.UIDThread(opts)
		} else {
			cmd = client.Thread(opts)
		}
		res, err := cmd.Wait()
		if want == nil {
			var imapErr *imap.Error
			if !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeNo || imapErr.Code != imap.ResponseCodeLimit {
				t.Fatalf("THREAD over the limit = %v, want NO [LIMIT]", err)
			}
			if !strings.Contains(imapErr.Text, "more than 3 messages") {
				t.Errorf("limit response = %q, want configured cap 3", imapErr.Text)
			}
			if len(res) != 0 {
				t.Errorf("refused THREAD returned partial results: %v", res)
			}
			return
		}
		if err != nil {
			t.Fatalf("THREAD within the limit failed: %v", err)
		}
		if got := roots(res); !reflect.DeepEqual(got, want) {
			t.Errorf("THREAD = %v, want %v", got, want)
		}
	}

	for _, uid := range []bool{false, true} {
		for _, algorithm := range []imap.ThreadAlgorithm{imap.ThreadReferences, imap.ThreadRefs, imap.ThreadOrderedSubject} {
			for _, tc := range []struct {
				name       string
				start, end imap.UID
				want       []uint32
			}{
				{name: "ALL over"},
				{name: "below", start: 2, end: 3, want: []uint32{2, 3}},
				{name: "at", start: 2, end: 4, want: []uint32{2, 3, 4}},
				{name: "over", start: 1, end: 4},
			} {
				t.Run(fmt.Sprintf("uid=%v/%s/%s", uid, algorithm, tc.name), func(t *testing.T) {
					criteria := &imap.SearchCriteria{}
					if tc.start != 0 {
						criteria.UID = []imap.UIDSet{{imap.UIDRange{Start: tc.start, Stop: tc.end}}}
					}
					check(t, c, uid, algorithm, criteria, tc.want)
				})
			}
		}
	}

	// Raising the cap on another listener admits its full mailbox without
	// changing the first listener's limit.
	higher, closeHigher := dialSelected(t, &common.IMAPServerOpts{ThreadMaxMessages: 4})
	defer closeHigher()
	appendStandalone(t, higher, 4)
	for _, uid := range []bool{false, true} {
		for _, algorithm := range []imap.ThreadAlgorithm{imap.ThreadReferences, imap.ThreadRefs, imap.ThreadOrderedSubject} {
			check(t, higher, uid, algorithm, &imap.SearchCriteria{}, []uint32{1, 2, 3, 4})
			check(t, c, uid, algorithm, &imap.SearchCriteria{}, nil)
		}
	}
}
