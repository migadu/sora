//go:build integration

package imap_test

import (
	"slices"
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_QuotedAtLocalPart_EnvelopeAndSort(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	appendRaw := func(headers string) imap.UID {
		t.Helper()
		msg := headers +
			"Subject: Quoted At Local-Part Test\r\n" +
			"Date: Wed, 01 Jan 2020 00:00:00 +0000\r\n\r\n" +
			"body\r\n"
		ac := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		data, err := ac.Wait()
		if err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
		return data.UID
	}

	// Message 1: addr-mailbox "a@z" / "t@z" / "c@z" (no Sender -> Sender defaults to From).
	uid1 := appendRaw(
		"From: Alice <\"a@z\"@example.com>\r\n" +
			"To: Target Z <\"t@z\"@example.com>\r\n" +
			"Cc: Copy Z <\"c@z\"@example.com>\r\n" +
			"Reply-To: <\"r@z\"@example.com>\r\n",
	)
	// Message 2: addr-mailbox "a@a" / "t@a" / "c@a" on zzz.example, plus explicit Sender.
	uid2 := appendRaw(
		"From: Bob <\"a@a\"@zzz.example>\r\n" +
			"Sender: Delegate <\"s@a\"@zzz.example>\r\n" +
			"To: Target A <\"t@a\"@zzz.example>\r\n" +
			"Cc: Copy A <\"c@a\"@zzz.example>\r\n",
	)
	// Message 3: same addr-mailbox "a@a" / "t@a" / "c@a" as Message 2 on earlier domain aaa.example.
	// RFC 5256 §3 compares addr-mailbox only, so Message 2 and Message 3 tie and stay in UID order.
	uid3 := appendRaw(
		"From: Carol <\"a@a\"@aaa.example>\r\n" +
			"To: Target A2 <\"t@a\"@aaa.example>\r\n" +
			"Cc: Copy A2 <\"c@a\"@aaa.example>\r\n",
	)

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	var fetchSet imap.UIDSet
	fetchSet.AddNum(uid1, uid2)
	msgs, err := c.Fetch(fetchSet, &imap.FetchOptions{
		UID:      true,
		Envelope: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH ENVELOPE failed: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 fetched messages, got %d", len(msgs))
	}

	byUID := make(map[imap.UID]*imap.Envelope, len(msgs))
	for _, m := range msgs {
		byUID[m.UID] = m.Envelope
	}

	if env := byUID[uid1]; env == nil {
		t.Errorf("UID %d: nil ENVELOPE", uid1)
	} else {
		wantFrom := []imap.Address{{Name: "Alice", Mailbox: "a@z", Host: "example.com"}}
		if !slices.Equal(env.From, wantFrom) {
			t.Errorf("UID %d ENVELOPE From = %+v, want %+v", uid1, env.From, wantFrom)
		}
		if !slices.Equal(env.Sender, wantFrom) {
			t.Errorf("UID %d ENVELOPE Sender = %+v, want %+v", uid1, env.Sender, wantFrom)
		}
		wantTo := []imap.Address{{Name: "Target Z", Mailbox: "t@z", Host: "example.com"}}
		if !slices.Equal(env.To, wantTo) {
			t.Errorf("UID %d ENVELOPE To = %+v, want %+v", uid1, env.To, wantTo)
		}
		wantCc := []imap.Address{{Name: "Copy Z", Mailbox: "c@z", Host: "example.com"}}
		if !slices.Equal(env.Cc, wantCc) {
			t.Errorf("UID %d ENVELOPE Cc = %+v, want %+v", uid1, env.Cc, wantCc)
		}
		wantReplyTo := []imap.Address{{Mailbox: "r@z", Host: "example.com"}}
		if !slices.Equal(env.ReplyTo, wantReplyTo) {
			t.Errorf("UID %d ENVELOPE ReplyTo = %+v, want %+v", uid1, env.ReplyTo, wantReplyTo)
		}
	}

	if env := byUID[uid2]; env == nil {
		t.Errorf("UID %d: nil ENVELOPE", uid2)
	} else {
		wantFrom := []imap.Address{{Name: "Bob", Mailbox: "a@a", Host: "zzz.example"}}
		if !slices.Equal(env.From, wantFrom) {
			t.Errorf("UID %d ENVELOPE From = %+v, want %+v", uid2, env.From, wantFrom)
		}
		wantSender := []imap.Address{{Name: "Delegate", Mailbox: "s@a", Host: "zzz.example"}}
		if !slices.Equal(env.Sender, wantSender) {
			t.Errorf("UID %d ENVELOPE Sender = %+v, want %+v", uid2, env.Sender, wantSender)
		}
	}

	wantOrder := []imap.UID{uid2, uid3, uid1}
	for _, key := range []imap.SortKey{imap.SortKeyFrom, imap.SortKeyTo, imap.SortKeyCc} {
		// Exercise both the simple query path (ALL) and the TEXT UNION CTE rewrite path.
		for _, tc := range []struct {
			label    string
			criteria *imap.SearchCriteria
		}{
			{"ALL", &imap.SearchCriteria{}},
			{"TEXT example", &imap.SearchCriteria{Text: []string{"example"}}},
		} {
			res, err := c.UIDSort(&imapclient.SortOptions{
				SearchCriteria: tc.criteria,
				SortCriteria:   []imap.SortCriterion{{Key: key}},
			}).Wait()
			if err != nil {
				t.Fatalf("UID SORT (%s) UTF-8 %s failed: %v", key, tc.label, err)
			}
			if !slices.Equal(res.UIDs, wantOrder) {
				t.Errorf("UID SORT (%s) UTF-8 %s = %v, want %v", key, tc.label, res.UIDs, wantOrder)
			}
		}
	}
}
