//go:build integration

package imap_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SearchDateKeysDayBoundaries is the regression test for #593.
//
// RFC 9051 §6.4.4 (same text in RFC 3501):
//
//	BEFORE <date>  Messages whose internal date (disregarding time and timezone)
//	               is earlier than the specified date.
//	ON <date>      Messages whose internal date (disregarding time and timezone)
//	               is within the specified date.
//	SINCE <date>   Messages whose internal date (disregarding time and timezone)
//	               is within or later than the specified date.
//
// and SENTBEFORE / SENTON / SENTSINCE likewise for the Date: header field.
//
// A message dated exactly midnight of a day is within that day: not earlier than it,
// and not within the day before. The internal dates are APPENDed in several zones;
// sora reports INTERNALDATE in +0000, so its date part is the UTC day, and that is the
// day ON must find it under (checked against FETCH INTERNALDATE at the end). The
// Date: header cases use zones whose own calendar day is also the UTC day, so they
// test the day boundary alone.
func TestIMAP_SearchDateKeysDayBoundaries(t *testing.T) {
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

	zone := func(name string, hours int) *time.Location { return time.FixedZone(name, hours*3600) }
	// The other date of each message is far from the dates searched, and each search
	// is confined to its group's UIDs, so a key reading the wrong column finds nothing.
	farInternal := time.Date(2030, 6, 15, 12, 0, 0, 0, time.UTC)
	farSent := time.Date(2020, 6, 15, 12, 0, 0, 0, time.UTC)

	const (
		internalGroup = iota
		sentGroup
	)
	msgs := []struct {
		name     string
		group    int
		internal time.Time // APPEND date-time -> INTERNALDATE
		sent     time.Time // Date: header
	}{
		{"internal 31-Dec 12:00 UTC", internalGroup, time.Date(2024, 12, 31, 12, 0, 0, 0, time.UTC), farSent},
		{"internal 31-Dec 23:59:59 UTC", internalGroup, time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC), farSent},
		{"internal 1-Jan 00:00 UTC", internalGroup, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), farSent},
		{"internal 1-Jan 01:00 +0200 (31-Dec 23:00 UTC)", internalGroup, time.Date(2025, 1, 1, 1, 0, 0, 0, zone("EET", 2)), farSent},
		{"internal 31-Dec 16:00 -0800 (1-Jan 00:00 UTC)", internalGroup, time.Date(2024, 12, 31, 16, 0, 0, 0, zone("PST", -8)), farSent},
		{"internal 2-Jan 00:00 UTC", internalGroup, time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC), farSent},
		{"sent 31-Dec 12:00 UTC", sentGroup, farInternal, time.Date(2024, 12, 31, 12, 0, 0, 0, time.UTC)},
		{"sent 31-Dec 18:59:59 -0500 (23:59:59 UTC)", sentGroup, farInternal, time.Date(2024, 12, 31, 18, 59, 59, 0, zone("EST", -5))},
		{"sent 1-Jan 00:00 UTC", sentGroup, farInternal, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"sent 1-Jan 09:00 +0900 (00:00 UTC)", sentGroup, farInternal, time.Date(2025, 1, 1, 9, 0, 0, 0, zone("JST", 9))},
		{"sent 2-Jan 00:00 UTC", sentGroup, farInternal, time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)},
	}

	uidOf := make(map[string]imap.UID, len(msgs))
	groupUIDs := make(map[int][]imap.UID)
	var allUIDs []imap.UID
	for i, m := range msgs {
		body := fmt.Sprintf("From: sender@example.com\r\n"+
			"To: %s\r\n"+
			"Subject: date boundary %d\r\n"+
			"Date: %s\r\n"+
			"Message-ID: <date-boundary-%d@example.com>\r\n"+
			"\r\n"+
			"%s\r\n", account.Email, i, m.sent.Format(time.RFC1123Z), i, m.name)
		appendCmd := c.Append("INBOX", int64(len(body)), &imap.AppendOptions{Time: m.internal})
		if _, err := appendCmd.Write([]byte(body)); err != nil {
			t.Fatalf("APPEND %q write failed: %v", m.name, err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND %q close failed: %v", m.name, err)
		}
		data, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND %q failed: %v", m.name, err)
		}
		uidOf[m.name] = data.UID
		groupUIDs[m.group] = append(groupUIDs[m.group], data.UID)
		allUIDs = append(allUIDs, data.UID)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	day := func(y int, mo time.Month, d int) time.Time { return time.Date(y, mo, d, 0, 0, 0, 0, time.UTC) }
	dec31, jan1, jan2 := day(2024, 12, 31), day(2025, 1, 1), day(2025, 1, 2)
	// imapclient sends Since = d, Before = d + 1 day as ON d (and SENTON likewise),
	// which go-imap's server decodes back into the same pair.
	on := func(d time.Time) imap.SearchCriteria {
		return imap.SearchCriteria{Since: d, Before: d.AddDate(0, 0, 1)}
	}
	senton := func(d time.Time) imap.SearchCriteria {
		return imap.SearchCriteria{SentSince: d, SentBefore: d.AddDate(0, 0, 1)}
	}

	internalDec31 := []string{
		"internal 31-Dec 12:00 UTC",
		"internal 31-Dec 23:59:59 UTC",
		"internal 1-Jan 01:00 +0200 (31-Dec 23:00 UTC)",
	}
	internalJan1 := []string{
		"internal 1-Jan 00:00 UTC",
		"internal 31-Dec 16:00 -0800 (1-Jan 00:00 UTC)",
	}
	sentDec31 := []string{
		"sent 31-Dec 12:00 UTC",
		"sent 31-Dec 18:59:59 -0500 (23:59:59 UTC)",
	}
	sentJan1 := []string{
		"sent 1-Jan 00:00 UTC",
		"sent 1-Jan 09:00 +0900 (00:00 UTC)",
	}

	tests := []struct {
		key      string // the search key the client sends
		group    int
		criteria imap.SearchCriteria
		want     []string
	}{
		{"BEFORE 1-Jan-2025", internalGroup, imap.SearchCriteria{Before: jan1}, internalDec31},
		{"BEFORE 31-Dec-2024", internalGroup, imap.SearchCriteria{Before: dec31}, nil},
		{"ON 31-Dec-2024", internalGroup, on(dec31), internalDec31},
		{"ON 1-Jan-2025", internalGroup, on(jan1), internalJan1},
		{"SINCE 1-Jan-2025", internalGroup, imap.SearchCriteria{Since: jan1}, append(slices.Clone(internalJan1), "internal 2-Jan 00:00 UTC")},
		{"SINCE 2-Jan-2025", internalGroup, imap.SearchCriteria{Since: jan2}, []string{"internal 2-Jan 00:00 UTC"}},
		{"SENTBEFORE 1-Jan-2025", sentGroup, imap.SearchCriteria{SentBefore: jan1}, sentDec31},
		{"SENTBEFORE 31-Dec-2024", sentGroup, imap.SearchCriteria{SentBefore: dec31}, nil},
		{"SENTON 31-Dec-2024", sentGroup, senton(dec31), sentDec31},
		{"SENTON 1-Jan-2025", sentGroup, senton(jan1), sentJan1},
		{"SENTSINCE 1-Jan-2025", sentGroup, imap.SearchCriteria{SentSince: jan1}, append(slices.Clone(sentJan1), "sent 2-Jan 00:00 UTC")},
		{"SENTSINCE 2-Jan-2025", sentGroup, imap.SearchCriteria{SentSince: jan2}, []string{"sent 2-Jan 00:00 UTC"}},
	}

	// SEARCH, SORT, THREAD and ESEARCH IN (MULTISEARCH) all take their criteria
	// through the same builder, so each must draw the day boundary alike.
	type command struct {
		name string
		run  func(criteria *imap.SearchCriteria) ([]imap.UID, error)
	}
	uidSearch := command{"UID SEARCH", func(criteria *imap.SearchCriteria) ([]imap.UID, error) {
		data, err := c.UIDSearch(criteria, nil).Wait()
		if err != nil {
			return nil, err
		}
		return data.AllUIDs(), nil
	}}
	commands := []command{
		uidSearch,
		{"UID SORT", func(criteria *imap.SearchCriteria) ([]imap.UID, error) {
			data, err := c.UIDSort(&imapclient.SortOptions{
				SearchCriteria: criteria,
				SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeyArrival}},
			}).Wait()
			if err != nil {
				return nil, err
			}
			return data.UIDs, nil
		}},
		{"UID THREAD", func(criteria *imap.SearchCriteria) ([]imap.UID, error) {
			threads, err := c.UIDThread(&imapclient.ThreadOptions{
				Algorithm:      imap.ThreadOrderedSubject,
				SearchCriteria: criteria,
			}).Wait()
			if err != nil {
				return nil, err
			}
			var uids []imap.UID
			var walk func([]imap.ThreadData)
			walk = func(threads []imap.ThreadData) {
				for _, thread := range threads {
					for _, uid := range thread.Chain {
						uids = append(uids, imap.UID(uid))
					}
					walk(thread.SubThreads)
				}
			}
			walk(threads)
			return uids, nil
		}},
		{"ESEARCH IN (MAILBOXES INBOX)", func(criteria *imap.SearchCriteria) ([]imap.UID, error) {
			results, err := c.MultiSearch(&imap.SearchSource{Mailboxes: []string{"INBOX"}}, criteria,
				&imap.SearchOptions{ReturnAll: true}).Wait()
			if err != nil {
				return nil, err
			}
			var uids []imap.UID
			for _, r := range results {
				uids = append(uids, r.AllUIDs()...)
			}
			return uids, nil
		}},
	}

	search := func(t *testing.T, cmd command, criteria imap.SearchCriteria, scope []imap.UID) []imap.UID {
		t.Helper()
		criteria.UID = []imap.UIDSet{imap.UIDSetNum(scope...)}
		got, err := cmd.run(&criteria)
		if err != nil {
			t.Fatalf("%s failed: %v", cmd.name, err)
		}
		slices.Sort(got)
		return got
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			var want []imap.UID
			for _, name := range tt.want {
				want = append(want, uidOf[name])
			}
			slices.Sort(want)
			for _, cmd := range commands {
				if got := search(t, cmd, tt.criteria, groupUIDs[tt.group]); !slices.Equal(got, want) {
					t.Errorf("%s %s = %v, want %v", cmd.name, tt.key, got, want)
				}
			}
		})
	}

	// ON <date part of the INTERNALDATE the server reports> must find each message,
	// and BEFORE that date must not: the date the client sees is the date searched.
	fetched, err := c.Fetch(imap.UIDSetNum(allUIDs...), &imap.FetchOptions{UID: true, InternalDate: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH INTERNALDATE failed: %v", err)
	}
	if len(fetched) != len(msgs) {
		t.Fatalf("FETCH returned %d messages, want %d", len(fetched), len(msgs))
	}
	for _, f := range fetched {
		y, mo, d := f.InternalDate.Date() // in the zone the server reported
		reported := day(y, mo, d)
		t.Run(fmt.Sprintf("UID %d INTERNALDATE %s", f.UID, f.InternalDate.Format("02-Jan-2006 15:04:05 -0700")), func(t *testing.T) {
			if got := search(t, uidSearch, on(reported), []imap.UID{f.UID}); !slices.Equal(got, []imap.UID{f.UID}) {
				t.Errorf("UID %d not found by ON %s", f.UID, reported.Format("2-Jan-2006"))
			}
			if got := search(t, uidSearch, imap.SearchCriteria{Before: reported}, []imap.UID{f.UID}); len(got) != 0 {
				t.Errorf("UID %d found by BEFORE %s", f.UID, reported.Format("2-Jan-2006"))
			}
		})
	}
}

// TestIMAP_SearchSentKeysUseHeaderDay is the regression test for #867, the steps from the
// issue. RFC 9051 §6.4.4 (same text in RFC 3501):
//
//	SENTON <date>  Messages whose [RFC5322] Date: header field (disregarding time and
//	               timezone) is within the specified date.
//
// Disregarding the time and timezone of "Tue, 31 Dec 2024 20:00:00 -0800" leaves
// 31 Dec 2024, although the instant is 1 Jan 2025 04:00 UTC. A COPY carries the zone with
// the message.
func TestIMAP_SearchSentKeysUseHeaderDay(t *testing.T) {
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

	body := "From: a@example.com\r\n" +
		"To: b@example.com\r\n" +
		"Subject: x\r\n" +
		"Date: Tue, 31 Dec 2024 20:00:00 -0800\r\n" +
		"\r\n" +
		"x\r\n"
	appendCmd := c.Append("INBOX", int64(len(body)), nil)
	if _, err := appendCmd.Write([]byte(body)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appended, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	const copyMailbox = "SentDayCopy"
	if err := c.Create(copyMailbox, nil).Wait(); err != nil {
		t.Fatalf("CREATE failed: %v", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}
	copied, err := c.Copy(imap.UIDSetNum(appended.UID), copyMailbox).Wait()
	if err != nil {
		t.Fatalf("COPY failed: %v", err)
	}
	if len(copied.UIDMapping) != 1 {
		t.Fatalf("COPY returned UID mapping %v, want one message", copied.UIDMapping)
	}

	day := func(y int, mo time.Month, d int) time.Time { return time.Date(y, mo, d, 0, 0, 0, 0, time.UTC) }
	dec31, jan1 := day(2024, 12, 31), day(2025, 1, 1)
	senton := func(d time.Time) imap.SearchCriteria {
		return imap.SearchCriteria{SentSince: d, SentBefore: d.AddDate(0, 0, 1)}
	}
	tests := []struct {
		key      string
		criteria imap.SearchCriteria
		found    bool
	}{
		{"SENTON 31-Dec-2024", senton(dec31), true},
		{"SENTON 1-Jan-2025", senton(jan1), false},
		{"SENTBEFORE 1-Jan-2025", imap.SearchCriteria{SentBefore: jan1}, true},
		{"SENTSINCE 1-Jan-2025", imap.SearchCriteria{SentSince: jan1}, false},
	}

	for _, mailbox := range []struct {
		name string
		uid  imap.UID
	}{{"INBOX", appended.UID}, {copyMailbox, copied.UIDMapping[0].Dest.Start}} {
		if _, err := c.Select(mailbox.name, nil).Wait(); err != nil {
			t.Fatalf("SELECT %s failed: %v", mailbox.name, err)
		}
		for _, tt := range tests {
			t.Run(mailbox.name+" "+tt.key, func(t *testing.T) {
				criteria := tt.criteria
				data, err := c.UIDSearch(&criteria, nil).Wait()
				if err != nil {
					t.Fatalf("UID SEARCH %s failed: %v", tt.key, err)
				}
				var want []imap.UID
				if tt.found {
					want = []imap.UID{mailbox.uid}
				}
				if got := data.AllUIDs(); !slices.Equal(got, want) {
					t.Errorf("UID SEARCH %s = %v, want %v", tt.key, got, want)
				}
			})
		}
	}
}
