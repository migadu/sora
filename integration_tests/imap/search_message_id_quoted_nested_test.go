//go:build integration

package imap_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func deliverRawMessageViaLMTP(t *testing.T, lmtpAddr, from, to, rawMessage string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", lmtpAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial LMTP: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	reader := bufio.NewReader(conn)
	readLine := func(expectPrefix string) {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read LMTP (%s): %v", expectPrefix, err)
		}
		if !strings.HasPrefix(line, expectPrefix) {
			t.Fatalf("LMTP reply = %q, want prefix %q", line, expectPrefix)
		}
	}

	readLine("220")
	if _, err := conn.Write([]byte("LHLO test.example.com\r\n")); err != nil {
		t.Fatalf("write LHLO: %v", err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read LHLO: %v", err)
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	for _, step := range []struct {
		cmd    string
		expect string
	}{
		{fmt.Sprintf("MAIL FROM:<%s>\r\n", from), "250"},
		{fmt.Sprintf("RCPT TO:<%s>\r\n", to), "250"},
		{"DATA\r\n", "354"},
	} {
		if _, err := conn.Write([]byte(step.cmd)); err != nil {
			t.Fatalf("write %q: %v", step.cmd, err)
		}
		readLine(step.expect)
	}

	if !strings.HasSuffix(rawMessage, "\r\n") {
		rawMessage += "\r\n"
	}
	if _, err := conn.Write([]byte(rawMessage + ".\r\n")); err != nil {
		t.Fatalf("write DATA body: %v", err)
	}
	readLine("250")
	_, _ = conn.Write([]byte("QUIT\r\n"))
}

// TestIMAP_HeaderMessageIDQuotedAngleBrackets verifies RFC 9051 §6.4.4 substring
// search on Message-ID headers whose obsolete quoted local-part (RFC 5322 §4.5.4
// obs-id-left) contains '<' or '>', across IMAP APPEND, LMTP delivery, and UID COPY.
func TestIMAP_HeaderMessageIDQuotedAngleBrackets(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapSrv, account := common.SetupIMAPServer(t)
	defer imapSrv.Close()

	lmtpSrv, _ := common.SetupLMTPServer(t)
	defer lmtpSrv.Close()

	c, err := imapclient.DialInsecure(imapSrv.Address, nil)
	if err != nil {
		t.Fatalf("dial IMAP: %v", err)
	}
	defer c.Close()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}

	appendMsg := func(raw string) imap.UID {
		t.Helper()
		ac := c.Append("INBOX", int64(len(raw)), nil)
		if _, err := ac.Write([]byte(raw)); err != nil {
			t.Fatalf("APPEND write: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND close: %v", err)
		}
		data, err := ac.Wait()
		if err != nil {
			t.Fatalf("APPEND wait: %v", err)
		}
		return data.UID
	}

	uNested := appendMsg("From: a@example.com\r\nSubject: nested\r\nMessage-ID: <\"<inner@example.com>\"@host.example>\r\n\r\nbody 1\r\n")
	uPrefixed := appendMsg("From: a@example.com\r\nSubject: prefixed\r\nMessage-ID: <\"tag:<tagged@example.com>:v1\"@host.example>\r\n\r\nbody 2\r\n")
	uOpenAngle := appendMsg("From: a@example.com\r\nSubject: open-angle\r\nMessage-ID: <\"<open\"@example.com>\r\n\r\nbody 3\r\n")
	uCloseAngle := appendMsg("From: a@example.com\r\nSubject: close-angle\r\nMessage-ID: <\"close>\"@example.com>\r\n\r\nbody 4\r\n")
	uPlainQuoted := appendMsg("From: a@example.com\r\nSubject: plain-quoted\r\nMessage-ID: <\"foo bar\"@example.com>\r\n\r\nbody 5\r\n")
	uAbsent := appendMsg("From: a@example.com\r\nSubject: absent\r\n\r\nbody 6\r\n")

	deliverRawMessageViaLMTP(t, lmtpSrv.Address, "sender@example.com", account.Email,
		fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nSubject: lmtp-quoted-nested\r\nMessage-ID: <\"<lmtp-inner@example.com>\"@relay.example>\r\n\r\nbody 7\r\n", account.Email))

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX: %v", err)
	}

	lmtpData, err := c.UIDSearch(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "lmtp-quoted-nested"}},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("UID SEARCH Subject lmtp-quoted-nested: %v", err)
	}
	lmtpUIDs := lmtpData.AllUIDs()
	if len(lmtpUIDs) != 1 {
		t.Fatalf("expected 1 LMTP message, got %v", lmtpUIDs)
	}
	uLMTP := lmtpUIDs[0]

	// Quoted local-parts without '<', '>', or '[' still omit message_id_raw.
	accountID, err := imapSrv.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("GetAccountIDByAddress: %v", err)
	}
	var plainQuotedRaw *string
	if err := imapSrv.ResilientDB.QueryRowWithRetry(
		context.Background(),
		`SELECT message_id_raw FROM messages WHERE account_id = $1 AND mailbox_path = 'INBOX' AND uid = $2 AND expunged_at IS NULL`,
		accountID, int64(uPlainQuoted),
	).Scan(&plainQuotedRaw); err != nil {
		t.Fatalf("query plain-quoted message_id_raw: %v", err)
	}
	if plainQuotedRaw != nil {
		t.Errorf("plain quoted local-part stored message_id_raw = %q, want NULL", *plainQuotedRaw)
	}

	header := func(value string) *imap.SearchCriteria {
		return &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: value}}}
	}
	notHeader := func(value string) *imap.SearchCriteria {
		return &imap.SearchCriteria{Not: []imap.SearchCriteria{*header(value)}}
	}

	allUIDs := []imap.UID{uNested, uPrefixed, uOpenAngle, uCloseAngle, uPlainQuoted, uAbsent, uLMTP}
	slices.Sort(allUIDs)
	without := func(exclude ...imap.UID) []imap.UID {
		var out []imap.UID
		for _, u := range allUIDs {
			if !slices.Contains(exclude, u) {
				out = append(out, u)
			}
		}
		return out
	}

	cases := []struct {
		name     string
		criteria *imap.SearchCriteria
		want     []imap.UID
	}{
		{"nested whole ID inside quoted local-part", header("<inner@example.com>"), []imap.UID{uNested}},
		{"nested whole ID case-insensitive", header("<INNER@EXAMPLE.COM>"), []imap.UID{uNested}},
		{"NOT nested whole ID excludes matching message", notHeader("<inner@example.com>"), without(uNested)},
		{"outer quoted Message-ID", header(`<"<inner@example.com>"@host.example>`), []imap.UID{uNested}},
		{"prefixed nested whole ID inside quoted local-part", header("<tagged@example.com>"), []imap.UID{uPrefixed}},
		{"NOT prefixed nested whole ID", notHeader("<tagged@example.com>"), without(uPrefixed)},
		{"opening angle bracket inside quoted local-part suffix whole ID", header(`<open"@example.com>`), []imap.UID{uOpenAngle}},
		{"closing angle bracket inside quoted local-part prefix whole ID", header(`<"close>`), []imap.UID{uCloseAngle}},
		{"plain quoted local-part without angle brackets", header(`<"foo bar"@example.com>`), []imap.UID{uPlainQuoted}},
		{"LMTP nested whole ID inside quoted local-part", header("<lmtp-inner@example.com>"), []imap.UID{uLMTP}},
		{"LMTP nested whole ID case-insensitive", header("<LMTP-INNER@EXAMPLE.COM>"), []imap.UID{uLMTP}},
		{"NOT LMTP nested whole ID", notHeader("<lmtp-inner@example.com>"), without(uLMTP)},
		{"present Message-ID empty term", header(""), without(uAbsent)},
		{"NOT present Message-ID empty term", notHeader(""), []imap.UID{uAbsent}},
	}

	runSearches := func(scope string) {
		t.Helper()
		for _, tc := range cases {
			data, err := c.UIDSearch(tc.criteria, nil).Wait()
			if err != nil {
				t.Errorf("%s / %s: UID SEARCH failed: %v", scope, tc.name, err)
				continue
			}
			got := data.AllUIDs()
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("%s / %s: UID SEARCH = %v, want %v", scope, tc.name, got, tc.want)
			}
		}
	}

	runSearches("INBOX")

	if err := c.Create("CopyDest", nil).Wait(); err != nil {
		t.Fatalf("CREATE CopyDest: %v", err)
	}
	var allSet imap.UIDSet
	for _, u := range allUIDs {
		allSet.AddNum(u)
	}
	if _, err := c.Copy(allSet, "CopyDest").Wait(); err != nil {
		t.Fatalf("UID COPY to CopyDest: %v", err)
	}
	if _, err := c.Select("CopyDest", nil).Wait(); err != nil {
		t.Fatalf("SELECT CopyDest: %v", err)
	}
	// Since CopyDest is newly created and UIDs 1..7 were copied in ascending order,
	// destination UIDs match 1..7.
	runSearches("CopyDest")
}
