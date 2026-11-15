//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLMTP_AbsentDateHeaderEnvelopeIsNIL: a message delivered without a Date: header has a
// NIL ENVELOPE date (RFC 9051 section 7.5.2) and sorts by its INTERNALDATE (RFC 5256
// section 2.2: "If the sent date cannot be determined (a Date: header is missing or cannot
// be parsed), the INTERNALDATE for that message is used as the sent date"). Before the fix
// the delivery time was stored and reported as the message's Date: header.
func TestLMTP_AbsentDateHeaderEnvelopeIsNIL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	lmtpAddr, _ := startLMTPForDelivery(t, rdb)
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	header := time.Date(2020, 1, 2, 3, 4, 5, 0, time.FixedZone("", -8*3600))
	marker := fmt.Sprintf("lmtp-envdate-%d", common.GetTimestamp())
	for _, m := range []struct{ subject, dateLine string }{
		{marker + " absent", ""},
		{marker + " present", "Date: Thu, 02 Jan 2020 03:04:05 -0800\r\n"},
	} {
		msg := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: " + m.subject + "\r\n" +
			m.dateLine + "Message-ID: <" + strings.ReplaceAll(m.subject, " ", "-") + "@example.com>\r\n\r\nbody\r\n"
		resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, msg)
		require.True(t, strings.HasPrefix(resp, "250"), "delivery failed: %s", resp)
	}

	for _, tc := range []struct {
		subject string
		date    time.Time // the Date: header, zero when absent
	}{
		{marker + " absent", time.Time{}},
		{marker + " present", header},
	} {
		var uid, mailboxID int64
		var sentDate, internalDate time.Time
		require.NoError(t, rdb.QueryRowWithRetry(ctx, `
			SELECT m.uid, m.mailbox_id, m.sent_date, m.internal_date
			FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
			WHERE mb.account_id = $1 AND mb.name = 'INBOX' AND m.subject = $2 AND m.expunged_at IS NULL
		`, accountID, tc.subject).Scan(&uid, &mailboxID, &sentDate, &internalDate))

		want := tc.date
		if want.IsZero() {
			want = internalDate
		}
		assert.True(t, sentDate.Equal(want), "%s: stored sent_date %v, want %v", tc.subject, sentDate, want)

		env, err := rdb.GetDatabase().GetMessageEnvelope(ctx, imap.UID(uid), mailboxID)
		require.NoError(t, err)
		assert.True(t, env.Date.Equal(tc.date), "%s: envelope date %v, want %v", tc.subject, env.Date, tc.date)
	}
}

// TestLMTP_ObsoleteZoneDate: a delivered message whose Date: header has an alphabetic zone
// (RFC 5322 section 4.3: "PDT is semantically equivalent to -0700") is stored at that
// offset, whatever zone the server runs in. Before the fix net/mail looked the name up in
// time.Local, so PDT was stored as 02:23:25 UTC on a server in UTC. At most one of PDT and
// EST can be the server's in July, so a zone looked up in the server's zone fails at least
// one of them.
func TestLMTP_ObsoleteZoneDate(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	lmtpAddr, _ := startLMTPForDelivery(t, rdb)
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	marker := fmt.Sprintf("lmtp-obszone-%d", common.GetTimestamp())
	for _, tc := range []struct {
		zone   string
		offset int32 // seconds east of UTC
	}{
		{"PDT", -7 * 3600},
		{"EST", -5 * 3600},
	} {
		subject := marker + " " + tc.zone
		msg := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: " + subject + "\r\n" +
			"Date: Wed, 17 Jul 1996 02:23:25 " + tc.zone + "\r\n" +
			"Message-ID: <" + strings.ReplaceAll(subject, " ", "-") + "@example.com>\r\n\r\nbody\r\n"
		resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, msg)
		require.True(t, strings.HasPrefix(resp, "250"), "delivery failed: %s", resp)

		var sentDate time.Time
		var offset *int32
		require.NoError(t, rdb.QueryRowWithRetry(ctx, `
			SELECT m.sent_date, m.sent_utc_offset
			FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
			WHERE mb.account_id = $1 AND mb.name = 'INBOX' AND m.subject = $2 AND m.expunged_at IS NULL
		`, accountID, subject).Scan(&sentDate, &offset))

		want := time.Date(1996, 7, 17, 2, 23, 25, 0, time.FixedZone("", int(tc.offset)))
		assert.True(t, sentDate.Equal(want), "%s: stored sent_date %v, want %v", tc.zone, sentDate, want)
		if assert.NotNil(t, offset, "%s: sent_utc_offset", tc.zone) {
			assert.Equal(t, tc.offset, *offset, "%s: sent_utc_offset", tc.zone)
		}
	}
}
