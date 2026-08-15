//go:build integration

package delivery_test

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/stretchr/testify/require"
)

// TestDelivery_BothDeliveryPathsCompileTheSameScriptVersion pins that the two paths that
// run a user's Sieve script - LMTP and the Admin API delivery path - agree on what that
// script currently says.
//
// They used to keep separate compiled-script caches with different keys: LMTP hashed the
// script text, the delivery path keyed on (script id, updated_at). Two caches with two
// keys can hold two different compilations of the same account's script at the same
// moment, and then the mailbox a message lands in depends on which daemon accepted it.
//
// The probe for that is a script body swapped in the database without touching
// updated_at - a stand-in for any mutation a timestamp key fails to notice. Whichever
// key is right, the two paths must not disagree, and neither may keep filtering with a
// script body the database no longer holds.
func TestDelivery_BothDeliveryPathsCompileTheSameScriptVersion(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	dctx := newSieveDeliveryContext(t, rdb, fake, accountID, sieveFileintoArchive)
	recipient := newSelfRecipient(t, accountID, account.Email)
	lmtpAddr := common.StartLMTPServerWithS3(t, rdb, fake)

	// Warm both paths on the same script version.
	require.Equal(t, consts.MailboxArchive,
		deliverSieveProbe(t, dctx, recipient, account.Email, "warm-http").MailboxName,
		"precondition: the active script must file into Archive")
	warmMarker := deliverLMTPProbe(t, lmtpAddr, account.Email, "warm-lmtp")
	require.Equal(t, consts.MailboxArchive, mailboxOfDelivered(t, rdb, accountID, warmMarker),
		"precondition: LMTP must run the same active script")

	active, err := rdb.GetActiveScriptWithRetry(ctx, accountID)
	require.NoError(t, err)
	_, err = rdb.ExecWithRetry(ctx,
		"UPDATE sieve_scripts SET script = $1 WHERE id = $2", sieveFileintoJunk, active.ID)
	require.NoError(t, err)

	httpMailbox := deliverSieveProbe(t, dctx, recipient, account.Email, "after-http").MailboxName
	lmtpMarker := deliverLMTPProbe(t, lmtpAddr, account.Email, "after-lmtp")
	lmtpMailbox := mailboxOfDelivered(t, rdb, accountID, lmtpMarker)

	require.Equal(t, lmtpMailbox, httpMailbox,
		"the two delivery paths filed the same account's mail into different mailboxes: they are "+
			"caching the same compiled Sieve script under different keys")
	require.Equal(t, consts.MailboxJunk, httpMailbox,
		"both paths kept filtering with a script body that is no longer in the database")
}

// TestDelivery_LMTPReusesTheDeliveryPathsCompiledScript pins that the two delivery paths
// share one cache, not merely one key. Two caches keyed the same way would still agree on
// where the mail goes, so the only thing left to observe is the duplicated parse.
func TestDelivery_LMTPReusesTheDeliveryPathsCompiledScript(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	// A script unique to this run, so the entry can only come from this test's deliveries.
	script := fmt.Sprintf("require [\"fileinto\"];\r\n# %d\r\nfileinto \"Archive\";\r\n", common.GetTimestamp())
	dctx := newSieveDeliveryContext(t, rdb, fake, accountID, script)
	recipient := newSelfRecipient(t, accountID, account.Email)
	lmtpAddr := common.StartLMTPServerWithS3(t, rdb, fake)

	// The Admin API delivery path compiles the script.
	require.Equal(t, consts.MailboxArchive,
		deliverSieveProbe(t, dctx, recipient, account.Email, "warm-http").MailboxName,
		"precondition: the active script must file into Archive")

	hitsBefore, missesBefore := sieveengine.SharedScriptCache().Stats()
	marker := deliverLMTPProbe(t, lmtpAddr, account.Email, "reuse-lmtp")
	require.Equal(t, consts.MailboxArchive, mailboxOfDelivered(t, rdb, accountID, marker),
		"LMTP must run the same active script")
	hitsAfter, missesAfter := sieveengine.SharedScriptCache().Stats()

	require.Equal(t, uint64(0), missesAfter-missesBefore,
		"the LMTP delivery parsed a script the delivery path had already compiled: the two paths "+
			"are not sharing one compiled-script cache")
	require.Equal(t, uint64(1), hitsAfter-hitsBefore,
		"the LMTP delivery did not go through the shared compiled-script cache at all")
}

// deliverLMTPProbe delivers one message via LMTP and returns its unique subject.
func deliverLMTPProbe(t *testing.T, addr, recipient, marker string) string {
	t.Helper()

	conn, err := common.DialLMTP(addr)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	r := bufio.NewReader(conn)
	reply := func() string {
		for {
			line, err := r.ReadString('\n')
			require.NoError(t, err)
			line = strings.TrimRight(line, "\r\n")
			if len(line) < 4 || line[3] != '-' {
				return line
			}
		}
	}
	send := func(line string) string {
		_, err := fmt.Fprintf(conn, "%s\r\n", line)
		require.NoError(t, err)
		return reply()
	}

	subject := fmt.Sprintf("sieve-cache-%s-%d", marker, common.GetTimestamp())
	require.True(t, strings.HasPrefix(send("LHLO delivery-test"), "250"))
	require.True(t, strings.HasPrefix(send("MAIL FROM:<sender@example.com>"), "250"))
	require.True(t, strings.HasPrefix(send("RCPT TO:<"+recipient+">"), "250"))
	require.True(t, strings.HasPrefix(send("DATA"), "354"))

	msg := strings.Join([]string{
		"From: sender@example.com",
		"To: " + recipient,
		"Subject: " + subject,
		"Date: " + time.Now().Format(time.RFC1123Z),
		"Message-ID: <" + subject + "@example.com>",
		"",
		"body",
		".",
	}, "\r\n")
	require.True(t, strings.HasPrefix(send(msg), "250"), "LMTP did not accept the message")
	return subject
}

// mailboxOfDelivered returns the mailbox holding the message with the given subject.
func mailboxOfDelivered(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64, subject string) string {
	t.Helper()
	var name string
	err := rdb.QueryRowWithRetry(context.Background(), `
		SELECT mb.name
		FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.account_id = $1 AND m.subject = $2 AND m.expunged_at IS NULL
	`, accountID, subject).Scan(&name)
	require.NoError(t, err, "no delivered message with subject %q", subject)
	return name
}
