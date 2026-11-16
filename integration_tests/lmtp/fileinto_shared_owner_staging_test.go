//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLMTP_FileintoSharedMailbox_OwnerStagingFails: a Sieve fileinto into a shared
// mailbox another account owns stores the message under the owner, whose pending upload
// reads the body only from the owner's staging file. When that file cannot be staged
// the delivery is deferred (451) and nothing is stored there; it used to be accepted
// with a log line, leaving the owner's message with a body its upload could not find
// (issue #1192).
func TestLMTP_FileintoSharedMailbox_OwnerStagingFails(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory permissions this test relies on")
	}

	imapSrv, contributor := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	domain := strings.Split(contributor.Email, "@")[1]
	ownerEmail := fmt.Sprintf("owner-%d@%s", common.GetTimestamp(), domain)
	const ownerPassword = "owner-pass-123"
	_, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email: ownerEmail, Password: ownerPassword, HashType: "bcrypt", IsPrimary: true,
	})
	require.NoError(t, err)
	shared := fmt.Sprintf("Shared/OwnerStage-%d", common.GetTimestamp())
	oc, err := imapclient.DialInsecure(imapSrv.Address, nil)
	require.NoError(t, err)
	require.NoError(t, oc.Login(ownerEmail, ownerPassword).Wait())
	require.NoError(t, oc.Create(shared, nil).Wait())
	_ = oc.Logout()
	ownerID, err := rdb.GetAccountIDByAddressWithRetry(ctx, ownerEmail)
	require.NoError(t, err)
	contributorID, err := rdb.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
	require.NoError(t, err)
	require.NoError(t, rdb.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerID, contributor.Email, shared, "lri"))

	sieve := fmt.Sprintf("require [\"fileinto\"];\r\nfileinto \"%s\";\r\n", shared)
	_, err = rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", contributorID)
	require.NoError(t, err)
	_, err = rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())`, contributorID, "fileinto-shared", sieve, true)
	require.NoError(t, err)

	// An LMTP server whose upload worker is never started, staging under a directory the
	// test knows. The owner's staging directory takes no new file, so neither a hard link
	// nor a copy can stage the body there.
	stagingDir := t.TempDir()
	up, err := uploader.NewWithS3Interface(stagingDir, 10, 1, 3, time.Second, 0, "owner-staging-lmtp", rdb,
		&common.NoopUploaderS3{}, &common.NoopUploaderCache{}, make(chan error, 1))
	require.NoError(t, err)
	ownerDir := filepath.Dir(up.FilePath(strings.Repeat("0", 64), ownerID))
	require.NoError(t, os.MkdirAll(ownerDir, 0o555))
	require.NoError(t, os.Chmod(ownerDir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(ownerDir, 0o755) })

	lmtpAddr := common.GetRandomAddress(t)
	srv, err := lmtpserver.New(context.Background(), "test-lmtp", "localhost", lmtpAddr,
		&storage.S3Storage{}, rdb, up, lmtpserver.LMTPServerOptions{})
	require.NoError(t, err)
	t.Cleanup(func() { srv.Close() })
	errChan := make(chan error, 1)
	go srv.Start(errChan)
	waitForLMTPListener(t, lmtpAddr, errChan)

	marker := fmt.Sprintf("owner-stage-lmtp-%d", common.GetTimestamp())
	msg := strings.Join([]string{
		"From: sender@example.com",
		"To: " + contributor.Email,
		"Subject: " + marker,
		"Message-ID: <" + marker + "@example.com>",
		"",
		"body",
	}, "\r\n")
	resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", contributor.Email, msg)

	assert.True(t, strings.HasPrefix(resp, "451"), "a body not staged for the owner must defer the delivery, got %q", resp)
	assert.Equal(t, 0, countInMailbox(t, rdb, ownerID, shared),
		"no message may be stored for the owner without a body staged for the owner's upload")
}
