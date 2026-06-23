//go:build integration

package imap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover audit item B2: a message stored in a shared mailbox must be
// owned by the mailbox owner (account_id + S3 path), not by whoever inserted it.

// fetchFullBody fetches BODY[] for the given sequence number and returns the raw bytes.
func fetchFullBody(t *testing.T, c *imapclient.Client, seq uint32) []byte {
	t.Helper()
	cmd := c.Fetch(imap.SeqSetNum(seq), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{{Part: []int{}}},
	})
	var body []byte
	for {
		msg := cmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if b, ok := item.(imapclient.FetchItemDataBodySection); ok {
				buf := new(bytes.Buffer)
				_, _ = io.Copy(buf, b.Literal)
				body = buf.Bytes()
			}
		}
	}
	_ = cmd.Close()
	return body
}

// createOwnerWithSharedMailbox creates a second same-domain account (the owner),
// has it create a shared mailbox via IMAP (which sets is_shared), and grants the
// given rights on it to grantee. Returns the owner's email, account id, and the
// shared mailbox name.
func createOwnerWithSharedMailbox(t *testing.T, server *common.TestServer, granteeEmail, rights string) (ownerEmail string, ownerID int64, sharedMailbox string) {
	t.Helper()
	ctx := context.Background()

	domain := strings.Split(granteeEmail, "@")[1]
	ownerEmail = fmt.Sprintf("owner-%d@%s", common.GetTimestamp(), domain)
	const ownerPassword = "owner-pass-123"
	if _, err := server.ResilientDB.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email:     ownerEmail,
		Password:  ownerPassword,
		HashType:  "bcrypt",
		IsPrimary: true,
	}); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	sharedMailbox = fmt.Sprintf("Shared/B2-%d", common.GetTimestamp())
	oc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err, "owner dial")
	require.NoError(t, oc.Login(ownerEmail, ownerPassword).Wait(), "owner login")
	require.NoError(t, oc.Create(sharedMailbox, nil).Wait(), "create shared mailbox")
	_ = oc.Logout()

	ownerID, err = server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, ownerEmail)
	require.NoError(t, err, "owner id")

	require.NoError(t,
		server.ResilientDB.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerID, granteeEmail, sharedMailbox, rights),
		"grant %q to grantee", rights)

	return ownerEmail, ownerID, sharedMailbox
}

// ownedMessageAttribution returns the account_id / s3_domain / s3_localpart of the
// single live message in (ownerID, mailboxName).
func ownedMessageAttribution(t *testing.T, server *common.TestServer, ownerID int64, mailboxName string) (accountID int64, s3Domain, s3Localpart string) {
	t.Helper()
	err := server.ResilientDB.QueryRowWithRetry(context.Background(), `
		SELECT m.account_id, m.s3_domain, m.s3_localpart
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.account_id = $1 AND mb.name = $2 AND m.expunged_at IS NULL
		ORDER BY m.uid DESC
		LIMIT 1
	`, ownerID, mailboxName).Scan(&accountID, &s3Domain, &s3Localpart)
	require.NoError(t, err, "query attribution for %q", mailboxName)
	return accountID, s3Domain, s3Localpart
}

// TestSharedMailboxOwnership_AppendAttribution verifies that an APPEND by a grantee
// into another account's shared mailbox is attributed to the mailbox OWNER (account_id
// + S3 path), and the body is retrievable by both the owner and the grantee.
func TestSharedMailboxOwnership_AppendAttribution(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, contributor := common.SetupIMAPServer(t)
	defer server.Close()
	ctx := context.Background()

	ownerEmail, ownerID, shared := createOwnerWithSharedMailbox(t, server, contributor.Email, "lrswi")

	contributorID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
	require.NoError(t, err)
	require.NotEqual(t, ownerID, contributorID, "owner and contributor must be distinct accounts")

	// Contributor appends into the owner's shared mailbox.
	cc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	require.NoError(t, cc.Login(contributor.Email, contributor.Password).Wait())

	const marker = "B2 shared ownership append marker"
	literal := "Subject: Shared Append\r\n\r\n" + marker
	appendCmd := cc.Append(shared, int64(len(literal)), nil)
	_, err = appendCmd.Write([]byte(literal))
	require.NoError(t, err)
	require.NoError(t, appendCmd.Close())
	_, err = appendCmd.Wait()
	require.NoError(t, err, "contributor APPEND into shared mailbox")

	// Attribution: the new row must belong to the OWNER, not the contributor.
	accountID, s3Domain, s3Localpart := ownedMessageAttribution(t, server, ownerID, shared)
	assert.Equal(t, ownerID, accountID, "message must be owned by mailbox owner, not inserter")
	ownerLocal := strings.Split(ownerEmail, "@")[0]
	ownerDomain := strings.Split(ownerEmail, "@")[1]
	assert.Equal(t, ownerDomain, s3Domain, "s3_domain must be the owner's")
	assert.Equal(t, ownerLocal, s3Localpart, "s3_localpart must be the owner's")

	// Body retrievable by the grantee (contributor still has 'r').
	mbox, err := cc.Select(shared, nil).Wait()
	require.NoError(t, err, "contributor SELECT shared")
	require.Equal(t, uint32(1), mbox.NumMessages)
	body := fetchFullBody(t, cc, 1)
	assert.Contains(t, string(body), marker, "grantee must be able to FETCH the body")
	_ = cc.Logout()

	// Body retrievable by the owner.
	oc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	require.NoError(t, oc.Login(ownerEmail, "owner-pass-123").Wait())
	defer oc.Logout()
	mbox, err = oc.Select(shared, nil).Wait()
	require.NoError(t, err, "owner SELECT shared")
	require.Equal(t, uint32(1), mbox.NumMessages)
	body = fetchFullBody(t, oc, 1)
	assert.Contains(t, string(body), marker, "owner must be able to FETCH the body")
}

// TestSharedMailboxOwnership_PurgeSurvival verifies the main driver of B2: purging a
// contributor must NOT delete content they filed into another user's shared folder.
// HardDeleteAccounts expunges messages by account_id; with owner-attribution the
// shared-folder message (owned by the owner) survives.
func TestSharedMailboxOwnership_PurgeSurvival(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, contributor := common.SetupIMAPServer(t)
	defer server.Close()
	ctx := context.Background()

	ownerEmail, ownerID, shared := createOwnerWithSharedMailbox(t, server, contributor.Email, "lrswi")
	contributorID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
	require.NoError(t, err)

	// Contributor files a message into the owner's shared folder.
	cc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	require.NoError(t, cc.Login(contributor.Email, contributor.Password).Wait())
	const marker = "B2 purge-survival marker"
	literal := "Subject: Shared Purge\r\n\r\n" + marker
	appendCmd := cc.Append(shared, int64(len(literal)), nil)
	_, err = appendCmd.Write([]byte(literal))
	require.NoError(t, err)
	require.NoError(t, appendCmd.Close())
	_, err = appendCmd.Wait()
	require.NoError(t, err)
	_ = cc.Logout()

	// Sanity: attributed to the owner before purge.
	accountID, _, _ := ownedMessageAttribution(t, server, ownerID, shared)
	require.Equal(t, ownerID, accountID, "precondition: message owned by owner")

	// Purge the contributor exactly as the admin path does (expunge by account_id,
	// then drop the contributor's mailboxes/credentials/pending_uploads).
	tx, err := server.ResilientDB.BeginTxWithRetry(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	require.NoError(t, server.ResilientDB.GetDatabase().HardDeleteAccounts(ctx, tx, []int64{contributorID}))
	require.NoError(t, tx.Commit(ctx))

	// The shared-folder message + body must survive.
	var live int
	err = server.ResilientDB.QueryRowWithRetry(ctx, `
		SELECT COUNT(*)
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.account_id = $1 AND mb.name = $2 AND m.expunged_at IS NULL
	`, ownerID, shared).Scan(&live)
	require.NoError(t, err)
	assert.Equal(t, 1, live, "shared-folder message must survive contributor purge")

	// Owner can still retrieve the body.
	oc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	require.NoError(t, oc.Login(ownerEmail, "owner-pass-123").Wait())
	defer oc.Logout()
	mbox, err := oc.Select(shared, nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), mbox.NumMessages, "owner still sees the surviving message")
	body := fetchFullBody(t, oc, 1)
	assert.Contains(t, string(body), marker, "owner must still FETCH the surviving body after purge")
}

// TestSharedMailboxOwnership_PersonalMailboxRegression verifies that APPEND/COPY/MOVE
// within a user's own mailboxes are unchanged: the message stays owned by that user.
func TestSharedMailboxOwnership_PersonalMailboxRegression(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	ctx := context.Background()

	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	selfLocal := strings.Split(account.Email, "@")[0]
	selfDomain := strings.Split(account.Email, "@")[1]

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	require.NoError(t, c.Login(account.Email, account.Password).Wait())
	defer c.Logout()

	require.NoError(t, c.Create("B2Archive", nil).Wait())

	const marker = "B2 personal regression marker"
	literal := "Subject: Personal\r\n\r\n" + marker
	appendCmd := c.Append("INBOX", int64(len(literal)), nil)
	_, err = appendCmd.Write([]byte(literal))
	require.NoError(t, err)
	require.NoError(t, appendCmd.Close())
	_, err = appendCmd.Wait()
	require.NoError(t, err)

	// APPEND attribution = self.
	id, dom, loc := ownedMessageAttribution(t, server, accountID, "INBOX")
	assert.Equal(t, accountID, id)
	assert.Equal(t, selfDomain, dom)
	assert.Equal(t, selfLocal, loc)

	// COPY INBOX -> B2Archive (same account): attribution unchanged.
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	_, err = c.Copy(imap.SeqSetNum(1), "B2Archive").Wait()
	require.NoError(t, err)
	id, dom, loc = ownedMessageAttribution(t, server, accountID, "B2Archive")
	assert.Equal(t, accountID, id, "COPY within own account stays self-owned")
	assert.Equal(t, selfDomain, dom)
	assert.Equal(t, selfLocal, loc)
	body := fetchFullBody(t, c, 1) // still selected on INBOX
	assert.Contains(t, string(body), marker)

	// MOVE INBOX -> B2Archive (same account): attribution unchanged.
	_, err = c.Move(imap.SeqSetNum(1), "B2Archive").Wait()
	require.NoError(t, err)
	mbox, err := c.Select("B2Archive", nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(2), mbox.NumMessages, "B2Archive has the copied + moved message")
	id, dom, loc = ownedMessageAttribution(t, server, accountID, "B2Archive")
	assert.Equal(t, accountID, id, "MOVE within own account stays self-owned")
	assert.Equal(t, selfDomain, dom)
	assert.Equal(t, selfLocal, loc)
}

// appendTo appends a one-part message with the given marker to mailbox via c.
func appendTo(t *testing.T, c *imapclient.Client, mailbox, subject, marker string) {
	t.Helper()
	literal := "Subject: " + subject + "\r\n\r\n" + marker
	cmd := c.Append(mailbox, int64(len(literal)), nil)
	_, err := cmd.Write([]byte(literal))
	require.NoError(t, err)
	require.NoError(t, cmd.Close())
	_, err = cmd.Wait()
	require.NoError(t, err, "APPEND to %q", mailbox)
}

// TestSharedMailboxOwnership_CopyEndToEnd exercises the full uploaded-body path with a
// real (in-memory) S3: a contributor APPENDs to their own INBOX (uploaded to S3 under
// the contributor's path), then COPYs into another account's shared mailbox. The body
// must be server-side-copied to the OWNER's S3 path, the new row attributed to the
// owner, and the body retrievable from S3 by both owner and grantee — and it must
// survive a purge of the contributor.
func TestSharedMailboxOwnership_CopyEndToEnd(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, contributor, fake := common.SetupIMAPServerWithRealS3(t)
	defer server.Close()
	ctx := context.Background()

	ownerEmail, ownerID, shared := createOwnerWithSharedMailbox(t, server, contributor.Email, "lrswi")
	contributorID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
	require.NoError(t, err)

	cc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	require.NoError(t, cc.Login(contributor.Email, contributor.Password).Wait())

	const marker = "B2 copy-end-to-end marker"
	appendTo(t, cc, "INBOX", "Copy E2E", marker)
	require.Equal(t, 1, fake.ObjectCount(), "APPEND must have uploaded one object (contributor's S3 path)")

	// Copy the message from the contributor's INBOX into the owner's shared mailbox.
	_, err = cc.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	_, err = cc.Copy(imap.SeqSetNum(1), shared).Wait()
	require.NoError(t, err, "cross-account COPY into shared mailbox")

	// The body must have been server-side-copied to the owner's S3 path.
	assert.Equal(t, 2, fake.ObjectCount(), "COPY must create a second S3 object under the owner's path")

	// Attribution: new row owned by the owner.
	accountID, s3Domain, s3Localpart := ownedMessageAttribution(t, server, ownerID, shared)
	assert.Equal(t, ownerID, accountID)
	assert.Equal(t, strings.Split(ownerEmail, "@")[1], s3Domain)
	assert.Equal(t, strings.Split(ownerEmail, "@")[0], s3Localpart)

	// Grantee (contributor, has 'r') retrieves the body — served from S3.
	mbox, err := cc.Select(shared, nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), mbox.NumMessages)
	assert.Contains(t, string(fetchFullBody(t, cc, 1)), marker, "grantee FETCH from S3")
	_ = cc.Logout()

	// Owner retrieves the body — served from S3 under the owner's path.
	oc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	require.NoError(t, oc.Login(ownerEmail, "owner-pass-123").Wait())
	defer oc.Logout()
	mbox, err = oc.Select(shared, nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), mbox.NumMessages)
	assert.Contains(t, string(fetchFullBody(t, oc, 1)), marker, "owner FETCH from S3")

	// Purge the contributor: the shared-folder message + its S3 body must survive.
	tx, err := server.ResilientDB.BeginTxWithRetry(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	require.NoError(t, server.ResilientDB.GetDatabase().HardDeleteAccounts(ctx, tx, []int64{contributorID}))
	require.NoError(t, tx.Commit(ctx))

	mbox, err = oc.Select(shared, nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), mbox.NumMessages, "shared message survives contributor purge")
	assert.Contains(t, string(fetchFullBody(t, oc, 1)), marker, "owner still FETCHes body from S3 after purge")
}

// TestSharedMailboxOwnership_MoveEndToEnd is the MOVE analogue of the COPY end-to-end
// test: the body is relocated to the owner's S3 path, the new row attributed to the
// owner, retrievable from S3, and surviving a contributor purge.
func TestSharedMailboxOwnership_MoveEndToEnd(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, contributor, fake := common.SetupIMAPServerWithRealS3(t)
	defer server.Close()
	ctx := context.Background()

	ownerEmail, ownerID, shared := createOwnerWithSharedMailbox(t, server, contributor.Email, "lrswi")
	contributorID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
	require.NoError(t, err)

	cc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	require.NoError(t, cc.Login(contributor.Email, contributor.Password).Wait())

	const marker = "B2 move-end-to-end marker"
	appendTo(t, cc, "INBOX", "Move E2E", marker)
	require.Equal(t, 1, fake.ObjectCount())

	_, err = cc.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	_, err = cc.Move(imap.SeqSetNum(1), shared).Wait()
	require.NoError(t, err, "cross-account MOVE into shared mailbox")
	assert.Equal(t, 2, fake.ObjectCount(), "MOVE must create the owner's S3 object")
	_ = cc.Logout()

	// Attribution: new row owned by the owner.
	accountID, s3Domain, s3Localpart := ownedMessageAttribution(t, server, ownerID, shared)
	assert.Equal(t, ownerID, accountID)
	assert.Equal(t, strings.Split(ownerEmail, "@")[1], s3Domain)
	assert.Equal(t, strings.Split(ownerEmail, "@")[0], s3Localpart)

	// Owner retrieves the moved body from S3.
	oc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	require.NoError(t, oc.Login(ownerEmail, "owner-pass-123").Wait())
	defer oc.Logout()
	mbox, err := oc.Select(shared, nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), mbox.NumMessages)
	assert.Contains(t, string(fetchFullBody(t, oc, 1)), marker, "owner FETCH moved body from S3")

	// Purge the contributor: moved message + S3 body survive.
	tx, err := server.ResilientDB.BeginTxWithRetry(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	require.NoError(t, server.ResilientDB.GetDatabase().HardDeleteAccounts(ctx, tx, []int64{contributorID}))
	require.NoError(t, tx.Commit(ctx))

	mbox, err = oc.Select(shared, nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), mbox.NumMessages, "moved message survives contributor purge")
	assert.Contains(t, string(fetchFullBody(t, oc, 1)), marker, "owner still FETCHes moved body from S3 after purge")
}
