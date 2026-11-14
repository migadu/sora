package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAnyoneAllowedFollowsAllowAnyoneIdentifier: [shared_mailboxes]
// allow_anyone_identifier alone decides whether a caller with a config may grant
// "anyone", whatever that config's enabled says (#350). Only a caller without a
// config, a direct database caller, is unrestricted.
func TestAnyoneAllowedFollowsAllowAnyoneIdentifier(t *testing.T) {
	withConfig := func(cfg *config.Config) context.Context {
		return context.WithValue(context.Background(), consts.ConfigContextKey, cfg)
	}
	shared := func(enabled, allowAnyone bool) context.Context {
		return withConfig(&config.Config{SharedMailboxes: config.SharedMailboxesConfig{
			Enabled: enabled, NamespacePrefix: "Shared/", AllowAnyoneIdentifier: allowAnyone,
		}})
	}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{"no config", context.Background(), true},
		{"nil config", withConfig(nil), true},
		{"enabled, anyone allowed", shared(true, true), true},
		{"enabled, anyone disallowed", shared(true, false), false},
		{"disabled, anyone allowed", shared(false, true), true},
		{"disabled, anyone disallowed", shared(false, false), false},
		{"no [shared_mailboxes] section", withConfig(&config.Config{}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, anyoneAllowed(tc.ctx))
		})
	}
}

// TestAnyoneGrantRefusedWhenCallerHasSharingDisabled: a mailbox is shared by its
// row (is_shared), not by the config of whoever grants on it. A caller whose config
// has sharing off and allow_anyone_identifier at its default (sora-admin with a
// config without [shared_mailboxes], an Admin API or IMAP node with sharing off) is
// refused a grant to "anyone" by every grant path, and LISTRIGHTS offers nothing,
// while users can still be granted and an existing "anyone" grant can still be
// reduced and revoked (#350).
func TestAnyoneGrantRefusedWhenCallerHasSharingDisabled(t *testing.T) {
	database := setupTestDatabase(t)
	defer database.Close()

	domain := fmt.Sprintf("anyonepolicy%d.example.com", time.Now().UnixNano())
	owner, _ := setupAccountWithInbox(t, database, context.Background(), "owner@"+domain)
	setupAccountWithInbox(t, database, context.Background(), "member@"+domain)

	const name = "Shared/Sales"
	creatorCtx := context.WithValue(context.Background(), consts.ConfigContextKey, &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/"},
	})
	tx, err := database.GetWritePool().Begin(creatorCtx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	require.NoError(t, database.CreateMailbox(creatorCtx, tx, owner, name, nil))
	require.NoError(t, tx.Commit(creatorCtx))
	mbox, err := database.GetMailboxByName(creatorCtx, owner, name)
	require.NoError(t, err)

	// The caller's config has no [shared_mailboxes] section.
	callerCtx := context.WithValue(context.Background(), consts.ConfigContextKey, &config.Config{})
	anyoneRights := func() (string, bool) {
		t.Helper()
		entries, err := database.GetMailboxACLs(callerCtx, mbox.ID)
		require.NoError(t, err)
		for _, e := range entries {
			if e.Identifier == AnyoneIdentifier {
				return e.Rights, true
			}
		}
		return "", false
	}

	// sora-admin and the Admin API (aclservice.Grant).
	err = database.GrantMailboxAccessByIdentifier(callerCtx, owner, AnyoneIdentifier, name, "lr")
	assert.ErrorIs(t, err, ErrAnyoneDisabled, "grant by owner and mailbox name")
	// IMAP SETACL, replacing and adding.
	for desc, mod := range map[string]ACLModification{"replace": ACLReplace, "add": ACLAdd} {
		err = database.SetMailboxACL(callerCtx, mbox.ID, owner, AnyoneIdentifier, mod, "lr")
		assert.ErrorIs(t, err, ErrAnyoneDisabled, "SETACL %s", desc)
	}
	// IMAP LISTRIGHTS.
	grantability, err := database.MailboxACLGrantability(callerCtx, mbox.ID, AnyoneIdentifier)
	require.NoError(t, err)
	assert.Equal(t, ACLGrantNone, grantability, "LISTRIGHTS anyone")
	_, found := anyoneRights()
	assert.False(t, found, "no anyone entry may be stored")

	// A user is still granted.
	require.NoError(t, database.GrantMailboxAccessByIdentifier(callerCtx, owner, "member@"+domain, name, "lr"))

	// allow_anyone_identifier = true grants "anyone" whatever enabled says.
	allowCtx := context.WithValue(context.Background(), consts.ConfigContextKey, &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{AllowAnyoneIdentifier: true},
	})
	grantability, err = database.MailboxACLGrantability(allowCtx, mbox.ID, AnyoneIdentifier)
	require.NoError(t, err)
	assert.Equal(t, ACLGrantAny, grantability, "LISTRIGHTS anyone with allow_anyone_identifier")
	require.NoError(t, database.GrantMailboxAccessByIdentifier(allowCtx, owner, AnyoneIdentifier, name, "lr"))

	// Back under the restricted config, the existing grant can be reduced and revoked,
	// but not extended.
	err = database.SetMailboxACL(callerCtx, mbox.ID, owner, AnyoneIdentifier, ACLAdd, "s")
	assert.ErrorIs(t, err, ErrAnyoneDisabled, "extending an existing anyone grant")
	require.NoError(t, database.SetMailboxACL(callerCtx, mbox.ID, owner, AnyoneIdentifier, ACLRemove, "r"))
	rights, found := anyoneRights()
	require.True(t, found)
	assert.Equal(t, "l", rights)
	require.NoError(t, database.RevokeMailboxAccessByIdentifier(callerCtx, mbox.ID, AnyoneIdentifier))
	_, found = anyoneRights()
	assert.False(t, found, "anyone entry revoked")
}
